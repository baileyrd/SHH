//! Channel multiplexer for `direct-tcpip` forwarding.
//!
//! A [`Connection`] owns the transport and is the *sole* reader and writer
//! of it. Each forwarded TCP stream runs in its own task and talks to the
//! loop over channels: an unbounded queue for received data, a shared
//! [`Semaphore`] of send-window credits, and a command channel back to the
//! loop. This keeps flow control honest — a slow forwarded endpoint stops
//! sending `Consumed`, the receive window closes, and the peer stops
//! sending; a closed send window blocks the reader task's credit
//! acquisition, applying TCP backpressure to the origin.
//!
//! Only `direct-tcpip` channels live here. Session channels use the
//! transport-driven path in the parent module; a connection runs one or
//! the other, never both (see the module docs).

use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};

use super::forward::{self, Policy};
use super::{
    chan, data_packet, open_failure, simple, window_adjust, LOCAL_WINDOW, MAX_CHUNK, WINDOW_REFILL,
};
use crate::transport::Transport;
use crate::wire::{msg, Reader, Writer};
use crate::{Error, Result};

/// Commands from channel tasks and forward acceptors to the loop.
pub(crate) enum Cmd {
    /// A local acceptor asks to open a direct-tcpip channel carrying `stream`.
    OpenDirect {
        target_host: String,
        target_port: u16,
        orig_host: String,
        orig_port: u16,
        stream: TcpStream,
    },
    /// Result of a server-side connect for an incoming direct-tcpip open.
    Connected {
        peer_id: u32,
        peer_window: u32,
        peer_max: u32,
        stream: std::io::Result<TcpStream>,
    },
    /// Channel data cleared to send (send-window credit already spent).
    Data { id: u32, bytes: Vec<u8> },
    /// The forwarded socket reached EOF on its read side.
    Eof { id: u32 },
    /// The forward task finished; tear the channel down.
    Close { id: u32 },
    /// `n` received bytes were written to the socket; replenish the window.
    Consumed { id: u32, n: u32 },
}

/// Messages the loop pushes to a channel's forward task.
pub(crate) enum ToTask {
    Data(Vec<u8>),
    Eof,
    Close,
}

/// A submission handle for local forward acceptors.
#[derive(Clone)]
pub struct Handle {
    tx: mpsc::UnboundedSender<Cmd>,
}

impl Handle {
    /// Request a new direct-tcpip channel for an accepted local connection.
    pub fn open_direct(
        &self,
        target_host: String,
        target_port: u16,
        orig_host: String,
        orig_port: u16,
        stream: TcpStream,
    ) {
        let _ = self.tx.send(Cmd::OpenDirect {
            target_host,
            target_port,
            orig_host,
            orig_port,
            stream,
        });
    }
}

struct Chan {
    peer_id: u32,
    /// Send-window credits (bytes) we may still send to the peer.
    credit: Arc<Semaphore>,
    /// Receive window we have granted and the peer has not yet used.
    local_window: u32,
    /// Consumed bytes awaiting a batched WINDOW_ADJUST.
    pending_consumed: u32,
    to_task: mpsc::UnboundedSender<ToTask>,
    sent_eof: bool,
    sent_close: bool,
    peer_closed: bool,
}

struct PendingOpen {
    stream: TcpStream,
}

/// The forwarding connection loop.
pub struct Connection<S> {
    t: Transport<S>,
    policy: Policy,
    channels: HashMap<u32, Chan>,
    pending: HashMap<u32, PendingOpen>,
    next_id: u32,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    done: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Connection<S> {
    /// Wrap an authenticated transport. `policy` gates *incoming*
    /// direct-tcpip opens (server role); a client passes [`Policy::DenyAll`].
    pub fn new(t: Transport<S>, policy: Policy) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        Connection {
            t,
            policy,
            channels: HashMap::new(),
            pending: HashMap::new(),
            next_id: 0,
            cmd_tx,
            cmd_rx,
            done: false,
        }
    }

    /// A handle for submitting local forward opens (client role).
    pub fn handle(&self) -> Handle {
        Handle {
            tx: self.cmd_tx.clone(),
        }
    }

    /// Run until the peer disconnects or the transport fails. `primed` is a
    /// CHANNEL_OPEN already read off the wire by a dispatcher; pass `None`
    /// when nothing has been consumed yet.
    pub async fn run(mut self, primed: Option<Vec<u8>>) -> Result<()> {
        if let Some(p) = primed {
            self.on_packet(p).await?;
        }
        while !self.done {
            // Process anything the transport queued while rekeying, and
            // honor time/byte rekey thresholds before blocking.
            if self.t.should_rekey() {
                self.t.rekey_initiate().await?;
            }
            while let Some(p) = self.t.queued.pop_front() {
                self.on_packet(p).await?;
                if self.done {
                    return Ok(());
                }
            }

            tokio::select! {
                biased;
                pkt = self.t.recv_raw() => self.on_packet(pkt?).await?,
                cmd = self.cmd_rx.recv() => {
                    // We hold a sender, so this is never None.
                    if let Some(cmd) = cmd {
                        self.on_cmd(cmd).await?;
                    }
                }
            }
        }
        Ok(())
    }

    fn alloc_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    // --------------------------------------------------- transport packets

    async fn on_packet(&mut self, p: Vec<u8>) -> Result<()> {
        match p[0] {
            msg::IGNORE | msg::DEBUG | msg::UNIMPLEMENTED => {}
            msg::EXT_INFO => self.t.note_ext_info(&p)?,
            msg::KEXINIT => self.t.rekey_respond(p).await?,
            msg::DISCONNECT => self.done = true,
            msg::GLOBAL_REQUEST => super::refuse_global_request(&mut self.t, &p).await?,
            msg::CHANNEL_OPEN => self.on_channel_open(&p).await?,
            msg::CHANNEL_OPEN_CONFIRMATION => self.on_open_confirm(&p)?,
            msg::CHANNEL_OPEN_FAILURE => self.on_open_failure(&p)?,
            msg::CHANNEL_DATA => self.on_data(&p).await?,
            msg::CHANNEL_EXTENDED_DATA => self.on_ext_data(&p).await?,
            msg::CHANNEL_WINDOW_ADJUST => self.on_window_adjust(&p)?,
            msg::CHANNEL_EOF => self.on_eof(&p)?,
            msg::CHANNEL_CLOSE => self.on_close(&p).await?,
            msg::CHANNEL_REQUEST => self.on_channel_request(&p).await?,
            // A forwarding connection issues no channel requests.
            msg::CHANNEL_SUCCESS | msg::CHANNEL_FAILURE => {}
            msg::NEWKEYS | msg::KEX_ECDH_INIT | msg::KEX_ECDH_REPLY => {
                return Err(Error::proto("key exchange message outside key exchange"))
            }
            other => return Err(Error::proto(format!("unexpected message {other}"))),
        }
        Ok(())
    }

    async fn on_channel_open(&mut self, p: &[u8]) -> Result<()> {
        let mut r = Reader::new(p);
        r.byte()?;
        let kind = r.utf8()?.to_owned();
        let sender = r.u32()?;
        let window = r.u32()?;
        let max = r.u32()?;
        if kind != "direct-tcpip" {
            return self
                .reject_open(sender, open_failure::UNKNOWN_CHANNEL_TYPE, "unsupported channel type")
                .await;
        }
        let host = r.utf8()?.to_owned();
        let port = u16::try_from(r.u32()?).map_err(|_| Error::proto("port out of range"))?;
        let _orig_host = r.utf8()?;
        let _orig_port = r.u32()?;
        r.finish()?;

        if !self.policy.permits(&host, port) {
            tracing::info!(%host, port, "direct-tcpip refused by policy");
            return self
                .reject_open(
                    sender,
                    open_failure::ADMINISTRATIVELY_PROHIBITED,
                    "forwarding to that target is not permitted",
                )
                .await;
        }

        // Connect out in a task so a slow/hung DNS or SYN can't stall the
        // loop and its other channels. The result comes back as a command.
        let cmd_tx = self.cmd_tx.clone();
        tokio::spawn(async move {
            let stream = TcpStream::connect((host.as_str(), port)).await;
            if let Ok(s) = &stream {
                s.set_nodelay(true).ok();
            }
            let _ = cmd_tx.send(Cmd::Connected {
                peer_id: sender,
                peer_window: window,
                peer_max: max,
                stream,
            });
        });
        Ok(())
    }

    async fn reject_open(&mut self, peer: u32, reason: u32, desc: &str) -> Result<()> {
        let mut w = chan(msg::CHANNEL_OPEN_FAILURE, peer);
        w.u32(reason);
        w.utf8(desc);
        w.utf8("");
        self.t.send(&w.into_bytes()).await
    }

    fn on_open_confirm(&mut self, p: &[u8]) -> Result<()> {
        let mut r = Reader::new(p);
        r.byte()?;
        let ours = r.u32()?;
        let peer = r.u32()?;
        let window = r.u32()?;
        let max = r.u32()?;
        r.finish()?;
        let Some(pending) = self.pending.remove(&ours) else {
            return Err(Error::proto("confirmation for an unknown channel"));
        };
        self.spawn_channel(ours, peer, window, max, pending.stream);
        Ok(())
    }

    fn on_open_failure(&mut self, p: &[u8]) -> Result<()> {
        let mut r = Reader::new(p);
        r.byte()?;
        let ours = r.u32()?;
        let _reason = r.u32()?;
        let desc = r.utf8().unwrap_or("no reason given");
        tracing::info!(channel = ours, "forward channel refused: {desc}");
        // Dropping the pending stream closes the local connection.
        self.pending.remove(&ours);
        Ok(())
    }

    async fn on_data(&mut self, p: &[u8]) -> Result<()> {
        let mut r = Reader::new(p);
        r.byte()?;
        let id = r.u32()?;
        let data = r.string()?;
        let Some(ch) = self.channels.get_mut(&id) else {
            return Ok(()); // data raced a close; drop it
        };
        let len = u32::try_from(data.len()).map_err(|_| Error::proto("data too large"))?;
        ch.local_window = ch
            .local_window
            .checked_sub(len)
            .ok_or_else(|| Error::proto("peer overflowed the channel window"))?;
        let _ = ch.to_task.send(ToTask::Data(data.to_vec()));
        Ok(())
    }

    async fn on_ext_data(&mut self, p: &[u8]) -> Result<()> {
        // direct-tcpip has no stderr stream; account the window and drop.
        let mut r = Reader::new(p);
        r.byte()?;
        let id = r.u32()?;
        let _kind = r.u32()?;
        let data = r.string()?;
        if let Some(ch) = self.channels.get_mut(&id) {
            let len = u32::try_from(data.len()).map_err(|_| Error::proto("data too large"))?;
            ch.local_window = ch.local_window.saturating_sub(len);
        }
        Ok(())
    }

    fn on_window_adjust(&mut self, p: &[u8]) -> Result<()> {
        let mut r = Reader::new(p);
        r.byte()?;
        let id = r.u32()?;
        let add = r.u32()?;
        if let Some(ch) = self.channels.get(&id) {
            ch.credit.add_permits(add as usize);
        }
        Ok(())
    }

    fn on_eof(&mut self, p: &[u8]) -> Result<()> {
        let mut r = Reader::new(p);
        r.byte()?;
        let id = r.u32()?;
        if let Some(ch) = self.channels.get(&id) {
            let _ = ch.to_task.send(ToTask::Eof);
        }
        Ok(())
    }

    async fn on_close(&mut self, p: &[u8]) -> Result<()> {
        let mut r = Reader::new(p);
        r.byte()?;
        let id = r.u32()?;
        if let Some(ch) = self.channels.get_mut(&id) {
            ch.peer_closed = true;
            let _ = ch.to_task.send(ToTask::Close);
            if !ch.sent_close {
                let peer = ch.peer_id;
                ch.sent_close = true;
                self.t.send(&simple(msg::CHANNEL_CLOSE, peer)).await?;
            }
            self.finish_if_closed(id);
        }
        Ok(())
    }

    async fn on_channel_request(&mut self, p: &[u8]) -> Result<()> {
        let mut r = Reader::new(p);
        r.byte()?;
        let _id = r.u32()?;
        let _kind = r.utf8()?;
        if r.boolean()? {
            // We never grant channel requests on a forwarded stream.
            if let Some(ch) = self.channels.get(&_id) {
                let peer = ch.peer_id;
                self.t.send(&simple(msg::CHANNEL_FAILURE, peer)).await?;
            }
        }
        Ok(())
    }

    // ---------------------------------------------------- task commands

    async fn on_cmd(&mut self, cmd: Cmd) -> Result<()> {
        match cmd {
            Cmd::OpenDirect {
                target_host,
                target_port,
                orig_host,
                orig_port,
                stream,
            } => {
                let id = self.alloc_id();
                self.pending.insert(id, PendingOpen { stream });
                let mut w = Writer::new();
                w.byte(msg::CHANNEL_OPEN);
                w.utf8("direct-tcpip");
                w.u32(id);
                w.u32(LOCAL_WINDOW);
                w.u32(MAX_CHUNK);
                w.utf8(&target_host);
                w.u32(target_port as u32);
                w.utf8(&orig_host);
                w.u32(orig_port as u32);
                self.t.send(&w.into_bytes()).await?;
            }
            Cmd::Connected {
                peer_id,
                peer_window,
                peer_max,
                stream,
            } => match stream {
                Ok(sock) => {
                    let id = self.alloc_id();
                    let mut w = chan(msg::CHANNEL_OPEN_CONFIRMATION, peer_id);
                    w.u32(id);
                    w.u32(LOCAL_WINDOW);
                    w.u32(MAX_CHUNK);
                    self.t.send(&w.into_bytes()).await?;
                    self.spawn_channel(id, peer_id, peer_window, peer_max, sock);
                }
                Err(e) => {
                    self.reject_open(
                        peer_id,
                        open_failure::CONNECT_FAILED,
                        &format!("connect failed: {e}"),
                    )
                    .await?;
                }
            },
            Cmd::Data { id, bytes } => {
                if let Some(ch) = self.channels.get(&id) {
                    let peer = ch.peer_id;
                    self.t.send(&data_packet(peer, &bytes)).await?;
                }
            }
            Cmd::Eof { id } => {
                if let Some(ch) = self.channels.get_mut(&id) {
                    if !ch.sent_eof {
                        ch.sent_eof = true;
                        let peer = ch.peer_id;
                        self.t.send(&simple(msg::CHANNEL_EOF, peer)).await?;
                    }
                }
            }
            Cmd::Close { id } => {
                if let Some(ch) = self.channels.get_mut(&id) {
                    if !ch.sent_close {
                        ch.sent_close = true;
                        let peer = ch.peer_id;
                        self.t.send(&simple(msg::CHANNEL_CLOSE, peer)).await?;
                    }
                    self.finish_if_closed(id);
                }
            }
            Cmd::Consumed { id, n } => {
                if let Some(ch) = self.channels.get_mut(&id) {
                    ch.pending_consumed += n;
                    if ch.pending_consumed >= WINDOW_REFILL {
                        let add = ch.pending_consumed;
                        ch.pending_consumed = 0;
                        ch.local_window = ch.local_window.saturating_add(add);
                        let peer = ch.peer_id;
                        self.t.send(&window_adjust(peer, add)).await?;
                    }
                }
            }
        }
        Ok(())
    }

    fn spawn_channel(&mut self, id: u32, peer_id: u32, peer_window: u32, peer_max: u32, stream: TcpStream) {
        let credit = Arc::new(Semaphore::new(peer_window as usize));
        let (to_task_tx, to_task_rx) = mpsc::unbounded_channel();
        // Never send a chunk larger than the peer will accept, or ours.
        let remote_max = peer_max.clamp(1, MAX_CHUNK);
        self.channels.insert(
            id,
            Chan {
                peer_id,
                credit: credit.clone(),
                local_window: LOCAL_WINDOW,
                pending_consumed: 0,
                to_task: to_task_tx,
                sent_eof: false,
                sent_close: false,
                peer_closed: false,
            },
        );
        tokio::spawn(forward::forward_task(
            id,
            stream,
            credit,
            remote_max,
            to_task_rx,
            self.cmd_tx.clone(),
        ));
    }

    fn finish_if_closed(&mut self, id: u32) {
        if let Some(ch) = self.channels.get(&id) {
            if ch.sent_close && ch.peer_closed {
                self.channels.remove(&id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::PrivateKey;
    use crate::transport::{ClientConfig, ServerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// A localhost echo server; returns its address.
    async fn echo_server() -> std::net::SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    async fn transport_pair() -> (
        Transport<tokio::io::DuplexStream>,
        Transport<tokio::io::DuplexStream>,
    ) {
        let (a, b) = tokio::io::duplex(1 << 20);
        let host_key = PrivateKey::generate();
        let (c, s) = tokio::join!(
            Transport::client(
                a,
                ClientConfig {
                    verify_host_key: Box::new(|_| Ok(())),
                },
            ),
            Transport::server(b, ServerConfig { host_key }),
        );
        (c.unwrap(), s.unwrap())
    }

    #[tokio::test]
    async fn local_forward_round_trips_through_the_tunnel() {
        let target = echo_server().await;
        let (client_t, server_t) = transport_pair().await;

        // Server: accept incoming direct-tcpip and connect out (allow all).
        let server = tokio::spawn(async move {
            Connection::new(server_t, Policy::AllowAll).run(None).await
        });

        // Client: a local listener that forwards to the echo target.
        let client_conn = Connection::new(client_t, Policy::DenyAll);
        let handle = client_conn.handle();
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local.local_addr().unwrap();
        tokio::spawn(super::super::forward::serve_local_forward(
            local,
            "127.0.0.1".into(),
            target.port(),
            handle,
        ));
        let client = tokio::spawn(async move { client_conn.run(None).await });

        // Drive traffic through the forwarded port.
        let mut app = TcpStream::connect(local_addr).await.unwrap();
        app.write_all(b"tunnel hello").await.unwrap();
        let mut buf = vec![0u8; 12];
        app.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"tunnel hello");

        // A larger payload to exercise window flow control and chunking.
        let big = vec![0x5au8; 500_000];
        app.write_all(&big).await.unwrap();
        let mut got = vec![0u8; big.len()];
        app.read_exact(&mut got).await.unwrap();
        assert_eq!(got, big);

        drop(app);
        drop(client);
        drop(server);
    }

    #[tokio::test]
    async fn policy_denies_disallowed_targets() {
        let target = echo_server().await;
        let (client_t, server_t) = transport_pair().await;

        // Server permits only port 1 — never the echo port.
        let server = tokio::spawn(async move {
            Connection::new(server_t, Policy::Allow(vec![("127.0.0.1".into(), 1)]))
                .run(None)
                .await
        });

        let client_conn = Connection::new(client_t, Policy::DenyAll);
        let handle = client_conn.handle();
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local.local_addr().unwrap();
        tokio::spawn(super::super::forward::serve_local_forward(
            local,
            "127.0.0.1".into(),
            target.port(),
            handle,
        ));
        let _client = tokio::spawn(async move { client_conn.run(None).await });

        // The server refuses the open, so the local connection is closed
        // without any data coming back.
        let mut app = TcpStream::connect(local_addr).await.unwrap();
        app.write_all(b"nope").await.ok();
        let mut buf = [0u8; 8];
        let n = app.read(&mut buf).await.unwrap_or(0);
        assert_eq!(n, 0, "denied forward must not echo data");

        drop(server);
    }
}
