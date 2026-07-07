//! Channel multiplexer: the one connection loop for sessions *and*
//! `direct-tcpip` forwarding.
//!
//! A [`Connection`] owns the transport and is the sole reader and writer of
//! it. Every channel — a session or a forwarded socket — runs in its own
//! task and talks to the loop over channels: an unbounded queue for
//! inbound events, a shared [`Semaphore`] of send-window credits, and a
//! command channel back to the loop. Flow control stays honest: a slow
//! consumer stops sending `Consumed`, the receive window closes, the peer
//! stops sending; a closed send window blocks the task's credit
//! acquisition, applying backpressure to the origin.
//!
//! Sessions and forwards share this machinery, so any mix of them rides one
//! connection. Session-specific traffic (channel requests, extended data,
//! request replies) flows over the same task channels.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};

use super::forward::{self, Policy};
use super::session::{self, SessionSpec};
use super::{
    chan, data_packet, ext_data_packet, open_failure, simple, window_adjust, LOCAL_WINDOW,
    MAX_CHUNK, WINDOW_REFILL,
};
use crate::transport::Transport;
use crate::wire::{disconnect, msg, Reader, Writer};
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
    /// A client asks to open a session channel.
    OpenSession(Box<SessionSpec>),
    /// Result of a server-side connect for an incoming direct-tcpip open.
    Connected {
        peer_id: u32,
        peer_window: u32,
        peer_max: u32,
        stream: std::io::Result<TcpStream>,
    },
    /// Channel data cleared to send (send-window credit already spent).
    Data { id: u32, bytes: Vec<u8> },
    /// Extended data (e.g. stderr); credit already spent.
    ExtData { id: u32, kind: u32, bytes: Vec<u8> },
    /// Send a CHANNEL_REQUEST; `body` is everything after the recipient
    /// field (`string(kind) ‖ bool(want_reply) ‖ type-specific`).
    ChannelRequest { id: u32, body: Vec<u8> },
    /// Reply to an incoming channel request.
    RequestReply { id: u32, success: bool },
    /// The task reached EOF on its outbound stream.
    Eof { id: u32 },
    /// The task finished; tear the channel down.
    Close { id: u32 },
    /// `n` received bytes were consumed; replenish the receive window.
    Consumed { id: u32, n: u32 },
}

/// Messages the loop pushes to a channel task.
pub(crate) enum ToTask {
    Data(Vec<u8>),
    ExtData(u32, Vec<u8>),
    Eof,
    Close,
    /// An incoming CHANNEL_REQUEST for this channel.
    Request {
        kind: String,
        want_reply: bool,
        data: Vec<u8>,
    },
    /// CHANNEL_SUCCESS (true) / CHANNEL_FAILURE (false) for a request we sent.
    RequestReply(bool),
}

/// A submission handle for opening channels from outside the loop.
#[derive(Clone)]
pub struct Handle {
    tx: mpsc::UnboundedSender<Cmd>,
}

impl Handle {
    /// Request a direct-tcpip channel for an accepted local connection.
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

    /// Request a session channel.
    pub fn open_session(&self, spec: SessionSpec) {
        let _ = self.tx.send(Cmd::OpenSession(Box::new(spec)));
    }
}

struct Chan {
    peer_id: u32,
    is_session: bool,
    /// End the whole connection when this channel closes.
    end_on_close: bool,
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

enum Pending {
    Direct(TcpStream),
    Session(Box<SessionSpec>),
}

/// The connection loop.
pub struct Connection<S> {
    t: Transport<S>,
    policy: Policy,
    channels: HashMap<u32, Chan>,
    pending: HashMap<u32, Pending>,
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

    /// A handle for opening channels from outside the loop.
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
            msg::CHANNEL_DATA => self.on_data(&p)?,
            msg::CHANNEL_EXTENDED_DATA => self.on_ext_data(&p)?,
            msg::CHANNEL_WINDOW_ADJUST => self.on_window_adjust(&p)?,
            msg::CHANNEL_EOF => self.on_eof(&p)?,
            msg::CHANNEL_CLOSE => self.on_close(&p).await?,
            msg::CHANNEL_REQUEST => self.on_channel_request(&p).await?,
            msg::CHANNEL_SUCCESS => self.on_request_reply(&p, true),
            msg::CHANNEL_FAILURE => self.on_request_reply(&p, false),
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

        match kind.as_str() {
            "session" => {
                let id = self.alloc_id();
                let mut w = chan(msg::CHANNEL_OPEN_CONFIRMATION, sender);
                w.u32(id);
                w.u32(LOCAL_WINDOW);
                w.u32(MAX_CHUNK);
                self.t.send(&w.into_bytes()).await?;
                self.spawn_session_server(id, sender, window, max);
                Ok(())
            }
            "direct-tcpip" => {
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
                // Connect out in a task so a slow SYN can't stall the loop.
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
            _ => {
                self.reject_open(sender, open_failure::UNKNOWN_CHANNEL_TYPE, "unsupported channel type")
                    .await
            }
        }
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
        match pending {
            Pending::Direct(stream) => self.spawn_forward(ours, peer, window, max, stream),
            Pending::Session(spec) => self.spawn_session_client(ours, peer, window, max, *spec),
        }
        Ok(())
    }

    fn on_open_failure(&mut self, p: &[u8]) -> Result<()> {
        let mut r = Reader::new(p);
        r.byte()?;
        let ours = r.u32()?;
        let _reason = r.u32()?;
        let desc = r.utf8().unwrap_or("no reason given");
        tracing::info!(channel = ours, "channel open refused: {desc}");
        // Dropping a pending session's oneshot lets the client learn it
        // failed; dropping a pending forward closes the local connection.
        self.pending.remove(&ours);
        Ok(())
    }

    fn on_data(&mut self, p: &[u8]) -> Result<()> {
        let mut r = Reader::new(p);
        r.byte()?;
        let id = r.u32()?;
        let data = r.string()?;
        let Some(ch) = self.channels.get_mut(&id) else {
            return Ok(());
        };
        let len = u32::try_from(data.len()).map_err(|_| Error::proto("data too large"))?;
        ch.local_window = ch
            .local_window
            .checked_sub(len)
            .ok_or_else(|| Error::proto("peer overflowed the channel window"))?;
        let _ = ch.to_task.send(ToTask::Data(data.to_vec()));
        Ok(())
    }

    fn on_ext_data(&mut self, p: &[u8]) -> Result<()> {
        let mut r = Reader::new(p);
        r.byte()?;
        let id = r.u32()?;
        let kind = r.u32()?;
        let data = r.string()?;
        let Some(ch) = self.channels.get_mut(&id) else {
            return Ok(());
        };
        let len = u32::try_from(data.len()).map_err(|_| Error::proto("data too large"))?;
        ch.local_window = ch
            .local_window
            .checked_sub(len)
            .ok_or_else(|| Error::proto("peer overflowed the channel window"))?;
        let _ = ch.to_task.send(ToTask::ExtData(kind, data.to_vec()));
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
            self.close_if_done(id).await?;
        }
        Ok(())
    }

    async fn on_channel_request(&mut self, p: &[u8]) -> Result<()> {
        let mut r = Reader::new(p);
        r.byte()?;
        let id = r.u32()?;
        let kind = r.utf8()?.to_owned();
        let want_reply = r.boolean()?;
        let data = r.rest().to_vec();
        match self.channels.get(&id) {
            Some(ch) if ch.is_session => {
                let _ = ch.to_task.send(ToTask::Request {
                    kind,
                    want_reply,
                    data,
                });
            }
            Some(ch) => {
                // A forwarded stream grants no requests.
                if want_reply {
                    let peer = ch.peer_id;
                    self.t.send(&simple(msg::CHANNEL_FAILURE, peer)).await?;
                }
            }
            None => {}
        }
        Ok(())
    }

    fn on_request_reply(&mut self, p: &[u8], success: bool) {
        let mut r = Reader::new(p);
        let _ = r.byte();
        if let Ok(id) = r.u32() {
            if let Some(ch) = self.channels.get(&id) {
                let _ = ch.to_task.send(ToTask::RequestReply(success));
            }
        }
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
                self.pending.insert(id, Pending::Direct(stream));
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
            Cmd::OpenSession(spec) => {
                let id = self.alloc_id();
                self.pending.insert(id, Pending::Session(spec));
                let mut w = Writer::new();
                w.byte(msg::CHANNEL_OPEN);
                w.utf8("session");
                w.u32(id);
                w.u32(LOCAL_WINDOW);
                w.u32(MAX_CHUNK);
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
                    self.spawn_forward(id, peer_id, peer_window, peer_max, sock);
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
            Cmd::ExtData { id, kind, bytes } => {
                if let Some(ch) = self.channels.get(&id) {
                    let peer = ch.peer_id;
                    self.t.send(&ext_data_packet(peer, kind, &bytes)).await?;
                }
            }
            Cmd::ChannelRequest { id, body } => {
                if let Some(ch) = self.channels.get(&id) {
                    let mut w = chan(msg::CHANNEL_REQUEST, ch.peer_id);
                    w.raw(&body);
                    self.t.send(&w.into_bytes()).await?;
                }
            }
            Cmd::RequestReply { id, success } => {
                if let Some(ch) = self.channels.get(&id) {
                    let byte = if success {
                        msg::CHANNEL_SUCCESS
                    } else {
                        msg::CHANNEL_FAILURE
                    };
                    self.t.send(&simple(byte, ch.peer_id)).await?;
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
                    self.close_if_done(id).await?;
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

    // ------------------------------------------------------ channel setup

    fn insert_chan(
        &mut self,
        id: u32,
        peer_id: u32,
        peer_window: u32,
        is_session: bool,
        end_on_close: bool,
    ) -> (Arc<Semaphore>, u32, mpsc::UnboundedReceiver<ToTask>) {
        let credit = Arc::new(Semaphore::new(peer_window as usize));
        let (to_task_tx, to_task_rx) = mpsc::unbounded_channel();
        self.channels.insert(
            id,
            Chan {
                peer_id,
                is_session,
                end_on_close,
                credit: credit.clone(),
                local_window: LOCAL_WINDOW,
                pending_consumed: 0,
                to_task: to_task_tx,
                sent_eof: false,
                sent_close: false,
                peer_closed: false,
            },
        );
        (credit, peer_window, to_task_rx)
    }

    fn spawn_forward(&mut self, id: u32, peer_id: u32, peer_window: u32, peer_max: u32, stream: TcpStream) {
        let (credit, _, rx) = self.insert_chan(id, peer_id, peer_window, false, false);
        let remote_max = peer_max.clamp(1, MAX_CHUNK);
        tokio::spawn(forward::forward_task(
            id,
            stream,
            credit,
            remote_max,
            rx,
            self.cmd_tx.clone(),
        ));
    }

    fn spawn_session_server(&mut self, id: u32, peer_id: u32, peer_window: u32, peer_max: u32) {
        let (credit, _, rx) = self.insert_chan(id, peer_id, peer_window, true, false);
        let remote_max = peer_max.clamp(1, MAX_CHUNK);
        tokio::spawn(session::session_server_task(
            id,
            credit,
            remote_max,
            rx,
            self.cmd_tx.clone(),
        ));
    }

    fn spawn_session_client(
        &mut self,
        id: u32,
        peer_id: u32,
        peer_window: u32,
        peer_max: u32,
        spec: SessionSpec,
    ) {
        let end_on_close = spec.end_connection_on_close;
        let (credit, _, rx) = self.insert_chan(id, peer_id, peer_window, true, end_on_close);
        let remote_max = peer_max.clamp(1, MAX_CHUNK);
        tokio::spawn(session::session_client_task(
            id,
            spec,
            credit,
            remote_max,
            rx,
            self.cmd_tx.clone(),
        ));
    }

    /// Remove a channel once both sides have closed. If it was the
    /// connection's terminal channel (a foreground session), say goodbye
    /// and stop the loop.
    async fn close_if_done(&mut self, id: u32) -> Result<()> {
        let terminal = match self.channels.get(&id) {
            Some(ch) if ch.sent_close && ch.peer_closed => {
                let terminal = ch.end_on_close;
                self.channels.remove(&id);
                terminal
            }
            _ => return Ok(()),
        };
        if terminal {
            self.t
                .disconnect(disconnect::BY_APPLICATION, "session closed")
                .await
                .ok();
            self.done = true;
        }
        Ok(())
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

        let server =
            tokio::spawn(async move { Connection::new(server_t, Policy::AllowAll).run(None).await });

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

        let mut app = TcpStream::connect(local_addr).await.unwrap();
        app.write_all(b"tunnel hello").await.unwrap();
        let mut buf = vec![0u8; 12];
        app.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"tunnel hello");

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
    async fn session_and_forward_share_one_connection() {
        use super::super::session::SessionSpec;
        use std::pin::Pin;
        use std::sync::{Arc, Mutex};
        use std::task::{Context, Poll};
        use tokio::sync::oneshot;

        // A shareable stdout sink for the session.
        #[derive(Clone)]
        struct VecSink(Arc<Mutex<Vec<u8>>>);
        impl AsyncWrite for VecSink {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                b: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                self.0.lock().unwrap().extend_from_slice(b);
                Poll::Ready(Ok(b.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let target = echo_server().await;
        let (client_t, server_t) = transport_pair().await;
        let server =
            tokio::spawn(async move { Connection::new(server_t, Policy::AllowAll).run(None).await });

        let client_conn = Connection::new(client_t, Policy::DenyAll);
        let handle = client_conn.handle();

        // A forward to the echo target...
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local.local_addr().unwrap();
        tokio::spawn(super::super::forward::serve_local_forward(
            local,
            "127.0.0.1".into(),
            target.port(),
            handle.clone(),
        ));

        // ...and, on the same connection, a session that echoes five bytes
        // of stdin. It does NOT end the connection, so the forward lives on.
        let out = Arc::new(Mutex::new(Vec::new()));
        let (exit_tx, exit_rx) = oneshot::channel();
        handle.open_session(SessionSpec {
            command: Some("head -c 5".into()),
            pty: None,
            resize: None,
            stdin: Box::new(&b"hello world"[..]),
            stdout: Box::new(VecSink(out.clone())),
            stderr: Box::new(tokio::io::sink()),
            exit: exit_tx,
            end_connection_on_close: false,
        });
        let client = tokio::spawn(async move { client_conn.run(None).await });

        // The forward round-trips while the session is live.
        let mut app = TcpStream::connect(local_addr).await.unwrap();
        app.write_all(b"tunnel").await.unwrap();
        let mut buf = [0u8; 6];
        app.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"tunnel");

        // The session delivered its output and a clean exit.
        let status = exit_rx.await.unwrap();
        assert_eq!(status.code, Some(0));
        assert_eq!(&*out.lock().unwrap(), b"hello");

        // The forward is still usable after the session ended.
        let mut app2 = TcpStream::connect(local_addr).await.unwrap();
        app2.write_all(b"again").await.unwrap();
        let mut buf2 = [0u8; 5];
        app2.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"again");

        drop(app);
        drop(client);
        drop(server);
    }

    #[tokio::test]
    async fn policy_denies_disallowed_targets() {
        let target = echo_server().await;
        let (client_t, server_t) = transport_pair().await;

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

        let mut app = TcpStream::connect(local_addr).await.unwrap();
        app.write_all(b"nope").await.ok();
        let mut buf = [0u8; 8];
        let n = app.read(&mut buf).await.unwrap_or(0);
        assert_eq!(n, 0, "denied forward must not echo data");

        drop(server);
    }
}
