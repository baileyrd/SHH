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

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::AbortHandle;
use tokio::time::MissedTickBehavior;

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
    /// An acceptor asks to open a tunnel channel (`direct-tcpip` for `-L`,
    /// `forwarded-tcpip` for `-R`) carrying an accepted socket. `addr`/`port`
    /// are the open's address fields.
    OpenTunnel {
        channel_type: &'static str,
        addr: String,
        port: u16,
        orig_host: String,
        orig_port: u16,
        stream: TcpStream,
    },
    /// A client asks the server to listen and forward back (`tcpip-forward`).
    RemoteForward {
        bind: String,
        port: u16,
        target_host: String,
        target_port: u16,
    },
    /// A client asks a session channel.
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
    /// Open a direct-tcpip channel (`-L`) for an accepted local connection.
    pub fn open_direct(
        &self,
        target_host: String,
        target_port: u16,
        orig_host: String,
        orig_port: u16,
        stream: TcpStream,
    ) {
        let _ = self.tx.send(Cmd::OpenTunnel {
            channel_type: "direct-tcpip",
            addr: target_host,
            port: target_port,
            orig_host,
            orig_port,
            stream,
        });
    }

    /// Open a forwarded-tcpip channel (`-R`) for a connection accepted on a
    /// server-side listener. `addr`/`port` are the listened address.
    pub fn open_forwarded(
        &self,
        addr: String,
        port: u16,
        orig_host: String,
        orig_port: u16,
        stream: TcpStream,
    ) {
        let _ = self.tx.send(Cmd::OpenTunnel {
            channel_type: "forwarded-tcpip",
            addr,
            port,
            orig_host,
            orig_port,
            stream,
        });
    }

    /// Ask the server to listen on `bind:port` and forward connections back
    /// to `target_host:target_port` (reachable from this side).
    pub fn request_remote_forward(
        &self,
        bind: String,
        port: u16,
        target_host: String,
        target_port: u16,
    ) {
        let _ = self.tx.send(Cmd::RemoteForward {
            bind,
            port,
            target_host,
            target_port,
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

/// A global request we sent with want_reply, awaiting its reply. RFC 4254
/// guarantees replies arrive in request order, so one FIFO queue correlates
/// them regardless of kind.
enum PendingGlobal {
    /// A `tcpip-forward`; on success, register (bind, port) → target.
    Forward {
        bind: String,
        port: u16,
        target: (String, u16),
    },
    /// A `keepalive@openssh.com`; any reply proves the peer is alive.
    Keepalive,
}

/// Default liveness settings: probe after this much silence, and give up
/// after this many unanswered probes (~90s to notice a dead peer).
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const KEEPALIVE_MAX_MISSED: u32 = 3;

/// The connection loop.
pub struct Connection<S> {
    t: Transport<S>,
    /// Gates incoming direct-tcpip opens (`-L` target, server role).
    policy: Policy,
    /// Gates incoming tcpip-forward requests (`-R` listen, server role).
    listen_policy: Policy,
    channels: HashMap<u32, Chan>,
    pending: HashMap<u32, Pending>,
    /// Established remote forwards (client role): server bind → local target.
    remote_forwards: HashMap<(String, u16), (String, u16)>,
    /// Bound server-side listeners (server role), for cancel + teardown.
    listeners: HashMap<(String, u16), AbortHandle>,
    /// Global requests awaiting a reply, in send order.
    pending_global: VecDeque<PendingGlobal>,
    // Liveness.
    keepalive_interval: Option<Duration>,
    keepalive_max_missed: u32,
    keepalive_outstanding: u32,
    /// Set whenever a packet arrives; a keepalive tick clears it.
    recv_since_tick: bool,
    next_id: u32,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    done: bool,
}

impl<S> Drop for Connection<S> {
    fn drop(&mut self) {
        // Stop any server-side remote-forward listeners with the connection.
        for (_, h) in self.listeners.drain() {
            h.abort();
        }
    }
}

/// Await the next tick of an optional interval; pend forever when there is
/// none (keepalives disabled), so the select arm simply never fires.
async fn tick(interval: Option<&mut tokio::time::Interval>) {
    match interval {
        Some(i) => {
            i.tick().await;
        }
        None => std::future::pending().await,
    }
}

/// Map a requested bind address to something bindable.
fn normalize_bind(bind: &str) -> String {
    match bind {
        "" | "*" => "0.0.0.0".to_string(),
        "localhost" => "127.0.0.1".to_string(),
        other => other.to_string(),
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Connection<S> {
    /// Wrap an authenticated transport. `policy` gates *incoming*
    /// direct-tcpip opens (server role); a client passes [`Policy::DenyAll`].
    /// Remote-forward listening is denied until [`Connection::listen_policy`].
    pub fn new(t: Transport<S>, policy: Policy) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        Connection {
            t,
            policy,
            listen_policy: Policy::DenyAll,
            channels: HashMap::new(),
            pending: HashMap::new(),
            remote_forwards: HashMap::new(),
            listeners: HashMap::new(),
            pending_global: VecDeque::new(),
            keepalive_interval: Some(KEEPALIVE_INTERVAL),
            keepalive_max_missed: KEEPALIVE_MAX_MISSED,
            keepalive_outstanding: 0,
            recv_since_tick: true,
            next_id: 0,
            cmd_tx,
            cmd_rx,
            done: false,
        }
    }

    /// Set the policy gating incoming `tcpip-forward` (remote `-R`) requests.
    pub fn listen_policy(mut self, policy: Policy) -> Self {
        self.listen_policy = policy;
        self
    }

    /// Configure liveness probes: send a keepalive after `interval` of
    /// silence and give up after `max_missed` unanswered ones. `interval`
    /// of zero disables keepalives.
    pub fn keepalive(mut self, interval: Duration, max_missed: u32) -> Self {
        self.keepalive_interval = (!interval.is_zero()).then_some(interval);
        self.keepalive_max_missed = max_missed.max(1);
        self
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
        // A liveness ticker (or a never-firing timer when keepalives are off).
        let mut ka = self.keepalive_interval.map(|d| {
            let mut i = tokio::time::interval(d);
            i.set_missed_tick_behavior(MissedTickBehavior::Skip);
            i
        });
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
                pkt = self.t.recv_raw() => {
                    self.recv_since_tick = true;
                    self.on_packet(pkt?).await?;
                }
                cmd = self.cmd_rx.recv() => {
                    // We hold a sender, so this is never None.
                    if let Some(cmd) = cmd {
                        self.on_cmd(cmd).await?;
                    }
                }
                _ = tick(ka.as_mut()) => self.on_keepalive_tick().await?,
            }
        }
        Ok(())
    }

    /// Handle a liveness tick: if nothing arrived since the last tick, probe
    /// the peer; too many unanswered probes means it is gone.
    async fn on_keepalive_tick(&mut self) -> Result<()> {
        if self.recv_since_tick {
            self.recv_since_tick = false;
            self.keepalive_outstanding = 0;
            return Ok(());
        }
        if self.keepalive_outstanding >= self.keepalive_max_missed {
            return Err(Error::Disconnect(format!(
                "peer unresponsive to {} keepalives",
                self.keepalive_outstanding
            )));
        }
        self.keepalive_outstanding += 1;
        self.pending_global.push_back(PendingGlobal::Keepalive);
        let mut w = Writer::new();
        w.byte(msg::GLOBAL_REQUEST);
        w.utf8("keepalive@openssh.com");
        w.boolean(true); // want_reply
        self.t.send(&w.into_bytes()).await
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
            msg::GLOBAL_REQUEST => self.on_global_request(&p).await?,
            msg::REQUEST_SUCCESS => self.on_global_reply(&p, true),
            msg::REQUEST_FAILURE => self.on_global_reply(&p, false),
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
            // Server side of `-L`: connect out to the requested target.
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
                self.spawn_connect(sender, window, max, host, port);
                Ok(())
            }
            // Client side of `-R`: match the listened address to a forward we
            // requested, then connect to its local target.
            "forwarded-tcpip" => {
                let addr = r.utf8()?.to_owned();
                let port = u16::try_from(r.u32()?).map_err(|_| Error::proto("port out of range"))?;
                let _orig_host = r.utf8()?;
                let _orig_port = r.u32()?;
                r.finish()?;
                match self.lookup_remote(&addr, port) {
                    Some((host, tport)) => {
                        self.spawn_connect(sender, window, max, host, tport);
                        Ok(())
                    }
                    None => {
                        tracing::info!(%addr, port, "forwarded-tcpip has no matching request");
                        self.reject_open(
                            sender,
                            open_failure::ADMINISTRATIVELY_PROHIBITED,
                            "no matching remote forward",
                        )
                        .await
                    }
                }
            }
            _ => {
                self.reject_open(sender, open_failure::UNKNOWN_CHANNEL_TYPE, "unsupported channel type")
                    .await
            }
        }
    }

    /// Connect out to `host:port` in a task (so a slow SYN can't stall the
    /// loop), reporting the result back as [`Cmd::Connected`].
    fn spawn_connect(&self, peer_id: u32, peer_window: u32, peer_max: u32, host: String, port: u16) {
        let cmd_tx = self.cmd_tx.clone();
        tokio::spawn(async move {
            let stream = TcpStream::connect((host.as_str(), port)).await;
            if let Ok(s) = &stream {
                s.set_nodelay(true).ok();
            }
            let _ = cmd_tx.send(Cmd::Connected {
                peer_id,
                peer_window,
                peer_max,
                stream,
            });
        });
    }

    /// Find the local target for a `forwarded-tcpip` open, matching the exact
    /// (address, port) first and falling back to any forward on that port.
    fn lookup_remote(&self, addr: &str, port: u16) -> Option<(String, u16)> {
        if let Some(t) = self.remote_forwards.get(&(addr.to_string(), port)) {
            return Some(t.clone());
        }
        self.remote_forwards
            .iter()
            .find(|((_, p), _)| *p == port)
            .map(|(_, v)| v.clone())
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

    // --------------------------------------------------- global requests

    async fn on_global_request(&mut self, p: &[u8]) -> Result<()> {
        let mut r = Reader::new(p);
        r.byte()?;
        let name = r.utf8()?.to_owned();
        let want_reply = r.boolean()?;
        match name.as_str() {
            "tcpip-forward" => {
                let bind = r.utf8()?.to_owned();
                let port = r.u32()?;
                self.handle_tcpip_forward(bind, port, want_reply).await
            }
            "cancel-tcpip-forward" => {
                let bind = r.utf8()?.to_owned();
                let port = u16::try_from(r.u32()?).unwrap_or(0);
                if let Some(h) = self.listeners.remove(&(normalize_bind(&bind), port)) {
                    h.abort();
                    tracing::info!(%bind, port, "remote forward cancelled");
                }
                if want_reply {
                    self.t.send(&[msg::REQUEST_SUCCESS]).await?;
                }
                Ok(())
            }
            _ => {
                if want_reply {
                    self.t.send(&[msg::REQUEST_FAILURE]).await?;
                }
                Ok(())
            }
        }
    }

    /// Server side: honor `tcpip-forward` by binding a listener (subject to
    /// the listen policy) whose connections open forwarded-tcpip channels.
    async fn handle_tcpip_forward(&mut self, bind: String, req_port: u32, want_reply: bool) -> Result<()> {
        let req_port = u16::try_from(req_port).unwrap_or(0);
        // Match the policy against the requested bind and its canonical form,
        // so `--permit-listen 127.0.0.1:PORT` also accepts OpenSSH's default
        // `localhost` bind (and `0.0.0.0` accepts an empty/`*` bind).
        let permitted = self.listen_policy.permits(&bind, req_port)
            || self.listen_policy.permits(&normalize_bind(&bind), req_port);
        if !permitted {
            tracing::info!(%bind, port = req_port, "tcpip-forward refused by policy");
            if want_reply {
                self.t.send(&[msg::REQUEST_FAILURE]).await?;
            }
            return Ok(());
        }
        let addr = normalize_bind(&bind);
        let listener = match TcpListener::bind((addr.as_str(), req_port)).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(%bind, port = req_port, "bind failed: {e}");
                if want_reply {
                    self.t.send(&[msg::REQUEST_FAILURE]).await?;
                }
                return Ok(());
            }
        };
        let actual = listener.local_addr().map(|a| a.port()).unwrap_or(req_port);
        if want_reply {
            let mut w = Writer::new();
            w.byte(msg::REQUEST_SUCCESS);
            // RFC 4254 §7.1: echo the allocated port only when 0 was asked.
            if req_port == 0 {
                w.u32(actual as u32);
            }
            self.t.send(&w.into_bytes()).await?;
        }
        tracing::info!(%bind, port = actual, "listening for remote forward");
        let task = tokio::spawn(forward::serve_remote_listener(
            listener,
            bind.clone(),
            actual,
            self.handle(),
        ));
        self.listeners.insert((addr, actual), task.abort_handle());
        Ok(())
    }

    /// Correlate a global-request reply with the request we sent (replies
    /// arrive in order). A keepalive reply proves liveness; a tcpip-forward
    /// reply registers the forward on success.
    fn on_global_reply(&mut self, p: &[u8], success: bool) {
        match self.pending_global.pop_front() {
            None => {}
            Some(PendingGlobal::Keepalive) => {
                self.keepalive_outstanding = 0;
            }
            Some(PendingGlobal::Forward { bind, port, target }) => {
                if !success {
                    tracing::warn!(%bind, port, "server refused remote forward");
                    return;
                }
                // For a port-0 request the reply carries the allocated port.
                let port = if port == 0 {
                    let mut r = Reader::new(p);
                    let _ = r.byte();
                    r.u32().ok().and_then(|v| u16::try_from(v).ok()).unwrap_or(0)
                } else {
                    port
                };
                tracing::info!(%bind, port, "remote forward established");
                self.remote_forwards.insert((bind, port), target);
            }
        }
    }

    // ---------------------------------------------------- task commands

    async fn on_cmd(&mut self, cmd: Cmd) -> Result<()> {
        match cmd {
            Cmd::OpenTunnel {
                channel_type,
                addr,
                port,
                orig_host,
                orig_port,
                stream,
            } => {
                let id = self.alloc_id();
                self.pending.insert(id, Pending::Direct(stream));
                let mut w = Writer::new();
                w.byte(msg::CHANNEL_OPEN);
                w.utf8(channel_type);
                w.u32(id);
                w.u32(LOCAL_WINDOW);
                w.u32(MAX_CHUNK);
                w.utf8(&addr);
                w.u32(port as u32);
                w.utf8(&orig_host);
                w.u32(orig_port as u32);
                self.t.send(&w.into_bytes()).await?;
            }
            Cmd::RemoteForward {
                bind,
                port,
                target_host,
                target_port,
            } => {
                self.pending_global.push_back(PendingGlobal::Forward {
                    bind: bind.clone(),
                    port,
                    target: (target_host, target_port),
                });
                let mut w = Writer::new();
                w.byte(msg::GLOBAL_REQUEST);
                w.utf8("tcpip-forward");
                w.boolean(true); // want_reply
                w.utf8(&bind);
                w.u32(port as u32);
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
                ClientConfig::with_verifier(Box::new(|_| Ok(()))),
            ),
            Transport::server(b, ServerConfig::with_host_key(host_key)),
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
    async fn dead_peer_detected_by_keepalive() {
        let (client_t, server_t) = transport_pair().await;
        // The peer's socket stays open, but nobody services it — so our
        // keepalives go unanswered.
        let _held = server_t;
        let client = Connection::new(client_t, Policy::DenyAll)
            .keepalive(Duration::from_millis(50), 2);
        let r = tokio::time::timeout(Duration::from_secs(3), client.run(None)).await;
        match r {
            Ok(Err(Error::Disconnect(_))) => {}
            other => panic!("expected a keepalive timeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn keepalives_keep_an_idle_connection_alive() {
        let (client_t, server_t) = transport_pair().await;
        // A live peer answers keepalives, so the client never times out.
        let server = tokio::spawn(
            Connection::new(server_t, Policy::AllowAll)
                .keepalive(Duration::from_millis(50), 2)
                .run(None),
        );
        let client = Connection::new(client_t, Policy::DenyAll)
            .keepalive(Duration::from_millis(50), 2);
        // Running past several keepalive intervals must NOT end the loop;
        // a timeout here means it's healthily still going.
        let r = tokio::time::timeout(Duration::from_millis(500), client.run(None)).await;
        assert!(r.is_err(), "idle connection died despite answered keepalives");
        server.abort();
    }

    #[tokio::test]
    async fn remote_forward_round_trips() {
        // The client asks the server to listen; connections there come back
        // as forwarded-tcpip channels the client splices to a local target.
        let target = echo_server().await; // reachable from the "client"
        let (client_t, server_t) = transport_pair().await;

        // Server permits remote-forward binds.
        let server = tokio::spawn(async move {
            Connection::new(server_t, Policy::DenyAll)
                .listen_policy(Policy::AllowAll)
                .run(None)
                .await
        });

        // Grab a free port for the server's listener, then ask for it.
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rport = probe.local_addr().unwrap().port();
        drop(probe);

        let client_conn = Connection::new(client_t, Policy::DenyAll);
        let handle = client_conn.handle();
        handle.request_remote_forward("127.0.0.1".into(), rport, "127.0.0.1".into(), target.port());
        let client = tokio::spawn(async move { client_conn.run(None).await });

        // Connect to the server-side port (retry until it's bound), then
        // exercise the reverse tunnel end to end.
        let mut app = loop {
            match TcpStream::connect(("127.0.0.1", rport)).await {
                Ok(s) => break s,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
            }
        };
        app.write_all(b"reverse").await.unwrap();
        let mut buf = [0u8; 7];
        app.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"reverse");

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
