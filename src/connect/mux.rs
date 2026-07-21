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
    MAX_CHUNK, WINDOW_MAX, WINDOW_REFILL,
};
use crate::transport::Transport;
use crate::wire::{disconnect, msg, Reader, Writer};
use crate::{Error, Result};

/// The channel type for forwarded agent connections (OpenSSH extension).
/// Its CHANNEL_OPEN carries no type-specific fields.
pub(crate) const AGENT_CHANNEL: &str = "auth-agent@openssh.com";

/// A client's `session-bind@openssh.com` material for the hop it made: the
/// server's host-key blob, the session id, and the host's signature over it.
/// When forwarding an agent (`-A`), the client replays this onto each
/// relayed agent connection so the agent sees the full path the request
/// traversed — the basis for multi-hop destination constraints.
#[derive(Clone)]
pub struct AgentBind {
    pub host_blob: Vec<u8>,
    pub session_id: Vec<u8>,
    pub sig: Vec<u8>,
}

/// Any byte stream a tunnel channel can splice — a TCP socket for the
/// `-L`/`-R` forwards, a Unix socket for a forwarded agent.
pub(crate) trait TunnelIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TunnelIo for T {}
pub(crate) type BoxedIo = Box<dyn TunnelIo>;

/// Commands from channel tasks and forward acceptors to the loop.
pub(crate) enum Cmd {
    /// An acceptor asks to open a tunnel channel (`direct-tcpip` for `-L`,
    /// `forwarded-tcpip` for `-R`, [`AGENT_CHANNEL`] for agent forwarding)
    /// carrying an accepted socket. `addr`/`port` are the open's address
    /// fields; the agent channel type has none and ignores them.
    OpenTunnel {
        channel_type: &'static str,
        addr: String,
        port: u16,
        orig_host: String,
        orig_port: u16,
        stream: BoxedIo,
        /// Held from the moment a socket is accepted until this command is
        /// dequeued and processed (dropped implicitly at the end of the
        /// `on_cmd` match arm). `cmd_tx` is unbounded, so without this an
        /// acceptor that outpaces the loop — e.g. the loop stalled on a
        /// slow peer — would queue accepted sockets without limit. This
        /// permit is what makes acceptance actually back off instead.
        _permit: tokio::sync::OwnedSemaphorePermit,
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
    /// Result of a local connect for an incoming tunnel open (the server's
    /// direct-tcpip target, or the client's agent socket).
    Connected {
        peer_id: u32,
        peer_window: u32,
        peer_max: u32,
        stream: std::io::Result<BoxedIo>,
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

/// Cap on `Cmd::OpenTunnel` commands accepted-but-not-yet-processed by the
/// loop, shared by every acceptor on a connection (`-L`, `-R`, and agent
/// forwarding). Bounds how many already-accepted sockets can pile up when
/// the loop is slow to drain its (unbounded, for the rest of `Cmd`) queue.
const MAX_PENDING_OPENS: usize = 64;

/// A submission handle for opening channels from outside the loop.
#[derive(Clone)]
pub struct Handle {
    tx: mpsc::UnboundedSender<Cmd>,
    open_admission: Arc<Semaphore>,
}

impl Handle {
    /// Open a direct-tcpip channel (`-L`) for an accepted local connection.
    /// Waits for admission if `MAX_PENDING_OPENS` opens are already queued,
    /// so a stalled loop applies backpressure to the accept loop rather than
    /// letting accepted sockets pile up unboundedly.
    pub async fn open_direct(
        &self,
        target_host: String,
        target_port: u16,
        orig_host: String,
        orig_port: u16,
        stream: TcpStream,
    ) {
        let Ok(_permit) = self.open_admission.clone().acquire_owned().await else {
            return; // the connection is gone; nothing to open onto
        };
        let _ = self.tx.send(Cmd::OpenTunnel {
            channel_type: "direct-tcpip",
            addr: target_host,
            port: target_port,
            orig_host,
            orig_port,
            stream: Box::new(stream),
            _permit,
        });
    }

    /// Open a forwarded-tcpip channel (`-R`) for a connection accepted on a
    /// server-side listener. `addr`/`port` are the listened address. See
    /// [`Handle::open_direct`] for the admission wait.
    pub async fn open_forwarded(
        &self,
        addr: String,
        port: u16,
        orig_host: String,
        orig_port: u16,
        stream: TcpStream,
    ) {
        let Ok(_permit) = self.open_admission.clone().acquire_owned().await else {
            return;
        };
        let _ = self.tx.send(Cmd::OpenTunnel {
            channel_type: "forwarded-tcpip",
            addr,
            port,
            orig_host,
            orig_port,
            stream: Box::new(stream),
            _permit,
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
    Direct(BoxedIo),
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

/// Ceiling on a single outbound TCP connect for a `direct-tcpip`/
/// `forwarded-tcpip` open. Without it, a peer directing us at a
/// black-holed address ties up a connect task (and its pending channel
/// slot) for the OS's SYN-retry ceiling, often well over a minute.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Cap on channels (pending + established + in-flight connects, see
/// `pending_connects`) an authenticated peer may have open on one
/// connection at a time, so a peer opening channels faster than they're
/// serviced (e.g. many direct-tcpip opens to unreachable targets) can't
/// exhaust file descriptors or memory without bound.
const MAX_CHANNELS: usize = 256;

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
    /// The account server-side sessions run as (privilege drop when root).
    session_user: Option<super::UserContext>,
    /// Server role: a `force-command` from the client's certificate. When
    /// set, every session runs this command instead of the client's request.
    force_command: Option<String>,
    /// Client role: the local agent socket to splice [`AGENT_CHANNEL`]
    /// opens to (`-A`). `None` refuses such opens.
    agent_path: Option<std::path::PathBuf>,
    /// Client role: this hop's binding, replayed onto each relayed agent
    /// connection so a forwarded agent records the whole path (`-A`).
    agent_bind: Option<AgentBind>,
    /// Server role: whether sessions may request agent forwarding.
    permit_agent: bool,
    next_id: u32,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    /// Admission control for `Cmd::OpenTunnel`; see [`MAX_PENDING_OPENS`].
    open_admission: Arc<Semaphore>,
    /// `direct-tcpip`/`forwarded-tcpip`/agent connects spawned but not yet
    /// resolved to a `Cmd::Connected`. Counted toward `MAX_CHANNELS`
    /// alongside `channels`/`pending`: without this, a peer's open is
    /// invisible to that cap for as long as `spawn_connect` takes to
    /// resolve (up to `CONNECT_TIMEOUT`), letting it spawn unbounded
    /// concurrent connect attempts by opening faster than any one resolves.
    pending_connects: usize,
    done: bool,
}

impl<S> Drop for Connection<S> {
    fn drop(&mut self) {
        // Stop any server-side remote-forward listeners with the connection.
        for (_, h) in self.listeners.drain() {
            h.abort();
        }
        // Wake any per-channel task blocked on send-window credit so it can
        // observe teardown and unwind, instead of hanging on the socket /
        // child process it owns.
        for (_, ch) in self.channels.drain() {
            ch.credit.close();
        }
        // Wake any acceptor blocked waiting for open-admission so it stops
        // accepting for a connection that no longer exists, rather than
        // hanging until its next accepted socket is dropped by a timeout.
        self.open_admission.close();
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

/// Write one `session-bind@openssh.com` request for `bind` onto a freshly
/// connected agent socket and read its reply, before any downstream traffic
/// flows. `is_forwarding` is true: this connection is a forwarded one.
#[cfg(unix)] // only the (unix) agent-splice path injects bindings
async fn inject_bind<S>(io: &mut S, bind: &AgentBind) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut w = Writer::new();
    w.byte(crate::agent::num::EXTENSION);
    w.utf8("session-bind@openssh.com");
    w.string(&bind.host_blob);
    w.string(&bind.session_id);
    w.string(&bind.sig);
    w.boolean(true);
    crate::agent::write_frame(io, &w.into_bytes()).await?;
    // Drain the SUCCESS/FAILURE so the downstream sees a clean stream.
    crate::agent::read_frame(io).await?;
    Ok(())
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
            session_user: None,
            force_command: None,
            agent_path: None,
            agent_bind: None,
            permit_agent: false,
            next_id: 0,
            cmd_tx,
            cmd_rx,
            open_admission: Arc::new(Semaphore::new(MAX_PENDING_OPENS)),
            pending_connects: 0,
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

    /// Run server-side sessions as this account (privilege drop when root).
    pub fn session_user(mut self, user: Option<super::UserContext>) -> Self {
        self.session_user = user;
        self
    }

    /// Server role: pin every session to this command (the certificate's
    /// `force-command` critical option), overriding whatever the client asks.
    pub fn force_command(mut self, command: Option<String>) -> Self {
        self.force_command = command;
        self
    }

    /// Client role: splice server-opened agent channels to the agent socket
    /// at `path` (`-A`). Without this, such opens are refused.
    pub fn agent_forward(mut self, path: Option<std::path::PathBuf>) -> Self {
        self.agent_path = path;
        self
    }

    /// Client role: this hop's binding, replayed onto each relayed agent
    /// connection so a forwarded agent learns the full path (multi-hop
    /// destination constraints). Only meaningful alongside `agent_forward`.
    pub fn agent_bind(mut self, bind: Option<AgentBind>) -> Self {
        self.agent_bind = bind;
        self
    }

    /// Server role: allow sessions to request agent forwarding (default:
    /// refused, consistent with the tcpip forwarding allowlists).
    pub fn permit_agent_forward(mut self, permit: bool) -> Self {
        self.permit_agent = permit;
        self
    }

    /// A handle for opening channels from outside the loop.
    pub fn handle(&self) -> Handle {
        Handle {
            tx: self.cmd_tx.clone(),
            open_admission: self.open_admission.clone(),
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

        if self.channels.len() + self.pending.len() + self.pending_connects >= MAX_CHANNELS {
            tracing::info!(%kind, "channel open refused: at MAX_CHANNELS");
            return self
                .reject_open(sender, open_failure::ADMINISTRATIVELY_PROHIBITED, "too many open channels")
                .await;
        }

        match kind.as_str() {
            // Serving sessions means child processes and ptys — Unix
            // machinery. A Windows build acts only as a client, so an
            // incoming session open is refused there.
            #[cfg(unix)]
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
            #[cfg(not(unix))]
            "session" => {
                self.reject_open(
                    sender,
                    open_failure::UNKNOWN_CHANNEL_TYPE,
                    "sessions are not served on this platform",
                )
                .await
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
            // Client side of `-A`: the server relays a connection from a
            // remote process back to our local agent. Agent sockets are Unix
            // sockets; a Windows client never offers -A, so any such open is
            // unsolicited and refused.
            AGENT_CHANNEL => {
                r.finish()?;
                #[cfg(unix)]
                if let Some(path) = self.agent_path.clone() {
                    self.spawn_connect_agent(sender, window, max, path, self.agent_bind.clone());
                    return Ok(());
                }
                tracing::info!("agent channel refused (forwarding not requested)");
                self.reject_open(
                    sender,
                    open_failure::ADMINISTRATIVELY_PROHIBITED,
                    "agent forwarding was not requested",
                )
                .await
            }
            _ => {
                self.reject_open(sender, open_failure::UNKNOWN_CHANNEL_TYPE, "unsupported channel type")
                    .await
            }
        }
    }

    /// Connect out to `host:port` in a task (so a slow SYN can't stall the
    /// loop), reporting the result back as [`Cmd::Connected`]. Bounded by
    /// [`CONNECT_TIMEOUT`]: without it, a peer directing us at a black-holed
    /// address ties up this task (and the channel slot it's pending on) for
    /// the OS's SYN-retry ceiling, often well over a minute.
    ///
    /// Counts toward `MAX_CHANNELS` via `pending_connects` from the moment
    /// this is called until `Cmd::Connected` resolves it (in `on_cmd`):
    /// without that, an open is invisible to the cap for the entire time its
    /// connect is in flight, letting a peer spawn unbounded concurrent
    /// attempts by opening faster than any one resolves.
    fn spawn_connect(&mut self, peer_id: u32, peer_window: u32, peer_max: u32, host: String, port: u16) {
        self.pending_connects += 1;
        let cmd_tx = self.cmd_tx.clone();
        tokio::spawn(async move {
            let stream = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port))).await {
                Ok(result) => result,
                Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out")),
            };
            if let Ok(s) = &stream {
                s.set_nodelay(true).ok();
            }
            let _ = cmd_tx.send(Cmd::Connected {
                peer_id,
                peer_window,
                peer_max,
                stream: stream.map(|s| Box::new(s) as BoxedIo),
            });
        });
    }

    /// Connect to the local agent socket for an accepted agent channel. See
    /// [`Connection::spawn_connect`] for the `pending_connects` accounting.
    #[cfg(unix)]
    fn spawn_connect_agent(
        &mut self,
        peer_id: u32,
        peer_window: u32,
        peer_max: u32,
        path: std::path::PathBuf,
        bind: Option<AgentBind>,
    ) {
        self.pending_connects += 1;
        let cmd_tx = self.cmd_tx.clone();
        tokio::spawn(async move {
            let stream = match tokio::net::UnixStream::connect(&path).await {
                Ok(mut s) => {
                    // Replay our own hop onto the connection before the
                    // downstream talks, so the agent records the full path
                    // (our host, then the downstream's). Best-effort: an
                    // agent that rejects it just won't enforce path
                    // constraints — endpoint constraints still hold via the
                    // downstream's own bind.
                    if let Some(b) = &bind {
                        if let Err(e) = inject_bind(&mut s, b).await {
                            tracing::info!("agent session-bind injection failed: {e}");
                        }
                    }
                    Ok(s)
                }
                Err(e) => Err(e),
            };
            let _ = cmd_tx.send(Cmd::Connected {
                peer_id,
                peer_window,
                peer_max,
                stream: stream.map(|s| Box::new(s) as BoxedIo),
            });
        });
    }

    /// Find the local target for a `forwarded-tcpip` open. Matches the exact
    /// (address, port) the client requested, then a wildcard bind on that
    /// port. It deliberately does *not* fall back to an arbitrary forward on
    /// the same port bound under a different address, which would let a server
    /// steer a reverse connection to the wrong local target.
    fn lookup_remote(&self, addr: &str, port: u16) -> Option<(String, u16)> {
        if let Some(t) = self.remote_forwards.get(&(addr.to_string(), port)) {
            return Some(t.clone());
        }
        for wild in ["", "0.0.0.0", "::", "*"] {
            if let Some(t) = self.remote_forwards.get(&(wild.to_string(), port)) {
                return Some(t.clone());
            }
        }
        None
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
        // A refused *terminal* session (`end_connection_on_close`, e.g.
        // `client_session`'s one-shot wrapper) never gets a `Chan` entry, so
        // `close_if_done` can never see it and end the loop — without this,
        // a server that refuses the only session this connection exists for
        // leaves `run()` parked forever waiting on a peer that has nothing
        // left to say either.
        if let Some(Pending::Session(spec)) = self.pending.remove(&ours) {
            if spec.end_connection_on_close {
                self.done = true;
            }
        }
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
            // RFC 4254 caps the send window at 2^32-1. Clamp additions to that
            // ceiling — and to what the semaphore itself can hold — so a peer
            // cannot drive the tokio Semaphore past `Semaphore::MAX_PERMITS`,
            // which would panic the process.
            let ceiling = (WINDOW_MAX as usize).min(Semaphore::MAX_PERMITS);
            let current = ch.credit.available_permits();
            let headroom = ceiling.saturating_sub(current);
            let grant = (add as usize).min(headroom);
            if grant > 0 {
                ch.credit.add_permits(grant);
            }
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
            // A forwarded stream grants no requests.
            Some(ch) if want_reply => {
                let peer = ch.peer_id;
                self.t.send(&simple(msg::CHANNEL_FAILURE, peer)).await?;
            }
            Some(_) | None => {}
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
        let handle = task.abort_handle();
        // Index under the actual allocated port, and — for a port-0 request —
        // also under the requested port so `cancel-tcpip-forward` keyed on the
        // originally requested (bind, 0) still finds the listener.
        if req_port != actual {
            self.listeners.insert((addr.clone(), req_port), handle.clone());
        }
        self.listeners.insert((addr, actual), handle);
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
                _permit,
            } => {
                // Mirrors the MAX_CHANNELS check in on_channel_open, applied
                // here to our own outgoing opens: without it, this side could
                // grow `pending` past the cap purely from local accept-loop
                // traffic while a slow peer sits on its replies. Dropping
                // `stream` (by falling out of scope) closes the accepted
                // socket, the same fail-safe the peer-initiated path takes.
                if self.channels.len() + self.pending.len() + self.pending_connects >= MAX_CHANNELS {
                    tracing::info!(%channel_type, "local channel open dropped: at MAX_CHANNELS");
                    return Ok(());
                }
                let id = self.alloc_id();
                self.pending.insert(id, Pending::Direct(stream));
                let mut w = Writer::new();
                w.byte(msg::CHANNEL_OPEN);
                w.utf8(channel_type);
                w.u32(id);
                w.u32(LOCAL_WINDOW);
                w.u32(MAX_CHUNK);
                // The agent channel type carries no type-specific fields.
                if channel_type != AGENT_CHANNEL {
                    w.utf8(&addr);
                    w.u32(port as u32);
                    w.utf8(&orig_host);
                    w.u32(orig_port as u32);
                }
                self.t.send(&w.into_bytes()).await?;
                // `_permit` drops here, releasing this command's admission
                // slot now that it's been fully processed.
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
                // Dropping `spec` here (falling out of scope) drops its
                // `exit` oneshot sender, which the caller (client_session /
                // client_subsystem) already treats as "session ended
                // without an exit status" -- a clean, already-handled error.
                if self.channels.len() + self.pending.len() + self.pending_connects >= MAX_CHANNELS {
                    tracing::info!("local session open dropped: at MAX_CHANNELS");
                    return Ok(());
                }
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
            } => {
                // Resolves the reservation `spawn_connect`/`spawn_connect_agent`
                // made against MAX_CHANNELS, whichever way the connect went.
                self.pending_connects = self.pending_connects.saturating_sub(1);
                match stream {
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
                }
            }
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
        // Clamp the initial window to what the semaphore can hold; on a 32-bit
        // target `Semaphore::MAX_PERMITS` (2^29) is below a u32 window, so a
        // peer's CHANNEL_OPEN could otherwise advertise a value that panics.
        let credit = Arc::new(Semaphore::new(
            (peer_window as usize).min(Semaphore::MAX_PERMITS),
        ));
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

    fn spawn_forward(&mut self, id: u32, peer_id: u32, peer_window: u32, peer_max: u32, stream: BoxedIo) {
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

    #[cfg(unix)]
    fn spawn_session_server(&mut self, id: u32, peer_id: u32, peer_window: u32, peer_max: u32) {
        let (credit, _, rx) = self.insert_chan(id, peer_id, peer_window, true, false);
        let remote_max = peer_max.clamp(1, MAX_CHUNK);
        tokio::spawn(session::session_server_task(
            id,
            credit,
            remote_max,
            rx,
            self.cmd_tx.clone(),
            self.open_admission.clone(),
            self.session_user.clone(),
            self.force_command.clone(),
            self.permit_agent,
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
                // Closing the semaphore wakes a task blocked in
                // `acquire_many` on the peer's exhausted send window, so it
                // returns `Err` and unwinds rather than leaking.
                ch.credit.close();
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

    /// Draining every `open_admission` permit simulates `MAX_PENDING_OPENS`
    /// `Cmd::OpenTunnel`s already queued and unprocessed; a further acceptor
    /// must then wait rather than pile up an unbounded number of accepted
    /// sockets. Dropping the `Connection` must wake that waiter (via
    /// `Semaphore::close` in `Connection::drop`) instead of leaving it
    /// blocked forever on a connection that no longer exists.
    #[tokio::test]
    async fn open_admission_blocks_then_unblocks_on_connection_drop() {
        let (client_t, _server_t) = transport_pair().await;
        let conn = Connection::new(client_t, Policy::DenyAll);

        let mut held = Vec::with_capacity(MAX_PENDING_OPENS);
        for _ in 0..MAX_PENDING_OPENS {
            held.push(conn.open_admission.clone().try_acquire_owned().unwrap());
        }
        assert!(
            conn.open_admission.clone().try_acquire_owned().is_err(),
            "admission should be fully drained"
        );

        let admission = conn.open_admission.clone();
        let waiter = tokio::spawn(async move { admission.acquire_owned().await });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished(), "waiter should still be blocked on admission");

        // Deliberately keep `held` alive: the point is that closing the
        // semaphore on connection teardown wakes the waiter even though no
        // permit was actually freed.
        drop(conn);

        let outcome = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("waiter should unblock once the connection drops")
            .unwrap();
        assert!(outcome.is_err(), "acquire should fail: the semaphore is closed");
    }

    /// A peer opening channels faster than they're serviced (e.g. many
    /// direct-tcpip opens to unreachable targets) must eventually be refused
    /// rather than let `pending`/`channels` grow without bound.
    #[tokio::test]
    async fn channel_open_refused_past_max_channels() {
        let (client_t, mut server_t) = transport_pair().await;
        let mut conn = Connection::new(client_t, Policy::AllowAll);

        // Fill to the cap with cheap dummy pending entries.
        for i in 0..MAX_CHANNELS {
            let (_keep, filler) = tokio::io::duplex(1);
            conn.pending.insert(i as u32, Pending::Direct(Box::new(filler)));
        }

        let mut w = Writer::new();
        w.byte(msg::CHANNEL_OPEN);
        w.utf8("direct-tcpip");
        w.u32(9999);
        w.u32(LOCAL_WINDOW);
        w.u32(MAX_CHUNK);
        w.utf8("127.0.0.1");
        w.u32(1);
        w.utf8("orig");
        w.u32(1);
        conn.on_channel_open(&w.into_bytes()).await.unwrap();

        let reply = server_t.recv().await.unwrap();
        assert_eq!(reply[0], msg::CHANNEL_OPEN_FAILURE, "should refuse past MAX_CHANNELS");
    }

    /// `spawn_connect`'s connect is asynchronous and can take up to
    /// `CONNECT_TIMEOUT` to resolve. Without `pending_connects`, an in-flight
    /// connect was invisible to `MAX_CHANNELS` for that whole window, letting
    /// a peer spawn unboundedly many concurrent connects by opening faster
    /// than any one resolved -- `self.channels`/`self.pending` only gain an
    /// entry once `Cmd::Connected` arrives. Simulate many in-flight connects
    /// directly (driving real ones and racing their timing isn't reliable in
    /// every environment; see `connect_timeout_wrapping_fires_on_a_stalled_connect`)
    /// and confirm a further open is refused before any of them resolve.
    #[tokio::test]
    async fn channel_open_refused_while_many_connects_are_in_flight() {
        let (client_t, mut server_t) = transport_pair().await;
        let mut conn = Connection::new(client_t, Policy::AllowAll);
        conn.pending_connects = MAX_CHANNELS;

        let mut w = Writer::new();
        w.byte(msg::CHANNEL_OPEN);
        w.utf8("direct-tcpip");
        w.u32(9999);
        w.u32(LOCAL_WINDOW);
        w.u32(MAX_CHUNK);
        w.utf8("127.0.0.1");
        w.u32(1);
        w.utf8("orig");
        w.u32(1);
        conn.on_channel_open(&w.into_bytes()).await.unwrap();

        let reply = server_t.recv().await.unwrap();
        assert_eq!(
            reply[0],
            msg::CHANNEL_OPEN_FAILURE,
            "should refuse while connects are in flight, not just once they resolve"
        );
    }

    /// A refused *terminal* session (`end_connection_on_close`, as
    /// `client_session`'s one-shot wrapper requests) must end the
    /// connection loop, not leave it parked forever: a refused open never
    /// gets a `Chan` entry, so `close_if_done` — the only other path that
    /// sets `done` for a terminal channel — can never see it. Without this,
    /// a peer that refuses the only session a connection exists for (e.g. a
    /// Windows-built server, which serves no sessions at all) leaves both
    /// ends of `run()` parked forever with nothing left to say.
    #[tokio::test]
    async fn refused_terminal_session_ends_the_connection() {
        let (client_t, _server_t) = transport_pair().await;
        let mut conn = Connection::new(client_t, Policy::DenyAll);

        let (exit_tx, exit_rx) = tokio::sync::oneshot::channel();
        conn.pending.insert(
            7,
            Pending::Session(Box::new(SessionSpec {
                command: None,
                subsystem: None,
                pty: None,
                resize: None,
                stdin: Box::new(tokio::io::empty()),
                stdout: Box::new(tokio::io::sink()),
                stderr: Box::new(tokio::io::sink()),
                exit: exit_tx,
                forward_agent: false,
                end_connection_on_close: true,
            })),
        );
        assert!(!conn.done);

        let mut w = Writer::new();
        w.byte(msg::CHANNEL_OPEN_FAILURE);
        w.u32(7);
        w.u32(open_failure::UNKNOWN_CHANNEL_TYPE);
        w.utf8("sessions are not served on this platform");
        w.utf8("");
        conn.on_open_failure(&w.into_bytes()).unwrap();

        assert!(conn.done, "a refused terminal session must end the connection loop");
        assert!(exit_rx.await.is_err(), "the exit oneshot must be dropped, not left dangling");
    }

    /// MAX_CHANNELS must also bound our own outgoing opens (local -L/-R
    /// accept-loop traffic, or a session request), not just peer-initiated
    /// ones -- otherwise this side could grow `pending` past the cap purely
    /// from local traffic while a slow peer sits on its replies.
    #[tokio::test]
    async fn local_open_dropped_past_max_channels() {
        let (client_t, _server_t) = transport_pair().await;
        let mut conn = Connection::new(client_t, Policy::DenyAll);
        conn.pending_connects = MAX_CHANNELS;

        let permit = conn.open_admission.clone().try_acquire_owned().unwrap();
        let (_keep, filler) = tokio::io::duplex(1);
        conn.on_cmd(Cmd::OpenTunnel {
            channel_type: "direct-tcpip",
            addr: "x".into(),
            port: 1,
            orig_host: "y".into(),
            orig_port: 1,
            stream: Box::new(filler),
            _permit: permit,
        })
        .await
        .unwrap();

        assert!(
            conn.pending.is_empty(),
            "should not insert a pending entry for a local open past MAX_CHANNELS"
        );
    }

    /// A peer's CHANNEL_WINDOW_ADJUST is attacker-controlled; a naive
    /// `add_permits` would let repeated near-`u32::MAX` adjusts drive the
    /// tokio `Semaphore` past `Semaphore::MAX_PERMITS`, which panics the
    /// process. The clamp in `on_window_adjust` must hold under repeated
    /// oversized grants, not just a single one.
    #[tokio::test]
    async fn window_adjust_never_exceeds_semaphore_max_permits() {
        let (client_t, _server_t) = transport_pair().await;
        let mut conn = Connection::new(client_t, Policy::DenyAll);
        let (credit, _, _rx) = conn.insert_chan(1, 100, 0, false, false);

        for _ in 0..4 {
            let mut w = Writer::new();
            w.byte(msg::CHANNEL_WINDOW_ADJUST);
            w.u32(1);
            w.u32(u32::MAX);
            conn.on_window_adjust(&w.into_bytes()).unwrap();
            assert!(credit.available_permits() <= Semaphore::MAX_PERMITS);
        }
    }

    /// The per-channel send-credit `Semaphore` must be closed once its
    /// channel is fully closed (both directions), not just when the whole
    /// connection drops: a task blocked in `acquire_many` on an exhausted
    /// window must wake and unwind instead of leaking its socket/child
    /// process on a channel that's gone but the connection lives on.
    #[tokio::test]
    async fn channel_close_wakes_a_task_blocked_on_exhausted_credit() {
        let (client_t, _server_t) = transport_pair().await;
        let mut conn = Connection::new(client_t, Policy::DenyAll);
        let (credit, _, _rx) = conn.insert_chan(1, 100, 0, false, false); // zero window

        let waiter_credit = credit.clone();
        let waiter = tokio::spawn(async move { waiter_credit.acquire_many(1).await.map(|_| ()) });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished(), "waiter should be blocked: the window is exhausted");

        // Mark the channel fully closed on both sides so close_if_done
        // actually removes it -- exercising the same path a real
        // CHANNEL_CLOSE exchange takes.
        conn.channels.get_mut(&1).unwrap().sent_close = true;
        conn.channels.get_mut(&1).unwrap().peer_closed = true;
        conn.close_if_done(1).await.unwrap();

        let outcome = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("waiter should unblock once the channel closes")
            .unwrap();
        assert!(outcome.is_err(), "acquire should fail: the credit semaphore is closed");
    }

    /// Isolates the exact timeout-wrapping pattern `spawn_connect` uses (a
    /// connect that never resolves must still report failure rather than
    /// tying up its task and channel slot forever) from real network timing:
    /// a black-holed address isn't a reliable test target in every
    /// environment (some route everything, including reserved ranges, in
    /// milliseconds). A future that never completes on its own stands in for
    /// a stalled connect; Tokio's paused-clock `advance` fires the timeout
    /// without waiting the real `CONNECT_TIMEOUT`.
    #[tokio::test(start_paused = true)]
    async fn connect_timeout_wrapping_fires_on_a_stalled_connect() {
        let task = tokio::spawn(async {
            tokio::time::timeout(CONNECT_TIMEOUT, std::future::pending::<std::io::Result<()>>()).await
        });
        tokio::time::advance(CONNECT_TIMEOUT + Duration::from_secs(1)).await;
        let result = task.await.unwrap();
        assert!(result.is_err(), "timeout must fire when the connect never resolves");
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

    /// A shareable stdout sink for session tests.
    #[cfg(unix)]
    #[derive(Clone, Default)]
    struct VecSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    #[cfg(unix)]
    impl AsyncWrite for VecSink {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            b: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.0.lock().unwrap().extend_from_slice(b);
            std::task::Poll::Ready(Ok(b.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// Wait for the session to print a full line, then return it.
    #[cfg(unix)]
    async fn wait_for_line(out: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>) -> String {
        for _ in 0..500 {
            {
                let v = out.lock().unwrap();
                if let Some(pos) = v.iter().position(|&b| b == b'\n') {
                    return String::from_utf8_lossy(&v[..pos]).into_owned();
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("session never printed its line");
    }

    // Runs a real POSIX shell command (`head -c 5`) through the session
    // server, which is `#[cfg(unix)]` — Windows serves no sessions at all.
    #[cfg(unix)]
    #[tokio::test]
    async fn session_and_forward_share_one_connection() {
        use super::super::session::SessionSpec;
        use std::sync::{Arc, Mutex};
        use tokio::sync::oneshot;

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
            subsystem: None,
            pty: None,
            resize: None,
            stdin: Box::new(&b"hello world"[..]),
            stdout: Box::new(VecSink(out.clone())),
            stderr: Box::new(tokio::io::sink()),
            exit: exit_tx,
            forward_agent: false,
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

    // ------------------------------------------------- agent forwarding ---
    // Unix-socket agent relaying (`agent::Client::connect` and the shell
    // commands the sessions below run) has no Windows equivalent — see the
    // agent forwarding follow-up in README.md.
    #[cfg(unix)]
    mod agent_forwarding {
    use super::*;

    /// A keyring behind a real Unix socket, standing in for the user's
    /// local agent. Returns the socket path (the tempdir rides along so it
    /// lives as long as the test).
    async fn local_agent(
        keyring: std::sync::Arc<crate::agent::server::Keyring>,
    ) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = listener.accept().await else {
                    break;
                };
                let kr = keyring.clone();
                tokio::spawn(async move {
                    let _ = crate::agent::server::serve_conn(s, &kr).await;
                });
            }
        });
        (dir, sock)
    }

    /// Open a session that prints its SSH_AUTH_SOCK and stays alive, and
    /// return the printed line (empty when the server granted nothing).
    async fn session_reporting_agent_sock(
        handle: &Handle,
        forward_agent: bool,
    ) -> (String, tokio::sync::oneshot::Receiver<crate::connect::ExitStatus>) {
        use crate::connect::session::SessionSpec;
        let out = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (exit_tx, exit_rx) = tokio::sync::oneshot::channel();
        handle.open_session(SessionSpec {
            command: Some(r#"printf '%s\n' "$SSH_AUTH_SOCK"; sleep 30"#.into()),
            subsystem: None,
            pty: None,
            resize: None,
            stdin: Box::new(tokio::io::empty()),
            stdout: Box::new(VecSink(out.clone())),
            stderr: Box::new(tokio::io::sink()),
            exit: exit_tx,
            forward_agent,
            end_connection_on_close: false,
        });
        (wait_for_line(&out).await, exit_rx)
    }

    #[tokio::test]
    async fn agent_forwarding_relays_to_the_local_agent() {
        // The "local" agent holds one key.
        let keyring = std::sync::Arc::new(crate::agent::server::Keyring::new());
        let (_dir, local_sock) = local_agent(keyring).await;
        let key = PrivateKey::generate();
        let mut direct = crate::agent::Client::connect(&local_sock).await.unwrap();
        direct.add(&key, None, "forwarded", None).await.unwrap();

        let (client_t, server_t) = transport_pair().await;
        let server = tokio::spawn(async move {
            Connection::new(server_t, Policy::DenyAll)
                .permit_agent_forward(true)
                .run(None)
                .await
        });
        let client_conn =
            Connection::new(client_t, Policy::DenyAll).agent_forward(Some(local_sock));
        let handle = client_conn.handle();
        let client = tokio::spawn(async move { client_conn.run(None).await });

        // The session's SSH_AUTH_SOCK names the server-side relay socket.
        let (path, _exit_rx) = session_reporting_agent_sock(&handle, true).await;
        assert!(!path.is_empty(), "session should see an SSH_AUTH_SOCK");

        // Drive the real agent protocol through the whole relay: server
        // socket -> channel -> client -> local socket -> keyring.
        let mut relayed = crate::agent::Client::connect(&path).await.unwrap();
        let ids = relayed.identities().await.unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].comment, "forwarded");
        let sig = relayed.sign(&ids[0].blob, b"signed across the wire").await.unwrap();
        key.public().verify(b"signed across the wire", &sig).unwrap();

        client.abort();
        server.abort();
    }

    #[tokio::test]
    async fn agent_forwarding_injects_the_forwarders_hop() {
        // The local agent holds a key pinned to the path local -> A -> B,
        // where A is the host this client (the forwarder) reached and B is the
        // host the downstream reaches. Signing succeeds only if the forwarder
        // replays its own bind for A onto the relayed connection — without it
        // the agent would see the chain [B] and refuse.
        let keyring = std::sync::Arc::new(crate::agent::server::Keyring::new());
        let (_dir, local_sock) = local_agent(keyring).await;

        let user = PrivateKey::generate();
        let host_a = PrivateKey::generate(); // the forwarder's hop
        let host_b = PrivateKey::generate(); // the downstream's hop
        let path = crate::agent::encode_path(&[
            (String::new(), "a".into(), vec![(host_a.public().to_blob(), false)]),
            (String::new(), "b".into(), vec![(host_b.public().to_blob(), false)]),
        ]);
        crate::agent::Client::connect(&local_sock)
            .await
            .unwrap()
            .add_constrained(&user, None, "pinned", None, Some(&path))
            .await
            .unwrap();

        // The forwarder carries A's binding, exactly as `shh -A` would.
        let a_sid = [1u8; 32];
        let bind = AgentBind {
            host_blob: host_a.public().to_blob(),
            session_id: a_sid.to_vec(),
            sig: host_a.sign(&a_sid),
        };

        let (client_t, server_t) = transport_pair().await;
        let server = tokio::spawn(async move {
            Connection::new(server_t, Policy::DenyAll)
                .permit_agent_forward(true)
                .run(None)
                .await
        });
        let client_conn = Connection::new(client_t, Policy::DenyAll)
            .agent_forward(Some(local_sock))
            .agent_bind(Some(bind));
        let handle = client_conn.handle();
        let client = tokio::spawn(async move { client_conn.run(None).await });

        let (relay_path, _exit) = session_reporting_agent_sock(&handle, true).await;
        assert!(!relay_path.is_empty());

        // The downstream reaches B: it sends its own bind for B, then signs.
        // With A injected ahead of it, the agent sees [A, B] and permits.
        let mut downstream = crate::agent::Client::connect(&relay_path).await.unwrap();
        let b_sid = [2u8; 32];
        downstream
            .session_bind(&host_b.public().to_blob(), &b_sid, &host_b.sign(&b_sid), false)
            .await
            .unwrap();
        let blob = user.public().to_blob();
        let sig = downstream.sign(&blob, b"through the path").await.unwrap();
        user.public().verify(b"through the path", &sig).unwrap();

        client.abort();
        server.abort();
    }

    #[tokio::test]
    async fn without_injection_a_path_key_is_refused_through_the_relay() {
        // Same setup, but the forwarder carries no binding (as if it never
        // reached A). The agent then sees only [B] for a key pinned to
        // local -> A -> B, and refuses — proving the injection is what makes
        // the path usable, not some looser check.
        let keyring = std::sync::Arc::new(crate::agent::server::Keyring::new());
        let (_dir, local_sock) = local_agent(keyring).await;
        let user = PrivateKey::generate();
        let host_a = PrivateKey::generate();
        let host_b = PrivateKey::generate();
        let path = crate::agent::encode_path(&[
            (String::new(), "a".into(), vec![(host_a.public().to_blob(), false)]),
            (String::new(), "b".into(), vec![(host_b.public().to_blob(), false)]),
        ]);
        crate::agent::Client::connect(&local_sock)
            .await
            .unwrap()
            .add_constrained(&user, None, "pinned", None, Some(&path))
            .await
            .unwrap();

        let (client_t, server_t) = transport_pair().await;
        let server = tokio::spawn(async move {
            Connection::new(server_t, Policy::DenyAll)
                .permit_agent_forward(true)
                .run(None)
                .await
        });
        // No `.agent_bind(...)`: the forwarder does not replay a hop.
        let client_conn =
            Connection::new(client_t, Policy::DenyAll).agent_forward(Some(local_sock));
        let handle = client_conn.handle();
        let client = tokio::spawn(async move { client_conn.run(None).await });

        let (relay_path, _exit) = session_reporting_agent_sock(&handle, true).await;
        let mut downstream = crate::agent::Client::connect(&relay_path).await.unwrap();
        let b_sid = [3u8; 32];
        downstream
            .session_bind(&host_b.public().to_blob(), &b_sid, &host_b.sign(&b_sid), false)
            .await
            .unwrap();
        assert!(
            downstream.sign(&user.public().to_blob(), b"x").await.is_err(),
            "path key must be refused when the forwarder's hop is missing"
        );

        client.abort();
        server.abort();
    }

    #[tokio::test]
    async fn agent_forwarding_refused_without_server_permit() {
        let (client_t, server_t) = transport_pair().await;
        // Server default: no permit.
        let server =
            tokio::spawn(async move { Connection::new(server_t, Policy::DenyAll).run(None).await });
        let client_conn = Connection::new(client_t, Policy::DenyAll)
            .agent_forward(Some(std::path::PathBuf::from("/nonexistent")));
        let handle = client_conn.handle();
        let client = tokio::spawn(async move { client_conn.run(None).await });

        // The request is silently refused: the session simply has no
        // SSH_AUTH_SOCK, and nothing else about it breaks.
        let (path, _exit_rx) = session_reporting_agent_sock(&handle, true).await;
        assert!(path.is_empty(), "refused forwarding must not set SSH_AUTH_SOCK, got {path:?}");

        client.abort();
        server.abort();
    }

    #[tokio::test]
    async fn client_refuses_agent_channels_it_did_not_request() {
        // The server permits and sets up its socket, but this client never
        // offered an agent (`agent_forward(None)`) — a malicious or confused
        // server-side process must find a dead end, not a fallback.
        let (client_t, server_t) = transport_pair().await;
        let server = tokio::spawn(async move {
            Connection::new(server_t, Policy::DenyAll)
                .permit_agent_forward(true)
                .run(None)
                .await
        });
        let client_conn = Connection::new(client_t, Policy::DenyAll); // no agent
        let handle = client_conn.handle();
        let client = tokio::spawn(async move { client_conn.run(None).await });

        let (path, _exit_rx) = session_reporting_agent_sock(&handle, true).await;
        assert!(!path.is_empty(), "server set up its side of the relay");

        // The relay socket exists, but every channel through it is refused
        // by the client, so the agent conversation dies at the first query.
        let mut relayed = crate::agent::Client::connect(&path).await.unwrap();
        assert!(relayed.identities().await.is_err());

        client.abort();
        server.abort();
    }
    } // mod agent_forwarding
}
