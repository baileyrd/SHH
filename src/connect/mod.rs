//! The connection protocol (RFC 4254): session channels (exec / shell /
//! pty, with window flow control and exit status) and `direct-tcpip`
//! port forwarding.
//!
//! Both channel kinds are driven by one multiplexer, [`mux::Connection`],
//! so a session and any number of forwards ride a single connection.
//! Sessions ([`session`]) and forwards ([`forward`]) each run as per-channel
//! tasks; the loop routes wire messages between them and the transport.
//! Forwarding uses an explicit allowlist ([`forward::Policy`]) rather than
//! RFC 4254's open-by-default posture. The [`client_session`] /
//! [`server_session`] wrappers below drive a connection carrying a lone
//! session, for callers that don't forward.
//!
//! Not present yet: reverse (`-R`) forwarding, X11, agent forwarding.

#[cfg(unix)]
pub mod pty;

pub mod forward;
pub mod mux;
pub mod session;

use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(unix)]
use tokio::io::AsyncReadExt; // for maybe_read's `.read()` (unix session server)
use tokio::sync::mpsc;

use crate::transport::Transport;
use crate::wire::{msg, Writer};
use crate::{Error, Result};

/// Receive window we grant the peer, and the largest data chunk we send.
pub(crate) const LOCAL_WINDOW: u32 = 2 * 1024 * 1024;
pub(crate) const MAX_CHUNK: u32 = 32 * 1024;
/// Re-grant the window when the peer has consumed half of it.
pub(crate) const WINDOW_REFILL: u32 = LOCAL_WINDOW / 2;
/// RFC 4254 upper bound on a channel window; the send-credit semaphore is
/// never grown past this so it cannot exceed `Semaphore::MAX_PERMITS`.
pub(crate) const WINDOW_MAX: u32 = u32::MAX;

pub(crate) const STDERR: u32 = 1; // SSH_EXTENDED_DATA_STDERR

/// CHANNEL_OPEN_FAILURE reason codes (RFC 4254 §5.1).
pub(crate) mod open_failure {
    pub const ADMINISTRATIVELY_PROHIBITED: u32 = 1;
    pub const CONNECT_FAILED: u32 = 2;
    pub const UNKNOWN_CHANNEL_TYPE: u32 = 3;
}

pub struct ExitStatus {
    pub code: Option<u32>,
    pub signal: Option<String>,
}

/// The system account a session should run as. When `shhd` runs as root it
/// drops to this user (gid, supplementary groups, then uid) before
/// executing, and runs the user's login shell in their home directory —
/// so a session is never more privileged than the account that logged in.
#[derive(Clone)]
pub struct UserContext {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: std::path::PathBuf,
    pub shell: String,
}

impl UserContext {
    /// Look up a user in the password database.
    #[cfg(unix)]
    pub fn for_user(name: &str) -> Option<UserContext> {
        let user = nix::unistd::User::from_name(name).ok().flatten()?;
        let shell = user.shell.to_string_lossy().into_owned();
        Some(UserContext {
            name: user.name,
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
            home: user.dir,
            shell: if shell.is_empty() {
                "/bin/sh".to_string()
            } else {
                shell
            },
        })
    }
}

/// `initgroups(3)`: set the caller's supplementary group list from `name`'s
/// membership, seeded with `gid` as the base group. `nix` only wraps the
/// libc call on Linux — it declines apple targets because their `basegroup`
/// parameter is a narrower `c_int` rather than a `Gid` — so on macOS we bind
/// the same libc function directly instead of leaving a "dropped-privilege"
/// process holding root's supplementary groups (the vulnerability this call
/// exists to close).
#[cfg(target_os = "linux")]
pub(crate) fn initgroups(name: &std::ffi::CStr, gid: nix::unistd::Gid) -> nix::Result<()> {
    nix::unistd::initgroups(name, gid)
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn initgroups(name: &std::ffi::CStr, gid: nix::unistd::Gid) -> nix::Result<()> {
    let rc = unsafe { libc::initgroups(name.as_ptr(), gid.as_raw() as libc::c_int) };
    if rc == 0 {
        Ok(())
    } else {
        Err(nix::errno::Errno::last())
    }
}

/// Ask the server for a pseudo-terminal with these dimensions.
#[derive(Clone)]
pub struct PtyRequest {
    pub term: String,
    pub cols: u32,
    pub rows: u32,
    pub xpix: u32,
    pub ypix: u32,
}

/// A terminal resize: (cols, rows, xpixels, ypixels).
pub type WindowChange = (u32, u32, u32, u32);

/// Read from a reader that may not exist; absent readers never produce.
#[cfg(unix)] // only the (unix) session server reads optional child pipes
pub(crate) async fn maybe_read<R: AsyncRead + Unpin>(
    r: Option<&mut R>,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    match r {
        Some(r) => r.read(buf).await,
        None => std::future::pending().await,
    }
}

/// Receive from a channel that may not exist.
pub(crate) async fn maybe_recv<T>(rx: Option<&mut mpsc::Receiver<T>>) -> Option<T> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

// ------------------------------------------------------- packet helpers --

pub(crate) fn chan(byte: u8, peer: u32) -> Writer {
    let mut w = Writer::new();
    w.byte(byte);
    w.u32(peer);
    w
}

pub(crate) fn data_packet(peer: u32, data: &[u8]) -> Vec<u8> {
    let mut w = chan(msg::CHANNEL_DATA, peer);
    w.string(data);
    w.into_bytes()
}

pub(crate) fn ext_data_packet(peer: u32, kind: u32, data: &[u8]) -> Vec<u8> {
    let mut w = chan(msg::CHANNEL_EXTENDED_DATA, peer);
    w.u32(kind);
    w.string(data);
    w.into_bytes()
}

pub(crate) fn window_adjust(peer: u32, add: u32) -> Vec<u8> {
    let mut w = chan(msg::CHANNEL_WINDOW_ADJUST, peer);
    w.u32(add);
    w.into_bytes()
}

pub(crate) fn simple(byte: u8, peer: u32) -> Vec<u8> {
    chan(byte, peer).into_bytes()
}

// ---------------------------------------------------- session convenience --
//
// Sessions now run as channels inside [`mux::Connection`]; these wrappers
// drive a connection that carries exactly one session, for callers that
// don't also forward ports. The unified client/server paths in the
// binaries use [`mux::Connection`] directly.

use tokio::sync::oneshot;

/// Open a session, run `command` (or a shell when `None`), shuttle stdio,
/// and return the remote exit status. Consumes the transport: the
/// connection ends when the session closes.
pub async fn client_session<S, I, O, E>(
    t: Transport<S>,
    command: Option<&str>,
    pty: Option<&PtyRequest>,
    resize: Option<mpsc::Receiver<WindowChange>>,
    stdin: I,
    stdout: O,
    stderr: E,
) -> Result<ExitStatus>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    I: AsyncRead + Unpin + Send + 'static,
    O: AsyncWrite + Unpin + Send + 'static,
    E: AsyncWrite + Unpin + Send + 'static,
{
    let conn = mux::Connection::new(t, forward::Policy::DenyAll);
    let handle = conn.handle();
    let (tx, rx) = oneshot::channel();
    handle.open_session(session::SessionSpec {
        command: command.map(str::to_owned),
        subsystem: None,
        pty: pty.cloned(),
        resize,
        stdin: Box::new(stdin),
        stdout: Box::new(stdout),
        stderr: Box::new(stderr),
        exit: tx,
        forward_agent: false,
        end_connection_on_close: true,
    });
    conn.run(None).await?;
    rx.await
        .map_err(|_| Error::Channel("session ended without an exit status".into()))
}

/// A subsystem channel on a fresh connection: byte streams to write requests
/// to and read replies from, plus the connection task pumping them. Drop the
/// whole thing to close the channel, then await `conn` for the final result.
pub struct SubsystemChannel {
    pub reader: tokio::io::DuplexStream,
    pub writer: tokio::io::DuplexStream,
    pub conn: tokio::task::JoinHandle<Result<()>>,
}

/// Open a session channel, request the named `subsystem` (e.g. `sftp`), and
/// return byte streams to talk to it over. Consumes the transport like
/// [`client_session`]: the connection runs in a spawned task until the
/// subsystem channel closes.
pub async fn client_subsystem<S>(t: Transport<S>, subsystem: &str) -> Result<SubsystemChannel>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let conn = mux::Connection::new(t, forward::Policy::DenyAll);
    let handle = conn.handle();
    // Two pipes: we write requests into `to_srv_ours` (the session reads its
    // twin as stdin); the session writes replies into `from_srv_theirs` and we
    // read them from its twin.
    let (to_srv_ours, to_srv_theirs) = tokio::io::duplex(1 << 16);
    let (from_srv_theirs, from_srv_ours) = tokio::io::duplex(1 << 16);
    let (exit_tx, _exit_rx) = oneshot::channel();
    handle.open_session(session::SessionSpec {
        command: None,
        subsystem: Some(subsystem.to_owned()),
        pty: None,
        resize: None,
        stdin: Box::new(to_srv_theirs),
        stdout: Box::new(from_srv_theirs),
        stderr: Box::new(tokio::io::sink()),
        exit: exit_tx,
        forward_agent: false,
        end_connection_on_close: true,
    });
    let conn = tokio::spawn(async move { conn.run(None).await });
    Ok(SubsystemChannel {
        reader: from_srv_ours,
        writer: to_srv_ours,
        conn,
    })
}

/// Serve a single connection that carries only a session (no forwarding).
/// `primed` is a CHANNEL_OPEN already read off the wire, or `None`.
pub async fn server_session<S>(t: Transport<S>, primed: Option<Vec<u8>>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    mux::Connection::new(t, forward::Policy::DenyAll)
        .run(primed)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth;
    use crate::crypto::ed25519::PrivateKey;
    use crate::transport::{ClientConfig, ServerConfig};
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use tokio::io::duplex;

    /// A shareable AsyncWrite that appends into a Vec — cloneable so a copy
    /// can be read back after the session task has moved the original.
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl Sink {
        fn take(&self) -> Vec<u8> {
            std::mem::take(&mut self.0.lock().unwrap())
        }
    }
    impl AsyncWrite for Sink {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[cfg(unix)]
    #[test]
    fn user_context_resolves_known_and_unknown() {
        let root = UserContext::for_user("root").expect("root always exists");
        assert_eq!(root.uid, 0);
        assert_eq!(root.name, "root");
        assert!(root.home.as_os_str().len() > 1);
        assert!(UserContext::for_user("no-such-user-9c1f2b").is_none());
    }

    async fn run(command: &str, stdin: &'static [u8]) -> (ExitStatus, Vec<u8>, Vec<u8>) {
        let (a, b) = duplex(1 << 20);
        let user_key = PrivateKey::generate();
        let host_key = PrivateKey::generate();
        let policy = auth::Policy {
            user: Some("tester".into()),
            keys: vec![user_key.public().into()],
            trusted_cas: vec![],
            banner: None,
        };
        let command = command.to_owned();

        let out = Sink::default();
        let err = Sink::default();
        let (out2, err2) = (out.clone(), err.clone());
        let client_side = async move {
            let mut t = Transport::client(
                a,
                ClientConfig::with_verifier(Box::new(|_| Ok(()))),
            )
            .await?;
            auth::client(&mut t, "tester", &user_key, None, |_| {}).await?;
            let status =
                client_session(t, Some(&command), None, None, stdin, out, err).await?;
            Ok::<_, Error>(status)
        };
        let server_side = async move {
            let mut t = Transport::server(b, ServerConfig::with_host_key(host_key)).await?;
            auth::server(&mut t, &policy, None).await?;
            server_session(t, None).await
        };
        let (c, s) = tokio::join!(client_side, server_side);
        s.unwrap();
        (c.unwrap(), out2.take(), err2.take())
    }

    #[tokio::test]
    async fn exec_captures_stdout_stderr_and_status() {
        let (status, out, err) =
            run("printf hello; printf oops >&2; exit 3", b"").await;
        assert_eq!(out, b"hello");
        assert_eq!(err, b"oops");
        assert_eq!(status.code, Some(3));
    }

    #[tokio::test]
    async fn stdin_reaches_the_command() {
        let (status, out, _) = run("tr a-z A-Z", b"quiet please\n").await;
        assert_eq!(out, b"QUIET PLEASE\n");
        assert_eq!(status.code, Some(0));
    }

    #[tokio::test]
    async fn force_command_overrides_client_request() {
        // The client asks to run `id`, but a certificate force-command pins
        // the session to a different command; the client's request appears
        // only as SSH_ORIGINAL_COMMAND.
        let (a, b) = duplex(1 << 20);
        let user_key = PrivateKey::generate();
        let host_key = PrivateKey::generate();
        let policy = auth::Policy {
            user: Some("tester".into()),
            keys: vec![user_key.public().into()],
            trusted_cas: vec![],
            banner: None,
        };
        let out = Sink::default();
        let out2 = out.clone();
        let client_side = async move {
            let mut t =
                Transport::client(a, ClientConfig::with_verifier(Box::new(|_| Ok(())))).await?;
            auth::client(&mut t, "tester", &user_key, None, |_| {}).await?;
            let status =
                client_session(t, Some("id"), None, None, b"".as_ref(), out, Sink::default())
                    .await?;
            Ok::<_, Error>(status)
        };
        let server_side = async move {
            let mut t = Transport::server(b, ServerConfig::with_host_key(host_key)).await?;
            auth::server(&mut t, &policy, None).await?;
            mux::Connection::new(t, forward::Policy::DenyAll)
                .force_command(Some(
                    "printf FORCED; printf '[%s]' \"$SSH_ORIGINAL_COMMAND\"".into(),
                ))
                .run(None)
                .await
        };
        let (c, s) = tokio::join!(client_side, server_side);
        s.unwrap();
        let status = c.unwrap();
        assert_eq!(out2.take(), b"FORCED[id]");
        assert_eq!(status.code, Some(0));
    }

    #[tokio::test]
    async fn bulk_data_exercises_flow_control() {
        // 8 MiB through a 2 MiB window: several WINDOW_ADJUST round trips.
        let (status, out, _) = run("head -c 8388608 /dev/zero", b"").await;
        assert_eq!(out.len(), 8 * 1024 * 1024);
        assert!(out.iter().all(|&b| b == 0));
        assert_eq!(status.code, Some(0));
    }

    #[tokio::test]
    async fn exit_signal_reported() {
        let (status, _, _) = run("kill -9 $$", b"").await;
        assert_eq!(status.code, None);
        assert_eq!(status.signal.as_deref(), Some("KILL"));
    }

    #[tokio::test]
    async fn pty_session_gets_a_real_terminal() {
        let (a, b) = duplex(1 << 20);
        let user_key = PrivateKey::generate();
        let host_key = PrivateKey::generate();
        let policy = auth::Policy {
            user: None,
            keys: vec![user_key.public().into()],
            trusted_cas: vec![],
            banner: None,
        };
        let client_side = async move {
            let mut t = Transport::client(
                a,
                ClientConfig::with_verifier(Box::new(|_| Ok(()))),
            )
            .await?;
            auth::client(&mut t, "tester", &user_key, None, |_| {}).await?;
            let req = PtyRequest {
                term: "vt100".into(),
                cols: 132,
                rows: 43,
                xpix: 0,
                ypix: 0,
            };
            let out = Sink::default();
            let out2 = out.clone();
            let status = client_session(
                t,
                Some("tty; echo TERM=$TERM; stty size"),
                Some(&req),
                None,
                &b""[..],
                out,
                Sink::default(),
            )
            .await?;
            Ok::<_, Error>((status, out2.take()))
        };
        let server_side = async move {
            let mut t = Transport::server(b, ServerConfig::with_host_key(host_key)).await?;
            auth::server(&mut t, &policy, None).await?;
            server_session(t, None).await
        };
        let (c, s) = tokio::join!(client_side, server_side);
        s.unwrap();
        let (status, out) = c.unwrap();
        let text = String::from_utf8_lossy(&out);
        // Linux devpts names ptys `/dev/pts/N`; BSD/macOS uses `/dev/ttysNNN`.
        assert!(
            text.contains("/dev/pts/") || text.contains("/dev/tty"),
            "no pty in output: {text}"
        );
        assert!(text.contains("TERM=vt100"), "TERM not set: {text}");
        assert!(text.contains("43 132"), "winsize not applied: {text}");
        assert_eq!(status.code, Some(0));
    }
}
