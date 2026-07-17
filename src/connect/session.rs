//! Session channels (exec / shell / pty) as multiplexer tasks.
//!
//! Where a forward channel splices a socket, a session channel drives
//! local stdio (client) or a child process (server). Both use the same
//! loop-side machinery — send-window credit, receive-window replenishment,
//! close handshake — so a session and any number of forwards ride one
//! connection. The extra session traffic (channel requests, extended data,
//! request replies) flows over the same task channels.
//!
//! Unix-only, like the rest of the daemon (the pty and process handling
//! depend on it).

// The server half — child processes, ptys, the per-session agent socket —
// is Unix machinery; only the client half compiles elsewhere (Windows).
#[cfg(unix)]
use std::process::Stdio;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(unix)]
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot, Semaphore};

#[cfg(unix)]
use super::mux::AGENT_CHANNEL;
use super::mux::{Cmd, ToTask};
#[cfg(unix)]
use super::{maybe_read, pty};
use super::{maybe_recv, ExitStatus, PtyRequest, WindowChange, MAX_CHUNK, STDERR};
use crate::wire::{Reader, Writer};

/// What a client wants from a session channel. Stdio is boxed so the
/// multiplexer's command enum stays free of type parameters.
pub struct SessionSpec {
    pub command: Option<String>,
    /// Request a subsystem (e.g. `sftp`) instead of exec/shell. Takes
    /// precedence over `command` when set.
    pub subsystem: Option<String>,
    pub pty: Option<PtyRequest>,
    pub resize: Option<mpsc::Receiver<WindowChange>>,
    pub stdin: Box<dyn AsyncRead + Unpin + Send>,
    pub stdout: Box<dyn AsyncWrite + Unpin + Send>,
    pub stderr: Box<dyn AsyncWrite + Unpin + Send>,
    /// Delivered the remote exit status when the channel closes.
    pub exit: oneshot::Sender<ExitStatus>,

    /// Ask the server to forward our agent (`-A`): processes it runs can
    /// reach back through the connection to the local `SSH_AUTH_SOCK`.
    pub forward_agent: bool,
    /// End the whole connection when this channel closes (foreground
    /// `shh host cmd`); false when forwards should outlive the session.
    pub end_connection_on_close: bool,
}

// ------------------------------------------------------- request bodies --

/// The bytes of a CHANNEL_REQUEST after the recipient-channel field:
/// `string(kind) ‖ bool(want_reply) ‖ type-specific`.
fn pty_req_body(req: &PtyRequest) -> Vec<u8> {
    let mut w = Writer::new();
    w.utf8("pty-req");
    w.boolean(true);
    w.utf8(&req.term);
    w.u32(req.cols);
    w.u32(req.rows);
    w.u32(req.xpix);
    w.u32(req.ypix);
    w.string(b""); // terminal modes: server-side defaults
    w.into_bytes()
}

fn exec_or_shell_body(command: &Option<String>) -> Vec<u8> {
    let mut w = Writer::new();
    match command {
        Some(cmd) => {
            w.utf8("exec");
            w.boolean(true);
            w.utf8(cmd);
        }
        None => {
            w.utf8("shell");
            w.boolean(true);
        }
    }
    w.into_bytes()
}

/// The `subsystem` channel request: `string("subsystem") ‖ bool ‖ string(name)`.
fn subsystem_body(name: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.utf8("subsystem");
    w.boolean(true);
    w.utf8(name);
    w.into_bytes()
}

fn window_change_body((cols, rows, xpix, ypix): WindowChange) -> Vec<u8> {
    let mut w = Writer::new();
    w.utf8("window-change");
    w.boolean(false);
    w.u32(cols);
    w.u32(rows);
    w.u32(xpix);
    w.u32(ypix);
    w.into_bytes()
}

#[cfg(unix)]
fn exit_request_body(status: std::process::ExitStatus) -> Vec<u8> {
    use std::os::unix::process::ExitStatusExt;
    let mut w = Writer::new();
    match status.code() {
        Some(code) => {
            w.utf8("exit-status");
            w.boolean(false);
            w.u32(code as u32);
        }
        None => {
            let name = match status.signal() {
                Some(1) => "HUP",
                Some(2) => "INT",
                Some(3) => "QUIT",
                Some(6) => "ABRT",
                Some(9) => "KILL",
                Some(11) => "SEGV",
                Some(13) => "PIPE",
                Some(15) => "TERM",
                _ => "UNKNOWN",
            };
            w.utf8("exit-signal");
            w.boolean(false);
            w.utf8(name);
            w.boolean(false); // no core dump info
            w.utf8("");
            w.utf8("");
        }
    }
    w.into_bytes()
}

/// Split `data` into window-limited chunks, reserving send credit for each,
/// and hand them to the loop. `ext` selects a CHANNEL_EXTENDED_DATA kind.
async fn send_credited(
    cmd_tx: &mpsc::UnboundedSender<Cmd>,
    credit: &Semaphore,
    id: u32,
    remote_max: u32,
    ext: Option<u32>,
    data: &[u8],
) -> bool {
    let mut off = 0;
    while off < data.len() {
        let take = ((data.len() - off) as u32).min(remote_max);
        match credit.acquire_many(take).await {
            Ok(p) => p.forget(),
            Err(_) => return false,
        }
        let bytes = data[off..off + take as usize].to_vec();
        let cmd = match ext {
            None => Cmd::Data { id, bytes },
            Some(kind) => Cmd::ExtData { id, kind, bytes },
        };
        if cmd_tx.send(cmd).is_err() {
            return false;
        }
        off += take as usize;
    }
    true
}

/// Wait for the reply to a request we sent. SSH orders a request's reply
/// before any channel data, so nothing else precedes it.
async fn await_reply(to_task: &mut mpsc::UnboundedReceiver<ToTask>) -> bool {
    loop {
        match to_task.recv().await {
            Some(ToTask::RequestReply(ok)) => return ok,
            Some(ToTask::Close) | None => return false,
            _ => {}
        }
    }
}

// ------------------------------------------------------------- client ----

pub(crate) async fn session_client_task(
    id: u32,
    spec: SessionSpec,
    credit: Arc<Semaphore>,
    remote_max: u32,
    mut to_task: mpsc::UnboundedReceiver<ToTask>,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
) {
    let SessionSpec {
        command,
        subsystem,
        pty,
        mut resize,
        mut stdin,
        mut stdout,
        mut stderr,
        exit,
        forward_agent,
        ..
    } = spec;

    // Requests: agent forwarding (fire-and-forget, as OpenSSH sends it —
    // refusal just means no forwarding), optional pty, then exec/shell.
    let give_up = |exit: oneshot::Sender<ExitStatus>| {
        let _ = exit.send(ExitStatus { code: None, signal: None });
        let _ = cmd_tx.send(Cmd::Close { id });
    };
    if forward_agent {
        let mut w = Writer::new();
        w.utf8("auth-agent-req@openssh.com");
        w.boolean(false);
        let _ = cmd_tx.send(Cmd::ChannelRequest {
            id,
            body: w.into_bytes(),
        });
    }
    if let Some(req) = &pty {
        let _ = cmd_tx.send(Cmd::ChannelRequest {
            id,
            body: pty_req_body(req),
        });
        if !await_reply(&mut to_task).await {
            give_up(exit);
            return;
        }
    }
    let _ = cmd_tx.send(Cmd::ChannelRequest {
        id,
        body: match &subsystem {
            Some(name) => subsystem_body(name),
            None => exec_or_shell_body(&command),
        },
    });
    if !await_reply(&mut to_task).await {
        give_up(exit);
        return;
    }

    // Pump: local stdio <-> channel.
    let mut exit_status: Option<ExitStatus> = None;
    let mut stdin_buf = vec![0u8; MAX_CHUNK as usize];
    let mut stdin_done = false;

    loop {
        tokio::select! {
            biased;
            msg = to_task.recv() => match msg {
                None | Some(ToTask::Close) => break,
                Some(ToTask::Data(b)) => {
                    let _ = stdout.write_all(&b).await;
                    let _ = stdout.flush().await;
                    let _ = cmd_tx.send(Cmd::Consumed { id, n: b.len() as u32 });
                }
                Some(ToTask::ExtData(kind, b)) => {
                    if kind == STDERR {
                        let _ = stderr.write_all(&b).await;
                        let _ = stderr.flush().await;
                    }
                    let _ = cmd_tx.send(Cmd::Consumed { id, n: b.len() as u32 });
                }
                Some(ToTask::Request { kind, data, .. }) => {
                    let mut r = Reader::new(&data);
                    match kind.as_str() {
                        "exit-status" => {
                            if let Ok(code) = r.u32() {
                                exit_status = Some(ExitStatus { code: Some(code), signal: None });
                            }
                        }
                        "exit-signal" => {
                            if let Ok(sig) = r.utf8() {
                                exit_status = Some(ExitStatus {
                                    code: None,
                                    signal: Some(sig.to_owned()),
                                });
                            }
                        }
                        _ => {}
                    }
                }
                Some(ToTask::Eof) => {}
                Some(ToTask::RequestReply(_)) => {}
            },
            n = stdin.read(&mut stdin_buf), if !stdin_done => match n {
                Ok(0) | Err(_) => {
                    stdin_done = true;
                    let _ = cmd_tx.send(Cmd::Eof { id });
                }
                Ok(n) => {
                    if !send_credited(&cmd_tx, &credit, id, remote_max, None, &stdin_buf[..n]).await {
                        break;
                    }
                }
            },
            ws = maybe_recv(resize.as_mut()) => match ws {
                Some(w) => {
                    let _ = cmd_tx.send(Cmd::ChannelRequest { id, body: window_change_body(w) });
                }
                None => resize = None,
            },
        }
    }

    let _ = exit.send(exit_status.unwrap_or(ExitStatus { code: None, signal: None }));
    let _ = cmd_tx.send(Cmd::Close { id });
}

// ------------------------------------------------------------- server ----

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn session_server_task(
    id: u32,
    credit: Arc<Semaphore>,
    remote_max: u32,
    mut to_task: mpsc::UnboundedReceiver<ToTask>,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    open_admission: Arc<Semaphore>,
    user: Option<super::UserContext>,
    force_command: Option<String>,
    permit_agent: bool,
) {
    let mut allocated: Option<pty::Pty> = None;
    let mut early_stdin: Vec<u8> = Vec::new();
    let mut stdin_eof = false;
    // Lives as long as the session: dropping it (any exit path) stops the
    // acceptor and removes the socket.
    let mut agent_fwd: Option<AgentListener> = None;

    // Phase 1: wait for exec/shell, honoring pty-req and early stdin.
    let mut child = loop {
        let msg = match to_task.recv().await {
            Some(m) => m,
            None => return,
        };
        match msg {
            ToTask::Data(b) => {
                early_stdin.extend_from_slice(&b);
                let _ = cmd_tx.send(Cmd::Consumed { id, n: b.len() as u32 });
            }
            ToTask::Eof => stdin_eof = true,
            ToTask::Close => return,
            ToTask::Request {
                kind,
                want_reply,
                data,
            } => match kind.as_str() {
                "pty-req" => {
                    let ok = allocate_pty(&data, &mut allocated);
                    if want_reply {
                        let _ = cmd_tx.send(Cmd::RequestReply { id, success: ok });
                    }
                }
                "window-change" => {
                    let mut r = Reader::new(&data);
                    if let (Ok(c), Ok(rw), Ok(x), Ok(y)) = (r.u32(), r.u32(), r.u32(), r.u32()) {
                        if let Some(p) = &allocated {
                            p.resize(c, rw, x, y);
                        }
                    }
                    if want_reply {
                        let _ = cmd_tx.send(Cmd::RequestReply { id, success: true });
                    }
                }
                "auth-agent-req@openssh.com" => {
                    let ok = if !permit_agent {
                        tracing::info!("agent forwarding refused (no --permit-agent-forwarding)");
                        false
                    } else if agent_fwd.is_some() {
                        true // one socket per session; a repeat is harmless
                    } else {
                        agent_fwd =
                            start_agent_listener(&cmd_tx, open_admission.clone(), user.as_ref());
                        agent_fwd.is_some()
                    };
                    if want_reply {
                        let _ = cmd_tx.send(Cmd::RequestReply { id, success: ok });
                    }
                }
                "exec" | "shell" => {
                    // The login shell: the account's shell when we know it,
                    // else $SHELL / /bin/sh.
                    let shell = match &user {
                        Some(u) => u.shell.clone(),
                        None => std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into()),
                    };
                    // What the client asked to run (empty for a shell).
                    let requested = if kind == "exec" {
                        let mut r = Reader::new(&data);
                        Some(r.utf8().unwrap_or("").to_owned())
                    } else {
                        None
                    };
                    let mut cmd = Command::new(&shell);
                    match &force_command {
                        // A certificate's force-command overrides the request:
                        // run the pinned command, and expose what the client
                        // asked for as SSH_ORIGINAL_COMMAND (as OpenSSH does).
                        Some(forced) => {
                            cmd.arg("-c").arg(forced);
                            if let Some(orig) = &requested {
                                cmd.env("SSH_ORIGINAL_COMMAND", orig);
                            }
                        }
                        None => {
                            if let Some(line) = &requested {
                                cmd.arg("-c").arg(line);
                            }
                        }
                    }
                    cmd.kill_on_drop(true);
                    // The child sees an SSH_AUTH_SOCK only when the client
                    // forwarded an agent — never the daemon's own, which
                    // would hand every session the operator's keys.
                    cmd.env_remove("SSH_AUTH_SOCK");
                    if let Some(fwd) = &agent_fwd {
                        cmd.env("SSH_AUTH_SOCK", &fwd.sock);
                    }
                    match spawn_child(&mut cmd, allocated.as_mut(), user.as_ref()) {
                        Ok(c) => {
                            if want_reply {
                                let _ = cmd_tx.send(Cmd::RequestReply { id, success: true });
                            }
                            break c;
                        }
                        Err(e) => {
                            tracing::warn!("spawn failed: {e}");
                            if want_reply {
                                let _ = cmd_tx.send(Cmd::RequestReply { id, success: false });
                            }
                            let _ = cmd_tx.send(Cmd::Close { id });
                            return;
                        }
                    }
                }
                "subsystem" => {
                    let mut r = Reader::new(&data);
                    let name = r.utf8().unwrap_or("").to_owned();
                    // We speak one subsystem: sftp. A certificate force-command
                    // means "only this command" — so it denies subsystems too.
                    if force_command.is_some() || name != "sftp" {
                        if force_command.is_some() {
                            tracing::info!(%name, "refusing subsystem: certificate forces a command");
                        } else {
                            tracing::info!(%name, "refusing unknown subsystem");
                        }
                        if want_reply {
                            let _ = cmd_tx.send(Cmd::RequestReply { id, success: false });
                        }
                        continue;
                    }
                    // Run our own sftp-server: re-exec this binary in
                    // `--internal-sftp` mode through the same privilege-drop
                    // path as a shell, so it operates as the session user.
                    let exe = match std::env::current_exe() {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!("cannot locate sftp-server: {e}");
                            if want_reply {
                                let _ = cmd_tx.send(Cmd::RequestReply { id, success: false });
                            }
                            continue;
                        }
                    };
                    let mut cmd = Command::new(exe);
                    cmd.arg("--internal-sftp");
                    cmd.kill_on_drop(true);
                    cmd.env_remove("SSH_AUTH_SOCK");
                    if let Some(fwd) = &agent_fwd {
                        cmd.env("SSH_AUTH_SOCK", &fwd.sock);
                    }
                    match spawn_child(&mut cmd, None, user.as_ref()) {
                        Ok(c) => {
                            if want_reply {
                                let _ = cmd_tx.send(Cmd::RequestReply { id, success: true });
                            }
                            break c;
                        }
                        Err(e) => {
                            tracing::warn!("sftp-server spawn failed: {e}");
                            if want_reply {
                                let _ = cmd_tx.send(Cmd::RequestReply { id, success: false });
                            }
                            let _ = cmd_tx.send(Cmd::Close { id });
                            return;
                        }
                    }
                }
                _ => {
                    if want_reply {
                        let _ = cmd_tx.send(Cmd::RequestReply { id, success: false });
                    }
                }
            },
            ToTask::RequestReply(_) | ToTask::ExtData(..) => {}
        }
    };

    // Phase 2: pump child stdio (pipes or pty master) <-> channel.
    let mut child_stdin = child.stdin.take();
    let mut child_stdout = child.stdout.take();
    let mut child_stderr = child.stderr.take();
    let (mut pty_r, mut pty_w, pty_fd) = match allocated.take() {
        Some(p) => {
            let (master, fd) = p.into_parts();
            let (r, w) = tokio::io::split(master);
            (Some(r), Some(w), Some(fd))
        }
        None => (None, None, None),
    };
    let is_pty = pty_fd.is_some();

    if !early_stdin.is_empty() {
        if let Some(w) = pty_w.as_mut() {
            let _ = w.write_all(&early_stdin).await;
        } else if let Some(cin) = child_stdin.as_mut() {
            let _ = cin.write_all(&early_stdin).await;
        }
        early_stdin.clear();
    }
    if stdin_eof && !is_pty {
        child_stdin = None;
    }

    let mut out_buf = vec![0u8; MAX_CHUNK as usize];
    let mut pty_buf = vec![0u8; if is_pty { MAX_CHUNK as usize } else { 0 }];
    let mut err_buf = vec![0u8; MAX_CHUNK as usize];
    let mut stdout_eof = false;
    let mut stderr_eof = is_pty; // a pty folds stderr into the terminal
    let mut exited: Option<std::process::ExitStatus> = None;

    loop {
        // Child gone and its output drained: report status and close.
        if let (Some(status), true, true) = (exited, stdout_eof, stderr_eof) {
            let _ = cmd_tx.send(Cmd::ChannelRequest {
                id,
                body: exit_request_body(status),
            });
            let _ = cmd_tx.send(Cmd::Eof { id });
            let _ = cmd_tx.send(Cmd::Close { id });
            break;
        }

        tokio::select! {
            biased;
            msg = to_task.recv() => match msg {
                None | Some(ToTask::Close) => break,
                Some(ToTask::Data(b)) => {
                    if let Some(w) = pty_w.as_mut() {
                        if w.write_all(&b).await.is_err() {
                            pty_w = None;
                        }
                    } else if let Some(cin) = child_stdin.as_mut() {
                        if cin.write_all(&b).await.is_err() {
                            child_stdin = None;
                        }
                    }
                    let _ = cmd_tx.send(Cmd::Consumed { id, n: b.len() as u32 });
                }
                Some(ToTask::Eof) => {
                    if !is_pty {
                        child_stdin = None;
                    }
                }
                Some(ToTask::Request { kind, want_reply, data }) => {
                    if kind == "window-change" {
                        let mut r = Reader::new(&data);
                        if let (Ok(c), Ok(rw), Ok(x), Ok(y)) = (r.u32(), r.u32(), r.u32(), r.u32()) {
                            if let Some(fd) = pty_fd {
                                pty::resize_fd(fd, c, rw, x, y);
                            }
                        }
                    }
                    if want_reply {
                        let _ = cmd_tx.send(Cmd::RequestReply { id, success: kind == "window-change" });
                    }
                }
                Some(ToTask::ExtData(..)) | Some(ToTask::RequestReply(_)) => {}
            },
            n = maybe_read(child_stdout.as_mut(), &mut out_buf), if !stdout_eof && !is_pty => match n {
                Ok(0) | Err(_) => stdout_eof = true,
                Ok(n) => {
                    if !send_credited(&cmd_tx, &credit, id, remote_max, None, &out_buf[..n]).await {
                        break;
                    }
                }
            },
            n = read_opt(pty_r.as_mut(), &mut pty_buf), if !stdout_eof && is_pty => match n {
                Ok(0) | Err(_) => stdout_eof = true,
                Ok(n) => {
                    if !send_credited(&cmd_tx, &credit, id, remote_max, None, &pty_buf[..n]).await {
                        break;
                    }
                }
            },
            n = maybe_read(child_stderr.as_mut(), &mut err_buf), if !stderr_eof => match n {
                Ok(0) | Err(_) => stderr_eof = true,
                Ok(n) => {
                    let ok =
                        send_credited(&cmd_tx, &credit, id, remote_max, Some(STDERR), &err_buf[..n])
                            .await;
                    if !ok {
                        break;
                    }
                }
            },
            status = child.wait(), if exited.is_none() => {
                exited = Some(status.unwrap_or_else(|_| dummy_failure()));
            }
        }
    }
}

#[cfg(unix)]
fn allocate_pty(data: &[u8], slot: &mut Option<pty::Pty>) -> bool {
    let mut r = Reader::new(data);
    let parsed = (|| -> Result<_, crate::wire::WireError> {
        Ok((r.utf8()?.to_owned(), r.u32()?, r.u32()?, r.u32()?, r.u32()?))
    })();
    let Ok((term, cols, rows, xpix, ypix)) = parsed else {
        return false;
    };
    match pty::Pty::allocate(&term, cols, rows, xpix, ypix) {
        Ok(p) => {
            *slot = Some(p);
            true
        }
        Err(e) => {
            tracing::warn!("pty allocation failed: {e}");
            false
        }
    }
}

/// Spawn the child: wire its stdio to the pty slave (if any) or to pipes,
/// set the login environment and working directory, and — in one post-fork
/// `pre_exec` hook — become a session leader with the pty as controlling
/// terminal and, when running as root, drop to the target user's
/// credentials before exec.
/// A per-session agent socket whose connections become agent channels back
/// to the client. Dropping it stops the acceptor and removes the socket.
#[cfg(unix)]
struct AgentListener {
    sock: std::path::PathBuf,
    dir: std::path::PathBuf,
    abort: tokio::task::AbortHandle,
}

#[cfg(unix)]
impl Drop for AgentListener {
    fn drop(&mut self) {
        self.abort.abort();
        std::fs::remove_file(&self.sock).ok();
        std::fs::remove_dir(&self.dir).ok();
    }
}

/// Bind the session's agent socket and relay every connection to it as an
/// agent channel. The socket sits in a fresh 0700 directory owned by the
/// session user, and connections are accepted only from that user (or
/// ourselves, when not dropping privileges) — checked by peer credentials,
/// not just file modes.
#[cfg(unix)]
fn start_agent_listener(
    cmd_tx: &mpsc::UnboundedSender<Cmd>,
    open_admission: Arc<Semaphore>,
    user: Option<&super::UserContext>,
) -> Option<AgentListener> {
    use rand_core::{OsRng, RngCore};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let mut rnd = [0u8; 8];
    OsRng.fill_bytes(&mut rnd);
    let name: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    let dir = std::env::temp_dir().join(format!("shh-{name}"));
    if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        tracing::warn!("agent socket dir: {e}");
        return None;
    }
    let sock = dir.join(format!("agent.{}", std::process::id()));
    let cleanup_dir = || {
        std::fs::remove_dir(&dir).ok();
    };
    let listener = match tokio::net::UnixListener::bind(&sock) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("agent socket bind: {e}");
            cleanup_dir();
            return None;
        }
    };
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600)).ok();

    // When we will drop privileges, the child runs as the session user —
    // the socket must be theirs to connect to.
    let ours = nix::unistd::geteuid();
    let expect_uid = match user.filter(|_| ours.is_root()) {
        Some(u) => {
            let uid = nix::unistd::Uid::from_raw(u.uid);
            let gid = nix::unistd::Gid::from_raw(u.gid);
            if let Err(e) = nix::unistd::chown(&dir, Some(uid), Some(gid))
                .and_then(|()| nix::unistd::chown(&sock, Some(uid), Some(gid)))
            {
                tracing::warn!("agent socket chown: {e}");
                std::fs::remove_file(&sock).ok();
                cleanup_dir();
                return None;
            }
            u.uid
        }
        None => ours.as_raw(),
    };

    let cmd_tx = cmd_tx.clone();
    let ours = ours.as_raw();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            match stream.peer_cred() {
                Ok(c) if c.uid() == expect_uid || c.uid() == ours => {}
                Ok(c) => {
                    tracing::warn!(uid = c.uid(), "refusing agent connection from another uid");
                    continue;
                }
                Err(e) => {
                    tracing::warn!("cannot identify agent socket peer: {e}");
                    continue;
                }
            }
            let Ok(_permit) = open_admission.clone().acquire_owned().await else {
                break; // the connection is gone
            };
            let _ = cmd_tx.send(Cmd::OpenTunnel {
                channel_type: AGENT_CHANNEL,
                addr: String::new(),
                port: 0,
                orig_host: String::new(),
                orig_port: 0,
                stream: Box::new(stream),
                _permit,
            });
        }
    });

    tracing::info!(sock = %sock.display(), "agent forwarding socket ready");
    Some(AgentListener {
        sock,
        dir,
        abort: task.abort_handle(),
    })
}

#[cfg(unix)]
fn spawn_child(
    cmd: &mut Command,
    pty: Option<&mut pty::Pty>,
    user: Option<&super::UserContext>,
) -> std::io::Result<tokio::process::Child> {
    let is_pty = match pty {
        Some(p) => {
            let slave = p
                .take_slave()
                .ok_or_else(|| std::io::Error::other("pty slave already consumed"))?;
            cmd.stdin(Stdio::from(slave.try_clone()?))
                .stdout(Stdio::from(slave.try_clone()?))
                .stderr(Stdio::from(slave))
                .env("TERM", &p.term);
            true
        }
        None => {
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            false
        }
    };

    // Login environment and home directory.
    if let Some(u) = user {
        cmd.env("HOME", &u.home)
            .env("USER", &u.name)
            .env("LOGNAME", &u.name)
            .env("SHELL", &u.shell)
            .current_dir(&u.home);
    }

    // The privilege drop only happens when we can actually do it (root).
    let drop = user
        .filter(|_| nix::unistd::geteuid().is_root())
        .map(|u| {
            (
                nix::unistd::Uid::from_raw(u.uid),
                nix::unistd::Gid::from_raw(u.gid),
                std::ffi::CString::new(u.name.clone()).ok(),
            )
        });

    // One post-fork hook: session/controlling-tty setup as root, then the
    // credential drop (gid + supplementary groups + uid, in that order).
    unsafe {
        cmd.pre_exec(move || {
            if is_pty {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if let Some((uid, gid, name)) = &drop {
                nix::unistd::setgid(*gid).map_err(std::io::Error::from)?;
                if let Some(name) = name {
                    nix::unistd::initgroups(name, *gid).map_err(std::io::Error::from)?;
                }
                nix::unistd::setuid(*uid).map_err(std::io::Error::from)?;
            }
            Ok(())
        });
    }
    cmd.spawn()
}

/// Read from an optional split-read half (the pty master).
#[cfg(unix)]
async fn read_opt<R: AsyncRead + Unpin>(
    r: Option<&mut R>,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    match r {
        Some(r) => r.read(buf).await,
        None => std::future::pending().await,
    }
}

/// A synthetic non-zero status for the rare case that reaping the child
/// fails; the client still gets a definite exit.
#[cfg(unix)]
fn dummy_failure() -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    std::process::ExitStatus::from_raw(1 << 8)
}
