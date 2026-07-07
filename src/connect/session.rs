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

use std::process::Stdio;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot, Semaphore};

use super::mux::{Cmd, ToTask};
use super::{maybe_read, maybe_recv, pty, ExitStatus, PtyRequest, WindowChange, MAX_CHUNK, STDERR};
use crate::wire::{Reader, Writer};

/// What a client wants from a session channel. Stdio is boxed so the
/// multiplexer's command enum stays free of type parameters.
pub struct SessionSpec {
    pub command: Option<String>,
    pub pty: Option<PtyRequest>,
    pub resize: Option<mpsc::Receiver<WindowChange>>,
    pub stdin: Box<dyn AsyncRead + Unpin + Send>,
    pub stdout: Box<dyn AsyncWrite + Unpin + Send>,
    pub stderr: Box<dyn AsyncWrite + Unpin + Send>,
    /// Delivered the remote exit status when the channel closes.
    pub exit: oneshot::Sender<ExitStatus>,
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
        pty,
        mut resize,
        mut stdin,
        mut stdout,
        mut stderr,
        exit,
        ..
    } = spec;

    // Requests: optional pty, then exec/shell — each awaits its reply.
    let give_up = |exit: oneshot::Sender<ExitStatus>| {
        let _ = exit.send(ExitStatus { code: None, signal: None });
        let _ = cmd_tx.send(Cmd::Close { id });
    };
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
        body: exec_or_shell_body(&command),
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

pub(crate) async fn session_server_task(
    id: u32,
    credit: Arc<Semaphore>,
    remote_max: u32,
    mut to_task: mpsc::UnboundedReceiver<ToTask>,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
) {
    let mut allocated: Option<pty::Pty> = None;
    let mut early_stdin: Vec<u8> = Vec::new();
    let mut stdin_eof = false;

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
                "exec" | "shell" => {
                    let mut cmd = if kind == "exec" {
                        let mut r = Reader::new(&data);
                        let line = r.utf8().unwrap_or("").to_owned();
                        let mut c = Command::new("/bin/sh");
                        c.arg("-c").arg(line);
                        c
                    } else {
                        Command::new(std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into()))
                    };
                    cmd.kill_on_drop(true);
                    match spawn_child(&mut cmd, allocated.as_mut()) {
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

/// Spawn the child, on the pty slave if one was allocated, else on pipes.
fn spawn_child(
    cmd: &mut Command,
    pty: Option<&mut pty::Pty>,
) -> std::io::Result<tokio::process::Child> {
    match pty {
        Some(p) => spawn_on_pty(cmd, p),
        None => cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn(),
    }
}

/// Spawn with the pty slave as stdio and controlling terminal, in a new
/// session.
fn spawn_on_pty(cmd: &mut Command, p: &mut pty::Pty) -> std::io::Result<tokio::process::Child> {
    let slave = p
        .take_slave()
        .ok_or_else(|| std::io::Error::other("pty slave already consumed"))?;
    cmd.stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave))
        .env("TERM", &p.term);
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn()
}

/// Read from an optional split-read half (the pty master).
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
fn dummy_failure() -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    std::process::ExitStatus::from_raw(1 << 8)
}
