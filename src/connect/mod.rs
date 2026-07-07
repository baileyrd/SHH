//! The connection protocol (RFC 4254), scoped to what a remote-command
//! tool actually needs: one `session` channel per connection, `exec` or
//! `shell`, bidirectional data with real window flow control, exit status.
//!
//! Not present, on purpose (for now): PTY allocation, TCP forwarding, X11,
//! agent forwarding. Forwarding will arrive with an explicit allowlist
//! model rather than RFC 4254's open-by-default posture.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;

use crate::transport::Transport;
use crate::wire::{msg, Reader, Writer};
use crate::{Error, Result};

/// Receive window we grant the peer, and the largest data chunk we send.
const LOCAL_WINDOW: u32 = 2 * 1024 * 1024;
const MAX_CHUNK: u32 = 32 * 1024;
/// Re-grant the window when the peer has consumed half of it.
const WINDOW_REFILL: u32 = LOCAL_WINDOW / 2;

const STDERR: u32 = 1; // SSH_EXTENDED_DATA_STDERR

pub struct ExitStatus {
    pub code: Option<u32>,
    pub signal: Option<String>,
}

// ------------------------------------------------------- packet helpers --

fn chan(byte: u8, peer: u32) -> Writer {
    let mut w = Writer::new();
    w.byte(byte);
    w.u32(peer);
    w
}

fn data_packet(peer: u32, data: &[u8]) -> Vec<u8> {
    let mut w = chan(msg::CHANNEL_DATA, peer);
    w.string(data);
    w.into_bytes()
}

fn ext_data_packet(peer: u32, kind: u32, data: &[u8]) -> Vec<u8> {
    let mut w = chan(msg::CHANNEL_EXTENDED_DATA, peer);
    w.u32(kind);
    w.string(data);
    w.into_bytes()
}

fn window_adjust(peer: u32, add: u32) -> Vec<u8> {
    let mut w = chan(msg::CHANNEL_WINDOW_ADJUST, peer);
    w.u32(add);
    w.into_bytes()
}

fn simple(byte: u8, peer: u32) -> Vec<u8> {
    chan(byte, peer).into_bytes()
}

/// Track the window we granted the peer; returns Some(refill) when it is
/// time to top it up.
fn consume_local_window(window: &mut u32, len: usize) -> Result<Option<u32>> {
    let len = u32::try_from(len).map_err(|_| Error::proto("data larger than any window"))?;
    *window = window
        .checked_sub(len)
        .ok_or_else(|| Error::proto("peer overflowed the data window"))?;
    if *window < LOCAL_WINDOW - WINDOW_REFILL {
        let add = LOCAL_WINDOW - *window;
        *window = LOCAL_WINDOW;
        Ok(Some(add))
    } else {
        Ok(None)
    }
}

/// Send as much of `pending` as the peer's window allows.
async fn flush_pending<S>(
    t: &mut Transport<S>,
    peer: u32,
    kind: Option<u32>,
    pending: &mut Vec<u8>,
    remote_window: &mut u32,
    remote_max: u32,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    while *remote_window > 0 && !pending.is_empty() {
        let n = pending
            .len()
            .min(*remote_window as usize)
            .min(remote_max as usize)
            .min(MAX_CHUNK as usize);
        let chunk: Vec<u8> = pending.drain(..n).collect();
        let pkt = match kind {
            None => data_packet(peer, &chunk),
            Some(k) => ext_data_packet(peer, k, &chunk),
        };
        t.send(&pkt).await?;
        *remote_window -= n as u32;
    }
    Ok(())
}

/// Reply to a GLOBAL_REQUEST we don't serve (they're all optional
/// extensions; OpenSSH sends `hostkeys-00@openssh.com` routinely).
async fn refuse_global_request<S>(t: &mut Transport<S>, payload: &[u8]) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut r = Reader::new(payload);
    r.byte()?;
    let _name = r.utf8()?;
    if r.boolean()? {
        t.send(&[msg::REQUEST_FAILURE]).await?;
    }
    Ok(())
}

// -------------------------------------------------------------- client --

/// Open a session, run `command` (or a shell when `None`), shuttle stdio,
/// and return the remote exit status.
pub async fn client_session<S, I, O, E>(
    t: &mut Transport<S>,
    command: Option<&str>,
    mut stdin: I,
    mut stdout: O,
    mut stderr: E,
) -> Result<ExitStatus>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    // --- open the channel
    let mut w = Writer::new();
    w.byte(msg::CHANNEL_OPEN);
    w.utf8("session");
    w.u32(0); // our channel id
    w.u32(LOCAL_WINDOW);
    w.u32(MAX_CHUNK);
    t.send(&w.into_bytes()).await?;

    let (peer, mut remote_window, remote_max) = loop {
        let p = t.recv().await?;
        let mut r = Reader::new(&p);
        match r.byte()? {
            msg::CHANNEL_OPEN_CONFIRMATION => {
                let _ours = r.u32()?;
                let peer = r.u32()?;
                let window = r.u32()?;
                let max = r.u32()?;
                break (peer, window, max);
            }
            msg::CHANNEL_OPEN_FAILURE => {
                let _ours = r.u32()?;
                let _reason = r.u32()?;
                let desc = r.utf8().unwrap_or("no reason given");
                return Err(Error::Channel(format!("server refused session: {desc}")));
            }
            msg::GLOBAL_REQUEST => refuse_global_request(t, &p).await?,
            other => return Err(Error::proto(format!("unexpected message {other}"))),
        }
    };

    // --- request exec or shell
    let mut w = chan(msg::CHANNEL_REQUEST, peer);
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
    t.send(&w.into_bytes()).await?;

    let mut local_window = LOCAL_WINDOW;
    let mut exit: Option<ExitStatus> = None;

    loop {
        let p = t.recv().await?;
        let mut r = Reader::new(&p);
        match r.byte()? {
            msg::CHANNEL_SUCCESS => break,
            msg::CHANNEL_FAILURE => {
                return Err(Error::Channel("server refused to run the command".into()))
            }
            msg::CHANNEL_WINDOW_ADJUST => {
                r.u32()?;
                remote_window = remote_window.saturating_add(r.u32()?);
            }
            msg::GLOBAL_REQUEST => refuse_global_request(t, &p).await?,
            other => return Err(Error::proto(format!("unexpected message {other}"))),
        }
    }

    // --- shuttle data until the channel closes in both directions
    let mut stdin_buf = vec![0u8; MAX_CHUNK as usize];
    let mut pending_in: Vec<u8> = Vec::new();
    let mut stdin_eof = false;
    let mut sent_eof = false;
    let mut sent_close = false;
    let mut recvd_close = false;

    while !(sent_close && recvd_close) {
        // Ship queued stdin as the window allows.
        flush_pending(t, peer, None, &mut pending_in, &mut remote_window, remote_max).await?;
        if stdin_eof && pending_in.is_empty() && !sent_eof {
            t.send(&simple(msg::CHANNEL_EOF, peer)).await?;
            sent_eof = true;
        }
        if t.should_rekey() {
            t.rekey_initiate().await?;
            continue;
        }

        tokio::select! {
            biased;
            // Both arms are cancel-safe: recv_raw resumes via the
            // transport's read state, a dropped read() loses nothing.
            pkt = t.recv_raw() => {
                let p = pkt?;
                let mut r = Reader::new(&p);
                match r.byte()? {
                    msg::IGNORE | msg::DEBUG | msg::UNIMPLEMENTED => {}
                    msg::EXT_INFO => t.note_ext_info(&p)?,
                    msg::KEXINIT => t.rekey_respond(p).await?,
                    msg::DISCONNECT => {
                        // A peer that says goodbye after delivering the
                        // exit status is merely terse, not broken.
                        match exit {
                            Some(e) => return Ok(e),
                            None => return Err(Error::proto("disconnect before exit status")),
                        }
                    }
                    msg::CHANNEL_DATA => {
                        r.u32()?;
                        let data = r.string()?;
                        if let Some(add) = consume_local_window(&mut local_window, data.len())? {
                            t.send(&window_adjust(peer, add)).await?;
                        }
                        stdout.write_all(data).await?;
                        stdout.flush().await?;
                    }
                    msg::CHANNEL_EXTENDED_DATA => {
                        r.u32()?;
                        let kind = r.u32()?;
                        let data = r.string()?;
                        if let Some(add) = consume_local_window(&mut local_window, data.len())? {
                            t.send(&window_adjust(peer, add)).await?;
                        }
                        if kind == STDERR {
                            stderr.write_all(data).await?;
                            stderr.flush().await?;
                        }
                    }
                    msg::CHANNEL_WINDOW_ADJUST => {
                        r.u32()?;
                        remote_window = remote_window.saturating_add(r.u32()?);
                    }
                    msg::CHANNEL_REQUEST => {
                        r.u32()?;
                        let kind = r.utf8()?.to_owned();
                        let want_reply = r.boolean()?;
                        match kind.as_str() {
                            "exit-status" => {
                                exit = Some(ExitStatus { code: Some(r.u32()?), signal: None });
                            }
                            "exit-signal" => {
                                exit = Some(ExitStatus {
                                    code: None,
                                    signal: Some(r.utf8()?.to_owned()),
                                });
                            }
                            _ => {}
                        }
                        if want_reply {
                            t.send(&simple(msg::CHANNEL_FAILURE, peer)).await?;
                        }
                    }
                    msg::CHANNEL_EOF => {}
                    msg::CHANNEL_CLOSE => {
                        recvd_close = true;
                        if !sent_close {
                            t.send(&simple(msg::CHANNEL_CLOSE, peer)).await?;
                            sent_close = true;
                        }
                    }
                    msg::GLOBAL_REQUEST => refuse_global_request(t, &p).await?,
                    other => return Err(Error::proto(format!("unexpected message {other}"))),
                }
            }
            n = stdin.read(&mut stdin_buf), if pending_in.is_empty() && !stdin_eof => {
                match n? {
                    0 => stdin_eof = true,
                    n => pending_in.extend_from_slice(&stdin_buf[..n]),
                }
            }
        }
    }

    Ok(exit.unwrap_or(ExitStatus { code: None, signal: None }))
}

// -------------------------------------------------------------- server --

/// Serve one session channel: accept it, run the requested command, wire
/// the child's stdio to the channel, report the exit status.
pub async fn server_session<S>(t: &mut Transport<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // --- accept a session channel
    let (client_id, mut remote_window, remote_max) = loop {
        let p = t.recv().await?;
        let mut r = Reader::new(&p);
        match r.byte()? {
            msg::CHANNEL_OPEN => {
                let kind = r.utf8()?.to_owned();
                let sender = r.u32()?;
                let window = r.u32()?;
                let max = r.u32()?;
                if kind == "session" {
                    let mut w = chan(msg::CHANNEL_OPEN_CONFIRMATION, sender);
                    w.u32(0); // our id
                    w.u32(LOCAL_WINDOW);
                    w.u32(MAX_CHUNK);
                    t.send(&w.into_bytes()).await?;
                    break (sender, window, max);
                }
                let mut w = chan(msg::CHANNEL_OPEN_FAILURE, sender);
                w.u32(3); // SSH_OPEN_UNKNOWN_CHANNEL_TYPE
                w.utf8("only session channels are served");
                w.utf8("");
                t.send(&w.into_bytes()).await?;
            }
            msg::GLOBAL_REQUEST => refuse_global_request(t, &p).await?,
            other => return Err(Error::proto(format!("unexpected message {other}"))),
        }
    };

    // --- wait for exec/shell; refuse decorations we don't do (pty, env)
    let mut early_stdin: Vec<u8> = Vec::new();
    let mut local_window = LOCAL_WINDOW;
    let mut stdin_eof = false;
    let mut child = loop {
        let p = t.recv().await?;
        let mut r = Reader::new(&p);
        match r.byte()? {
            msg::CHANNEL_REQUEST => {
                r.u32()?;
                let kind = r.utf8()?.to_owned();
                let want_reply = r.boolean()?;
                let mut cmd = match kind.as_str() {
                    "exec" => {
                        let line = r.utf8()?.to_owned();
                        let mut c = Command::new("/bin/sh");
                        c.arg("-c").arg(line);
                        c
                    }
                    "shell" => {
                        // No PTY support yet, so this is a pipe shell:
                        // fine for scripted use, not a login terminal.
                        Command::new(std::env::var("SHELL").unwrap_or("/bin/sh".into()))
                    }
                    _ => {
                        if want_reply {
                            t.send(&simple(msg::CHANNEL_FAILURE, client_id)).await?;
                        }
                        continue;
                    }
                };
                let child = cmd
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn();
                match child {
                    Ok(c) => {
                        if want_reply {
                            t.send(&simple(msg::CHANNEL_SUCCESS, client_id)).await?;
                        }
                        break c;
                    }
                    Err(e) => {
                        tracing::warn!("spawn failed: {e}");
                        if want_reply {
                            t.send(&simple(msg::CHANNEL_FAILURE, client_id)).await?;
                        }
                        return Err(Error::Channel(format!("cannot spawn: {e}")));
                    }
                }
            }
            // A pipelining client may ship stdin before we accepted exec.
            msg::CHANNEL_DATA => {
                r.u32()?;
                let data = r.string()?;
                if let Some(add) = consume_local_window(&mut local_window, data.len())? {
                    t.send(&window_adjust(client_id, add)).await?;
                }
                early_stdin.extend_from_slice(data);
            }
            msg::CHANNEL_EOF => stdin_eof = true,
            msg::CHANNEL_WINDOW_ADJUST => {
                r.u32()?;
                remote_window = remote_window.saturating_add(r.u32()?);
            }
            msg::GLOBAL_REQUEST => refuse_global_request(t, &p).await?,
            other => return Err(Error::proto(format!("unexpected message {other}"))),
        }
    };

    // --- pump: child stdio ⇄ channel
    let mut child_stdin = child.stdin.take();
    let mut child_stdout = child.stdout.take().expect("stdout was piped");
    let mut child_stderr = child.stderr.take().expect("stderr was piped");

    if !early_stdin.is_empty() {
        if let Some(cin) = child_stdin.as_mut() {
            cin.write_all(&early_stdin).await.ok();
        }
        early_stdin.clear();
    }
    if stdin_eof {
        child_stdin = None; // dropping closes the pipe
    }

    let mut out_buf = vec![0u8; MAX_CHUNK as usize];
    let mut err_buf = vec![0u8; MAX_CHUNK as usize];
    let mut pending_out: Vec<u8> = Vec::new();
    let mut pending_err: Vec<u8> = Vec::new();
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    let mut exit: Option<std::process::ExitStatus> = None;
    let mut sent_close = false;
    let mut recvd_close = false;
    let mut reported = false;

    while !(sent_close && recvd_close) {
        flush_pending(t, client_id, None, &mut pending_out, &mut remote_window, remote_max)
            .await?;
        flush_pending(
            t,
            client_id,
            Some(STDERR),
            &mut pending_err,
            &mut remote_window,
            remote_max,
        )
        .await?;

        // Child fully drained and gone: report and close our side.
        if let (Some(status), true, true, true, true, false) = (
            exit,
            stdout_eof,
            stderr_eof,
            pending_out.is_empty(),
            pending_err.is_empty(),
            reported,
        ) {
            send_exit(t, client_id, status).await?;
            t.send(&simple(msg::CHANNEL_EOF, client_id)).await?;
            t.send(&simple(msg::CHANNEL_CLOSE, client_id)).await?;
            sent_close = true;
            reported = true;
            continue;
        }
        if t.should_rekey() {
            t.rekey_initiate().await?;
            continue;
        }

        tokio::select! {
            biased;
            pkt = t.recv_raw() => {
                let p = pkt?;
                let mut r = Reader::new(&p);
                match r.byte()? {
                    msg::IGNORE | msg::DEBUG | msg::UNIMPLEMENTED => {}
                    msg::EXT_INFO => t.note_ext_info(&p)?,
                    msg::KEXINIT => t.rekey_respond(p).await?,
                    msg::DISCONNECT => return Err(Error::Disconnect("peer left".into())),
                    msg::CHANNEL_DATA => {
                        r.u32()?;
                        let data = r.string()?;
                        if let Some(add) = consume_local_window(&mut local_window, data.len())? {
                            t.send(&window_adjust(client_id, add)).await?;
                        }
                        if let Some(cin) = child_stdin.as_mut() {
                            // Backpressure note: a child that never reads
                            // can stall this write; the client's window
                            // (2 MiB) bounds how much can pile up.
                            if cin.write_all(data).await.is_err() {
                                child_stdin = None; // child closed its end
                            }
                        }
                    }
                    msg::CHANNEL_EOF => { child_stdin = None; }
                    msg::CHANNEL_CLOSE => {
                        recvd_close = true;
                        if !sent_close {
                            t.send(&simple(msg::CHANNEL_CLOSE, client_id)).await?;
                            sent_close = true;
                        }
                    }
                    msg::CHANNEL_WINDOW_ADJUST => {
                        r.u32()?;
                        remote_window = remote_window.saturating_add(r.u32()?);
                    }
                    msg::CHANNEL_REQUEST => {
                        r.u32()?;
                        let _kind = r.utf8()?;
                        if r.boolean()? {
                            t.send(&simple(msg::CHANNEL_FAILURE, client_id)).await?;
                        }
                    }
                    msg::GLOBAL_REQUEST => refuse_global_request(t, &p).await?,
                    other => return Err(Error::proto(format!("unexpected message {other}"))),
                }
            }
            n = child_stdout.read(&mut out_buf), if !stdout_eof && pending_out.is_empty() => {
                match n? {
                    0 => stdout_eof = true,
                    n => pending_out.extend_from_slice(&out_buf[..n]),
                }
            }
            n = child_stderr.read(&mut err_buf), if !stderr_eof && pending_err.is_empty() => {
                match n? {
                    0 => stderr_eof = true,
                    n => pending_err.extend_from_slice(&err_buf[..n]),
                }
            }
            status = child.wait(), if exit.is_none() => {
                exit = Some(status?);
            }
        }
    }
    Ok(())
}

async fn send_exit<S>(
    t: &mut Transport<S>,
    peer: u32,
    status: std::process::ExitStatus,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    match status.code() {
        Some(code) => {
            let mut w = chan(msg::CHANNEL_REQUEST, peer);
            w.utf8("exit-status");
            w.boolean(false);
            w.u32(code as u32);
            t.send(&w.into_bytes()).await
        }
        None => {
            #[cfg(unix)]
            let name = {
                use std::os::unix::process::ExitStatusExt;
                match status.signal() {
                    Some(1) => "HUP",
                    Some(2) => "INT",
                    Some(3) => "QUIT",
                    Some(6) => "ABRT",
                    Some(9) => "KILL",
                    Some(11) => "SEGV",
                    Some(13) => "PIPE",
                    Some(15) => "TERM",
                    _ => "UNKNOWN",
                }
            };
            #[cfg(not(unix))]
            let name = "UNKNOWN";
            let mut w = chan(msg::CHANNEL_REQUEST, peer);
            w.utf8("exit-signal");
            w.boolean(false);
            w.utf8(name);
            w.boolean(false); // no core dump info
            w.utf8("");
            w.utf8("");
            t.send(&w.into_bytes()).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth;
    use crate::crypto::ed25519::PrivateKey;
    use crate::transport::{ClientConfig, ServerConfig};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::duplex;

    /// AsyncWrite that appends into a Vec.
    #[derive(Default)]
    struct Sink(Vec<u8>);
    impl AsyncWrite for Sink {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.0.extend_from_slice(buf);
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

    async fn run(
        command: &str,
        stdin: &'static [u8],
    ) -> (ExitStatus, Vec<u8>, Vec<u8>) {
        let (a, b) = duplex(1 << 20);
        let user_key = PrivateKey::generate();
        let host_key = PrivateKey::generate();
        let policy = auth::Policy {
            user: Some("tester".into()),
            keys: vec![user_key.public()],
            banner: None,
        };

        let client_side = async move {
            let mut t = Transport::client(
                a,
                ClientConfig {
                    verify_host_key: Box::new(|_| Ok(())),
                },
            )
            .await?;
            auth::client(&mut t, "tester", &user_key, |_| {}).await?;
            let mut out = Sink::default();
            let mut err = Sink::default();
            let status = client_session(&mut t, Some(command), stdin, &mut out, &mut err).await?;
            Ok::<_, Error>((status, out.0, err.0))
        };
        let server_side = async move {
            let mut t = Transport::server(b, ServerConfig { host_key }).await?;
            auth::server(&mut t, &policy).await?;
            server_session(&mut t).await
        };
        let (c, s) = tokio::join!(client_side, server_side);
        s.unwrap();
        c.unwrap()
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
}
