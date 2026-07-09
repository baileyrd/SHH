//! Live terminal sessions: dial a saved host with `shh::client::connect`
//! (the same authenticated-transport flow the `shh` CLI uses), then drive a
//! pty session over it with stdin/stdout wired to duplex pipes so the
//! frontend can push keystrokes in and receive output as events, instead of
//! real process stdio.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::prelude::{Engine as _, BASE64_STANDARD};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};

use shh::connect::{forward, mux, session, PtyRequest, WindowChange};
use shh::crypto::keyfile;

use rand_core::{OsRng, RngCore};

struct SessionHandle {
    stdin: std::sync::Arc<AsyncMutex<tokio::io::DuplexStream>>,
    resize_tx: mpsc::Sender<WindowChange>,
    conn_task: tokio::task::AbortHandle,
    reader_task: tokio::task::AbortHandle,
}

#[derive(Default)]
pub struct SessionRegistry {
    sessions: Mutex<HashMap<String, SessionHandle>>,
}

impl SessionRegistry {
    fn insert(&self, id: String, handle: SessionHandle) {
        self.sessions.lock().unwrap().insert(id, handle);
    }

    fn remove(&self, id: &str) {
        if let Some(h) = self.sessions.lock().unwrap().remove(id) {
            h.conn_task.abort();
            h.reader_task.abort();
        }
    }

    fn stdin_of(&self, id: &str) -> Option<std::sync::Arc<AsyncMutex<tokio::io::DuplexStream>>> {
        self.sessions.lock().unwrap().get(id).map(|h| h.stdin.clone())
    }

    fn resize(&self, id: &str, change: WindowChange) -> Option<()> {
        self.sessions.lock().unwrap().get(id)?.resize_tx.try_send(change).ok()
    }
}

fn random_id() -> String {
    let mut buf = [0u8; 8];
    OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Serialize, Clone)]
struct SessionOutput {
    id: String,
    data: String,
}

#[derive(Serialize, Clone)]
struct SessionExit {
    id: String,
    message: String,
}

#[derive(Serialize, Clone)]
struct HostTrusted {
    #[serde(rename = "hostId")]
    host_id: String,
    label: String,
    fingerprint: String,
}

/// Dial `host_id`, authenticate, open an interactive pty shell, and return a
/// session id the frontend uses for `send_input`/`resize_session`. New host
/// keys are trusted on first contact and recorded to `~/.shh/known_hosts`
/// (shared with the CLI) — the same posture as `shh --accept-new`. A host
/// key that changes since it was recorded is always refused, first contact
/// or not.
#[tauri::command]
pub async fn connect_host(
    app: AppHandle,
    state: State<'_, crate::AppState>,
    host_id: String,
    cols: u32,
    rows: u32,
) -> Result<String, String> {
    let host = state.hosts.get(&host_id).ok_or("host not found")?;
    let known_hosts = shh::client::default_path("known_hosts");
    let label = keyfile::host_label(&host.hostname, host.port);
    let first_contact = std::fs::read_to_string(&known_hosts)
        .ok()
        .and_then(|text| keyfile::known_hosts_lookup(&text, &label))
        .is_none();

    let opts = shh::client::Options {
        host: host.hostname.clone(),
        port: host.port,
        user: host.user.clone(),
        known_hosts: known_hosts.clone(),
        accept_new: true,
        host_ca: None,
        identity: host.identity.as_ref().map(std::path::PathBuf::from),
        certificate: None,
        no_agent: false,
    };
    let transport = shh::client::connect(&opts).await?;

    if first_contact {
        if let Some(key) = std::fs::read_to_string(&known_hosts)
            .ok()
            .and_then(|text| keyfile::known_hosts_lookup(&text, &label))
        {
            let _ = app.emit(
                "host-trusted",
                HostTrusted {
                    host_id: host.id.clone(),
                    label: label.clone(),
                    fingerprint: key.fingerprint(),
                },
            );
        }
    }

    let pty = PtyRequest {
        term: "xterm-256color".into(),
        cols,
        rows,
        xpix: 0,
        ypix: 0,
    };
    let (resize_tx, resize_rx) = mpsc::channel::<WindowChange>(8);
    let (stdin_ours, stdin_theirs) = tokio::io::duplex(64 * 1024);
    let (stdout_theirs, mut stdout_ours) = tokio::io::duplex(64 * 1024);
    let (exit_tx, exit_rx) = oneshot::channel();

    let conn = mux::Connection::new(transport, forward::Policy::DenyAll);
    let handle = conn.handle();
    handle.open_session(session::SessionSpec {
        command: None,
        subsystem: None,
        pty: Some(pty),
        resize: Some(resize_rx),
        stdin: Box::new(stdin_theirs),
        stdout: Box::new(stdout_theirs),
        stderr: Box::new(tokio::io::sink()), // folded into the pty stream
        exit: exit_tx,
        forward_agent: false,
        end_connection_on_close: true,
    });

    let session_id = random_id();

    let conn_task = tokio::spawn(async move {
        let _ = conn.run(None).await;
    });

    let reader_app = app.clone();
    let reader_id = session_id.clone();
    let reader_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match stdout_ours.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let _ = reader_app.emit(
                        "session-output",
                        SessionOutput {
                            id: reader_id.clone(),
                            data: BASE64_STANDARD.encode(&buf[..n]),
                        },
                    );
                }
            }
        }
    });

    let exit_app = app.clone();
    let exit_id = session_id.clone();
    let exit_registry_id = session_id.clone();
    tokio::spawn(async move {
        let message = match exit_rx.await {
            Ok(status) => match (status.code, status.signal) {
                (Some(0), _) => "exited normally".to_string(),
                (Some(code), _) => format!("exited with status {code}"),
                (None, Some(sig)) => format!("killed by SIG{sig}"),
                (None, None) => "connection closed".to_string(),
            },
            Err(_) => "connection closed".to_string(),
        };
        let _ = exit_app.emit("session-exit", SessionExit { id: exit_id, message });
        let registry = exit_app.state::<crate::AppState>();
        registry.sessions.remove(&exit_registry_id);
    });

    state.sessions.insert(
        session_id.clone(),
        SessionHandle {
            stdin: std::sync::Arc::new(AsyncMutex::new(stdin_ours)),
            resize_tx,
            conn_task: conn_task.abort_handle(),
            reader_task: reader_task.abort_handle(),
        },
    );

    Ok(session_id)
}

#[tauri::command]
pub async fn send_input(
    state: State<'_, crate::AppState>,
    session_id: String,
    data: String,
) -> Result<(), String> {
    let bytes = BASE64_STANDARD.decode(data).map_err(|e| e.to_string())?;
    let stdin = state.sessions.stdin_of(&session_id).ok_or("no such session")?;
    let mut w = stdin.lock().await;
    w.write_all(&bytes).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub fn resize_session(
    state: State<'_, crate::AppState>,
    session_id: String,
    cols: u32,
    rows: u32,
) -> Result<(), String> {
    state.sessions.resize(&session_id, (cols, rows, 0, 0));
    Ok(())
}

#[tauri::command]
pub fn disconnect_session(state: State<'_, crate::AppState>, session_id: String) -> Result<(), String> {
    state.sessions.remove(&session_id);
    Ok(())
}
