//! shh — the SHH client.
//!
//! `shh [user@]host [command…]` — run a command (or a pipe shell) on a
//! server, speaking only the modern subset: hybrid PQ key exchange,
//! Ed25519 keys, AEAD ciphers, public-key auth.

use std::io::IsTerminal;
use std::path::PathBuf;

use clap::Parser;

use shh::connect;

#[derive(Parser)]
#[command(name = "shh", about = "SHH client: modern SSH, nothing legacy")]
struct Args {
    /// Destination, as `[user@]host`.
    dest: String,

    /// Command to run remotely; none means a (pipe) shell.
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,

    /// Port.
    #[arg(short = 'p', long, default_value_t = 2222)]
    port: u16,

    /// Identity (private key) file.
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,

    /// Certificate to present (default: `<identity>-cert.pub` if present).
    #[arg(long)]
    certificate: Option<PathBuf>,

    /// Login name (overrides `user@`).
    #[arg(short = 'l', long)]
    login: Option<String>,

    /// known_hosts file.
    #[arg(long, default_value_os_t = default_path("known_hosts"))]
    known_hosts: PathBuf,

    /// Trusted host-certificate CA keys, one per line (in addition to any
    /// `@cert-authority` lines in known_hosts). A host presenting a valid
    /// certificate from a trusted CA is accepted without a TOFU prompt.
    #[arg(long)]
    host_ca: Option<PathBuf>,

    /// Trust and record an unseen host key without prompting.
    #[arg(long)]
    accept_new: bool,

    /// Force a pseudo-terminal (default: only for an interactive shell).
    #[arg(short = 't', long)]
    tty: bool,

    /// Never allocate a pseudo-terminal.
    #[arg(short = 'T', long, conflicts_with = "tty")]
    no_tty: bool,

    /// Local port forward: `[bind:]localport:host:hostport` (repeatable).
    /// Works alongside a session, or with -N for a forwarding-only session.
    #[arg(short = 'L', long = "local-forward", value_name = "spec")]
    local_forward: Vec<String>,

    /// Remote port forward: `[bind:]port:host:hostport` (repeatable). The
    /// server listens on `bind:port` and forwards back to `host:hostport`
    /// reachable from here.
    #[arg(short = 'R', long = "remote-forward", value_name = "spec")]
    remote_forward: Vec<String>,

    /// Do not run a remote command; hold the connection open (for -L / -R).
    #[arg(short = 'N', long = "no-command")]
    no_command: bool,

    /// Do not use a key agent, even when SSH_AUTH_SOCK is set.
    #[arg(long)]
    no_agent: bool,

    /// Forward the agent: processes on the server can reach the local
    /// SSH_AUTH_SOCK agent through this connection. Use only on servers
    /// you trust — root there can use (not read) your keys while connected.
    #[arg(short = 'A', long)]
    forward_agent: bool,

    /// Seconds of silence before sending a keepalive probe (0 disables).
    #[arg(long, default_value_t = 30)]
    keepalive_interval: u64,

    /// Unanswered keepalives before declaring the connection dead.
    #[arg(long, default_value_t = 3)]
    keepalive_count: u32,
}

fn default_path(name: &str) -> PathBuf {
    let home = std::env::var_os("HOME").unwrap_or_else(|| ".".into());
    PathBuf::from(home).join(".shh").join(name)
}


async fn run(args: Args) -> Result<i32, String> {
    let (user_at, host) = match args.dest.split_once('@') {
        Some((u, h)) => (Some(u.to_string()), h.to_string()),
        None => (None, args.dest.clone()),
    };
    let user = args
        .login
        .or(user_at)
        .or_else(|| std::env::var("USER").ok())
        .ok_or("no username (use user@host or -l)")?;

    // Parse -L / -R specs before touching the network so a typo fails fast.
    let forwards: Vec<connect::forward::LocalForward> = args
        .local_forward
        .iter()
        .map(|s| connect::forward::LocalForward::parse(s))
        .collect::<Result<_, _>>()?;
    let remotes: Vec<connect::forward::RemoteForward> = args
        .remote_forward
        .iter()
        .map(|s| connect::forward::RemoteForward::parse(s))
        .collect::<Result<_, _>>()?;
    if args.no_command && !args.command.is_empty() {
        return Err("-N does not take a remote command".into());
    }

    // Dial and authenticate — the shared client flow (agent or key file,
    // host-key verification, userauth). It hands back the ready transport.
    let opts = shh::client::Options {
        host: host.clone(),
        port: args.port,
        user: user.clone(),
        known_hosts: args.known_hosts.clone(),
        accept_new: args.accept_new,
        host_ca: args.host_ca.clone(),
        identity: args.identity.clone(),
        certificate: args.certificate.clone(),
        no_agent: args.no_agent,
    };
    let t = shh::client::connect(&opts).await?;

    // -A: forward whatever agent SSH_AUTH_SOCK names. Auth may have used
    // key files; forwarding is an independent choice.
    let agent_sock = if args.forward_agent {
        match std::env::var_os("SSH_AUTH_SOCK") {
            Some(p) => Some(std::path::PathBuf::from(p)),
            None => {
                eprintln!("shh: -A ignored: SSH_AUTH_SOCK is not set");
                None
            }
        }
    } else {
        None
    };

    // Our own binding for this hop, replayed onto each relayed agent
    // connection so a forwarded agent records the full path (this host, then
    // the downstream's). Captured before the transport moves into the loop.
    let agent_bind = agent_sock.as_ref().and_then(|_| {
        let (blob, sig) = t.host_binding();
        (!blob.is_empty()).then(|| connect::mux::AgentBind {
            host_blob: blob.to_vec(),
            session_id: t.session_id().to_vec(),
            sig: sig.to_vec(),
        })
    });

    // One multiplexed connection carries the session (unless -N) and every
    // -L forward, concurrently.
    let conn = connect::mux::Connection::new(t, connect::forward::Policy::DenyAll)
        .keepalive(
            std::time::Duration::from_secs(args.keepalive_interval),
            args.keepalive_count,
        )
        .agent_forward(agent_sock.clone())
        .agent_bind(agent_bind);
    let handle = conn.handle();
    for spec in &forwards {
        let listener = tokio::net::TcpListener::bind(&spec.bind)
            .await
            .map_err(|e| format!("bind {}: {e}", spec.bind))?;
        eprintln!(
            "shh: forwarding {} -> {}:{}",
            spec.bind, spec.target_host, spec.target_port
        );
        tokio::spawn(connect::forward::serve_local_forward(
            listener,
            spec.target_host.clone(),
            spec.target_port,
            handle.clone(),
        ));
    }

    // Ask the server to set up each -R remote forward. The reply (and the
    // resulting forwarded-tcpip channels) are handled by the loop.
    for rf in &remotes {
        eprintln!(
            "shh: remote forward {}:{} -> {}:{}",
            rf.listen_bind, rf.listen_port, rf.target_host, rf.target_port
        );
        handle.request_remote_forward(
            rf.listen_bind.clone(),
            rf.listen_port,
            rf.target_host.clone(),
            rf.target_port,
        );
    }

    // -N: no session — hold the connection open for the forwards until Ctrl-C.
    if args.no_command {
        if forwards.is_empty() && remotes.is_empty() {
            eprintln!("shh: connected to {user}@{host}; holding open (Ctrl-C to exit)");
        }
        tokio::select! {
            r = conn.run(None) => r.map_err(|e| e.to_string())?,
            _ = tokio::signal::ctrl_c() => eprintln!("\nshh: closing"),
        }
        return Ok(0);
    }

    let command = if args.command.is_empty() {
        None
    } else {
        Some(args.command.join(" "))
    };

    // A pty when forced with -t, or by default for an interactive shell.
    let want_tty =
        !args.no_tty && (args.tty || (command.is_none() && std::io::stdin().is_terminal()));
    let (pty_req, resize_rx, _raw) = if want_tty {
        let (cols, rows, xpix, ypix) = shh::tty::winsize().unwrap_or((80, 24, 0, 0));
        let req = connect::PtyRequest {
            term: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into()),
            cols,
            rows,
            xpix,
            ypix,
        };
        // SIGWINCH → window-change requests. Unix only; on Windows the
        // session just keeps the initial size (no console-resize signal here).
        let (tx, rx) = tokio::sync::mpsc::channel::<connect::WindowChange>(4);
        #[cfg(unix)]
        tokio::spawn(async move {
            let Ok(mut winch) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
            else {
                return;
            };
            while winch.recv().await.is_some() {
                if let Some(ws) = shh::tty::winsize() {
                    if tx.send(ws).await.is_err() {
                        break;
                    }
                }
            }
        });
        #[cfg(not(unix))]
        let _ = &tx;
        // Raw mode for the duration of the session; restored on drop.
        let raw = shh::tty::RawMode::enable()
            .map_err(|e| format!("cannot set raw terminal mode: {e}"))?;
        (Some(req), Some(rx), raw)
    } else {
        (None, None, None)
    };

    // Open the session; its close ends the whole connection (tearing down
    // any forwards, like foreground ssh).
    let (exit_tx, exit_rx) = tokio::sync::oneshot::channel();
    handle.open_session(connect::session::SessionSpec {
        command,
        subsystem: None,
        pty: pty_req,
        resize: resize_rx,
        stdin: Box::new(tokio::io::stdin()),
        stdout: Box::new(tokio::io::stdout()),
        stderr: Box::new(tokio::io::stderr()),
        exit: exit_tx,
        forward_agent: agent_sock.is_some(),
        end_connection_on_close: true,
    });
    conn.run(None).await.map_err(|e| e.to_string())?;
    let status = exit_rx
        .await
        .map_err(|_| "session ended without an exit status".to_string())?;

    match (status.code, status.signal) {
        (Some(code), _) => Ok(code as i32),
        (None, Some(sig)) => {
            eprintln!("shh: remote command died on SIG{sig}");
            Ok(255)
        }
        (None, None) => Ok(0),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    match run(args).await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("shh: {e}");
            std::process::exit(255);
        }
    }
}
