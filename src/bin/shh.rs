//! shh — the SHH client.
//!
//! `shh [user@]host [command…]` — run a command (or a pipe shell) on a
//! server, speaking only the modern subset: hybrid PQ key exchange,
//! Ed25519 keys, AEAD ciphers, public-key auth.

use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;

use clap::Parser;
use tokio::net::TcpStream;

use shh::crypto::ed25519::PublicKey;
use shh::crypto::keyfile;
use shh::transport::{ClientConfig, Transport};
use shh::{auth, connect, Error};

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

fn find_identity(explicit: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    let candidates = [default_path("id_ed25519"), {
        let home = std::env::var_os("HOME").unwrap_or_else(|| ".".into());
        PathBuf::from(home).join(".ssh").join("id_ed25519")
    }];
    candidates
        .iter()
        .find(|p| p.exists())
        .cloned()
        .ok_or_else(|| {
            format!(
                "no identity found (tried {}); generate one with \
                 `shh-keygen -f {}`",
                candidates
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                candidates[0].display(),
            )
        })
}

/// Ask on the controlling terminal, so piped stdin/stdout stay clean.
fn ask_tty(prompt: &str) -> bool {
    let Ok(mut tty) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    else {
        return false;
    };
    let _ = write!(tty, "{prompt} [yes/no] ");
    let _ = tty.flush();
    let mut answer = String::new();
    let mut byte = [0u8; 1];
    while tty.read(&mut byte).map(|n| n == 1).unwrap_or(false) && byte[0] != b'\n' {
        answer.push(byte[0] as char);
    }
    answer.trim() == "yes"
}

/// The trust decision for a presented host key: known-good, first contact
/// (TOFU), or mismatch.
fn verify_host_key(
    key: &PublicKey,
    label: &str,
    path: &PathBuf,
    accept_new: bool,
) -> shh::Result<()> {
    let recorded = std::fs::read_to_string(path)
        .ok()
        .and_then(|text| keyfile::known_hosts_lookup(&text, label));

    match recorded {
        Some(known) if &known == key => Ok(()),
        Some(known) => Err(Error::HostKey(format!(
            "HOST KEY MISMATCH for {label}!\n\
             recorded: {}\n\
             presented: {}\n\
             Someone could be intercepting this connection. If the host\n\
             key really changed, remove the old line from {}.",
            known.fingerprint(),
            key.fingerprint(),
            path.display(),
        ))),
        None => {
            let fp = key.fingerprint();
            let accept = accept_new || {
                std::io::stderr().is_terminal()
                    && ask_tty(&format!(
                        "The authenticity of host '{label}' can't be established.\n\
                         Ed25519 key fingerprint is {fp}.\n\
                         Continue connecting?"
                    ))
            };
            if !accept {
                return Err(Error::HostKey(format!(
                    "unknown host {label} (fingerprint {fp}); \
                     rerun with --accept-new to trust it"
                )));
            }
            if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir).ok();
            }
            let line = keyfile::known_hosts_line(label, key);
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| Error::HostKey(format!("cannot record host key: {e}")))?;
            f.write_all(line.as_bytes())
                .map_err(|e| Error::HostKey(format!("cannot record host key: {e}")))?;
            eprintln!("shh: permanently added '{label}' ({fp}) to {}", path.display());
            Ok(())
        }
    }
}

/// Decode the identity file, prompting for its passphrase when protected.
fn load_identity(text: &str, path: &std::path::Path) -> Result<shh::crypto::ed25519::PrivateKey, String> {
    let protected = keyfile::needs_passphrase(text).map_err(|e| format!("{}: {e}", path.display()))?;
    if !protected {
        return keyfile::decode_private(text)
            .map(|(k, _)| k)
            .map_err(|e| format!("{}: {e}", path.display()));
    }
    for _ in 0..3 {
        let pass = shh::tty::read_passphrase(&format!(
            "Enter passphrase for {}: ",
            path.display()
        ))
        .map_err(|e| format!("cannot prompt for passphrase: {e}"))?;
        match keyfile::decode_private_protected(text, Some(&pass)) {
            Ok((k, _)) => return Ok(k),
            Err(e) if e.to_string().contains("wrong passphrase") => {
                eprintln!("shh: wrong passphrase, try again");
            }
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    }
    Err("too many passphrase attempts".into())
}

/// Load a certificate blob: from `explicit` if given, else from
/// `<identity>-cert.pub` if it happens to exist. Absent is not an error.
fn load_certificate(
    explicit: Option<&PathBuf>,
    identity: &std::path::Path,
) -> Result<Option<Vec<u8>>, String> {
    let path = match explicit {
        Some(p) => p.clone(),
        None => {
            let mut p = identity.as_os_str().to_owned();
            p.push("-cert.pub");
            let p = PathBuf::from(p);
            if !p.exists() {
                return Ok(None);
            }
            p
        }
    };
    let line = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let blob = keyfile::decode_cert(line.trim()).map_err(|e| format!("{}: {e}", path.display()))?;
    eprintln!("shh: presenting certificate {}", path.display());
    Ok(Some(blob))
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

    // How to authenticate: an agent holding usable identities (when
    // SSH_AUTH_SOCK is set and no -i pins a file), else a key file. Decided
    // before dialing, so passphrase prompts never race the handshake.
    let mut agent: Option<(shh::agent::Client, Vec<shh::agent::Identity>)> = None;
    if !args.no_agent && args.identity.is_none() && std::env::var_os("SSH_AUTH_SOCK").is_some() {
        match shh::agent::Client::from_env().await {
            Ok(mut c) => match c.identities().await {
                Ok(ids) => {
                    use shh::crypto::{cert::CERT_ALGO, ed25519::ALGO};
                    let usable = ids
                        .iter()
                        .filter(|i| {
                            matches!(i.algo().as_deref(), Some(ALGO) | Some(CERT_ALGO))
                        })
                        .count();
                    if usable > 0 {
                        agent = Some((c, ids));
                    } // an empty agent is no agent: quietly use key files
                }
                Err(e) => eprintln!("shh: agent: {e}; falling back to key files"),
            },
            Err(e) => eprintln!("shh: agent: {e}; falling back to key files"),
        }
    }

    // Without an agent, a key file (with a certificate beside it, OpenSSH
    // convention `<identity>-cert.pub`; an explicit --certificate overrides).
    let file_key = match &agent {
        Some(_) => None,
        None => {
            let identity = find_identity(args.identity)?;
            let text = std::fs::read_to_string(&identity)
                .map_err(|e| format!("{}: {e}", identity.display()))?;
            let key = load_identity(&text, &identity)?;
            let cert = load_certificate(args.certificate.as_ref(), &identity)?;
            Some((key, cert))
        }
    };

    let label = keyfile::host_label(&host, args.port);
    let known_hosts = args.known_hosts.clone();
    let accept_new = args.accept_new;

    // Trusted host-certificate CAs: from --host-ca and from `@cert-authority`
    // lines in known_hosts. With any, a valid host cert skips the TOFU prompt.
    let mut host_cas = Vec::new();
    if let Some(path) = &args.host_ca {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        host_cas.extend(keyfile::parse_authorized_keys(&text));
    }
    if let Ok(text) = std::fs::read_to_string(&args.known_hosts) {
        host_cas.extend(keyfile::known_hosts_cert_authorities(&text));
    }

    let socket = TcpStream::connect((host.as_str(), args.port))
        .await
        .map_err(|e| format!("connect to {label}: {e}"))?;
    socket.set_nodelay(true).ok();

    let config = ClientConfig {
        verify_host_key: Box::new(move |k| verify_host_key(k, &label, &known_hosts, accept_new)),
        host_cas,
        hostname: host.clone(),
    };
    let mut t = Transport::client(socket, config)
        .await
        .map_err(|e| e.to_string())?;

    match (&mut agent, &file_key) {
        (Some((client, ids)), _) => {
            auth::client_agent(&mut t, &user, client, ids, |banner| eprint!("{banner}")).await
        }
        (None, Some((key, cert))) => {
            auth::client(&mut t, &user, key, cert.as_deref(), |banner| eprint!("{banner}")).await
        }
        (None, None) => unreachable!("one auth source is always chosen"),
    }
    .map_err(|e| e.to_string())?;

    // One multiplexed connection carries the session (unless -N) and every
    // -L forward, concurrently.
    let conn = connect::mux::Connection::new(t, connect::forward::Policy::DenyAll).keepalive(
        std::time::Duration::from_secs(args.keepalive_interval),
        args.keepalive_count,
    );
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
        // SIGWINCH → window-change requests.
        let (tx, rx) = tokio::sync::mpsc::channel::<connect::WindowChange>(4);
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
        pty: pty_req,
        resize: resize_rx,
        stdin: Box::new(tokio::io::stdin()),
        stdout: Box::new(tokio::io::stdout()),
        stderr: Box::new(tokio::io::stderr()),
        exit: exit_tx,
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
