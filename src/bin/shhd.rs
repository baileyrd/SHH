//! shhd — the SHH server.
//!
//! Serves session channels (exec/shell and the `sftp` subsystem) and, where
//! the allowlists permit, `-L`/`-R` forwards, to holders of authorized keys
//! or valid certificates.
//! When run as root it drops each session to the authenticated user's
//! account (uid/gid/groups, home, login shell); an unknown user is refused
//! rather than run with root privileges. `--privsep` holds the host key in a
//! separate signer process, and `--sandbox` additionally drops the whole
//! parsing daemon to an unprivileged account (running every session as that
//! account) so no untrusted parsing runs with privilege. A per-connection
//! sandboxed parser with per-user session handoff (OpenSSH's full monitor)
//! is not built yet, so still prefer a container when exposing broadly.

// shhd is a Unix daemon: the session model needs fork/setuid, ptys, and (for
// privsep) a single-threaded fork at startup. On non-Unix it builds as an
// honest stub (see the bottom of the file) rather than a broken binary.
#![cfg_attr(not(unix), allow(unused))]

#[cfg(unix)]
use std::path::PathBuf;

#[cfg(unix)]
use clap::Parser;
#[cfg(unix)]
use tokio::net::TcpListener;

#[cfg(unix)]
use shh::crypto::{ed25519::PrivateKey, keyfile};
#[cfg(unix)]
use shh::transport::{ServerConfig, Transport};
#[cfg(unix)]
use shh::{auth, connect};

#[cfg(unix)]
#[derive(Parser)]
#[command(name = "shhd", about = "SHH server: modern SSH, nothing legacy")]
struct Args {
    /// Address to listen on.
    #[arg(short = 'L', long, default_value = "127.0.0.1:2222")]
    listen: String,

    /// Host key file; generated on first run if absent.
    #[arg(long, default_value_os_t = default_path("host_key"))]
    host_key: PathBuf,

    /// Host certificate to present (an `ssh-ed25519-cert-v01` line certifying
    /// the host key). Clients that trust the CA skip TOFU. Default:
    /// `<host_key>-cert.pub` if it exists.
    #[arg(long)]
    host_cert: Option<PathBuf>,

    /// authorized_keys file (standard format; Ed25519 lines count).
    #[arg(long, default_value_os_t = default_path("authorized_keys"))]
    authorized_keys: PathBuf,

    /// Trusted user-CA public keys, one per line. Any Ed25519 user
    /// certificate signed by one of these is accepted (subject to its
    /// validity window and principals). Optional.
    #[arg(long, default_value_os_t = default_path("trusted_user_ca_keys"))]
    trusted_ca_keys: PathBuf,

    /// Username clients must present. Defaults to the current user;
    /// `--user '*'` accepts any name (keys still gate access).
    #[arg(long)]
    user: Option<String>,

    /// Banner text shown to clients before authentication.
    #[arg(long)]
    banner: Option<String>,

    /// Permit direct-tcpip forwarding to a target (repeatable). `host:port`,
    /// port `*` for any port, or `any` for all targets. Default: forwarding
    /// is refused entirely.
    #[arg(long = "permit-open", value_name = "host:port")]
    permit_open: Vec<String>,

    /// Permit remote (`-R`) forwarding: bind a listener for a client
    /// (repeatable). `bind:port`, port `*` for any, or `any`. Default:
    /// remote forwarding is refused entirely.
    #[arg(long = "permit-listen", value_name = "bind:port")]
    permit_listen: Vec<String>,

    /// Permit agent forwarding (`ssh -A` / `shh -A`): sessions get an
    /// SSH_AUTH_SOCK reaching back to the client's agent. Default:
    /// refused, like the other forwarding kinds.
    #[arg(long)]
    permit_agent_forwarding: bool,

    /// Seconds of silence before probing a client with a keepalive (0 off).
    #[arg(long, default_value_t = 30)]
    keepalive_interval: u64,

    /// Unanswered keepalives before dropping an unresponsive client.
    #[arg(long, default_value_t = 3)]
    keepalive_count: u32,

    /// Do not drop to the authenticated user; run every session as the
    /// account `shhd` itself runs as. Use only for single-user or test
    /// setups where login names are not system accounts.
    #[arg(long)]
    no_privilege_drop: bool,

    /// Privilege separation: hold the host private key in a separate,
    /// minimal signer process, so the daemon that parses untrusted
    /// network input never has the key in its address space.
    #[arg(long)]
    privsep: bool,

    /// Account the privsep signer drops to when `shhd` runs as root
    /// (default: `nobody`). Ignored when not root.
    #[arg(long, default_value = "nobody")]
    privsep_user: String,

    /// Run the whole daemon unprivileged: after the privileged setup (port
    /// bind, host-key read, signer fork) drop to `--privsep-user` for the
    /// daemon's entire life, so all untrusted parsing runs without privilege
    /// or the host key. Implies `--privsep`. Sessions then run as that one
    /// account (no per-user privilege drop).
    #[arg(long)]
    sandbox: bool,
}

#[cfg(unix)]
fn default_path(name: &str) -> PathBuf {
    let home = std::env::var_os("HOME").unwrap_or_else(|| ".".into());
    PathBuf::from(home).join(".shh").join(name)
}

/// Where host-key signatures come from: the private key held in this process,
/// or a separate privilege-separation signer that holds it for us.
#[cfg(unix)]
#[derive(Clone)]
enum HostAuth {
    Local(PrivateKey),
    Monitor(shh::privsep::MonitorSigner),
}

#[cfg(unix)]
fn load_or_create_host_key(path: &PathBuf) -> std::io::Result<PrivateKey> {
    if path.exists() {
        let text = std::fs::read_to_string(path)?;
        let (key, _) = keyfile::decode_private(&text)
            .map_err(|e| std::io::Error::other(format!("{}: {e}", path.display())))?;
        return Ok(key);
    }
    let key = PrivateKey::generate();
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(keyfile::encode_private(&key, "shhd host key").as_bytes())?;
    tracing::info!("generated host key at {}", path.display());
    Ok(key)
}

/// Serve one SFTP client on stdin/stdout and exit. The daemon re-execs this
/// binary in `--internal-sftp` mode as the `sftp` subsystem child, already
/// dropped to the session user — the same model as OpenSSH's `sftp-server`.
#[cfg(unix)]
fn run_internal_sftp() -> std::io::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        shh::sftp::server::run(tokio::io::stdin(), tokio::io::stdout()).await
    })
}

/// Honest stub on non-Unix: the server has no Windows session model.
#[cfg(not(unix))]
fn main() {
    eprintln!(
        "shhd (the SHH server) runs only on Unix — its session model needs \
         fork/setuid and pseudo-terminals. Use shh / shh-sftp on this platform."
    );
    std::process::exit(1);
}

#[cfg(unix)]
fn main() -> std::io::Result<()> {
    // Subsystem mode is dispatched before the normal CLI so `--internal-sftp`
    // (an internal re-exec flag, not a user-facing option) never reaches clap.
    if std::env::args().skip(1).any(|a| a == "--internal-sftp") {
        return run_internal_sftp();
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();

    let host_key = load_or_create_host_key(&args.host_key)?;
    tracing::info!("host key fingerprint: {}", host_key.public().fingerprint());

    // Load a host certificate if configured or sitting next to the host key.
    let host_cert_path = args.host_cert.clone().or_else(|| {
        let p = PathBuf::from(format!("{}-cert.pub", args.host_key.display()));
        p.exists().then_some(p)
    });
    let host_cert = match &host_cert_path {
        Some(path) => {
            let line = std::fs::read_to_string(path)?;
            let blob = keyfile::decode_cert(line.trim())
                .map_err(|e| std::io::Error::other(format!("{}: {e}", path.display())))?;
            tracing::info!("presenting host certificate {}", path.display());
            Some(blob)
        }
        None => None,
    };

    let keys = match std::fs::read_to_string(&args.authorized_keys) {
        Ok(text) => keyfile::parse_authorized_user_keys(&text),
        Err(e) => {
            tracing::warn!("{}: {e}", args.authorized_keys.display());
            Vec::new()
        }
    };
    let trusted_cas = match std::fs::read_to_string(&args.trusted_ca_keys) {
        Ok(text) => keyfile::parse_authorized_keys(&text),
        Err(_) => Vec::new(),
    };
    if keys.is_empty() && trusted_cas.is_empty() {
        tracing::warn!(
            "no authorized keys ({}) and no trusted CAs ({}) — nobody can log in",
            args.authorized_keys.display(),
            args.trusted_ca_keys.display(),
        );
    } else {
        tracing::info!(
            "{} authorized key(s), {} trusted CA(s) loaded",
            keys.len(),
            trusted_cas.len()
        );
    }

    let user = match args.user.clone() {
        Some(u) if u == "*" => None,
        Some(u) if u.is_empty() => {
            eprintln!("shhd: --user must not be empty (use '*' to accept any name)");
            std::process::exit(2);
        }
        Some(u) => Some(u),
        None => Some(
            std::env::var("USER")
                .or_else(|_| std::env::var("LOGNAME"))
                .unwrap_or_else(|_| "root".into()),
        ),
    };
    match &user {
        Some(u) => tracing::info!("accepting logins for user {u:?}"),
        None => tracing::info!("accepting any username (keys still gate access)"),
    }

    // Validate the forwarding allowlists up front so a typo fails at startup.
    for (flag, specs) in [("--permit-open", &args.permit_open), ("--permit-listen", &args.permit_listen)] {
        if let Err(e) = connect::forward::Policy::parse(specs) {
            eprintln!("shhd: {flag}: {e}");
            std::process::exit(2);
        }
    }
    if args.permit_open.is_empty() {
        tracing::info!("local (-L) forwarding disabled (no --permit-open)");
    } else {
        tracing::info!("local (-L) forwarding permitted for: {}", args.permit_open.join(", "));
    }
    if args.permit_listen.is_empty() {
        tracing::info!("remote (-R) forwarding disabled (no --permit-listen)");
    } else {
        tracing::info!("remote (-R) forwarding permitted for: {}", args.permit_listen.join(", "));
    }
    if args.permit_agent_forwarding {
        tracing::info!("agent forwarding permitted");
    } else {
        tracing::info!("agent forwarding disabled (no --permit-agent-forwarding)");
    }

    let started_root = nix::unistd::geteuid().is_root();
    // --sandbox implies --privsep (the key must be out of the parser before
    // the parser goes unprivileged, or it would still be readable there).
    let privsep = args.privsep || args.sandbox;
    if args.no_privilege_drop && started_root {
        // The riskiest combination this flag can produce: every
        // authenticated key gets a full root session, with nothing at
        // startup louder than a log line to notice it. --no-privilege-drop's
        // own help text says "use only for single-user or test setups," but
        // an operator can still reach for it in production (e.g. copying a
        // test config forward) without registering that "the shhd account"
        // means root here. eprintln! too: a warn! alone can be lost to log
        // filtering/redirection in exactly the deployment where this matters
        // most.
        eprintln!(
            "shhd: WARNING — running as root with --no-privilege-drop: \
             every authenticated session will run as root"
        );
        tracing::warn!("privilege drop disabled while running as root — sessions run as root");
    } else if args.no_privilege_drop {
        tracing::warn!("privilege drop disabled — sessions run as the shhd account");
    } else if !started_root && !args.sandbox {
        tracing::warn!("not running as root — sessions run as the shhd account (cannot drop)");
    }

    // Bind the listen socket *before* dropping privileges, so a privileged
    // port (< 1024) still works under --sandbox. Blocking bind is fine here —
    // we hand the socket to the runtime below.
    let listener = std::net::TcpListener::bind(&args.listen)?;
    listener.set_nonblocking(true)?;

    // Privilege separation: fork the host-key signer *now*, while the process
    // is still single-threaded, before the async runtime spawns any workers.
    // After this the daemon no longer holds the host private key.
    let host_auth = if privsep {
        let signer = shh::privsep::spawn_signer(host_key, Some(&args.privsep_user))?;
        tracing::info!("privilege separation on: host key held by a separate signer process");
        HostAuth::Monitor(signer)
    } else {
        HostAuth::Local(host_key)
    };

    // --sandbox: drop the daemon itself to the unprivileged account, now that
    // the port is bound, the key is read, and the signer is forked. From here
    // on all untrusted parsing runs without privilege or the host key.
    if args.sandbox {
        shh::privsep::drop_daemon_privileges(&args.privsep_user)?;
        // warn, not info: this is easy to read as "extra hardening on top of
        // normal operation" when it actually removes per-user isolation --
        // every authenticated principal's session becomes an OS-level
        // sibling process under the same shared account, able to see and
        // signal each other. Appropriate for a single-purpose server, a
        // real regression for a multi-user login host.
        tracing::warn!(
            "sandbox on: daemon dropped to {:?}; ALL sessions share that one account \
             (no per-user isolation) — do not use for a multi-user login host",
            args.privsep_user
        );
    }
    // After a sandbox drop we are no longer root; per-user session drop is off.
    let is_root = nix::unistd::geteuid().is_root();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(serve(
        args, listener, host_auth, host_cert, keys, trusted_cas, user, is_root,
    ))
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
async fn serve(
    args: Args,
    listener: std::net::TcpListener,
    host_auth: HostAuth,
    host_cert: Option<Vec<u8>>,
    keys: Vec<shh::crypto::userkey::UserKey>,
    trusted_cas: Vec<shh::crypto::ed25519::PublicKey>,
    user: Option<String>,
    is_root: bool,
) -> std::io::Result<()> {
    // The listener was bound (as root, for privileged ports) before any
    // privilege drop; adopt it into the runtime here.
    let listener = TcpListener::from_std(listener)?;
    tracing::info!("listening on {}", args.listen);

    loop {
        let (socket, addr) = listener.accept().await?;
        socket.set_nodelay(true).ok();
        let host_auth = host_auth.clone();
        let host_cert = host_cert.clone();
        let policy = auth::Policy {
            user: user.clone(),
            keys: keys.clone(),
            trusted_cas: trusted_cas.clone(),
            banner: args.banner.clone(),
        };
        let permit_open = args.permit_open.clone();
        let permit_listen = args.permit_listen.clone();
        let permit_agent = args.permit_agent_forwarding;
        let ka_interval = args.keepalive_interval;
        let ka_count = args.keepalive_count;
        // Under --sandbox the daemon is already unprivileged and cannot setuid,
        // so sessions run as the daemon account — the same as no-privilege-drop.
        let no_privilege_drop = args.no_privilege_drop || args.sandbox;
        tokio::spawn(async move {
            let handshake = match host_auth {
                HostAuth::Local(key) => {
                    Transport::server(socket, ServerConfig { host_key: key, host_cert }).await
                }
                HostAuth::Monitor(signer) => {
                    Transport::server_with_signer(socket, Box::new(signer), host_cert).await
                }
            };
            let mut t = match handshake {
                Ok(t) => t,
                Err(e) => {
                    tracing::info!(%addr, "handshake failed: {e}");
                    return;
                }
            };
            let auth::Authenticated {
                user,
                force_command,
            } = match auth::server(&mut t, &policy, Some(addr.ip())).await {
                Ok(a) => a,
                Err(e) => {
                    tracing::info!(%addr, "authentication failed: {e}");
                    t.bail(&e).await;
                    return;
                }
            };
            if force_command.is_some() {
                tracing::info!(%addr, %user, "certificate pins a forced command");
            }

            // Resolve the account the session should run as. When we are
            // root we drop to it; an unknown user is refused rather than run
            // with our own (root) privileges.
            let session_user = if no_privilege_drop {
                None
            } else {
                match connect::UserContext::for_user(&user) {
                    Some(ctx) => {
                        tracing::info!(%addr, %user, uid = ctx.uid, "session will run as user");
                        Some(ctx)
                    }
                    None if is_root => {
                        tracing::warn!(%addr, %user, "no such system user; refusing session");
                        t.disconnect(11, "no such user").await.ok();
                        return;
                    }
                    None => None, // not root: can't drop anyway, run as self
                }
            };

            // One multiplexed connection serves sessions and, where the
            // allowlists permit, `-L` and `-R` forwards — concurrently.
            tracing::info!(%addr, %user, "connection established");
            let fwd = connect::forward::Policy::parse(&permit_open)
                .expect("policy validated at startup");
            let listen = connect::forward::Policy::parse(&permit_listen)
                .expect("policy validated at startup");
            let conn = connect::mux::Connection::new(t, fwd)
                .listen_policy(listen)
                .keepalive(std::time::Duration::from_secs(ka_interval), ka_count)
                .session_user(session_user)
                .force_command(force_command)
                .permit_agent_forward(permit_agent);
            match conn.run(None).await {
                Ok(()) => tracing::info!(%addr, %user, "connection ended"),
                Err(e) => tracing::info!(%addr, %user, "connection error: {e}"),
            }
        });
    }
}
