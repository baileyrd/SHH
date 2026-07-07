//! shhd — the SHH server.
//!
//! Serves session channels (exec/shell) to holders of authorized Ed25519
//! keys. Runs as the invoking user with no privilege separation yet, so
//! point it at a dedicated account or a container if exposing it beyond
//! localhost.

use std::path::PathBuf;

use clap::Parser;
use tokio::net::TcpListener;

use shh::crypto::{ed25519::PrivateKey, keyfile};
use shh::transport::{ServerConfig, Transport};
use shh::{auth, connect};

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
}

fn default_path(name: &str) -> PathBuf {
    let home = std::env::var_os("HOME").unwrap_or_else(|| ".".into());
    PathBuf::from(home).join(".shh").join(name)
}

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

#[tokio::main]
async fn main() -> std::io::Result<()> {
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
        Ok(text) => keyfile::parse_authorized_keys(&text),
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

    let user = match args.user {
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

    let listener = TcpListener::bind(&args.listen).await?;
    tracing::info!("listening on {}", args.listen);

    loop {
        let (socket, addr) = listener.accept().await?;
        socket.set_nodelay(true).ok();
        let host_key = host_key.clone();
        let host_cert = host_cert.clone();
        let policy = auth::Policy {
            user: user.clone(),
            keys: keys.clone(),
            trusted_cas: trusted_cas.clone(),
            banner: args.banner.clone(),
        };
        let permit_open = args.permit_open.clone();
        let permit_listen = args.permit_listen.clone();
        tokio::spawn(async move {
            let config = ServerConfig {
                host_key,
                host_cert,
            };
            let mut t = match Transport::server(socket, config).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::info!(%addr, "handshake failed: {e}");
                    return;
                }
            };
            let user = match auth::server(&mut t, &policy).await {
                Ok(u) => u,
                Err(e) => {
                    tracing::info!(%addr, "authentication failed: {e}");
                    t.bail(&e).await;
                    return;
                }
            };

            // One multiplexed connection serves sessions and, where the
            // allowlists permit, `-L` and `-R` forwards — concurrently.
            tracing::info!(%addr, %user, "connection established");
            let fwd = connect::forward::Policy::parse(&permit_open)
                .expect("policy validated at startup");
            let listen = connect::forward::Policy::parse(&permit_listen)
                .expect("policy validated at startup");
            let conn = connect::mux::Connection::new(t, fwd).listen_policy(listen);
            match conn.run(None).await {
                Ok(()) => tracing::info!(%addr, %user, "connection ended"),
                Err(e) => tracing::info!(%addr, %user, "connection error: {e}"),
            }
        });
    }
}
