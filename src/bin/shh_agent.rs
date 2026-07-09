//! shh-agent — an Ed25519-only SSH agent.
//!
//! One long-lived process holds private keys; `shh` (and OpenSSH's `ssh` and
//! `ssh-add` — the protocol is the standard one) ask it to sign over a Unix
//! socket, so keys never enter short-lived client processes. Run without a
//! subcommand it serves in the foreground; the subcommands are the `ssh-add`
//! equivalents and talk to a running agent.
//!
//!     $ shh-agent &                      # serve on ~/.shh/agent.sock
//!     SSH_AUTH_SOCK=/home/u/.shh/agent.sock; export SSH_AUTH_SOCK;
//!     $ shh-agent add                    # add the default identity
//!     $ shh you@host uptime              # signs via the agent

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};

use shh::agent::{server, Client};
use shh::crypto::keyfile;
use shh::Error;

#[derive(Parser)]
#[command(
    name = "shh-agent",
    about = "SHH key agent: hold Ed25519 keys, sign for clients, nothing legacy"
)]
struct Args {
    /// Agent socket. Daemon default: ~/.shh/agent.sock. Subcommand default:
    /// $SSH_AUTH_SOCK, then ~/.shh/agent.sock.
    #[arg(short = 'a', long)]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Add private keys (default: ~/.shh/id_ed25519, then ~/.ssh/id_ed25519).
    /// A `<file>-cert.pub` beside a key is added as a certificate identity.
    Add {
        files: Vec<PathBuf>,
        /// Forget the key after this many seconds.
        #[arg(short = 't', long, value_name = "seconds")]
        lifetime: Option<u32>,
        /// Restrict the key to a destination (`[user@]host`, repeatable).
        /// Chain hops with `>` for a path — `gw>prod` pins the key so it
        /// signs for prod only when the forwarded agent reached prod via gw
        /// (and gw itself). Repeating `-H` allows several destinations. Each
        /// host's key must be in known_hosts; the agent refuses to sign for
        /// anything else, even through forwarding.
        #[arg(short = 'H', long = "destination", value_name = "[user@]host[>host…]")]
        destination: Vec<String>,
        /// known_hosts file used to resolve `--destination` host keys.
        #[arg(long, default_value_os_t = default_path("known_hosts"))]
        known_hosts: PathBuf,
    },
    /// List held identities (fingerprints; --public for full key lines).
    List {
        #[arg(long)]
        public: bool,
    },
    /// Remove identities named by key file (and their certificates).
    Remove {
        files: Vec<PathBuf>,
        /// Remove every identity instead.
        #[arg(long, conflicts_with = "files")]
        all: bool,
    },
    /// Lock the agent: identities vanish until unlocked.
    Lock,
    /// Unlock a locked agent.
    Unlock,
}

fn default_path(name: &str) -> PathBuf {
    let home = std::env::var_os("HOME").unwrap_or_else(|| ".".into());
    PathBuf::from(home).join(".shh").join(name)
}

/// The socket a client subcommand should talk to.
fn client_socket(explicit: Option<PathBuf>) -> PathBuf {
    explicit
        .or_else(|| std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from))
        .unwrap_or_else(|| default_path("agent.sock"))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    let result = match args.cmd {
        None => daemon(args.socket.unwrap_or_else(|| default_path("agent.sock"))).await,
        Some(cmd) => run_client(client_socket(args.socket), cmd).await,
    };
    if let Err(e) = result {
        eprintln!("shh-agent: {e}");
        std::process::exit(1);
    }
}

// -------------------------------------------------------------- daemon ---

async fn daemon(path: PathBuf) -> Result<(), String> {
    let listener = server::bind(&path).await.map_err(|e| e.to_string())?;
    // The line a shell can eval; the daemon itself stays in the foreground.
    println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", path.display());
    tracing::info!("agent listening on {}", path.display());

    let keyring = Arc::new(server::Keyring::new());
    let our_uid = nix::unistd::geteuid().as_raw();
    loop {
        let stream = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(e) => {
                    tracing::warn!("accept: {e}");
                    continue;
                }
            },
            _ = tokio::signal::ctrl_c() => break,
        };
        // Socket modes are the first line of defense; the peer check is the
        // second. Root is not exempted: an agent is a user's secret-holder,
        // and root can take the keys other ways without being humored here.
        match stream.peer_cred() {
            Ok(cred) if cred.uid() == our_uid => {}
            Ok(cred) => {
                tracing::warn!("refusing connection from uid {}", cred.uid());
                continue;
            }
            Err(e) => {
                tracing::warn!("cannot identify peer: {e}");
                continue;
            }
        }
        let keyring = keyring.clone();
        tokio::spawn(async move {
            if let Err(e) = server::serve_conn(stream, &keyring).await {
                tracing::info!("connection ended: {e}");
            }
        });
    }
    std::fs::remove_file(&path).ok();
    tracing::info!("agent stopped");
    Ok(())
}

// ------------------------------------------------------- client commands ---

async fn run_client(socket: PathBuf, cmd: Cmd) -> Result<(), String> {
    // Subcommands write listings to stdout; dying quietly when the pipe
    // closes (`shh-agent list | head -1`) is the unix-correct behavior.
    // The daemon path must NOT do this — a client hanging up mid-write
    // would kill the whole agent.
    unsafe {
        let _ = nix::sys::signal::signal(
            nix::sys::signal::Signal::SIGPIPE,
            nix::sys::signal::SigHandler::SigDfl,
        );
    }
    let mut client = Client::connect(&socket).await.map_err(|e| {
        format!(
            "cannot reach an agent at {} (start one with `shh-agent`): {e}",
            socket.display()
        )
    })?;
    match cmd {
        Cmd::Add {
            files,
            lifetime,
            destination,
            known_hosts,
        } => add(&mut client, files, lifetime, destination, known_hosts).await,
        Cmd::List { public } => list(&mut client, public).await,
        Cmd::Remove { files, all } => remove(&mut client, files, all).await,
        Cmd::Lock => {
            let pass = shh::tty::read_passphrase("Enter lock passphrase: ")
                .map_err(|e| e.to_string())?;
            let again = shh::tty::read_passphrase("Again: ").map_err(|e| e.to_string())?;
            if pass != again {
                return Err("passphrases do not match".into());
            }
            client.lock(pass.as_bytes()).await.map_err(|e| e.to_string())?;
            eprintln!("agent locked");
            Ok(())
        }
        Cmd::Unlock => {
            let pass = shh::tty::read_passphrase("Enter unlock passphrase: ")
                .map_err(|e| e.to_string())?;
            client
                .unlock(pass.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            eprintln!("agent unlocked");
            Ok(())
        }
    }
}

fn default_identities() -> Vec<PathBuf> {
    let ssh_default = {
        let home = std::env::var_os("HOME").unwrap_or_else(|| ".".into());
        PathBuf::from(home).join(".ssh").join("id_ed25519")
    };
    [default_path("id_ed25519"), ssh_default]
        .into_iter()
        .filter(|p| p.exists())
        .take(1)
        .collect()
}

/// Decode a private key file, prompting for its passphrase when protected.
fn load_key(path: &PathBuf) -> Result<(shh::crypto::ed25519::PrivateKey, String), String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let protected =
        keyfile::needs_passphrase(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    if !protected {
        return keyfile::decode_private(&text).map_err(|e| format!("{}: {e}", path.display()));
    }
    for _ in 0..3 {
        let pass =
            shh::tty::read_passphrase(&format!("Enter passphrase for {}: ", path.display()))
                .map_err(|e| format!("cannot prompt for passphrase: {e}"))?;
        match keyfile::decode_private_protected(&text, Some(&pass)) {
            Ok(found) => return Ok(found),
            Err(e) if e.to_string().contains("wrong passphrase") => {
                eprintln!("shh-agent: wrong passphrase, try again");
            }
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    }
    Err("too many passphrase attempts".into())
}

fn cert_path(identity: &std::path::Path) -> PathBuf {
    let mut p = identity.as_os_str().to_owned();
    p.push("-cert.pub");
    PathBuf::from(p)
}

/// Resolve `--destination` specs into a constraint payload, looking each
/// host's key up in known_hosts. Each spec is a `>`-separated path from the
/// local host (`gw>prod` means "prod only via gw"); repeating `-H` allows
/// several independent destinations, exactly like OpenSSH's `ssh-add -h`.
fn build_destinations(
    specs: &[String],
    known_hosts: &std::path::Path,
) -> Result<Option<Vec<u8>>, String> {
    if specs.is_empty() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(known_hosts)
        .map_err(|e| format!("{}: {e}", known_hosts.display()))?;
    let mut payload = Vec::new();
    for spec in specs {
        let mut hops = Vec::new();
        for part in spec.split('>') {
            let (user, host) = match part.split_once('@') {
                Some((u, h)) => (u.to_string(), h.to_string()),
                None => (String::new(), part.to_string()),
            };
            let entries = keyfile::known_hosts_constraint_keys(&text, &host);
            if entries.is_empty() {
                return Err(format!(
                    "no host key or matching @cert-authority for {host:?} in {} — connect once \
                     (or add a CA line) before restricting to it",
                    known_hosts.display()
                ));
            }
            hops.push((
                user,
                host,
                entries.iter().map(|(k, ca)| (k.to_blob(), *ca)).collect(),
            ));
        }
        // One spec = one path (local → h1 → h2 → …); specs are ORed.
        payload.extend(shh::agent::encode_path(&hops));
    }
    Ok(Some(payload))
}

async fn add(
    client: &mut Client,
    files: Vec<PathBuf>,
    lifetime: Option<u32>,
    destination: Vec<String>,
    known_hosts: PathBuf,
) -> Result<(), String> {
    let destinations = build_destinations(&destination, &known_hosts)?;
    let files = if files.is_empty() {
        let found = default_identities();
        if found.is_empty() {
            return Err("no identity found (generate one with `shh-keygen`)".into());
        }
        found
    } else {
        files
    };
    for path in &files {
        let (key, comment) = load_key(path)?;
        let comment = if comment.is_empty() {
            path.display().to_string()
        } else {
            comment
        };
        client
            .add_constrained(&key, None, &comment, lifetime, destinations.as_deref())
            .await
            .map_err(|e| e.to_string())?;
        eprintln!(
            "added {} ({}){}",
            path.display(),
            key.public().fingerprint(),
            if destination.is_empty() {
                String::new()
            } else {
                format!(" restricted to {}", destination.join(", "))
            }
        );
        let cp = cert_path(path);
        if cp.exists() {
            let line =
                std::fs::read_to_string(&cp).map_err(|e| format!("{}: {e}", cp.display()))?;
            let cert = keyfile::decode_cert(line.trim())
                .map_err(|e| format!("{}: {e}", cp.display()))?;
            client
                .add_constrained(&key, Some(&cert), &comment, lifetime, destinations.as_deref())
                .await
                .map_err(|e| e.to_string())?;
            eprintln!("added certificate {}", cp.display());
        }
    }
    Ok(())
}

async fn list(client: &mut Client, public: bool) -> Result<(), String> {
    let ids = client.identities().await.map_err(|e| e.to_string())?;
    if ids.is_empty() {
        eprintln!("the agent holds no identities");
        return Ok(());
    }
    for id in &ids {
        let algo = id.algo().unwrap_or_else(|| "?".into());
        if public {
            use base64::prelude::{Engine as _, BASE64_STANDARD};
            println!("{algo} {} {}", BASE64_STANDARD.encode(&id.blob), id.comment);
        } else {
            // Match `ssh-add -l`: 256-bit column, and a certificate is
            // fingerprinted by the key it certifies, not the whole blob.
            let fp = match shh::crypto::cert::Certificate::parse_and_verify(&id.blob) {
                Ok(cert) => cert.key.fingerprint(),
                Err(_) => id.fingerprint(),
            };
            println!("256 {fp} {} ({algo})", id.comment);
        }
    }
    Ok(())
}

async fn remove(client: &mut Client, files: Vec<PathBuf>, all: bool) -> Result<(), String> {
    if all {
        client.remove_all().await.map_err(|e| e.to_string())?;
        eprintln!("all identities removed");
        return Ok(());
    }
    if files.is_empty() {
        return Err("name key files to remove, or use --all".into());
    }
    for path in &files {
        // The public half is enough to name the identity; try `<file>.pub`
        // first so removal never prompts for a passphrase.
        let pub_path = PathBuf::from(format!("{}.pub", path.display()));
        let blob = if pub_path.exists() {
            let line = std::fs::read_to_string(&pub_path)
                .map_err(|e| format!("{}: {e}", pub_path.display()))?;
            let (key, _) = keyfile::decode_public(line.trim())
                .map_err(|e| format!("{}: {e}", pub_path.display()))?;
            key.to_blob()
        } else {
            load_key(path)?.0.public().to_blob()
        };
        client.remove(&blob).await.map_err(|e| e.to_string())?;
        eprintln!("removed {}", path.display());
        let cp = cert_path(path);
        if cp.exists() {
            if let Ok(line) = std::fs::read_to_string(&cp) {
                if let Ok(cert) = keyfile::decode_cert(line.trim()) {
                    match client.remove(&cert).await {
                        Ok(()) => eprintln!("removed certificate {}", cp.display()),
                        Err(Error::Agent(_)) => {} // wasn't loaded; fine
                        Err(e) => return Err(e.to_string()),
                    }
                }
            }
        }
    }
    Ok(())
}
