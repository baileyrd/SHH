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
use shh::wire::disconnect;
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

    /// Login name (overrides `user@`).
    #[arg(short = 'l', long)]
    login: Option<String>,

    /// known_hosts file.
    #[arg(long, default_value_os_t = default_path("known_hosts"))]
    known_hosts: PathBuf,

    /// Trust and record an unseen host key without prompting.
    #[arg(long)]
    accept_new: bool,
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

    let identity = find_identity(args.identity)?;
    let text = std::fs::read_to_string(&identity)
        .map_err(|e| format!("{}: {e}", identity.display()))?;
    let (key, _) =
        keyfile::decode_private(&text).map_err(|e| format!("{}: {e}", identity.display()))?;

    let label = keyfile::host_label(&host, args.port);
    let known_hosts = args.known_hosts.clone();
    let accept_new = args.accept_new;

    let socket = TcpStream::connect((host.as_str(), args.port))
        .await
        .map_err(|e| format!("connect to {label}: {e}"))?;
    socket.set_nodelay(true).ok();

    let config = ClientConfig {
        verify_host_key: Box::new(move |k| verify_host_key(k, &label, &known_hosts, accept_new)),
    };
    let mut t = Transport::client(socket, config)
        .await
        .map_err(|e| e.to_string())?;

    auth::client(&mut t, &user, &key, |banner| eprint!("{banner}"))
        .await
        .map_err(|e| e.to_string())?;

    let command = if args.command.is_empty() {
        None
    } else {
        Some(args.command.join(" "))
    };

    let status = connect::client_session(
        &mut t,
        command.as_deref(),
        tokio::io::stdin(),
        tokio::io::stdout(),
        tokio::io::stderr(),
    )
    .await
    .map_err(|e| e.to_string())?;

    t.disconnect(disconnect::BY_APPLICATION, "done").await.ok();

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
