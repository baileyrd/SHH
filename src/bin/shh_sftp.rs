//! shh-sftp — a small SFTP client.
//!
//! `shh-sftp [user@]host <command>` connects like `shh` (same identities,
//! host-key policy, and agent support), opens the `sftp` subsystem, and runs
//! one file-transfer command: `ls`, `get`, `put`, `mkdir`, `rmdir`, `rm`,
//! `rename`. Non-interactive by design — one command per invocation composes
//! cleanly in scripts.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use shh::client::{default_path, Options};
use shh::connect;
use shh::sftp::client::Client;

#[derive(Parser)]
#[command(name = "shh-sftp", about = "SHH SFTP client: modern SSH file transfer")]
struct Args {
    /// Destination, as `[user@]host`.
    dest: String,

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

    /// Trusted host-certificate CA keys, one per line.
    #[arg(long)]
    host_ca: Option<PathBuf>,

    /// Trust and record an unseen host key without prompting.
    #[arg(long)]
    accept_new: bool,

    /// Do not use a key agent, even when SSH_AUTH_SOCK is set.
    #[arg(long)]
    no_agent: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List a remote directory (long form, one entry per line).
    Ls { path: Option<String> },
    /// Download a remote file (local name defaults to its basename).
    Get { remote: String, local: Option<String> },
    /// Upload a local file (remote name defaults to its basename).
    Put { local: String, remote: Option<String> },
    /// Create a remote directory.
    Mkdir { path: String },
    /// Remove a remote directory.
    Rmdir { path: String },
    /// Remove a remote file.
    Rm { path: String },
    /// Rename/move a remote path.
    Rename { from: String, to: String },
}

/// The final path component, for defaulting get/put names.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().filter(|s| !s.is_empty()).unwrap_or(path)
}

/// The Unix mode bits to record for an uploaded file: the local file's own on
/// Unix, a sensible default elsewhere (Windows has no Unix permission bits).
#[cfg(unix)]
async fn local_file_mode(file: &tokio::fs::File) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    file.metadata()
        .await
        .map(|m| m.permissions().mode())
        .unwrap_or(0o644)
}
#[cfg(not(unix))]
async fn local_file_mode(_file: &tokio::fs::File) -> u32 {
    0o644
}

async fn run_cmd<R, W>(client: &mut Client<R, W>, cmd: &Cmd) -> Result<(), String>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let e = |x: shh::Error| x.to_string();
    match cmd {
        Cmd::Ls { path } => {
            let path = match path {
                Some(p) => p.clone(),
                None => client.realpath(".").await.map_err(e)?,
            };
            let mut entries = client.list(&path).await.map_err(e)?;
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            for ent in entries {
                println!("{}", ent.long_name);
            }
        }
        Cmd::Get { remote, local } => {
            let local = local.clone().unwrap_or_else(|| basename(remote).to_owned());
            let mut file = tokio::fs::File::create(&local)
                .await
                .map_err(|err| format!("{local}: {err}"))?;
            client.download(remote, &mut file).await.map_err(e)?;
            eprintln!("shh-sftp: fetched {remote} -> {local}");
        }
        Cmd::Put { local, remote } => {
            let remote = remote.clone().unwrap_or_else(|| basename(local).to_owned());
            let mut file = tokio::fs::File::open(local)
                .await
                .map_err(|err| format!("{local}: {err}"))?;
            let mode = local_file_mode(&file).await;
            client.upload(&mut file, &remote, mode).await.map_err(e)?;
            eprintln!("shh-sftp: sent {local} -> {remote}");
        }
        Cmd::Mkdir { path } => client.mkdir(path).await.map_err(e)?,
        Cmd::Rmdir { path } => client.rmdir(path).await.map_err(e)?,
        Cmd::Rm { path } => client.remove(path).await.map_err(e)?,
        Cmd::Rename { from, to } => client.rename(from, to).await.map_err(e)?,
    }
    Ok(())
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

    let opts = Options {
        host,
        port: args.port,
        user,
        known_hosts: args.known_hosts,
        accept_new: args.accept_new,
        host_ca: args.host_ca,
        identity: args.identity,
        certificate: args.certificate,
        no_agent: args.no_agent,
    };
    let t = shh::client::connect(&opts).await?;

    // Open the sftp subsystem; the connection runs in the background task.
    let ch = connect::client_subsystem(t, "sftp")
        .await
        .map_err(|err| err.to_string())?;
    let connect::SubsystemChannel { reader, writer, conn } = ch;
    let mut client = Client::connect(reader, writer)
        .await
        .map_err(|err| err.to_string())?;

    let result = run_cmd(&mut client, &args.cmd).await;

    // Closing the client sends EOF; let the connection wind down.
    drop(client);
    let _ = conn.await;
    result.map(|()| 0)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    match run(args).await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("shh-sftp: {e}");
            std::process::exit(1);
        }
    }
}
