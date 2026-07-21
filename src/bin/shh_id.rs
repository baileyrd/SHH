//! shh-id — a local, self-hosted alternative to sshid.io.
//!
//! sshid.io keeps a per-user vault of public keys and publishes them at
//! `https://sshid.io/<handle>`, so provisioning a server is one command:
//! `curl https://sshid.io/<handle> >> ~/.ssh/authorized_keys`. `shh-id` gets
//! the same workflow without a hosted vault: each device's public key lives
//! as a file under `<dir>/<handle>/`, that directory is yours to sync across
//! devices however you like (Syncthing, a private git repo, a network
//! share), and `shh-id serve` publishes it — from your own machine, your own
//! LAN, or your own VPS — at `GET /<handle>`:
//!
//!     $ shh-id add me ~/.shh/id_ed25519.pub    # this device's key
//!     $ shh-id serve --dir ~/.shh/id            # http://127.0.0.1:8422/me
//!     $ curl http://127.0.0.1:8422/me >> ~/.ssh/authorized_keys
//!
//! There is nothing secret to protect here: only public keys are ever read,
//! written, or served. `shh-id` has no notion of accounts or auth — the
//! directory boundary and whatever you bind `serve` to are the whole trust
//! model, same as running `python -m http.server` over a directory of
//! `authorized_keys` snippets. Bind beyond loopback only where you mean to.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use shh::crypto::keyfile;

#[derive(Parser)]
#[command(
    name = "shh-id",
    about = "Local, self-hosted alternative to sshid.io: publish device public keys by handle"
)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Add a device's public key to a handle.
    Add {
        /// Handle to add this key under (letters, digits, `-`, `_`, `.`).
        handle: String,
        /// Public key file(s) to add (default: this device's default
        /// identity, `~/.shh/id_ed25519.pub` then `~/.ssh/id_ed25519.pub`).
        files: Vec<PathBuf>,
        /// Shared directory synced across your devices.
        #[arg(long, default_value_os_t = default_dir())]
        dir: PathBuf,
        /// Name for this device's entry (default: hostname).
        #[arg(long)]
        name: Option<String>,
    },
    /// List handles, or the devices under one handle.
    List {
        /// Restrict the listing to one handle (default: every handle).
        handle: Option<String>,
        #[arg(long, default_value_os_t = default_dir())]
        dir: PathBuf,
    },
    /// Print one handle's public keys, exactly as `serve` would.
    Export {
        handle: String,
        #[arg(long, default_value_os_t = default_dir())]
        dir: PathBuf,
    },
    /// Serve every handle in `dir` over HTTP: `GET /<handle>`.
    Serve {
        #[arg(long, default_value_os_t = default_dir())]
        dir: PathBuf,
        /// Address to listen on. There is no authentication — anyone who
        /// can reach this port can fetch any handle's public keys (which is
        /// the point: they are public). Bind beyond loopback only on a host
        /// you mean to expose this on.
        #[arg(short = 'L', long, default_value = "127.0.0.1:8422")]
        listen: SocketAddr,
    },
}

fn default_dir() -> PathBuf {
    shh::client::default_path("id")
}

/// A handle is one path segment and nothing else: reject anything that
/// could escape `dir` (`..`, `/`, `\0`) or that isn't a sane directory name.
fn is_valid_handle(h: &str) -> bool {
    !h.is_empty()
        && h != "."
        && h != ".."
        && h.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn sanitize_name(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '-' })
        .collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "device".to_string()
    } else {
        cleaned
    }
}

fn device_name() -> String {
    #[cfg(unix)]
    {
        if let Ok(name) = nix::unistd::gethostname() {
            if let Some(s) = name.to_str().filter(|s| !s.is_empty()) {
                return sanitize_name(s);
            }
        }
    }
    #[cfg(windows)]
    {
        if let Ok(s) = std::env::var("COMPUTERNAME") {
            if !s.is_empty() {
                return sanitize_name(&s);
            }
        }
    }
    "device".to_string()
}

fn default_pub_identities() -> Vec<PathBuf> {
    let ssh_default = {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .unwrap_or_else(|| ".".into());
        PathBuf::from(home).join(".ssh").join("id_ed25519.pub")
    };
    [shh::client::default_path("id_ed25519.pub"), ssh_default]
        .into_iter()
        .filter(|p| p.exists())
        .take(1)
        .collect()
}

/// The first non-empty, non-comment line of a `.pub` file, validated as a
/// key `shhd` would actually accept.
fn read_pub_line(path: &Path) -> Result<(String, shh::crypto::userkey::UserKey), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or_else(|| format!("{}: empty public key file", path.display()))?
        .to_string();
    let key = keyfile::decode_user_key(&line).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok((line, key))
}

fn add(handle: &str, files: &[PathBuf], dir: &Path, name: Option<String>) -> Result<(), String> {
    if !is_valid_handle(handle) {
        return Err(format!(
            "{handle:?} is not a valid handle (letters, digits, -, _, . only)"
        ));
    }
    let files = if files.is_empty() { default_pub_identities() } else { files.to_vec() };
    if files.is_empty() {
        return Err("no public key given, and no default identity found \
             (generate one with `shh-keygen`, or name a `.pub` file)"
            .into());
    }
    let handle_dir = dir.join(handle);
    std::fs::create_dir_all(&handle_dir).map_err(|e| format!("{}: {e}", handle_dir.display()))?;
    let device = sanitize_name(&name.unwrap_or_else(device_name));
    for file in &files {
        let (line, key) = read_pub_line(file)?;
        let dest = handle_dir.join(format!("{device}.pub"));
        std::fs::write(&dest, format!("{line}\n")).map_err(|e| format!("{}: {e}", dest.display()))?;
        println!("added {} ({}) to {handle:?} as {}", file.display(), key.fingerprint(), dest.display());
    }
    Ok(())
}

/// Every valid public-key line under `dir/handle`, one per file, sorted by
/// file name for a stable order. `Ok(None)` means the handle doesn't exist;
/// `Ok(Some(""))` means it exists but holds no valid key yet. A file that
/// fails to parse is skipped (noted on stderr), not fatal — one bad or
/// half-synced file shouldn't take the rest of the handle down.
fn collect_handle(dir: &Path, handle: &str) -> std::io::Result<Option<String>> {
    if !is_valid_handle(handle) {
        return Ok(None);
    }
    let handle_dir = dir.join(handle);
    if !handle_dir.is_dir() {
        return Ok(None);
    }
    let mut entries: Vec<_> = std::fs::read_dir(&handle_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "pub"))
        .collect();
    entries.sort_by_key(|e| e.file_name());

    let mut out = String::new();
    for entry in entries {
        let path = entry.path();
        match read_pub_line(&path) {
            Ok((line, _)) => {
                out.push_str(&line);
                out.push('\n');
            }
            Err(e) => eprintln!("shh-id: skipping {e}"),
        }
    }
    Ok(Some(out))
}

fn list(handle: Option<String>, dir: &Path) -> Result<(), String> {
    let handles: Vec<String> = match handle {
        Some(h) => vec![h],
        None => {
            let mut found: Vec<String> = std::fs::read_dir(dir)
                .map(|rd| {
                    rd.filter_map(|e| e.ok())
                        .filter(|e| e.path().is_dir())
                        .filter_map(|e| e.file_name().into_string().ok())
                        .collect()
                })
                .unwrap_or_default();
            found.sort();
            found
        }
    };
    if handles.is_empty() {
        eprintln!("no handles under {}", dir.display());
        return Ok(());
    }
    for h in handles {
        let handle_dir = dir.join(&h);
        let mut files: Vec<_> = std::fs::read_dir(&handle_dir)
            .map_err(|e| format!("{}: {e}", handle_dir.display()))?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "pub"))
            .collect();
        files.sort_by_key(|e| e.file_name());
        println!("{h}");
        for entry in files {
            let path = entry.path();
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("?");
            match read_pub_line(&path) {
                Ok((_, key)) => println!("  {stem:<20} {}", key.fingerprint()),
                Err(e) => println!("  {stem:<20} invalid: {e}"),
            }
        }
    }
    Ok(())
}

fn export(handle: &str, dir: &Path) -> Result<(), String> {
    match collect_handle(dir, handle).map_err(|e| format!("{}: {e}", dir.display()))? {
        Some(text) => {
            print!("{text}");
            Ok(())
        }
        None => Err(format!("no such handle {handle:?} under {}", dir.display())),
    }
}

// ------------------------------------------------------------- serve ---

const MAX_REQUEST_BYTES: u64 = 16 * 1024;

/// Read one CRLF- or LF-terminated line, bounded by the reader's own byte
/// budget. `Ok(None)` means the peer closed before sending anything (a
/// normal idle disconnect); `Ok(Some(line))` strips the trailing newline.
/// A line that never terminates within the budget is reported as an error
/// so the caller can answer 400 instead of hanging or growing unbounded.
async fn read_line_bounded<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Option<String>> {
    let mut buf = String::new();
    let n = reader.read_line(&mut buf).await?;
    if n == 0 {
        return Ok(None);
    }
    if !buf.ends_with('\n') {
        return Err(std::io::Error::other("request line too long or truncated"));
    }
    while buf.ends_with('\n') || buf.ends_with('\r') {
        buf.pop();
    }
    Ok(Some(buf))
}

async fn respond<W: AsyncWrite + Unpin>(
    w: &mut W,
    status: u16,
    reason: &str,
    body: &str,
    include_body: bool,
) -> std::io::Result<()> {
    let mut resp = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    if include_body {
        resp.push_str(body);
    }
    w.write_all(resp.as_bytes()).await?;
    w.shutdown().await
}

async fn handle_conn(stream: tokio::net::TcpStream, dir: &Path) -> std::io::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half.take(MAX_REQUEST_BYTES));

    let request_line = match read_line_bounded(&mut reader).await {
        Ok(Some(line)) => line,
        Ok(None) => return Ok(()), // peer closed without sending a request
        Err(_) => return respond(&mut write_half, 400, "Bad Request", "bad request\n", true).await,
    };

    // Drain headers; we don't need any of them.
    loop {
        match read_line_bounded(&mut reader).await {
            Ok(Some(line)) if line.is_empty() => break,
            Ok(Some(_)) => continue,
            Ok(None) => return Ok(()),
            Err(_) => {
                return respond(&mut write_half, 400, "Bad Request", "bad request\n", true).await
            }
        }
    }

    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    if method != "GET" && method != "HEAD" {
        return respond(&mut write_half, 405, "Method Not Allowed", "GET only\n", true).await;
    }

    let handle = path.strip_prefix('/').filter(|rest| !rest.is_empty() && !rest.contains('/'));
    let body = match handle {
        Some(h) => collect_handle(dir, h).unwrap_or(None),
        None => None,
    };

    match body {
        Some(text) => respond(&mut write_half, 200, "OK", &text, method == "GET").await,
        None => respond(&mut write_half, 404, "Not Found", "no such handle\n", method == "GET").await,
    }
}

async fn serve(dir: PathBuf, listen: SocketAddr) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    println!("shh-id: serving {} — GET http://{listen}/<handle>", dir.display());
    let dir = Arc::new(dir);
    loop {
        let (stream, _) = listener.accept().await?;
        let dir = dir.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, dir.as_path()).await {
                tracing::debug!("connection error: {e}");
            }
        });
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();
    let result = match args.cmd {
        Cmd::Add { handle, files, dir, name } => add(&handle, &files, &dir, name),
        Cmd::List { handle, dir } => list(handle, &dir),
        Cmd::Export { handle, dir } => export(&handle, &dir),
        Cmd::Serve { dir, listen } => serve(dir, listen).await.map_err(|e| e.to_string()),
    };
    if let Err(e) = result {
        eprintln!("shh-id: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_validation_rejects_traversal() {
        for bad in ["..", ".", "", "a/b", "a\0b"] {
            assert!(!is_valid_handle(bad), "{bad:?} should be rejected");
        }
        for good in ["me", "alice-laptop", "team.corp", "a_b"] {
            assert!(is_valid_handle(good), "{good:?} should be accepted");
        }
    }

    #[test]
    fn collect_handle_skips_invalid_and_keeps_valid() {
        let dir = tempfile::tempdir().unwrap();
        let handle_dir = dir.path().join("me");
        std::fs::create_dir_all(&handle_dir).unwrap();

        let key = shh::crypto::ed25519::PrivateKey::generate();
        let good_line = keyfile::encode_public(&key.public(), "laptop");
        std::fs::write(handle_dir.join("laptop.pub"), &good_line).unwrap();
        std::fs::write(handle_dir.join("garbage.pub"), "not a key at all\n").unwrap();
        std::fs::write(handle_dir.join("ignored.txt"), &good_line).unwrap();

        let out = collect_handle(dir.path(), "me").unwrap().unwrap();
        assert_eq!(out.lines().count(), 1);
        assert!(out.contains("laptop"));
    }

    #[test]
    fn collect_handle_missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(collect_handle(dir.path(), "nobody").unwrap().is_none());
    }

    #[test]
    fn collect_handle_rejects_traversal_handle() {
        let dir = tempfile::tempdir().unwrap();
        assert!(collect_handle(dir.path(), "../etc").unwrap().is_none());
    }
}
