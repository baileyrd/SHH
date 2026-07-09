//! Shared client-side connection setup for the `shh` and `shh-sftp` binaries.
//!
//! Dialing a server, verifying its host key (known-hosts TOFU or a host-cert
//! CA), loading the local identity (key file or agent, optionally with a
//! certificate), and running user authentication are the same regardless of
//! what the connection is *for* — a shell, a forward, or a file transfer. So
//! that flow lives here and [`connect`] hands back an authenticated
//! [`Transport`], leaving each binary to open whatever channels it wants.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use tokio::net::TcpStream;

use crate::crypto::ed25519::{PrivateKey, PublicKey};
use crate::crypto::keyfile;
use crate::crypto::sk::SoftwareKey;
use crate::transport::{ClientConfig, Transport};
use crate::{auth, Error};

/// Where and how to connect. Everything the shared flow needs; each binary
/// fills it from its own CLI.
pub struct Options {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub known_hosts: PathBuf,
    pub accept_new: bool,
    /// Extra trusted host-certificate CA keys (a file of pubkey lines).
    pub host_ca: Option<PathBuf>,
    /// Explicit identity file; `None` searches the usual locations.
    pub identity: Option<PathBuf>,
    /// Explicit certificate to present; `None` auto-loads `<identity>-cert.pub`.
    pub certificate: Option<PathBuf>,
    /// Ignore `SSH_AUTH_SOCK` even when set.
    pub no_agent: bool,
}

/// The default location for one of our dotfiles (`~/.shh/<name>`). Uses
/// `HOME`, falling back to `USERPROFILE` (Windows) and then the CWD.
pub fn default_path(name: &str) -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .unwrap_or_else(|| ".".into());
    PathBuf::from(home).join(".shh").join(name)
}

/// How a key-file identity authenticates: a plain Ed25519 key or a security
/// key, either optionally accompanied by a certificate to present.
enum FileAuth {
    Ed25519(PrivateKey, Option<Vec<u8>>),
    SecurityKey(SoftwareKey, Option<Vec<u8>>),
}

/// Dial `opts.host:opts.port`, verify the host key, authenticate, and return
/// the ready transport. Prints progress/prompts to stderr and the tty.
pub async fn connect(opts: &Options) -> Result<Transport<TcpStream>, String> {
    // How to authenticate: an agent holding usable identities (when
    // SSH_AUTH_SOCK is set and no -i pins a file), else a key file. Decided
    // before dialing, so passphrase prompts never race the handshake.
    let mut agent: Option<(crate::agent::Client, Vec<crate::agent::Identity>)> = None;
    // The agent is reached over a Unix socket named by SSH_AUTH_SOCK; on
    // Windows (no named-pipe agent yet) auth uses key files only.
    #[cfg(unix)]
    if !opts.no_agent && opts.identity.is_none() && std::env::var_os("SSH_AUTH_SOCK").is_some() {
        match crate::agent::Client::from_env().await {
            Ok(mut c) => match c.identities().await {
                Ok(ids) => {
                    use crate::crypto::{cert::CERT_ALGO, ed25519::ALGO};
                    let usable = ids
                        .iter()
                        .filter(|i| matches!(i.algo().as_deref(), Some(ALGO) | Some(CERT_ALGO)))
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

    // Without an agent, a key file. An Ed25519 identity may present a
    // certificate beside it (OpenSSH convention `<identity>-cert.pub`; an
    // explicit certificate overrides); a security key presents itself.
    let file_key = match &agent {
        Some(_) => None,
        None => {
            let identity = find_identity(opts.identity.clone())?;
            let text = std::fs::read_to_string(&identity)
                .map_err(|e| format!("{}: {e}", identity.display()))?;
            Some(match load_identity(&text, &identity)? {
                keyfile::PrivateIdentity::Ed25519(key) => {
                    let cert = load_certificate(opts.certificate.as_ref(), &identity)?;
                    FileAuth::Ed25519(key, cert)
                }
                keyfile::PrivateIdentity::SecurityKey(sk) => {
                    let cert = load_certificate(opts.certificate.as_ref(), &identity)?;
                    FileAuth::SecurityKey(sk, cert)
                }
            })
        }
    };

    let label = keyfile::host_label(&opts.host, opts.port);
    let known_hosts = opts.known_hosts.clone();
    let accept_new = opts.accept_new;

    // Trusted host-certificate CAs: from --host-ca and from `@cert-authority`
    // lines in known_hosts. With any, a valid host cert skips the TOFU prompt.
    let mut host_cas = Vec::new();
    if let Some(path) = &opts.host_ca {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        host_cas.extend(keyfile::parse_authorized_keys(&text));
    }
    if let Ok(text) = std::fs::read_to_string(&opts.known_hosts) {
        host_cas.extend(keyfile::known_hosts_cert_authorities(&text));
    }

    let socket = TcpStream::connect((opts.host.as_str(), opts.port))
        .await
        .map_err(|e| format!("connect to {label}: {e}"))?;
    socket.set_nodelay(true).ok();

    let config = ClientConfig {
        verify_host_key: Box::new(move |k| verify_host_key(k, &label, &known_hosts, accept_new)),
        host_cas,
        hostname: opts.host.clone(),
    };
    let mut t = Transport::client(socket, config)
        .await
        .map_err(|e| e.to_string())?;

    // Bind the agent connection to this host before using it, matching
    // OpenSSH: it proves to the agent (via the host's signature over the
    // session id) which host we reached, so a destination-constrained key can
    // decide whether to sign. Best-effort.
    if let Some((client, _)) = &mut agent {
        let (blob, sig) = t.host_binding();
        if !blob.is_empty() {
            if let Err(e) = client.session_bind(blob, t.session_id(), sig, false).await {
                eprintln!("shh: agent session-bind failed ({e}); destination-constrained keys may be refused");
            }
        }
    }

    match (&mut agent, &file_key) {
        (Some((client, ids)), _) => {
            auth::client_agent(&mut t, &opts.user, client, ids, |banner| eprint!("{banner}")).await
        }
        (None, Some(FileAuth::Ed25519(key, cert))) => {
            auth::client(&mut t, &opts.user, key, cert.as_deref(), |banner| eprint!("{banner}")).await
        }
        (None, Some(FileAuth::SecurityKey(sk, cert))) => {
            confirm_presence();
            auth::client_sk(&mut t, &opts.user, sk, cert.as_deref(), |banner| eprint!("{banner}")).await
        }
        (None, None) => unreachable!("one auth source is always chosen"),
    }
    .map_err(|e| e.to_string())?;

    Ok(t)
}

/// Resolve the identity file: an explicit path, else the usual locations.
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
                "no identity found (tried {}); generate one with `shh-keygen -f {}`",
                candidates
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                candidates[0].display(),
            )
        })
}

/// Decode the identity file (Ed25519 or security key), prompting for its
/// passphrase when protected.
fn load_identity(text: &str, path: &Path) -> Result<keyfile::PrivateIdentity, String> {
    let protected =
        keyfile::needs_passphrase(text).map_err(|e| format!("{}: {e}", path.display()))?;
    if !protected {
        return keyfile::decode_private_identity(text, None)
            .map(|(id, _)| id)
            .map_err(|e| format!("{}: {e}", path.display()));
    }
    for _ in 0..3 {
        let pass = crate::tty::read_passphrase(&format!("Enter passphrase for {}: ", path.display()))
            .map_err(|e| format!("cannot prompt for passphrase: {e}"))?;
        match keyfile::decode_private_identity(text, Some(&pass)) {
            Ok((id, _)) => return Ok(id),
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
fn load_certificate(explicit: Option<&PathBuf>, identity: &Path) -> Result<Option<Vec<u8>>, String> {
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

/// Confirm user presence for a (software) security key. A real token would
/// blink for a touch; here we ask on the terminal, and proceed automatically
/// when there is none (scripts, tests).
fn confirm_presence() {
    let _ = crate::tty::prompt_line("shh: confirm presence for the security key (press Enter): ");
}

/// Ask a yes/no question on the controlling terminal.
fn ask_tty(prompt: &str) -> bool {
    crate::tty::prompt_line(&format!("{prompt} [yes/no] "))
        .map(|a| a.trim() == "yes")
        .unwrap_or(false)
}

/// The trust decision for a presented host key: known-good, first contact
/// (TOFU), or mismatch.
fn verify_host_key(
    key: &PublicKey,
    label: &str,
    path: &PathBuf,
    accept_new: bool,
) -> crate::Result<()> {
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
