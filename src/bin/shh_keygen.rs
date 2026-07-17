//! Generate a keypair, or sign a user certificate. The default key type is
//! Ed25519; `-t ed25519-sk` makes a *software-emulated* security key (see
//! `--type`).

use std::io::Write;
use std::path::{Path, PathBuf};

use base64::prelude::{Engine as _, BASE64_STANDARD};
use clap::Parser;
use shh::crypto::{cert, ed25519::PrivateKey, keyfile, sk::SoftwareKey, userkey::UserKey};

#[derive(Parser)]
#[command(name = "shh-keygen", about = "Generate an Ed25519 key or sign a certificate")]
struct Args {
    /// Key file. Generating: output private key (`.pub` written alongside).
    /// Signing (`--sign`): the public key to certify.
    #[arg(short = 'f', long = "file")]
    file: PathBuf,

    /// Key type: `ed25519` (default) or `ed25519-sk`. The `-sk` type is a
    /// *software-emulated* FIDO2 security key — the seed lives in the file,
    /// not a hardware token, so it has no hardware protection; it is for
    /// testing and environments without a key. The public credential is a
    /// standard `sk-ssh-ed25519@openssh.com` line any server accepts.
    #[arg(short = 't', long = "type", default_value = "ed25519")]
    key_type: String,

    /// Comment embedded in the generated key.
    #[arg(short = 'C', long = "comment", default_value = "")]
    comment: String,

    /// Passphrase ("" for none). Prompted for interactively when omitted.
    #[arg(short = 'N', long = "passphrase")]
    passphrase: Option<String>,

    /// Overwrite an existing key.
    #[arg(long)]
    force: bool,

    /// Sign the public key in `-f` with this CA private key, producing a
    /// certificate `<file-without-.pub>-cert.pub`.
    #[arg(short = 's', long = "sign", value_name = "CA_KEY")]
    sign: Option<PathBuf>,

    /// Certificate identity (key id), shown in logs and audit trails.
    #[arg(short = 'I', long = "cert-id", default_value = "shh")]
    cert_id: String,

    /// Comma-separated principals the certificate is valid for. For user
    /// certs these are login names; for host certs (`--host`) they are
    /// hostnames (empty is rejected for host certs).
    #[arg(short = 'n', long = "principals", default_value = "")]
    principals: String,

    /// Sign a host certificate instead of a user certificate.
    #[arg(short = 'H', long = "host")]
    host: bool,

    /// Mint a user certificate with an empty principal list, valid for *any*
    /// login name. Off by default: an all-users credential should be a
    /// deliberate choice, not the result of forgetting `-n`.
    #[arg(long = "allow-any-principal")]
    allow_any_principal: bool,

    /// Certificate validity in days from now.
    #[arg(long = "days", default_value_t = 365)]
    days: u64,

    /// Certificate serial number.
    #[arg(long = "serial", default_value_t = 0)]
    serial: u64,

    /// Certificate critical option, `key=value`, repeatable. Supported on
    /// user certs: `force-command=<cmd>` (the session runs this whatever the
    /// client asked) and `source-address=<cidr[,cidr...]>` (the cert is
    /// refused from a client outside those ranges). Mirrors `ssh-keygen -O`.
    #[arg(short = 'O', long = "option", value_name = "KEY=VALUE")]
    options: Vec<String>,
}

/// Resolve the passphrase for a freshly generated key: flag wins; otherwise
/// prompt twice on the terminal; no terminal means unencrypted.
fn choose_passphrase(flag: Option<String>) -> std::io::Result<Option<String>> {
    if let Some(p) = flag {
        return Ok(if p.is_empty() { None } else { Some(p) });
    }
    if !Path::new("/dev/tty").exists() {
        return Ok(None);
    }
    // A terminal exists (checked above), so a read error here is a real
    // failure — propagate it instead of silently writing an unencrypted key.
    let first = shh::tty::read_passphrase("Enter passphrase (empty for none): ")?;
    if first.is_empty() {
        return Ok(None);
    }
    let second = shh::tty::read_passphrase("Enter same passphrase again: ")?;
    if first != second {
        eprintln!("shh-keygen: passphrases do not match");
        std::process::exit(1);
    }
    Ok(Some(first))
}

/// Load a private key, prompting for its passphrase if the file is encrypted.
fn load_ca_key(path: &Path) -> std::io::Result<PrivateKey> {
    let text = std::fs::read_to_string(path)?;
    let protected = keyfile::needs_passphrase(&text)
        .map_err(|e| std::io::Error::other(format!("{}: {e}", path.display())))?;
    if !protected {
        return keyfile::decode_private(&text)
            .map(|(k, _)| k)
            .map_err(|e| std::io::Error::other(format!("{}: {e}", path.display())));
    }
    for _ in 0..3 {
        let pass = shh::tty::read_passphrase(&format!("Enter passphrase for CA {}: ", path.display()))?;
        match keyfile::decode_private_protected(&text, Some(&pass)) {
            Ok((k, _)) => return Ok(k),
            Err(e) if e.to_string().contains("wrong passphrase") => {
                eprintln!("shh-keygen: wrong passphrase, try again");
            }
            Err(e) => return Err(std::io::Error::other(format!("{}: {e}", path.display()))),
        }
    }
    Err(std::io::Error::other("too many passphrase attempts"))
}

fn sign_certificate(args: &Args, ca_path: &Path) -> std::io::Result<()> {
    let ca = load_ca_key(ca_path)?;
    let pub_text = std::fs::read_to_string(&args.file)?;
    let pub_line = pub_text.trim();
    // A user cert may certify an Ed25519 key or a security key; a host cert is
    // Ed25519 only. Decode as a UserKey and branch on what we got.
    let user_key = keyfile::decode_user_key(pub_line)
        .map_err(|e| std::io::Error::other(format!("{}: {e}", args.file.display())))?;
    // The comment is whatever trails the algo + base64 blob.
    let comment = pub_line.split_whitespace().skip(2).collect::<Vec<_>>().join(" ");

    let principals: Vec<String> = args
        .principals
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if args.host && principals.is_empty() {
        eprintln!("shh-keygen: a host certificate needs at least one hostname (-n)");
        std::process::exit(1);
    }
    if !args.host && principals.is_empty() && !args.allow_any_principal {
        eprintln!(
            "shh-keygen: a user certificate needs at least one principal (-n); \
             pass --allow-any-principal to mint an any-user certificate on purpose"
        );
        std::process::exit(1);
    }
    let now = cert::now_secs();
    let valid_after = now.saturating_sub(60); // small clock-skew grace
    let valid_before = now + args.days.saturating_mul(86_400);

    let options = parse_cert_options(&args.options);
    if args.host && options != cert::CertOptions::default() {
        eprintln!("shh-keygen: critical options (-O) apply to user certificates only");
        std::process::exit(1);
    }

    let (blob, algo) = match &user_key {
        UserKey::Ed25519(key) if args.host => (
            cert::sign_host_cert(&ca, key, args.serial, &args.cert_id, &principals, valid_after, valid_before),
            cert::CERT_ALGO,
        ),
        UserKey::Ed25519(key) => (
            cert::sign_user_cert_with(&ca, key, &options, args.serial, &args.cert_id, &principals, valid_after, valid_before),
            cert::CERT_ALGO,
        ),
        UserKey::Sk(_) if args.host => {
            eprintln!("shh-keygen: a security key cannot be a host key");
            std::process::exit(1);
        }
        UserKey::Sk(sk) => (
            cert::sign_sk_user_cert_with(&ca, sk, &options, args.serial, &args.cert_id, &principals, valid_after, valid_before),
            cert::SK_CERT_ALGO,
        ),
    };

    // `<file>` is `foo.pub`; the certificate goes to `foo-cert.pub`.
    let stem = args
        .file
        .to_string_lossy()
        .strip_suffix(".pub")
        .map(str::to_owned)
        .unwrap_or_else(|| args.file.to_string_lossy().into_owned());
    let cert_path = PathBuf::from(format!("{stem}-cert.pub"));
    let line = format!("{} {} {comment}\n", algo, BASE64_STANDARD.encode(&blob));
    std::fs::write(&cert_path, line)?;

    let who = if principals.is_empty() {
        "any principal".to_string()
    } else {
        principals.join(",")
    };
    let kind = if args.host { "host" } else { "user" };
    println!("{kind} certificate: {}", cert_path.display());
    println!("  signed by CA {}", ca.public().fingerprint());
    println!("  id {:?}, serial {}, valid for {} day(s), principals: {who}", args.cert_id, args.serial, args.days);
    if let Some(cmd) = &options.force_command {
        println!("  force-command: {cmd:?}");
    }
    if let Some(src) = &options.source_address {
        println!("  source-address: {src}");
    }
    Ok(())
}

/// Turn `-O key=value` flags into [`cert::CertOptions`]. Unknown keys are a
/// hard error rather than a silent no-op.
fn parse_cert_options(raw: &[String]) -> cert::CertOptions {
    let mut opts = cert::CertOptions::default();
    for item in raw {
        let (key, value) = match item.split_once('=') {
            Some(kv) => kv,
            None => {
                eprintln!("shh-keygen: -O expects key=value, got {item:?}");
                std::process::exit(2);
            }
        };
        match key {
            "force-command" => opts.force_command = Some(value.to_owned()),
            "source-address" => opts.source_address = Some(value.to_owned()),
            other => {
                eprintln!(
                    "shh-keygen: unsupported certificate option {other:?} \
                     (force-command, source-address)"
                );
                std::process::exit(2);
            }
        }
    }
    opts
}

fn generate_key(args: &Args) -> std::io::Result<()> {
    if args.file.exists() && !args.force {
        eprintln!(
            "shh-keygen: {} already exists (use --force to overwrite)",
            args.file.display()
        );
        std::process::exit(1);
    }
    if let Some(dir) = args.file.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }

    let passphrase = choose_passphrase(args.passphrase.clone())?;

    // Serialize the private key and its `.pub` line, per key type.
    let (encoded, pub_line, fingerprint) = match args.key_type.as_str() {
        "ed25519" => {
            let key = PrivateKey::generate();
            let enc = keyfile::encode_private_protected(&key, &args.comment, passphrase.as_deref())
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            (
                enc,
                keyfile::encode_public(&key.public(), &args.comment),
                key.public().fingerprint(),
            )
        }
        "ed25519-sk" => {
            let key = SoftwareKey::generate("ssh:");
            let enc = keyfile::encode_sk_private(&key, &args.comment, passphrase.as_deref())
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            eprintln!(
                "shh-keygen: note: ed25519-sk here is SOFTWARE-emulated (no hardware \
                 protection); the seed is stored in the key file."
            );
            (
                enc,
                keyfile::encode_sk_public(&key.public(), &args.comment),
                key.public().fingerprint(),
            )
        }
        other => {
            eprintln!("shh-keygen: unknown key type {other:?} (ed25519 or ed25519-sk)");
            std::process::exit(2);
        }
    };

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&args.file)?;
    f.write_all(encoded.as_bytes())?;

    let pub_path = {
        let mut p = args.file.clone().into_os_string();
        p.push(".pub");
        PathBuf::from(p)
    };
    std::fs::write(&pub_path, pub_line)?;

    println!("private key: {}", args.file.display());
    println!("public key:  {}", pub_path.display());
    println!("fingerprint: {fingerprint}");
    Ok(())
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    match &args.sign {
        Some(ca) => sign_certificate(&args, ca),
        None => generate_key(&args),
    }
}
