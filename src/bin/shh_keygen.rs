//! Generate an Ed25519 keypair, or sign a user certificate. There is no
//! `-t` option: SHH has exactly one key type.

use std::io::Write;
use std::path::{Path, PathBuf};

use base64::prelude::{Engine as _, BASE64_STANDARD};
use clap::Parser;
use shh::crypto::{cert, ed25519::PrivateKey, keyfile};

#[derive(Parser)]
#[command(name = "shh-keygen", about = "Generate an Ed25519 key or sign a certificate")]
struct Args {
    /// Key file. Generating: output private key (`.pub` written alongside).
    /// Signing (`--sign`): the public key to certify.
    #[arg(short = 'f', long = "file")]
    file: PathBuf,

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

    /// Certificate validity in days from now.
    #[arg(long = "days", default_value_t = 365)]
    days: u64,

    /// Certificate serial number.
    #[arg(long = "serial", default_value_t = 0)]
    serial: u64,
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
    let first = match shh::tty::read_passphrase("Enter passphrase (empty for none): ") {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };
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
    let (user_key, comment) = keyfile::decode_public(pub_text.trim())
        .map_err(|e| std::io::Error::other(format!("{}: {e}", args.file.display())))?;

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
    let now = cert::now_secs();
    let valid_after = now.saturating_sub(60); // small clock-skew grace
    let valid_before = now + args.days.saturating_mul(86_400);

    let sign = if args.host {
        cert::sign_host_cert
    } else {
        cert::sign_user_cert
    };
    let blob = sign(
        &ca,
        &user_key,
        args.serial,
        &args.cert_id,
        &principals,
        valid_after,
        valid_before,
    );

    // `<file>` is `foo.pub`; the certificate goes to `foo-cert.pub`.
    let stem = args
        .file
        .to_string_lossy()
        .strip_suffix(".pub")
        .map(str::to_owned)
        .unwrap_or_else(|| args.file.to_string_lossy().into_owned());
    let cert_path = PathBuf::from(format!("{stem}-cert.pub"));
    let line = format!("{} {} {comment}\n", cert::CERT_ALGO, BASE64_STANDARD.encode(&blob));
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
    Ok(())
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

    let key = PrivateKey::generate();
    let passphrase = choose_passphrase(args.passphrase.clone())?;
    let encoded = keyfile::encode_private_protected(&key, &args.comment, passphrase.as_deref())
        .map_err(|e| std::io::Error::other(e.to_string()))?;

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
    std::fs::write(&pub_path, keyfile::encode_public(&key.public(), &args.comment))?;

    println!("private key: {}", args.file.display());
    println!("public key:  {}", pub_path.display());
    println!("fingerprint: {}", key.public().fingerprint());
    Ok(())
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    match &args.sign {
        Some(ca) => sign_certificate(&args, ca),
        None => generate_key(&args),
    }
}
