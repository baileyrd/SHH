//! Generate an Ed25519 keypair in OpenSSH format. There is no `-t`
//! option: SHH has exactly one key type.

use std::io::Write;
use std::path::PathBuf;

use clap::Parser;
use shh::crypto::{ed25519::PrivateKey, keyfile};

#[derive(Parser)]
#[command(name = "shh-keygen", about = "Generate an Ed25519 key for shh")]
struct Args {
    /// Output file for the private key (`.pub` is written alongside).
    #[arg(short = 'f', long = "file")]
    file: PathBuf,

    /// Comment embedded in the key.
    #[arg(short = 'C', long = "comment", default_value = "")]
    comment: String,

    /// Passphrase ("" for none). Prompted for interactively when omitted.
    #[arg(short = 'N', long = "passphrase")]
    passphrase: Option<String>,

    /// Overwrite an existing key.
    #[arg(long)]
    force: bool,
}

/// Resolve the passphrase: flag wins; otherwise prompt twice on the
/// terminal; no terminal means unencrypted.
fn choose_passphrase(flag: Option<String>) -> std::io::Result<Option<String>> {
    if let Some(p) = flag {
        return Ok(if p.is_empty() { None } else { Some(p) });
    }
    if !std::path::Path::new("/dev/tty").exists() {
        return Ok(None);
    }
    let first = match shh::tty::read_passphrase("Enter passphrase (empty for none): ") {
        Ok(p) => p,
        Err(_) => return Ok(None), // no usable tty after all
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

fn main() -> std::io::Result<()> {
    let args = Args::parse();
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
    let passphrase = choose_passphrase(args.passphrase)?;
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
