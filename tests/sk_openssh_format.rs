//! Prove our `sk-ssh-ed25519@openssh.com` public-key encoding is byte-exact
//! with OpenSSH's: write an authorized_keys line from our encoder and have
//! `ssh-keygen -l` parse and fingerprint it. If OpenSSH computes the same
//! SHA256 fingerprint we do, the blobs are identical.
//!
//! (Full sign-side interop needs a physical security key, which CI lacks;
//! this checks the wire format a server actually stores and matches on.)

use base64::prelude::{Engine as _, BASE64_STANDARD};
use shh::crypto::ed25519::PrivateKey;
use shh::crypto::sk::SkPublicKey;

#[test]
fn openssh_fingerprints_our_sk_pubkey_identically() {
    // Skip gracefully where ssh-keygen isn't installed.
    if std::process::Command::new("ssh-keygen")
        .arg("-Q")
        .output()
        .is_err()
    {
        eprintln!("ssh-keygen not found; skipping sk format interop");
        return;
    }

    // A security-key credential over a fresh Ed25519 public key.
    let ed = PrivateKey::generate().public();
    let sk = SkPublicKey::new(ed.0.to_bytes(), "ssh:").unwrap();
    let line = format!(
        "sk-ssh-ed25519@openssh.com {} test@shh\n",
        BASE64_STANDARD.encode(sk.to_blob())
    );

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("id_sk.pub");
    std::fs::write(&path, &line).unwrap();

    let out = std::process::Command::new("ssh-keygen")
        .arg("-l")
        .arg("-f")
        .arg(&path)
        .output()
        .expect("run ssh-keygen -l");
    assert!(
        out.status.success(),
        "ssh-keygen rejected our sk pubkey: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // ssh-keygen prints: "256 SHA256:xxxx comment (ED25519-SK)".
    let openssh_fp = stdout
        .split_whitespace()
        .nth(1)
        .expect("fingerprint column");
    assert_eq!(
        openssh_fp,
        sk.fingerprint(),
        "OpenSSH fingerprint {openssh_fp} != ours {}; encoding differs",
        sk.fingerprint()
    );
    assert!(
        stdout.contains("ED25519-SK"),
        "ssh-keygen should recognize the sk key type: {stdout}"
    );
}
