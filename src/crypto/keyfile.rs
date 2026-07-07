//! Key files. We read and write the standard OpenSSH formats so keys are
//! portable in both directions: `openssh-key-v1` private keys (unencrypted;
//! passphrase-encrypted files are rejected with a clear error for now),
//! `ssh-ed25519 AAAA... comment` public lines, and the same line format for
//! authorized_keys and known_hosts.

use base64::prelude::{Engine as _, BASE64_STANDARD};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};

use super::ed25519::{PrivateKey, PublicKey, ALGO};
use crate::wire::{Reader, Writer};
use crate::{Error, Result};

const PEM_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PEM_END: &str = "-----END OPENSSH PRIVATE KEY-----";
const AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";

fn bad(msg: impl Into<String>) -> Error {
    Error::KeyFile(msg.into())
}

// ------------------------------------------------------------- private --

/// Serialize a private key as an unencrypted `openssh-key-v1` file.
pub fn encode_private(key: &PrivateKey, comment: &str) -> String {
    let pub_blob = key.public().to_blob();

    let mut inner = Writer::new();
    let check = OsRng.next_u32();
    inner.u32(check).u32(check);
    inner.utf8(ALGO);
    inner.string(key.public().0.as_bytes());
    // "private" field is seed ‖ public, per the format.
    let mut sk = key.0.to_bytes().to_vec();
    sk.extend_from_slice(key.public().0.as_bytes());
    inner.string(&sk);
    inner.utf8(comment);
    let mut inner = inner.into_bytes();
    let mut padbyte = 1u8;
    while inner.len() % 8 != 0 {
        inner.push(padbyte);
        padbyte = padbyte.wrapping_add(1);
    }

    let mut w = Writer::new();
    // no framing for the magic — it's a bare NUL-terminated literal
    let mut out = AUTH_MAGIC.to_vec();
    w.utf8("none"); // ciphername
    w.utf8("none"); // kdfname
    w.string(b""); // kdfoptions
    w.u32(1); // number of keys
    w.string(&pub_blob);
    w.string(&inner);
    out.extend_from_slice(&w.into_bytes());

    let b64 = BASE64_STANDARD.encode(&out);
    let mut file = String::from(PEM_BEGIN);
    file.push('\n');
    for chunk in b64.as_bytes().chunks(70) {
        file.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        file.push('\n');
    }
    file.push_str(PEM_END);
    file.push('\n');
    file
}

/// Parse an `openssh-key-v1` private key file (Ed25519, unencrypted).
pub fn decode_private(text: &str) -> Result<(PrivateKey, String)> {
    let body: String = text
        .lines()
        .map(str::trim)
        .skip_while(|l| *l != PEM_BEGIN)
        .skip(1)
        .take_while(|l| *l != PEM_END)
        .collect();
    if body.is_empty() {
        return Err(bad("not an OPENSSH PRIVATE KEY file"));
    }
    let raw = BASE64_STANDARD
        .decode(&body)
        .map_err(|e| bad(format!("base64: {e}")))?;
    let rest = raw
        .strip_prefix(AUTH_MAGIC)
        .ok_or_else(|| bad("missing openssh-key-v1 magic"))?;

    let mut r = Reader::new(rest);
    let cipher = r.utf8()?.to_owned();
    let kdf = r.utf8()?.to_owned();
    let _kdfopts = r.string()?;
    if cipher != "none" || kdf != "none" {
        return Err(bad(
            "passphrase-protected keys are not supported yet; \
             decrypt with `ssh-keygen -p -N \"\"` first",
        ));
    }
    let nkeys = r.u32()?;
    if nkeys != 1 {
        return Err(bad(format!("expected 1 key in file, found {nkeys}")));
    }
    let _pub_blob = r.string()?;
    let inner = r.string()?;
    r.finish()?;

    let mut r = Reader::new(inner);
    let c1 = r.u32()?;
    let c2 = r.u32()?;
    if c1 != c2 {
        return Err(bad("check bytes mismatch (corrupt file?)"));
    }
    let algo = r.utf8()?;
    if algo != ALGO {
        return Err(bad(format!("unsupported key type {algo:?} (Ed25519 only)")));
    }
    let public = r.string()?;
    let sk = r.string()?;
    let comment = r.utf8()?.to_owned();
    // remaining bytes are deterministic padding 1,2,3…
    for (i, &b) in r.rest().iter().enumerate() {
        if b != (i + 1) as u8 {
            return Err(bad("bad trailing padding"));
        }
    }

    if sk.len() != 64 || public.len() != 32 || &sk[32..] != public {
        return Err(bad("inconsistent ed25519 key material"));
    }
    let seed: [u8; 32] = sk[..32].try_into().expect("length checked");
    let key = PrivateKey(SigningKey::from_bytes(&seed));
    if key.public().0.as_bytes() != public {
        return Err(bad("public key does not match private seed"));
    }
    Ok((key, comment))
}

// -------------------------------------------------------------- public --

/// One `ssh-ed25519 AAAA... comment` line.
pub fn encode_public(key: &PublicKey, comment: &str) -> String {
    let b64 = BASE64_STANDARD.encode(key.to_blob());
    if comment.is_empty() {
        format!("{ALGO} {b64}\n")
    } else {
        format!("{ALGO} {b64} {comment}\n")
    }
}

/// Parse a public key line (as found in `.pub`, authorized_keys, or the
/// key part of known_hosts). Returns the key and comment.
pub fn decode_public(line: &str) -> Result<(PublicKey, String)> {
    let mut parts = line.split_whitespace();
    let algo = parts.next().ok_or_else(|| bad("empty public key line"))?;
    if algo != ALGO {
        return Err(bad(format!("unsupported key type {algo:?} (Ed25519 only)")));
    }
    let b64 = parts.next().ok_or_else(|| bad("missing key material"))?;
    let blob = BASE64_STANDARD
        .decode(b64)
        .map_err(|e| bad(format!("base64: {e}")))?;
    let key = PublicKey::from_blob(&blob)?;
    Ok((key, parts.collect::<Vec<_>>().join(" ")))
}

/// Parse an authorized_keys file: Ed25519 lines are candidates, comments
/// and other key types are skipped (they can't authenticate here anyway).
pub fn parse_authorized_keys(text: &str) -> Vec<PublicKey> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| decode_public(l).ok().map(|(k, _)| k))
        .collect()
}

// --------------------------------------------------------- known_hosts --

/// The host token used in known_hosts lines: bare hostname on the default
/// port, `[host]:port` otherwise (the OpenSSH convention).
pub fn host_label(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

/// Find the recorded Ed25519 key for `label` in known_hosts text.
/// Hashed (`|1|…`) and marker (`@…`) lines are skipped — we only write
/// plain lines and only need to read our own.
pub fn known_hosts_lookup(text: &str, label: &str) -> Option<PublicKey> {
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
            continue;
        }
        let Some((hosts, rest)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if hosts.split(',').any(|h| h == label) {
            if let Ok((key, _)) = decode_public(rest.trim_start()) {
                return Some(key);
            }
        }
    }
    None
}

/// One known_hosts line for `label`.
pub fn known_hosts_line(label: &str, key: &PublicKey) -> String {
    format!("{label} {}", encode_public(key, ""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_roundtrip() {
        let key = PrivateKey::generate();
        let text = encode_private(&key, "test@shh");
        let (back, comment) = decode_private(&text).unwrap();
        assert_eq!(back.0.to_bytes(), key.0.to_bytes());
        assert_eq!(comment, "test@shh");
    }

    #[test]
    fn public_roundtrip() {
        let key = PrivateKey::generate().public();
        let line = encode_public(&key, "me@host");
        let (back, comment) = decode_public(&line).unwrap();
        assert_eq!(back, key);
        assert_eq!(comment, "me@host");
    }

    #[test]
    fn authorized_keys_skips_junk() {
        let k1 = PrivateKey::generate().public();
        let k2 = PrivateKey::generate().public();
        let text = format!(
            "# a comment\n\n{}ssh-rsa AAAA not-ours\n{}",
            encode_public(&k1, "one"),
            encode_public(&k2, "two"),
        );
        let keys = parse_authorized_keys(&text);
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&k1) && keys.contains(&k2));
    }

    #[test]
    fn garbage_rejected() {
        assert!(decode_private("not a key").is_err());
        assert!(decode_public("ecdsa-sha2-nistp256 AAAA...").is_err());
    }
}
