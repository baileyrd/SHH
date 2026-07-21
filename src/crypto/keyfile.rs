//! Key files. We read and write the standard OpenSSH formats so keys are
//! portable in both directions: `openssh-key-v1` private keys (plain, or
//! passphrase-protected with bcrypt + AES-256-CTR exactly as `ssh-keygen`
//! writes them), `ssh-ed25519 AAAA... comment` public lines, and the same
//! line format for authorized_keys and known_hosts.

use aes::Aes256;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use ctr::cipher::{KeyIvInit, StreamCipher};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

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

/// bcrypt work factor for keys we write — ssh-keygen's `-a` default.
const BCRYPT_ROUNDS: u32 = 16;

/// The plaintext "inner" section: check bytes, key material, comment,
/// deterministic padding up to `block`.
fn build_inner(key: &PrivateKey, comment: &str, block: usize) -> Zeroizing<Vec<u8>> {
    let mut inner = Writer::new();
    let check = OsRng.next_u32();
    inner.u32(check).u32(check);
    inner.utf8(ALGO);
    inner.string(key.public().0.as_bytes());
    // "private" field is seed ‖ public, per the format.
    let mut sk = Zeroizing::new(key.0.to_bytes().to_vec());
    sk.extend_from_slice(key.public().0.as_bytes());
    inner.string(&sk);
    inner.utf8(comment);
    let mut inner = Zeroizing::new(inner.into_bytes());
    let mut padbyte = 1u8;
    while inner.len() % block != 0 {
        inner.push(padbyte);
        padbyte = padbyte.wrapping_add(1);
    }
    inner
}

fn pem_wrap(payload: &[u8]) -> String {
    let b64 = BASE64_STANDARD.encode(payload);
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

/// Derive the AES-256-CTR key+IV from a passphrase (bcrypt KDF).
fn kdf_material(passphrase: &str, salt: &[u8], rounds: u32) -> Result<Zeroizing<[u8; 48]>> {
    let mut km = Zeroizing::new([0u8; 48]);
    bcrypt_pbkdf::bcrypt_pbkdf(passphrase, salt, rounds, &mut km[..])
        .map_err(|_| bad("bcrypt KDF failed (empty passphrase?)"))?;
    Ok(km)
}

/// Wrap a public blob and a private-section builder into an `openssh-key-v1`
/// file, encrypting with AES-256-CTR under a bcrypt-derived key when a
/// passphrase is given. `build_inner(block)` returns the padded inner
/// section for the given cipher block size.
fn armor_key(
    pub_blob: &[u8],
    build_inner: impl Fn(usize) -> Zeroizing<Vec<u8>>,
    passphrase: Option<&str>,
) -> Result<String> {
    let mut w = Writer::new();
    let mut out = AUTH_MAGIC.to_vec();
    match passphrase {
        None | Some("") => {
            w.utf8("none");
            w.utf8("none");
            w.string(b"");
            w.u32(1);
            w.string(pub_blob);
            w.string(&build_inner(8));
        }
        Some(pass) => {
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            let km = kdf_material(pass, &salt, BCRYPT_ROUNDS)?;
            let mut inner = build_inner(16);
            Aes256Ctr::new(
                km[..32].try_into().expect("kdf_material produced a 32-byte key"),
                km[32..].try_into().expect("kdf_material produced a 16-byte iv"),
            )
            .apply_keystream(&mut inner);

            w.utf8("aes256-ctr");
            w.utf8("bcrypt");
            let mut opts = Writer::new();
            opts.string(&salt);
            opts.u32(BCRYPT_ROUNDS);
            w.string(&opts.into_bytes());
            w.u32(1);
            w.string(pub_blob);
            w.string(&inner);
        }
    }
    out.extend_from_slice(&w.into_bytes());
    Ok(pem_wrap(&out))
}

/// Serialize a private key as an `openssh-key-v1` file; encrypted with
/// AES-256-CTR under a bcrypt-derived key when a passphrase is given.
pub fn encode_private_protected(
    key: &PrivateKey,
    comment: &str,
    passphrase: Option<&str>,
) -> Result<String> {
    armor_key(
        &key.public().to_blob(),
        |block| build_inner(key, comment, block),
        passphrase,
    )
}

/// Serialize a private key unencrypted (host keys, tests).
pub fn encode_private(key: &PrivateKey, comment: &str) -> String {
    encode_private_protected(key, comment, None).expect("unencrypted encoding cannot fail")
}

/// The private "inner" section for a software security key, mirroring
/// OpenSSH's `sk-ssh-ed25519` layout — except the "key handle" a real
/// authenticator stores is, for a software key, the Ed25519 seed itself.
fn build_sk_inner(
    key: &crate::crypto::sk::SoftwareKey,
    comment: &str,
    block: usize,
) -> Zeroizing<Vec<u8>> {
    let mut inner = Writer::new();
    let check = OsRng.next_u32();
    inner.u32(check).u32(check);
    inner.utf8(crate::crypto::sk::SK_ALGO);
    inner.string(&key.verifying_bytes());
    inner.utf8(key.application());
    inner.byte(0x01); // SSH_SK_USER_PRESENCE_REQUIRED
    let handle = Zeroizing::new(key.seed().to_vec()); // software: the seed
    inner.string(&handle);
    inner.string(b""); // reserved
    inner.utf8(comment);
    let mut inner = Zeroizing::new(inner.into_bytes());
    let mut padbyte = 1u8;
    while inner.len() % block != 0 {
        inner.push(padbyte);
        padbyte = padbyte.wrapping_add(1);
    }
    inner
}

/// Serialize a software security key as an `openssh-key-v1` file.
pub fn encode_sk_private(
    key: &crate::crypto::sk::SoftwareKey,
    comment: &str,
    passphrase: Option<&str>,
) -> Result<String> {
    armor_key(
        &key.public().to_blob(),
        |block| build_sk_inner(key, comment, block),
        passphrase,
    )
}

/// Strip PEM armor and base64.
fn unarmor(text: &str) -> Result<Zeroizing<Vec<u8>>> {
    // The decoded bytes hold the private seed when the file is unencrypted, so
    // both the base64 body and the decoded output are zeroized on drop.
    let body: Zeroizing<String> = Zeroizing::new(
        text.lines()
            .map(str::trim)
            .skip_while(|l| *l != PEM_BEGIN)
            .skip(1)
            .take_while(|l| *l != PEM_END)
            .collect(),
    );
    if body.is_empty() {
        return Err(bad("not an OPENSSH PRIVATE KEY file"));
    }
    BASE64_STANDARD
        .decode(body.as_bytes())
        .map(Zeroizing::new)
        .map_err(|e| bad(format!("base64: {e}")))
}

/// Does this key file require a passphrase to open?
pub fn needs_passphrase(text: &str) -> Result<bool> {
    let raw = unarmor(text)?;
    let rest = raw
        .strip_prefix(AUTH_MAGIC)
        .ok_or_else(|| bad("missing openssh-key-v1 magic"))?;
    let mut r = Reader::new(rest);
    Ok(r.utf8()? != "none")
}

/// Parse an `openssh-key-v1` private key file (Ed25519, unencrypted).
pub fn decode_private(text: &str) -> Result<(PrivateKey, String)> {
    decode_private_protected(text, None)
}

/// Parse an `openssh-key-v1` private key file, decrypting with
/// `passphrase` if the file is protected.
pub fn decode_private_protected(
    text: &str,
    passphrase: Option<&str>,
) -> Result<(PrivateKey, String)> {
    match decode_private_identity(text, passphrase)? {
        (PrivateIdentity::Ed25519(key), comment) => Ok((key, comment)),
        (PrivateIdentity::SecurityKey(_), _) => Err(bad(
            "this is a security-key identity; load it as one",
        )),
    }
}

/// Decrypt and check-validate the inner private section of an
/// `openssh-key-v1` file, without parsing the key material itself. Returns
/// the decrypted inner bytes positioned at the first key field (algorithm),
/// so the caller can dispatch on key type.
fn open_inner(text: &str, passphrase: Option<&str>) -> Result<Zeroizing<Vec<u8>>> {
    let raw = unarmor(text)?;
    let rest = raw
        .strip_prefix(AUTH_MAGIC)
        .ok_or_else(|| bad("missing openssh-key-v1 magic"))?;

    let mut r = Reader::new(rest);
    let cipher = r.utf8()?.to_owned();
    let kdf = r.utf8()?.to_owned();
    let kdfopts = r.string()?.to_vec();

    let encrypted = match (cipher.as_str(), kdf.as_str()) {
        ("none", "none") => false,
        ("aes256-ctr", "bcrypt") => true,
        _ => {
            return Err(bad(format!(
                "unsupported key protection {cipher}/{kdf}; re-encrypt with \
                 `ssh-keygen -p -Z aes256-ctr` or shh-keygen"
            )))
        }
    };

    let nkeys = r.u32()?;
    if nkeys != 1 {
        return Err(bad(format!("expected 1 key in file, found {nkeys}")));
    }
    let _pub_blob = r.string()?;
    let mut inner = Zeroizing::new(r.string()?.to_vec());
    r.finish()?;

    if encrypted {
        let pass = passphrase.ok_or_else(|| bad("key is passphrase-protected"))?;
        let mut opts = Reader::new(&kdfopts);
        let salt = opts.string()?.to_vec();
        let rounds = opts.u32()?;
        opts.finish()?;
        if rounds == 0 || rounds > 1 << 24 {
            return Err(bad(format!("unreasonable bcrypt rounds {rounds}")));
        }
        let km = kdf_material(pass, &salt, rounds)?;
        Aes256Ctr::new(
            km[..32].try_into().expect("kdf_material produced a 32-byte key"),
            km[32..].try_into().expect("kdf_material produced a 16-byte iv"),
        )
        .apply_keystream(&mut inner);
    }

    // Validate the check-int pair up front so a wrong passphrase is caught
    // before we try to interpret garbage as key fields.
    let mut r = Reader::new(&inner);
    if r.u32()? != r.u32()? {
        return Err(if encrypted {
            bad("wrong passphrase")
        } else {
            bad("check bytes mismatch (corrupt file?)")
        });
    }
    // Return the decrypted inner; callers re-read from the algorithm field.
    let pos = 8; // two consumed check words
    Ok(Zeroizing::new(inner[pos..].to_vec()))
}

/// A private authentication identity loaded from a file: a plain Ed25519 key
/// or a (software) security key.
pub enum PrivateIdentity {
    Ed25519(PrivateKey),
    SecurityKey(crate::crypto::sk::SoftwareKey),
}

/// Parse any private identity we support, dispatching on the key type in the
/// file. Handles passphrase decryption via `passphrase`.
pub fn decode_private_identity(
    text: &str,
    passphrase: Option<&str>,
) -> Result<(PrivateIdentity, String)> {
    let inner = open_inner(text, passphrase)?;
    let mut r = Reader::new(&inner);
    let algo = r.utf8()?.to_owned();
    match algo.as_str() {
        ALGO => {
            let public = r.string()?;
            let sk = r.string()?;
            let comment = r.utf8()?.to_owned();
            check_padding(r.rest())?;
            if sk.len() != 64 || public.len() != 32 || &sk[32..] != public {
                return Err(bad("inconsistent ed25519 key material"));
            }
            let seed: [u8; 32] = sk[..32].try_into().expect("length checked");
            let key = PrivateKey(SigningKey::from_bytes(&seed));
            if key.public().0.as_bytes() != public {
                return Err(bad("public key does not match private seed"));
            }
            Ok((PrivateIdentity::Ed25519(key), comment))
        }
        a if a == crate::crypto::sk::SK_ALGO => {
            let enc_a: [u8; 32] = r
                .string()?
                .try_into()
                .map_err(|_| bad("sk public key must be 32 bytes"))?;
            let application = r.utf8()?.to_owned();
            let _flags = r.byte()?;
            let handle = Zeroizing::new(r.string()?.to_vec()); // software: the seed
            let _reserved = r.string()?;
            let comment = r.utf8()?.to_owned();
            check_padding(r.rest())?;
            let seed: [u8; 32] = handle
                .as_slice()
                .try_into()
                .map_err(|_| bad("this security key is not software-backed (no seed to sign with)"))?;
            let key = crate::crypto::sk::SoftwareKey::from_seed(seed, &application);
            if key.verifying_bytes() != enc_a {
                return Err(bad("sk public key does not match the stored seed"));
            }
            Ok((PrivateIdentity::SecurityKey(key), comment))
        }
        other => Err(bad(format!("unsupported key type {other:?}"))),
    }
}

/// The trailing bytes of an inner section must be deterministic padding
/// 1, 2, 3, ….
fn check_padding(rest: &[u8]) -> Result<()> {
    for (i, &b) in rest.iter().enumerate() {
        if b != (i + 1) as u8 {
            return Err(bad("bad trailing padding"));
        }
    }
    Ok(())
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

/// One `sk-ssh-ed25519@openssh.com AAAA... comment` line (a security-key
/// credential, for `.pub` / authorized_keys).
pub fn encode_sk_public(key: &crate::crypto::sk::SkPublicKey, comment: &str) -> String {
    let b64 = BASE64_STANDARD.encode(key.to_blob());
    let algo = crate::crypto::sk::SK_ALGO;
    if comment.is_empty() {
        format!("{algo} {b64}\n")
    } else {
        format!("{algo} {b64} {comment}\n")
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

/// Decode one authorized-key line as a [`UserKey`]: a plain Ed25519 key or a
/// FIDO2 security-key credential (`sk-ssh-ed25519@openssh.com`).
pub fn decode_user_key(line: &str) -> Result<crate::crypto::userkey::UserKey> {
    let mut parts = line.split_whitespace();
    let _algo = parts.next().ok_or_else(|| bad("empty public key line"))?;
    let b64 = parts.next().ok_or_else(|| bad("missing key material"))?;
    let blob = BASE64_STANDARD
        .decode(b64)
        .map_err(|e| bad(format!("base64: {e}")))?;
    crate::crypto::userkey::UserKey::from_blob(&blob)
}

/// Parse an authorized_keys file into [`UserKey`]s — Ed25519 and security-key
/// lines both count; anything else is skipped.
pub fn parse_authorized_user_keys(text: &str) -> Vec<crate::crypto::userkey::UserKey> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| decode_user_key(l).ok())
        .collect()
}

// -------------------------------------------------------- certificates --

/// Parse a certificate line (`ssh-ed25519-cert-v01@openssh.com AAAA... id`,
/// or the `sk-ssh-ed25519-cert-v01@openssh.com` security-key form) and return
/// the raw certificate blob. The signature is *not* verified here — that
/// happens where the cert is used.
pub fn decode_cert(line: &str) -> Result<Vec<u8>> {
    let mut parts = line.split_whitespace();
    let algo = parts.next().ok_or_else(|| bad("empty certificate line"))?;
    if algo != super::cert::CERT_ALGO && algo != super::cert::SK_CERT_ALGO {
        return Err(bad(format!("not an Ed25519 certificate: {algo:?}")));
    }
    let b64 = parts.next().ok_or_else(|| bad("missing certificate blob"))?;
    BASE64_STANDARD
        .decode(b64)
        .map_err(|e| bad(format!("base64: {e}")))
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

/// The bare hostname of a known_hosts host pattern: strips a `[host]:port`
/// wrapper or a trailing `:port`, leaving `host`.
fn label_host(pattern: &str) -> &str {
    if let Some(inner) = pattern.strip_prefix('[').and_then(|s| s.split_once(']')) {
        return inner.0;
    }
    match pattern.rsplit_once(':') {
        Some((h, _)) => h,
        None => pattern,
    }
}

/// Every recorded Ed25519 host key for `host` in known_hosts, matching on the
/// bare hostname so `[host]:port` and `host` entries both count. Used to fill
/// in a destination constraint's allowed host keys.
pub fn known_hosts_keys_for(text: &str, host: &str) -> Vec<PublicKey> {
    let mut out = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
            continue;
        }
        let Some((hosts, rest)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if hosts.split(',').any(|h| label_host(h) == host) {
            if let Ok((key, _)) = decode_public(rest.trim_start()) {
                out.push(key);
            }
        }
    }
    out
}

/// Collect the trusted host-certificate CA keys from `@cert-authority` lines
/// in known_hosts. The host pattern is not matched (we trust the CA for any
/// host it certifies); only Ed25519 CA keys are returned.
pub fn known_hosts_cert_authorities(text: &str) -> Vec<PublicKey> {
    text.lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("@cert-authority"))
        .filter_map(|rest| {
            // `<host-pattern> ssh-ed25519 AAAA... comment`
            let rest = rest.trim_start();
            let (_pattern, keypart) = rest.split_once(char::is_whitespace)?;
            decode_public(keypart.trim_start()).ok().map(|(k, _)| k)
        })
        .collect()
}

/// Match a known_hosts host pattern against a hostname, honoring `*`/`?`
/// wildcards (comma-separated alternatives are the caller's business).
///
/// Iterative two-pointer matching (the same shape OpenSSH's own
/// `match_pattern` uses), not naive recursive backtracking on `*`: a pattern
/// with many wildcards against a long non-matching host is O(pattern · host)
/// here, not exponential. Host patterns come from a local `known_hosts`
/// file, so a crafted or attacker-appended line — including one consulted
/// for agent destination-constraints — can no longer hang the process.
fn host_pattern_matches(pattern: &str, host: &str) -> bool {
    let p = label_host(pattern).as_bytes();
    let h = host.as_bytes();

    let (mut pi, mut hi) = (0usize, 0usize);
    // The most recent `*` seen, and the host position matching resumed from
    // last time we backtracked to it (advanced by one on each retry).
    let mut star: Option<(usize, usize)> = None;

    while hi < h.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == h[hi]) {
            pi += 1;
            hi += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, hi));
            pi += 1;
        } else if let Some((star_pi, star_hi)) = star {
            let retry_from = star_hi + 1;
            pi = star_pi + 1;
            hi = retry_from;
            star = Some((star_pi, retry_from));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&b| b == b'*')
}

/// Destination-constraint key entries for `host`: every plain host key
/// (`is_ca = false`) recorded for it, plus every `@cert-authority` CA key
/// whose pattern matches it (`is_ca = true`). The CA entries let a constraint
/// name a whole certificate authority instead of one host key.
pub fn known_hosts_constraint_keys(text: &str, host: &str) -> Vec<(PublicKey, bool)> {
    let mut out = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("@cert-authority") {
            let rest = rest.trim_start();
            let Some((pattern, keypart)) = rest.split_once(char::is_whitespace) else {
                continue;
            };
            if pattern.split(',').any(|p| host_pattern_matches(p, host)) {
                if let Ok((key, _)) = decode_public(keypart.trim_start()) {
                    out.push((key, true));
                }
            }
            continue;
        }
        if line.starts_with('@') {
            continue; // other markers (e.g. @revoked) are not ours to use
        }
        let Some((hosts, rest)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if hosts.split(',').any(|h| host_pattern_matches(h, host)) {
            if let Ok((key, _)) = decode_public(rest.trim_start()) {
                out.push((key, false));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_pattern_matching_semantics() {
        assert!(host_pattern_matches("example.com", "example.com"));
        assert!(!host_pattern_matches("example.com", "example.org"));

        // `*` matches zero or more characters, anywhere in the pattern.
        assert!(host_pattern_matches("*.example.com", "gw.example.com"));
        assert!(host_pattern_matches("*.example.com", "a.b.example.com"));
        assert!(!host_pattern_matches("*.example.com", "example.com"));
        assert!(host_pattern_matches("*", "anything.at.all"));
        assert!(host_pattern_matches("*", ""));
        assert!(host_pattern_matches("host*", "host"));
        assert!(host_pattern_matches("*a*b*c*", "xaxbxcx"));
        assert!(!host_pattern_matches("*a*b*c*", "xbxax")); // wrong order

        // `?` matches exactly one character.
        assert!(host_pattern_matches("host?", "host1"));
        assert!(!host_pattern_matches("host?", "host"));
        assert!(!host_pattern_matches("host?", "host12"));

        // `[host]:port` and bare `host:port` patterns match on the bare host.
        assert!(host_pattern_matches("[gw]:2222", "gw"));
        assert!(host_pattern_matches("gw:2222", "gw"));

        // Empty host only matches an all-`*` (or empty) pattern.
        assert!(!host_pattern_matches("a*", ""));
        assert!(host_pattern_matches("", ""));
        assert!(!host_pattern_matches("a", ""));
    }

    /// The matcher used to be naive recursive backtracking on `*`, which is
    /// exponential for a pattern with many wildcards against a long
    /// non-matching host — exactly the shape below. The iterative two-pointer
    /// rewrite is O(pattern · host); this should return well under a second
    /// even though the equivalent recursive call count would have been
    /// astronomical.
    #[test]
    fn host_pattern_matching_does_not_blow_up_on_many_wildcards() {
        let pattern = "*a".repeat(30) + "z"; // many stars, never matches
        let host = "a".repeat(2000); // long, and never contains 'z'
        let start = std::time::Instant::now();
        assert!(!host_pattern_matches(&pattern, &host));
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "pattern matching took too long: {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn private_roundtrip() {
        let key = PrivateKey::generate();
        let text = encode_private(&key, "test@shh");
        assert!(!needs_passphrase(&text).unwrap());
        let (back, comment) = decode_private(&text).unwrap();
        assert_eq!(back.0.to_bytes(), key.0.to_bytes());
        assert_eq!(comment, "test@shh");
    }

    #[test]
    fn encrypted_roundtrip_and_wrong_passphrase() {
        let key = PrivateKey::generate();
        let text = encode_private_protected(&key, "sealed@shh", Some("hunter2")).unwrap();
        assert!(needs_passphrase(&text).unwrap());
        // no passphrase → clear error
        assert!(decode_private(&text).is_err());
        // wrong passphrase → detected via check bytes
        let err = match decode_private_protected(&text, Some("hunter3")) {
            Err(e) => e,
            Ok(_) => panic!("wrong passphrase must not decode"),
        };
        assert!(err.to_string().contains("wrong passphrase"), "{err}");
        // right passphrase → key back
        let (back, comment) = decode_private_protected(&text, Some("hunter2")).unwrap();
        assert_eq!(back.0.to_bytes(), key.0.to_bytes());
        assert_eq!(comment, "sealed@shh");
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

    #[test]
    fn sk_private_round_trips_plain_and_protected() {
        use crate::crypto::sk::SoftwareKey;
        let key = SoftwareKey::generate("ssh:");

        // Unencrypted.
        let text = encode_sk_private(&key, "yubi@shh", None).unwrap();
        assert!(!needs_passphrase(&text).unwrap());
        match decode_private_identity(&text, None).unwrap() {
            (PrivateIdentity::SecurityKey(k), comment) => {
                assert_eq!(k.public(), key.public());
                assert_eq!(comment, "yubi@shh");
            }
            _ => panic!("expected a security key"),
        }
        // decode_private (Ed25519-only) rejects it clearly.
        assert!(decode_private(&text).is_err());

        // Passphrase-protected: right passphrase opens, wrong one fails.
        let enc = encode_sk_private(&key, "c", Some("hunter2")).unwrap();
        assert!(needs_passphrase(&enc).unwrap());
        assert!(decode_private_identity(&enc, Some("wrong")).is_err());
        match decode_private_identity(&enc, Some("hunter2")).unwrap().0 {
            PrivateIdentity::SecurityKey(k) => assert_eq!(k.public(), key.public()),
            _ => panic!("expected a security key"),
        }
    }

    #[test]
    fn constraint_keys_collect_plain_and_matching_ca() {
        let host_key = PrivateKey::generate().public();
        let ca = PrivateKey::generate().public();
        let other_ca = PrivateKey::generate().public();
        let text = format!(
            "{}@cert-authority *.corp {}@cert-authority other.net {}",
            known_hosts_line("prod.corp", &host_key),
            encode_public(&ca, ""),
            encode_public(&other_ca, ""),
        );
        let got = known_hosts_constraint_keys(&text, "prod.corp");
        // The plain key (is_ca=false) and the *.corp CA (is_ca=true), but not
        // the other.net CA whose pattern does not match.
        assert_eq!(got.len(), 2, "plain key + matching CA");
        assert!(got.iter().any(|(k, ca)| *k == host_key && !ca));
        assert!(got.iter().any(|(k, is_ca)| *k == ca && *is_ca));
        assert!(!got.iter().any(|(k, _)| *k == other_ca));
        // A host the CA pattern also covers, with no plain entry: just the CA.
        let only_ca = known_hosts_constraint_keys(&text, "web.corp");
        assert_eq!(only_ca.len(), 1);
        assert!(only_ca[0].1, "the sole entry is the CA");
    }

    #[test]
    fn known_hosts_keys_for_matches_bare_host() {
        let k1 = PrivateKey::generate().public();
        let k2 = PrivateKey::generate().public();
        let stranger = PrivateKey::generate().public();
        let text = format!(
            "{}{}{}",
            known_hosts_line("[gw]:2222", &k1),
            known_hosts_line("gw", &k2),
            known_hosts_line("elsewhere", &stranger),
        );
        let found = known_hosts_keys_for(&text, "gw");
        assert_eq!(found.len(), 2, "both gw entries, regardless of port");
        assert!(found.contains(&k1) && found.contains(&k2));
        assert!(!found.contains(&stranger));
        assert!(known_hosts_keys_for(&text, "unknown").is_empty());
    }
}
