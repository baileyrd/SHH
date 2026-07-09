//! OpenSSH Ed25519 user certificates (`ssh-ed25519-cert-v01@openssh.com`).
//!
//! A certificate is a CA signature over a user's public key plus a policy:
//! a validity window and a set of principals (login names). Trusting one CA
//! key replaces per-key `authorized_keys` churn — the modern way to run SSH
//! at more than one host.
//!
//! We implement *user* certificates only, and we fail closed: any critical
//! option we don't understand rejects the certificate. Host certificates,
//! `force-command`, and `source-address` are deliberately not honored yet.

use ed25519_dalek::VerifyingKey;
use rand_core::{OsRng, RngCore};

use super::ed25519::{PrivateKey, PublicKey};
use super::sk::SkPublicKey;
use super::userkey::UserKey;
use crate::wire::{Reader, Writer};
use crate::{Error, Result};

pub const CERT_ALGO: &str = "ssh-ed25519-cert-v01@openssh.com";
/// The certificate form of a FIDO2 security key. Identical to `CERT_ALGO`
/// except for the type string and an extra `application` field after the key.
pub const SK_CERT_ALGO: &str = "sk-ssh-ed25519-cert-v01@openssh.com";
pub const CERT_TYPE_USER: u32 = 1;
pub const CERT_TYPE_HOST: u32 = 2;

/// The standard "permit-*" extensions OpenSSH puts on a user cert. We don't
/// enforce them, but including them keeps our certs usable by OpenSSH sshd
/// (e.g. it won't grant a pty without `permit-pty`).
const DEFAULT_EXTENSIONS: &[&str] = &[
    "permit-X11-forwarding",
    "permit-agent-forwarding",
    "permit-port-forwarding",
    "permit-pty",
    "permit-user-rc",
];

/// A parsed, CA-signature-verified certificate. Construct only via
/// [`Certificate::parse_and_verify`], so a `Certificate` always has a good
/// signature from *some* CA (whether that CA is trusted is a later check).
#[derive(Clone)]
pub struct Certificate {
    /// The certified key — for a security-key certificate, the Ed25519 point
    /// it is built on; combine with [`sk_application`] via
    /// [`certified_user_key`] to get the credential proper.
    ///
    /// [`sk_application`]: Self::sk_application
    /// [`certified_user_key`]: Self::certified_user_key
    pub key: PublicKey,
    /// `Some(application)` when this certifies a FIDO2 security key
    /// (`sk-ssh-ed25519-cert-v01`); `None` for a plain Ed25519 certificate.
    pub sk_application: Option<String>,
    pub serial: u64,
    pub cert_type: u32,
    pub key_id: String,
    /// Login names this cert is valid for; empty means "any principal".
    pub principals: Vec<String>,
    pub valid_after: u64,
    pub valid_before: u64,
    /// The CA whose signature was verified.
    pub ca_key: PublicKey,
    /// The full certificate blob, for re-presentation in userauth.
    blob: Vec<u8>,
}

/// Read a packed list of SSH strings (principals, option names).
fn read_string_list(bytes: &[u8]) -> Result<Vec<String>> {
    let mut r = Reader::new(bytes);
    let mut out = Vec::new();
    while r.remaining() > 0 {
        out.push(r.utf8()?.to_owned());
    }
    Ok(out)
}

/// Pack principals into the inner bytes of the "valid principals" string.
fn pack_string_list(items: &[String]) -> Vec<u8> {
    let mut w = Writer::new();
    for item in items {
        w.utf8(item);
    }
    w.into_bytes()
}

fn read_ed25519_point(raw: &[u8]) -> Result<PublicKey> {
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| Error::proto("cert key must be 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&raw).map_err(|_| Error::Crypto("bad ed25519 point"))?;
    Ok(PublicKey(key))
}

impl Certificate {
    /// Parse a certificate blob and verify the CA's signature over it. The
    /// returned certificate still needs trust, validity, principal, and type
    /// checks (see the `check_*` / `permits_*` methods).
    pub fn parse_and_verify(blob: &[u8]) -> Result<Certificate> {
        let mut r = Reader::new(blob);
        let is_sk = match r.utf8()? {
            CERT_ALGO => false,
            SK_CERT_ALGO => true,
            _ => return Err(Error::proto("not an ssh-ed25519 certificate")),
        };
        let _nonce = r.string()?;
        let key = read_ed25519_point(r.string()?)?;
        // A security-key certificate carries the application right after the
        // key; a plain one does not.
        let sk_application = if is_sk {
            Some(r.utf8()?.to_owned())
        } else {
            None
        };
        let serial = r.u64()?;
        let cert_type = r.u32()?;
        let key_id = r.utf8()?.to_owned();
        let principals = read_string_list(r.string()?)?;
        let valid_after = r.u64()?;
        let valid_before = r.u64()?;
        let critical = r.string()?.to_vec();
        let _extensions = r.string()?;
        let _reserved = r.string()?;
        let sig_key_blob = r.string()?.to_vec();
        // Everything up to here is what the CA signed.
        let signed_len = blob.len() - r.remaining();
        let signature = r.string()?.to_vec();
        r.finish()?;

        // Fail closed on any critical option we don't implement.
        if !critical.is_empty() {
            let names = read_string_list(&critical).unwrap_or_default();
            return Err(Error::Auth(format!(
                "certificate carries unsupported critical option(s): {}",
                names.join(", ")
            )));
        }

        let ca_key = PublicKey::from_blob(&sig_key_blob)?;
        ca_key
            .verify(&blob[..signed_len], &signature)
            .map_err(|_| Error::Auth("certificate signature is invalid".into()))?;

        Ok(Certificate {
            key,
            sk_application,
            serial,
            cert_type,
            key_id,
            principals,
            valid_after,
            valid_before,
            ca_key,
            blob: blob.to_vec(),
        })
    }

    pub fn blob(&self) -> &[u8] {
        &self.blob
    }

    /// The certified key as a [`UserKey`]: a security key when this is an
    /// `sk-ssh-ed25519-cert-v01`, otherwise a plain Ed25519 key. This is the
    /// key a userauth signature must verify against.
    pub fn certified_user_key(&self) -> UserKey {
        match &self.sk_application {
            Some(app) => UserKey::Sk(
                SkPublicKey::new(self.key.0.to_bytes(), app)
                    .expect("certified point already validated"),
            ),
            None => UserKey::Ed25519(self.key.clone()),
        }
    }

    /// Is `now` (seconds since the Unix epoch) within the validity window?
    pub fn valid_at(&self, now: u64) -> bool {
        now >= self.valid_after && now <= self.valid_before
    }

    /// Does this cert authorize logging in as `principal`? An empty
    /// principal list means "any" (OpenSSH semantics).
    pub fn permits_principal(&self, principal: &str) -> bool {
        self.principals.is_empty() || self.principals.iter().any(|p| p == principal)
    }
}

/// The current time in seconds since the Unix epoch (for validity checks).
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Sign a user certificate for `user_key` with certificate authority `ca`.
#[allow(clippy::too_many_arguments)]
pub fn sign_user_cert(
    ca: &PrivateKey,
    user_key: &PublicKey,
    serial: u64,
    key_id: &str,
    principals: &[String],
    valid_after: u64,
    valid_before: u64,
) -> Vec<u8> {
    sign_cert(ca, user_key.0.as_bytes(), None, CERT_TYPE_USER, serial, key_id, principals, valid_after, valid_before)
}

/// Sign a host certificate for `host_key`. The principals are hostnames.
#[allow(clippy::too_many_arguments)]
pub fn sign_host_cert(
    ca: &PrivateKey,
    host_key: &PublicKey,
    serial: u64,
    key_id: &str,
    principals: &[String],
    valid_after: u64,
    valid_before: u64,
) -> Vec<u8> {
    sign_cert(ca, host_key.0.as_bytes(), None, CERT_TYPE_HOST, serial, key_id, principals, valid_after, valid_before)
}

/// Sign a user certificate for a FIDO2 security key (`sk_key`).
#[allow(clippy::too_many_arguments)]
pub fn sign_sk_user_cert(
    ca: &PrivateKey,
    sk_key: &SkPublicKey,
    serial: u64,
    key_id: &str,
    principals: &[String],
    valid_after: u64,
    valid_before: u64,
) -> Vec<u8> {
    sign_cert(
        ca,
        &sk_key.ed25519_bytes(),
        Some(sk_key.application()),
        CERT_TYPE_USER,
        serial,
        key_id,
        principals,
        valid_after,
        valid_before,
    )
}

#[allow(clippy::too_many_arguments)]
fn sign_cert(
    ca: &PrivateKey,
    key_point: &[u8],
    sk_application: Option<&str>,
    cert_type: u32,
    serial: u64,
    key_id: &str,
    principals: &[String],
    valid_after: u64,
    valid_before: u64,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.utf8(if sk_application.is_some() {
        SK_CERT_ALGO
    } else {
        CERT_ALGO
    });
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    w.string(&nonce);
    w.string(key_point);
    if let Some(app) = sk_application {
        w.utf8(app); // the sk application follows the key
    }
    w.u64(serial);
    w.u32(cert_type);
    w.utf8(key_id);
    w.string(&pack_string_list(principals));
    w.u64(valid_after);
    w.u64(valid_before);
    w.string(b""); // critical options: none
    // The permit-* extensions apply to user certs only; host certs carry none.
    let mut ext = Writer::new();
    if cert_type == CERT_TYPE_USER {
        for name in DEFAULT_EXTENSIONS {
            ext.utf8(name);
            ext.string(b""); // extension data: empty
        }
    }
    w.string(&ext.into_bytes());
    w.string(b""); // reserved
    w.string(&ca.public().to_blob());

    let body = w.into_bytes();
    let sig = ca.sign(&body);
    let mut w = Writer::new();
    w.string(&sig);
    let mut out = body;
    out.extend_from_slice(&w.into_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_cert(principals: &[&str], after: u64, before: u64) -> (PrivateKey, PrivateKey, Vec<u8>) {
        let ca = PrivateKey::generate();
        let user = PrivateKey::generate();
        let principals: Vec<String> = principals.iter().map(|s| s.to_string()).collect();
        let blob = sign_user_cert(&ca, &user.public(), 7, "id@test", &principals, after, before);
        (ca, user, blob)
    }

    #[test]
    fn sign_parse_verify_roundtrip() {
        let (ca, user, blob) = user_cert(&["river", "tester"], 0, u64::MAX);
        let cert = Certificate::parse_and_verify(&blob).unwrap();
        assert_eq!(cert.key, user.public());
        assert_eq!(cert.ca_key, ca.public());
        assert_eq!(cert.cert_type, CERT_TYPE_USER);
        assert_eq!(cert.key_id, "id@test");
        assert_eq!(cert.serial, 7);
        assert!(cert.permits_principal("river"));
        assert!(cert.permits_principal("tester"));
        assert!(!cert.permits_principal("mallory"));
        assert!(cert.valid_at(1_000_000));
    }

    #[test]
    fn empty_principals_permits_any() {
        let (_ca, _user, blob) = user_cert(&[], 0, u64::MAX);
        let cert = Certificate::parse_and_verify(&blob).unwrap();
        assert!(cert.permits_principal("anyone"));
    }

    #[test]
    fn validity_window_enforced() {
        let (_ca, _user, blob) = user_cert(&["x"], 100, 200);
        let cert = Certificate::parse_and_verify(&blob).unwrap();
        assert!(!cert.valid_at(99));
        assert!(cert.valid_at(100));
        assert!(cert.valid_at(200));
        assert!(!cert.valid_at(201));
    }

    #[test]
    fn tampered_signature_rejected() {
        let (_ca, _user, mut blob) = user_cert(&["x"], 0, u64::MAX);
        // Flip a bit in the key-id region (well before the signature).
        let mid = blob.len() / 3;
        blob[mid] ^= 0x40;
        assert!(Certificate::parse_and_verify(&blob).is_err());
    }

    #[test]
    fn foreign_algorithm_rejected() {
        let mut w = Writer::new();
        w.utf8("ssh-rsa-cert-v01@openssh.com");
        assert!(Certificate::parse_and_verify(&w.into_bytes()).is_err());
    }

    // ------------------------------------------ security-key certificates ---

    #[test]
    fn sk_cert_roundtrip_carries_application() {
        use crate::crypto::sk::SoftwareKey;
        let ca = PrivateKey::generate();
        let sk = SoftwareKey::generate("ssh:").public();
        let blob = sign_sk_user_cert(&ca, &sk, 3, "sk@test", &["river".into()], 0, u64::MAX);

        let cert = Certificate::parse_and_verify(&blob).unwrap();
        // The extra application string is parsed and preserved…
        assert_eq!(cert.sk_application.as_deref(), Some("ssh:"));
        assert_eq!(cert.ca_key, ca.public());
        assert_eq!(cert.cert_type, CERT_TYPE_USER);
        assert!(cert.permits_principal("river"));
        // …and the certified key is the security-key credential, not a bare
        // Ed25519 point.
        match cert.certified_user_key() {
            UserKey::Sk(pk) => assert_eq!(pk, sk),
            other => panic!("expected an sk credential, got {other:?}"),
        }
    }

    #[test]
    fn sk_cert_verifies_a_touched_assertion() {
        // An end-to-end check that the certified sk key verifies an assertion
        // the way the auth path will: sign a message with the software key,
        // then verify it against the key the certificate certifies.
        use crate::crypto::sk::SoftwareKey;
        let ca = PrivateKey::generate();
        let dev = SoftwareKey::generate("ssh:");
        let blob = sign_sk_user_cert(&ca, &dev.public(), 1, "id", &[], 0, u64::MAX);

        let cert = Certificate::parse_and_verify(&blob).unwrap();
        let key = cert.certified_user_key();
        let sig = dev.sign(b"the challenge", true);
        key.verify(b"the challenge", &sig).unwrap();
        // A different key's assertion does not verify against this cert.
        let other = SoftwareKey::generate("ssh:").sign(b"the challenge", true);
        assert!(key.verify(b"the challenge", &other).is_err());
    }

    #[test]
    fn plain_cert_has_no_application() {
        let (_ca, _user, blob) = user_cert(&["x"], 0, u64::MAX);
        let cert = Certificate::parse_and_verify(&blob).unwrap();
        assert!(cert.sk_application.is_none());
        assert!(matches!(cert.certified_user_key(), UserKey::Ed25519(_)));
    }
}
