//! OpenSSH Ed25519 user certificates (`ssh-ed25519-cert-v01@openssh.com`).
//!
//! A certificate is a CA signature over a user's public key plus a policy:
//! a validity window and a set of principals (login names). Trusting one CA
//! key replaces per-key `authorized_keys` churn — the modern way to run SSH
//! at more than one host.
//!
//! We implement *user* certificates only, and we fail closed: any critical
//! option we don't understand rejects the certificate. Two critical options
//! *are* honored — `force-command` (the session runs this command whatever
//! the client asked for) and `source-address` (the cert is refused from a
//! client IP outside the listed CIDR ranges). Host certificates are not.

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
    /// `force-command` critical option: when set, the server runs this
    /// command instead of whatever the client requested (exec or shell).
    pub force_command: Option<String>,
    /// `source-address` critical option: a comma-separated CIDR list the
    /// client's address must fall within, or the cert is refused.
    pub source_address: Option<String>,
    /// The CA whose signature was verified.
    pub ca_key: PublicKey,
    /// The full certificate blob, for re-presentation in userauth.
    blob: Vec<u8>,
}

/// The critical options a signer can put on a user certificate. Both are
/// `None` by default; see [`Certificate::force_command`] and
/// [`Certificate::source_address`] for what they mean at the server.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CertOptions {
    pub force_command: Option<String>,
    pub source_address: Option<String>,
}

/// Parse the certificate's critical-options buffer. Each entry is
/// `string name ‖ string data`, where `data` wraps a single SSH string value.
/// We recognize `force-command` and `source-address`; any other name rejects
/// the certificate (fail-closed). OpenSSH requires the names to be strictly
/// ascending and unique, and so do we.
fn parse_critical_options(bytes: &[u8]) -> Result<(Option<String>, Option<String>)> {
    let mut r = Reader::new(bytes);
    let mut force_command = None;
    let mut source_address = None;
    let mut last: Option<String> = None;
    while r.remaining() > 0 {
        let name = r.utf8()?.to_owned();
        if let Some(prev) = &last {
            if name.as_str() <= prev.as_str() {
                return Err(Error::Auth(
                    "certificate critical options are not sorted and unique".into(),
                ));
            }
        }
        let data = r.string()?;
        // Reject unknown options by name before interpreting their data, so a
        // valueless unknown option still fails as "unsupported", not "malformed".
        match name.as_str() {
            "force-command" => force_command = Some(read_option_value(data)?),
            "source-address" => source_address = Some(read_option_value(data)?),
            other => {
                return Err(Error::Auth(format!(
                    "certificate carries unsupported critical option: {other}"
                )))
            }
        }
        last = Some(name);
    }
    Ok((force_command, source_address))
}

/// A known critical option's value is a single SSH string nested inside its
/// data buffer (and nothing more).
fn read_option_value(data: &[u8]) -> Result<String> {
    let mut r = Reader::new(data);
    let value = r.utf8()?.to_owned();
    r.finish()?;
    Ok(value)
}

/// Does `ip` satisfy an OpenSSH-style `source-address` CIDR list? Entries are
/// comma-separated `addr` or `addr/bits`, optionally negated with a leading
/// `!`. A negated match denies outright; otherwise the address must match at
/// least one positive entry — mirroring OpenSSH's `addr_match_cidr_list`.
pub fn source_address_permits(list: &str, ip: std::net::IpAddr) -> bool {
    // Fold an IPv4-mapped IPv6 address back to plain IPv4 so a v4 CIDR still
    // matches a peer that arrived on a dual-stack socket.
    let ip = ip.to_canonical();
    let mut matched = false;
    for raw in list.split(',') {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        let (negated, spec) = match entry.strip_prefix('!') {
            Some(rest) => (true, rest.trim()),
            None => (false, entry),
        };
        if cidr_contains(spec, ip) {
            if negated {
                return false;
            }
            matched = true;
        }
    }
    matched
}

/// Is `ip` inside the single CIDR (or bare address) `spec`? A malformed spec
/// or a family mismatch (v4 spec vs v6 peer) simply does not match.
fn cidr_contains(spec: &str, ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    let (addr_str, bits) = match spec.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (spec, None),
    };
    match (addr_str.parse::<IpAddr>(), ip) {
        (Ok(IpAddr::V4(net)), IpAddr::V4(ip)) => {
            let bits = match bits {
                Some(b) => match b.parse::<u32>() {
                    Ok(n) if n <= 32 => n,
                    _ => return false,
                },
                None => 32,
            };
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            (u32::from(net) & mask) == (u32::from(ip) & mask)
        }
        (Ok(IpAddr::V6(net)), IpAddr::V6(ip)) => {
            let bits = match bits {
                Some(b) => match b.parse::<u32>() {
                    Ok(n) if n <= 128 => n,
                    _ => return false,
                },
                None => 128,
            };
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            (u128::from(net) & mask) == (u128::from(ip) & mask)
        }
        _ => false,
    }
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

        let ca_key = PublicKey::from_blob(&sig_key_blob)?;
        ca_key
            .verify(&blob[..signed_len], &signature)
            .map_err(|_| Error::Auth("certificate signature is invalid".into()))?;

        // Only interpret the (CA-signed) critical options now the signature
        // has checked out. Known options are captured; any other rejects the
        // cert (fail-closed).
        let (force_command, source_address) = parse_critical_options(&critical)?;

        Ok(Certificate {
            key,
            sk_application,
            serial,
            cert_type,
            key_id,
            principals,
            valid_after,
            valid_before,
            force_command,
            source_address,
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
    /// `valid_before` is exclusive, matching OpenSSH (`valid_after <= now <
    /// valid_before`), so a cert is not honored for the extra second at its
    /// stated expiry.
    pub fn valid_at(&self, now: u64) -> bool {
        now >= self.valid_after && now < self.valid_before
    }

    /// Does this cert authorize logging in as `principal`? An empty
    /// principal list means "any" (OpenSSH semantics).
    pub fn permits_principal(&self, principal: &str) -> bool {
        self.principals.is_empty() || self.principals.iter().any(|p| p == principal)
    }

    /// Does this cert's `source-address` option (if any) admit a client at
    /// `peer`? A cert without the option admits anyone; a cert *with* it
    /// needs a known peer address inside its ranges — an unknown address
    /// (`None`) is refused rather than waved through.
    pub fn permits_source(&self, peer: Option<std::net::IpAddr>) -> bool {
        match &self.source_address {
            None => true,
            Some(list) => match peer {
                Some(ip) => source_address_permits(list, ip),
                None => false,
            },
        }
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
    sign_user_cert_with(ca, user_key, &CertOptions::default(), serial, key_id, principals, valid_after, valid_before)
}

/// Sign a user certificate carrying critical options (`force-command` /
/// `source-address`).
#[allow(clippy::too_many_arguments)]
pub fn sign_user_cert_with(
    ca: &PrivateKey,
    user_key: &PublicKey,
    options: &CertOptions,
    serial: u64,
    key_id: &str,
    principals: &[String],
    valid_after: u64,
    valid_before: u64,
) -> Vec<u8> {
    sign_cert(ca, user_key.0.as_bytes(), None, CERT_TYPE_USER, options, serial, key_id, principals, valid_after, valid_before)
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
    sign_cert(ca, host_key.0.as_bytes(), None, CERT_TYPE_HOST, &CertOptions::default(), serial, key_id, principals, valid_after, valid_before)
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
    sign_sk_user_cert_with(ca, sk_key, &CertOptions::default(), serial, key_id, principals, valid_after, valid_before)
}

/// Sign a security-key user certificate carrying critical options.
#[allow(clippy::too_many_arguments)]
pub fn sign_sk_user_cert_with(
    ca: &PrivateKey,
    sk_key: &SkPublicKey,
    options: &CertOptions,
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
        options,
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
    options: &CertOptions,
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
    // Critical options, written in ascending name order (force-command <
    // source-address). Each value is an SSH string nested in the data string.
    let mut crit = Writer::new();
    if let Some(cmd) = &options.force_command {
        crit.utf8("force-command");
        let mut d = Writer::new();
        d.utf8(cmd);
        crit.string(&d.into_bytes());
    }
    if let Some(src) = &options.source_address {
        crit.utf8("source-address");
        let mut d = Writer::new();
        d.utf8(src);
        crit.string(&d.into_bytes());
    }
    w.string(&crit.into_bytes());
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
        assert!(cert.valid_at(100)); // valid_after is inclusive
        assert!(cert.valid_at(199));
        assert!(!cert.valid_at(200)); // valid_before is exclusive (OpenSSH)
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

    // ------------------------------------------------ critical options ---

    #[test]
    fn force_command_round_trips() {
        let ca = PrivateKey::generate();
        let user = PrivateKey::generate();
        let opts = CertOptions {
            force_command: Some("/usr/bin/backup --nightly".into()),
            ..Default::default()
        };
        let blob = sign_user_cert_with(&ca, &user.public(), &opts, 1, "id", &["river".into()], 0, u64::MAX);
        let cert = Certificate::parse_and_verify(&blob).unwrap();
        assert_eq!(cert.force_command.as_deref(), Some("/usr/bin/backup --nightly"));
        assert!(cert.source_address.is_none());
    }

    #[test]
    fn source_address_round_trips_and_matches() {
        use std::net::IpAddr;
        let ca = PrivateKey::generate();
        let user = PrivateKey::generate();
        let opts = CertOptions {
            source_address: Some("192.0.2.0/24,203.0.113.5".into()),
            ..Default::default()
        };
        let blob = sign_user_cert_with(&ca, &user.public(), &opts, 1, "id", &[], 0, u64::MAX);
        let cert = Certificate::parse_and_verify(&blob).unwrap();
        assert_eq!(cert.source_address.as_deref(), Some("192.0.2.0/24,203.0.113.5"));

        // Inside the /24, and the exact single host: admitted.
        assert!(cert.permits_source(Some("192.0.2.77".parse::<IpAddr>().unwrap())));
        assert!(cert.permits_source(Some("203.0.113.5".parse::<IpAddr>().unwrap())));
        // Outside every range: refused. Unknown address: refused (fail-closed).
        assert!(!cert.permits_source(Some("198.51.100.1".parse::<IpAddr>().unwrap())));
        assert!(!cert.permits_source(None));
    }

    #[test]
    fn no_source_address_admits_anyone() {
        use std::net::IpAddr;
        let (_ca, _user, blob) = user_cert(&["x"], 0, u64::MAX);
        let cert = Certificate::parse_and_verify(&blob).unwrap();
        assert!(cert.permits_source(Some("10.0.0.1".parse::<IpAddr>().unwrap())));
        assert!(cert.permits_source(None));
    }

    #[test]
    fn source_address_cidr_edges_and_negation() {
        use std::net::IpAddr;
        let v4 = |s: &str| s.parse::<IpAddr>().unwrap();
        // /32 is a single host.
        assert!(source_address_permits("10.1.2.3/32", v4("10.1.2.3")));
        assert!(!source_address_permits("10.1.2.3/32", v4("10.1.2.4")));
        // /0 matches everything.
        assert!(source_address_permits("0.0.0.0/0", v4("8.8.8.8")));
        // A v4 rule never admits a v6 peer.
        assert!(!source_address_permits("10.0.0.0/8", "::1".parse::<IpAddr>().unwrap()));
        // IPv6 prefix matching.
        assert!(source_address_permits("2001:db8::/32", "2001:db8::dead".parse::<IpAddr>().unwrap()));
        assert!(!source_address_permits("2001:db8::/32", "2001:dba::1".parse::<IpAddr>().unwrap()));
        // An IPv4-mapped v6 peer is folded to plain v4 and matches a v4 rule.
        assert!(source_address_permits("192.0.2.0/24", "::ffff:192.0.2.9".parse::<IpAddr>().unwrap()));
        // Negation: in the subnet but explicitly excluded → denied.
        assert!(!source_address_permits("10.0.0.0/8,!10.9.9.9", v4("10.9.9.9")));
        assert!(source_address_permits("10.0.0.0/8,!10.9.9.9", v4("10.1.1.1")));
    }

    #[test]
    fn both_options_present_are_ordered() {
        // force-command sorts before source-address; a cert with both must
        // parse (the parser rejects unsorted/duplicate option names).
        let ca = PrivateKey::generate();
        let user = PrivateKey::generate();
        let opts = CertOptions {
            force_command: Some("id".into()),
            source_address: Some("127.0.0.1/32".into()),
        };
        let blob = sign_user_cert_with(&ca, &user.public(), &opts, 1, "id", &[], 0, u64::MAX);
        let cert = Certificate::parse_and_verify(&blob).unwrap();
        assert_eq!(cert.force_command.as_deref(), Some("id"));
        assert_eq!(cert.source_address.as_deref(), Some("127.0.0.1/32"));
    }

    #[test]
    fn unknown_critical_option_still_rejected() {
        // Hand-build a cert body with an unsupported critical option and a
        // valid CA signature; parse must reject it (fail-closed).
        let ca = PrivateKey::generate();
        let user = PrivateKey::generate();
        let mut w = Writer::new();
        w.utf8(CERT_ALGO);
        w.string(&[0u8; 32]); // nonce
        w.string(user.public().0.as_bytes());
        w.u64(1);
        w.u32(CERT_TYPE_USER);
        w.utf8("id");
        w.string(&pack_string_list(&[]));
        w.u64(0);
        w.u64(u64::MAX);
        let mut crit = Writer::new();
        crit.utf8("verify-required"); // an option we do not implement
        crit.string(b"");
        w.string(&crit.into_bytes());
        w.string(b""); // extensions
        w.string(b""); // reserved
        w.string(&ca.public().to_blob());
        let body = w.into_bytes();
        let sig = ca.sign(&body);
        let mut full = body;
        let mut sw = Writer::new();
        sw.string(&sig);
        full.extend_from_slice(&sw.into_bytes());

        match Certificate::parse_and_verify(&full) {
            Err(e) => assert!(format!("{e}").contains("unsupported critical option")),
            Ok(_) => panic!("expected an unsupported-critical-option error"),
        }
    }
}
