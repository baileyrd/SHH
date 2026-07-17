//! FIDO2 / U2F security-key credentials: `sk-ssh-ed25519@openssh.com`.
//!
//! A hardware security key holds the Ed25519 private key and never releases
//! it. SSH sees only the public credential — an Ed25519 public key plus an
//! "application" string (the relying-party id, conventionally `ssh:`) — and,
//! per authentication, an *assertion* the authenticator produced when the
//! user touched it.
//!
//! We verify those assertions. That is the half a *server* needs: it lets a
//! user log in with a security key, and it is pure arithmetic — no hardware.
//! Producing assertions requires the physical authenticator and is a
//! client-side concern (`ssh -i id_ed25519_sk` on a machine with the key);
//! that path is not implemented here.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::wire::{Reader, Writer};
use crate::{Error, Result};

pub const SK_ALGO: &str = "sk-ssh-ed25519@openssh.com";

/// User-presence flag: the authenticator asserts the user physically touched
/// it. We insist on it — unattended use defeats the point of a security key.
const FLAG_USER_PRESENT: u8 = 0x01;

/// A security-key public credential: an Ed25519 public key and the
/// application string it is scoped to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkPublicKey {
    key: VerifyingKey,
    application: String,
}

impl SkPublicKey {
    /// Build a credential from the raw Ed25519 public key and its application
    /// string (e.g. `ssh:`). Mainly useful for tooling and tests; real
    /// credentials arrive over the wire and are parsed with [`from_blob`].
    ///
    /// [`from_blob`]: Self::from_blob
    pub fn new(ed25519_public: [u8; 32], application: &str) -> Result<Self> {
        let key = VerifyingKey::from_bytes(&ed25519_public)
            .map_err(|_| Error::Crypto("bad ed25519 point"))?;
        Ok(SkPublicKey {
            key,
            application: application.to_owned(),
        })
    }

    /// Parse `string algo ‖ string enc_A ‖ string application`.
    pub fn from_blob(blob: &[u8]) -> Result<Self> {
        let mut r = Reader::new(blob);
        if r.utf8()? != SK_ALGO {
            return Err(Error::proto("not an sk-ssh-ed25519 key"));
        }
        let raw: [u8; 32] = r
            .string()?
            .try_into()
            .map_err(|_| Error::proto("sk ed25519 key must be 32 bytes"))?;
        let application = r.utf8()?.to_owned();
        r.finish()?;
        let key = VerifyingKey::from_bytes(&raw).map_err(|_| Error::Crypto("bad ed25519 point"))?;
        Ok(SkPublicKey { key, application })
    }

    pub fn to_blob(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.utf8(SK_ALGO);
        w.string(self.key.as_bytes());
        w.utf8(&self.application);
        w.into_bytes()
    }

    /// The raw 32-byte Ed25519 public key (`enc_A`).
    pub fn ed25519_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    /// The application (relying-party) string this credential is scoped to.
    pub fn application(&self) -> &str {
        &self.application
    }

    pub fn fingerprint(&self) -> String {
        use base64::prelude::{Engine as _, BASE64_STANDARD_NO_PAD};
        format!(
            "SHA256:{}",
            BASE64_STANDARD_NO_PAD.encode(Sha256::digest(self.to_blob()))
        )
    }

    /// Verify a security-key assertion over `message`.
    ///
    /// The signature blob is `string algo ‖ string sig ‖ byte flags ‖
    /// u32 counter`. The authenticator actually signed `SHA256(application)
    /// ‖ flags ‖ counter ‖ SHA256(message)`, so we rebuild that and check the
    /// Ed25519 signature — after insisting the user-presence flag is set.
    pub fn verify(&self, message: &[u8], sig_blob: &[u8]) -> Result<()> {
        let mut r = Reader::new(sig_blob);
        if r.utf8()? != SK_ALGO {
            return Err(Error::proto("not an sk-ssh-ed25519 signature"));
        }
        let raw: [u8; 64] = r
            .string()?
            .try_into()
            .map_err(|_| Error::proto("sk signature must be 64 bytes"))?;
        let flags = r.byte()?;
        let counter = r.u32()?;
        r.finish()?;

        if flags & FLAG_USER_PRESENT == 0 {
            return Err(Error::Auth("security key did not assert user presence".into()));
        }

        let signed = authenticator_data(&self.application, flags, counter, message);
        self.key
            .verify(&signed, &Signature::from_bytes(&raw))
            .map_err(|_| Error::Crypto("sk signature verification failed"))
    }
}

/// The exact bytes a FIDO2 authenticator signs for an SSH assertion:
/// `SHA256(application) ‖ flags ‖ counter ‖ SHA256(message)`.
fn authenticator_data(application: &str, flags: u8, counter: u32, message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 1 + 4 + 32);
    out.extend_from_slice(&Sha256::digest(application.as_bytes()));
    out.push(flags);
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(&Sha256::digest(message));
    out
}

/// A **software-emulated** security key: it holds the Ed25519 seed itself and
/// produces assertions the way a hardware token would.
///
/// This has none of the protection a real authenticator gives — the secret
/// lives in a file, not a tamper-resistant chip — so it is a convenience for
/// testing, CI, and environments without a token, *not* a substitute for
/// hardware. Assertions it produces are cryptographically ordinary and are
/// accepted by any `sk-ssh-ed25519` verifier (SHH's or OpenSSH's); the honest
/// difference is only where the key is kept. Real hardware belongs behind an
/// external authenticator helper.
#[derive(Clone)]
pub struct SoftwareKey {
    signing: ed25519_dalek::SigningKey,
    application: String,
}

impl SoftwareKey {
    pub fn generate(application: &str) -> Self {
        SoftwareKey {
            signing: ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng),
            application: application.to_owned(),
        }
    }

    /// Rebuild from the 32-byte seed and application (as loaded from a file).
    pub fn from_seed(seed: [u8; 32], application: &str) -> Self {
        SoftwareKey {
            signing: ed25519_dalek::SigningKey::from_bytes(&seed),
            application: application.to_owned(),
        }
    }

    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    pub fn application(&self) -> &str {
        &self.application
    }

    /// The raw 32-byte Ed25519 public key (`enc_A`), for the key-file blob.
    pub fn verifying_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn public(&self) -> SkPublicKey {
        SkPublicKey {
            key: self.signing.verifying_key(),
            application: self.application.clone(),
        }
    }

    /// Produce an assertion over `message`. `user_present` sets the
    /// user-presence flag; the CLI sets it only after confirming presence.
    /// The counter is fixed at 0 — a stateless software key cannot maintain a
    /// monotonic one, and servers do not require it.
    pub fn sign(&self, message: &[u8], user_present: bool) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let flags = if user_present { FLAG_USER_PRESENT } else { 0 };
        let counter = 0u32;
        let signed = authenticator_data(&self.application, flags, counter, message);
        let sig = self.signing.sign(&signed);
        let mut w = Writer::new();
        w.utf8(SK_ALGO);
        w.string(&sig.to_bytes());
        w.byte(flags);
        w.u32(counter);
        w.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assertion_round_trips() {
        let auth = SoftwareKey::generate("ssh:");
        let pk = auth.public();

        // The public credential survives a blob round trip.
        let reparsed = SkPublicKey::from_blob(&pk.to_blob()).unwrap();
        assert_eq!(reparsed, pk);

        // Touched assertions over distinct messages verify.
        let sig1 = auth.sign(b"first message", true);
        pk.verify(b"first message", &sig1).unwrap();
        let sig2 = auth.sign(b"second message", true);
        pk.verify(b"second message", &sig2).unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn seed_round_trips() {
        let key = SoftwareKey::generate("ssh:");
        let same = SoftwareKey::from_seed(*key.seed(), key.application());
        assert_eq!(same.public(), key.public());
    }

    #[test]
    fn wrong_message_or_key_is_rejected() {
        let auth = SoftwareKey::generate("ssh:");
        let pk = auth.public();
        let sig = auth.sign(b"the message", true);
        assert!(pk.verify(b"a different message", &sig).is_err());

        let other = SoftwareKey::generate("ssh:").public();
        assert!(other.verify(b"the message", &sig).is_err());
    }

    #[test]
    fn untouched_assertion_is_refused() {
        // No user-presence flag: the server must reject it even though the
        // Ed25519 math is valid.
        let auth = SoftwareKey::generate("ssh:");
        let pk = auth.public();
        let sig = auth.sign(b"m", false);
        assert!(pk.verify(b"m", &sig).is_err());
    }

    #[test]
    fn application_is_bound() {
        // Two credentials with the same key but different applications must
        // not verify each other's assertions (the app is hashed into the
        // signed data).
        let a = SoftwareKey::generate("ssh:");
        let b = SoftwareKey::from_seed(*a.seed(), "ssh:other");
        let sig = b.sign(b"m", true);
        assert!(a.public().verify(b"m", &sig).is_err());
    }
}
