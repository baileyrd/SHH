//! Ed25519 keys and signatures with their SSH wire encodings (RFC 8709).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;

use crate::wire::{Reader, Writer};
use crate::{Error, Result};

pub const ALGO: &str = "ssh-ed25519";

/// A public key, plus helpers for the SSH blob encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(pub VerifyingKey);

impl PublicKey {
    /// Encode as the standard blob: string "ssh-ed25519" ‖ string key.
    pub fn to_blob(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.utf8(ALGO);
        w.string(self.0.as_bytes());
        w.into_bytes()
    }

    pub fn from_blob(blob: &[u8]) -> Result<Self> {
        let mut r = Reader::new(blob);
        let algo = r.utf8()?;
        if algo != ALGO {
            return Err(Error::proto(format!("unsupported key algorithm {algo:?}")));
        }
        let raw: [u8; 32] = r
            .string()?
            .try_into()
            .map_err(|_| Error::proto("ed25519 public key must be 32 bytes"))?;
        r.finish()?;
        let key = VerifyingKey::from_bytes(&raw).map_err(|_| Error::Crypto("bad ed25519 point"))?;
        Ok(PublicKey(key))
    }

    /// Verify an SSH signature blob (string "ssh-ed25519" ‖ string sig)
    /// over `message`.
    pub fn verify(&self, message: &[u8], sig_blob: &[u8]) -> Result<()> {
        let mut r = Reader::new(sig_blob);
        let algo = r.utf8()?;
        if algo != ALGO {
            return Err(Error::proto(format!("unsupported sig algorithm {algo:?}")));
        }
        let raw: [u8; 64] = r
            .string()?
            .try_into()
            .map_err(|_| Error::proto("ed25519 signature must be 64 bytes"))?;
        r.finish()?;
        self.0
            .verify(message, &Signature::from_bytes(&raw))
            .map_err(|_| Error::Crypto("signature verification failed"))
    }
}

/// A private key. The inner `SigningKey` zeroizes on drop.
pub struct PrivateKey(pub SigningKey);

impl PrivateKey {
    pub fn generate() -> Self {
        PrivateKey(SigningKey::generate(&mut OsRng))
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// Sign `message`, producing the SSH signature blob.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig = self.0.sign(message);
        let mut w = Writer::new();
        w.utf8(ALGO);
        w.string(&sig.to_bytes());
        w.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_roundtrip_and_signature() {
        let key = PrivateKey::generate();
        let blob = key.public().to_blob();
        let parsed = PublicKey::from_blob(&blob).unwrap();
        assert_eq!(parsed.0.as_bytes(), key.public().0.as_bytes());

        let sig = key.sign(b"attack at dawn");
        parsed.verify(b"attack at dawn", &sig).unwrap();
        assert!(parsed.verify(b"attack at dusk", &sig).is_err());
    }

    #[test]
    fn rejects_foreign_algorithms() {
        let mut w = Writer::new();
        w.utf8("ssh-rsa");
        w.string(&[0u8; 32]);
        assert!(PublicKey::from_blob(&w.into_bytes()).is_err());
    }
}
