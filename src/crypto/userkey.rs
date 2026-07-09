//! A user's authentication key, in the two forms `shhd` accepts: a plain
//! Ed25519 key or a FIDO2 security-key credential
//! (`sk-ssh-ed25519@openssh.com`). One type so the auth path can carry,
//! authorize, and verify either without caring which it is.

use crate::crypto::ed25519::{PublicKey, ALGO};
use crate::crypto::sk::{SkPublicKey, SK_ALGO};
use crate::wire::Reader;
use crate::{Error, Result};

#[derive(Clone, Debug)]
pub enum UserKey {
    Ed25519(PublicKey),
    Sk(SkPublicKey),
}

impl UserKey {
    /// Decode a public-key blob, dispatching on its algorithm name.
    pub fn from_blob(blob: &[u8]) -> Result<Self> {
        match Reader::new(blob).utf8()? {
            ALGO => Ok(UserKey::Ed25519(PublicKey::from_blob(blob)?)),
            SK_ALGO => Ok(UserKey::Sk(SkPublicKey::from_blob(blob)?)),
            other => Err(Error::proto(format!(
                "unsupported user key algorithm {other:?}"
            ))),
        }
    }

    pub fn to_blob(&self) -> Vec<u8> {
        match self {
            UserKey::Ed25519(k) => k.to_blob(),
            UserKey::Sk(k) => k.to_blob(),
        }
    }

    pub fn algo(&self) -> &'static str {
        match self {
            UserKey::Ed25519(_) => ALGO,
            UserKey::Sk(_) => SK_ALGO,
        }
    }

    /// Verify a userauth signature over `message`. For a security key this
    /// also checks the assertion's user-presence flag.
    pub fn verify(&self, message: &[u8], sig: &[u8]) -> Result<()> {
        match self {
            UserKey::Ed25519(k) => k.verify(message, sig),
            UserKey::Sk(k) => k.verify(message, sig),
        }
    }

    pub fn fingerprint(&self) -> String {
        match self {
            UserKey::Ed25519(k) => k.fingerprint(),
            UserKey::Sk(k) => k.fingerprint(),
        }
    }

    /// The same credential? Compared by encoded blob, in constant time.
    pub fn matches(&self, other: &UserKey) -> bool {
        use subtle::ConstantTimeEq;
        let (a, b) = (self.to_blob(), other.to_blob());
        a.len() == b.len() && a.ct_eq(&b).unwrap_u8() == 1
    }
}

impl From<PublicKey> for UserKey {
    fn from(k: PublicKey) -> Self {
        UserKey::Ed25519(k)
    }
}
