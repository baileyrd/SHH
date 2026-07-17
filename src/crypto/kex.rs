//! Key exchange: hybrid ML-KEM-768 + X25519 (as deployed in OpenSSH 9.9+),
//! or plain X25519 (curve25519-sha256, RFC 8731).
//!
//! Both use the ECDH-shaped message flow (KEX_ECDH_INIT / KEX_ECDH_REPLY):
//! the client sends `Q_C`, the server replies with `Q_S`, host key, and a
//! signature over the exchange hash. For the hybrid, `Q_C` is the ML-KEM
//! encapsulation key concatenated with the X25519 public key, `Q_S` is the
//! ML-KEM ciphertext concatenated with the server's X25519 public key, and
//! the shared secret is SHA-256(K_mlkem ‖ K_x25519).
//!
//! This module returns the shared secret already in its exchange-hash
//! encoding (`k_encoded`): an mpint for curve25519, an SSH string for the
//! hybrid (the hybrid secret is uniform hash output, so the mpint dance of
//! RFC 4253 is dropped — matching the deployed spec).

use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublic};
use zeroize::Zeroizing;

use crate::wire::Writer;
use crate::{Error, Result};

pub const MLKEM768_EK_LEN: usize = 1184;
pub const MLKEM768_CT_LEN: usize = 1088;
pub const X25519_LEN: usize = 32;

type MlKemDk = <MlKem768 as KemCore>::DecapsulationKey;
type MlKemEk = <MlKem768 as KemCore>::EncapsulationKey;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Algorithm {
    MlKem768X25519Sha256,
    Curve25519Sha256,
}

impl Algorithm {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "mlkem768x25519-sha256" => Some(Algorithm::MlKem768X25519Sha256),
            "curve25519-sha256" => Some(Algorithm::Curve25519Sha256),
            _ => None,
        }
    }
}

/// Encode the X25519 shared secret, checking contributory behaviour:
/// RFC 8731 §3 requires aborting on an all-zero shared secret (low-order
/// peer points).
fn x25519_shared(secret: EphemeralSecret, peer: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let peer: [u8; 32] = peer
        .try_into()
        .map_err(|_| Error::Crypto("x25519 public key must be 32 bytes"))?;
    let shared = secret.diffie_hellman(&XPublic::from(peer));
    if !shared.was_contributory() {
        return Err(Error::Crypto("x25519 peer sent a low-order point"));
    }
    Ok(Zeroizing::new(shared.to_bytes()))
}

/// Copy the ML-KEM-768 shared secret into a fixed 32-byte buffer. Currently
/// guaranteed to be exactly 32 bytes by the `ml-kem` crate's own types for
/// `MlKem768`, so `copy_from_slice` cannot panic today -- this exists so a
/// future dependency change that altered that invariant would surface as a
/// clean `Error::Crypto`, not a panic on a local (not wire-parsed) value.
fn mlkem_shared_secret(raw: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| Error::Crypto("ML-KEM shared secret has unexpected length"))?;
    Ok(Zeroizing::new(arr))
}

fn encode_mpint(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut w = Writer::new();
    w.mpint(bytes);
    Zeroizing::new(w.into_bytes())
}

fn encode_string(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut w = Writer::new();
    w.string(bytes);
    Zeroizing::new(w.into_bytes())
}

fn hybrid_secret(mlkem_ss: &[u8], x_ss: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut h = Sha256::new();
    h.update(mlkem_ss);
    h.update(x_ss);
    Zeroizing::new(h.finalize().to_vec())
}

/// Client half of the exchange. Holds ephemeral secrets between sending
/// KEX_ECDH_INIT and receiving KEX_ECDH_REPLY.
pub struct ClientKex {
    algo: Algorithm,
    x_secret: EphemeralSecret,
    mlkem_dk: Option<MlKemDk>,
    /// `Q_C`, ready to send.
    pub public: Vec<u8>,
}

impl ClientKex {
    pub fn generate(algo: Algorithm) -> Self {
        let x_secret = EphemeralSecret::random_from_rng(OsRng);
        let x_public = XPublic::from(&x_secret);
        match algo {
            Algorithm::Curve25519Sha256 => ClientKex {
                algo,
                x_secret,
                mlkem_dk: None,
                public: x_public.as_bytes().to_vec(),
            },
            Algorithm::MlKem768X25519Sha256 => {
                let (dk, ek) = MlKem768::generate(&mut OsRng);
                let mut public = ek.as_bytes().to_vec();
                public.extend_from_slice(x_public.as_bytes());
                ClientKex {
                    algo,
                    x_secret,
                    mlkem_dk: Some(dk),
                    public,
                }
            }
        }
    }

    /// Consume the server's `Q_S` and produce the encoded shared secret.
    pub fn finish(self, q_s: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        match self.algo {
            Algorithm::Curve25519Sha256 => {
                let ss = x25519_shared(self.x_secret, q_s)?;
                Ok(encode_mpint(&ss[..]))
            }
            Algorithm::MlKem768X25519Sha256 => {
                if q_s.len() != MLKEM768_CT_LEN + X25519_LEN {
                    return Err(Error::Crypto("hybrid KEX reply has wrong length"));
                }
                let (ct, x_pub) = q_s.split_at(MLKEM768_CT_LEN);
                let ct = ml_kem::Ciphertext::<MlKem768>::try_from(ct)
                    .map_err(|_| Error::Crypto("bad ML-KEM ciphertext"))?;
                // ML-KEM uses implicit rejection: a corrupt ciphertext yields
                // a garbage secret and the exchange-hash signature check
                // fails downstream. No oracle here.
                let raw = self
                    .mlkem_dk
                    .expect("hybrid client always has a decapsulation key")
                    .decapsulate(&ct)
                    .map_err(|_| Error::Crypto("ML-KEM decapsulation failed"))?;
                let mlkem_ss = mlkem_shared_secret(&raw)?;
                let x_ss = x25519_shared(self.x_secret, x_pub)?;
                Ok(encode_string(&hybrid_secret(&mlkem_ss[..], &x_ss[..])))
            }
        }
    }
}

/// Server half: one shot. Takes the client's `Q_C`, returns `Q_S` and the
/// encoded shared secret.
pub fn server_exchange(algo: Algorithm, q_c: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let x_secret = EphemeralSecret::random_from_rng(OsRng);
    let x_public = XPublic::from(&x_secret);
    match algo {
        Algorithm::Curve25519Sha256 => {
            let ss = x25519_shared(x_secret, q_c)?;
            Ok((x_public.as_bytes().to_vec(), encode_mpint(&ss[..])))
        }
        Algorithm::MlKem768X25519Sha256 => {
            if q_c.len() != MLKEM768_EK_LEN + X25519_LEN {
                return Err(Error::Crypto("hybrid KEX init has wrong length"));
            }
            let (ek_bytes, x_pub) = q_c.split_at(MLKEM768_EK_LEN);
            let encoded = Encoded::<MlKemEk>::try_from(ek_bytes)
                .map_err(|_| Error::Crypto("bad ML-KEM encapsulation key"))?;
            let ek = MlKemEk::from_bytes(&encoded);
            let (ct, raw) = ek
                .encapsulate(&mut OsRng)
                .map_err(|_| Error::Crypto("ML-KEM encapsulation failed"))?;
            let mlkem_ss = mlkem_shared_secret(&raw)?;
            let x_ss = x25519_shared(x_secret, x_pub)?;
            let mut q_s = ct.to_vec();
            q_s.extend_from_slice(x_public.as_bytes());
            Ok((q_s, encode_string(&hybrid_secret(&mlkem_ss[..], &x_ss[..]))))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curve25519_agrees() {
        let client = ClientKex::generate(Algorithm::Curve25519Sha256);
        assert_eq!(client.public.len(), 32);
        let (q_s, k_server) = server_exchange(Algorithm::Curve25519Sha256, &client.public).unwrap();
        let k_client = client.finish(&q_s).unwrap();
        assert_eq!(&k_client[..], &k_server[..]);
        // mpint encoding: 4-byte length prefix, value ≤ 33 bytes
        assert!(k_client.len() <= 4 + 33);
    }

    #[test]
    fn hybrid_agrees() {
        let client = ClientKex::generate(Algorithm::MlKem768X25519Sha256);
        assert_eq!(client.public.len(), MLKEM768_EK_LEN + X25519_LEN);
        let (q_s, k_server) =
            server_exchange(Algorithm::MlKem768X25519Sha256, &client.public).unwrap();
        assert_eq!(q_s.len(), MLKEM768_CT_LEN + X25519_LEN);
        let k_client = client.finish(&q_s).unwrap();
        assert_eq!(&k_client[..], &k_server[..]);
        // string encoding of a 32-byte hash
        assert_eq!(k_client.len(), 4 + 32);
        assert_eq!(&k_client[..4], &[0, 0, 0, 32]);
    }

    #[test]
    fn hybrid_corrupt_ciphertext_changes_secret_without_erroring() {
        // Implicit rejection: tampering must not be distinguishable here.
        let client = ClientKex::generate(Algorithm::MlKem768X25519Sha256);
        let (mut q_s, k_server) =
            server_exchange(Algorithm::MlKem768X25519Sha256, &client.public).unwrap();
        q_s[0] ^= 0x01;
        let k_client = client.finish(&q_s).unwrap();
        assert_ne!(&k_client[..], &k_server[..]);
    }

    #[test]
    fn low_order_x25519_point_rejected() {
        let client = ClientKex::generate(Algorithm::Curve25519Sha256);
        assert!(client.finish(&[0u8; 32]).is_err());
    }

    #[test]
    fn wrong_lengths_rejected() {
        let client = ClientKex::generate(Algorithm::MlKem768X25519Sha256);
        assert!(client.finish(&[0u8; 10]).is_err());
        assert!(server_exchange(Algorithm::MlKem768X25519Sha256, &[0u8; 10]).is_err());
        assert!(server_exchange(Algorithm::Curve25519Sha256, &[0u8; 31]).is_err());
    }
}
