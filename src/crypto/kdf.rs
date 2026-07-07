//! Key derivation, RFC 4253 §7.2.
//!
//! key = HASH(K ‖ H ‖ letter ‖ session_id), extended as needed by
//! HASH(K ‖ H ‖ key_so_far). Both of our KEX algorithms hash with SHA-256.
//!
//! `K` here is the *encoded* shared secret exactly as it appears in the
//! exchange hash: an mpint for curve25519-sha256, an SSH string for the
//! hybrid KEX (its secret is uniform hash output, so mpint games are
//! pointless — one of the small ways the modern algorithms clean up after
//! the RFC).

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Key-material letters from RFC 4253 §7.2.
#[derive(Clone, Copy)]
pub enum Usage {
    IvClientToServer,
    IvServerToClient,
    KeyClientToServer,
    KeyServerToClient,
}

impl Usage {
    fn letter(self) -> u8 {
        match self {
            Usage::IvClientToServer => b'A',
            Usage::IvServerToClient => b'B',
            Usage::KeyClientToServer => b'C',
            Usage::KeyServerToClient => b'D',
        }
    }
}

/// Derive `len` bytes of key material.
///
/// `k_encoded` is the wire-encoded shared secret, `h` the exchange hash,
/// `session_id` the first exchange hash of the connection.
pub fn derive(
    k_encoded: &[u8],
    h: &[u8],
    session_id: &[u8],
    usage: Usage,
    len: usize,
) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(len.next_multiple_of(32)));
    let mut hasher = Sha256::new();
    hasher.update(k_encoded);
    hasher.update(h);
    hasher.update([usage.letter()]);
    hasher.update(session_id);
    out.extend_from_slice(&hasher.finalize());

    while out.len() < len {
        let mut hasher = Sha256::new();
        hasher.update(k_encoded);
        hasher.update(h);
        hasher.update(&out[..]);
        out.extend_from_slice(&hasher.finalize());
    }
    out.truncate(len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_extends() {
        let k = b"\x00\x00\x00\x04\x01\x02\x03\x04";
        let h = [0xaa; 32];
        let sid = [0xbb; 32];
        let a = derive(k, &h, &sid, Usage::KeyClientToServer, 64);
        let b = derive(k, &h, &sid, Usage::KeyClientToServer, 64);
        assert_eq!(&a[..], &b[..]);
        // The first 32 bytes of a 64-byte derivation match the 32-byte one.
        let short = derive(k, &h, &sid, Usage::KeyClientToServer, 32);
        assert_eq!(&a[..32], &short[..]);
        // Different letters give different keys.
        let other = derive(k, &h, &sid, Usage::KeyServerToClient, 64);
        assert_ne!(&a[..], &other[..]);
    }
}
