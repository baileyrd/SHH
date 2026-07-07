//! Packet sealing and opening: the binary packet protocol's cryptographic
//! framing, for exactly three states — plaintext (pre-NEWKEYS only),
//! chacha20-poly1305@openssh.com, and aes256-gcm@openssh.com.
//!
//! Both real ciphers are AEAD, so there is no separate MAC layer anywhere
//! in this implementation, and no encrypt-and-MAC plaintext authentication
//! bug to inherit from RFC 4253.
//!
//! Wire shapes (T = 16-byte tag):
//! * plain:     len(4) ‖ padlen(1) ‖ payload ‖ pad            — align 8
//! * chachapoly: enc-len(4) ‖ enc(padlen ‖ payload ‖ pad) ‖ T — align 8,
//!   length encrypted under a second key; the tag covers enc-len too
//! * aes-gcm:   len(4)=AAD ‖ enc(padlen ‖ payload ‖ pad) ‖ T  — align 16,
//!   nonce = 12-byte IV whose low 8 bytes count invocations
//!
//! Alignment for the AEAD ciphers is over the *encrypted* portion only;
//! the length field does not participate (RFC 5647 / OpenSSH PROTOCOL).

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit};
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20Legacy;
use poly1305::Poly1305;
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result};

/// Hard ceiling on the length field of an incoming packet. RFC 4253
/// requires accepting 35000; we allow more for bulk data but refuse
/// anything a sane peer would never send.
pub const MAX_PACKET: usize = 256 * 1024;

const TAG_LEN: usize = 16;
const MIN_PAD: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Algorithm {
    ChaChaPoly,
    Aes256Gcm,
}

impl Algorithm {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "chacha20-poly1305@openssh.com" => Some(Algorithm::ChaChaPoly),
            "aes256-gcm@openssh.com" => Some(Algorithm::Aes256Gcm),
            _ => None,
        }
    }

    /// Bytes of key material the KDF must produce.
    pub fn key_len(self) -> usize {
        match self {
            Algorithm::ChaChaPoly => 64,
            Algorithm::Aes256Gcm => 32,
        }
    }

    /// Bytes of IV material the KDF must produce.
    pub fn iv_len(self) -> usize {
        match self {
            Algorithm::ChaChaPoly => 0,
            Algorithm::Aes256Gcm => 12,
        }
    }

    pub fn make(self, key: &[u8], iv: &[u8]) -> Box<dyn PacketCipher> {
        match self {
            Algorithm::ChaChaPoly => Box::new(ChaChaPolyCipher::new(key)),
            Algorithm::Aes256Gcm => Box::new(GcmCipher::new(key, iv)),
        }
    }
}

/// One direction of the packet stream. `seq` is the 32-bit packet sequence
/// number for that direction.
pub trait PacketCipher: Send {
    /// Build the full wire bytes for `payload`.
    fn seal(&mut self, seq: u32, payload: &[u8]) -> Vec<u8>;

    /// Recover the packet length field from the first four wire bytes.
    /// Must not consume per-packet state (it is called before `open`).
    fn packet_length(&self, seq: u32, first4: [u8; 4]) -> Result<usize>;

    /// Bytes that follow the first four on the wire, given the length field.
    fn body_len(&self, packet_length: usize) -> usize;

    /// Authenticate and decrypt; returns the payload.
    fn open(&mut self, seq: u32, first4: [u8; 4], body: &mut [u8]) -> Result<Vec<u8>>;
}

/// Sanity-check a length field and its alignment before allocating.
fn check_length(len: usize, align: usize) -> Result<usize> {
    // padlen byte + minimum padding, and room for at least an empty payload
    if !(1 + MIN_PAD..=MAX_PACKET).contains(&len) || len % align != 0 {
        return Err(Error::proto(format!("bad packet length {len}")));
    }
    Ok(len)
}

/// Assemble padlen ‖ payload ‖ random-pad, aligned so `4*with_len + out.len()`
/// is a multiple of `align`.
fn padded(payload: &[u8], align: usize, length_counts: bool) -> Vec<u8> {
    let base = if length_counts { 4 } else { 0 } + 1 + payload.len();
    let mut pad = align - (base % align);
    if pad < MIN_PAD {
        pad += align;
    }
    let mut out = Vec::with_capacity(1 + payload.len() + pad);
    out.push(pad as u8);
    out.extend_from_slice(payload);
    let start = out.len();
    out.resize(start + pad, 0);
    OsRng.fill_bytes(&mut out[start..]);
    out
}

/// Strip padlen ‖ payload ‖ pad down to the payload.
fn unpad(block: &[u8]) -> Result<Vec<u8>> {
    let (&padlen, rest) = block
        .split_first()
        .ok_or_else(|| Error::proto("empty packet"))?;
    let padlen = padlen as usize;
    if padlen < MIN_PAD || padlen > rest.len() {
        return Err(Error::proto("bad padding length"));
    }
    Ok(rest[..rest.len() - padlen].to_vec())
}

// ---------------------------------------------------------------- plain --

/// Pre-NEWKEYS framing. Sequence numbers still advance; nothing is
/// protected. Strict KEX confines what may traverse this state.
pub struct PlainCipher;

impl PacketCipher for PlainCipher {
    fn seal(&mut self, _seq: u32, payload: &[u8]) -> Vec<u8> {
        let block = padded(payload, 8, true);
        let mut out = Vec::with_capacity(4 + block.len());
        out.extend_from_slice(&(block.len() as u32).to_be_bytes());
        out.extend_from_slice(&block);
        out
    }

    fn packet_length(&self, _seq: u32, first4: [u8; 4]) -> Result<usize> {
        let len = u32::from_be_bytes(first4) as usize;
        // for the plain cipher the 4-byte length field itself counts
        // toward the 8-byte alignment
        if !(1 + MIN_PAD..=MAX_PACKET).contains(&len) || (len + 4) % 8 != 0 {
            return Err(Error::proto(format!("bad packet length {len}")));
        }
        Ok(len)
    }

    fn body_len(&self, packet_length: usize) -> usize {
        packet_length
    }

    fn open(&mut self, _seq: u32, _first4: [u8; 4], body: &mut [u8]) -> Result<Vec<u8>> {
        unpad(body)
    }
}

// ----------------------------------------------- chacha20-poly1305 -------

pub struct ChaChaPolyCipher {
    /// Payload key (first 32 bytes of KDF output).
    k_main: Zeroizing<[u8; 32]>,
    /// Length key (second 32 bytes).
    k_len: Zeroizing<[u8; 32]>,
}

impl ChaChaPolyCipher {
    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), 64, "chachapoly wants 64 bytes of key");
        let mut k_main = Zeroizing::new([0u8; 32]);
        let mut k_len = Zeroizing::new([0u8; 32]);
        k_main.copy_from_slice(&key[..32]);
        k_len.copy_from_slice(&key[32..]);
        ChaChaPolyCipher { k_main, k_len }
    }

    fn nonce(seq: u32) -> [u8; 8] {
        (seq as u64).to_be_bytes()
    }

    /// Poly1305 key: block 0 of the main-key keystream.
    fn poly_key(&self, nonce: &[u8; 8]) -> Zeroizing<[u8; 32]> {
        let mut key = Zeroizing::new([0u8; 32]);
        let mut c = ChaCha20Legacy::new(self.k_main[..].into(), nonce.into());
        c.apply_keystream(&mut key[..]);
        key
    }
}

impl PacketCipher for ChaChaPolyCipher {
    fn seal(&mut self, seq: u32, payload: &[u8]) -> Vec<u8> {
        let nonce = Self::nonce(seq);
        let mut block = padded(payload, 8, false);

        let mut out = Vec::with_capacity(4 + block.len() + TAG_LEN);
        out.extend_from_slice(&(block.len() as u32).to_be_bytes());
        ChaCha20Legacy::new(self.k_len[..].into(), (&nonce).into())
            .apply_keystream(&mut out[..4]);

        let mut main = ChaCha20Legacy::new(self.k_main[..].into(), (&nonce).into());
        main.seek(64u64); // keystream block 1; block 0 is the poly1305 key
        main.apply_keystream(&mut block);
        out.extend_from_slice(&block);
        block.zeroize();

        let tag = Poly1305::new((&*self.poly_key(&nonce)).into()).compute_unpadded(&out);
        out.extend_from_slice(&tag);
        out
    }

    fn packet_length(&self, seq: u32, mut first4: [u8; 4]) -> Result<usize> {
        let nonce = Self::nonce(seq);
        ChaCha20Legacy::new(self.k_len[..].into(), (&nonce).into())
            .apply_keystream(&mut first4);
        check_length(u32::from_be_bytes(first4) as usize, 8)
    }

    fn body_len(&self, packet_length: usize) -> usize {
        packet_length + TAG_LEN
    }

    fn open(&mut self, seq: u32, first4: [u8; 4], body: &mut [u8]) -> Result<Vec<u8>> {
        let nonce = Self::nonce(seq);
        let (ct, tag) = body.split_at_mut(body.len() - TAG_LEN);

        // Tag covers the encrypted length bytes followed by the ciphertext.
        let mac = Poly1305::new((&*self.poly_key(&nonce)).into());
        let mut msg = Vec::with_capacity(4 + ct.len());
        msg.extend_from_slice(&first4);
        msg.extend_from_slice(ct);
        let expect = mac.compute_unpadded(&msg);
        if expect.ct_eq(&*tag).unwrap_u8() != 1 {
            return Err(Error::Crypto("packet authentication failed"));
        }

        let mut main = ChaCha20Legacy::new(self.k_main[..].into(), (&nonce).into());
        main.seek(64u64);
        main.apply_keystream(ct);
        unpad(ct)
    }
}

// ------------------------------------------------------- aes256-gcm ------

pub struct GcmCipher {
    cipher: Aes256Gcm,
    /// Fixed(4) ‖ invocation-counter(8); the counter increments per packet
    /// (RFC 5647 §7.1) independently of the sequence number.
    iv: [u8; 12],
}

impl GcmCipher {
    pub fn new(key: &[u8], iv: &[u8]) -> Self {
        assert_eq!(key.len(), 32, "aes256-gcm wants a 32-byte key");
        GcmCipher {
            cipher: Aes256Gcm::new(key.into()),
            iv: iv.try_into().expect("aes256-gcm wants a 12-byte IV"),
        }
    }

    fn bump(&mut self) -> [u8; 12] {
        let nonce = self.iv;
        let ctr = u64::from_be_bytes(self.iv[4..].try_into().unwrap()).wrapping_add(1);
        self.iv[4..].copy_from_slice(&ctr.to_be_bytes());
        nonce
    }
}

impl PacketCipher for GcmCipher {
    fn seal(&mut self, _seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut block = padded(payload, 16, false);
        let len_be = (block.len() as u32).to_be_bytes();
        let nonce = self.bump();
        let tag = self
            .cipher
            .encrypt_in_place_detached((&nonce).into(), &len_be, &mut block)
            .expect("gcm encryption is infallible for in-range sizes");
        let mut out = Vec::with_capacity(4 + block.len() + TAG_LEN);
        out.extend_from_slice(&len_be);
        out.extend_from_slice(&block);
        out.extend_from_slice(&tag);
        out
    }

    fn packet_length(&self, _seq: u32, first4: [u8; 4]) -> Result<usize> {
        check_length(u32::from_be_bytes(first4) as usize, 16)
    }

    fn body_len(&self, packet_length: usize) -> usize {
        packet_length + TAG_LEN
    }

    fn open(&mut self, _seq: u32, first4: [u8; 4], body: &mut [u8]) -> Result<Vec<u8>> {
        let nonce = self.bump();
        let (ct, tag) = body.split_at_mut(body.len() - TAG_LEN);
        self.cipher
            .decrypt_in_place_detached((&nonce).into(), &first4, ct, (&*tag).into())
            .map_err(|_| Error::Crypto("packet authentication failed"))?;
        unpad(ct)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(mk: impl Fn() -> Box<dyn PacketCipher>) {
        let mut tx = mk();
        let mut rx = mk();
        for (seq, payload) in [
            (0u32, &b""[..]),
            (1, b"x"),
            (2, &[0u8; 300][..]),
            (700, &[0xabu8; 40000][..]),
        ] {
            let wire = tx.seal(seq, payload);
            let first4: [u8; 4] = wire[..4].try_into().unwrap();
            let len = rx.packet_length(seq, first4).unwrap();
            let mut body = wire[4..].to_vec();
            assert_eq!(body.len(), rx.body_len(len));
            let got = rx.open(seq, first4, &mut body).unwrap();
            assert_eq!(got, payload);
        }
    }

    #[test]
    fn plain_roundtrip() {
        roundtrip(|| Box::new(PlainCipher));
    }

    #[test]
    fn chachapoly_roundtrip() {
        let key = [0x42u8; 64];
        roundtrip(move || Box::new(ChaChaPolyCipher::new(&key)));
    }

    #[test]
    fn gcm_roundtrip() {
        let key = [0x42u8; 32];
        let iv = [7u8; 12];
        roundtrip(move || Box::new(GcmCipher::new(&key, &iv)));
    }

    #[test]
    fn chachapoly_length_is_confidential_and_seq_bound() {
        let mut tx = ChaChaPolyCipher::new(&[9u8; 64]);
        let w1 = tx.seal(0, b"same payload");
        let w2 = tx.seal(1, b"same payload");
        // Same true length, different encrypted length fields.
        assert_ne!(&w1[..4], &w2[..4]);
        // Decrypting with the wrong sequence number must not yield the
        // real length (or must fail outright).
        let rx = ChaChaPolyCipher::new(&[9u8; 64]);
        let real = rx
            .packet_length(0, w1[..4].try_into().unwrap())
            .unwrap();
        if let Ok(l) = rx.packet_length(5, w1[..4].try_into().unwrap()) {
            assert_ne!(l, real);
        }
    }

    #[test]
    fn tamper_detected() {
        for mk in [
            (|| Box::new(ChaChaPolyCipher::new(&[3u8; 64])) as Box<dyn PacketCipher>)
                as fn() -> Box<dyn PacketCipher>,
            || Box::new(GcmCipher::new(&[3u8; 32], &[0u8; 12])),
        ] {
            let mut tx = mk();
            let mut rx = mk();
            let wire = tx.seal(0, b"integrity matters");
            let first4: [u8; 4] = wire[..4].try_into().unwrap();
            let len = rx.packet_length(0, first4).unwrap();
            let mut body = wire[4..].to_vec();
            let mid = body.len() / 2;
            body[mid] ^= 0x80;
            assert!(rx.open(0, first4, &mut body).is_err());
            assert_eq!(body.len(), rx.body_len(len));
        }
    }

    #[test]
    fn gcm_replay_fails_because_nonce_advances() {
        let mut tx = GcmCipher::new(&[3u8; 32], &[0u8; 12]);
        let mut rx = GcmCipher::new(&[3u8; 32], &[0u8; 12]);
        let wire = tx.seal(0, b"first");
        let first4: [u8; 4] = wire[..4].try_into().unwrap();
        let mut body = wire[4..].to_vec();
        rx.open(0, first4, &mut body).unwrap();
        // Feeding the same packet again hits a different nonce → auth failure.
        let mut body2 = wire[4..].to_vec();
        assert!(rx.open(0, first4, &mut body2).is_err());
    }

    #[test]
    fn oversized_length_rejected() {
        let rx = GcmCipher::new(&[3u8; 32], &[0u8; 12]);
        let huge = (MAX_PACKET as u32 + 16).to_be_bytes();
        assert!(rx.packet_length(0, huge).is_err());
    }
}
