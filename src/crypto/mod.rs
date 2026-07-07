//! Cryptographic algorithms: the complete list, not the default list.
//!
//! There is deliberately no registry, no trait-object plugin system, and no
//! way to add an algorithm without editing this module. The negotiable
//! surface is: two key exchanges, one signature scheme, two AEAD ciphers.

pub mod cert;
pub mod cipher;
pub mod ed25519;
pub mod kdf;
pub mod kex;
pub mod keyfile;

/// KEX algorithms in preference order, as advertised in KEXINIT.
pub const KEX_ALGORITHMS: &[&str] = &["mlkem768x25519-sha256", "curve25519-sha256"];

/// Host key algorithms. Ed25519, full stop.
pub const HOST_KEY_ALGORITHMS: &[&str] = &["ssh-ed25519"];

/// AEAD ciphers in preference order.
pub const CIPHERS: &[&str] = &["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"];

/// MAC name-list sent in KEXINIT. Both our ciphers are AEAD, so the MAC
/// negotiation result is never used; the list exists because the KEXINIT
/// wire format requires one. We advertise a real algorithm so that mixed
/// negotiations with stock OpenSSH configs cannot fail on an empty list.
pub const MACS: &[&str] = &["hmac-sha2-256"];

/// Compression: none. Not "none by default" — none.
pub const COMPRESSION: &[&str] = &["none"];
