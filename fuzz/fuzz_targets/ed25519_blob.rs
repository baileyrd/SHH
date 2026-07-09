#![no_main]
//! Fuzz Ed25519 public-key blob decoding (`string "ssh-ed25519" ‖ string
//! key`). Decoding runs on peer-supplied bytes before any trust decision, so
//! a malformed blob must be an error, not a panic or an out-of-bounds read.

use libfuzzer_sys::fuzz_target;
use shh::crypto::ed25519::PublicKey;

fuzz_target!(|data: &[u8]| {
    let _ = PublicKey::from_blob(data);
});
