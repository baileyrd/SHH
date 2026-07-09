#![no_main]
//! Fuzz OpenSSH certificate parsing + signature verification. The blob is
//! fully attacker-controlled (presented by a peer during auth or KEX):
//! nested strings, principal/option/extension name-lists, an embedded CA key
//! and a signature. Parsing must fail closed on any malformation, not panic.

use libfuzzer_sys::fuzz_target;
use shh::crypto::cert::Certificate;

fuzz_target!(|data: &[u8]| {
    let _ = Certificate::parse_and_verify(data);
});
