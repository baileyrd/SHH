#![no_main]
//! Fuzz KEXINIT parsing — the first attacker-controlled packet in the
//! protocol, parsed before any key exchange. Ten name-lists, a boolean and a
//! reserved word, all length-prefixed. Must reject malformed input, not panic.

use libfuzzer_sys::fuzz_target;
use shh::transport::kexinit::KexInit;

fuzz_target!(|data: &[u8]| {
    let _ = KexInit::parse(data);
});
