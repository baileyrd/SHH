#![no_main]
//! Fuzz the text key-file parsers: authorized_keys / known_hosts lines,
//! public-key and certificate lines, and the base64 `openssh-key-v1` private
//! blob. These read files that may be attacker-influenced; every decoder must
//! return an error on garbage rather than panic.

use libfuzzer_sys::fuzz_target;
use shh::crypto::keyfile;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let _ = keyfile::decode_public(&s);
    let _ = keyfile::decode_cert(&s);
    let _ = keyfile::decode_private(&s);
    let _ = keyfile::needs_passphrase(&s);
    let _ = keyfile::parse_authorized_keys(&s);
    let _ = keyfile::known_hosts_cert_authorities(&s);
    let _ = keyfile::known_hosts_lookup(&s, "example.com:22");
});
