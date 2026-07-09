//! Always-on parser robustness: the same panic-free promise the `fuzz/`
//! crate checks with libFuzzer, captured here as a deterministic test that
//! runs under an ordinary `cargo test` (no nightly needed). Every parser that
//! touches peer-controlled bytes is hammered with random and near-valid
//! (mutated) input; a panic on any path fails the test.
//!
//! This is a smoke test, not a substitute for a real fuzzing campaign — see
//! `fuzz/README.md`. Its value is that the guarantee is checked in CI on
//! stable, and that any crash a fuzzer finds can be pinned here as a
//! regression seed.

use shh::crypto::cert::{self, Certificate};
use shh::crypto::ed25519::{PrivateKey, PublicKey};
use shh::crypto::keyfile;
use shh::transport::kexinit::KexInit;
use shh::transport::Side;
use shh::wire::Reader;

/// SplitMix64 — a tiny deterministic PRNG so runs are reproducible and need
/// no external dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = self.below(max + 1);
        (0..len).map(|_| (self.next() & 0xff) as u8).collect()
    }
}

/// Byte-level corruption of a valid encoding: the near-miss inputs that trip
/// up length handling — truncation, extension, single-byte flips, splices.
fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut v = seed.to_vec();
    for _ in 0..1 + rng.below(6) {
        if v.is_empty() {
            v.push((rng.next() & 0xff) as u8);
            continue;
        }
        match rng.below(5) {
            0 => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 => v.truncate(rng.below(v.len())),
            2 => {
                let i = rng.below(v.len() + 1);
                v.insert(i, (rng.next() & 0xff) as u8);
            }
            3 => {
                let i = rng.below(v.len());
                v[i] = (rng.next() & 0xff) as u8;
            }
            _ => {
                // Corrupt a length prefix: 4 bytes near the front dominate
                // how the rest is interpreted.
                let i = rng.below(v.len());
                v[i] = if rng.next() & 1 == 0 { 0xff } else { 0x00 };
            }
        }
    }
    v
}

/// Assert `f` returns without unwinding; report the offending input if not.
fn no_panic(label: &str, input: &[u8], f: impl FnOnce() + std::panic::UnwindSafe) {
    if std::panic::catch_unwind(f).is_err() {
        panic!(
            "{label} panicked on {}-byte input: {}",
            input.len(),
            input
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join("")
        );
    }
}

/// Replays the `wire_reader` fuzz target's opcode loop deterministically.
fn drive_reader(buf: &[u8], mut op: u8) {
    let mut r = Reader::new(buf);
    for _ in 0..128 {
        let step = match op % 8 {
            0 => r.byte().map(|_| ()),
            1 => r.boolean().map(|_| ()),
            2 => r.u32().map(|_| ()),
            3 => r.u64().map(|_| ()),
            4 => r.string().map(|_| ()),
            5 => r.utf8().map(|_| ()),
            6 => r.name_list().map(|_| ()),
            _ => {
                let _ = r.rest();
                Ok(())
            }
        };
        if step.is_err() || r.remaining() == 0 {
            break;
        }
        op = op.wrapping_mul(31).wrapping_add(7);
    }
    let _ = r.finish();
}

#[test]
fn wire_reader_never_panics() {
    let mut rng = Rng(0x5148_4820_7769_7265); // "SHH wire"
    // A few structurally valid buffers to mutate toward near-misses.
    let seeds: Vec<Vec<u8>> = vec![
        {
            let mut w = shh::wire::Writer::new();
            w.u32(4);
            w.string(b"test");
            w.name_list(&["a", "b", "c"]);
            w.into_bytes()
        },
        vec![0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o'],
        vec![0xff, 0xff, 0xff, 0xff],
    ];
    for _ in 0..8000 {
        let buf = rng.bytes(256);
        let op = (rng.next() & 0xff) as u8;
        no_panic("wire::Reader", &buf, || drive_reader(&buf, op));
    }
    for _ in 0..4000 {
        let seed = &seeds[rng.below(seeds.len())];
        let buf = mutate(&mut rng, seed);
        let op = (rng.next() & 0xff) as u8;
        no_panic("wire::Reader", &buf, || drive_reader(&buf, op));
    }
}

#[test]
fn kexinit_parse_never_panics() {
    let mut rng = Rng(0x4b45_5849_4e49_5401); // "KEXINIT"
    let valid = KexInit::local(Side::Client, &["ssh-ed25519".to_string()]).encode();
    for _ in 0..6000 {
        let buf = rng.bytes(512);
        no_panic("KexInit::parse", &buf, || {
            let _ = KexInit::parse(&buf);
        });
    }
    for _ in 0..6000 {
        let buf = mutate(&mut rng, &valid);
        no_panic("KexInit::parse", &buf, || {
            let _ = KexInit::parse(&buf);
        });
    }
}

#[test]
fn cert_parse_never_panics() {
    let mut rng = Rng(0x4345_5254_4649_5a5a); // "CERTFIZZ"
    // A genuine, fully valid certificate to mutate — exercises the paths past
    // structural parsing (principals, options, CA key, signature check).
    let ca = PrivateKey::generate();
    let user = PrivateKey::generate();
    let valid = cert::sign_user_cert(
        &ca,
        &user.public(),
        1,
        "alice@corp",
        &["deploy".to_string(), "admin".to_string()],
        0,
        u64::MAX,
    );
    for _ in 0..3000 {
        let buf = rng.bytes(400);
        no_panic("Certificate::parse_and_verify", &buf, || {
            let _ = Certificate::parse_and_verify(&buf);
        });
    }
    for _ in 0..5000 {
        let buf = mutate(&mut rng, &valid);
        no_panic("Certificate::parse_and_verify", &buf, || {
            let _ = Certificate::parse_and_verify(&buf);
        });
    }
}

#[test]
fn ed25519_blob_never_panics() {
    let mut rng = Rng(0x6564_3235_3531_3900); // "ed25519"
    let valid = PrivateKey::generate().public().to_blob();
    for _ in 0..5000 {
        let buf = rng.bytes(128);
        no_panic("PublicKey::from_blob", &buf, || {
            let _ = PublicKey::from_blob(&buf);
        });
    }
    for _ in 0..5000 {
        let buf = mutate(&mut rng, &valid);
        no_panic("PublicKey::from_blob", &buf, || {
            let _ = PublicKey::from_blob(&buf);
        });
    }
}

#[test]
fn keyfile_text_parsers_never_panic() {
    let mut rng = Rng(0x6b65_7966_696c_6500); // "keyfile"
    let key = PrivateKey::generate();
    let seeds: Vec<Vec<u8>> = vec![
        keyfile::encode_public(&key.public(), "user@host").into_bytes(),
        keyfile::encode_private(&key, "comment").into_bytes(),
        format!("example.com:22 {}", keyfile::encode_public(&key.public(), "").trim())
            .into_bytes(),
        b"@cert-authority *.corp ssh-ed25519 AAAAlemon comment".to_vec(),
    ];
    let run = |s: &str| {
        let _ = keyfile::decode_public(s);
        let _ = keyfile::decode_cert(s);
        let _ = keyfile::decode_private(s);
        let _ = keyfile::needs_passphrase(s);
        let _ = keyfile::parse_authorized_keys(s);
        let _ = keyfile::known_hosts_cert_authorities(s);
        let _ = keyfile::known_hosts_lookup(s, "example.com:22");
    };
    for _ in 0..4000 {
        let buf = rng.bytes(256);
        let s = String::from_utf8_lossy(&buf).into_owned();
        no_panic("keyfile::*", &buf, || run(&s));
    }
    for _ in 0..4000 {
        let seed = &seeds[rng.below(seeds.len())];
        let buf = mutate(&mut rng, seed);
        let s = String::from_utf8_lossy(&buf).into_owned();
        no_panic("keyfile::*", &buf, || run(&s));
    }
}
