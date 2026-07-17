//! Raw AEAD packet-cipher throughput: `seal`/`open` for both wire ciphers at
//! representative sizes — an interactive-sized packet (64 B) and a
//! bulk-transfer packet (`MAX_CHUNK`, 32 KiB, the largest chunk the channel
//! layer ever sends in one packet). This isolates the crypto cost from
//! transport framing, mux window accounting, and I/O — the number here is
//! the ceiling nothing above it can beat.
//!
//! Run: `cargo bench --bench cipher`

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use shh::crypto::cipher::Algorithm;

const INTERACTIVE: usize = 64;
const BULK: usize = 32 * 1024; // connect::MAX_CHUNK

fn key_iv(algo: Algorithm) -> (Vec<u8>, Vec<u8>) {
    (vec![0x42; algo.key_len()], vec![0x24; algo.iv_len()])
}

fn bench_seal(c: &mut Criterion) {
    let mut group = c.benchmark_group("seal");
    for algo in [Algorithm::ChaChaPoly, Algorithm::Aes256Gcm] {
        for &size in &[INTERACTIVE, BULK] {
            let (key, iv) = key_iv(algo);
            let payload = vec![0x5au8; size];
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("{algo:?}"), size),
                &size,
                |b, _| {
                    let mut cipher = algo.make(&key, &iv);
                    let mut seq = 0u32;
                    b.iter(|| {
                        let out = cipher.seal(seq, &payload);
                        seq = seq.wrapping_add(1);
                        std::hint::black_box(out)
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_open(c: &mut Criterion) {
    let mut group = c.benchmark_group("open");
    for algo in [Algorithm::ChaChaPoly, Algorithm::Aes256Gcm] {
        for &size in &[INTERACTIVE, BULK] {
            let (key, iv) = key_iv(algo);
            let payload = vec![0x5au8; size];
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("{algo:?}"), size),
                &size,
                |b, _| {
                    // GCM's `open` advances an *internal* IV counter on every
                    // call (independent of the `seq` argument), so a receiver
                    // cipher can only ever open the next packet its sender
                    // counterpart produced — reusing a fixed pool out of
                    // sequence would desync the nonce and start failing
                    // authentication. Build a fresh, correctly-sequenced
                    // single-packet opener each iteration instead; the setup
                    // (key schedule + seal) is excluded from the timed cost.
                    b.iter_batched(
                        || {
                            let mut sealer = algo.make(&key, &iv);
                            let wire = sealer.seal(0, &payload);
                            let opener = algo.make(&key, &iv);
                            (opener, wire)
                        },
                        |(mut opener, mut wire)| {
                            let first4: [u8; 4] = wire[..4].try_into().unwrap();
                            let out = opener.open(0, first4, &mut wire[4..]).unwrap();
                            std::hint::black_box(out)
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_seal, bench_open);
criterion_main!(benches);
