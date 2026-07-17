# Benchmarking SHH

Two [Criterion](https://github.com/bheisler/criterion.rs) suites:

| Bench | Measures |
|---|---|
| `cipher` | Raw AEAD `seal`/`open` throughput for both wire ciphers (`chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`) at an interactive packet size (64 B) and the bulk-transfer chunk size (32 KiB, `connect::MAX_CHUNK`). This is the crypto-only ceiling — no framing, no mux, no I/O. |
| `throughput` | End-to-end bulk-push throughput through the full client/server stack: handshake, transport encryption, channel multiplexing, and window flow control, over a `direct-tcpip` tunnel. The two transports are connected by an in-memory pipe (`tokio::io::duplex`), not a real socket, so this isolates the implementation's own CPU-bound overhead from network conditions. |

The gap between the two is the cost of everything *above* the cipher: packet
framing, per-packet allocation, channel window accounting, and task
scheduling. Tracking both together is what makes a regression in the mux/
transport hot path visible even when the crypto itself is untouched.

## Running

```console
$ cargo bench --bench cipher
$ cargo bench --bench throughput
```

Criterion writes an HTML report to `target/criterion/report/index.html`
(needs `gnuplot` for the nicer plots; falls back to a plain summary
otherwise). Both benches accept the usual Criterion CLI flags, e.g. a
quicker run for local iteration:

```console
$ cargo bench --bench cipher -- --sample-size 20 --measurement-time 3
```

## Reading the numbers

- Two SHH peers always negotiate `chacha20-poly1305@openssh.com` — it's
  offered first by both sides and there's no per-connection override — so
  `throughput` only ever exercises that cipher. `cipher` is where the
  AES-256-GCM comparison lives.
- On hardware with AES-NI + CLMUL (most modern x86-64), expect AES-256-GCM to
  noticeably outrun ChaCha20-Poly1305 at the bulk size; the RustCrypto AES
  path uses those instructions, while ChaCha20 has no comparable hardware
  primitive to lean on.
- `throughput` numbers will sit well below `cipher`'s bulk-size ceiling —
  that gap is expected and is the point of running both.
- These are not network-transfer numbers and shouldn't be quoted as
  "SHH does N MB/s over the wire." They're a regression baseline for this
  implementation's own overhead, measured in a way that's reproducible in
  CI without a second SSH implementation or real network involved.
