# Fuzzing SHH's wire parsers

SHH promises its parsers are *panic-free on arbitrary input* (see
`DESIGN.md`). These [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
targets exercise that promise with coverage-guided (libFuzzer) fuzzing on
every byte string a peer can put on the wire before it is trusted.

The same parsers also get a deterministic, always-on smoke test in the main
crate — `tests/parser_robustness.rs`, run by an ordinary `cargo test` — so
the robustness guarantee is checked in CI even without a nightly toolchain.
The fuzz targets below are for deep, dedicated campaigns.

## Targets

| Target | Parser | Attack surface |
|---|---|---|
| `wire_reader` | `wire::Reader` primitives | every length-prefixed field |
| `kexinit_parse` | `KexInit::parse` | the first packet, pre-KEX |
| `cert_parse` | `Certificate::parse_and_verify` | peer-presented user/host certs |
| `keyfile_decode` | `keyfile::*` | authorized_keys / known_hosts / key files |
| `ed25519_blob` | `ed25519::PublicKey::from_blob` | peer public keys |

## Running

`cargo-fuzz` needs a **nightly** toolchain and libFuzzer (`-Z` build-std is
not required, but the sanitizer instrumentation is nightly-only):

```console
$ cargo install cargo-fuzz
$ rustup toolchain install nightly

# fuzz one target
$ cargo +nightly fuzz run wire_reader

# time-boxed run, useful in CI
$ cargo +nightly fuzz run cert_parse -- -max_total_time=60

# list targets
$ cargo fuzz list
```

A crash writes a reproducer under `fuzz/artifacts/<target>/`; replay it with
`cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file>`.

This crate is a nested workspace so `libfuzzer-sys` (nightly-only) never
enters the parent crate's dependency graph; a plain `cargo build` / `cargo
test` at the repo root ignores it entirely.
