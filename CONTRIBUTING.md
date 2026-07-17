# Contributing to SHH

Thanks for considering a contribution. This project is a from-scratch SSH
implementation — see [DESIGN.md](DESIGN.md) for the goals and every
deliberate deviation from the RFCs, and [README.md](README.md) for what's
implemented today.

For anything that looks like a security vulnerability, please see
[SECURITY.md](SECURITY.md) instead of opening a public issue or PR.

## Development

```console
$ cargo build --all-targets   # everything, including tests and benches
$ cargo test                  # unit + integration tests
$ cargo clippy --all-targets -- -D warnings
```

The GUI (`gui/`) is a separate Tauri + TypeScript project:

```console
$ cd gui && npm ci && npm run build   # typechecks and builds the frontend
$ cd gui/src-tauri && cargo check     # the Rust side (needs GTK/WebKit
                                       # dev packages on Linux — see the
                                       # `gui` job in .github/workflows/ci.yml
                                       # for the exact apt packages CI installs)
```

Fuzz targets live under `fuzz/` (needs a nightly toolchain and
`cargo-fuzz`); see [fuzz/README.md](fuzz/README.md). The same parsers get
an always-on, stable-toolchain smoke test in `tests/parser_robustness.rs`,
run by ordinary `cargo test`.

Benchmarks live under `benches/` (Criterion); see
[benches/README.md](benches/README.md). They're excluded from CI's `cargo
test` step deliberately — see the comment in
`.github/workflows/ci.yml` — so run them by hand with `cargo bench`.

## Before opening a PR

- `cargo test` and `cargo clippy --all-targets -- -D warnings` should
  pass. CI runs both (plus the GUI build) on every PR across Linux,
  macOS, and Windows.
- Add tests for new behavior, especially anything touching wire parsing,
  channel/window accounting, or key material — this is exactly the kind
  of code where a regression is easy to introduce silently. See the
  existing test modules for the project's conventions (round-trip tests,
  adversarial/malformed-input tests, and — for anything timing- or
  concurrency-sensitive — a test that actually exercises the failure mode
  rather than just the happy path).
- Match the existing code style: minimal comments (only where the *why*
  isn't obvious from the code itself — no restating what a well-named
  function already says), no `unsafe`, secrets wrapped in `zeroize`-on-drop
  types, secret comparisons via `subtle`.
- Keep changes scoped. A bug fix doesn't need an accompanying refactor;
  a new feature doesn't need to solve problems it wasn't asked to solve.

## Reporting non-security bugs

Open a GitHub issue with reproduction steps. For protocol-interop bugs
against OpenSSH, include the OpenSSH version and, if possible, a packet
capture or `-vvv` log from both sides.
