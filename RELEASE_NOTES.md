# Release notes

SHH's first tagged release is `v0.1.0` (matching `Cargo.toml`), cut from the
entry below dated 2026-07-21. Everything before that tag is grouped into
the four clearly distinct phases the project moved through pre-release,
newest first, so it's possible to see what landed when without reading
through dozens of PR descriptions.

Every entry below is real work verified against the repository history;
nothing here is aspirational. See [DESIGN.md](DESIGN.md) for the rationale
behind each protocol decision and [README.md](README.md) for how to use
what's described here.

---

## v0.1.0 — Local key publishing and CI health — 2026-07-21

`shh-id`, a small addition that closes a real gap in the "how do keys move
between my devices" story, plus a project-process pass: CI had been red on
every push for several days from issues unrelated to any one feature, and
fixing them surfaced a real connection-lifecycle bug that had simply never
been exercised before.

### New: shh-id

- **`shh-id`**: a local, self-hosted alternative to hosted "SSH passkey"
  services like sshid.io. Public keys for a handle live under a directory
  the user syncs across their own devices (Syncthing, a private git repo,
  a network share, ...) rather than a cloud vault; `shh-id serve` publishes
  them at `GET /<handle>` from wherever it's run, so `curl
  http://host:port/<handle> >> authorized_keys` works exactly like the
  hosted service did. `add`/`list`/`export` round out the CLI, and a
  malformed or half-synced `.pub` file is skipped with a warning rather
  than served or taking the whole handle down.

### Fixes

- **Connection hang on a refused terminal session.** A client session
  meant to end the whole connection when it closes (`client_session`'s
  one-shot wrapper) never did if the server refused the channel open
  outright: the refusal only dropped the pending entry, never signaled the
  loop to stop, and `close_if_done` — the only other path that ends a
  terminal connection — needs a channel entry a refused open never gets.
  Both ends of the connection would then park forever with nothing left to
  send. Not platform-specific in the code, just previously unreachable:
  every test that exercises a session runs client and server in the same
  process, and this path only fires when a peer serves no sessions at all
  (Windows CI, see below) — which nothing had ever hit before now.

### Project process

- **CI actually runs on Windows and macOS now.** Four issues had made every
  push to `main` fail for several days, none related to any one feature: a
  clippy lint newly enforced by a toolchain bump, Linux-only libc calls
  (`prctl`, `initgroups`, an `rlimit` resource type) used unconditionally
  in `privsep.rs`/`session.rs`, Unix-only test code that had never been
  gated for Windows, and the GUI check running `cargo check` before the
  frontend build it depends on. Fixed all four, plus properly `#[cfg(unix)]`
  gating the POSIX-shell session tests the connection-hang fix above
  exposed for the first time.

---

## Hardening, performance, and process — 2026-07-17

Five rounds of adversarial self-review across the whole tree, plus a
benchmark harness and the project infrastructure a repo this size should
have had from day one. No new protocol features — every change here is a
correctness, security, or robustness fix to what the previous phase built,
each backed by a test that exercises the actual failure mode.

### Security fixes

- **GUI known_hosts injection.** The desktop GUI's saved-host storage
  accepted a hostname containing a newline, which would have let a
  compromised renderer process poison `known_hosts` with an attacker-chosen
  key under an unrelated hostname — a one-time IPC call turning into a
  persistent MITM setup. Fixed on both the save path and on load from disk
  (an already-poisoned file could otherwise survive the fix that closed the
  save path).
- **Agent unlock timing leak.** The key agent's `unlock` compared passphrase
  length before running its constant-time byte comparison, leaking the true
  held passphrase's length to a local attacker timing guesses of different
  lengths. Now compares fixed-size padded buffers unconditionally.
- **Empty-principal certificates.** `shh-keygen` minted user certificates
  valid for *any* login name by default when `-n` was omitted. Now requires
  at least one principal, or an explicit `--allow-any-principal` opt-in.
- **Rekey host-key substitution.** A rekey re-ran the full TOFU trust
  decision from scratch, so a server could rotate to a different host key
  mid-session (and a TOFU prompt could re-fire after the user thought
  they'd already verified). A rekey must now present the same key the
  session was established with.
- **Security-key-as-host-key confusion.** A server could present a FIDO2
  security-key certificate under the plain host-key algorithm; now rejected
  per RFC 4253 §7.1 (the presented key must match what was negotiated).
- **Agent socket hardening.** `shh-agent`'s bind path could chmod an
  *existing* parent directory to 0700 (dangerous if that directory was
  something like `/tmp`), raced on stale-socket cleanup, and left a brief
  world-writable window before the final permission set. All three fixed;
  only a directory this call itself creates gets chmodded, a stale socket
  is verified to be a socket owned by the caller before removal, and the
  umask is tightened for the whole bind.
- **Agent destination constraints.** A certificate-authority constraint
  entry matched any certificate the CA ever signed, including an expired
  one or a *user* certificate presented as if it were a host. A
  non-forwarding hop could also be extended with another hop behind it,
  letting independent direct connections forge a multi-hop path they never
  actually traversed. Both now enforce OpenSSH's actual rules (host type +
  validity window; a non-forwarding hop must be the end of the chain).
- **Privilege-separation gaps.** The signer subprocess dropped gid and uid
  but never called `initgroups`, so it kept root's supplementary groups
  after "dropping" privileges — closed to match the daemon's own drop path.
  A poisoned mutex in the same signer could also cascade one panic into
  every future request; now survives a poisoned lock instead.
- **Resource exhaustion.** Several unbounded-growth paths closed: a
  `direct-tcpip`/`forwarded-tcpip` accept queue that could grow without
  limit if the connection loop stalled; no cap on concurrent channels per
  connection (plus a separate accounting gap where an in-flight outbound
  connect was invisible to that cap for up to ten seconds); no timeout on
  outbound connects at all; an SFTP session that could hold unlimited open
  file/directory handles; and a lock-passphrase length that was capped on
  unlock but not on lock, which would have permanently bricked an agent's
  unlock if a passphrase over the cap was ever set.
- **Catastrophic backtracking.** The `known_hosts` glob matcher (`*`/`?`
  patterns) used naive recursive backtracking, exponential against a
  crafted pattern with many wildcards. Replaced with the standard iterative
  two-pointer algorithm (the same shape OpenSSH's own matcher uses).
- **Non-ASCII passphrase corruption.** Passphrase and prompt input on Unix
  cast each raw byte to a `char` as it arrived, silently corrupting any
  multi-byte UTF-8 character — a user with an accented or non-Latin
  passphrase could never type it correctly. Fixed to decode once at the
  end.
- **SFTP OPEN mutating past the handle cap.** The newly-added handle-count
  limit was checked *after* `OPEN` had already created or truncated a file,
  so a refused request could still have side effects. Reordered to check
  first, matching how `OPENDIR` already did it.

### Performance

- Added a [Criterion benchmark harness](benches/README.md): raw AEAD
  `seal`/`open` throughput per cipher, and end-to-end bulk-transfer
  throughput through the full client/server stack over an in-memory pipe
  (isolating the implementation's own overhead from network conditions).
- `ChaCha20-Poly1305`'s packet-open path no longer copies the whole
  ciphertext into a scratch buffer just to compute the authentication tag —
  measured **~5–6% faster** at the 32 KiB bulk chunk size, verified
  byte-for-byte identical against the original algorithm across every
  block-boundary case before shipping.
- Widening the benchmark's payload-size sweep exposed (and fixed) a real
  task/file-descriptor leak in the *benchmark harness itself*: background
  tasks spawned per iteration were never torn down, exhausting descriptors
  within a couple thousand fast iterations.

### Project process

- `SECURITY.md` (private vulnerability reporting via GitHub Security
  Advisories) and `CONTRIBUTING.md` (dev setup, PR expectations).
- CI (`.github/workflows/ci.yml`): build + test + clippy across Linux,
  macOS, and Windows, plus a GUI build (Rust and the TypeScript frontend
  both) — none of which existed before this phase.
- Dependabot for both Rust manifests, the GUI's npm dependencies, and
  GitHub Actions itself.
- `--locked` added throughout CI so a build is reproducible against the
  committed lockfile rather than silently drifting.
- Operator-facing warnings sharpened: running `shhd` as root with
  `--no-privilege-drop` now says explicitly that every session will run as
  root (and prints to stderr directly, not just a log line); `--sandbox`'s
  "sessions share one account" trade-off is now a `warn!`, not an `info!`.
- `DESIGN.md` and this file now document the hardening and benchmarking
  work; previously neither existed anywhere in the repo.

---

## Agent, security keys, SFTP, the GUI, and Windows — 2026-07-09

The client and server surface grew from "talks the modern subset of SSH" to
something resembling a full toolkit: a key agent, FIDO2 support, a file
transfer protocol, a desktop app, and a second target platform.

### Key agent and forwarding

- **`shh-agent`**: an Ed25519-only SSH agent speaking the standard agent
  protocol, interoperable with OpenSSH's `ssh`/`ssh-add` in both
  directions. Fails closed on anything it can't fully honor — legacy key
  types, a public half that contradicts the private seed, the
  confirm-per-use constraint, unknown extensions — rather than silently
  ignoring them. `shh` uses whatever `SSH_AUTH_SOCK` names when no `-i`
  pins a file.
- **Agent forwarding (`-A`)**, default-deny on both ends (unlike OpenSSH,
  where the server side is open by default): `shhd` requires
  `--permit-agent-forwarding`, and the client never offers its agent
  unasked. The daemon also scrubs its own inherited `SSH_AUTH_SOCK` from
  session environments, closing a real leak an interop test caught.
- **Destination-constrained keys**: `shh-agent add -H host` (or
  `gw>prod` for a multi-hop path, or a certificate authority) pins a
  forwarded key to where it may actually authenticate, enforced via
  `session-bind@openssh.com` — the client proves each hop with the host's
  own signature over the session id, so a malicious intermediate can't
  claim a path it never took.
- **Privilege separation (`shhd --privsep`)**: the host private key moves
  to a minimal signer subprocess forked before the daemon starts parsing
  any untrusted input, so a memory-disclosure bug in that parsing can't
  walk away with the key.

### FIDO2 security keys

- `sk-ssh-ed25519@openssh.com` accepted for login, both bare and
  CA-certified (`sk-ssh-ed25519-cert-v01@openssh.com`) — wire-compatible
  with OpenSSH in both directions. User presence is required; an assertion
  without it is refused.
- The client can present a **software-emulated** key (`shh-keygen -t
  ed25519-sk`) for testing and tokenless environments — explicitly not a
  substitute for real hardware, which needs an external authenticator
  helper not yet built.

### Certificates

- **Critical options**: `force-command` (pin a session to a fixed command
  regardless of what the client asked for) and `source-address` (CIDR-scope
  a certificate to specific client addresses) are now enforced, not just
  tolerated — any *other* critical option still fails closed.

### File transfer

- **SFTP v3** server and client, both interoperable with OpenSSH's real
  `sftp`/`sftp-server` in either direction. `shhd` runs the file server as
  the logged-in user, the same model as OpenSSH's `sftp-server`.

### Desktop GUI and Windows

- **`gui/`**: a Termius-style host manager and terminal (Tauri + xterm.js)
  built on the same library crate — saved hosts, generated/listed
  identities, one pty session per tab, sharing `~/.shh` with the CLI.
- **Native Windows client build**: `shh`, `shh-sftp`, and `shh-keygen`
  cross-compile and run on Windows behind a native console backend (raw
  mode, no-echo passphrase entry, window size), verified under Wine
  against a native Linux `shhd`. `shhd`/`shh-agent` stay Unix-only — their
  session model has no Windows equivalent short of a ConPTY rewrite.
- **`shhd --sandbox`**: beyond `--privsep`'s host-key isolation, drops the
  *entire* daemon to an unprivileged account once the port is bound and the
  signer forked, at the cost of every session sharing that one account —
  a fit for single-purpose servers, not multi-user login hosts.

### Also in this phase

- Fuzz targets (`fuzz/`) for every peer-controlled parser, plus an
  always-on `cargo test` version (`tests/parser_robustness.rs`) so the
  panic-free promise is checked on stable, not just under `cargo-fuzz`.
- A transport stress test that fragments the stream to one byte per read
  and freezes reads mid-packet, proving the incremental reader is
  cancel-safe and never desyncs.

---

## Core protocol — 2026-07-07

The foundation, built in one sustained run: a working SSH client and server
speaking a strict, modern subset of the protocol, interoperable with
OpenSSH from the very first milestone.

- **Wire, crypto, and transport**: bounds-checked panic-free parsing;
  hybrid ML-KEM-768 + X25519 key exchange (with plain X25519 as the only
  fallback); Ed25519 keys with OpenSSH file-format interop; AEAD-only
  packet ciphers (`chacha20-poly1305@openssh.com`,
  `aes256-gcm@openssh.com`); mandatory strict KEX (the Terrapin
  countermeasure, CVE-2023-48795, closed by construction rather than
  negotiated); automatic non-negotiable rekeying.
- **Auth and sessions**: public-key-only userauth with session-bound
  signatures; exec/shell channels with window flow control and exit-status
  reporting; a cancel-safe packet reader so channel pumps can `select!`
  freely. Verified against OpenSSH 9.6 in both directions from the start.
- **Interactive PTY sessions**: pty-req/window-change handling, a real
  controlling terminal server-side, local raw mode with restore-on-drop,
  `SIGWINCH` forwarded live. Encrypted key files (bcrypt-pbkdf +
  AES-256-CTR `openssh-key-v1`) compatible with `ssh-keygen` in both
  directions.
- **Port forwarding and multiplexing**: local (`-L`) and remote (`-R`)
  forwarding through a channel multiplexer with real per-channel flow
  control (send-window credit, consumption-driven receive-window
  replenishment). Sessions and any number of forwards ride one connection.
  Both forwarding kinds are default-deny server allowlists
  (`--permit-open`/`--permit-listen`) — the opposite of RFC 4254's
  open-by-default posture.
- **Certificate authentication**: CA-signed Ed25519 user *and host*
  certificates (`ssh-ed25519-cert-v01@openssh.com`), interoperable with
  `ssh-keygen`/OpenSSH both ways — host certificates let a client trust a
  CA instead of pinning a key per host in `known_hosts`.
- **Keep-alives**: `keepalive@openssh.com` probes after an idle interval,
  dropping a peer that leaves several unanswered — verified to detect a
  frozen (`SIGSTOP`) peer in ~4 seconds rather than hanging indefinitely.
- **Privilege drop**: when `shhd` runs as root, each session drops to the
  authenticated user's own account (uid, gid, supplementary groups, home,
  login shell) instead of running everything as root; an unknown login
  name is refused rather than run privileged.
