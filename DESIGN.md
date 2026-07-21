# SHH — Design

SHH is a from-scratch implementation of the SSH protocol in Rust, using the SSH
RFCs (4251–4254 and successors) as a *baseline* rather than a contract. Where
the RFCs permit legacy weight, we cut it; where modern practice has moved past
them, we follow modern practice. The result speaks a strict, modern subset of
SSH2 that interoperates with current OpenSSH, while refusing to speak anything
weaker.

## Goals

1. **Modern crypto only.** There is no algorithm-agility escape hatch into the
   past. If a peer cannot meet the floor, the connection fails.
2. **Post-quantum by default.** Hybrid ML-KEM-768 + X25519 key exchange is the
   preferred KEX, matching current OpenSSH deployment.
3. **Small, auditable core.** One library crate, three protocol layers, no
   optional features that multiply the state space.
4. **Interoperable with the modern subset.** A current OpenSSH client can talk
   to `shhd`, and `shh` can talk to a current `sshd` — using only the
   algorithms below.

## What we keep from the RFCs

- The three-layer architecture: transport (RFC 4253), user authentication
  (RFC 4252), connection/channels (RFC 4254).
- The binary packet protocol framing, message numbers, and name-list
  negotiation — this is what buys interoperability.
- The RFC 4253 §7.2 key derivation (HASH(K || H || letter || session_id)).
- Channel flow control (window/adjust) exactly as specified.

## Where we deviate — and why

### Key exchange
| Offered | Basis |
|---|---|
| `mlkem768x25519-sha256` | ML-KEM-768 (FIPS 203) hybrid with X25519, as deployed in OpenSSH 9.9+ |
| `curve25519-sha256` | RFC 8731 |

Nothing else. No `diffie-hellman-group14-sha256` (finite-field DH is slow and
has no future), no group-exchange (RFC 4419 adds a negotiation round-trip and
historical weaknesses), no NIST curves (implementation-hostile, no benefit
over X25519).

**Strict KEX is mandatory.** We always advertise
`kex-strict-{c,s}-v00@openssh.com` and enforce its rules (no unexpected
packets during KEX, sequence numbers reset on NEWKEYS). This closes the
Terrapin attack (CVE-2023-48795) by construction. The RFCs treat message
injection tolerance during KEX as a feature; we treat it as a bug.

### Host keys and user keys
`ssh-ed25519` (RFC 8709) only, plus its certificate form
(`ssh-ed25519-cert-v01@openssh.com`) as a host-key algorithm when a host
certificate is in use. RSA drags in SHA-1 legacy and key-size negotiation;
ECDSA has nonce-reuse fragility; DSA is dead. Ed25519 signatures are
deterministic, fast, small, and misuse-resistant. A client offers the
certificate host-key algorithm only when it has trusted host CAs, so a
plain-key TOFU handshake is byte-for-byte what it was before certificates
existed.

### Ciphers — AEAD only, MACs are vestigial
`chacha20-poly1305@openssh.com` and `aes256-gcm@openssh.com`. No CBC (padding
oracles: RFC 4253's own cipher list is a museum of CVEs), no CTR+HMAC
(encrypt-and-MAC as specified in RFC 4253 authenticates the *plaintext*, a
design error the AEAD modes fix). Because both ciphers are AEAD, the
negotiated MAC list is wire-filler; we send a fixed list and ignore it, as
OpenSSH does for these ciphers.

### Compression: removed
RFC 4253 makes zlib optional; OpenSSH defaults it off. Compression of
attacker-influenceable plaintext before encryption is a CRIME-class oracle,
and post-AEAD it buys nothing. We offer and accept only `none`.

### Authentication: public key only
RFC 4252's `password` method ships plaintext passwords inside the tunnel and
trains users to type secrets into prompts; `keyboard-interactive` is the same
with more steps. Neither is implemented — not disabled, *not present*.
`publickey` with Ed25519 keys is the only method. The signature is computed
over the session identifier exactly per RFC 4252 §7, binding auth to the
channel. Both bare keys and OpenSSH-style Ed25519 user certificates
(`ssh-ed25519-cert-v01@openssh.com`) are accepted: a server may trust a CA
(`--trusted-ca-keys`) and admit any certificate it signed whose validity
window covers now and whose principals include the login name. Two critical
options are enforced: `force-command` pins the session to a fixed command
regardless of what the client asks (the client's request survives only as
`SSH_ORIGINAL_COMMAND`), and `source-address` refuses the certificate from a
client whose address falls outside its CIDR list — an unknown client address
fails that check closed. We still fail closed on *any other* critical option
(an unknown one denies the cert), and host certificates are not honored.
FIDO2 security
keys (`sk-ssh-ed25519@openssh.com`) are supported both ways: the server
verifies the authenticator's assertion — an Ed25519 signature over
`SHA256(application) ‖ flags ‖ counter ‖ SHA256(signed-data)` — and
refuses one that does not assert user presence, and the client can present
one. Client-side, the only authenticator implemented is
*software-emulated* (`shh-keygen -t ed25519-sk`): the seed lives in the
key file rather than a tamper-resistant chip, so it has no hardware
protection — a convenience for testing and tokenless environments, not a
substitute for a real key. The assertions it produces are cryptographically
ordinary and verify anywhere, including under OpenSSH `sshd`. Real hardware
belongs behind an external authenticator helper, which is not yet built.

A security key can also be *certified*: the certificate form
(`sk-ssh-ed25519-cert-v01@openssh.com`) is the plain Ed25519 certificate
with one extra field — the credential's application string, sitting right
after the certified public point — so the CA vouches for the security key
just as it would a bare key. We keep the certified point and that
application together, and reconstruct the security-key credential when
checking the userauth signature: the assertion must verify (user presence
and all) against the *certified* key, and the CA must be trusted. `shh`
presents an `<identity>-cert.pub` beside an sk key, and `shh-keygen -s`
signs an sk public key into one. The wire format matches OpenSSH exactly in
both directions — `ssh-keygen -L` reads our certs, our parser reads
`ssh-keygen -s`'s, and OpenSSH `sshd` with `TrustedUserCAKeys` accepts a
certificate we minted over an assertion our client produced.

The private key may live in an agent instead of the client process:
`shh` signs through whatever `SSH_AUTH_SOCK` names, and `shh-agent` is our
own agent — protocol-compatible with OpenSSH's in both directions, but
Ed25519-only and fail-closed (see milestones 7–9). Client-side, an agent
identity is offered certificate-first, and any identity type we don't
speak is skipped rather than negotiated down. An agent key can be pinned
to specific destination hosts (milestone 9), and `shh` binds each agent
connection to the host it reached (`session-bind@openssh.com`) so that
pinning is enforceable.

### Rekeying
Automatic and non-negotiable: rekey after 1 GiB of traffic in either
direction or 1 hour, whichever comes first. RFC 4253 recommends this;
we enforce it.

### Extension negotiation
`ext-info` (RFC 8308) is supported; we send `server-sig-algs` listing
`ssh-ed25519`.

### Other cuts
- No SSH1 compatibility of any kind, including the version-string dialects.
- No `none` cipher, no `none` auth success path.
- TCP forwarding uses explicit server allowlists (`--permit-open` for `-L`
  targets, `--permit-listen` for `-R` binds; both default deny) rather than
  RFC 4254's open-by-default posture, where any authenticated user may open
  a forward to any address or make the server listen on any port.
- Random packet padding is always fresh CSPRNG output (RFC 4253 merely
  suggests randomness).

## Engineering posture

- **Rust, tokio.** Memory safety for a protocol whose C implementations have
  a long CVE history; structured async for connection handling.
- **Secrets hygiene.** All key material is wrapped in `zeroize`-on-drop
  types; secret comparisons go through `subtle`.
- **Audited primitives.** RustCrypto (`ml-kem`, `chacha20poly1305`,
  `aes-gcm`, `sha2`) and dalek (`x25519-dalek`, `ed25519-dalek`) crates.
- **Testing.** Unit tests per layer, end-to-end `shh`↔`shhd` tests over
  localhost, and interop tests against OpenSSH where available. Wire parsers
  are written to be fuzzable (no panics on arbitrary input): every
  peer-controlled parser has a `cargo-fuzz` target under `fuzz/` (KEXINIT,
  certificates, key files, Ed25519 blobs, the wire cursor), and the same
  panic-free promise is checked on stable in ordinary `cargo test` by
  `tests/parser_robustness.rs`, which hammers each parser with random and
  near-valid (mutated) input. The transport reader is exercised under
  pathological byte fragmentation — a `Dribble` adapter that hands over one
  byte per poll, plus a metered-input test that freezes `recv_raw`
  mid-packet and drops it to prove the incremental reader is cancel-safe and
  never desyncs. Concurrency- and timing-sensitive fixes (channel-window
  accounting, admission control, connect timeouts) get a test that exercises
  the actual failure mode — a task genuinely blocked, a semaphore genuinely
  drained — not just the happy path; several use Tokio's virtual clock so
  they're deterministic instead of racing real wall-clock time or (as with
  outbound network timeouts) an outbound-routing setup that varies by
  environment.
- **Performance.** `benches/` holds two Criterion suites: raw AEAD
  `seal`/`open` throughput per cipher, and end-to-end bulk-transfer
  throughput through the full client/server stack over an in-memory pipe
  (isolating the implementation's own CPU-bound overhead — allocation,
  packet framing, window bookkeeping — from real network conditions). See
  `benches/README.md`. Not run as part of `cargo test` (a `harness = false`
  Criterion binary run under `cargo test` executes a full measurement pass
  rather than being skipped) — run by hand with `cargo bench`.
- **Hardening.** CHANNEL_WINDOW_ADJUST and the initial channel window are
  clamped to what the send-credit semaphore can hold, so a peer can't panic
  the process with an oversized value; a rekey must present the same host
  key the session was established with, so a TOFU verifier never re-fires
  mid-session; outbound connects and the accept-time admission queue for
  new channels are both bounded, so a stalled peer or a flood of opens to
  unreachable targets can't grow memory or file-descriptor usage without
  limit.

## Crate layout

```
shh/                 one library crate
├── src/wire/        SSH primitives (string, mpint, name-list), packet framing
├── src/crypto/      KEX, keys (Ed25519, security-key, certs), ciphers, KDF
├── src/transport/   version exchange, negotiation, KEX state machine,
│                    encrypted packet stream, rekeying
├── src/auth/        userauth (publickey), local keys or via agent
├── src/agent/       SSH agent protocol: client, Ed25519 keyring server
├── src/privsep.rs   host-key signer subprocess (privilege separation)
├── src/connect/     channels, session (exec/shell/subsystem), flow control
├── src/sftp/        SFTP v3 protocol: server engine + client engine
├── src/client.rs    shared dial-and-auth flow for the client binaries
├── src/bin/shh.rs   client (shell/exec/forwarding)
├── src/bin/shh-sftp file-transfer client
├── src/bin/shhd.rs  server
├── tests/           integration + parser-robustness tests (`cargo test`)
├── benches/         Criterion benchmarks (`cargo bench`)
└── fuzz/            cargo-fuzz targets for the peer-controlled parsers
```

### Portability

The protocol core — `crypto`, `transport`, `wire`, `auth`, `agent`, and the
channel `connect` machinery — is platform-neutral Rust. Platform-specific
code is confined and cfg-gated: `tty` has a Unix (`/dev/tty` + termios) and a
Windows (console API) backend behind one facade; `sftp::server`, `privsep`,
and the session server (fork/setuid/ptys) are `#[cfg(unix)]`; the agent's
Unix-socket transport is gated while its protocol is shared. So the **client**
binaries (`shh`, `shh-sftp`, `shh-keygen`) compile and run on Windows, macOS,
and Linux, while the **server** and **agent** are Unix, building as explicit
stubs elsewhere. The Windows client is cross-built and exercised under Wine
against a native Linux `shhd`.

## Milestones

1. **End to end (done).** `shh user@host cmd` against `shhd`:
   version exchange → hybrid PQ KEX → Ed25519 host key verify → publickey
   auth → exec, stdout/stderr/exit-status back. Known-hosts pinning (TOFU).
2. **Interactive sessions (done).** PTY allocation with controlling
   terminal, raw client mode, window-change on SIGWINCH, and
   passphrase-protected key files (bcrypt + AES-256-CTR, `ssh-keygen`
   compatible in both directions).
3. **Port forwarding (done).** Local `direct-tcpip` (`-L`) and remote
   `forwarded-tcpip` / `tcpip-forward` (`-R`) forwarding through the channel
   multiplexer, each behind a default-deny server allowlist (`--permit-open`
   for `-L` targets, `--permit-listen` for `-R` binds) rather than RFC
   4254's open-by-default posture. Sessions and forwards are both
   multiplexer channels, so any mix of them rides one connection — a
   foreground session tears everything down on exit, matching OpenSSH.
4. **Certificate auth (done).** CA-signed Ed25519 user *and host*
   certificates (`ssh-ed25519-cert-v01@openssh.com`): `shh-keygen -s`
   issues them (`-H` for host certs), `shhd --trusted-ca-keys` / `shh
   --trusted-cas` trust user CAs, `shhd --host-cert` presents a host cert,
   and `shh` verifies it against `@cert-authority` / `--host-ca` CAs instead
   of TOFU. Interoperable with `ssh-keygen` / OpenSSH both ways.
5. **Keep-alives (done).** Both sides send `keepalive@openssh.com` global
   requests after a configurable idle interval and drop a peer that leaves
   several unanswered, keeping NAT state warm and surfacing dead
   connections instead of hanging.
6. **Privilege drop (done).** When `shhd` runs as root it resolves the
   authenticated login name in the password database and drops each
   session to that account — gid, supplementary groups, then uid, in a
   single post-fork hook that also sets `HOME`/`USER`/`SHELL`, changes to
   the home directory, and runs the login shell. An unknown user is
   refused rather than run as root.
7. **Key agent (done).** `shh-agent` speaks the standard SSH agent
   protocol (draft-miller-ssh-agent) on a Unix socket, so it is
   interchangeable with `ssh-agent`: OpenSSH's `ssh`/`ssh-add` drive it,
   and `shh` uses whatever `SSH_AUTH_SOCK` names (certificates offered
   before bare keys, non-Ed25519 identities skipped). The store is
   Ed25519-only and fails closed on everything it cannot fully honor:
   legacy key types, a public half that does not match the private seed,
   the confirm-per-use constraint (we will not pretend to prompt), and
   unknown constraints or extensions are all refused, not ignored. Lock
   hides identities behind a constant-time passphrase check; the lifetime
   constraint expires keys server-side. Connections are accepted only
   from the agent's own uid (`SO_PEERCRED`), the socket is 0600 inside a
   0700 directory, and seeds are zeroized wherever they pass.
8. **Agent forwarding (done).** `shh -A` asks the server to relay agent
   connections back over the connection (`auth-agent-req@openssh.com` /
   `auth-agent@openssh.com`, the OpenSSH extension). Both defaults are
   *off*: the client never offers its agent unasked, and `shhd` refuses
   the request without `--permit-agent-forwarding` — agent forwarding is
   a third forwarding kind behind the same default-deny posture as `-L`
   and `-R`. Server-side, each session gets a fresh socket in a 0700
   directory owned by the session user, guarded by an `SO_PEERCRED` uid
   check (not just file modes), torn down with the session. A client that
   did not send `-A` refuses `auth-agent` channel opens outright, and the
   daemon scrubs its own inherited `SSH_AUTH_SOCK` from session
   environments so an operator's agent can never leak into sessions.
9. **Agent key restriction (done).** A key held in `shh-agent` can be
   pinned to the hosts it may authenticate to (`shh-agent add -H
   [user@]host`), so a forwarded agent is no longer a blank cheque a
   compromised intermediate can spend anywhere. The mechanism is
   OpenSSH's: the client binds each agent connection to the host it
   reached with `session-bind@openssh.com` — a host-key blob, the session
   id, and the host's signature over it — and the agent *verifies that
   signature* before recording the hop, so a malicious host cannot claim a
   path it never took. At sign time a destination-constrained key is used
   only if the connection's proven binding chain is permitted by its
   `restrict-destination-v00@openssh.com` constraints; with no bindings, a
   constrained key does not sign at all (fail-closed). `shh` sends the
   binding before it uses any agent, so the restriction works whether the
   agent is ours or OpenSSH's, and our agent enforces constraints written
   by OpenSSH's `ssh-add -h` (verified against the captured wire format).
   Both endpoint pins (`local → host`) and multi-hop *paths*
   (`local → gw → prod`, so a key reaches `prod` only *through* `gw`,
   never directly) are enforced: the agent checks every hop of the
   connection's binding chain against the constraint list, each hop
   reachable only from the one before it. For the chain to form through
   forwarding, the forwarder replays its own binding onto each relayed
   agent connection (`shh -A` does this), so the agent sees the whole
   route the request travelled. `shh-agent add -H gw>prod` expresses a
   path; repeating `-H` allows several destinations, matching `ssh-add
   -h`. A constraint hop may name a host key directly or a **certificate
   authority** (an `is_ca` entry): a host presenting a certificate that CA
   signed then matches, so a key can be pinned to "any host under this host
   CA" rather than an enumerated key list. `shh-agent -H` fills those in
   from `@cert-authority` lines in known_hosts, exactly as `ssh-add -h`
   does.
10. **Privilege separation — host-key isolation (done).** `shhd --privsep`
    keeps the host private key out of the process that parses untrusted
    network input. At startup — while still single-threaded, so `fork()`
    is safe — the daemon forks a minimal **signer** subprocess that holds
    the key and does nothing but answer "sign this exchange hash"; the
    parent zeroizes its copy and, for every key exchange (initial and each
    rekey), delegates the host-key signature to the signer over a
    socketpair. A memory-disclosure or code-execution bug in the daemon's
    pre-authentication parsing therefore can no longer exfiltrate the host
    key. When root, the signer drops to an unprivileged account
    (`--privsep-user`, default `nobody`), sets `no_new_privs`, and clamps
    its resource limits — its whole job is a read/sign/write loop, so its
    attack surface is almost nil.

    **`--sandbox` goes further:** once the privileged setup is done — binding
    the listen port (possibly < 1024), reading the host key, forking the
    signer — the daemon *itself* drops to the unprivileged account and sets
    `no_new_privs`, so from then on **every byte of untrusted parsing runs
    without privilege and without the host key**. A memory-safety compromise
    of the parser now yields only that unprivileged account — not root, not
    the key, and (the signer being a separate address space) not a signing
    oracle beyond what the live socket already allows. The trade-off is that
    sessions run as that one account rather than as each authenticated user,
    so `--sandbox` suits single-purpose servers (a git or SFTP endpoint, a
    bastion) rather than multi-user login hosts. Remaining: real-hardware
    FIDO2 on the client (a software-emulated security key works today — see
    the auth section — but a physical token needs an external authenticator
    helper), and OpenSSH's full monitor model, where the parser runs in a
    *per-connection* sandboxed child and a privileged monitor hands back a
    session running as *each authenticated user* — the step past `--sandbox`,
    which removes privilege from the parser but gives up per-user sessions to
    do it. That handoff needs the monitor to re-verify authentication and pass
    session descriptors back to the parser; it is not built yet.
11. **FIDO2 security keys (done).** `sk-ssh-ed25519@openssh.com` credentials
    authenticate both ways. Server-side, `shhd` verifies the authenticator's
    assertion — an Ed25519 signature over `SHA256(application) ‖ flags ‖
    counter ‖ SHA256(signed-data)` — and refuses one that does not assert
    user presence, so an unattended replay is rejected even when the maths
    checks out. Client-side, `shh-keygen -t ed25519-sk` mints a
    *software-emulated* key: the seed lives in the key file, not a
    tamper-resistant chip, so it carries no hardware protection (a
    convenience for testing and tokenless CI, not a substitute for a token),
    but the assertions it produces are cryptographically ordinary and verify
    under OpenSSH `sshd`. `shh` prompts for presence before signing. The
    certificate form (`sk-ssh-ed25519-cert-v01@openssh.com`) is supported
    too: it is the Ed25519 certificate with the credential's application
    string appended after the certified point, so a CA can vouch for a
    security key; `shh-keygen -s` signs one, `shh` presents an
    `<identity>-cert.pub`, and the server verifies the assertion against the
    *certified* key. Wire-compatible with OpenSSH in both directions —
    `ssh-keygen -L` reads our sk certs and ours reads its, and OpenSSH `sshd`
    with `TrustedUserCAKeys` accepts a cert we minted over an assertion our
    client produced. Real hardware belongs behind an external authenticator
    helper, which is not yet built.
12. **Certificate critical options (done).** Two of OpenSSH's user-cert
    critical options are now enforced, not just tolerated. `force-command`
    pins every session to a fixed command whatever the client requested —
    the client's own command survives only as `SSH_ORIGINAL_COMMAND`, the way
    OpenSSH exposes it — so a certificate can grant "this key may only run the
    backup script." `source-address` scopes a certificate to a CIDR list: a
    client whose address is outside the ranges is refused at authentication,
    and an *unknown* client address (no peer info) fails the check closed
    rather than being waved through. Negated entries (`!10.9.9.9`) and
    IPv4-mapped IPv6 peers are handled as OpenSSH's `addr_match_cidr_list`
    does. `shh-keygen -O force-command=… -O source-address=…` mints them,
    mirroring `ssh-keygen -O`, and any *other* critical option still fails
    closed. Verified against OpenSSH both ways: `ssh-keygen -L` prints our
    options, OpenSSH `sshd` runs a `force-command` from a cert we signed, and
    our `shhd` honors a `force-command` cert `ssh-keygen -s` signed.
13. **SFTP (done).** The SSH File Transfer Protocol, version 3 (the
    version OpenSSH speaks by default), rides a session channel: the client
    sends a `subsystem` request naming `sftp`, and the channel then carries
    length-prefixed SFTP packets. `shhd` serves it exactly as OpenSSH does —
    by re-execing itself in `--internal-sftp` mode through the same
    privilege-drop path a shell takes, so the file server runs as the
    logged-in user with no path sandbox beyond ordinary filesystem
    permissions (`sftp-server`'s model). The engine (`src/sftp/`) is
    transport-agnostic: a `server::run` loop and a `client::Client` over any
    async reader/writer, so it is unit-tested end to end over an in-memory
    pipe with no SSH at all. Operations implemented: open/read/write/close,
    opendir/readdir, stat/lstat/fstat, setstat/fsetstat (size, mode, times),
    mkdir/rmdir/remove/rename, realpath, readlink/symlink. A certificate
    `force-command` denies the subsystem (fail-closed: "only this command"
    means only that command). Verified against OpenSSH both ways — the real
    `sftp` client drives our `shhd` (put/get/ls/mkdir/rename/rm), and
    `shh-sftp` (our client) drives OpenSSH's `sftp-server` behind OpenSSH
    `sshd`. The dial-and-auth flow shared by `shh` and `shh-sftp` now lives in
    `src/client.rs`, and a client opens any subsystem channel through
    `connect::client_subsystem`.
14. **Desktop GUI and a native Windows client (done).** A Tauri +
    xterm.js host manager (`gui/`) built on this same library crate —
    saved hosts, generated/listed identities, one pty session per tab —
    sharing `~/.shh` with the CLI binaries. Alongside it, the client
    binaries (`shh`, `shh-sftp`, `shh-keygen`) gained a native Windows
    console backend (raw mode, no-echo passphrase entry, window size) behind
    the same `tty` facade Unix uses, cross-built and verified under Wine
    against a native Linux `shhd`. `shhd --sandbox` also landed here:
    beyond `--privsep`'s host-key isolation, it drops the *whole* daemon to
    an unprivileged account once the port is bound and the signer forked,
    at the cost of running every session as that one account rather than
    per authenticated user — see the privilege-separation milestone above.
15. **Adversarial self-review (ongoing).** Repeated rounds of targeted
    review across the whole tree, each fix backed by a test that exercises
    the actual failure mode rather than just the happy path. Highlights:
    channel window/admission accounting hardened against a peer that opens
    channels or grants window credit faster than they're serviced (bounded
    connects, a `MAX_CHANNELS` cap, a `Semaphore`-close on teardown so a
    blocked task unblocks instead of leaking); the agent's lock passphrase
    and destination-constraint checks tightened (constant-time comparison
    that doesn't leak length via timing, a length cap enforced on both the
    lock and unlock paths so the two can never disagree); the GUI's saved-host
    storage hardened against control-character/known_hosts injection, on
    both the save path and on load from disk; and project process
    formalized (`SECURITY.md`, `CONTRIBUTING.md`, CI across three OSes plus
    a GUI build, Dependabot). See [RELEASE_NOTES.md](RELEASE_NOTES.md) for
    the detailed, dated history.
