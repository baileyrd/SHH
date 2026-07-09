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
window covers now and whose principals include the login name. We fail
closed on unrecognized critical options, and host certificates plus
`force-command` / `source-address` are not yet honored. FIDO2 hardware
security keys (`sk-ssh-ed25519@openssh.com`) are accepted too: the server
verifies the authenticator's assertion — an Ed25519 signature over
`SHA256(application) ‖ flags ‖ counter ‖ SHA256(signed-data)` — and
refuses one that does not assert user presence. Producing an assertion
needs the physical key and is a client concern; `shhd` implements the
verification a server needs (an OpenSSH `ssh -i id_ed25519_sk` logs in).

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
  never desyncs.

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
├── src/connect/     channels, session (exec/shell), flow control
├── src/bin/shh.rs   client
├── src/bin/shhd.rs  server
├── tests/           integration + parser-robustness tests (`cargo test`)
└── fuzz/            cargo-fuzz targets for the peer-controlled parsers
```

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
    attack surface is almost nil. Remaining: client-side FIDO2 signing (the
    server side is done — see the auth section), and the fuller monitor
    model where the untrusted pre-auth *parsing* itself runs in a separate
    sandboxed unprivileged process (with a post-auth per-user session
    handed off from it) — this milestone moves the secret out of harm's way
    but still parses in the main daemon.
