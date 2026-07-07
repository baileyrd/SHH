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
`ssh-ed25519` (RFC 8709) only. RSA drags in SHA-1 legacy and key-size
negotiation; ECDSA has nonce-reuse fragility; DSA is dead. Ed25519 signatures
are deterministic, fast, small, and misuse-resistant.

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
channel. (Planned: `sk-ssh-ed25519@openssh.com` FIDO2 keys and OpenSSH-style
certificates.)

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
  are written to be fuzzable (no panics on arbitrary input).

## Crate layout

```
shh/                 one library crate
├── src/wire/        SSH primitives (string, mpint, name-list), packet framing
├── src/crypto/      KEX, host keys, AEAD cipher bindings, KDF
├── src/transport/   version exchange, negotiation, KEX state machine,
│                    encrypted packet stream, rekeying
├── src/auth/        userauth (publickey)
├── src/connect/     channels, session (exec/shell), flow control
├── src/bin/shh.rs   client
└── src/bin/shhd.rs  server
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
4. Keep-alives, `sk-ssh-ed25519` FIDO2 keys, certificates, agent protocol,
   hardened privilege separation in `shhd`.
