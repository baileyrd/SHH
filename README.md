# SHH

A from-scratch, modernized implementation of SSH in Rust. The RFCs
(4251–4254) are the baseline, not the contract: SHH speaks a strict modern
subset of SSH2 that interoperates with current OpenSSH while refusing to
speak anything weaker.

**What "modern" means here** (see [DESIGN.md](DESIGN.md) for every
deviation and its rationale):

- **Post-quantum by default** — hybrid ML-KEM-768 + X25519 key exchange
  (`mlkem768x25519-sha256`), with `curve25519-sha256` as the only fallback.
- **Ed25519 only** for host keys and user keys. No RSA, no ECDSA, no DSA.
- **AEAD only** — `chacha20-poly1305@openssh.com` and
  `aes256-gcm@openssh.com`. No CBC, no CTR+HMAC, no encrypt-and-MAC.
- **Strict KEX required** (the Terrapin countermeasure) — a peer without
  `kex-strict` is refused, not accommodated.
- **Public-key auth only.** Password and keyboard-interactive are not
  disabled; they are not implemented.
- **No compression, no SSH1, no rekey avoidance** (automatic rekey at
  1 GiB / 1 hour), `ext-info` (RFC 8308) supported.
- Memory-safe implementation, secrets zeroized on drop, constant-time
  comparisons, panic-free wire parsing, cancel-safe async I/O.

## Quick start

```console
$ cargo build --release

# generate a user key (or reuse an existing ~/.ssh/id_ed25519)
$ shh-keygen -f ~/.shh/id_ed25519 -C you@laptop

# server: authorize the key, then listen
$ cp ~/.shh/id_ed25519.pub ~/.shh/authorized_keys
$ shhd -L 127.0.0.1:2222        # host key generated on first run

# client: run a command
$ shh -p 2222 you@127.0.0.1 'uname -a'
```

`shh host cmd` behaves like `ssh`: stdin is forwarded, stdout/stderr come
back separated, and the remote exit status becomes `shh`'s exit status.
`shh host` with a terminal opens an interactive shell on a real
pseudo-terminal (raw mode locally, `TERM` and window size propagated,
resizes forwarded); `-t` forces a pty for commands, `-T` disables it.
Host keys are pinned in `~/.shh/known_hosts` — first contact prompts on the
terminal (or use `--accept-new`), and a changed key is a hard error.
Keys may be passphrase-protected (`shh-keygen -N`, prompted otherwise);
the format matches `ssh-keygen` (bcrypt + AES-256-CTR).

### Port forwarding

Local (`-L`) forwarding tunnels a local port to a target reachable from the
server. It runs alongside a session on the same connection, or on its own
with `-N`:

```console
# a dedicated tunnel (no remote command)
$ shh -N -L 8080:db.internal:5432 you@gateway

# a session and a tunnel over one connection, like OpenSSH
$ shh -L 8080:db.internal:5432 you@gateway 'tail -f /var/log/app.log'
```

The server refuses forwarding by default; an operator opts targets in
explicitly (the opposite of OpenSSH's default-open posture):

```console
$ shhd -L 0.0.0.0:2222 --permit-open db.internal:5432 --permit-open 127.0.0.1:*
# or --permit-open any to allow everything (trusted networks only)
```

Interoperates with OpenSSH both ways (`ssh -L … host cmd` through `shhd`,
`shh -L … host cmd` through `sshd`), session and forwards multiplexed on
one connection. Remote (`-R`) forwarding is not yet supported.

## Interoperability

Verified against OpenSSH 9.6 in both directions (`ssh → shhd` and
`shh → sshd`) over `curve25519-sha256` + `ssh-ed25519` +
`chacha20-poly1305@openssh.com` / `aes256-gcm@openssh.com`, with strict
KEX active. OpenSSH ≥ 9.9 also negotiates the post-quantum
`mlkem768x25519-sha256`; SHH↔SHH always uses it. Keys are standard
`openssh-key-v1` files: `ssh-keygen` and `shh-keygen` output is mutually
readable (unencrypted keys for now).

## Status

Transport, auth, exec sessions, interactive PTY sessions (pty-req,
window-change, controlling terminal), encrypted key files, and
`direct-tcpip` local (`-L`) port forwarding with a server-side allowlist —
all multiplexed so a session and any number of forwards share one
connection — are complete and tested (`cargo test`). Not yet implemented:
remote (`-R`) forwarding, FIDO2 `sk-ssh-ed25519` keys, certificates,
sshd-style privilege separation. Treat it as a working protocol
implementation, not a hardened production daemon.
