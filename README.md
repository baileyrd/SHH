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
  comparisons, panic-free wire parsing, cancel-safe async I/O — the last two
  backed by `cargo-fuzz` targets (`fuzz/`), an always-on parser-robustness
  test, and a transport test that fragments the stream to one byte per read.

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

### Certificates

Instead of listing every key in `authorized_keys`, a server can trust a
certificate authority and accept any Ed25519 user certificate it signed —
scoped by a validity window and a principal (login-name) list. The format
is OpenSSH's `ssh-ed25519-cert-v01@openssh.com`, so `shh-keygen` and
`ssh-keygen` issue and consume each other's certificates.

```console
# a CA signs a user's key for principal "deploy", valid 90 days
$ shh-keygen -s ca_key -I alice@corp -n deploy --days 90 -f id_ed25519.pub
# writes id_ed25519-cert.pub

# server: trust the CA (authorized_keys can be empty)
$ shhd --trusted-ca-keys /etc/shh/user_ca.pub --user deploy

# client: the cert next to the key is presented automatically
$ shh -i id_ed25519 deploy@host uptime
```

SHH honors the validity window and principals and fails closed on any
critical option it doesn't implement. `force-command` / `source-address`
options are not yet honored.

**Host certificates** work the same way in reverse: a server presents a
CA-signed certificate as its host key, and the client verifies it against a
trusted CA and the hostname instead of pinning a key in `known_hosts`.

```console
# a host CA signs the server's host key for its hostnames
$ shh-keygen -s host_ca -H -I gw -n gateway.corp,10.0.0.1 -f host_key.pub
$ shhd --host-cert host_key-cert.pub          # or <host_key>-cert.pub auto

# client: trust the CA (no TOFU prompt, no per-host key churn)
$ echo "@cert-authority *.corp $(cat host_ca.pub)" >> ~/.shh/known_hosts
$ shh you@gateway.corp uptime
```

When no host certificate or CA is configured, host identity falls back to
`known_hosts` TOFU pinning, exactly as before.

### Key agent

`shh-agent` holds Ed25519 keys in one long-lived process and signs for
clients over a Unix socket, so private keys never enter short-lived client
processes. The protocol is the standard SSH agent protocol, so the pieces
are interchangeable with OpenSSH's: `ssh` and `ssh-add` work against
`shh-agent`, and `shh` uses any agent named by `SSH_AUTH_SOCK` — including
`ssh-agent`. Certificates ride along automatically (`<key>-cert.pub`), and
agent-held certificates are offered before bare keys.

```console
$ shh-agent &                       # serve on ~/.shh/agent.sock (0600)
SSH_AUTH_SOCK=/home/you/.shh/agent.sock; export SSH_AUTH_SOCK;
$ shh-agent add                     # add the default identity (+ cert)
$ shh you@host uptime               # signs via the agent — no key file read
$ shh-agent list                    # fingerprints, like ssh-add -l
$ shh-agent lock                    # identities vanish until unlock
```

The agent accepts only what it can fully honor: Ed25519 keys and
certificates, and the lifetime constraint (`add -t 3600`). Anything else —
legacy key types, confirm-per-use, unknown constraints or extensions — is
refused, never silently ignored. Connections from other uids are dropped,
and `shh --no-agent` forces key files even when an agent is running.

**Agent forwarding** (`-A`) relays agent connections from the server back
to the local agent, so a session can hop onward (`ssh`/`shh` from the
remote host) without any key ever leaving this machine:

```console
$ shh -A you@bastion            # remote processes see an SSH_AUTH_SOCK
bastion$ shh you@internal-host  # signs via YOUR local agent
```

Unlike OpenSSH, the server default is deny: `shhd` honors the request only
with `--permit-agent-forwarding`, the same posture as the `-L`/`-R`
allowlists. The per-session relay socket is owned by the session user and
checked by peer uid, a client that didn't pass `-A` refuses relay channels
outright, and forward it only to servers you trust — root there can use
(though never read) your keys while the session lasts.

To narrow that trust, **pin a key to the hosts it may authenticate to**:

```console
$ shh you@gateway              # record gateway's host key once
$ shh-agent add -H gateway ~/.shh/id_ed25519
added … restricted to gateway
$ shh -A you@gateway           # forward the agent onward
gateway$ shh you@prod          # REFUSED: key is pinned to gateway
```

The client binds each agent connection to the host it reached
(`session-bind@openssh.com`) — proving the hop with the host's own
signature over the session id — and the agent signs with a
destination-constrained key only when the proven path is allowed. So a
forwarded agent is no longer a blank cheque: a compromised intermediate
can use a pinned key toward its permitted host and nowhere else.

Chain hops with `>` to pin a **path** — the key reaches the far host only
*through* the named route, never directly:

```console
$ shh-agent add -H 'gateway>prod' ~/.shh/id_ed25519
$ shh -A you@gateway
gateway$ shh you@prod          # OK — reached prod via gateway
gateway$ shh you@other         # REFUSED — off the pinned path
```

For the path to be provable across a hop, `shh -A` replays its own binding
onto each relayed agent connection, so the agent sees the whole route. The
constraint is OpenSSH's `restrict-destination-v00@openssh.com`, so
`ssh-add -h` writes constraints `shh-agent` enforces and vice versa —
endpoint pins and multi-hop paths alike.

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
server; remote (`-R`) forwarding is the reverse — the server listens and
forwards connections back to a target reachable from the client. Either
runs alongside a session on the same connection, or on its own with `-N`:

```console
# local: localhost:8080 -> db:5432 (reachable from the server)
$ shh -N -L 8080:db.internal:5432 you@gateway

# remote: gateway:9000 -> localhost:3000 (reachable from here)
$ shh -N -R 9000:localhost:3000 you@gateway

# a session and a tunnel over one connection, like OpenSSH
$ shh -L 8080:db.internal:5432 you@gateway 'tail -f /var/log/app.log'
```

The server refuses forwarding by default; an operator opts in explicitly
(the opposite of OpenSSH's default-open posture) — `--permit-open` for `-L`
targets, `--permit-listen` for `-R` binds:

```console
$ shhd -L 0.0.0.0:2222 \
       --permit-open db.internal:5432 --permit-open 127.0.0.1:* \
       --permit-listen 127.0.0.1:9000
# `any` on either flag allows everything (trusted networks only)
```

Interoperates with OpenSSH both ways for `-L` and `-R` (`ssh -L/-R … host`
through `shhd`, `shh -L/-R … host` through `sshd`), sessions and forwards
multiplexed on one connection.

## Interoperability

Verified against OpenSSH 9.6 in both directions (`ssh → shhd` and
`shh → sshd`) over `curve25519-sha256` + `ssh-ed25519` +
`chacha20-poly1305@openssh.com` / `aes256-gcm@openssh.com`, with strict
KEX active. OpenSSH ≥ 9.9 also negotiates the post-quantum
`mlkem768x25519-sha256`; SHH↔SHH always uses it. Keys are standard
`openssh-key-v1` files: `ssh-keygen` and `shh-keygen` output is mutually
readable (unencrypted keys for now).

## Status

Transport, auth (keys and CA-signed user certificates, from files or an
agent), host certificates, exec sessions, interactive PTY sessions
(pty-req, window-change, controlling terminal), encrypted key files, local
(`-L`) and remote (`-R`) TCP forwarding with server-side allowlists, and
connection keep-alives — all multiplexed so a session and any number of
forwards share one connection — are complete and tested (`cargo test`).
Keep-alives probe an idle peer (`keepalive@openssh.com`) and drop it after
several unanswered probes (`--keepalive-interval` / `--keepalive-count`,
on by default). When `shhd` runs as root it drops each session to the
authenticated user's account — uid, gid, supplementary groups, home
directory, and login shell — so a session is never more privileged than
the account that logged in; an unknown login name is refused. `shh-agent`
is a drop-in, Ed25519-only `ssh-agent` (interop verified with `ssh-add`
and `ssh` both ways), agent forwarding (`-A`, server default-deny via
`--permit-agent-forwarding`) relays it across hops, and agent keys can be
pinned to specific destination hosts or whole paths (`shh-agent add -H
gw>prod`, enforced via `session-bind@openssh.com` /
`restrict-destination-v00`). Not yet implemented: FIDO2 `sk-ssh-ed25519`
keys and a sandboxed pre-auth process (privilege *separation*, distinct
from the privilege *drop* above). Treat it as a working protocol
implementation, not a hardened production daemon.
