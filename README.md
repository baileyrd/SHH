# SHH

A from-scratch, modernized implementation of SSH in Rust. The RFCs
(4251–4254) are the baseline, not the contract: SHH speaks a strict modern
subset of SSH2 that interoperates with current OpenSSH while refusing to
speak anything weaker.

**What "modern" means here** (see [DESIGN.md](DESIGN.md) for every
deviation and its rationale):

- **Post-quantum by default** — hybrid ML-KEM-768 + X25519 key exchange
  (`mlkem768x25519-sha256`), with `curve25519-sha256` as the only fallback.
- **Ed25519 only** for host keys and user keys. No RSA, no ECDSA, no DSA —
  plus FIDO2 security keys (`sk-ssh-ed25519@openssh.com`), bare or
  CA-certified, for login.
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

### Platform support

The **clients** — `shh`, `shh-sftp`, `shh-keygen` — build and run on
**Windows, macOS, and Linux**: the protocol core is portable Rust, and the
console handling (no-echo passphrase entry, raw mode, terminal size) has a
native backend per platform. The **server** `shhd` and the key agent
`shh-agent` are **Unix only** — their session model (fork/setuid, ptys, a
Unix-socket agent with peer-credential checks) has no Windows equivalent
short of a ConPTY + named-pipe rewrite; on Windows they build as honest
"not supported here" stubs, not broken binaries. Agent auth on the Windows
client (OpenSSH's `\\.\pipe\openssh-ssh-agent`) is a planned follow-up; today
the Windows client uses key files.

The Windows client is cross-compiled (`--target x86_64-pc-windows-gnu`) and
verified end to end under Wine against a native Linux `shhd`: `shh.exe` runs
remote commands and `shh-sftp.exe` transfers files, over the full
post-quantum handshake.

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

SHH honors the validity window and principals, and enforces two critical
options: **`force-command`** pins the session to a fixed command whatever the
client requested (the client's command survives only as
`SSH_ORIGINAL_COMMAND`), and **`source-address`** refuses the certificate
from a client outside its CIDR list. Mint them with `shh-keygen -O`, exactly
like `ssh-keygen`:

```console
# this cert may only run the backup script, and only from the office subnet
$ shh-keygen -s ca_key -I alice -n deploy \
    -O force-command='/usr/local/bin/backup' \
    -O source-address='198.51.100.0/24' -f id_ed25519.pub
```

Any *other* critical option still fails closed (an unknown one denies the
cert). Verified against OpenSSH both ways — `ssh-keygen -L` prints ours,
OpenSSH `sshd` runs a `force-command` from a cert we signed, and `shhd`
honors one `ssh-keygen -s` signed.

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

### Security keys (FIDO2)

`shhd` accepts FIDO2 security keys — put an `sk-ssh-ed25519@openssh.com`
line in `authorized_keys` and a user logs in with their key. The server
verifies the authenticator's assertion and **requires user presence**; an
assertion without it is refused. The public-key encoding is byte-identical
to OpenSSH's (verified against `ssh-keygen`).

The `shh` client can present one too. The only authenticator it drives is
**software-emulated** (`shh-keygen -t ed25519-sk`) — the seed lives in the
key file, so it has *no hardware protection*; it is for testing and
tokenless environments, not a replacement for a real key. Its assertions
are cryptographically ordinary and verify anywhere:

```console
$ shh-keygen -t ed25519-sk -f ~/.shh/id_sk       # software-emulated
$ cat ~/.shh/id_sk.pub >> ~/.ssh/authorized_keys # on the server
$ shh -i ~/.shh/id_sk you@host uptime            # OpenSSH sshd accepts it too
```

A security key can be **certified** just like a bare key: sign its public
key with a CA and the server trusts it via `--trusted-ca-keys`, no
per-key `authorized_keys` entry needed. The certificate algorithm is
OpenSSH's `sk-ssh-ed25519-cert-v01@openssh.com`, so `shh-keygen` and
`ssh-keygen` issue and consume each other's sk certificates.

```console
$ shh-keygen -s user_ca -I river -n you -f ~/.shh/id_sk.pub  # writes id_sk-cert.pub
$ shh -i ~/.shh/id_sk you@host uptime                        # presents the cert
```

### File transfer (SFTP)

`shhd` serves the **SFTP** subsystem (version 3, the one OpenSSH speaks), and
`shh-sftp` is our matching client — either interoperates with the other side's
OpenSSH counterpart. Both do `put`, `get`, `ls`, `mkdir`, `rmdir`, `rm`,
`rename`:

```console
# our client, one command per invocation (composes in scripts)
$ shh-sftp -i ~/.shh/id you@host put report.pdf
$ shh-sftp -i ~/.shh/id you@host get logs/today.log
$ shh-sftp -i ~/.shh/id you@host ls /var/log

# or the standard OpenSSH sftp client against shhd
$ sftp -P 2222 -i ~/.shh/id you@host
sftp> put report.pdf
```

Like OpenSSH's `sftp-server`, `shhd` runs the file server as the logged-in
user (it re-execs itself in `--internal-sftp` mode through the same
privilege-drop path a shell takes), so ordinary filesystem permissions are
the boundary. The engine (`src/sftp/`) is a self-contained SFTP v3
implementation — both a server and a client half — verified against OpenSSH
in both directions: the real `sftp` client drives `shhd`, and `shh-sftp`
drives OpenSSH's `sftp-server` behind OpenSSH `sshd`.

Real hardware tokens (`ssh -i id_ed25519_sk` against a physical key) need
an external authenticator helper, which is not yet built.

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
onto each relayed agent connection, so the agent sees the whole route. A
destination may also name a **certificate authority** instead of a specific
host key — any host presenting a certificate that CA signed then matches,
so one pin covers a whole fleet:

```console
$ echo "@cert-authority *.corp $(cat host_ca.pub)" >> ~/.shh/known_hosts
$ shh-agent add -H gw.corp ~/.shh/id_ed25519   # pins to hosts under the corp CA
```

The constraint is OpenSSH's `restrict-destination-v00@openssh.com`, so
`ssh-add -h` writes constraints `shh-agent` enforces and vice versa —
endpoint pins, multi-hop paths, and CA-scoped destinations alike.

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

### Privilege separation

The daemon parses a lot of attacker-controlled data before anyone has
authenticated. `shhd --privsep` keeps the host private key out of that
blast radius: at startup it forks a minimal **signer** subprocess that
holds the key and answers only "sign this exchange hash", then drops its
own copy. Every key exchange (initial and each rekey) is signed through
the signer, so a memory-disclosure or code-execution bug in the daemon's
pre-auth parsing can't walk away with the host key.

```console
$ shhd -L 0.0.0.0:2222 --privsep            # signer runs as `nobody` under root
```

When `shhd` runs as root the signer drops to `--privsep-user` (default
`nobody`), sets `no_new_privs`, and clamps its resource limits to a bare
read/sign/write loop. (This isolates the *secret*; running the untrusted
pre-auth *parsing* in a separate sandboxed process is the next step.)

### Desktop GUI

A Termius-style host manager and terminal — saved hosts, generated/listed
identities, a live pty session per tab — lives in [`gui/`](gui/README.md),
built on this same library crate.

```console
$ cd gui && npm install && npm run tauri dev
```

## Interoperability

Verified against OpenSSH 9.6 in both directions (`ssh → shhd` and
`shh → sshd`) over `curve25519-sha256` + `ssh-ed25519` +
`chacha20-poly1305@openssh.com` / `aes256-gcm@openssh.com`, with strict
KEX active. OpenSSH ≥ 9.9 also negotiates the post-quantum
`mlkem768x25519-sha256`; SHH↔SHH always uses it. Keys are standard
`openssh-key-v1` files: `ssh-keygen` and `shh-keygen` output is mutually
readable, including passphrase-protected keys (bcrypt + AES-256-CTR).

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
pinned to specific hosts, whole paths, or a certificate authority
(`shh-agent add -H gw>prod`, enforced via `session-bind@openssh.com` /
`restrict-destination-v00`). Privilege separation (`shhd --privsep`) holds
the host key in a separate signer subprocess, out of the pre-auth parser's
reach; `--sandbox` goes further and drops the whole parsing daemon to an
unprivileged account after binding the port and forking the signer, so all
untrusted parsing runs without privilege or the key (at the cost of running
sessions as that one account — for single-purpose servers, not multi-user
login hosts). FIDO2 security keys (`sk-ssh-ed25519@openssh.com`) work both ways —
`shhd` verifies them, `shh` can present a software-emulated one, and they
can be CA-certified (`sk-ssh-ed25519-cert-v01@openssh.com`, interop-verified
with `ssh-keygen` and OpenSSH `sshd` in both directions). User certificates
enforce the `force-command` and `source-address` critical options (and fail
closed on any other). File transfer works: `shhd` serves the **SFTP v3**
subsystem to the standard `sftp` client (running the file server as the
logged-in user, like OpenSSH's `sftp-server`), and `shh-sftp` is a matching
client that also drives OpenSSH's `sftp-server`. Not
yet implemented: real-hardware FIDO2
on the client (needs an external
authenticator helper) and the fuller privsep model that also sandboxes the
pre-auth *parsing* in its own unprivileged process. Treat it as a working
protocol implementation, not a hardened production daemon.
