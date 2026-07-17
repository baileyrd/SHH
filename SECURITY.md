# Security Policy

SHH is a from-scratch SSH implementation handling cryptographic key
material, network-facing parsing, and privileged operations (`shhd`
listens on a network socket and can drop privileges from root). Security
issues are taken seriously and a private report is always preferred over
a public issue for anything that looks exploitable.

## Reporting a vulnerability

Please report suspected vulnerabilities privately using [GitHub's Security
Advisories](https://github.com/baileyrd/SHH/security/advisories/new) for
this repository ("Report a vulnerability" under the Security tab). This
opens a private discussion with maintainers before any details become
public.

Please include, where relevant:

- The affected component (e.g. `shhd`, `shh-agent`, the SFTP server, the
  GUI) and version/commit.
- A description of the issue and its impact.
- Steps to reproduce, or a proof-of-concept if you have one.

## Scope

In scope: the wire protocol implementation (`src/transport`,
`src/connect`, `src/crypto`, `src/sftp`, `src/agent`), the CLI binaries
(`shh`, `shhd`, `shh-keygen`, `shh-agent`, `shh-sftp`), privilege
separation (`src/privsep.rs`), and the desktop GUI (`gui/`).

Out of scope: issues that require an attacker to already control the
local user account the process runs as (SHH's threat model, like
OpenSSH's, does not attempt to defend against a fully compromised local
account), and vulnerabilities in third-party dependencies that don't
have a SHH-specific exploitation path (please report those upstream, and
feel free to also flag them here so they can be tracked).

## Response

There's no formal SLA, but reports will be acknowledged and triaged as
promptly as possible. A fix is typically released before any public
disclosure of the details.
