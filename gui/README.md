# SHH desktop GUI

A Termius-style host manager for SHH: a saved-host sidebar and a live
terminal, built on the `shh` library crate (the same authenticated-transport
and pty-session code the `shh` CLI uses) with a [Tauri](https://tauri.app)
shell and an xterm.js frontend.

Hosts and identities live in `~/.shh`, the same home the `shh`/`shhd`/
`shh-agent` binaries use — `~/.shh/known_hosts` and any key you already have
there are shared with the CLI.

## What it does

- **Hosts**: add/edit/delete saved connections (name, hostname, port, user,
  optional identity file); click one to open a session.
- **Terminal**: a real interactive pty per session (multiple tabs), keys and
  resizes forwarded live, exit status shown when the remote side closes.
- **Identities**: lists Ed25519 keys found in `~/.shh`, and can generate a
  new one (optionally passphrase-protected) the same way `shh-keygen` does.
- **Trust**: a new host's key is trusted on first connect and recorded to
  `~/.shh/known_hosts` (the CLI's `--accept-new` posture); a key that later
  changes is always refused — the connection fails with the mismatch instead
  of silently proceeding.

Not yet wired up here: certificates, agent forwarding, port forwarding, and
encrypted identities (an encrypted key needs a controlling terminal to
prompt for its passphrase, which a GUI-launched process doesn't have — use
an unencrypted key or `shh-agent` for now).

## Building

Needs Node.js and the [Tauri Linux prerequisites](https://v2.tauri.app/start/prerequisites/)
(`libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `librsvg2-dev`, build-essential).

```console
$ npm install
$ npm run tauri build      # release bundle (.deb/.AppImage/etc under src-tauri/target/release/bundle)
$ npm run tauri dev         # hot-reloading dev build
```

`npm run build` alone builds just the frontend into `dist/`; `cargo build
--release` in `src-tauri/` picks that up and compiles the desktop binary
without going through the `tauri` CLI, if you'd rather drive it directly.
