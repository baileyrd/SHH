//! Privilege separation: keep the host private key out of the process that
//! parses untrusted network input.
//!
//! `shhd` parses a great deal of attacker-controlled data before a peer has
//! authenticated — version strings, KEXINIT, key-exchange blobs, public keys
//! and certificates. A memory-disclosure or code-execution bug there would,
//! in a monolithic daemon, hand over the host private key (and, running as
//! root, the machine). Privilege separation splits the key off: a tiny
//! **signer** subprocess holds the host key and does nothing but answer
//! "sign this exchange hash"; the main daemon delegates every host-key
//! signature to it and never holds the key itself.
//!
//! The signer is forked once at startup — deliberately *before* the async
//! runtime spawns any threads, so the `fork()` is single-threaded and safe —
//! and, when running as root, drops to an unprivileged account and tightens
//! its resource limits, shrinking its own attack surface to almost nothing
//! (a loop that reads a hash, signs it, and writes the signature back).
//!
//! What this does *not* yet do: run the pre-authentication parsing itself in
//! a separate, sandboxed, unprivileged process (OpenSSH's full monitor +
//! pre-auth child model). That is the remaining step; here the untrusted
//! parsing still runs in the main daemon — but a compromise there can no
//! longer exfiltrate the host key.

#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use crate::crypto::ed25519::PrivateKey;
use crate::transport::HostSigner;

/// A signature request is just the exchange hash; the reply is the signature
/// blob. Both are `u32`-length-framed. A hash is a SHA-256/512 digest, so
/// anything larger than this is a bug or an attack.
const MAX_MSG: usize = 4096;

/// A [`HostSigner`] that delegates to the signer subprocess over a
/// socketpair. Cloneable and shared across all connections; the mutex
/// serializes each request/reply round trip.
#[derive(Clone)]
pub struct MonitorSigner {
    sock: Arc<Mutex<UnixStream>>,
    public_blob: Vec<u8>,
}

impl HostSigner for MonitorSigner {
    fn public_blob(&self) -> Vec<u8> {
        self.public_blob.clone()
    }

    fn sign(&self, exchange_hash: &[u8]) -> Vec<u8> {
        match self.request(exchange_hash) {
            Ok(sig) => sig,
            Err(e) => {
                // The signer is gone or misbehaving. Returning an empty
                // signature makes the peer's verification fail and the
                // handshake abort — the safe outcome.
                tracing::error!("host-key signer request failed: {e}");
                Vec::new()
            }
        }
    }
}

impl MonitorSigner {
    fn request(&self, hash: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut sock = self.sock.lock().expect("signer socket poisoned");
        write_frame(&mut *sock, hash)?;
        read_frame(&mut *sock)
    }
}

fn write_frame(w: &mut impl Write, body: &[u8]) -> std::io::Result<()> {
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(body)?;
    w.flush()
}

fn read_frame(r: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_MSG {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "privsep frame too large",
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(body)
}

/// Fork the host-key signer.
///
/// The child holds `host_key` and serves signature requests until the parent
/// closes the socket; the parent drops its copy of the key (it is zeroized on
/// drop) and returns a [`MonitorSigner`] the daemon uses for every host-key
/// signature. **Call this before starting the async runtime** — the `fork()`
/// must happen while the process is single-threaded.
///
/// When `drop_to` names a user and we are root, the signer drops to that
/// account before serving; otherwise it stays as the current user (still a
/// separate address space, just not a lower privilege level).
pub fn spawn_signer(host_key: PrivateKey, drop_to: Option<&str>) -> std::io::Result<MonitorSigner> {
    let public_blob = host_key.public().to_blob();
    let (parent, child) = UnixStream::pair()?;

    // SAFETY: the caller guarantees a single-threaded process at this point,
    // so the child touches only async-signal-safe state before it settles
    // into its own read/sign/write loop.
    match unsafe { nix::unistd::fork() }.map_err(std::io::Error::from)? {
        nix::unistd::ForkResult::Child => {
            drop(parent);
            harden(drop_to);
            serve(host_key, child); // loops until EOF
            std::process::exit(0);
        }
        nix::unistd::ForkResult::Parent { .. } => {
            drop(child);
            // The parent must not retain the private key: dropping zeroizes it.
            drop(host_key);
            Ok(MonitorSigner {
                sock: Arc::new(Mutex::new(parent)),
                public_blob,
            })
        }
    }
}

/// The signer loop: read an exchange hash, sign it, write the signature.
fn serve(host_key: PrivateKey, mut sock: UnixStream) {
    loop {
        let hash = match read_frame(&mut sock) {
            Ok(h) => h,
            Err(_) => return, // parent closed the socket: the daemon is done
        };
        let sig = host_key.sign(&hash);
        if write_frame(&mut sock, &sig).is_err() {
            return;
        }
    }
}

/// Shrink the signer's attack surface: when root, drop to `drop_to` (gid,
/// supplementary groups, then uid); always forbid new privileges and clamp
/// resource limits to what a sign loop needs. Best-effort — a failure to
/// harden is logged, not fatal, so a misconfigured account can't wedge the
/// daemon, but the separation (a distinct address space without the key on
/// the daemon side) still holds.
fn harden(drop_to: Option<&str>) {
    // No child of the signer may ever regain privilege via setuid binaries.
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }

    if nix::unistd::geteuid().is_root() {
        if let Some(name) = drop_to {
            match crate::connect::UserContext::for_user(name) {
                Some(u) => {
                    let gid = nix::unistd::Gid::from_raw(u.gid);
                    let uid = nix::unistd::Uid::from_raw(u.uid);
                    let dropped = nix::unistd::setgid(gid)
                        .and_then(|_| nix::unistd::setuid(uid))
                        .is_ok();
                    if dropped {
                        // If we can regain root, the drop was ineffective.
                        if nix::unistd::setuid(nix::unistd::Uid::from_raw(0)).is_ok() {
                            eprintln!("shhd: signer failed to drop privileges; refusing to run");
                            std::process::exit(1);
                        }
                    } else {
                        eprintln!("shhd: signer could not drop to {name:?}");
                    }
                }
                None => eprintln!("shhd: signer drop user {name:?} not found; staying root"),
            }
        }
    }

    // A sign loop needs no child processes and only a couple of file
    // descriptors; clamp both so a hijacked signer cannot fork-bomb or hoard.
    set_limit(libc::RLIMIT_NPROC, 0);
    set_limit(libc::RLIMIT_NOFILE, 16);
}

fn set_limit(resource: libc::__rlimit_resource_t, value: u64) {
    let rl = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    unsafe {
        libc::setrlimit(resource, &rl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercise the RPC protocol and the signer loop without `fork()` (unsafe
    /// in the multi-threaded test process): run `serve` on a thread and drive
    /// a `MonitorSigner` from the other end of a socketpair. The real fork at
    /// daemon startup is covered by the OpenSSH interop tests.
    #[test]
    fn monitor_signer_round_trips_and_verifies() {
        let host = PrivateKey::generate();
        let public = host.public();
        let (a, b) = UnixStream::pair().unwrap();

        let signer_key = host.clone();
        let handle = std::thread::spawn(move || serve(signer_key, b));

        let mon = MonitorSigner {
            sock: Arc::new(Mutex::new(a)),
            public_blob: public.to_blob(),
        };

        // The advertised public blob is the host key's.
        assert_eq!(mon.public_blob(), public.to_blob());

        // Several signatures (as an initial KEX plus rekeys would need), each
        // verifying against the host public key.
        for msg in [&b"exchange-hash-1"[..], b"rekey-hash-2", b"rekey-hash-3"] {
            let sig = mon.sign(msg);
            public.verify(msg, &sig).expect("monitor signature verifies");
        }

        // Dropping the client end ends the serve loop.
        drop(mon);
        handle.join().unwrap();
    }

    #[test]
    fn oversized_frame_is_rejected() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&(u32::MAX).to_be_bytes()).unwrap();
        assert!(read_frame(&mut b).is_err());
    }
}
