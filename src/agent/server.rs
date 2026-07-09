//! The agent's key store and its message loop.
//!
//! `Keyring::handle` is a pure request→response function over parsed frames,
//! so every policy decision is unit-testable without a socket. The store
//! accepts only what it can fully honor: Ed25519 keys and certificates, and
//! the lifetime constraint. A confirm constraint (which OpenSSH satisfies by
//! prompting through askpass) is refused rather than silently ignored —
//! ignoring it would grant every signature the user believed they'd gate.

use std::sync::Mutex;

use ed25519_dalek::SigningKey;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use super::{num, read_frame, write_frame};
use crate::crypto::cert::{Certificate, CERT_ALGO};
use crate::crypto::ed25519::{PrivateKey, ALGO};
use crate::wire::{Reader, Writer};
use crate::Result;

struct Stored {
    /// The public blob the identity is named by: a plain key blob or a
    /// whole certificate.
    blob: Vec<u8>,
    key: PrivateKey,
    comment: String,
    expires: Option<tokio::time::Instant>,
}

#[derive(Default)]
struct State {
    keys: Vec<Stored>,
    /// While `Some`, the store is locked: identities are hidden and every
    /// mutating or signing request fails until the passphrase returns.
    lock: Option<Zeroizing<Vec<u8>>>,
}

/// An in-memory Ed25519 key store speaking the agent protocol.
#[derive(Default)]
pub struct Keyring {
    state: Mutex<State>,
}

fn failure() -> Vec<u8> {
    vec![num::FAILURE]
}

fn success() -> Vec<u8> {
    vec![num::SUCCESS]
}

impl Keyring {
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer one request frame. Malformed input earns FAILURE, never a
    /// panic and never a half-applied mutation.
    pub fn handle(&self, req: &[u8]) -> Vec<u8> {
        let mut state = self.state.lock().expect("keyring lock poisoned");
        state.purge_expired();
        let Some((&op, body)) = req.split_first() else {
            return failure();
        };
        let locked = state.lock.is_some();
        match op {
            num::REQUEST_IDENTITIES => state.list(locked),
            _ if locked && op != num::UNLOCK => failure(),
            num::SIGN_REQUEST => state.sign(body).unwrap_or_else(failure),
            num::ADD_IDENTITY => state.add(body, false).unwrap_or_else(failure),
            num::ADD_ID_CONSTRAINED => state.add(body, true).unwrap_or_else(failure),
            num::REMOVE_IDENTITY => state.remove(body).unwrap_or_else(failure),
            num::REMOVE_ALL_IDENTITIES => {
                state.keys.clear();
                success()
            }
            num::LOCK => state.set_lock(body).unwrap_or_else(failure),
            num::UNLOCK => state.unset_lock(body).unwrap_or_else(failure),
            // Extensions (session-bind@openssh.com and friends): the draft
            // says unsupported extensions get plain FAILURE, and OpenSSH
            // clients treat that as "no extension support" and move on.
            num::EXTENSION => failure(),
            _ => failure(),
        }
    }

    /// How many identities are currently held (expired ones excluded).
    pub fn len(&self) -> usize {
        let mut state = self.state.lock().expect("keyring lock poisoned");
        state.purge_expired();
        state.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl State {
    fn purge_expired(&mut self) {
        let now = tokio::time::Instant::now();
        self.keys.retain(|k| k.expires.is_none_or(|t| t > now));
    }

    fn find(&self, blob: &[u8]) -> Option<&Stored> {
        self.keys.iter().find(|k| k.blob == blob)
    }

    fn list(&self, locked: bool) -> Vec<u8> {
        let mut w = Writer::new();
        w.byte(num::IDENTITIES_ANSWER);
        if locked {
            // A locked agent admits nothing, not even how much it holds.
            w.u32(0);
            return w.into_bytes();
        }
        w.u32(self.keys.len() as u32);
        for k in &self.keys {
            w.string(&k.blob);
            w.utf8(&k.comment);
        }
        w.into_bytes()
    }

    /// Parse and apply an ADD_IDENTITY / ADD_ID_CONSTRAINED. `None` = refuse.
    fn add(&mut self, body: &[u8], constrained: bool) -> Option<Vec<u8>> {
        let mut r = Reader::new(body);
        let algo = r.utf8().ok()?;

        // Both forms end with `string k||ENC(A)`, `string comment`; the cert
        // form carries the certificate first. The key is rebuilt from the
        // seed, and every public copy must match it — a blob that lies about
        // its private half is refused, not stored.
        let (cert_blob, claimed_pub) = match algo {
            ALGO => (None, r.string().ok()?.to_vec()),
            CERT_ALGO => {
                let cert = r.string().ok()?.to_vec();
                let claimed = r.string().ok()?.to_vec();
                (Some(cert), claimed)
            }
            _ => return None, // Ed25519 only; nothing legacy enters the store
        };
        let sk = Zeroizing::new(r.string().ok()?.to_vec());
        let comment = r.utf8().ok()?.to_owned();

        let seed: [u8; 32] = sk.get(..32)?.try_into().ok()?;
        let key = PrivateKey(SigningKey::from_bytes(&seed));
        let public = key.public();
        if claimed_pub != public.0.as_bytes() || sk.get(32..)? != public.0.as_bytes() {
            return None;
        }
        if let Some(cert) = &cert_blob {
            // The certificate must be internally sound and actually certify
            // this key. Whether its CA is trusted is the servers' business.
            let parsed = Certificate::parse_and_verify(cert).ok()?;
            if parsed.key.0.as_bytes() != public.0.as_bytes() {
                return None;
            }
        }

        let mut expires = None;
        if constrained {
            while r.remaining() > 0 {
                match r.byte().ok()? {
                    num::CONSTRAIN_LIFETIME => {
                        let secs = r.u32().ok()?;
                        if secs == 0 {
                            return None;
                        }
                        expires = Some(
                            tokio::time::Instant::now() + std::time::Duration::from_secs(secs.into()),
                        );
                    }
                    // Confirm-per-use and constraint extensions: we cannot
                    // honor them, so we refuse the add outright.
                    _ => return None,
                }
            }
        }
        r.finish().ok()?;

        let blob = match cert_blob {
            Some(c) => c,
            None => public.to_blob(),
        };
        // Re-adding an identity replaces it (fresh comment and lifetime).
        self.keys.retain(|k| k.blob != blob);
        self.keys.push(Stored {
            blob,
            key,
            comment,
            expires,
        });
        Some(success())
    }

    fn sign(&self, body: &[u8]) -> Option<Vec<u8>> {
        let mut r = Reader::new(body);
        let blob = r.string().ok()?;
        let data = r.string().ok()?;
        let _flags = r.u32().ok()?; // RSA hash selection; meaningless here
        r.finish().ok()?;
        let stored = self.find(blob)?;
        let mut w = Writer::new();
        w.byte(num::SIGN_RESPONSE);
        w.string(&stored.key.sign(data));
        Some(w.into_bytes())
    }

    fn remove(&mut self, body: &[u8]) -> Option<Vec<u8>> {
        let mut r = Reader::new(body);
        let blob = r.string().ok()?.to_vec();
        r.finish().ok()?;
        let before = self.keys.len();
        self.keys.retain(|k| k.blob != blob);
        (self.keys.len() < before).then(success)
    }

    fn set_lock(&mut self, body: &[u8]) -> Option<Vec<u8>> {
        let mut r = Reader::new(body);
        let pass = r.string().ok()?.to_vec();
        r.finish().ok()?;
        if self.lock.is_some() {
            return None; // handle() already gates this; belt and braces
        }
        self.lock = Some(Zeroizing::new(pass));
        Some(success())
    }

    fn unset_lock(&mut self, body: &[u8]) -> Option<Vec<u8>> {
        let mut r = Reader::new(body);
        let pass = r.string().ok()?;
        r.finish().ok()?;
        let held = self.lock.as_ref()?;
        // Constant-time comparison: a lock passphrase is a secret even if
        // the store behind it is only fingerprints away.
        if held.len() != pass.len() || held.ct_eq(pass).unwrap_u8() != 1 {
            return None;
        }
        self.lock = None;
        Some(success())
    }
}

/// Serve one connection: frames in, `Keyring::handle` answers out, until the
/// peer hangs up. Framing violations (not policy refusals) end the
/// connection.
pub async fn serve_conn<S>(mut io: S, keyring: &Keyring) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    while let Some(req) = read_frame(&mut io).await? {
        let resp = keyring.handle(&req);
        write_frame(&mut io, &resp).await?;
    }
    Ok(())
}

/// Bind the agent's Unix socket: parent directory 0700, socket 0600, and a
/// stale socket file from a dead agent is replaced while a live one is
/// respected.
#[cfg(unix)]
pub async fn bind(path: &std::path::Path) -> Result<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;

    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    if path.exists() {
        match tokio::net::UnixStream::connect(path).await {
            Ok(_) => {
                return Err(crate::Error::Agent(format!(
                    "an agent is already listening on {}",
                    path.display()
                )))
            }
            Err(_) => std::fs::remove_file(path)?,
        }
    }
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::agent::{num, Client};
    use crate::crypto::cert;

    /// A live agent on an in-memory pipe: the `Client` is the API under
    /// test, the `Keyring` handle lets tests inspect the store directly.
    fn spawn_agent() -> (Client, Arc<Keyring>) {
        let (a, b) = tokio::io::duplex(1 << 16);
        let keyring = Arc::new(Keyring::new());
        let kr = keyring.clone();
        tokio::spawn(async move {
            let _ = serve_conn(b, &kr).await;
        });
        (Client::from_stream(a), keyring)
    }

    #[tokio::test]
    async fn add_list_sign_remove_roundtrip() {
        let (mut c, _kr) = spawn_agent();
        let key = PrivateKey::generate();
        c.add(&key, None, "test key", None).await.unwrap();

        let ids = c.identities().await.unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].comment, "test key");
        assert_eq!(ids[0].blob, key.public().to_blob());

        // A signature made by the agent must verify like a local one.
        let sig = c.sign(&ids[0].blob, b"the message").await.unwrap();
        key.public().verify(b"the message", &sig).unwrap();

        c.remove(&ids[0].blob).await.unwrap();
        assert!(c.identities().await.unwrap().is_empty());
        assert!(c.sign(&ids[0].blob, b"again").await.is_err());
        // Removing what is gone is a refusal, not a silent success.
        assert!(c.remove(&ids[0].blob).await.is_err());
    }

    #[tokio::test]
    async fn certificate_identity_signs_by_cert_blob() {
        let (mut c, _kr) = spawn_agent();
        let ca = PrivateKey::generate();
        let key = PrivateKey::generate();
        let cert_blob = cert::sign_user_cert(
            &ca,
            &key.public(),
            1,
            "id",
            &["deploy".into()],
            0,
            u64::MAX,
        );
        c.add(&key, Some(&cert_blob), "certified", None).await.unwrap();

        let ids = c.identities().await.unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].algo().as_deref(), Some(CERT_ALGO));
        assert_eq!(ids[0].blob, cert_blob);

        let sig = c.sign(&cert_blob, b"span").await.unwrap();
        key.public().verify(b"span", &sig).unwrap();
    }

    #[tokio::test]
    async fn readding_a_key_replaces_it() {
        let (mut c, kr) = spawn_agent();
        let key = PrivateKey::generate();
        c.add(&key, None, "old comment", None).await.unwrap();
        c.add(&key, None, "new comment", None).await.unwrap();
        assert_eq!(kr.len(), 1);
        let ids = c.identities().await.unwrap();
        assert_eq!(ids[0].comment, "new comment");
    }

    #[tokio::test]
    async fn lock_hides_everything_until_the_right_passphrase() {
        let (mut c, _kr) = spawn_agent();
        let key = PrivateKey::generate();
        c.add(&key, None, "k", None).await.unwrap();
        let blob = key.public().to_blob();

        c.lock(b"open sesame").await.unwrap();
        // Locked: the list is empty (not an error), nothing signs, nothing
        // mutates, and a second lock is refused.
        assert!(c.identities().await.unwrap().is_empty());
        assert!(c.sign(&blob, b"m").await.is_err());
        assert!(c.add(&key, None, "k2", None).await.is_err());
        assert!(c.remove_all().await.is_err());
        assert!(c.lock(b"double").await.is_err());

        assert!(c.unlock(b"wrong").await.is_err());
        c.unlock(b"open sesame").await.unwrap();
        assert_eq!(c.identities().await.unwrap().len(), 1);
        c.sign(&blob, b"m").await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn lifetime_constraint_expires_the_key() {
        let (mut c, kr) = spawn_agent();
        let key = PrivateKey::generate();
        c.add(&key, None, "ephemeral", Some(60)).await.unwrap();
        assert_eq!(c.identities().await.unwrap().len(), 1);

        tokio::time::advance(std::time::Duration::from_secs(61)).await;
        assert!(c.identities().await.unwrap().is_empty());
        assert_eq!(kr.len(), 0);
        assert!(c.sign(&key.public().to_blob(), b"m").await.is_err());
    }

    // ------------- raw-frame refusals, straight against Keyring::handle ---

    #[tokio::test]
    async fn legacy_key_types_are_refused() {
        let kr = Keyring::new();
        let mut w = Writer::new();
        w.byte(num::ADD_IDENTITY);
        w.utf8("ssh-rsa");
        w.string(&[3, 1, 0, 1]);
        w.string(&[0u8; 256]);
        w.utf8("rsa key");
        assert_eq!(kr.handle(&w.into_bytes()), vec![num::FAILURE]);
        assert!(kr.is_empty());
    }

    #[tokio::test]
    async fn lying_public_half_is_refused() {
        let kr = Keyring::new();
        let key = PrivateKey::generate();
        let other = PrivateKey::generate();
        // Claim `other`'s public key over `key`'s seed.
        let mut sk = Vec::new();
        sk.extend_from_slice(&key.0.to_bytes());
        sk.extend_from_slice(other.public().0.as_bytes());
        let mut w = Writer::new();
        w.byte(num::ADD_IDENTITY);
        w.utf8(ALGO);
        w.string(other.public().0.as_bytes());
        w.string(&sk);
        w.utf8("liar");
        assert_eq!(kr.handle(&w.into_bytes()), vec![num::FAILURE]);
        assert!(kr.is_empty());
    }

    #[tokio::test]
    async fn confirm_constraint_fails_closed() {
        let kr = Keyring::new();
        let key = PrivateKey::generate();
        let mut sk = Vec::new();
        sk.extend_from_slice(&key.0.to_bytes());
        sk.extend_from_slice(key.public().0.as_bytes());
        let mut w = Writer::new();
        w.byte(num::ADD_ID_CONSTRAINED);
        w.utf8(ALGO);
        w.string(key.public().0.as_bytes());
        w.string(&sk);
        w.utf8("wants confirmation");
        w.byte(num::CONSTRAIN_CONFIRM);
        // We cannot prompt per use, so we must not pretend we will.
        assert_eq!(kr.handle(&w.into_bytes()), vec![num::FAILURE]);
        assert!(kr.is_empty());
    }

    #[tokio::test]
    async fn garbage_frames_are_refused_not_fatal() {
        let kr = Keyring::new();
        assert_eq!(kr.handle(&[]), vec![num::FAILURE]);
        assert_eq!(kr.handle(&[199]), vec![num::FAILURE]);
        assert_eq!(kr.handle(&[num::ADD_IDENTITY, 0xff, 0xff]), vec![num::FAILURE]);
        assert_eq!(kr.handle(&[num::SIGN_REQUEST]), vec![num::FAILURE]);
        // Unknown extensions get a plain FAILURE (draft §4.7), which OpenSSH
        // clients read as "no extension support" and carry on.
        let mut w = Writer::new();
        w.byte(num::EXTENSION);
        w.utf8("session-bind@openssh.com");
        assert_eq!(kr.handle(&w.into_bytes()), vec![num::FAILURE]);
    }
}
