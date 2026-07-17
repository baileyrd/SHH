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
use crate::crypto::cert::{now_secs as cert_now_secs, Certificate, CERT_ALGO, CERT_TYPE_HOST};
use crate::crypto::ed25519::{PrivateKey, PublicKey, ALGO};
use crate::wire::{Reader, Writer};
use crate::Result;

/// OpenSSH agent extension names we speak.
const EXT_SESSION_BIND: &str = "session-bind@openssh.com";
const EXT_RESTRICT_DESTINATION: &str = "restrict-destination-v00@openssh.com";

/// One end of a destination-constraint hop: the host keys (or CA keys) that
/// identify a host. A hop with no keys is the local origin. Enforcement is by
/// key — matching OpenSSH, which passes a NULL user at sign time — so the
/// username and hostname the wire also carries are parsed and discarded.
struct Hop {
    keys: Vec<(Vec<u8>, bool)>, // (host-key blob, is_ca)
}

/// A permitted hop `from` → `to` in a destination constraint.
struct DestConstraint {
    from: Hop,
    to: Hop,
}

struct Stored {
    /// The public blob the identity is named by: a plain key blob or a
    /// whole certificate.
    blob: Vec<u8>,
    key: PrivateKey,
    comment: String,
    expires: Option<tokio::time::Instant>,
    /// Destination constraints (`restrict-destination-v00@openssh.com`).
    /// Empty means the key is unconstrained.
    constraints: Vec<DestConstraint>,
}

/// One `session-bind@openssh.com` binding recorded on a connection: the host
/// the client proved (by a host signature over the session id) it exchanged
/// keys with, in the order the connection traversed them.
struct Binding {
    host_key: Vec<u8>,
    session_id: Vec<u8>,
    /// True if this hop forwarded the agent onward. A binding that did not
    /// forward may only be the final hop of a proven path.
    is_forwarding: bool,
}

/// Per-connection agent state: the chain of verified session bindings. Lives
/// on the socket connection, not the shared store, so destination
/// constraints are judged against the path *this* client actually took.
#[derive(Default)]
pub struct ConnState {
    bindings: Vec<Binding>,
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

    /// Answer one request frame on connection `conn`. Malformed input earns
    /// FAILURE, never a panic and never a half-applied mutation.
    pub fn handle(&self, conn: &mut ConnState, req: &[u8]) -> Vec<u8> {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.purge_expired();
        let Some((&op, body)) = req.split_first() else {
            return failure();
        };
        let locked = state.lock.is_some();
        match op {
            num::REQUEST_IDENTITIES => state.list(locked),
            _ if locked && op != num::UNLOCK => failure(),
            num::SIGN_REQUEST => state.sign(body, &conn.bindings).unwrap_or_else(failure),
            num::ADD_IDENTITY => state.add(body, false).unwrap_or_else(failure),
            num::ADD_ID_CONSTRAINED => state.add(body, true).unwrap_or_else(failure),
            num::REMOVE_IDENTITY => state.remove(body).unwrap_or_else(failure),
            num::REMOVE_ALL_IDENTITIES => {
                state.keys.clear();
                success()
            }
            num::LOCK => state.set_lock(body).unwrap_or_else(failure),
            num::UNLOCK => state.unset_lock(body).unwrap_or_else(failure),
            num::EXTENSION => {
                let mut r = Reader::new(body);
                let name = r.utf8().map(str::to_owned).ok();
                let rest = r.rest();
                match name.as_deref() {
                    // Bind this connection to a verified host: the client
                    // proves it exchanged keys with the host by a signature
                    // over the session id. This is what lets destination
                    // constraints trust the path the connection took.
                    Some(EXT_SESSION_BIND) => conn.session_bind(rest).unwrap_or_else(failure),
                    // Any other extension: plain FAILURE, which OpenSSH reads
                    // as "unsupported" and moves past.
                    _ => failure(),
                }
            }
            _ => failure(),
        }
    }

    /// How many identities are currently held (expired ones excluded).
    pub fn len(&self) -> usize {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.purge_expired();
        state.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The underlying Ed25519 public key of a host-key blob — the key itself,
/// or the key a certificate certifies.
fn underlying_key(blob: &[u8]) -> Option<PublicKey> {
    match Reader::new(blob).utf8().ok()? {
        CERT_ALGO => Certificate::parse_and_verify(blob).ok().map(|c| c.key),
        _ => PublicKey::from_blob(blob).ok(),
    }
}

impl ConnState {
    /// Handle `session-bind@openssh.com`: verify the host signature over the
    /// session id, then record the binding. Verification is the whole point
    /// — it stops a malicious host from claiming a path it never took.
    fn session_bind(&mut self, body: &[u8]) -> Option<Vec<u8>> {
        let mut r = Reader::new(body);
        let host_blob = r.string().ok()?;
        let session_id = r.string().ok()?;
        let sig = r.string().ok()?;
        let is_forwarding = r.boolean().ok()?;
        r.finish().ok()?;

        // The signature must be a real host signature over the session id.
        underlying_key(host_blob)?.verify(session_id, sig).ok()?;

        // Reject a replayed session id (loop / double-bind), as OpenSSH does.
        if self.bindings.iter().any(|b| b.session_id == session_id) {
            return None;
        }
        // A non-forwarding binding is the endpoint of a path: once one is
        // recorded, no further hop may be added on top of it. This is what
        // makes an intermediate `is_forwarding` flag mean "traffic actually
        // traversed this hop" — without it a client holding independent
        // direct connections could forge a multi-hop path (OpenSSH's rule).
        if self.bindings.last().is_some_and(|b| !b.is_forwarding) {
            return None;
        }
        self.bindings.push(Binding {
            host_key: host_blob.to_vec(),
            session_id: session_id.to_vec(),
            is_forwarding,
        });
        Some(success())
    }
}

/// Does a host-key `blob` match one of a hop's key entries — either equal to
/// a listed key, or (for a CA entry) a certificate that CA signed?
fn hop_lists_key(hop: &Hop, blob: &[u8]) -> bool {
    let target = underlying_key(blob);
    hop.keys.iter().any(|(entry, is_ca)| {
        if *is_ca {
            // The bound host presented a *host* certificate signed by this CA
            // and still inside its validity window. Without the type/validity
            // check a leaked user certificate — or an expired host cert —
            // signed by the same CA would count as "a host under this CA".
            Certificate::parse_and_verify(blob)
                .ok()
                .filter(|c| c.cert_type == CERT_TYPE_HOST && c.valid_at(cert_now_secs()))
                .zip(underlying_key(entry))
                .map(|(c, ca)| ca.0 == c.ca_key.0)
                .unwrap_or(false)
        } else {
            match (&target, underlying_key(entry)) {
                (Some(a), Some(b)) => a.0 == b.0,
                _ => false,
            }
        }
    })
}

/// Is the whole binding chain permitted by `constraints`? Each hop must be
/// reachable `from` the previous host `to` the current one; the first hop's
/// `from` is the local origin (a constraint hop with no keys).
fn destinations_permit(constraints: &[DestConstraint], bindings: &[Binding]) -> bool {
    if constraints.is_empty() {
        return true; // unconstrained key
    }
    if bindings.is_empty() {
        return false; // a constrained key needs a proven path
    }
    bindings.iter().enumerate().all(|(i, b)| {
        let from: Option<&[u8]> = (i > 0).then(|| bindings[i - 1].host_key.as_slice());
        constraints.iter().any(|c| {
            let from_ok = match from {
                None => c.from.keys.is_empty(), // origin hop
                Some(k) => hop_lists_key(&c.from, k),
            };
            from_ok && hop_lists_key(&c.to, &b.host_key)
        })
    })
}

/// Parse one hop of a destination constraint: user, host, reserved, then a
/// run of `(host-key blob, is_ca)` entries.
fn parse_hop(bytes: &[u8]) -> Option<Hop> {
    let mut r = Reader::new(bytes);
    let _user = r.string().ok()?;
    let _host = r.string().ok()?;
    let _reserved = r.string().ok()?;
    let mut keys = Vec::new();
    while r.remaining() > 0 {
        let kb = r.string().ok()?.to_vec();
        let is_ca = r.boolean().ok()?;
        keys.push((kb, is_ca));
    }
    Some(Hop { keys })
}

/// Parse a `restrict-destination-v00@openssh.com` payload: a run of
/// constraints, each a string wrapping `(string from-hop, string to-hop,
/// string reserved)`.
fn parse_dest_constraints(blob: &[u8]) -> Option<Vec<DestConstraint>> {
    let mut r = Reader::new(blob);
    let mut out = Vec::new();
    while r.remaining() > 0 {
        let mut c = Reader::new(r.string().ok()?);
        let from = c.string().ok()?;
        let to = c.string().ok()?;
        let _reserved = c.string().ok()?;
        c.finish().ok()?;
        out.push(DestConstraint {
            from: parse_hop(from)?,
            to: parse_hop(to)?,
        });
    }
    Some(out)
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
        let mut constraints = Vec::new();
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
                    num::CONSTRAIN_EXTENSION => {
                        // The only key-constraint extension we honor pins the
                        // key to a set of destinations; the payload wraps the
                        // constraint list in one string.
                        match r.utf8().ok()? {
                            EXT_RESTRICT_DESTINATION => {
                                let blob = r.string().ok()?;
                                constraints.extend(parse_dest_constraints(blob)?);
                            }
                            _ => return None, // unknown extension: refuse
                        }
                    }
                    // Confirm-per-use and anything else we cannot honor: we
                    // refuse the add outright rather than silently drop it.
                    _ => return None,
                }
            }
        }
        r.finish().ok()?;

        let blob = match cert_blob {
            Some(c) => c,
            None => public.to_blob(),
        };
        // Re-adding an identity replaces it (fresh comment, lifetime, constraints).
        self.keys.retain(|k| k.blob != blob);
        self.keys.push(Stored {
            blob,
            key,
            comment,
            expires,
            constraints,
        });
        Some(success())
    }

    fn sign(&self, body: &[u8], bindings: &[Binding]) -> Option<Vec<u8>> {
        let mut r = Reader::new(body);
        let blob = r.string().ok()?;
        let data = r.string().ok()?;
        let _flags = r.u32().ok()?; // RSA hash selection; meaningless here
        r.finish().ok()?;
        let stored = self.find(blob)?;
        // A destination-constrained key signs only for a proven path that its
        // constraints allow. Fail closed: no bindings, no signature.
        if !destinations_permit(&stored.constraints, bindings) {
            tracing::info!("refusing to sign: destination not permitted for this key");
            return None;
        }
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
    // Session bindings accumulate for the life of this connection.
    let mut conn = ConnState::default();
    while let Some(req) = read_frame(&mut io).await? {
        let resp = keyring.handle(&mut conn, &req);
        write_frame(&mut io, &resp).await?;
    }
    Ok(())
}

/// Bind the agent's Unix socket. Any directory this call *creates* is made
/// 0700; a pre-existing parent (e.g. `/tmp`) is left untouched. The socket is
/// created 0600 with no world-accessible window (umask forced to 0o177 across
/// the bind), and a stale socket is replaced only when it is a socket owned by
/// the current user — never an arbitrary file or another user's socket.
#[cfg(unix)]
pub async fn bind(path: &std::path::Path) -> Result<tokio::net::UnixListener> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        if !dir.exists() {
            // We are creating the directory, so it is ours to lock down. A
            // directory that already existed keeps its own permissions.
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        // Only touch a genuine leftover: a socket we own. Anything else
        // (regular file, symlink, another user's socket) is left in place and
        // the bind below fails loudly rather than silently clobbering it.
        let ours = meta.file_type().is_socket()
            && meta.uid() == unsafe { libc::getuid() };
        if ours {
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
    }
    // Force a restrictive umask around bind so the socket is never briefly
    // world/group accessible before the explicit chmod.
    let prev_umask = unsafe { libc::umask(0o177) };
    let bound = tokio::net::UnixListener::bind(path);
    unsafe { libc::umask(prev_umask) };
    let listener = bound?;
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
        let keyring = Arc::new(Keyring::new());
        let client = client_for(&keyring);
        (client, keyring)
    }

    /// Another client on its own connection (its own binding chain) against
    /// an existing keyring.
    fn client_for(keyring: &Arc<Keyring>) -> Client {
        let (a, b) = tokio::io::duplex(1 << 16);
        let kr = keyring.clone();
        tokio::spawn(async move {
            let _ = serve_conn(b, &kr).await;
        });
        Client::from_stream(a)
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
        assert_eq!(kr.handle(&mut ConnState::default(), &w.into_bytes()), vec![num::FAILURE]);
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
        assert_eq!(kr.handle(&mut ConnState::default(), &w.into_bytes()), vec![num::FAILURE]);
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
        assert_eq!(kr.handle(&mut ConnState::default(), &w.into_bytes()), vec![num::FAILURE]);
        assert!(kr.is_empty());
    }

    #[tokio::test]
    async fn garbage_frames_are_refused_not_fatal() {
        let kr = Keyring::new();
        assert_eq!(kr.handle(&mut ConnState::default(), &[]), vec![num::FAILURE]);
        assert_eq!(kr.handle(&mut ConnState::default(), &[199]), vec![num::FAILURE]);
        assert_eq!(kr.handle(&mut ConnState::default(), &[num::ADD_IDENTITY, 0xff, 0xff]), vec![num::FAILURE]);
        assert_eq!(kr.handle(&mut ConnState::default(), &[num::SIGN_REQUEST]), vec![num::FAILURE]);
        // Unknown extensions get a plain FAILURE (draft §4.7), which OpenSSH
        // clients read as "no extension support" and carry on.
        let mut w = Writer::new();
        w.byte(num::EXTENSION);
        w.utf8("nonexistent-extension@example.com");
        assert_eq!(kr.handle(&mut ConnState::default(), &w.into_bytes()), vec![num::FAILURE]);
    }

    // ----------------------------------------- session-bind + restriction ---

    #[tokio::test]
    async fn session_bind_requires_a_valid_host_signature() {
        let (mut c, _kr) = spawn_agent();
        let host = PrivateKey::generate();
        let sessid = [7u8; 32];

        // A genuine host signature over the session id binds.
        c.session_bind(&host.public().to_blob(), &sessid, &host.sign(&sessid), false)
            .await
            .unwrap();

        // A signature by some other key does not.
        let liar = PrivateKey::generate();
        assert!(c
            .session_bind(&host.public().to_blob(), &sessid, &liar.sign(&sessid), false)
            .await
            .is_err());
    }

    /// Build the destination-constraint payload allowing exactly `host`.
    fn only(host: &PrivateKey) -> Vec<u8> {
        crate::agent::encode_destinations(&[(
            String::new(),
            "h".into(),
            vec![(host.public().to_blob(), false)],
        )])
    }

    #[tokio::test]
    async fn destination_constrained_key_signs_only_for_the_bound_host() {
        let (mut adder, kr) = spawn_agent();
        let user = PrivateKey::generate();
        let host = PrivateKey::generate();
        adder
            .add_constrained(&user, None, "k", None, Some(&only(&host)))
            .await
            .unwrap();
        let blob = user.public().to_blob();

        // A connection that never bound a host: the key is unusable.
        let mut bare = client_for(&kr);
        assert!(bare.sign(&blob, b"data").await.is_err());

        // Bind the permitted host, then signing works and verifies.
        let mut ok = client_for(&kr);
        let sid = [9u8; 32];
        ok.session_bind(&host.public().to_blob(), &sid, &host.sign(&sid), false)
            .await
            .unwrap();
        let sig = ok.sign(&blob, b"data").await.unwrap();
        user.public().verify(b"data", &sig).unwrap();

        // Bind a *different* host: the same key refuses to sign.
        let other = PrivateKey::generate();
        let mut wrong = client_for(&kr);
        let sid2 = [11u8; 32];
        wrong
            .session_bind(&other.public().to_blob(), &sid2, &other.sign(&sid2), false)
            .await
            .unwrap();
        assert!(wrong.sign(&blob, b"data").await.is_err());
    }

    #[test]
    fn restrict_destination_encoding_has_the_openssh_nesting() {
        // OpenSSH's `restrict-destination-v00@openssh.com` payload is a run of
        // constraints, each a string wrapping `string(from) string(to)
        // string(reserved)`, where a hop is `string(user) string(host)
        // string(reserved) (string(keyblob) byte(is_ca))*`. This asserts our
        // encoder produces exactly that shape — the byte-level match with real
        // OpenSSH is covered by the interop script. (Verified by round-trip
        // through the very parser that accepts `ssh-add -h` bytes.)
        let host = PrivateKey::generate();
        let hk = host.public().to_blob();
        let payload = crate::agent::encode_destinations(&[(
            "deploy".into(),
            "gw".into(),
            vec![(hk.clone(), false)],
        )]);

        // Outer list: exactly one string-wrapped constraint, nothing trailing.
        let mut list = Reader::new(&payload);
        let constraint = list.string().unwrap();
        assert_eq!(list.remaining(), 0);

        // Constraint: from-hop, to-hop, reserved.
        let mut c = Reader::new(constraint);
        let from = c.string().unwrap();
        let to = c.string().unwrap();
        assert!(c.string().unwrap().is_empty(), "reserved is empty");
        c.finish().unwrap();

        // from is the local origin: user, host, reserved all empty, no keys.
        let mut f = Reader::new(from);
        assert!(f.string().unwrap().is_empty());
        assert!(f.string().unwrap().is_empty());
        assert!(f.string().unwrap().is_empty());
        assert_eq!(f.remaining(), 0, "origin hop carries no keys");

        // to names the destination and its host key with is_ca = 0.
        let mut t = Reader::new(to);
        assert_eq!(t.utf8().unwrap(), "deploy");
        assert_eq!(t.utf8().unwrap(), "gw");
        assert!(t.string().unwrap().is_empty());
        assert_eq!(t.string().unwrap(), hk.as_slice());
        assert_eq!(t.byte().unwrap(), 0);
        t.finish().unwrap();

        // And it parses + enforces: the named host is permitted, others not.
        let constraints = parse_dest_constraints(&payload).unwrap();
        let bound = |blob: &[u8]| Binding {
            host_key: blob.to_vec(),
            session_id: vec![1],
            is_forwarding: false,
        };
        assert!(destinations_permit(&constraints, &[bound(&hk)]));
        let stranger = PrivateKey::generate().public().to_blob();
        assert!(!destinations_permit(&constraints, &[bound(&stranger)]));
    }

    #[test]
    fn encode_path_chains_each_hop_from_the_previous() {
        // The security-critical shape: constraint[i].from must carry hop
        // i-1's key (and constraint[0].from is the empty origin), so a hop is
        // reachable only *through* the one before it.
        let a = PrivateKey::generate().public().to_blob();
        let b = PrivateKey::generate().public().to_blob();
        let payload = crate::agent::encode_path(&[
            (String::new(), "a".into(), vec![(a.clone(), false)]),
            (String::new(), "b".into(), vec![(b.clone(), false)]),
        ]);
        let constraints = parse_dest_constraints(&payload).unwrap();
        assert_eq!(constraints.len(), 2);
        // local → A
        assert!(constraints[0].from.keys.is_empty());
        assert!(hop_lists_key(&constraints[0].to, &a));
        // A → B (the "from" is A, not the origin)
        assert!(hop_lists_key(&constraints[1].from, &a));
        assert!(hop_lists_key(&constraints[1].to, &b));
        assert!(!constraints[1].from.keys.is_empty(), "second hop is not from origin");
    }

    /// Bind `host` (with a fresh session id keyed by `seed`) on `c`. A hop that
    /// forwards the agent onward sets `forwarding`; only the final hop of a
    /// path is non-forwarding (OpenSSH's rule, enforced in `session_bind`).
    async fn bind(c: &mut Client, host: &PrivateKey, seed: u8, forwarding: bool) {
        let sid = [seed; 32];
        c.session_bind(&host.public().to_blob(), &sid, &host.sign(&sid), forwarding)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn path_constraint_requires_the_whole_chain_in_order() {
        let (mut adder, kr) = spawn_agent();
        let user = PrivateKey::generate();
        let a = PrivateKey::generate(); // first hop
        let b = PrivateKey::generate(); // second hop
        let c = PrivateKey::generate(); // a stranger
        // Pin the key to the path local → A → B.
        let path = crate::agent::encode_path(&[
            (String::new(), "a".into(), vec![(a.public().to_blob(), false)]),
            (String::new(), "b".into(), vec![(b.public().to_blob(), false)]),
        ]);
        adder
            .add_constrained(&user, None, "k", None, Some(&path))
            .await
            .unwrap();
        let blob = user.public().to_blob();

        // The full chain A→B: permitted (this is the point of the path).
        let mut full = client_for(&kr);
        bind(&mut full, &a, 1, true).await;
        bind(&mut full, &b, 2, false).await;
        full.sign(&blob, b"d").await.unwrap();

        // At the first hop alone: still permitted (the key authenticates to A
        // to make the hop in the first place).
        let mut at_a = client_for(&kr);
        bind(&mut at_a, &a, 3, false).await;
        at_a.sign(&blob, b"d").await.unwrap();

        // Straight to B without going through A: refused.
        let mut skip = client_for(&kr);
        bind(&mut skip, &b, 4, false).await;
        assert!(skip.sign(&blob, b"d").await.is_err());

        // A then a *different* second hop: refused.
        let mut wrong = client_for(&kr);
        bind(&mut wrong, &a, 5, true).await;
        bind(&mut wrong, &c, 6, false).await;
        assert!(wrong.sign(&blob, b"d").await.is_err());

        // The hops out of order (B then A): refused.
        let mut reversed = client_for(&kr);
        bind(&mut reversed, &b, 7, true).await;
        bind(&mut reversed, &a, 8, false).await;
        assert!(reversed.sign(&blob, b"d").await.is_err());
    }

    #[tokio::test]
    async fn non_forwarding_hop_cannot_be_followed_by_another() {
        // A binding that did not forward the agent is an endpoint: OpenSSH
        // refuses to record a further hop on top of it, so a client cannot
        // forge a multi-hop path out of independent direct connections.
        let (_adder, kr) = spawn_agent();
        let a = PrivateKey::generate();
        let b = PrivateKey::generate();
        let mut c = client_for(&kr);

        let sid_a = [1u8; 32];
        // First hop is *not* forwarding.
        c.session_bind(&a.public().to_blob(), &sid_a, &a.sign(&sid_a), false)
            .await
            .unwrap();
        // A second bind on top of it must be rejected.
        let sid_b = [2u8; 32];
        assert!(c
            .session_bind(&b.public().to_blob(), &sid_b, &b.sign(&sid_b), false)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn ca_constraint_matches_any_host_that_ca_certifies() {
        let (mut adder, kr) = spawn_agent();
        let user = PrivateKey::generate();
        let ca = PrivateKey::generate();
        // Pin the key to "any host certified by `ca`" (an is_ca = true entry).
        let dests = crate::agent::encode_destinations(&[(
            String::new(),
            "corp".into(),
            vec![(ca.public().to_blob(), true)],
        )]);
        adder
            .add_constrained(&user, None, "k", None, Some(&dests))
            .await
            .unwrap();
        let blob = user.public().to_blob();

        // A host presenting a certificate this CA signed: bind carries the
        // cert; the CA entry matches; signing is permitted.
        let host = PrivateKey::generate();
        let host_cert =
            cert::sign_host_cert(&ca, &host.public(), 1, "h", &["corp".into()], 0, u64::MAX);
        let mut ok = client_for(&kr);
        let sid = [21u8; 32];
        ok.session_bind(&host_cert, &sid, &host.sign(&sid), false)
            .await
            .unwrap();
        let sig = ok.sign(&blob, b"d").await.unwrap();
        user.public().verify(b"d", &sig).unwrap();

        // A certificate from a *different* CA: refused.
        let other_ca = PrivateKey::generate();
        let host2 = PrivateKey::generate();
        let cert2 =
            cert::sign_host_cert(&other_ca, &host2.public(), 1, "h", &["corp".into()], 0, u64::MAX);
        let mut wrong = client_for(&kr);
        let sid2 = [22u8; 32];
        wrong
            .session_bind(&cert2, &sid2, &host2.sign(&sid2), false)
            .await
            .unwrap();
        assert!(wrong.sign(&blob, b"d").await.is_err());

        // A bare host key (no certificate at all): a CA entry never matches.
        let plain = PrivateKey::generate();
        let mut bare = client_for(&kr);
        let sid3 = [23u8; 32];
        bare.session_bind(&plain.public().to_blob(), &sid3, &plain.sign(&sid3), false)
            .await
            .unwrap();
        assert!(bare.sign(&blob, b"d").await.is_err());
    }

    #[tokio::test]
    async fn unconstrained_key_still_signs_without_any_binding() {
        // The restriction must not leak to ordinary keys.
        let (mut c, _kr) = spawn_agent();
        let user = PrivateKey::generate();
        c.add(&user, None, "plain", None).await.unwrap();
        let sig = c.sign(&user.public().to_blob(), b"data").await.unwrap();
        user.public().verify(b"data", &sig).unwrap();
    }
}
