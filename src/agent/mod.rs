//! SSH agent protocol (draft-miller-ssh-agent), Ed25519 only.
//!
//! The agent holds private keys in one long-lived process; clients ask it to
//! sign by blob, so keys never enter short-lived client processes at all.
//! The protocol is uint32-length-framed messages over a Unix socket — the
//! same wire format OpenSSH's `ssh-agent`/`ssh-add` speak, so either side
//! can be swapped for ours.
//!
//! We speak the modern subset: Ed25519 keys and their certificates. RSA
//! flags, DSA/ECDSA identities, smartcard messages, and the confirm
//! constraint (which needs an interactive prompter we refuse to fake) are
//! not implemented; adds of anything we cannot fully honor fail closed.

pub mod server;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::crypto::ed25519::PrivateKey;
use crate::wire::{Reader, Writer};
use crate::{Error, Result};

/// Message numbers (draft-miller-ssh-agent §5.1) — the subset we speak.
pub mod num {
    pub const FAILURE: u8 = 5;
    pub const SUCCESS: u8 = 6;
    pub const REQUEST_IDENTITIES: u8 = 11;
    pub const IDENTITIES_ANSWER: u8 = 12;
    pub const SIGN_REQUEST: u8 = 13;
    pub const SIGN_RESPONSE: u8 = 14;
    pub const ADD_IDENTITY: u8 = 17;
    pub const REMOVE_IDENTITY: u8 = 18;
    pub const REMOVE_ALL_IDENTITIES: u8 = 19;
    pub const LOCK: u8 = 22;
    pub const UNLOCK: u8 = 23;
    pub const ADD_ID_CONSTRAINED: u8 = 25;
    pub const EXTENSION: u8 = 27;

    // Key constraints (§5.2).
    pub const CONSTRAIN_LIFETIME: u8 = 1;
    pub const CONSTRAIN_CONFIRM: u8 = 2;
    pub const CONSTRAIN_EXTENSION: u8 = 255;
}

/// Cap on one agent message, matching OpenSSH's MAX_AGENT_MESSAGE. Anything
/// larger is a protocol violation, not a big key.
pub const MAX_FRAME: usize = 256 * 1024;

/// Read one framed message; `None` on clean EOF (peer closed between
/// messages). An EOF mid-frame is an error, as is an empty or oversized one.
pub(crate) async fn read_frame<S>(io: &mut S) -> Result<Option<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    let mut len4 = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        let n = io.read(&mut len4[got..]).await?;
        if n == 0 {
            if got == 0 {
                return Ok(None);
            }
            return Err(Error::proto("agent stream closed mid-frame"));
        }
        got += n;
    }
    let len = u32::from_be_bytes(len4) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(Error::proto(format!("agent frame length {len} out of range")));
    }
    let mut body = vec![0u8; len];
    io.read_exact(&mut body).await?;
    Ok(Some(body))
}

pub(crate) async fn write_frame<S>(io: &mut S, body: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    debug_assert!(!body.is_empty() && body.len() <= MAX_FRAME);
    io.write_all(&(body.len() as u32).to_be_bytes()).await?;
    io.write_all(body).await?;
    io.flush().await?;
    Ok(())
}

/// One identity as the agent reports it: a public blob (a plain key or a
/// certificate) and its comment.
#[derive(Clone, Debug)]
pub struct Identity {
    pub blob: Vec<u8>,
    pub comment: String,
}

impl Identity {
    /// The algorithm name leading the blob (`ssh-ed25519`,
    /// `ssh-ed25519-cert-v01@openssh.com`, or something we don't speak).
    pub fn algo(&self) -> Option<String> {
        Reader::new(&self.blob).utf8().ok().map(str::to_owned)
    }

    /// OpenSSH-style `SHA256:` fingerprint of the blob.
    pub fn fingerprint(&self) -> String {
        use base64::prelude::{Engine as _, BASE64_STANDARD_NO_PAD};
        use sha2::{Digest, Sha256};
        format!(
            "SHA256:{}",
            BASE64_STANDARD_NO_PAD.encode(Sha256::digest(&self.blob))
        )
    }
}

/// The private half of an ADD_IDENTITY for an Ed25519 key: for a plain key
/// the blob is the algorithm + public key; for a certificate it is the
/// algorithm + whole certificate, and the raw key parts follow either way.
fn encode_add(key: &PrivateKey, cert: Option<&[u8]>, comment: &str) -> Writer {
    let public = key.public();
    let mut w = Writer::new();
    match cert {
        Some(c) => {
            w.utf8(crate::crypto::cert::CERT_ALGO);
            w.string(c);
        }
        None => {
            w.utf8(crate::crypto::ed25519::ALGO);
        }
    }
    // ENC(A) follows the algorithm (and, for certificates, the cert blob).
    w.string(public.0.as_bytes());
    // k || ENC(A): the 32-byte seed followed by the 32-byte public key.
    let mut sk = Vec::with_capacity(64);
    sk.extend_from_slice(&key.0.to_bytes());
    sk.extend_from_slice(public.0.as_bytes());
    w.string(&sk);
    zeroize::Zeroize::zeroize(&mut sk);
    w.utf8(comment);
    w
}

/// Build the `restrict-destination-v00@openssh.com` payload permitting
/// authentication to each `(user, hostname, host_key_blobs)` endpoint from
/// the local origin. The result is the constraint-list bytes to hand to
/// [`Client::add_constrained`]. Each destination becomes one `local → host`
/// constraint, so a key with several is usable toward any of them.
/// A destination hop for a constraint: `(username, hostname, key entries)`,
/// where each key entry is `(host-key blob, is_ca)` — `is_ca` naming a CA
/// whose certificates all match, rather than one exact host key.
pub type Destination = (String, String, Vec<(Vec<u8>, bool)>);

pub fn encode_destinations(dests: &[Destination]) -> Vec<u8> {
    let mut list = Writer::new();
    for (user, host, keys) in dests {
        push_constraint(&mut list, &encode_hop("", "", &[]), &encode_hop(user, host, keys));
    }
    list.into_bytes()
}

/// Build a `restrict-destination-v00@openssh.com` payload for a *path*: the
/// key may be used only along `hops` in order (`local → hop0 → hop1 → …`).
/// Each constraint links the previous host to the next, so the agent — fed a
/// session-bind for every hop the request traversed — permits a signature
/// only when the whole path is present and in order. A single hop is the
/// same as one entry of [`encode_destinations`] (an endpoint pin).
pub fn encode_path(hops: &[Destination]) -> Vec<u8> {
    let mut list = Writer::new();
    let mut from = encode_hop("", "", &[]); // the local origin
    for (user, host, keys) in hops {
        let to = encode_hop(user, host, keys);
        push_constraint(&mut list, &from, &to);
        from = to; // the next hop starts where this one ended
    }
    list.into_bytes()
}

/// One destination-constraint hop: `string user, string host, string
/// reserved, then (string keyblob, byte is_ca)*`. A key entry with
/// `is_ca = true` matches any host presenting a certificate that CA signed,
/// rather than one exact host key.
fn encode_hop(user: &str, host: &str, keys: &[(Vec<u8>, bool)]) -> Vec<u8> {
    let mut w = Writer::new();
    w.utf8(user);
    w.utf8(host);
    w.string(&[]);
    for (k, is_ca) in keys {
        w.string(k);
        w.byte(u8::from(*is_ca));
    }
    w.into_bytes()
}

/// Append `string(from ‖ to ‖ reserved)` — one constraint, itself wrapped in
/// a string so the list can be walked without knowing hop sizes.
fn push_constraint(list: &mut Writer, from: &[u8], to: &[u8]) {
    let mut c = Writer::new();
    c.string(from);
    c.string(to);
    c.string(&[]); // per-constraint reserved
    list.string(&c.into_bytes());
}

/// Something we can read and write frames over. Boxed so `Client` needs no
/// stream type parameter (auth code would otherwise carry two generics).
trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// A client of a running agent — ours or OpenSSH's.
pub struct Client {
    io: Box<dyn Stream>,
}

impl Client {
    /// Connect to the agent at `path` (a Unix socket).
    #[cfg(unix)]
    pub async fn connect(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let io = tokio::net::UnixStream::connect(path.as_ref()).await?;
        Ok(Client { io: Box::new(io) })
    }

    /// Connect to the agent named by `$SSH_AUTH_SOCK`.
    #[cfg(unix)]
    pub async fn from_env() -> Result<Self> {
        match std::env::var_os("SSH_AUTH_SOCK") {
            Some(path) => Self::connect(path).await,
            None => Err(Error::Agent("SSH_AUTH_SOCK is not set".into())),
        }
    }

    /// Wrap an already-connected stream (used by tests).
    pub fn from_stream<S>(io: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Client { io: Box::new(io) }
    }

    async fn roundtrip(&mut self, req: &[u8]) -> Result<Vec<u8>> {
        write_frame(&mut self.io, req).await?;
        read_frame(&mut self.io)
            .await?
            .ok_or_else(|| Error::Agent("agent closed the connection".into()))
    }

    /// A request whose only interesting answer is SUCCESS.
    async fn expect_success(&mut self, req: &[u8], what: &str) -> Result<()> {
        let resp = self.roundtrip(req).await?;
        match resp[0] {
            num::SUCCESS => Ok(()),
            num::FAILURE => Err(Error::Agent(format!("agent refused to {what}"))),
            other => Err(Error::proto(format!("unexpected agent message {other}"))),
        }
    }

    /// All identities the agent is willing to name.
    pub async fn identities(&mut self) -> Result<Vec<Identity>> {
        let resp = self.roundtrip(&[num::REQUEST_IDENTITIES]).await?;
        let mut r = Reader::new(&resp);
        match r.byte()? {
            num::IDENTITIES_ANSWER => {}
            num::FAILURE => return Err(Error::Agent("agent refused to list identities".into())),
            other => return Err(Error::proto(format!("unexpected agent message {other}"))),
        }
        let n = r.u32()?;
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(Identity {
                blob: r.string()?.to_vec(),
                comment: r.utf8()?.to_owned(),
            });
        }
        r.finish()?;
        Ok(out)
    }

    /// Sign `data` with the identity named by `blob`. Returns the standard
    /// SSH signature blob.
    pub async fn sign(&mut self, blob: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.byte(num::SIGN_REQUEST);
        w.string(blob);
        w.string(data);
        w.u32(0); // flags: the RSA hash bits mean nothing to Ed25519
        let resp = self.roundtrip(&w.into_bytes()).await?;
        let mut r = Reader::new(&resp);
        match r.byte()? {
            num::SIGN_RESPONSE => {
                let sig = r.string()?.to_vec();
                r.finish()?;
                Ok(sig)
            }
            num::FAILURE => Err(Error::Agent("agent refused to sign".into())),
            other => Err(Error::proto(format!("unexpected agent message {other}"))),
        }
    }

    /// Add a key (with `Some(cert)`, the certificate identity for it).
    /// `lifetime` in seconds makes the agent forget it after that long.
    pub async fn add(
        &mut self,
        key: &PrivateKey,
        cert: Option<&[u8]>,
        comment: &str,
        lifetime: Option<u32>,
    ) -> Result<()> {
        self.add_constrained(key, cert, comment, lifetime, None).await
    }

    /// Add a key with optional constraints: a `lifetime` and/or a
    /// destination-constraint payload (`destinations` = the constraint list
    /// bytes, the content of the `restrict-destination-v00@openssh.com`
    /// string). A key so constrained signs only for a bound path it allows.
    pub async fn add_constrained(
        &mut self,
        key: &PrivateKey,
        cert: Option<&[u8]>,
        comment: &str,
        lifetime: Option<u32>,
        destinations: Option<&[u8]>,
    ) -> Result<()> {
        let constrained = lifetime.is_some() || destinations.is_some();
        let mut w = Writer::new();
        w.byte(if constrained {
            num::ADD_ID_CONSTRAINED
        } else {
            num::ADD_IDENTITY
        });
        w.raw(encode_add(key, cert, comment).into_bytes().as_slice());
        if let Some(secs) = lifetime {
            w.byte(num::CONSTRAIN_LIFETIME);
            w.u32(secs);
        }
        if let Some(dc) = destinations {
            w.byte(num::CONSTRAIN_EXTENSION);
            w.utf8("restrict-destination-v00@openssh.com");
            w.string(dc);
        }
        self.expect_success(&w.into_bytes(), "add the key").await
    }

    /// Remove the identity named by `blob`.
    pub async fn remove(&mut self, blob: &[u8]) -> Result<()> {
        let mut w = Writer::new();
        w.byte(num::REMOVE_IDENTITY);
        w.string(blob);
        self.expect_success(&w.into_bytes(), "remove the key").await
    }

    /// Remove every identity.
    pub async fn remove_all(&mut self) -> Result<()> {
        self.expect_success(&[num::REMOVE_ALL_IDENTITIES], "clear identities")
            .await
    }

    /// Lock the agent: identities vanish and nothing signs until `unlock`.
    pub async fn lock(&mut self, passphrase: &[u8]) -> Result<()> {
        let mut w = Writer::new();
        w.byte(num::LOCK);
        w.string(passphrase);
        self.expect_success(&w.into_bytes(), "lock").await
    }

    pub async fn unlock(&mut self, passphrase: &[u8]) -> Result<()> {
        let mut w = Writer::new();
        w.byte(num::UNLOCK);
        w.string(passphrase);
        self.expect_success(&w.into_bytes(), "unlock").await
    }

    /// Bind this agent connection to a host with `session-bind@openssh.com`:
    /// `host_blob` is the server's host-key blob, `session_id` the session
    /// identifier, and `sig` the host's signature over it (all straight from
    /// the transport). The agent verifies the signature and records the hop,
    /// which is how destination-constrained keys learn the path taken.
    /// `is_forwarding` marks a connection that is itself being forwarded on.
    pub async fn session_bind(
        &mut self,
        host_blob: &[u8],
        session_id: &[u8],
        sig: &[u8],
        is_forwarding: bool,
    ) -> Result<()> {
        let mut w = Writer::new();
        w.byte(num::EXTENSION);
        w.utf8("session-bind@openssh.com");
        w.string(host_blob);
        w.string(session_id);
        w.string(sig);
        w.boolean(is_forwarding);
        self.expect_success(&w.into_bytes(), "bind the session").await
    }
}
