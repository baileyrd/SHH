//! User authentication (RFC 4252) — public key only.
//!
//! `password` and `keyboard-interactive` are not disabled; they do not
//! exist. A client that offers anything but `publickey` gets the standard
//! USERAUTH_FAILURE naming `publickey` as the one road in. Signatures are
//! bound to the session identifier (RFC 4252 §7), so a captured auth
//! exchange is useless on any other connection.

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::crypto::cert::{self, Certificate, CERT_ALGO, CERT_TYPE_USER};
use crate::crypto::ed25519::{PrivateKey, PublicKey, ALGO};
use crate::transport::Transport;
use crate::wire::{msg, Reader, Writer};
use crate::{Error, Result};

const SERVICE_USERAUTH: &str = "ssh-userauth";
const SERVICE_CONNECTION: &str = "ssh-connection";
/// A peer that can't authenticate in this many requests is done trying.
const MAX_ATTEMPTS: u32 = 16;

/// The bytes an authentication signature covers: the session identifier,
/// then the USERAUTH_REQUEST fields up to and including the public-key blob
/// (a plain key or a certificate, named by `algo`).
fn signed_span(session_id: &[u8], user: &str, algo: &str, pubkey_blob: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.string(session_id);
    w.byte(msg::USERAUTH_REQUEST);
    w.utf8(user);
    w.utf8(SERVICE_CONNECTION);
    w.utf8("publickey");
    w.boolean(true);
    w.utf8(algo);
    w.string(pubkey_blob);
    w.into_bytes()
}

// ------------------------------------------------------------- client ---

/// Where a credential's signature comes from: a private key in this
/// process, or an agent that holds it for us.
enum SignWith<'a> {
    Key(&'a PrivateKey),
    Agent(&'a mut crate::agent::Client),
}

/// Authenticate as `user` with `key`. If `cert` (a certificate blob whose
/// key is `key`) is given, present the certificate first and fall back to
/// the bare key. Banner text, if the server sends any, goes to `on_banner`.
pub async fn client<S>(
    t: &mut Transport<S>,
    user: &str,
    key: &PrivateKey,
    cert: Option<&[u8]>,
    on_banner: impl FnMut(&str),
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut creds: Vec<(String, Vec<u8>)> = Vec::new();
    if let Some(c) = cert {
        creds.push((CERT_ALGO.to_owned(), c.to_vec()));
    }
    creds.push((ALGO.to_owned(), key.public().to_blob()));
    run_auth(t, user, creds, SignWith::Key(key), on_banner).await
}

/// Authenticate as `user` with identities held by an agent, certificates
/// first. Identities the modern subset can't use (non-Ed25519) are skipped.
pub async fn client_agent<S>(
    t: &mut Transport<S>,
    user: &str,
    agent: &mut crate::agent::Client,
    identities: &[crate::agent::Identity],
    on_banner: impl FnMut(&str),
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut creds: Vec<(String, Vec<u8>)> = Vec::new();
    for want_cert in [true, false] {
        for id in identities {
            match id.algo().as_deref() {
                Some(CERT_ALGO) if want_cert => creds.push((CERT_ALGO.to_owned(), id.blob.clone())),
                Some(ALGO) if !want_cert => creds.push((ALGO.to_owned(), id.blob.clone())),
                _ => {}
            }
        }
    }
    if creds.is_empty() {
        return Err(Error::Auth("the agent holds no Ed25519 identities".into()));
    }
    run_auth(t, user, creds, SignWith::Agent(agent), on_banner).await
}

/// The userauth conversation: offer each credential in turn, signature up
/// front (the PK_OK probe buys nothing when signing is this cheap), until
/// the server accepts one or the list runs out.
async fn run_auth<S>(
    t: &mut Transport<S>,
    user: &str,
    creds: Vec<(String, Vec<u8>)>,
    mut with: SignWith<'_>,
    mut on_banner: impl FnMut(&str),
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut w = Writer::new();
    w.byte(msg::SERVICE_REQUEST);
    w.utf8(SERVICE_USERAUTH);
    t.send(&w.into_bytes()).await?;

    let p = t.recv().await?;
    let mut r = Reader::new(&p);
    if r.byte()? != msg::SERVICE_ACCEPT || r.utf8()? != SERVICE_USERAUTH {
        return Err(Error::proto("expected SERVICE_ACCEPT ssh-userauth"));
    }

    let total = creds.len();
    let mut accepts = String::new();
    for (algo, blob) in creds {
        let span = signed_span(t.session_id(), user, &algo, &blob);
        let sig = match &mut with {
            SignWith::Key(k) => k.sign(&span),
            SignWith::Agent(a) => match a.sign(&blob, &span).await {
                Ok(sig) => sig,
                Err(e) => {
                    // The agent balked (key expired, agent locked mid-run).
                    // Nothing was sent, so the next credential is untainted.
                    tracing::info!("agent would not sign with an identity: {e}");
                    continue;
                }
            },
        };
        let mut w = Writer::new();
        w.byte(msg::USERAUTH_REQUEST);
        w.utf8(user);
        w.utf8(SERVICE_CONNECTION);
        w.utf8("publickey");
        w.boolean(true);
        w.utf8(&algo);
        w.string(&blob);
        w.string(&sig);
        t.send(&w.into_bytes()).await?;

        loop {
            let p = t.recv().await?;
            let mut r = Reader::new(&p);
            match r.byte()? {
                msg::USERAUTH_SUCCESS => return Ok(()),
                msg::USERAUTH_BANNER => on_banner(r.utf8()?),
                msg::USERAUTH_FAILURE => {
                    accepts = r.name_list()?.join(",");
                    break; // next credential
                }
                other => {
                    return Err(Error::proto(format!(
                        "unexpected message {other} during authentication"
                    )))
                }
            }
        }
    }
    Err(Error::Auth(format!(
        "server rejected all {total} offered credential(s) (it accepts: {accepts})"
    )))
}

// ------------------------------------------------------------- server ---

/// Who may log in.
pub struct Policy {
    /// Required username; `None` accepts any name (the key still decides).
    pub user: Option<String>,
    /// Keys that may authenticate directly.
    pub keys: Vec<PublicKey>,
    /// Certificate authorities whose user certificates are trusted.
    pub trusted_cas: Vec<PublicKey>,
    /// Optional banner shown before authentication.
    pub banner: Option<String>,
}

fn same_key(a: &PublicKey, b: &PublicKey) -> bool {
    a.0.as_bytes().ct_eq(b.0.as_bytes()).unwrap_u8() == 1
}

impl Policy {
    fn key_authorized(&self, key: &PublicKey) -> bool {
        self.keys.iter().any(|k| same_key(k, key))
    }

    fn user_allowed(&self, user: &str) -> bool {
        match &self.user {
            Some(u) => u == user,
            None => true,
        }
    }

    /// Validate a presented certificate for `user` and, if it checks out,
    /// return the certified key to verify the userauth signature against.
    fn authorize_cert(&self, blob: &[u8], user: &str) -> Option<PublicKey> {
        let cert = match Certificate::parse_and_verify(blob) {
            Ok(c) => c,
            Err(e) => {
                tracing::info!("rejecting certificate: {e}");
                return None;
            }
        };
        if cert.cert_type != CERT_TYPE_USER {
            tracing::info!("rejecting non-user certificate (type {})", cert.cert_type);
            return None;
        }
        if !self.trusted_cas.iter().any(|ca| same_key(ca, &cert.ca_key)) {
            tracing::info!(key_id = %cert.key_id, "certificate CA is not trusted");
            return None;
        }
        if !cert.valid_at(cert::now_secs()) {
            tracing::info!(key_id = %cert.key_id, "certificate is expired or not yet valid");
            return None;
        }
        if !cert.permits_principal(user) {
            tracing::info!(key_id = %cert.key_id, %user, "certificate does not list this principal");
            return None;
        }
        Some(cert.key)
    }
}

/// Run the server side of authentication; returns the authenticated
/// username.
pub async fn server<S>(t: &mut Transport<S>, policy: &Policy) -> Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let p = t.recv().await?;
    let mut r = Reader::new(&p);
    if r.byte()? != msg::SERVICE_REQUEST || r.utf8()? != SERVICE_USERAUTH {
        return Err(Error::proto("expected SERVICE_REQUEST ssh-userauth"));
    }
    let mut w = Writer::new();
    w.byte(msg::SERVICE_ACCEPT);
    w.utf8(SERVICE_USERAUTH);
    t.send(&w.into_bytes()).await?;

    if let Some(text) = &policy.banner {
        let mut w = Writer::new();
        w.byte(msg::USERAUTH_BANNER);
        w.utf8(text);
        w.utf8(""); // language
        t.send(&w.into_bytes()).await?;
    }

    for _ in 0..MAX_ATTEMPTS {
        let p = t.recv().await?;
        let mut r = Reader::new(&p);
        if r.byte()? != msg::USERAUTH_REQUEST {
            return Err(Error::proto("expected USERAUTH_REQUEST"));
        }
        let user = r.utf8()?.to_owned();
        let service = r.utf8()?.to_owned();
        let method = r.utf8()?.to_owned();

        if service != SERVICE_CONNECTION {
            return Err(Error::Auth(format!("unknown service {service:?}")));
        }
        if method != "publickey" {
            // Includes the ritual "none" probe. The answer never varies:
            // publickey or nothing.
            reject(t).await?;
            continue;
        }

        let has_sig = r.boolean()?;
        let algo = r.utf8()?.to_owned();
        let blob = r.string()?.to_vec();

        // Derive the key whose signature we must verify: the presented key
        // itself (plain publickey) or the key certified by a trusted CA.
        let verify_key = if !policy.user_allowed(&user) {
            None
        } else if algo == ALGO {
            PublicKey::from_blob(&blob)
                .ok()
                .filter(|k| policy.key_authorized(k))
        } else if algo == CERT_ALGO {
            policy.authorize_cert(&blob, &user)
        } else {
            None
        };
        let Some(verify_key) = verify_key else {
            reject(t).await?;
            continue;
        };

        if !has_sig {
            // The client is asking "would this key be worth signing with?"
            r.finish()?;
            let mut w = Writer::new();
            w.byte(msg::USERAUTH_PK_OK);
            w.utf8(&algo);
            w.string(&blob);
            t.send(&w.into_bytes()).await?;
            continue;
        }

        let sig = r.string()?.to_vec();
        r.finish()?;
        let span = signed_span(t.session_id(), &user, &algo, &blob);
        if verify_key.verify(&span, &sig).is_err() {
            reject(t).await?;
            continue;
        }

        t.send(&[msg::USERAUTH_SUCCESS]).await?;
        return Ok(user);
    }

    Err(Error::Auth("too many authentication attempts".into()))
}

async fn reject<S>(t: &mut Transport<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut w = Writer::new();
    w.byte(msg::USERAUTH_FAILURE);
    w.name_list(&["publickey"]);
    w.boolean(false); // no partial success
    t.send(&w.into_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{ClientConfig, ServerConfig};
    use tokio::io::duplex;

    async fn authed_pair(
        client_key: &PrivateKey,
        policy: Policy,
        user: &str,
    ) -> (Result<()>, Result<String>) {
        let (a, b) = duplex(1 << 20);
        let host_key = PrivateKey::generate();
        let client_side = async move {
            let mut t = Transport::client(
                a,
                ClientConfig::with_verifier(Box::new(|_| Ok(()))),
            )
            .await?;
            client(&mut t, user, client_key, None, |_| {}).await
        };
        let server_side = async move {
            let mut t = Transport::server(b, ServerConfig::with_host_key(host_key)).await?;
            server(&mut t, &policy).await
        };
        tokio::join!(client_side, server_side)
    }

    #[tokio::test]
    async fn authorized_key_succeeds() {
        let key = PrivateKey::generate();
        let policy = Policy {
            user: Some("river".into()),
            keys: vec![key.public()],
            trusted_cas: vec![],
            banner: Some("welcome to the test rig".into()),
        };
        let (c, s) = authed_pair(&key, policy, "river").await;
        c.unwrap();
        assert_eq!(s.unwrap(), "river");
    }

    #[tokio::test]
    async fn unauthorized_key_fails() {
        let key = PrivateKey::generate();
        let policy = Policy {
            user: None,
            keys: vec![PrivateKey::generate().public()], // someone else's
            trusted_cas: vec![],
            banner: None,
        };
        let (c, s) = authed_pair(&key, policy, "river").await;
        assert!(matches!(c, Err(Error::Auth(_))));
        assert!(s.is_err());
    }

    #[tokio::test]
    async fn wrong_username_fails() {
        let key = PrivateKey::generate();
        let policy = Policy {
            user: Some("river".into()),
            keys: vec![key.public()],
            trusted_cas: vec![],
            banner: None,
        };
        let (c, _s) = authed_pair(&key, policy, "mallory").await;
        assert!(matches!(c, Err(Error::Auth(_))));
    }

    /// Authenticate with a CA-signed certificate instead of a listed key.
    async fn cert_authed(
        client_key: &PrivateKey,
        cert: Option<Vec<u8>>,
        policy: Policy,
        user: &str,
    ) -> (Result<()>, Result<String>) {
        let (a, b) = duplex(1 << 20);
        let host_key = PrivateKey::generate();
        let user = user.to_owned();
        let client_key = client_key.clone();
        let client_side = async move {
            let mut t = Transport::client(
                a,
                ClientConfig::with_verifier(Box::new(|_| Ok(()))),
            )
            .await?;
            client(&mut t, &user, &client_key, cert.as_deref(), |_| {}).await
        };
        let server_side = async move {
            let mut t = Transport::server(b, ServerConfig::with_host_key(host_key)).await?;
            server(&mut t, &policy).await
        };
        tokio::join!(client_side, server_side)
    }

    #[tokio::test]
    async fn trusted_certificate_succeeds() {
        let ca = PrivateKey::generate();
        let user_key = PrivateKey::generate();
        let cert = cert::sign_user_cert(
            &ca,
            &user_key.public(),
            1,
            "id",
            &["river".into()],
            0,
            u64::MAX,
        );
        let policy = Policy {
            user: Some("river".into()),
            keys: vec![], // no listed keys — the CA is the only trust
            trusted_cas: vec![ca.public()],
            banner: None,
        };
        let (c, s) = cert_authed(&user_key, Some(cert), policy, "river").await;
        c.unwrap();
        assert_eq!(s.unwrap(), "river");
    }

    #[tokio::test]
    async fn certificate_from_untrusted_ca_fails() {
        let real_ca = PrivateKey::generate();
        let other_ca = PrivateKey::generate();
        let user_key = PrivateKey::generate();
        let cert =
            cert::sign_user_cert(&real_ca, &user_key.public(), 1, "id", &["river".into()], 0, u64::MAX);
        let policy = Policy {
            user: Some("river".into()),
            keys: vec![],
            trusted_cas: vec![other_ca.public()], // trusts a different CA
            banner: None,
        };
        let (c, _s) = cert_authed(&user_key, Some(cert), policy, "river").await;
        assert!(matches!(c, Err(Error::Auth(_))));
    }

    #[tokio::test]
    async fn certificate_wrong_principal_fails() {
        let ca = PrivateKey::generate();
        let user_key = PrivateKey::generate();
        let cert =
            cert::sign_user_cert(&ca, &user_key.public(), 1, "id", &["river".into()], 0, u64::MAX);
        let policy = Policy {
            user: None, // server accepts any username; the cert must gate it
            keys: vec![],
            trusted_cas: vec![ca.public()],
            banner: None,
        };
        // Logs in as "mallory", who is not a listed principal.
        let (c, _s) = cert_authed(&user_key, Some(cert), policy, "mallory").await;
        assert!(matches!(c, Err(Error::Auth(_))));
    }

    #[tokio::test]
    async fn untrusted_cert_falls_back_to_bare_key() {
        // The server trusts the key directly but not the cert's CA. The
        // client offers the cert first, is refused, and lands on the key.
        let ca = PrivateKey::generate();
        let key = PrivateKey::generate();
        let cert =
            cert::sign_user_cert(&ca, &key.public(), 1, "id", &["river".into()], 0, u64::MAX);
        let policy = Policy {
            user: Some("river".into()),
            keys: vec![key.public()],
            trusted_cas: vec![], // nobody trusts the CA
            banner: None,
        };
        let (c, s) = cert_authed(&key, Some(cert), policy, "river").await;
        c.unwrap();
        assert_eq!(s.unwrap(), "river");
    }

    /// A live in-memory agent holding `keys` (and one certificate, when
    /// given), plus the auth pair that uses it.
    async fn agent_authed(
        keys: &[&PrivateKey],
        cert: Option<(&PrivateKey, Vec<u8>)>,
        policy: Policy,
        user: &str,
    ) -> (Result<()>, Result<String>) {
        let (a, b) = duplex(1 << 16);
        let keyring = std::sync::Arc::new(crate::agent::server::Keyring::new());
        let kr = keyring.clone();
        tokio::spawn(async move {
            let _ = crate::agent::server::serve_conn(b, &kr).await;
        });
        let mut agent = crate::agent::Client::from_stream(a);
        for key in keys {
            agent.add(key, None, "held", None).await.unwrap();
        }
        if let Some((key, blob)) = cert {
            agent.add(key, Some(&blob), "certified", None).await.unwrap();
        }

        let (ta, tb) = duplex(1 << 20);
        let host_key = PrivateKey::generate();
        let user = user.to_owned();
        let client_side = async move {
            let mut t =
                Transport::client(ta, ClientConfig::with_verifier(Box::new(|_| Ok(())))).await?;
            let ids = agent.identities().await?;
            client_agent(&mut t, &user, &mut agent, &ids, |_| {}).await
        };
        let server_side = async move {
            let mut t = Transport::server(tb, ServerConfig::with_host_key(host_key)).await?;
            server(&mut t, &policy).await
        };
        tokio::join!(client_side, server_side)
    }

    #[tokio::test]
    async fn agent_key_authenticates() {
        let key = PrivateKey::generate();
        let policy = Policy {
            user: Some("river".into()),
            keys: vec![key.public()],
            trusted_cas: vec![],
            banner: None,
        };
        let (c, s) = agent_authed(&[&key], None, policy, "river").await;
        c.unwrap();
        assert_eq!(s.unwrap(), "river");
    }

    #[tokio::test]
    async fn agent_tries_keys_until_one_fits() {
        // The agent holds three keys; only the last is authorized.
        let stranger1 = PrivateKey::generate();
        let stranger2 = PrivateKey::generate();
        let key = PrivateKey::generate();
        let policy = Policy {
            user: Some("river".into()),
            keys: vec![key.public()],
            trusted_cas: vec![],
            banner: None,
        };
        let (c, s) = agent_authed(&[&stranger1, &stranger2, &key], None, policy, "river").await;
        c.unwrap();
        assert_eq!(s.unwrap(), "river");
    }

    #[tokio::test]
    async fn agent_certificate_authenticates() {
        let ca = PrivateKey::generate();
        let key = PrivateKey::generate();
        let cert_blob =
            cert::sign_user_cert(&ca, &key.public(), 1, "id", &["river".into()], 0, u64::MAX);
        let policy = Policy {
            user: Some("river".into()),
            keys: vec![], // only the CA is trusted; the cert must carry it
            trusted_cas: vec![ca.public()],
            banner: None,
        };
        let (c, s) = agent_authed(&[], Some((&key, cert_blob)), policy, "river").await;
        c.unwrap();
        assert_eq!(s.unwrap(), "river");
    }

    #[tokio::test]
    async fn agent_with_no_authorized_key_fails() {
        let key = PrivateKey::generate();
        let policy = Policy {
            user: Some("river".into()),
            keys: vec![PrivateKey::generate().public()],
            trusted_cas: vec![],
            banner: None,
        };
        let (c, s) = agent_authed(&[&key], None, policy, "river").await;
        assert!(matches!(c, Err(Error::Auth(_))));
        assert!(s.is_err());
    }

    #[tokio::test]
    async fn expired_certificate_fails() {
        let ca = PrivateKey::generate();
        let user_key = PrivateKey::generate();
        // Valid window entirely in the past.
        let cert = cert::sign_user_cert(&ca, &user_key.public(), 1, "id", &["river".into()], 0, 100);
        let policy = Policy {
            user: Some("river".into()),
            keys: vec![],
            trusted_cas: vec![ca.public()],
            banner: None,
        };
        let (c, _s) = cert_authed(&user_key, Some(cert), policy, "river").await;
        assert!(matches!(c, Err(Error::Auth(_))));
    }
}
