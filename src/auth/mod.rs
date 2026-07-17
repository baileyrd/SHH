//! User authentication (RFC 4252) — public key only.
//!
//! `password` and `keyboard-interactive` are not disabled; they do not
//! exist. A client that offers anything but `publickey` gets the standard
//! USERAUTH_FAILURE naming `publickey` as the one road in. Signatures are
//! bound to the session identifier (RFC 4252 §7), so a captured auth
//! exchange is useless on any other connection.

use std::net::IpAddr;

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::crypto::cert::{self, Certificate, CERT_ALGO, CERT_TYPE_USER, SK_CERT_ALGO};
use crate::crypto::ed25519::{PrivateKey, PublicKey, ALGO};
use crate::crypto::sk::{SoftwareKey, SK_ALGO};
use crate::crypto::userkey::UserKey;
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
/// process, an agent that holds it for us, or a (software-emulated)
/// security key that produces an assertion.
enum SignWith<'a> {
    Key(&'a PrivateKey),
    Agent(&'a mut crate::agent::Client),
    SecurityKey(&'a SoftwareKey),
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

/// Authenticate as `user` with a security key: present its
/// `sk-ssh-ed25519@openssh.com` credential and sign the challenge as an
/// assertion. If `cert` (an `sk-ssh-ed25519-cert-v01` blob certifying this
/// key) is given, present it first and fall back to the bare credential.
/// User presence is assumed already confirmed by the caller (the CLI prompts
/// before calling), so the assertion carries the presence flag.
pub async fn client_sk<S>(
    t: &mut Transport<S>,
    user: &str,
    key: &SoftwareKey,
    cert: Option<&[u8]>,
    on_banner: impl FnMut(&str),
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut creds: Vec<(String, Vec<u8>)> = Vec::new();
    if let Some(c) = cert {
        creds.push((SK_CERT_ALGO.to_owned(), c.to_vec()));
    }
    creds.push((SK_ALGO.to_owned(), key.public().to_blob()));
    run_auth(t, user, creds, SignWith::SecurityKey(key), on_banner).await
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
            SignWith::SecurityKey(sk) => sk.sign(&span, true),
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
    /// Keys that may authenticate directly — Ed25519 or security-key
    /// (`sk-ssh-ed25519@openssh.com`) credentials.
    pub keys: Vec<UserKey>,
    /// Certificate authorities whose user certificates are trusted.
    pub trusted_cas: Vec<PublicKey>,
    /// Optional banner shown before authentication.
    pub banner: Option<String>,
}

fn same_key(a: &PublicKey, b: &PublicKey) -> bool {
    a.0.as_bytes().ct_eq(b.0.as_bytes()).unwrap_u8() == 1
}

impl Policy {
    fn key_authorized(&self, key: &UserKey) -> bool {
        self.keys.iter().any(|k| k.matches(key))
    }

    fn user_allowed(&self, user: &str) -> bool {
        match &self.user {
            Some(u) => u == user,
            None => true,
        }
    }

    /// Validate a presented certificate for `user`, connecting from `peer`,
    /// and if it checks out return the certified key to verify the userauth
    /// signature against together with any `force-command` it carries.
    fn authorize_cert(
        &self,
        blob: &[u8],
        user: &str,
        peer: Option<IpAddr>,
    ) -> Option<(UserKey, Option<String>)> {
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
        if cert.principals.is_empty() {
            tracing::warn!(
                key_id = %cert.key_id, %user,
                "accepting a certificate with no principals: valid for ANY login name"
            );
        }
        if !cert.permits_source(peer) {
            tracing::info!(key_id = %cert.key_id, ?peer, "certificate source-address does not admit this client");
            return None;
        }
        Some((cert.certified_user_key(), cert.force_command))
    }
}

/// The result of a successful authentication: the login name plus any
/// `force-command` the presented certificate pins the session to.
#[derive(Clone, Debug)]
pub struct Authenticated {
    pub user: String,
    pub force_command: Option<String>,
}

/// Run the server side of authentication. `peer` is the client's address,
/// used to enforce a certificate's `source-address` option (an unknown
/// address fails such a check closed). Returns the authenticated login name
/// and any `force-command` its certificate pins the session to.
pub async fn server<S>(
    t: &mut Transport<S>,
    policy: &Policy,
    peer: Option<IpAddr>,
) -> Result<Authenticated>
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
        // itself (plain publickey) or the key certified by a trusted CA. A
        // certificate may additionally pin a forced command.
        let authorized = if !policy.user_allowed(&user) {
            None
        } else if algo == ALGO || algo == SK_ALGO {
            // A bare key or a security-key credential: it must be listed.
            UserKey::from_blob(&blob)
                .ok()
                .filter(|k| policy.key_authorized(k))
                .map(|k| (k, None))
        } else if algo == CERT_ALGO || algo == SK_CERT_ALGO {
            policy.authorize_cert(&blob, &user, peer)
        } else {
            None
        };
        let Some((verify_key, force_command)) = authorized else {
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
        return Ok(Authenticated {
            user,
            force_command,
        });
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
            server(&mut t, &policy, None).await.map(|a| a.user)
        };
        tokio::join!(client_side, server_side)
    }

    #[tokio::test]
    async fn authorized_key_succeeds() {
        let key = PrivateKey::generate();
        let policy = Policy {
            user: Some("river".into()),
            keys: vec![key.public().into()],
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
            keys: vec![PrivateKey::generate().public().into()], // someone else's
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
            keys: vec![key.public().into()],
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
            server(&mut t, &policy, None).await.map(|a| a.user)
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
            keys: vec![key.public().into()],
            trusted_cas: vec![], // nobody trusts the CA
            banner: None,
        };
        let (c, s) = cert_authed(&key, Some(cert), policy, "river").await;
        c.unwrap();
        assert_eq!(s.unwrap(), "river");
    }

    /// Like `cert_authed` but keeps the full `Authenticated` result and lets
    /// the test supply the client's apparent peer address (for source-address).
    async fn cert_authed_peer(
        client_key: &PrivateKey,
        cert: Vec<u8>,
        policy: Policy,
        user: &str,
        peer: Option<IpAddr>,
    ) -> (Result<()>, Result<Authenticated>) {
        let (a, b) = duplex(1 << 20);
        let host_key = PrivateKey::generate();
        let user = user.to_owned();
        let client_key = client_key.clone();
        let client_side = async move {
            let mut t =
                Transport::client(a, ClientConfig::with_verifier(Box::new(|_| Ok(())))).await?;
            client(&mut t, &user, &client_key, Some(&cert), |_| {}).await
        };
        let server_side = async move {
            let mut t = Transport::server(b, ServerConfig::with_host_key(host_key)).await?;
            server(&mut t, &policy, peer).await
        };
        tokio::join!(client_side, server_side)
    }

    #[tokio::test]
    async fn cert_force_command_is_surfaced() {
        let ca = PrivateKey::generate();
        let user_key = PrivateKey::generate();
        let opts = cert::CertOptions {
            force_command: Some("/usr/bin/backup --nightly".into()),
            ..Default::default()
        };
        let cert = cert::sign_user_cert_with(
            &ca, &user_key.public(), &opts, 1, "id", &["river".into()], 0, u64::MAX,
        );
        let policy = Policy {
            user: Some("river".into()),
            keys: vec![],
            trusted_cas: vec![ca.public()],
            banner: None,
        };
        let (c, s) = cert_authed_peer(&user_key, cert, policy, "river", None).await;
        c.unwrap();
        let authed = s.unwrap();
        assert_eq!(authed.user, "river");
        assert_eq!(authed.force_command.as_deref(), Some("/usr/bin/backup --nightly"));
    }

    #[tokio::test]
    async fn cert_source_address_gates_login() {
        let ca = PrivateKey::generate();
        let user_key = PrivateKey::generate();
        let opts = cert::CertOptions {
            source_address: Some("192.0.2.0/24".into()),
            ..Default::default()
        };
        let cert = cert::sign_user_cert_with(
            &ca, &user_key.public(), &opts, 1, "id", &["river".into()], 0, u64::MAX,
        );
        let mk_policy = || Policy {
            user: Some("river".into()),
            keys: vec![], // only the cert can let anyone in
            trusted_cas: vec![ca.public()],
            banner: None,
        };

        // An in-range client is admitted.
        let ok: IpAddr = "192.0.2.10".parse().unwrap();
        let (c, s) = cert_authed_peer(&user_key, cert.clone(), mk_policy(), "river", Some(ok)).await;
        c.unwrap();
        assert_eq!(s.unwrap().user, "river");

        // An out-of-range client is refused (no fallback key is authorized).
        let bad: IpAddr = "198.51.100.1".parse().unwrap();
        let (c, _s) = cert_authed_peer(&user_key, cert, mk_policy(), "river", Some(bad)).await;
        assert!(matches!(c, Err(Error::Auth(_))));
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
            server(&mut t, &policy, None).await.map(|a| a.user)
        };
        tokio::join!(client_side, server_side)
    }

    #[tokio::test]
    async fn agent_key_authenticates() {
        let key = PrivateKey::generate();
        let policy = Policy {
            user: Some("river".into()),
            keys: vec![key.public().into()],
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
            keys: vec![key.public().into()],
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
            keys: vec![PrivateKey::generate().public().into()],
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

    // --------------------------------------------- security keys (FIDO2) ---

    /// Drive a userauth exchange presenting a security-key assertion built by
    /// a software authenticator. `touch` models the user-presence flag.
    /// Returns the server's reply byte and the server-side auth result.
    async fn sk_authed(
        dev: crate::crypto::sk::SoftwareKey,
        policy: Policy,
        user: &str,
        touch: bool,
    ) -> (Result<u8>, Result<String>) {
        let (a, b) = duplex(1 << 20);
        let host_key = PrivateKey::generate();
        let blob = dev.public().to_blob();
        let user = user.to_owned();
        let client_side = async move {
            let mut t =
                Transport::client(a, ClientConfig::with_verifier(Box::new(|_| Ok(())))).await?;
            let mut w = Writer::new();
            w.byte(msg::SERVICE_REQUEST);
            w.utf8(SERVICE_USERAUTH);
            t.send(&w.into_bytes()).await?;
            let _accept = t.recv().await?;

            let span = signed_span(t.session_id(), &user, SK_ALGO, &blob);
            let sig = dev.sign(&span, touch);
            let mut w = Writer::new();
            w.byte(msg::USERAUTH_REQUEST);
            w.utf8(&user);
            w.utf8(SERVICE_CONNECTION);
            w.utf8("publickey");
            w.boolean(true);
            w.utf8(SK_ALGO);
            w.string(&blob);
            w.string(&sig);
            t.send(&w.into_bytes()).await?;
            let reply = t.recv().await?;
            Ok::<u8, Error>(reply[0])
        };
        let server_side = async move {
            let mut t = Transport::server(b, ServerConfig::with_host_key(host_key)).await?;
            server(&mut t, &policy, None).await.map(|a| a.user)
        };
        tokio::join!(client_side, server_side)
    }

    #[tokio::test]
    async fn client_sk_authenticates_end_to_end() {
        // The real client entry point (auth::client_sk) against auth::server.
        let key = crate::crypto::sk::SoftwareKey::generate("ssh:");
        let policy = Policy {
            user: Some("river".into()),
            keys: vec![UserKey::Sk(key.public())],
            trusted_cas: vec![],
            banner: None,
        };
        let (a, b) = duplex(1 << 20);
        let host_key = PrivateKey::generate();
        let client_side = async move {
            let mut t =
                Transport::client(a, ClientConfig::with_verifier(Box::new(|_| Ok(())))).await?;
            client_sk(&mut t, "river", &key, None, |_| {}).await
        };
        let server_side = async move {
            let mut t = Transport::server(b, ServerConfig::with_host_key(host_key)).await?;
            server(&mut t, &policy, None).await.map(|a| a.user)
        };
        let (c, s) = tokio::join!(client_side, server_side);
        c.unwrap();
        assert_eq!(s.unwrap(), "river");
    }

    #[tokio::test]
    async fn client_sk_certificate_authenticates_end_to_end() {
        // A security key presenting a CA-signed sk certificate: the server
        // trusts only the CA, and the certified sk credential must verify the
        // assertion.
        let ca = PrivateKey::generate();
        let key = crate::crypto::sk::SoftwareKey::generate("ssh:");
        let cert = cert::sign_sk_user_cert(
            &ca,
            &key.public(),
            1,
            "sk-id",
            &["river".into()],
            0,
            u64::MAX,
        );
        let policy = Policy {
            user: Some("river".into()),
            keys: vec![], // only the CA is trusted; the cert must carry it
            trusted_cas: vec![ca.public()],
            banner: None,
        };
        let (a, b) = duplex(1 << 20);
        let host_key = PrivateKey::generate();
        let client_side = async move {
            let mut t =
                Transport::client(a, ClientConfig::with_verifier(Box::new(|_| Ok(())))).await?;
            client_sk(&mut t, "river", &key, Some(&cert), |_| {}).await
        };
        let server_side = async move {
            let mut t = Transport::server(b, ServerConfig::with_host_key(host_key)).await?;
            server(&mut t, &policy, None).await.map(|a| a.user)
        };
        let (c, s) = tokio::join!(client_side, server_side);
        c.unwrap();
        assert_eq!(s.unwrap(), "river");
    }

    #[tokio::test]
    async fn sk_certificate_from_untrusted_ca_falls_back_to_bare_key() {
        // The server trusts the sk credential directly but not the cert's CA.
        // The client offers the cert first, is refused, and lands on the bare
        // credential.
        let ca = PrivateKey::generate();
        let key = crate::crypto::sk::SoftwareKey::generate("ssh:");
        let cert =
            cert::sign_sk_user_cert(&ca, &key.public(), 1, "id", &["river".into()], 0, u64::MAX);
        let policy = Policy {
            user: Some("river".into()),
            keys: vec![UserKey::Sk(key.public())],
            trusted_cas: vec![], // nobody trusts the CA
            banner: None,
        };
        let (a, b) = duplex(1 << 20);
        let host_key = PrivateKey::generate();
        let client_side = async move {
            let mut t =
                Transport::client(a, ClientConfig::with_verifier(Box::new(|_| Ok(())))).await?;
            client_sk(&mut t, "river", &key, Some(&cert), |_| {}).await
        };
        let server_side = async move {
            let mut t = Transport::server(b, ServerConfig::with_host_key(host_key)).await?;
            server(&mut t, &policy, None).await.map(|a| a.user)
        };
        let (c, s) = tokio::join!(client_side, server_side);
        c.unwrap();
        assert_eq!(s.unwrap(), "river");
    }

    #[tokio::test]
    async fn security_key_authenticates() {
        let dev = crate::crypto::sk::SoftwareKey::generate("ssh:");
        let policy = Policy {
            user: Some("river".into()),
            keys: vec![UserKey::Sk(dev.public())],
            trusted_cas: vec![],
            banner: None,
        };
        let (reply, user) = sk_authed(dev, policy, "river", true).await;
        assert_eq!(reply.unwrap(), msg::USERAUTH_SUCCESS);
        assert_eq!(user.unwrap(), "river");
    }

    #[tokio::test]
    async fn security_key_without_touch_is_refused() {
        // A valid Ed25519 assertion, but the authenticator did not assert
        // user presence: the server must reject it.
        let dev = crate::crypto::sk::SoftwareKey::generate("ssh:");
        let policy = Policy {
            user: Some("river".into()),
            keys: vec![UserKey::Sk(dev.public())],
            trusted_cas: vec![],
            banner: None,
        };
        let (reply, _s) = sk_authed(dev, policy, "river", false).await;
        assert_eq!(reply.unwrap(), msg::USERAUTH_FAILURE);
    }

    #[tokio::test]
    async fn unlisted_security_key_is_refused() {
        let dev = crate::crypto::sk::SoftwareKey::generate("ssh:");
        let other = crate::crypto::sk::SoftwareKey::generate("ssh:");
        let policy = Policy {
            user: Some("river".into()),
            keys: vec![UserKey::Sk(other.public())], // a different credential
            trusted_cas: vec![],
            banner: None,
        };
        let (reply, _s) = sk_authed(dev, policy, "river", true).await;
        assert_eq!(reply.unwrap(), msg::USERAUTH_FAILURE);
    }
}
