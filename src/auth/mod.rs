//! User authentication (RFC 4252) — public key only.
//!
//! `password` and `keyboard-interactive` are not disabled; they do not
//! exist. A client that offers anything but `publickey` gets the standard
//! USERAUTH_FAILURE naming `publickey` as the one road in. Signatures are
//! bound to the session identifier (RFC 4252 §7), so a captured auth
//! exchange is useless on any other connection.

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::crypto::ed25519::{PrivateKey, PublicKey, ALGO};
use crate::transport::Transport;
use crate::wire::{msg, Reader, Writer};
use crate::{Error, Result};

const SERVICE_USERAUTH: &str = "ssh-userauth";
const SERVICE_CONNECTION: &str = "ssh-connection";
/// A peer that can't authenticate in this many requests is done trying.
const MAX_ATTEMPTS: u32 = 16;

/// The bytes an authentication signature covers: the session identifier,
/// then the USERAUTH_REQUEST fields up to and including the public key.
fn signed_span(session_id: &[u8], user: &str, pubkey_blob: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.string(session_id);
    w.byte(msg::USERAUTH_REQUEST);
    w.utf8(user);
    w.utf8(SERVICE_CONNECTION);
    w.utf8("publickey");
    w.boolean(true);
    w.utf8(ALGO);
    w.string(pubkey_blob);
    w.into_bytes()
}

// ------------------------------------------------------------- client ---

/// Authenticate as `user` with `key`. Banner text, if the server sends
/// any, is handed to `on_banner`.
pub async fn client<S>(
    t: &mut Transport<S>,
    user: &str,
    key: &PrivateKey,
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

    // One key, one attempt, signature included up front. The PK_OK probe
    // round-trip exists for clients juggling many keys; we are not one.
    let blob = key.public().to_blob();
    let sig = key.sign(&signed_span(t.session_id(), user, &blob));
    let mut w = Writer::new();
    w.byte(msg::USERAUTH_REQUEST);
    w.utf8(user);
    w.utf8(SERVICE_CONNECTION);
    w.utf8("publickey");
    w.boolean(true);
    w.utf8(ALGO);
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
                let methods = r.name_list()?;
                return Err(Error::Auth(format!(
                    "server rejected our key (it accepts: {})",
                    methods.join(",")
                )));
            }
            other => {
                return Err(Error::proto(format!(
                    "unexpected message {other} during authentication"
                )))
            }
        }
    }
}

// ------------------------------------------------------------- server ---

/// Who may log in.
pub struct Policy {
    /// Required username; `None` accepts any name (the key still decides).
    pub user: Option<String>,
    /// Keys that may authenticate.
    pub keys: Vec<PublicKey>,
    /// Optional banner shown before authentication.
    pub banner: Option<String>,
}

impl Policy {
    fn key_authorized(&self, key: &PublicKey) -> bool {
        self.keys
            .iter()
            .any(|k| k.0.as_bytes().ct_eq(key.0.as_bytes()).unwrap_u8() == 1)
    }

    fn user_allowed(&self, user: &str) -> bool {
        match &self.user {
            Some(u) => u == user,
            None => true,
        }
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

        let acceptable = algo == ALGO
            && policy.user_allowed(&user)
            && PublicKey::from_blob(&blob)
                .map(|k| policy.key_authorized(&k))
                .unwrap_or(false);
        if !acceptable {
            reject(t).await?;
            continue;
        }

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
        let key = PublicKey::from_blob(&blob)?;
        let span = signed_span(t.session_id(), &user, &blob);
        if key.verify(&span, &sig).is_err() {
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
                ClientConfig {
                    verify_host_key: Box::new(|_| Ok(())),
                },
            )
            .await?;
            client(&mut t, user, client_key, |_| {}).await
        };
        let server_side = async move {
            let mut t = Transport::server(b, ServerConfig { host_key }).await?;
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
            banner: None,
        };
        let (c, _s) = authed_pair(&key, policy, "mallory").await;
        assert!(matches!(c, Err(Error::Auth(_))));
    }
}
