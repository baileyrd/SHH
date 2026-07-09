//! Destination-constrained agent keys, end to end over a real transport:
//! a key restricted to one host authenticates through that host and is
//! refused for any other — driven exactly as `shh` drives it (session-bind
//! from the transport's host binding, then agent auth).

use std::sync::Arc;

use shh::agent::server::{serve_conn, Keyring};
use shh::agent::{encode_destinations, Client};
use shh::auth::{self, Policy};
use shh::crypto::ed25519::PrivateKey;
use shh::transport::{ClientConfig, ServerConfig, Transport};

/// A keyring behind an in-memory socket, plus a client for it.
fn agent() -> (Arc<Keyring>, Client) {
    let keyring = Arc::new(Keyring::new());
    let (a, b) = tokio::io::duplex(1 << 16);
    let kr = keyring.clone();
    tokio::spawn(async move {
        let _ = serve_conn(b, &kr).await;
    });
    (keyring, Client::from_stream(a))
}

fn client_for(keyring: &Arc<Keyring>) -> Client {
    let (a, b) = tokio::io::duplex(1 << 16);
    let kr = keyring.clone();
    tokio::spawn(async move {
        let _ = serve_conn(b, &kr).await;
    });
    Client::from_stream(a)
}

/// Authenticate to a server that uses `server_host_key`, with an agent
/// connection `agent` holding `user_key` (constrained or not). Mirrors
/// `shh`: bind the agent to the host, then run agent auth. Returns the auth
/// result for the client side.
async fn attempt(
    server_host_key: PrivateKey,
    mut agent: Client,
    authorized: &PrivateKey,
) -> shh::Result<()> {
    let (a, b) = tokio::io::duplex(1 << 20);
    let policy = Policy {
        user: Some("river".into()),
        keys: vec![authorized.public().into()],
        trusted_cas: vec![],
        banner: None,
    };
    let server = tokio::spawn(async move {
        let mut t = Transport::server(b, ServerConfig::with_host_key(server_host_key))
            .await
            .unwrap();
        let _ = auth::server(&mut t, &policy, None).await;
    });

    let mut t = Transport::client(a, ClientConfig::with_verifier(Box::new(|_| Ok(())))).await?;
    // Exactly what shh does before using the agent (owned copies so the
    // immutable host borrow ends before auth takes `&mut t`).
    let (blob, session_id, sig) = {
        let (blob, sig) = t.host_binding();
        (blob.to_vec(), t.session_id().to_vec(), sig.to_vec())
    };
    agent.session_bind(&blob, &session_id, &sig, false).await?;
    let ids = agent.identities().await?;
    let result = auth::client_agent(&mut t, "river", &mut agent, &ids, |_| {}).await;
    server.abort();
    result
}

#[tokio::test]
async fn constrained_key_authenticates_to_its_permitted_host() {
    let host = PrivateKey::generate();
    let user = PrivateKey::generate();
    let (kr, mut adder) = agent();

    // Restrict the user key to the server's host key.
    let dests = encode_destinations(&[(
        String::new(),
        "gw".into(),
        vec![(host.public().to_blob(), false)],
    )]);
    adder
        .add_constrained(&user, None, "restricted", None, Some(&dests))
        .await
        .unwrap();

    // Connecting to that very host: the agent signs, auth succeeds.
    attempt(host, client_for(&kr), &user).await.unwrap();
}

#[tokio::test]
async fn constrained_key_refused_for_a_different_host() {
    let permitted = PrivateKey::generate();
    let actual = PrivateKey::generate(); // the server actually uses this one
    let user = PrivateKey::generate();
    let (kr, mut adder) = agent();

    // Restrict to `permitted`, but connect to a server keyed by `actual`.
    let dests = encode_destinations(&[(
        String::new(),
        "gw".into(),
        vec![(permitted.public().to_blob(), false)],
    )]);
    adder
        .add_constrained(&user, None, "restricted", None, Some(&dests))
        .await
        .unwrap();

    // The bind carries the actual host key, which the constraint forbids, so
    // the agent refuses to sign and auth fails — the key can't be used here.
    let err = attempt(actual, client_for(&kr), &user)
        .await
        .unwrap_err();
    assert!(matches!(err, shh::Error::Auth(_)), "got {err:?}");
}
