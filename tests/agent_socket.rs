//! The agent over a real Unix socket: binding semantics (permissions, stale
//! socket replacement, live-agent refusal) and a client round trip — the
//! same path `shh-agent` the binary drives, minus the CLI.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use shh::agent::{server, Client};
use shh::crypto::ed25519::PrivateKey;

fn serve(listener: tokio::net::UnixListener, keyring: Arc<server::Keyring>) {
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let kr = keyring.clone();
            tokio::spawn(async move {
                let _ = server::serve_conn(stream, &kr).await;
            });
        }
    });
}

#[tokio::test]
async fn socket_roundtrip_with_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.sock");
    let listener = server::bind(&path).await.unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "agent socket must be 0600");

    serve(listener, Arc::new(server::Keyring::new()));

    let key = PrivateKey::generate();
    let mut c = Client::connect(&path).await.unwrap();
    c.add(&key, None, "over the socket", None).await.unwrap();

    // A second client sees the identity and gets signatures from it.
    let mut c2 = Client::connect(&path).await.unwrap();
    let ids = c2.identities().await.unwrap();
    assert_eq!(ids.len(), 1);
    let sig = c2.sign(&ids[0].blob, b"payload").await.unwrap();
    key.public().verify(b"payload", &sig).unwrap();
}

#[tokio::test]
async fn bind_replaces_stale_but_respects_live() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.sock");

    // A dead agent leaves its socket file behind; a new bind takes over.
    drop(server::bind(&path).await.unwrap());
    assert!(path.exists(), "socket file lingers after the listener dies");
    let listener = server::bind(&path).await.unwrap();

    // But a *live* agent on the path is not clobbered.
    serve(listener, Arc::new(server::Keyring::new()));
    let err = server::bind(&path).await.unwrap_err();
    assert!(err.to_string().contains("already listening"), "{err}");
}
