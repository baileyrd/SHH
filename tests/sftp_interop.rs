//! Interop: our SFTP *client* engine against OpenSSH's real `sftp-server`.
//!
//! `sftp-server` speaks SFTP directly on its stdin/stdout — no SSH transport
//! is involved — so we can drive it as a subprocess and confirm our client
//! interoperates with the reference implementation on every operation we use.
//! Skips cleanly (a pass) when no `sftp-server` binary is installed.

use shh::sftp::client::Client;
use tokio::process::Command;

fn find_sftp_server() -> Option<&'static str> {
    [
        "/usr/lib/openssh/sftp-server",
        "/usr/libexec/sftp-server",
        "/usr/lib/ssh/sftp-server",
        "/usr/libexec/openssh/sftp-server",
    ]
    .into_iter()
    .find(|p| std::path::Path::new(p).exists())
}

#[tokio::test]
async fn client_drives_openssh_sftp_server() {
    let Some(server_bin) = find_sftp_server() else {
        eprintln!("no OpenSSH sftp-server installed; skipping interop test");
        return;
    };

    let mut child = Command::new(server_bin)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn sftp-server");
    let writer = child.stdin.take().unwrap();
    let reader = child.stdout.take().unwrap();

    let mut c = Client::connect(reader, writer)
        .await
        .expect("SFTP handshake with OpenSSH sftp-server");

    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().to_string_lossy().into_owned();
    let p = |name: &str| format!("{base}/{name}");

    // put → the reference server writes our bytes to disk.
    let content = b"round trip through OpenSSH sftp-server\n";
    c.upload(&mut &content[..], &p("a.txt"), 0o644).await.unwrap();
    assert_eq!(std::fs::read(p("a.txt")).unwrap(), content);

    // stat + get come back identical.
    assert_eq!(c.stat(&p("a.txt")).await.unwrap().size, Some(content.len() as u64));
    let mut got = Vec::new();
    c.download(&p("a.txt"), &mut got).await.unwrap();
    assert_eq!(got, content);

    // mkdir + list (the reference server builds the NAME/longname entries).
    c.mkdir(&p("d")).await.unwrap();
    let names: Vec<String> = c.list(&base).await.unwrap().into_iter().map(|e| e.name).collect();
    assert!(names.contains(&"a.txt".to_string()));
    assert!(names.contains(&"d".to_string()));

    // rename, remove, rmdir, realpath all interoperate.
    c.rename(&p("a.txt"), &p("b.txt")).await.unwrap();
    assert!(std::fs::metadata(p("b.txt")).is_ok());
    c.remove(&p("b.txt")).await.unwrap();
    c.rmdir(&p("d")).await.unwrap();
    assert!(c.realpath(&base).await.unwrap().starts_with('/'));

    drop(c); // closes stdin → sftp-server exits
    let _ = child.wait().await;
}
