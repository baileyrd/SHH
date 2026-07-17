//! `direct-tcpip` forwarding: the per-channel splice task, the server's
//! allowlist policy, and the client's local-listener acceptor.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Semaphore};

use super::mux::{Cmd, Handle, ToTask};
use super::MAX_CHUNK;

/// Which direct-tcpip targets a server will connect to on a client's
/// behalf. The default is [`Policy::DenyAll`]: forwarding is off unless an
/// operator explicitly opens targets, the opposite of RFC 4254's posture.
pub enum Policy {
    /// Refuse every forward (also the client-side value: clients never
    /// accept incoming opens).
    DenyAll,
    /// Permit any target. Only sensible on a trusted network.
    AllowAll,
    /// Permit these `(host, port)` pairs. `"*"` matches any host; port `0`
    /// matches any port.
    Allow(Vec<(String, u16)>),
}

impl Policy {
    pub fn permits(&self, host: &str, port: u16) -> bool {
        match self {
            Policy::DenyAll => false,
            Policy::AllowAll => true,
            Policy::Allow(list) => list
                .iter()
                .any(|(h, p)| (h == "*" || h == host) && (*p == 0 || *p == port)),
        }
    }

    /// Build a policy from `--permit-open` specs. `"any"` (or `"*:*"`) is
    /// [`Policy::AllowAll`]; otherwise each spec is `host:port`, where the
    /// port may be `*` for "any port".
    pub fn parse(specs: &[String]) -> Result<Policy, String> {
        if specs.is_empty() {
            return Ok(Policy::DenyAll);
        }
        let mut list = Vec::new();
        for spec in specs {
            let spec = spec.trim();
            if spec == "any" || spec == "*:*" {
                return Ok(Policy::AllowAll);
            }
            let (host, port) = spec
                .rsplit_once(':')
                .ok_or_else(|| format!("bad --permit-open spec {spec:?} (want host:port)"))?;
            let port = if port == "*" {
                0
            } else {
                port.parse::<u16>()
                    .map_err(|_| format!("bad port in --permit-open spec {spec:?}"))?
            };
            list.push((host.to_string(), port));
        }
        Ok(Policy::Allow(list))
    }
}

/// Splice a forwarded socket to a channel: socket reads become channel
/// data (gated by send-window credit), channel data becomes socket writes
/// (reported back so the receive window can reopen). Generic over the
/// stream type so tests and real `TcpStream`s share one path.
pub(crate) async fn forward_task<IO>(
    id: u32,
    stream: IO,
    credit: Arc<Semaphore>,
    remote_max: u32,
    mut to_task: mpsc::UnboundedReceiver<ToTask>,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(stream);

    // socket -> channel
    let reader = {
        let cmd_tx = cmd_tx.clone();
        async move {
            let mut buf = vec![0u8; MAX_CHUNK as usize];
            loop {
                let n = match rd.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let mut off = 0;
                while off < n {
                    let take = ((n - off) as u32).min(remote_max);
                    // Reserve send-window credit; the permit is spent until
                    // the peer grants more via WINDOW_ADJUST.
                    match credit.acquire_many(take).await {
                        Ok(p) => p.forget(),
                        Err(_) => return, // semaphore closed: channel gone
                    }
                    let chunk = buf[off..off + take as usize].to_vec();
                    if cmd_tx.send(Cmd::Data { id, bytes: chunk }).is_err() {
                        return;
                    }
                    off += take as usize;
                }
            }
            let _ = cmd_tx.send(Cmd::Eof { id });
        }
    };

    // channel -> socket
    let writer = {
        let cmd_tx = cmd_tx.clone();
        async move {
            while let Some(m) = to_task.recv().await {
                match m {
                    ToTask::Data(b) => {
                        if wr.write_all(&b).await.is_err() {
                            break;
                        }
                        let _ = cmd_tx.send(Cmd::Consumed {
                            id,
                            n: b.len() as u32,
                        });
                    }
                    ToTask::Eof => {
                        let _ = wr.shutdown().await;
                    }
                    ToTask::Close => break,
                    // A forwarded stream has no stderr and grants no
                    // channel requests.
                    ToTask::Request { want_reply, .. } => {
                        if want_reply {
                            let _ = cmd_tx.send(Cmd::RequestReply { id, success: false });
                        }
                    }
                    ToTask::ExtData(..) | ToTask::RequestReply(_) => {}
                }
            }
        }
    };

    tokio::join!(reader, writer);
    let _ = cmd_tx.send(Cmd::Close { id });
}

/// A parsed `-L` local forward: listen on `bind`, connect each accepted
/// socket to `target_host:target_port` through the tunnel.
pub struct LocalForward {
    pub bind: String,
    pub target_host: String,
    pub target_port: u16,
}

impl LocalForward {
    /// Parse `[bind:]localport:host:hostport` (IPv4 / hostname targets).
    /// A bare `localport` binds `127.0.0.1`.
    pub fn parse(spec: &str) -> Result<LocalForward, String> {
        let parts: Vec<&str> = spec.split(':').collect();
        let (bind_host, lport, host, hport) = match parts.as_slice() {
            [lport, host, hport] => ("127.0.0.1", *lport, *host, *hport),
            [bind, lport, host, hport] => (*bind, *lport, *host, *hport),
            _ => {
                return Err(format!(
                    "bad -L spec {spec:?} (want [bind:]localport:host:hostport)"
                ))
            }
        };
        let lport: u16 = lport
            .parse()
            .map_err(|_| format!("bad local port in -L spec {spec:?}"))?;
        let hport: u16 = hport
            .parse()
            .map_err(|_| format!("bad host port in -L spec {spec:?}"))?;
        if host.is_empty() {
            return Err(format!("empty target host in -L spec {spec:?}"));
        }
        Ok(LocalForward {
            bind: format!("{bind_host}:{lport}"),
            target_host: host.to_string(),
            target_port: hport,
        })
    }
}

/// Accept local connections on `listener` and open a forwarded channel for
/// each. Runs until the listener errors or the connection loop is gone.
pub async fn serve_local_forward(
    listener: TcpListener,
    target_host: String,
    target_port: u16,
    handle: Handle,
) -> std::io::Result<()> {
    loop {
        let (sock, peer) = listener.accept().await?;
        sock.set_nodelay(true).ok();
        handle
            .open_direct(target_host.clone(), target_port, peer.ip().to_string(), peer.port(), sock)
            .await;
    }
}

/// A parsed `-R` remote forward: ask the server to listen on
/// `listen_bind:listen_port`, and connect the connections it forwards back
/// to `target_host:target_port` (reachable from this side).
pub struct RemoteForward {
    pub listen_bind: String,
    pub listen_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

impl RemoteForward {
    /// Parse `[bind:]port:host:hostport`. A bare `port` binds loopback on
    /// the server; an explicit bind of `*` or empty means all interfaces.
    pub fn parse(spec: &str) -> Result<RemoteForward, String> {
        let parts: Vec<&str> = spec.split(':').collect();
        let (bind, port, host, hport) = match parts.as_slice() {
            [port, host, hport] => ("127.0.0.1", *port, *host, *hport),
            [bind, port, host, hport] => (*bind, *port, *host, *hport),
            _ => {
                return Err(format!(
                    "bad -R spec {spec:?} (want [bind:]port:host:hostport)"
                ))
            }
        };
        let listen_port: u16 = port
            .parse()
            .map_err(|_| format!("bad listen port in -R spec {spec:?}"))?;
        let target_port: u16 = hport
            .parse()
            .map_err(|_| format!("bad host port in -R spec {spec:?}"))?;
        if host.is_empty() {
            return Err(format!("empty target host in -R spec {spec:?}"));
        }
        Ok(RemoteForward {
            listen_bind: bind.to_string(),
            listen_port,
            target_host: host.to_string(),
            target_port,
        })
    }
}

/// Accept connections on a server-side remote-forward listener and open a
/// `forwarded-tcpip` channel back to the client for each. `addr`/`port` are
/// the listened address as the client requested them (echoed in the open).
pub async fn serve_remote_listener(
    listener: TcpListener,
    addr: String,
    port: u16,
    handle: Handle,
) {
    loop {
        let Ok((sock, peer)) = listener.accept().await else {
            break;
        };
        sock.set_nodelay(true).ok();
        handle
            .open_forwarded(addr.clone(), port, peer.ip().to_string(), peer.port(), sock)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_parsing_and_matching() {
        assert!(matches!(Policy::parse(&[]).unwrap(), Policy::DenyAll));
        assert!(matches!(
            Policy::parse(&["any".into()]).unwrap(),
            Policy::AllowAll
        ));

        let p = Policy::parse(&["db.internal:5432".into(), "127.0.0.1:*".into()]).unwrap();
        assert!(p.permits("db.internal", 5432));
        assert!(!p.permits("db.internal", 5433));
        assert!(p.permits("127.0.0.1", 9999)); // wildcard port
        assert!(!p.permits("evil.example", 80));

        assert!(Policy::parse(&["no-port".into()]).is_err());
        assert!(Policy::parse(&["host:notaport".into()]).is_err());
    }

    #[test]
    fn local_forward_specs() {
        let f = LocalForward::parse("8080:example.com:80").unwrap();
        assert_eq!(f.bind, "127.0.0.1:8080");
        assert_eq!(f.target_host, "example.com");
        assert_eq!(f.target_port, 80);

        let f = LocalForward::parse("0.0.0.0:2200:10.0.0.5:22").unwrap();
        assert_eq!(f.bind, "0.0.0.0:2200");
        assert_eq!(f.target_host, "10.0.0.5");
        assert_eq!(f.target_port, 22);

        assert!(LocalForward::parse("nope").is_err());
        assert!(LocalForward::parse("80:host:notaport").is_err());
    }

    #[test]
    fn remote_forward_specs() {
        let f = RemoteForward::parse("9000:localhost:3000").unwrap();
        assert_eq!(f.listen_bind, "127.0.0.1");
        assert_eq!(f.listen_port, 9000);
        assert_eq!(f.target_host, "localhost");
        assert_eq!(f.target_port, 3000);

        let f = RemoteForward::parse("*:8080:10.0.0.2:80").unwrap();
        assert_eq!(f.listen_bind, "*");
        assert_eq!(f.listen_port, 8080);
        assert_eq!(f.target_host, "10.0.0.2");
        assert_eq!(f.target_port, 80);

        assert!(RemoteForward::parse("nope").is_err());
        assert!(RemoteForward::parse("notaport:host:80").is_err());
    }
}
