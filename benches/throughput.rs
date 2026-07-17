//! End-to-end bulk-transfer throughput through the full client/server stack:
//! handshake, transport encryption, channel multiplexing, and window flow
//! control — the complete `direct-tcpip` data path a real `-L` forward or an
//! `scp`-style transfer rides.
//!
//! The client and server transports are connected over an in-memory
//! `tokio::io::duplex` pipe, not a real socket, so this measures the
//! **implementation's own CPU-bound ceiling** (crypto + framing + copies +
//! window accounting) with no network latency or bandwidth mixed in. It is
//! not a substitute for a real network benchmark, but it is the right number
//! for "how much does SHH's own overhead cost," and for tracking regressions
//! across changes to the mux/transport hot path.
//!
//! Two SHH peers always negotiate `chacha20-poly1305@openssh.com` (it is
//! offered first by both sides and there's no per-connection override), so
//! that is the cipher this exercises; see `benches/cipher.rs` for a
//! side-by-side of the two supported AEAD ciphers in isolation.
//!
//! Run: `cargo bench --bench throughput`

use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use shh::connect::forward::{serve_local_forward, Policy};
use shh::connect::mux::Connection;
use shh::crypto::ed25519::PrivateKey;
use shh::transport::{ClientConfig, ServerConfig, Transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::task::AbortHandle;

// From just above a single MAX_CHUNK (64 KiB) up to a stress size (64 MiB),
// so the curve shows whether per-packet/window overhead is a fixed cost that
// amortizes away at scale or a per-byte cost that holds throughput flat.
const SIZES: &[usize] = &[64 << 10, 256 << 10, 1 << 20, 8 << 20, 32 << 20, 64 << 20];

/// A TCP "sink": reads until the writer half half-closes (EOF), then writes
/// back one ack byte. This measures one-directional bulk-push throughput
/// (the `scp`/`get` shape) plus a negligible confirmation round trip, rather
/// than paying to encrypt an echoed copy back.
///
/// Returns the accept loop's `AbortHandle` alongside the address: with tiny
/// payloads criterion's warm-up picks thousands of iterations, and this task
/// (like every task `open_tunnel` spawns) would otherwise never terminate —
/// a `direct-tcpip` connection closing does not end the underlying mux
/// `Connection` or a listener's accept loop. Left unaborted, the listener,
/// its ephemeral port, and the duplex buffers pile up across iterations
/// until the process runs out of file descriptors (this is exactly what
/// produced spurious `ConnectionReset` failures before this fix).
async fn spawn_sink() -> (std::net::SocketAddr, AbortHandle) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(_) => return,
                    }
                }
                let _ = s.write_all(&[1u8]).await;
            });
        }
    })
    .abort_handle();
    (addr, handle)
}

/// Everything a benchmark iteration must tear down once it's done: the
/// application socket to drive the transfer over, plus every background task
/// `open_tunnel` spawned to carry it (both `Connection::run` loops and the
/// local-forward accept loop) — none of which exit on their own just because
/// the one `direct-tcpip` channel they carried has closed.
struct Tunnel {
    app: TcpStream,
    tasks: Vec<AbortHandle>,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Build a fully handshaken client/server connection pair over an in-memory
/// duplex pipe and wire up a local forward to `target`, returning a
/// connected application socket ready to carry bulk data through it.
async fn open_tunnel(target: std::net::SocketAddr) -> Tunnel {
    let (a, b) = tokio::io::duplex(4 << 20);
    let host_key = PrivateKey::generate();
    let (client_t, server_t) = tokio::join!(
        Transport::client(a, ClientConfig::with_verifier(Box::new(|_| Ok(())))),
        Transport::server(b, ServerConfig::with_host_key(host_key)),
    );
    let (client_t, server_t) = (client_t.unwrap(), server_t.unwrap());

    let mut tasks = Vec::with_capacity(3);

    let server_conn = Connection::new(server_t, Policy::AllowAll);
    tasks.push(tokio::spawn(async move { server_conn.run(None).await }).abort_handle());

    let client_conn = Connection::new(client_t, Policy::DenyAll);
    let handle = client_conn.handle();
    tasks.push(tokio::spawn(async move { client_conn.run(None).await }).abort_handle());

    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = local.local_addr().unwrap();
    tasks.push(
        tokio::spawn(serve_local_forward(local, target.ip().to_string(), target.port(), handle))
            .abort_handle(),
    );

    let app = TcpStream::connect(local_addr).await.unwrap();
    Tunnel { app, tasks }
}

fn bench_bulk_push(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("tunnel_bulk_push");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(15));

    for &size in SIZES {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            // Fresh handshake + forward wiring per iteration, but excluded
            // from the measured duration: `iter_custom` lets us do that
            // async setup, start a manual clock only around the transfer
            // itself, and hand criterion just that Duration.
            b.to_async(&rt).iter_custom(move |iters| async move {
                let payload = vec![0x5au8; size];
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let (sink_addr, sink_task) = spawn_sink().await;
                    let mut tunnel = open_tunnel(sink_addr).await;

                    let start = Instant::now();
                    tunnel.app.write_all(&payload).await.unwrap();
                    tunnel.app.shutdown().await.unwrap();
                    let mut ack = [0u8; 1];
                    tunnel.app.read_exact(&mut ack).await.unwrap();
                    total += start.elapsed();

                    // Untimed: reclaim this iteration's tasks, listeners, and
                    // duplex buffers before the next one starts.
                    drop(tunnel);
                    sink_task.abort();
                }
                total
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_bulk_push);
criterion_main!(benches);
