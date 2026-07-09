//! The transport layer: identification exchange, algorithm negotiation,
//! key exchange, and the encrypted packet stream (RFC 4253, modernized).
//!
//! Deviations from the RFC, all deliberate:
//! * Strict KEX (OpenSSH `kex-strict-*`) is required, not negotiated-to-off.
//!   During key exchange only key-exchange messages are accepted, and both
//!   sequence numbers reset to zero at every NEWKEYS. Terrapin-class
//!   prefix-injection dies here.
//! * Rekeying is automatic after 1 GiB or 1 hour and cannot be disabled.
//! * There is no compression state machine at all.

pub mod kexinit;

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::crypto::cert::{Certificate, CERT_ALGO, CERT_TYPE_HOST};
use crate::crypto::cipher::{self, PacketCipher, PlainCipher};
use crate::crypto::ed25519::{PrivateKey, PublicKey, ALGO};
use crate::crypto::kdf::{self, Usage};
use crate::crypto::kex::{self, ClientKex};
use crate::wire::{disconnect, msg, Reader, Writer};
use crate::{Error, Result};

pub use kexinit::Side;

/// The host-key algorithms we advertise: the certificate type (preferred)
/// plus the plain key when certificates are in play, otherwise just the key.
fn host_key_algos(with_cert: bool) -> Vec<String> {
    if with_cert {
        vec![CERT_ALGO.to_string(), ALGO.to_string()]
    } else {
        vec![ALGO.to_string()]
    }
}

const REKEY_BYTES: u64 = 1 << 30; // 1 GiB
const REKEY_INTERVAL: Duration = Duration::from_secs(3600);
/// Rekey long before a sequence counter can wrap (RFC 4253 §9 requires a
/// rekey within 2^32 packets; we stay far under it).
const REKEY_PACKETS: u32 = 1 << 28;

/// Callback deciding whether a server host key is trusted (the TOFU path,
/// used when the server presents a bare key rather than a certificate).
pub type HostKeyVerifier = Box<dyn FnMut(&PublicKey) -> Result<()> + Send>;

pub struct ClientConfig {
    pub verify_host_key: HostKeyVerifier,
    /// Trusted host-certificate CAs. When non-empty, the client offers the
    /// certificate host-key algorithm and verifies a presented host cert
    /// against these CAs, the hostname, and its validity window.
    pub host_cas: Vec<PublicKey>,
    /// The hostname being connected to, checked against a host cert's
    /// principals.
    pub hostname: String,
}

impl ClientConfig {
    /// A plain TOFU client with no host-certificate trust.
    pub fn with_verifier(verify_host_key: HostKeyVerifier) -> Self {
        ClientConfig {
            verify_host_key,
            host_cas: Vec::new(),
            hostname: String::new(),
        }
    }
}

pub struct ServerConfig {
    pub host_key: PrivateKey,
    /// An optional host certificate (`ssh-ed25519-cert-v01`) certifying
    /// `host_key`. When present, it is offered as the host key so clients
    /// that trust the CA skip TOFU.
    pub host_cert: Option<Vec<u8>>,
}

impl ServerConfig {
    pub fn with_host_key(host_key: PrivateKey) -> Self {
        ServerConfig {
            host_key,
            host_cert: None,
        }
    }
}

/// Progress of an in-flight packet read. Lives in the transport so that a
/// cancelled `recv_raw` future (e.g. the losing arm of a `select!`) resumes
/// exactly where it stopped instead of desynchronizing the stream.
enum ReadState {
    Idle,
    Header { first4: [u8; 4], got: usize },
    Body { first4: [u8; 4], buf: Vec<u8>, got: usize },
}

/// One SSH transport over `S`, after a completed handshake. All packet
/// I/O flows through `send`/`recv`, which handle keepalive chatter,
/// EXT_INFO, disconnects, and transparent rekeying.
pub struct Transport<S> {
    io: S,
    side: Side,
    v_local: String,
    v_peer: String,
    read_state: ReadState,

    tx: Box<dyn PacketCipher>,
    rx: Box<dyn PacketCipher>,
    tx_seq: u32,
    rx_seq: u32,
    traffic: u64,
    kexed_at: Instant,
    rekey_bytes: u64,
    rekey_interval: Duration,

    session_id: Vec<u8>,
    /// App packets that legitimately arrived while we were waiting for the
    /// peer's KEXINIT during a rekey we initiated.
    pub(crate) queued: VecDeque<Vec<u8>>,

    // Host-key material.
    host_key: Option<PrivateKey>,      // when we are the server
    host_cert: Option<Vec<u8>>,        // optional server host certificate
    verifier: Option<HostKeyVerifier>, // TOFU decision, when we are the client
    host_cas: Vec<PublicKey>,          // trusted host-cert CAs (client)
    hostname: String,                  // for host-cert principal check (client)
    /// Host-key algorithms we advertise in KEXINIT (cert + plain, or plain).
    host_key_algos: Vec<String>,
    peer_host_key: Option<PublicKey>,
    /// Client role: the host-key blob as presented (a plain key or a
    /// certificate) and the host's signature over the first exchange hash
    /// (== the session id). Kept for `session-bind@openssh.com`.
    peer_host_blob: Vec<u8>,
    peer_host_sig: Vec<u8>,

    peer_ext_info: bool,
    server_sig_algs: Option<Vec<String>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Transport<S> {
    pub async fn client(io: S, config: ClientConfig) -> Result<Self> {
        let mut t = Self::new(io, Side::Client, None, Some(config.verify_host_key));
        t.host_cas = config.host_cas;
        t.hostname = config.hostname;
        t.host_key_algos = host_key_algos(!t.host_cas.is_empty());
        t.exchange_idents().await?;
        t.initial_kex().await?;
        Ok(t)
    }

    pub async fn server(io: S, config: ServerConfig) -> Result<Self> {
        let mut t = Self::new(io, Side::Server, Some(config.host_key), None);
        t.host_cert = config.host_cert;
        t.host_key_algos = host_key_algos(t.host_cert.is_some());
        t.exchange_idents().await?;
        t.initial_kex().await?;
        Ok(t)
    }

    fn new(
        io: S,
        side: Side,
        host_key: Option<PrivateKey>,
        verifier: Option<HostKeyVerifier>,
    ) -> Self {
        Transport {
            io,
            side,
            v_local: crate::IDENT.to_string(),
            v_peer: String::new(),
            read_state: ReadState::Idle,
            tx: Box::new(PlainCipher),
            rx: Box::new(PlainCipher),
            tx_seq: 0,
            rx_seq: 0,
            traffic: 0,
            kexed_at: Instant::now(),
            rekey_bytes: REKEY_BYTES,
            rekey_interval: REKEY_INTERVAL,
            session_id: Vec::new(),
            queued: VecDeque::new(),
            host_key,
            host_cert: None,
            verifier,
            host_cas: Vec::new(),
            hostname: String::new(),
            host_key_algos: vec![crate::crypto::ed25519::ALGO.to_string()],
            peer_host_key: None,
            peer_host_blob: Vec::new(),
            peer_host_sig: Vec::new(),
            peer_ext_info: false,
            server_sig_algs: None,
        }
    }

    /// Verify a presented host certificate against our trusted CAs, the
    /// hostname, and its validity window, returning the certified key.
    fn verify_host_cert(&self, blob: &[u8]) -> Result<PublicKey> {
        let cert = Certificate::parse_and_verify(blob)
            .map_err(|e| Error::HostKey(format!("host certificate: {e}")))?;
        if cert.cert_type != CERT_TYPE_HOST {
            return Err(Error::HostKey("presented a non-host certificate".into()));
        }
        if !self.host_cas.contains(&cert.ca_key) {
            return Err(Error::HostKey(format!(
                "host certificate signed by an untrusted CA ({})",
                cert.ca_key.fingerprint()
            )));
        }
        if !cert.valid_at(crate::crypto::cert::now_secs()) {
            return Err(Error::HostKey("host certificate is expired or not yet valid".into()));
        }
        // A host cert lists hostnames as principals; empty means "any host",
        // which we refuse for host certs (too broad to be a real identity).
        if cert.principals.is_empty() {
            return Err(Error::HostKey("host certificate lists no hostnames".into()));
        }
        if !cert.permits_principal(&self.hostname) {
            return Err(Error::HostKey(format!(
                "host certificate is not valid for {:?}",
                self.hostname
            )));
        }
        Ok(cert.key)
    }

    /// The session identifier: the exchange hash of the first key exchange.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// The server's host key, once the client handshake completed.
    pub fn peer_host_key(&self) -> Option<&PublicKey> {
        self.peer_host_key.as_ref()
    }

    /// The material a client needs to bind its agent to this hop with
    /// `session-bind@openssh.com`: the host-key blob as presented (plain key
    /// or certificate) and the host's signature over the session id. Empty
    /// on the server side or before the first key exchange.
    pub fn host_binding(&self) -> (&[u8], &[u8]) {
        (&self.peer_host_blob, &self.peer_host_sig)
    }

    /// `server-sig-algs` from the peer's EXT_INFO, if it sent one.
    pub fn server_sig_algs(&self) -> Option<&[String]> {
        self.server_sig_algs.as_deref()
    }

    /// Lower the rekey thresholds (testing and paranoia knob — thresholds
    /// can only shrink; the defaults are already the ceiling).
    pub fn tighten_rekey_limits(&mut self, bytes: u64, interval: Duration) {
        self.rekey_bytes = self.rekey_bytes.min(bytes);
        self.rekey_interval = self.rekey_interval.min(interval);
    }

    // ------------------------------------------------------ identification

    async fn exchange_idents(&mut self) -> Result<()> {
        self.io
            .write_all(format!("{}\r\n", self.v_local).as_bytes())
            .await?;
        self.io.flush().await?;

        // Read the peer's line without over-reading: bytes after the ident
        // already belong to the binary packet protocol.
        let mut lines = 0usize;
        let mut total = 0usize;
        loop {
            let line = self.read_line().await?;
            total += line.len();
            lines += 1;
            if line.starts_with("SSH-") {
                if !line.starts_with("SSH-2.0-") {
                    return Err(Error::proto(format!(
                        "peer speaks {:?}, not SSH 2.0",
                        line.chars().take(16).collect::<String>()
                    )));
                }
                self.v_peer = line;
                return Ok(());
            }
            // RFC 4253 §4.2 lets a *server* preface its ident with banner
            // lines. A client has no such license.
            if self.side == Side::Server || lines > 32 || total > 8192 {
                return Err(Error::proto("junk before identification string"));
            }
        }
    }

    async fn read_line(&mut self) -> Result<String> {
        let mut line = Vec::with_capacity(64);
        loop {
            let mut b = [0u8; 1];
            self.io.read_exact(&mut b).await?;
            match b[0] {
                b'\n' => break,
                b'\r' => {}
                c => {
                    if line.len() >= 1024 {
                        return Err(Error::proto("identification line too long"));
                    }
                    line.push(c);
                }
            }
        }
        String::from_utf8(line).map_err(|_| Error::proto("identification line is not UTF-8"))
    }

    // ------------------------------------------------------- raw packets

    async fn send_raw(&mut self, payload: &[u8]) -> Result<()> {
        let wire = self.tx.seal(self.tx_seq, payload);
        self.tx_seq = self.tx_seq.wrapping_add(1);
        self.traffic += wire.len() as u64;
        self.io.write_all(&wire).await?;
        self.io.flush().await?;
        Ok(())
    }

    /// Read one packet. Cancel-safe: dropping this future between polls
    /// keeps partial progress in `self.read_state`, so the next call
    /// resumes mid-packet. This is what makes it legal to race `recv_raw`
    /// against other work in `select!`.
    pub(crate) async fn recv_raw(&mut self) -> Result<Vec<u8>> {
        loop {
            // Split borrows: the state machine and the socket are separate
            // fields, but the compiler needs to see that explicitly.
            let Transport {
                io, read_state, rx, ..
            } = self;
            match read_state {
                ReadState::Idle => {
                    *read_state = ReadState::Header {
                        first4: [0u8; 4],
                        got: 0,
                    };
                }
                ReadState::Header { first4, got } => {
                    if *got < 4 {
                        let n = io.read(&mut first4[*got..]).await?;
                        if n == 0 {
                            return Err(Error::proto("connection closed mid-packet"));
                        }
                        *got += n;
                        continue;
                    }
                    let len = rx.packet_length(self.rx_seq, *first4)?;
                    *read_state = ReadState::Body {
                        first4: *first4,
                        buf: vec![0u8; rx.body_len(len)],
                        got: 0,
                    };
                }
                ReadState::Body { first4, buf, got } => {
                    if *got < buf.len() {
                        let n = io.read(&mut buf[*got..]).await?;
                        if n == 0 {
                            return Err(Error::proto("connection closed mid-packet"));
                        }
                        *got += n;
                        continue;
                    }
                    let first4 = *first4;
                    let mut buf = std::mem::take(buf);
                    self.read_state = ReadState::Idle;
                    let payload = self.rx.open(self.rx_seq, first4, &mut buf)?;
                    self.rx_seq = self.rx_seq.wrapping_add(1);
                    self.traffic += (4 + buf.len()) as u64;
                    if payload.is_empty() {
                        return Err(Error::proto("empty packet payload"));
                    }
                    return Ok(payload);
                }
            }
        }
    }

    // -------------------------------------------------------- public API

    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        if self.should_rekey() {
            self.rekey_initiate().await?;
        }
        self.send_raw(payload).await
    }

    /// Next application-layer packet. Transport chatter never escapes.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        loop {
            if let Some(p) = self.queued.pop_front() {
                return Ok(p);
            }
            if self.should_rekey() {
                self.rekey_initiate().await?;
                continue;
            }
            let p = self.recv_raw().await?;
            match p[0] {
                msg::IGNORE => {}
                msg::DEBUG => {
                    if let Ok(text) = parse_debug(&p) {
                        tracing::debug!(peer_debug = %text);
                    }
                }
                msg::UNIMPLEMENTED => {
                    tracing::warn!("peer reports an unimplemented message");
                }
                msg::DISCONNECT => return Err(parse_disconnect(&p)),
                msg::EXT_INFO => self.note_ext_info(&p)?,
                msg::KEXINIT => {
                    self.rekey_respond(p).await?;
                }
                msg::NEWKEYS | msg::KEX_ECDH_INIT | msg::KEX_ECDH_REPLY => {
                    return Err(Error::proto("key exchange message outside key exchange"));
                }
                _ => return Ok(p),
            }
        }
    }

    pub async fn disconnect(&mut self, reason: u32, description: &str) -> Result<()> {
        let mut w = Writer::new();
        w.byte(msg::DISCONNECT);
        w.u32(reason);
        w.utf8(description);
        w.utf8(""); // language tag
        let payload = w.into_bytes();
        self.send_raw(&payload).await?;
        self.io.shutdown().await.ok();
        Ok(())
    }

    /// Best-effort DISCONNECT chosen from the error we're dying with.
    pub async fn bail(&mut self, err: &Error) {
        let reason = match err {
            Error::Negotiation { .. } => disconnect::KEY_EXCHANGE_FAILED,
            Error::HostKey(_) => disconnect::HOST_KEY_NOT_VERIFIABLE,
            Error::Auth(_) => disconnect::NO_MORE_AUTH_METHODS_AVAILABLE,
            _ => disconnect::PROTOCOL_ERROR,
        };
        let _ = self.disconnect(reason, &err.to_string()).await;
    }

    // ------------------------------------------------------ key exchange

    pub(crate) fn should_rekey(&self) -> bool {
        self.traffic >= self.rekey_bytes
            || self.kexed_at.elapsed() >= self.rekey_interval
            || self.tx_seq >= REKEY_PACKETS
            || self.rx_seq >= REKEY_PACKETS
    }

    async fn initial_kex(&mut self) -> Result<()> {
        let ours = kexinit::KexInit::local(self.side, &self.host_key_algos);
        let ours_bytes = ours.encode();
        self.send_raw(&ours_bytes).await?;
        // Strict KEX: the first packet on the wire must be KEXINIT.
        let theirs_bytes = self.recv_raw().await?;
        if theirs_bytes[0] != msg::KEXINIT {
            return Err(Error::proto("first packet was not KEXINIT"));
        }
        self.run_kex(&ours, ours_bytes, theirs_bytes).await
    }

    /// We want new keys: send KEXINIT, queue in-flight app traffic until
    /// the peer's KEXINIT arrives, then run the exchange.
    pub(crate) async fn rekey_initiate(&mut self) -> Result<()> {
        tracing::debug!("initiating rekey");
        let ours = kexinit::KexInit::local(self.side, &self.host_key_algos);
        let ours_bytes = ours.encode();
        self.send_raw(&ours_bytes).await?;
        let theirs_bytes = loop {
            let p = self.recv_raw().await?;
            match p[0] {
                msg::KEXINIT => break p,
                msg::IGNORE | msg::DEBUG | msg::UNIMPLEMENTED => {}
                msg::DISCONNECT => return Err(parse_disconnect(&p)),
                msg::NEWKEYS | msg::KEX_ECDH_INIT | msg::KEX_ECDH_REPLY => {
                    return Err(Error::proto("kex message before peer KEXINIT"));
                }
                // In-flight application data the peer sent before it saw
                // our KEXINIT. Deliver it after the rekey.
                _ => self.queued.push_back(p),
            }
        };
        self.run_kex(&ours, ours_bytes, theirs_bytes).await
    }

    /// The peer wants new keys (its KEXINIT payload is `theirs_bytes`).
    pub(crate) async fn rekey_respond(&mut self, theirs_bytes: Vec<u8>) -> Result<()> {
        tracing::debug!("peer initiated rekey");
        let ours = kexinit::KexInit::local(self.side, &self.host_key_algos);
        let ours_bytes = ours.encode();
        self.send_raw(&ours_bytes).await?;
        self.run_kex(&ours, ours_bytes, theirs_bytes).await
    }

    async fn run_kex(
        &mut self,
        ours: &kexinit::KexInit,
        ours_bytes: Vec<u8>,
        theirs_bytes: Vec<u8>,
    ) -> Result<()> {
        let theirs = kexinit::KexInit::parse(&theirs_bytes)?;
        let neg = kexinit::negotiate(self.side, ours, &theirs)?;
        tracing::debug!(
            kex = ?neg.kex,
            c2s = ?neg.cipher_c2s,
            s2c = ?neg.cipher_s2c,
            "negotiated"
        );
        if neg.discard_guess {
            let _ = self.recv_raw().await?;
        }
        let first_kex = self.session_id.is_empty();

        let (i_c, i_s) = match self.side {
            Side::Client => (&ours_bytes, &theirs_bytes),
            Side::Server => (&theirs_bytes, &ours_bytes),
        };
        let (v_c, v_s) = match self.side {
            Side::Client => (self.v_local.clone(), self.v_peer.clone()),
            Side::Server => (self.v_peer.clone(), self.v_local.clone()),
        };

        let (k, h): (Zeroizing<Vec<u8>>, [u8; 32]) = match self.side {
            Side::Client => {
                let eph = ClientKex::generate(neg.kex);
                let q_c = eph.public.clone();
                let mut w = Writer::new();
                w.byte(msg::KEX_ECDH_INIT);
                w.string(&q_c);
                let payload = w.into_bytes();
                self.send_raw(&payload).await?;

                let reply = self.recv_raw().await?;
                let mut r = Reader::new(&reply);
                if r.byte()? != msg::KEX_ECDH_REPLY {
                    return Err(Error::proto("expected KEX_ECDH_REPLY"));
                }
                let k_s = r.string()?.to_vec();
                let q_s = r.string()?.to_vec();
                let sig = r.string()?.to_vec();
                r.finish()?;

                // Trust decision first, then the proof of possession. A host
                // certificate is checked against our trusted CAs, the
                // hostname, and its validity; a bare key goes through TOFU.
                let host_key = if neg.host_key_algo == CERT_ALGO {
                    self.verify_host_cert(&k_s)?
                } else {
                    let hk = PublicKey::from_blob(&k_s)?;
                    (self
                        .verifier
                        .as_mut()
                        .expect("client always has a verifier"))(&hk)?;
                    hk
                };

                let k = eph.finish(&q_s)?;
                let h = exchange_hash(&v_c, &v_s, i_c, i_s, &k_s, &q_c, &q_s, &k);
                host_key
                    .verify(&h, &sig)
                    .map_err(|_| Error::HostKey("host key signature invalid".into()))?;
                self.peer_host_key = Some(host_key);
                if first_kex {
                    // Retain the proof for `session-bind@openssh.com`: the
                    // presented blob and the signature over the session id.
                    self.peer_host_blob = k_s.clone();
                    self.peer_host_sig = sig.clone();
                }
                (k, h)
            }
            Side::Server => {
                let init = self.recv_raw().await?;
                let mut r = Reader::new(&init);
                if r.byte()? != msg::KEX_ECDH_INIT {
                    return Err(Error::proto("expected KEX_ECDH_INIT"));
                }
                let q_c = r.string()?.to_vec();
                r.finish()?;

                let (q_s, k) = kex::server_exchange(neg.kex, &q_c)?;
                let host_key = self.host_key.as_ref().expect("server always has a host key");
                // Present the certificate as the host key when it was
                // negotiated; we still sign with the (certified) private key.
                let k_s = if neg.host_key_algo == CERT_ALGO {
                    self.host_cert
                        .clone()
                        .expect("cert host-key algo implies we have a host cert")
                } else {
                    host_key.public().to_blob()
                };
                let h = exchange_hash(&v_c, &v_s, i_c, i_s, &k_s, &q_c, &q_s, &k);
                let sig = host_key.sign(&h);

                let mut w = Writer::new();
                w.byte(msg::KEX_ECDH_REPLY);
                w.string(&k_s);
                w.string(&q_s);
                w.string(&sig);
                let payload = w.into_bytes();
                self.send_raw(&payload).await?;
                (k, h)
            }
        };

        if first_kex {
            self.session_id = h.to_vec();
        }
        self.peer_ext_info = neg.peer_ext_info;

        // NEWKEYS, then swap ciphers per direction. Strict KEX: sequence
        // numbers reset to zero with each direction's NEWKEYS.
        self.send_raw(&[msg::NEWKEYS]).await?;
        let (c2s, s2c) = (neg.cipher_c2s, neg.cipher_s2c);
        let (tx_algo, tx_key, tx_iv) = match self.side {
            Side::Client => (c2s, Usage::KeyClientToServer, Usage::IvClientToServer),
            Side::Server => (s2c, Usage::KeyServerToClient, Usage::IvServerToClient),
        };
        self.tx = make_cipher(tx_algo, &k, &h, &self.session_id, tx_key, tx_iv);
        self.tx_seq = 0;

        let nk = self.recv_raw().await?;
        if nk.as_slice() != [msg::NEWKEYS] {
            return Err(Error::proto("expected NEWKEYS"));
        }
        let (rx_algo, rx_key, rx_iv) = match self.side {
            Side::Client => (s2c, Usage::KeyServerToClient, Usage::IvServerToClient),
            Side::Server => (c2s, Usage::KeyClientToServer, Usage::IvClientToServer),
        };
        self.rx = make_cipher(rx_algo, &k, &h, &self.session_id, rx_key, rx_iv);
        self.rx_seq = 0;

        self.traffic = 0;
        self.kexed_at = Instant::now();

        // RFC 8308: EXT_INFO goes out right after the first NEWKEYS.
        if first_kex && self.side == Side::Server && self.peer_ext_info {
            let mut w = Writer::new();
            w.byte(msg::EXT_INFO);
            w.u32(1);
            w.utf8("server-sig-algs");
            w.utf8("ssh-ed25519,ssh-ed25519-cert-v01@openssh.com");
            let payload = w.into_bytes();
            self.send_raw(&payload).await?;
        }
        Ok(())
    }

    pub(crate) fn note_ext_info(&mut self, payload: &[u8]) -> Result<()> {
        let mut r = Reader::new(payload);
        r.byte()?;
        let count = r.u32()?;
        // Each extension is two strings; stop at the packet's actual end
        // rather than trusting the count.
        for _ in 0..count {
            if r.remaining() == 0 {
                break;
            }
            let name = r.utf8()?.to_owned();
            let value = r.string()?.to_vec();
            if name == "server-sig-algs" {
                let value = String::from_utf8(value)
                    .map_err(|_| Error::proto("server-sig-algs is not UTF-8"))?;
                self.server_sig_algs = Some(value.split(',').map(str::to_owned).collect());
            }
        }
        Ok(())
    }
}

fn make_cipher(
    algo: cipher::Algorithm,
    k: &[u8],
    h: &[u8],
    session_id: &[u8],
    key_usage: Usage,
    iv_usage: Usage,
) -> Box<dyn PacketCipher> {
    let key = kdf::derive(k, h, session_id, key_usage, algo.key_len());
    let iv = kdf::derive(k, h, session_id, iv_usage, algo.iv_len());
    algo.make(&key, &iv)
}

/// RFC 4253 §8: H = hash(V_C ‖ V_S ‖ I_C ‖ I_S ‖ K_S ‖ Q_C ‖ Q_S ‖ K),
/// every field a string except K, which arrives already encoded.
#[allow(clippy::too_many_arguments)]
fn exchange_hash(
    v_c: &str,
    v_s: &str,
    i_c: &[u8],
    i_s: &[u8],
    k_s: &[u8],
    q_c: &[u8],
    q_s: &[u8],
    k_encoded: &[u8],
) -> [u8; 32] {
    let mut w = Writer::new();
    w.utf8(v_c);
    w.utf8(v_s);
    w.string(i_c);
    w.string(i_s);
    w.string(k_s);
    w.string(q_c);
    w.string(q_s);
    w.raw(k_encoded);
    Sha256::digest(w.into_bytes()).into()
}

fn parse_disconnect(payload: &[u8]) -> Error {
    let mut r = Reader::new(payload);
    let _ = r.byte();
    let reason = r.u32().unwrap_or(0);
    let desc = r.utf8().unwrap_or("<garbled>").to_owned();
    Error::Disconnect(format!("reason {reason}: {desc}"))
}

fn parse_debug(payload: &[u8]) -> Result<String> {
    let mut r = Reader::new(payload);
    r.byte()?;
    let _always_display = r.boolean()?;
    Ok(r.utf8()?.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn trusting_client() -> ClientConfig {
        ClientConfig::with_verifier(Box::new(|_| Ok(())))
    }

    async fn pair() -> (
        Transport<tokio::io::DuplexStream>,
        Transport<tokio::io::DuplexStream>,
    ) {
        let (a, b) = duplex(1 << 20);
        let host_key = PrivateKey::generate();
        let (c, s) = tokio::join!(
            Transport::client(a, trusting_client()),
            Transport::server(b, ServerConfig::with_host_key(host_key)),
        );
        (c.unwrap(), s.unwrap())
    }

    #[tokio::test]
    async fn handshake_and_echo() {
        let (mut c, mut s) = pair().await;
        assert_eq!(c.session_id(), s.session_id());
        assert!(c.peer_host_key().is_some());
        c.send(&[99, 1, 2, 3]).await.unwrap();
        assert_eq!(s.recv().await.unwrap(), vec![99, 1, 2, 3]);
        s.send(&[100, 9]).await.unwrap();
        assert_eq!(c.recv().await.unwrap(), vec![100, 9]);
        // Client advertised ext-info-c, so the server sent server-sig-algs
        // (plain Ed25519 plus the certificate algorithm).
        let algs = c.server_sig_algs().unwrap();
        assert!(algs.contains(&"ssh-ed25519".to_string()));
        assert!(algs.contains(&"ssh-ed25519-cert-v01@openssh.com".to_string()));
    }

    /// A server that presents a host cert (signed by `ca`) for `principals`,
    /// against a client that trusts `client_cas` and connects to `hostname`.
    async fn cert_handshake(
        ca: &PrivateKey,
        principals: &[&str],
        hostname: &str,
        client_cas: Vec<PublicKey>,
    ) -> (
        Result<Transport<tokio::io::DuplexStream>>,
        Result<Transport<tokio::io::DuplexStream>>,
    ) {
        let (a, b) = duplex(1 << 20);
        let host_key = PrivateKey::generate();
        let principals: Vec<String> = principals.iter().map(|s| s.to_string()).collect();
        let host_cert = crate::crypto::cert::sign_host_cert(
            ca,
            &host_key.public(),
            1,
            "host",
            &principals,
            0,
            u64::MAX,
        );
        let client = ClientConfig {
            verify_host_key: Box::new(|_| panic!("TOFU must not run when a cert is presented")),
            host_cas: client_cas,
            hostname: hostname.to_string(),
        };
        let server = ServerConfig {
            host_key,
            host_cert: Some(host_cert),
        };
        tokio::join!(Transport::client(a, client), Transport::server(b, server))
    }

    #[tokio::test]
    async fn host_certificate_accepted_and_tofu_skipped() {
        let ca = PrivateKey::generate();
        let (c, s) = cert_handshake(&ca, &["myhost"], "myhost", vec![ca.public()]).await;
        c.unwrap();
        s.unwrap();
    }

    #[tokio::test]
    async fn host_certificate_wrong_hostname_rejected() {
        let ca = PrivateKey::generate();
        // Trust the right CA, but connect under a hostname the cert omits.
        let (c, _s) = cert_handshake(&ca, &["realhost"], "wronghost", vec![ca.public()]).await;
        assert!(matches!(c, Err(Error::HostKey(_))));
    }

    #[tokio::test]
    async fn host_certificate_untrusted_ca_rejected() {
        let ca = PrivateKey::generate();
        let stranger = PrivateKey::generate();
        // Cert is signed by `ca`, but the client only trusts `stranger`.
        let (c, _s) = cert_handshake(&ca, &["myhost"], "myhost", vec![stranger.public()]).await;
        assert!(matches!(c, Err(Error::HostKey(_))));
    }

    #[tokio::test]
    async fn client_rejects_untrusted_host_key() {
        let (a, b) = duplex(1 << 20);
        let host_key = PrivateKey::generate();
        let client = Transport::client(
            a,
            ClientConfig::with_verifier(Box::new(|_| Err(Error::HostKey("not on the list".into())))),
        );
        let server = Transport::server(b, ServerConfig::with_host_key(host_key));
        let (c, _s) = tokio::join!(client, server);
        assert!(matches!(c, Err(Error::HostKey(_))));
    }

    /// Echo everything back until the peer disconnects. Runs in its own
    /// task: a rekey needs both ends of the pipe making progress.
    fn echo_server<S>(mut s: Transport<S>) -> tokio::task::JoinHandle<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        tokio::spawn(async move {
            while let Ok(p) = s.recv().await {
                s.send(&p).await.unwrap();
            }
        })
    }

    #[tokio::test]
    async fn rekey_transparent_to_app_traffic() {
        let (mut c, s) = pair().await;
        // Force the client to rekey roughly every kilobyte.
        c.tighten_rekey_limits(1024, Duration::from_secs(3600));
        let server = echo_server(s);
        for i in 0..64u32 {
            let payload = vec![200u8, (i % 256) as u8, 7, 7, 7];
            c.send(&payload).await.unwrap();
            assert_eq!(c.recv().await.unwrap(), payload);
        }
        // The traffic counter resets at each rekey, so it can never have
        // accumulated the whole run.
        assert!(c.traffic < 20_000);
        drop(c);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn server_initiated_rekey_also_works() {
        let (c, mut s) = pair().await;
        s.tighten_rekey_limits(512, Duration::from_secs(3600));
        let client = echo_server(c);
        for _ in 0..32 {
            s.send(&[210u8; 200]).await.unwrap();
            assert_eq!(s.recv().await.unwrap(), vec![210u8; 200]);
        }
        drop(s);
        client.await.unwrap();
    }

    #[tokio::test]
    async fn disconnect_surfaces_as_error() {
        let (mut c, mut s) = pair().await;
        c.disconnect(disconnect::BY_APPLICATION, "goodbye")
            .await
            .unwrap();
        match s.recv().await {
            Err(Error::Disconnect(m)) => assert!(m.contains("goodbye")),
            other => panic!("expected disconnect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn garbage_peer_rejected() {
        let (a, mut b) = duplex(1 << 16);
        let client = Transport::client(a, trusting_client());
        let feeder = async move {
            b.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                .await
                .unwrap();
            // dropping `b` closes the stream; the client hits EOF
        };
        let (c, ()) = tokio::join!(client, feeder);
        assert!(c.is_err());
    }

    // ---------------------------------------------------------------------
    // Transport chaos: byte-fragmentation / cancel-safety of the reader.
    //
    // TCP gives no message boundaries; a real network can split any packet
    // across arbitrarily many segments and hand them over a few bytes at a
    // time. The incremental reader (`recv_raw` + `ReadState`) is built to
    // survive that and to be cancel-safe under `select!`. These tests model
    // the pathological case directly rather than hoping the OS produces it.
    // ---------------------------------------------------------------------

    /// An `AsyncRead`/`AsyncWrite` shim that moves at most `chunk` bytes per
    /// poll in each direction — a stand-in for a network that fragments the
    /// stream into tiny segments. Every SSH packet must be reassembled across
    /// many partial reads without the reader losing sync.
    struct Dribble<S> {
        inner: S,
        chunk: usize,
    }

    impl<S> Dribble<S> {
        fn new(inner: S, chunk: usize) -> Self {
            Dribble {
                inner,
                chunk: chunk.max(1),
            }
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for Dribble<S> {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let me = self.get_mut();
            let cap = buf.remaining().min(me.chunk);
            if cap == 0 {
                return std::task::Poll::Ready(Ok(()));
            }
            let mut tmp = vec![0u8; cap];
            let mut rb = tokio::io::ReadBuf::new(&mut tmp);
            match std::pin::Pin::new(&mut me.inner).poll_read(cx, &mut rb) {
                std::task::Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    buf.put_slice(&tmp[..n]);
                    std::task::Poll::Ready(Ok(()))
                }
                other => other,
            }
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for Dribble<S> {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            data: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let me = self.get_mut();
            let n = data.len().min(me.chunk);
            std::pin::Pin::new(&mut me.inner).poll_write(cx, &data[..n])
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    /// A full handshake through `Dribble` on both ends, `chunk` bytes/poll.
    async fn dribble_pair(
        chunk: usize,
    ) -> (
        Transport<Dribble<tokio::io::DuplexStream>>,
        Transport<Dribble<tokio::io::DuplexStream>>,
    ) {
        let (a, b) = duplex(1 << 20);
        let host_key = PrivateKey::generate();
        let (c, s) = tokio::join!(
            Transport::client(Dribble::new(a, chunk), trusting_client()),
            Transport::server(Dribble::new(b, chunk), ServerConfig::with_host_key(host_key)),
        );
        (c.unwrap(), s.unwrap())
    }

    #[tokio::test]
    async fn handshake_survives_one_byte_at_a_time() {
        // One byte per poll in both directions: the whole handshake — idents,
        // KEXINIT, the large hybrid-KEX reply (host key + KEM + signature),
        // NEWKEYS — must reassemble from single-byte reads.
        let (mut c, mut s) = dribble_pair(1).await;
        assert_eq!(c.session_id(), s.session_id());
        assert!(c.peer_host_key().is_some());
        c.send(&[42, 1, 2, 3]).await.unwrap();
        assert_eq!(s.recv().await.unwrap(), vec![42, 1, 2, 3]);
    }

    #[tokio::test]
    async fn echo_and_rekey_survive_fragmentation() {
        // Fragment every segment, force frequent rekeys, and push a large
        // payload that spans hundreds of single-byte reads on its own.
        let (mut c, s) = dribble_pair(1).await;
        c.tighten_rekey_limits(1024, Duration::from_secs(3600));
        let server = echo_server(s);
        for i in 0..48u32 {
            let payload = vec![0xA5u8, (i & 0xff) as u8, 1, 2, 3, 4, 5];
            c.send(&payload).await.unwrap();
            assert_eq!(c.recv().await.unwrap(), payload);
        }
        // A packet far larger than any single segment.
        let big: Vec<u8> = (0..5000u32).map(|i| (i & 0xff) as u8).collect();
        c.send(&big).await.unwrap();
        assert_eq!(c.recv().await.unwrap(), big);
        // Rekeys fired along the way (the counter resets at each).
        assert!(c.traffic < 40_000);
        drop(c);
        server.await.unwrap();
    }

    /// Like `Dribble`, but the read direction obeys a shared byte budget: it
    /// hands out at most `budget` bytes total, then returns `Pending`. Lets a
    /// test freeze a `recv_raw` exactly mid-packet. Writes pass through.
    struct Gate<S> {
        inner: S,
        budget: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for Gate<S> {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            use std::sync::atomic::Ordering::Relaxed;
            let me = self.get_mut();
            let cap = buf.remaining().min(me.budget.load(Relaxed));
            if cap == 0 {
                // Out of budget: suspend. The test raises the budget and
                // re-polls by hand (noop waker), so no wake is needed here.
                return std::task::Poll::Pending;
            }
            let mut tmp = vec![0u8; cap];
            let mut rb = tokio::io::ReadBuf::new(&mut tmp);
            match std::pin::Pin::new(&mut me.inner).poll_read(cx, &mut rb) {
                std::task::Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    me.budget.fetch_sub(n, Relaxed);
                    buf.put_slice(&tmp[..n]);
                    std::task::Poll::Ready(Ok(()))
                }
                other => other,
            }
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for Gate<S> {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            data: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn recv_raw_resumes_after_mid_packet_drop() {
        use std::future::Future;
        use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
        use std::sync::Arc;

        // Client reads through a Gate so we can meter its input to the byte.
        let (a, b) = duplex(1 << 20);
        let budget = Arc::new(AtomicUsize::new(usize::MAX)); // unrestricted for the handshake
        let host_key = PrivateKey::generate();
        let (c, s) = tokio::join!(
            Transport::client(
                Gate {
                    inner: a,
                    budget: budget.clone()
                },
                trusting_client()
            ),
            Transport::server(b, ServerConfig::with_host_key(host_key)),
        );
        let (mut c, mut s) = (c.unwrap(), s.unwrap());

        // The server emitted EXT_INFO during the handshake; `recv_raw` is the
        // raw primitive (unlike `recv`, it does not swallow transport
        // chatter), so drain that packet before metering our own.
        assert_eq!(c.recv_raw().await.unwrap()[0], msg::EXT_INFO);

        let payload = vec![0x5Au8, 1, 2, 3, 4, 5, 6, 7];
        s.send(&payload).await.unwrap(); // all sealed bytes now buffered in the pipe

        // Let the client read only 5 bytes: enough for the 4-byte length
        // header plus one body byte, then starve it. `recv_raw` must return
        // `Pending` with its partial progress parked in `self.read_state`.
        budget.store(5, Relaxed);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        {
            // Poll once (starves mid-packet), then drop the in-flight future
            // at the end of this block — exactly as a lost `select!` arm would.
            let mut fut = std::pin::pin!(c.recv_raw());
            assert!(
                fut.as_mut().poll(&mut cx).is_pending(),
                "reader should starve mid-packet at a 5-byte budget"
            );
        }

        // A brand-new `recv_raw` must resume from the parked state and return
        // the whole packet, intact and in order — nothing lost, no desync.
        budget.store(usize::MAX, Relaxed);
        let got = c.recv_raw().await.unwrap();
        assert_eq!(got, payload);

        // And the stream is still healthy for the next packet.
        s.send(&[9, 9]).await.unwrap();
        assert_eq!(c.recv_raw().await.unwrap(), vec![9, 9]);
    }
}
