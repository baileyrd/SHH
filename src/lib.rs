//! SHH — a modern SSH implementation.
//!
//! Speaks a strict subset of SSH2: hybrid post-quantum key exchange
//! (ML-KEM-768 + X25519) or X25519 alone, Ed25519 keys everywhere, AEAD
//! ciphers only, public-key authentication only. See DESIGN.md for the
//! rationale behind each cut.

pub mod agent;
pub mod auth;
pub mod connect;
pub mod crypto;
pub mod transport;
#[cfg(unix)]
pub mod tty;
pub mod wire;

/// Protocol version string sent during the identification exchange
/// (without the trailing CRLF).
pub const IDENT: &str = concat!("SSH-2.0-SHH_", env!("CARGO_PKG_VERSION"));

/// Errors produced anywhere in the protocol stack.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("wire format: {0}")]
    Wire(#[from] wire::WireError),
    #[error("protocol violation: {0}")]
    Protocol(String),
    #[error("no common {kind} algorithm; peer offered [{offered}]")]
    Negotiation { kind: &'static str, offered: String },
    #[error("cryptographic failure: {0}")]
    Crypto(&'static str),
    #[error("host key verification failed: {0}")]
    HostKey(String),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("peer disconnected: {0}")]
    Disconnect(String),
    #[error("channel: {0}")]
    Channel(String),
    #[error("bad key file: {0}")]
    KeyFile(String),
    #[error("agent: {0}")]
    Agent(String),
}

impl Error {
    pub(crate) fn proto(msg: impl Into<String>) -> Self {
        Error::Protocol(msg.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
