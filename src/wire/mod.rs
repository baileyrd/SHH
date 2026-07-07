//! SSH wire primitives (RFC 4251 §5) and message numbers.
//!
//! Parsers here must never panic on arbitrary input; every read is
//! bounds-checked and errors are returned, not thrown. This module is the
//! fuzzing surface of the crate.

mod reader;
mod writer;

pub use reader::Reader;
pub use writer::Writer;

/// Message numbers for the subset of SSH2 we speak.
pub mod msg {
    // Transport layer (RFC 4253).
    pub const DISCONNECT: u8 = 1;
    pub const IGNORE: u8 = 2;
    pub const UNIMPLEMENTED: u8 = 3;
    pub const DEBUG: u8 = 4;
    pub const SERVICE_REQUEST: u8 = 5;
    pub const SERVICE_ACCEPT: u8 = 6;
    pub const EXT_INFO: u8 = 7; // RFC 8308
    pub const KEXINIT: u8 = 20;
    pub const NEWKEYS: u8 = 21;
    // ECDH-style KEX (RFC 5656 §4 numbering; also used by the hybrid KEX).
    pub const KEX_ECDH_INIT: u8 = 30;
    pub const KEX_ECDH_REPLY: u8 = 31;
    // User authentication (RFC 4252).
    pub const USERAUTH_REQUEST: u8 = 50;
    pub const USERAUTH_FAILURE: u8 = 51;
    pub const USERAUTH_SUCCESS: u8 = 52;
    pub const USERAUTH_BANNER: u8 = 53;
    pub const USERAUTH_PK_OK: u8 = 60;
    // Connection protocol (RFC 4254).
    pub const GLOBAL_REQUEST: u8 = 80;
    pub const REQUEST_SUCCESS: u8 = 81;
    pub const REQUEST_FAILURE: u8 = 82;
    pub const CHANNEL_OPEN: u8 = 90;
    pub const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
    pub const CHANNEL_OPEN_FAILURE: u8 = 92;
    pub const CHANNEL_WINDOW_ADJUST: u8 = 93;
    pub const CHANNEL_DATA: u8 = 94;
    pub const CHANNEL_EXTENDED_DATA: u8 = 95;
    pub const CHANNEL_EOF: u8 = 96;
    pub const CHANNEL_CLOSE: u8 = 97;
    pub const CHANNEL_REQUEST: u8 = 98;
    pub const CHANNEL_SUCCESS: u8 = 99;
    pub const CHANNEL_FAILURE: u8 = 100;
}

/// Disconnect reason codes (RFC 4253 §11.1), the ones we actually use.
pub mod disconnect {
    pub const PROTOCOL_ERROR: u32 = 2;
    pub const KEY_EXCHANGE_FAILED: u32 = 3;
    pub const HOST_KEY_NOT_VERIFIABLE: u32 = 9;
    pub const BY_APPLICATION: u32 = 11;
    pub const NO_MORE_AUTH_METHODS_AVAILABLE: u32 = 14;
}

/// Errors from decoding wire data.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireError {
    #[error("truncated: needed {needed} more bytes")]
    Truncated { needed: usize },
    #[error("length {len} exceeds limit {limit}")]
    Oversized { len: usize, limit: usize },
    #[error("invalid UTF-8 in string field")]
    BadUtf8,
    #[error("invalid boolean byte")]
    BadBool,
    #[error("trailing garbage: {0} bytes left after message")]
    TrailingBytes(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_types() {
        let mut w = Writer::new();
        w.byte(42);
        w.boolean(true);
        w.boolean(false);
        w.u32(0xdead_beef);
        w.u64(0x0123_4567_89ab_cdef);
        w.string(b"hello");
        w.utf8("wörld");
        w.name_list(&["a", "bc", "def"]);
        w.mpint(&[0x00, 0x00, 0x80, 0x01]); // leading zeros stripped, sign byte added

        let buf = w.into_bytes();
        let mut r = Reader::new(&buf);
        assert_eq!(r.byte().unwrap(), 42);
        assert!(r.boolean().unwrap());
        assert!(!r.boolean().unwrap());
        assert_eq!(r.u32().unwrap(), 0xdead_beef);
        assert_eq!(r.u64().unwrap(), 0x0123_4567_89ab_cdef);
        assert_eq!(r.string().unwrap(), b"hello");
        assert_eq!(r.utf8().unwrap(), "wörld");
        assert_eq!(r.name_list().unwrap(), vec!["a", "bc", "def"]);
        // mpint 0x8001 encodes as 00 80 01 with a sign byte
        assert_eq!(r.string().unwrap(), &[0x00, 0x80, 0x01]);
        r.finish().unwrap();
    }

    #[test]
    fn mpint_zero_is_empty() {
        let mut w = Writer::new();
        w.mpint(&[0, 0, 0]);
        assert_eq!(w.into_bytes(), vec![0, 0, 0, 0]);
    }

    #[test]
    fn mpint_no_sign_byte_when_high_bit_clear() {
        let mut w = Writer::new();
        w.mpint(&[0x7f, 0xff]);
        assert_eq!(w.into_bytes(), vec![0, 0, 0, 2, 0x7f, 0xff]);
    }

    #[test]
    fn truncated_reads_error_not_panic() {
        let mut r = Reader::new(&[0, 0, 0, 10, b'x']);
        assert!(matches!(r.string(), Err(WireError::Truncated { .. })));
        let mut r = Reader::new(&[0, 0]);
        assert!(matches!(r.u32(), Err(WireError::Truncated { .. })));
        let mut r = Reader::new(&[]);
        assert!(matches!(r.byte(), Err(WireError::Truncated { .. })));
    }

    #[test]
    fn absurd_length_rejected() {
        let mut r = Reader::new(&[0xff, 0xff, 0xff, 0xff, 1, 2, 3]);
        assert!(matches!(r.string(), Err(WireError::Truncated { .. })));
    }

    #[test]
    fn finish_flags_trailing_bytes() {
        let mut r = Reader::new(&[1, 2]);
        r.byte().unwrap();
        assert_eq!(r.finish(), Err(WireError::TrailingBytes(1)));
    }

    #[test]
    fn empty_name_list() {
        let mut w = Writer::new();
        w.name_list(&[]);
        let buf = w.into_bytes();
        let mut r = Reader::new(&buf);
        assert_eq!(r.name_list().unwrap(), Vec::<String>::new());
    }
}
