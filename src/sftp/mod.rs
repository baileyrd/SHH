//! SFTP — the SSH File Transfer Protocol, version 3
//! (draft-ietf-secsh-filexfer-02, the version OpenSSH speaks by default).
//!
//! SFTP rides a single SSH session channel: the client sends a `subsystem`
//! request naming `sftp`, and from then on the channel carries a stream of
//! length-prefixed SFTP packets rather than shell bytes. Each packet is
//! `uint32 length ‖ byte type ‖ payload`; every request but the initial
//! handshake carries a `uint32 request-id` so replies can be matched.
//!
//! This module is transport-agnostic: [`server::run`] and [`client::Client`]
//! operate over any async reader/writer pair. The daemon wires the server to
//! a subprocess's stdio (so it runs as the logged-in user, like OpenSSH's
//! `sftp-server`); the `shh-sftp` client wires its half to an SSH channel.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::wire::{Reader, Writer};

pub mod client;
// The server operates on the real filesystem with positioned I/O and unix
// permission/ownership metadata; the client half is portable.
#[cfg(unix)]
pub mod server;

/// The protocol version we implement and advertise.
pub const VERSION: u32 = 3;

/// A generous ceiling on a single SFTP packet, matching OpenSSH's default.
/// Anything larger is treated as a framing error rather than allocated.
pub const MAX_PACKET: u32 = 256 * 1024;

/// SFTP packet types (`byte type`).
pub mod fxp {
    pub const INIT: u8 = 1;
    pub const VERSION: u8 = 2;
    pub const OPEN: u8 = 3;
    pub const CLOSE: u8 = 4;
    pub const READ: u8 = 5;
    pub const WRITE: u8 = 6;
    pub const LSTAT: u8 = 7;
    pub const FSTAT: u8 = 8;
    pub const SETSTAT: u8 = 9;
    pub const FSETSTAT: u8 = 10;
    pub const OPENDIR: u8 = 11;
    pub const READDIR: u8 = 12;
    pub const REMOVE: u8 = 13;
    pub const MKDIR: u8 = 14;
    pub const RMDIR: u8 = 15;
    pub const REALPATH: u8 = 16;
    pub const STAT: u8 = 17;
    pub const RENAME: u8 = 18;
    pub const READLINK: u8 = 19;
    pub const SYMLINK: u8 = 20;

    pub const STATUS: u8 = 101;
    pub const HANDLE: u8 = 102;
    pub const DATA: u8 = 103;
    pub const NAME: u8 = 104;
    pub const ATTRS: u8 = 105;
}

/// SSH_FX_* status codes carried by an `SSH_FXP_STATUS` reply.
pub mod status {
    pub const OK: u32 = 0;
    pub const EOF: u32 = 1;
    pub const NO_SUCH_FILE: u32 = 2;
    pub const PERMISSION_DENIED: u32 = 3;
    pub const FAILURE: u32 = 4;
    pub const BAD_MESSAGE: u32 = 5;
    pub const OP_UNSUPPORTED: u32 = 8;
}

/// SSH_FXF_* flags for `SSH_FXP_OPEN`.
pub mod open {
    pub const READ: u32 = 0x0000_0001;
    pub const WRITE: u32 = 0x0000_0002;
    pub const APPEND: u32 = 0x0000_0004;
    pub const CREAT: u32 = 0x0000_0008;
    pub const TRUNC: u32 = 0x0000_0010;
    pub const EXCL: u32 = 0x0000_0020;
}

/// SSH_FILEXFER_ATTR_* presence flags in an attributes block.
pub mod attr {
    pub const SIZE: u32 = 0x0000_0001;
    pub const UIDGID: u32 = 0x0000_0002;
    pub const PERMISSIONS: u32 = 0x0000_0004;
    pub const ACMODTIME: u32 = 0x0000_0008;
    pub const EXTENDED: u32 = 0x8000_0000;
}

/// A file's attributes, as much of them as the peer chose to send. Every
/// field is optional: the wire `flags` say which are present.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attrs {
    pub size: Option<u64>,
    pub uid_gid: Option<(u32, u32)>,
    pub permissions: Option<u32>,
    /// (atime, mtime) in seconds since the Unix epoch.
    pub times: Option<(u32, u32)>,
}

impl Attrs {
    /// Build attributes from a filesystem metadata entry.
    #[cfg(unix)]
    pub fn from_metadata(m: &std::fs::Metadata) -> Attrs {
        use std::os::unix::fs::MetadataExt;
        Attrs {
            size: Some(m.size()),
            uid_gid: Some((m.uid(), m.gid())),
            permissions: Some(m.mode()),
            times: Some((m.atime() as u32, m.mtime() as u32)),
        }
    }

    /// Decode an attributes block from the current reader position.
    pub fn read(r: &mut Reader) -> Result<Attrs, crate::wire::WireError> {
        let flags = r.u32()?;
        let mut a = Attrs::default();
        if flags & attr::SIZE != 0 {
            a.size = Some(r.u64()?);
        }
        if flags & attr::UIDGID != 0 {
            a.uid_gid = Some((r.u32()?, r.u32()?));
        }
        if flags & attr::PERMISSIONS != 0 {
            a.permissions = Some(r.u32()?);
        }
        if flags & attr::ACMODTIME != 0 {
            a.times = Some((r.u32()?, r.u32()?));
        }
        if flags & attr::EXTENDED != 0 {
            // Skip any extended attributes: name/value string pairs.
            let count = r.u32()?;
            for _ in 0..count {
                r.string()?;
                r.string()?;
            }
        }
        Ok(a)
    }

    /// Encode this attributes block (flags plus present fields).
    pub fn write(&self, w: &mut Writer) {
        let mut flags = 0;
        if self.size.is_some() {
            flags |= attr::SIZE;
        }
        if self.uid_gid.is_some() {
            flags |= attr::UIDGID;
        }
        if self.permissions.is_some() {
            flags |= attr::PERMISSIONS;
        }
        if self.times.is_some() {
            flags |= attr::ACMODTIME;
        }
        w.u32(flags);
        if let Some(size) = self.size {
            w.u64(size);
        }
        if let Some((uid, gid)) = self.uid_gid {
            w.u32(uid);
            w.u32(gid);
        }
        if let Some(perms) = self.permissions {
            w.u32(perms);
        }
        if let Some((atime, mtime)) = self.times {
            w.u32(atime);
            w.u32(mtime);
        }
    }
}

/// Read one SFTP packet: `uint32 length ‖ byte type ‖ payload`. Returns the
/// type byte and the payload bytes (everything after the type). A length over
/// [`MAX_PACKET`] is refused rather than allocated.
pub async fn read_packet<R>(r: &mut R) -> std::io::Result<(u8, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    let len = r.read_u32().await?;
    if len == 0 || len > MAX_PACKET {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bad SFTP packet length {len}"),
        ));
    }
    let typ = r.read_u8().await?;
    let mut payload = vec![0u8; (len - 1) as usize];
    r.read_exact(&mut payload).await?;
    Ok((typ, payload))
}

/// Write one SFTP packet from a type byte and an already-built payload.
pub async fn write_packet<W>(w: &mut W, typ: u8, payload: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut header = Vec::with_capacity(5 + payload.len());
    header.extend_from_slice(&(payload.len() as u32 + 1).to_be_bytes());
    header.push(typ);
    w.write_all(&header).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attrs_round_trip() {
        let a = Attrs {
            size: Some(4096),
            uid_gid: Some((1000, 1000)),
            permissions: Some(0o100_644),
            times: Some((111, 222)),
        };
        let mut w = Writer::new();
        a.write(&mut w);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        let b = Attrs::read(&mut r).unwrap();
        r.finish().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn partial_attrs_round_trip() {
        // Only size set: flags must not claim the others.
        let a = Attrs {
            size: Some(9),
            ..Default::default()
        };
        let mut w = Writer::new();
        a.write(&mut w);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(Attrs::read(&mut r).unwrap(), a);
    }

    #[tokio::test]
    async fn packet_frames_round_trip() {
        let mut buf = Vec::new();
        write_packet(&mut buf, fxp::INIT, &[0, 0, 0, 3]).await.unwrap();
        let mut cur = std::io::Cursor::new(buf);
        let (typ, payload) = read_packet(&mut cur).await.unwrap();
        assert_eq!(typ, fxp::INIT);
        assert_eq!(payload, vec![0, 0, 0, 3]);
    }

    /// Drive our client against our server over an in-memory duplex — no SSH,
    /// no subprocess — exercising the whole operation set on a temp directory.
    #[cfg(unix)] // the server half is unix-only
    #[tokio::test]
    async fn client_and_server_round_trip_operations() {
        use crate::sftp::client::Client;

        let (client_end, server_end) = tokio::io::duplex(1 << 16);
        let (sr, sw) = tokio::io::split(server_end);
        let srv = tokio::spawn(async move { super::server::run(sr, sw).await });

        let (cr, cw) = tokio::io::split(client_end);
        let mut c = Client::connect(cr, cw).await.unwrap();

        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().to_string_lossy().into_owned();
        let p = |name: &str| format!("{base}/{name}");

        // upload → on-disk bytes match; permissions honored.
        let content = b"hello sftp, the modern way\n";
        c.upload(&mut &content[..], &p("up.txt"), 0o600).await.unwrap();
        assert_eq!(std::fs::read(p("up.txt")).unwrap(), content);

        // stat sees the right size.
        let a = c.stat(&p("up.txt")).await.unwrap();
        assert_eq!(a.size, Some(content.len() as u64));

        // download returns the same bytes.
        let mut got = Vec::new();
        c.download(&p("up.txt"), &mut got).await.unwrap();
        assert_eq!(got, content);

        // mkdir + list shows both entries.
        c.mkdir(&p("sub")).await.unwrap();
        let names: Vec<String> = c.list(&base).await.unwrap().into_iter().map(|e| e.name).collect();
        assert!(names.contains(&"up.txt".to_string()));
        assert!(names.contains(&"sub".to_string()));

        // rename then remove.
        c.rename(&p("up.txt"), &p("renamed.txt")).await.unwrap();
        assert!(std::fs::metadata(p("up.txt")).is_err());
        assert!(std::fs::metadata(p("renamed.txt")).is_ok());
        c.remove(&p("renamed.txt")).await.unwrap();
        assert!(std::fs::metadata(p("renamed.txt")).is_err());
        c.rmdir(&p("sub")).await.unwrap();

        // realpath of an existing dir is absolute.
        assert!(c.realpath(&base).await.unwrap().starts_with('/'));

        // A missing file is a clean error, not a hang.
        assert!(c.stat(&p("nope")).await.is_err());

        // Dropping the client closes the channel; the server ends cleanly.
        drop(c);
        srv.await.unwrap().unwrap();
    }
}
