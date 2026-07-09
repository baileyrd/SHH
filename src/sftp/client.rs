//! The SFTP v3 client engine.
//!
//! [`Client`] speaks the protocol over any async reader/writer pair — the
//! `shh-sftp` binary hands it the two halves of an SSH `sftp` subsystem
//! channel. It is deliberately synchronous per request (one outstanding
//! request at a time): send a packet, await its reply. That is plenty for a
//! command-line client and keeps reply matching trivial.

use tokio::io::{AsyncRead, AsyncWrite};

use super::{fxp, open, status, Attrs};
use crate::wire::{Reader, Writer};
use crate::{Error, Result};

/// One directory entry from a listing.
pub struct DirEntry {
    pub name: String,
    pub long_name: String,
    pub attrs: Attrs,
}

pub struct Client<R, W> {
    reader: R,
    writer: W,
    next_id: u32,
}

impl<R, W> Client<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// Handshake: send INIT, expect VERSION. Refuses a server newer than us
    /// (we speak strictly version 3).
    pub async fn connect(reader: R, writer: W) -> Result<Client<R, W>> {
        let mut c = Client {
            reader,
            writer,
            next_id: 0,
        };
        let mut w = Writer::new();
        w.u32(super::VERSION);
        super::write_packet(&mut c.writer, fxp::INIT, &w.into_bytes()).await?;
        let (typ, payload) = super::read_packet(&mut c.reader).await?;
        if typ != fxp::VERSION {
            return Err(Error::Sftp("server did not answer INIT with VERSION".into()));
        }
        let mut r = Reader::new(&payload);
        let version = r.u32()?;
        if version > super::VERSION {
            return Err(Error::Sftp(format!(
                "server speaks SFTP v{version}; we implement v{}",
                super::VERSION
            )));
        }
        Ok(c)
    }

    fn next_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// Send a request and read exactly one reply packet.
    async fn round_trip(&mut self, typ: u8, body: Vec<u8>) -> Result<(u8, Vec<u8>)> {
        super::write_packet(&mut self.writer, typ, &body).await?;
        let (rtyp, payload) = super::read_packet(&mut self.reader).await?;
        Ok((rtyp, payload))
    }

    /// Interpret a STATUS reply: OK is success, anything else an error.
    fn check_status(payload: &[u8]) -> Result<()> {
        let mut r = Reader::new(payload);
        let _id = r.u32()?;
        let code = r.u32()?;
        let msg = r.utf8().unwrap_or("");
        if code == status::OK {
            Ok(())
        } else {
            Err(Error::Sftp(format!("status {code}: {msg}")))
        }
    }

    /// `SSH_FXP_REALPATH`: canonicalize a (possibly relative) path server-side.
    pub async fn realpath(&mut self, path: &str) -> Result<String> {
        let id = self.next_id();
        let mut w = Writer::new();
        w.u32(id);
        w.utf8(path);
        let (typ, payload) = self.round_trip(fxp::REALPATH, w.into_bytes()).await?;
        match typ {
            fxp::NAME => {
                let mut r = Reader::new(&payload);
                let _id = r.u32()?;
                let _count = r.u32()?;
                Ok(r.utf8()?.to_owned())
            }
            fxp::STATUS => {
                Self::check_status(&payload)?;
                Err(Error::Sftp("REALPATH returned an empty status".into()))
            }
            _ => Err(Error::Sftp("unexpected reply to REALPATH".into())),
        }
    }

    /// `SSH_FXP_STAT`: follow symlinks and return the target's attributes.
    pub async fn stat(&mut self, path: &str) -> Result<Attrs> {
        let id = self.next_id();
        let mut w = Writer::new();
        w.u32(id);
        w.utf8(path);
        let (typ, payload) = self.round_trip(fxp::STAT, w.into_bytes()).await?;
        match typ {
            fxp::ATTRS => {
                let mut r = Reader::new(&payload);
                let _id = r.u32()?;
                Ok(Attrs::read(&mut r)?)
            }
            fxp::STATUS => {
                Self::check_status(&payload)?;
                Err(Error::Sftp("STAT returned an empty status".into()))
            }
            _ => Err(Error::Sftp("unexpected reply to STAT".into())),
        }
    }

    async fn open_handle(&mut self, typ: u8, body: Vec<u8>) -> Result<Vec<u8>> {
        let (rtyp, payload) = self.round_trip(typ, body).await?;
        match rtyp {
            fxp::HANDLE => {
                let mut r = Reader::new(&payload);
                let _id = r.u32()?;
                Ok(r.string()?.to_vec())
            }
            fxp::STATUS => {
                Self::check_status(&payload)?;
                Err(Error::Sftp("open returned an empty status".into()))
            }
            _ => Err(Error::Sftp("unexpected reply to open".into())),
        }
    }

    async fn close(&mut self, handle: &[u8]) -> Result<()> {
        let id = self.next_id();
        let mut w = Writer::new();
        w.u32(id);
        w.string(handle);
        let (_typ, payload) = self.round_trip(fxp::CLOSE, w.into_bytes()).await?;
        Self::check_status(&payload)
    }

    /// List a directory (`opendir` + `readdir` until EOF + `close`).
    pub async fn list(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        let id = self.next_id();
        let mut w = Writer::new();
        w.u32(id);
        w.utf8(path);
        let handle = self.open_handle(fxp::OPENDIR, w.into_bytes()).await?;

        let mut out = Vec::new();
        loop {
            let id = self.next_id();
            let mut w = Writer::new();
            w.u32(id);
            w.string(&handle);
            let (typ, payload) = self.round_trip(fxp::READDIR, w.into_bytes()).await?;
            match typ {
                fxp::NAME => {
                    let mut r = Reader::new(&payload);
                    let _id = r.u32()?;
                    let count = r.u32()?;
                    for _ in 0..count {
                        let name = r.utf8()?.to_owned();
                        let long_name = r.utf8()?.to_owned();
                        let attrs = Attrs::read(&mut r)?;
                        out.push(DirEntry {
                            name,
                            long_name,
                            attrs,
                        });
                    }
                }
                fxp::STATUS => {
                    // EOF ends the listing; any other status is an error.
                    let mut r = Reader::new(&payload);
                    let _id = r.u32()?;
                    let code = r.u32()?;
                    if code == status::EOF {
                        break;
                    }
                    let msg = r.utf8().unwrap_or("");
                    self.close(&handle).await.ok();
                    return Err(Error::Sftp(format!("readdir status {code}: {msg}")));
                }
                _ => {
                    self.close(&handle).await.ok();
                    return Err(Error::Sftp("unexpected reply to READDIR".into()));
                }
            }
        }
        self.close(&handle).await?;
        Ok(out)
    }

    /// Download `remote` into `sink`, streaming in bounded reads.
    pub async fn download<S>(&mut self, remote: &str, sink: &mut S) -> Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;
        let id = self.next_id();
        let mut w = Writer::new();
        w.u32(id);
        w.utf8(remote);
        w.u32(open::READ);
        Attrs::default().write(&mut w);
        let handle = self.open_handle(fxp::OPEN, w.into_bytes()).await?;

        let mut offset = 0u64;
        const CHUNK: u32 = 32 * 1024;
        loop {
            let id = self.next_id();
            let mut w = Writer::new();
            w.u32(id);
            w.string(&handle);
            w.u64(offset);
            w.u32(CHUNK);
            let (typ, payload) = self.round_trip(fxp::READ, w.into_bytes()).await?;
            match typ {
                fxp::DATA => {
                    let mut r = Reader::new(&payload);
                    let _id = r.u32()?;
                    let data = r.string()?;
                    if let Err(e) = sink.write_all(data).await {
                        self.close(&handle).await.ok();
                        return Err(e.into());
                    }
                    offset += data.len() as u64;
                }
                fxp::STATUS => {
                    let mut r = Reader::new(&payload);
                    let _id = r.u32()?;
                    let code = r.u32()?;
                    if code == status::EOF {
                        break;
                    }
                    let msg = r.utf8().unwrap_or("");
                    self.close(&handle).await.ok();
                    return Err(Error::Sftp(format!("read status {code}: {msg}")));
                }
                _ => {
                    self.close(&handle).await.ok();
                    return Err(Error::Sftp("unexpected reply to READ".into()));
                }
            }
        }
        sink.flush().await?;
        self.close(&handle).await
    }

    /// Upload `source` to `remote`, creating/truncating it with `mode`.
    pub async fn upload<Src>(&mut self, source: &mut Src, remote: &str, mode: u32) -> Result<()>
    where
        Src: AsyncRead + Unpin,
    {
        use tokio::io::AsyncReadExt;
        let id = self.next_id();
        let mut w = Writer::new();
        w.u32(id);
        w.utf8(remote);
        w.u32(open::WRITE | open::CREAT | open::TRUNC);
        Attrs {
            permissions: Some(mode & 0o7777),
            ..Default::default()
        }
        .write(&mut w);
        let handle = self.open_handle(fxp::OPEN, w.into_bytes()).await?;

        let mut offset = 0u64;
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = match source.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    self.close(&handle).await.ok();
                    return Err(e.into());
                }
            };
            let id = self.next_id();
            let mut w = Writer::new();
            w.u32(id);
            w.string(&handle);
            w.u64(offset);
            w.string(&buf[..n]);
            let (_typ, payload) = self.round_trip(fxp::WRITE, w.into_bytes()).await?;
            if let Err(e) = Self::check_status(&payload) {
                self.close(&handle).await.ok();
                return Err(e);
            }
            offset += n as u64;
        }
        self.close(&handle).await
    }

    /// A one-shot request whose only reply is a STATUS (mkdir, remove, …).
    async fn status_op(&mut self, typ: u8, build: impl FnOnce(&mut Writer)) -> Result<()> {
        let id = self.next_id();
        let mut w = Writer::new();
        w.u32(id);
        build(&mut w);
        let (_typ, payload) = self.round_trip(typ, w.into_bytes()).await?;
        Self::check_status(&payload)
    }

    pub async fn mkdir(&mut self, path: &str) -> Result<()> {
        self.status_op(fxp::MKDIR, |w| {
            w.utf8(path);
            // No attributes requested: an empty (flags=0) attrs block.
            w.u32(0);
        })
        .await
    }

    pub async fn rmdir(&mut self, path: &str) -> Result<()> {
        self.status_op(fxp::RMDIR, |w| {
            w.utf8(path);
        })
        .await
    }

    pub async fn remove(&mut self, path: &str) -> Result<()> {
        self.status_op(fxp::REMOVE, |w| {
            w.utf8(path);
        })
        .await
    }

    pub async fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        self.status_op(fxp::RENAME, |w| {
            w.utf8(from);
            w.utf8(to);
        })
        .await
    }
}

/// Whether a mode names a directory (for `ls` display and recursion guards).
pub fn is_dir(attrs: &Attrs) -> bool {
    attrs.permissions.map(|m| m & 0o170000 == 0o040000).unwrap_or(false)
}
