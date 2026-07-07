//! Server-side pseudo-terminal plumbing: an async wrapper around the pty
//! master and the bits needed to hand the slave to a child process as its
//! controlling terminal.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use nix::pty::{openpty, Winsize};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

fn winsize(cols: u32, rows: u32, xpix: u32, ypix: u32) -> Winsize {
    let clamp = |v: u32| v.min(u16::MAX as u32) as u16;
    Winsize {
        ws_col: clamp(cols),
        ws_row: clamp(rows),
        ws_xpixel: clamp(xpix),
        ws_ypixel: clamp(ypix),
    }
}

/// One allocated pseudo-terminal, pre-fork.
pub struct Pty {
    pub master: AsyncPty,
    /// Raw master fd for resize ioctls after `master` moves into split
    /// halves. Valid as long as the master `File` lives.
    master_fd: RawFd,
    slave: Option<OwnedFd>,
    pub term: String,
}

impl Pty {
    pub fn allocate(term: &str, cols: u32, rows: u32, xpix: u32, ypix: u32) -> io::Result<Pty> {
        let ws = winsize(cols, rows, xpix, ypix);
        let ends = openpty(Some(&ws), None).map_err(io::Error::from)?;
        let master_fd = ends.master.as_raw_fd();
        Ok(Pty {
            master: AsyncPty::new(ends.master)?,
            master_fd,
            slave: Some(ends.slave),
            term: term.to_string(),
        })
    }

    /// Slave end, surrendered once for the child's stdio.
    pub fn take_slave(&mut self) -> Option<OwnedFd> {
        self.slave.take()
    }

    pub fn resize(&self, cols: u32, rows: u32, xpix: u32, ypix: u32) {
        resize_fd(self.master_fd, cols, rows, xpix, ypix);
    }

    /// Surrender the async master and its raw fd (for later resize
    /// ioctls). Any unclaimed slave fd is dropped here — after this the
    /// child holds the only slave handles, so master reads will EOF when
    /// the child exits.
    pub fn into_parts(self) -> (AsyncPty, RawFd) {
        (self.master, self.master_fd)
    }
}

/// TIOCSWINSZ on a raw master fd, once the `Pty` has been dismantled.
pub fn resize_fd(fd: RawFd, cols: u32, rows: u32, xpix: u32, ypix: u32) {
    let ws = winsize(cols, rows, xpix, ypix);
    unsafe {
        libc::ioctl(fd, libc::TIOCSWINSZ, &ws);
    }
}

/// Async I/O over the pty master. EIO on read — the pty's way of saying
/// the slave side is gone — is reported as EOF.
pub struct AsyncPty {
    inner: AsyncFd<File>,
}

impl AsyncPty {
    fn new(fd: OwnedFd) -> io::Result<Self> {
        // Nonblocking is what makes AsyncFd honest.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(AsyncPty {
            inner: AsyncFd::new(File::from(fd))?,
        })
    }
}

impl AsyncRead for AsyncPty {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            let mut guard = match this.inner.poll_read_ready(cx) {
                Poll::Ready(r) => r?,
                Poll::Pending => return Poll::Pending,
            };
            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|fd| (&mut fd.get_ref()).read(unfilled)) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) if e.raw_os_error() == Some(libc::EIO) => {
                    return Poll::Ready(Ok(())); // slave closed: EOF
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for AsyncPty {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            let mut guard = match this.inner.poll_write_ready(cx) {
                Poll::Ready(r) => r?,
                Poll::Pending => return Poll::Pending,
            };
            match guard.try_io(|fd| (&mut fd.get_ref()).write(data)) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(())) // pty writes are unbuffered
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn pty_echoes_and_eofs() {
        let mut pty = Pty::allocate("dumb", 80, 24, 0, 0).unwrap();
        let slave = pty.take_slave().unwrap();
        // A child that reads its line back out (cat) via the pty.
        let mut child = tokio::process::Command::new("cat")
            .stdin(std::process::Stdio::from(slave.try_clone().unwrap()))
            .stdout(std::process::Stdio::from(slave))
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();

        pty.master.write_all(b"ping\n").await.unwrap();
        let mut buf = [0u8; 64];
        let mut got = Vec::new();
        // pty line discipline echoes input and cat writes it again
        while got.iter().filter(|&&b| b == b'\n' || b == b'\r').count() < 2 {
            let n = pty.master.read(&mut buf).await.unwrap();
            assert!(n > 0, "unexpected EOF");
            got.extend_from_slice(&buf[..n]);
        }
        assert!(got.windows(4).any(|w| w == b"ping"));

        child.kill().await.ok();
        let _ = child.wait().await;
        // With the slave gone, reads drain then return EOF (EIO mapped).
        loop {
            match pty.master.read(&mut buf).await {
                Ok(0) => break,
                Ok(_) => continue,
                Err(e) => panic!("expected EOF, got {e}"),
            }
        }
    }
}
