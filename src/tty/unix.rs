//! Unix terminal backend: `/dev/tty` + termios. Everything talks to
//! `/dev/tty` or stdin directly so piped stdio stays clean.
//!
//! `winsize()` and `RawMode` both operate on stdin, matching rustils'
//! `platform::term::Terminal` contract exactly, so they converge onto it
//! (`platform_linux::LinuxTerminal`; issue #43). `read_passphrase()`'s
//! echo toggle stays on raw termios: it deliberately targets `/dev/tty`
//! rather than stdin so the prompt still works when stdin is piped, and
//! `Terminal::set_echo` only operates on the three standard streams (no
//! arbitrary-fd/`/dev/tty` variant) — converging it would silently break
//! passphrase prompts under redirected stdin.

use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::AsFd;

use nix::sys::termios::{self, LocalFlags, SetArg};
use platform::term::Terminal as _;
use platform_linux::LinuxTerminal;

/// Read one line from `r` up to (and consuming) a `\n` or EOF, returning it
/// with any trailing `\r` stripped. Accumulates raw bytes and decodes once
/// at the end rather than casting each byte to `char` as it arrives: a
/// multi-byte UTF-8 character (an accented letter, a non-Latin script) typed
/// into a passphrase would otherwise be silently corrupted byte-by-byte,
/// making a non-ASCII passphrase impossible to enter correctly.
fn read_line_utf8(r: &mut impl Read) -> io::Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match r.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => line.push(byte[0]),
            Err(e) => return Err(e),
        }
    }
    String::from_utf8(line)
        .map(|s| s.trim_end_matches('\r').to_string())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "input is not valid UTF-8"))
}

pub fn read_passphrase(prompt: &str) -> io::Result<String> {
    let mut tty = File::options().read(true).write(true).open("/dev/tty")?;
    let orig = termios::tcgetattr(tty.as_fd()).map_err(io::Error::from)?;
    let mut quiet = orig.clone();
    quiet.local_flags.remove(LocalFlags::ECHO);
    quiet.local_flags.insert(LocalFlags::ECHONL); // still echo the newline
    termios::tcsetattr(tty.as_fd(), SetArg::TCSANOW, &quiet).map_err(io::Error::from)?;

    write!(tty, "{prompt}")?;
    tty.flush()?;
    let result = read_line_utf8(&mut tty);
    termios::tcsetattr(tty.as_fd(), SetArg::TCSANOW, &orig).map_err(io::Error::from)?;
    result
}

pub fn prompt_line(prompt: &str) -> io::Result<String> {
    let mut tty = File::options().read(true).write(true).open("/dev/tty")?;
    write!(tty, "{prompt}")?;
    tty.flush()?;
    read_line_utf8(&mut tty)
}

/// Puts stdin into raw mode via [`platform_linux::LinuxTerminal`];
/// restores the original settings on drop.
pub struct RawMode(LinuxTerminal);

impl RawMode {
    pub fn enable() -> io::Result<Option<RawMode>> {
        if !io::stdin().is_terminal() {
            return Ok(None);
        }
        let mut term = LinuxTerminal::new();
        term.enter_raw().map_err(io::Error::other)?;
        Ok(Some(RawMode(term)))
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = self.0.leave_raw();
    }
}

/// (cols, rows, xpixels, ypixels) of the local terminal, if input is one.
/// Pixel dimensions are always 0: `Terminal::window_size()` reports only
/// character-cell rows/cols (most terminals report 0 for `TIOCGWINSZ`'s
/// pixel fields too, and the SSH pty-req/window-change pixel fields are
/// advisory).
pub fn winsize() -> Option<(u32, u32, u32, u32)> {
    if !io::stdin().is_terminal() {
        return None;
    }
    let ws = LinuxTerminal::new().window_size().ok()?;
    if ws.cols == 0 {
        return None;
    }
    Some((ws.cols as u32, ws.rows as u32, 0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_line_utf8_handles_ascii_and_line_endings() {
        assert_eq!(read_line_utf8(&mut Cursor::new(b"hunter2\n")).unwrap(), "hunter2");
        assert_eq!(read_line_utf8(&mut Cursor::new(b"hunter2\r\n")).unwrap(), "hunter2");
        // EOF with no trailing newline still returns what was read.
        assert_eq!(read_line_utf8(&mut Cursor::new(b"no-newline")).unwrap(), "no-newline");
        assert_eq!(read_line_utf8(&mut Cursor::new(b"\n")).unwrap(), "");
    }

    /// The bug this guards against: casting each raw byte to `char`
    /// corrupts any multi-byte UTF-8 character instead of decoding it.
    #[test]
    fn read_line_utf8_preserves_multibyte_characters() {
        let line = "pässwörd\u{1F511}\n"; // accented Latin + a 4-byte emoji
        assert_eq!(read_line_utf8(&mut Cursor::new(line.as_bytes())).unwrap(), "pässwörd\u{1F511}");

        let cjk = "パスワード\n";
        assert_eq!(read_line_utf8(&mut Cursor::new(cjk.as_bytes())).unwrap(), "パスワード");
    }

    #[test]
    fn read_line_utf8_rejects_invalid_utf8() {
        // A lone continuation byte is never valid UTF-8 on its own.
        assert!(read_line_utf8(&mut Cursor::new(&[0x80u8, b'\n'])).is_err());
    }
}
