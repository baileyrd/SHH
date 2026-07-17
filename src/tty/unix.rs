//! Unix terminal backend: `/dev/tty` + termios. Everything talks to
//! `/dev/tty` or stdin directly so piped stdio stays clean.

use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::AsFd;

use nix::sys::termios::{self, LocalFlags, SetArg, Termios};

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

/// Puts stdin into raw mode; restores the original settings on drop.
pub struct RawMode {
    orig: Termios,
}

impl RawMode {
    pub fn enable() -> io::Result<Option<RawMode>> {
        let stdin = io::stdin();
        if !stdin.is_terminal() {
            return Ok(None);
        }
        let orig = termios::tcgetattr(stdin.as_fd()).map_err(io::Error::from)?;
        let mut raw = orig.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(stdin.as_fd(), SetArg::TCSANOW, &raw).map_err(io::Error::from)?;
        Ok(Some(RawMode { orig }))
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = termios::tcsetattr(io::stdin().as_fd(), SetArg::TCSANOW, &self.orig);
    }
}

pub fn winsize() -> Option<(u32, u32, u32, u32)> {
    if !io::stdin().is_terminal() {
        return None;
    }
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) };
    if rc != 0 || ws.ws_col == 0 {
        return None;
    }
    Some((
        ws.ws_col as u32,
        ws.ws_row as u32,
        ws.ws_xpixel as u32,
        ws.ws_ypixel as u32,
    ))
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
