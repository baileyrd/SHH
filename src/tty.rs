//! Local terminal helpers for the CLI binaries: no-echo passphrase
//! prompts, raw mode for interactive sessions, window-size queries.
//! Everything talks to `/dev/tty` or stdin directly so piped stdio stays
//! clean.

use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::AsFd;

use nix::sys::termios::{self, LocalFlags, SetArg, Termios};

/// Prompt on the controlling terminal with echo disabled.
pub fn read_passphrase(prompt: &str) -> io::Result<String> {
    let mut tty = File::options().read(true).write(true).open("/dev/tty")?;
    let orig = termios::tcgetattr(tty.as_fd()).map_err(io::Error::from)?;
    let mut quiet = orig.clone();
    quiet.local_flags.remove(LocalFlags::ECHO);
    quiet.local_flags.insert(LocalFlags::ECHONL); // still echo the newline
    termios::tcsetattr(tty.as_fd(), SetArg::TCSANOW, &quiet).map_err(io::Error::from)?;

    write!(tty, "{prompt}")?;
    tty.flush()?;
    let mut line = String::new();
    let mut byte = [0u8; 1];
    let result = loop {
        match tty.read(&mut byte) {
            Ok(0) => break Ok(line),
            Ok(_) if byte[0] == b'\n' => break Ok(line),
            Ok(_) => line.push(byte[0] as char),
            Err(e) => break Err(e),
        }
    };
    termios::tcsetattr(tty.as_fd(), SetArg::TCSANOW, &orig).map_err(io::Error::from)?;
    result.map(|s| s.trim_end_matches('\r').to_string())
}

/// Put stdin into raw mode for the duration of an interactive session;
/// restores the original settings on drop (and thus on error unwinds).
pub struct RawMode {
    orig: Termios,
}

impl RawMode {
    /// Returns `None` when stdin is not a terminal (nothing to do).
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

/// (cols, rows, xpixels, ypixels) of the local terminal, if stdin is one.
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
