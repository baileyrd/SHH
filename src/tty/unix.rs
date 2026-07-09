//! Unix terminal backend: `/dev/tty` + termios. Everything talks to
//! `/dev/tty` or stdin directly so piped stdio stays clean.

use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::AsFd;

use nix::sys::termios::{self, LocalFlags, SetArg, Termios};

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

pub fn prompt_line(prompt: &str) -> io::Result<String> {
    let mut tty = File::options().read(true).write(true).open("/dev/tty")?;
    write!(tty, "{prompt}")?;
    tty.flush()?;
    let mut line = String::new();
    let mut byte = [0u8; 1];
    loop {
        match tty.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => line.push(byte[0] as char),
            Err(e) => return Err(e),
        }
    }
    Ok(line.trim_end_matches('\r').to_string())
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
