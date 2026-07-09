//! Local terminal helpers for the CLI binaries: no-echo passphrase prompts,
//! raw mode for interactive sessions, window-size queries.
//!
//! The three operations are the same everywhere; only the console API under
//! them differs. This module is the portable facade; the `imp` submodule is
//! Unix (`/dev/tty` + termios) or Windows (the console API) as appropriate.

use std::io;

#[cfg_attr(unix, path = "tty/unix.rs")]
#[cfg_attr(windows, path = "tty/windows.rs")]
mod imp;

/// Prompt on the controlling terminal with echo disabled and read a line.
pub fn read_passphrase(prompt: &str) -> io::Result<String> {
    imp::read_passphrase(prompt)
}

/// Prompt on the controlling terminal (echo on) and read a line — for yes/no
/// confirmations and presence checks. Reads the terminal directly (Unix
/// `/dev/tty`) so a piped stdin doesn't swallow the answer; on Windows it
/// falls back to stdin.
pub fn prompt_line(prompt: &str) -> io::Result<String> {
    imp::prompt_line(prompt)
}

/// (cols, rows, xpixels, ypixels) of the local terminal, if input is one.
pub fn winsize() -> Option<(u32, u32, u32, u32)> {
    imp::winsize()
}

/// Put the terminal into raw mode for the life of the guard; the original
/// mode is restored on drop (and thus on any error unwind). The inner value
/// is held only for its `Drop`.
pub struct RawMode(#[allow(dead_code)] imp::RawMode);

impl RawMode {
    /// Enable raw mode; `None` when input is not a terminal (nothing to do).
    pub fn enable() -> io::Result<Option<RawMode>> {
        Ok(imp::RawMode::enable()?.map(RawMode))
    }
}
