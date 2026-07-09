//! Windows terminal backend: the console API. Passphrase entry toggles
//! `ENABLE_ECHO_INPUT`; raw mode clears line/echo/processed input and enables
//! virtual-terminal processing so the server's VT sequences render.

use std::io::{self, BufRead, Write};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetConsoleScreenBufferInfo, GetStdHandle, SetConsoleMode, CONSOLE_MODE,
    CONSOLE_SCREEN_BUFFER_INFO, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
    ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_INPUT_HANDLE,
    STD_OUTPUT_HANDLE,
};

fn std_handle(which: windows_sys::Win32::System::Console::STD_HANDLE) -> HANDLE {
    unsafe { GetStdHandle(which) }
}

pub fn read_passphrase(prompt: &str) -> io::Result<String> {
    // Prompt on stderr so a piped stdout stays clean, matching the Unix path.
    eprint!("{prompt}");
    io::stderr().flush()?;

    let stdin = std_handle(STD_INPUT_HANDLE);
    let mut orig: CONSOLE_MODE = 0;
    let is_console = unsafe { GetConsoleMode(stdin, &mut orig) } != 0;
    if is_console {
        unsafe { SetConsoleMode(stdin, orig & !ENABLE_ECHO_INPUT) };
    }

    let mut line = String::new();
    let read = io::stdin().lock().read_line(&mut line);

    if is_console {
        unsafe { SetConsoleMode(stdin, orig) };
        eprintln!(); // the un-echoed Enter needs a newline printed for it
    }
    read?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

pub fn prompt_line(prompt: &str) -> io::Result<String> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Restores the saved console modes on drop.
pub struct RawMode {
    stdin: HANDLE,
    stdin_orig: CONSOLE_MODE,
    stdout: HANDLE,
    stdout_orig: CONSOLE_MODE,
}

impl RawMode {
    pub fn enable() -> io::Result<Option<RawMode>> {
        let stdin = std_handle(STD_INPUT_HANDLE);
        let stdout = std_handle(STD_OUTPUT_HANDLE);
        let mut stdin_orig: CONSOLE_MODE = 0;
        // No console (redirected/piped): nothing to do, like a non-tty on Unix.
        if unsafe { GetConsoleMode(stdin, &mut stdin_orig) } == 0 {
            return Ok(None);
        }
        let mut stdout_orig: CONSOLE_MODE = 0;
        unsafe { GetConsoleMode(stdout, &mut stdout_orig) };

        let raw_in = (stdin_orig
            & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT))
            | ENABLE_VIRTUAL_TERMINAL_INPUT;
        unsafe { SetConsoleMode(stdin, raw_in) };
        unsafe { SetConsoleMode(stdout, stdout_orig | ENABLE_VIRTUAL_TERMINAL_PROCESSING) };

        Ok(Some(RawMode {
            stdin,
            stdin_orig,
            stdout,
            stdout_orig,
        }))
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        unsafe {
            SetConsoleMode(self.stdin, self.stdin_orig);
            SetConsoleMode(self.stdout, self.stdout_orig);
        }
    }
}

pub fn winsize() -> Option<(u32, u32, u32, u32)> {
    let stdout = std_handle(STD_OUTPUT_HANDLE);
    let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
    if unsafe { GetConsoleScreenBufferInfo(stdout, &mut info) } == 0 {
        return None;
    }
    let w = &info.srWindow;
    let cols = (w.Right - w.Left + 1).max(0) as u32;
    let rows = (w.Bottom - w.Top + 1).max(0) as u32;
    if cols == 0 {
        return None;
    }
    Some((cols, rows, 0, 0))
}
