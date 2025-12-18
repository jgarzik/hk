//! N_TTY Line Discipline
//!
//! This module implements the N_TTY line discipline, which provides:
//! - Canonical mode (line editing with ICANON)
//! - Echo processing (ECHO, ECHOE, ECHOK, ECHONL)
//! - Signal character processing (handled in Phase 4)
//! - Input/output character translation
//!
//! Reference: Linux drivers/tty/n_tty.c

use super::termios::*;
use super::{LineDiscipline, Tty};
use crate::chardev::DeviceError;

/// Maximum size of the read buffer
const READ_BUF_SIZE: usize = 4096;

/// Maximum size of the canonical (cooked) line buffer
const MAX_CANON: usize = 256;

/// N_TTY line discipline state
///
/// This is stored inside the LineDiscipline implementation and tracks:
/// - The read buffer (raw or cooked input)
/// - Canonical line buffer for ICANON mode
/// - Character processing state
pub struct NTtyData {
    /// Read buffer - holds processed input ready for userspace
    read_buf: [u8; READ_BUF_SIZE],
    read_head: usize,
    read_tail: usize,

    /// Canonical buffer - holds characters being edited in ICANON mode
    canon_buf: [u8; MAX_CANON],
    canon_head: usize,

    /// Number of newlines in read buffer (for canonical mode reads)
    canon_count: usize,
}

impl Default for NTtyData {
    fn default() -> Self {
        Self::new()
    }
}

impl NTtyData {
    /// Create new N_TTY data
    pub const fn new() -> Self {
        Self {
            read_buf: [0; READ_BUF_SIZE],
            read_head: 0,
            read_tail: 0,
            canon_buf: [0; MAX_CANON],
            canon_head: 0,
            canon_count: 0,
        }
    }

    /// Reset all buffers
    pub fn reset(&mut self) {
        self.read_head = 0;
        self.read_tail = 0;
        self.canon_head = 0;
        self.canon_count = 0;
    }

    /// Get number of bytes available in read buffer
    pub fn read_cnt(&self) -> usize {
        if self.read_head >= self.read_tail {
            self.read_head - self.read_tail
        } else {
            READ_BUF_SIZE - self.read_tail + self.read_head
        }
    }

    /// Push a byte to the read buffer
    fn push_read(&mut self, byte: u8) -> bool {
        let next = (self.read_head + 1) % READ_BUF_SIZE;
        if next != self.read_tail {
            self.read_buf[self.read_head] = byte;
            self.read_head = next;
            true
        } else {
            false // Buffer full
        }
    }

    /// Pop a byte from the read buffer
    fn pop_read(&mut self) -> Option<u8> {
        if self.read_head == self.read_tail {
            None
        } else {
            let byte = self.read_buf[self.read_tail];
            self.read_tail = (self.read_tail + 1) % READ_BUF_SIZE;
            Some(byte)
        }
    }

    /// Push a byte to the canonical buffer
    fn push_canon(&mut self, byte: u8) -> bool {
        if self.canon_head < MAX_CANON {
            self.canon_buf[self.canon_head] = byte;
            self.canon_head += 1;
            true
        } else {
            false // Buffer full
        }
    }

    /// Process a backspace in canonical mode
    fn erase_char(&mut self) -> Option<u8> {
        if self.canon_head > 0 {
            self.canon_head -= 1;
            Some(self.canon_buf[self.canon_head])
        } else {
            None
        }
    }

    /// Kill the entire line in canonical mode
    fn kill_line(&mut self) -> usize {
        let erased = self.canon_head;
        self.canon_head = 0;
        erased
    }

    /// Word erase - erase back to previous whitespace
    fn erase_word(&mut self) -> usize {
        let mut erased = 0;

        // First, skip any trailing whitespace
        while self.canon_head > 0 {
            let ch = self.canon_buf[self.canon_head - 1];
            if ch != b' ' && ch != b'\t' {
                break;
            }
            self.canon_head -= 1;
            erased += 1;
        }

        // Then erase the word
        while self.canon_head > 0 {
            let ch = self.canon_buf[self.canon_head - 1];
            if ch == b' ' || ch == b'\t' {
                break;
            }
            self.canon_head -= 1;
            erased += 1;
        }

        erased
    }

    /// Flush canonical buffer to read buffer
    fn flush_canon_to_read(&mut self) {
        for i in 0..self.canon_head {
            self.push_read(self.canon_buf[i]);
        }
        self.canon_head = 0;
        self.canon_count += 1;
    }
}

/// N_TTY line discipline implementation
pub struct NTtyLdisc {
    /// Per-tty state - using interior mutability for the static instance
    /// In a real implementation, this would be per-TTY state
    data: spin::Mutex<NTtyData>,
}

impl Default for NTtyLdisc {
    fn default() -> Self {
        Self::new()
    }
}

impl NTtyLdisc {
    /// Create a new N_TTY line discipline
    pub const fn new() -> Self {
        Self {
            data: spin::Mutex::new(NTtyData::new()),
        }
    }

    /// Process an input character based on c_iflag settings
    fn process_input_char(&self, ch: u8, termios: &Termios) -> Option<u8> {
        let mut c = ch;

        // Strip high bit if ISTRIP is set
        if termios.c_iflag & ISTRIP != 0 {
            c &= 0x7F;
        }

        // CR handling
        if c == b'\r' {
            if termios.c_iflag & IGNCR != 0 {
                return None; // Ignore CR
            }
            if termios.c_iflag & ICRNL != 0 {
                c = b'\n'; // CR -> NL
            }
        } else if c == b'\n' && termios.c_iflag & INLCR != 0 {
            c = b'\r'; // NL -> CR
        }

        Some(c)
    }

    /// Check if a character should generate a signal
    ///
    /// Returns Some(signal_number) if the character matches a signal character,
    /// None otherwise.
    fn check_signal_char(&self, ch: u8, termios: &Termios, _tty: &Tty) -> Option<u32> {
        use crate::signal::{SIGINT, SIGQUIT, SIGTSTP};

        let vintr = termios.c_cc[VINTR];
        let vquit = termios.c_cc[VQUIT];
        let vsusp = termios.c_cc[VSUSP];

        if vintr != 0 && ch == vintr {
            return Some(SIGINT);
        }
        if vquit != 0 && ch == vquit {
            return Some(SIGQUIT);
        }
        if vsusp != 0 && ch == vsusp {
            return Some(SIGTSTP);
        }

        None
    }

    /// Echo a character to the terminal
    fn echo_char(&self, tty: &Tty, ch: u8, termios: &Termios) {
        if termios.c_lflag & ECHOCTL != 0 && ch < 0x20 && ch != b'\t' && ch != b'\n' && ch != b'\r'
        {
            // Echo control characters as ^X
            let _ = tty.driver_write(b"^");
            let _ = tty.driver_write(&[ch + b'@']);
        } else {
            let _ = tty.driver_write(&[ch]);
        }
    }

    /// Echo an erase sequence (backspace-space-backspace)
    fn echo_erase(&self, tty: &Tty, termios: &Termios, erased_ch: u8) {
        if termios.c_lflag & ECHOE != 0 {
            if termios.c_lflag & ECHOCTL != 0 && erased_ch < 0x20 {
                // Control character was echoed as ^X, need to erase both
                let _ = tty.driver_write(b"\x08 \x08\x08 \x08");
            } else {
                let _ = tty.driver_write(b"\x08 \x08");
            }
        }
    }

    /// Echo line kill (clear the line)
    fn echo_kill(&self, tty: &Tty, termios: &Termios, count: usize) {
        if termios.c_lflag & ECHOK != 0 {
            // Echo newline
            let _ = tty.driver_write(b"\r\n");
        } else if termios.c_lflag & ECHOE != 0 {
            // Erase each character
            for _ in 0..count {
                let _ = tty.driver_write(b"\x08 \x08");
            }
        }
    }

    /// Process character in canonical mode
    fn canon_char(&self, tty: &Tty, ch: u8, termios: &Termios, data: &mut NTtyData) {
        let verase = termios.c_cc[VERASE];
        let vkill = termios.c_cc[VKILL];
        let vwerase = termios.c_cc[VWERASE];
        let veof = termios.c_cc[VEOF];

        // Check for special characters
        if verase != 0 && ch == verase {
            // Erase character
            if let Some(erased) = data.erase_char()
                && termios.c_lflag & ECHO != 0
            {
                self.echo_erase(tty, termios, erased);
            }
            return;
        }

        if vkill != 0 && ch == vkill {
            // Kill line
            let count = data.kill_line();
            if termios.c_lflag & ECHO != 0 {
                self.echo_kill(tty, termios, count);
            }
            return;
        }

        if vwerase != 0 && ch == vwerase {
            // Word erase
            let count = data.erase_word();
            if termios.c_lflag & ECHO != 0 && termios.c_lflag & ECHOE != 0 {
                for _ in 0..count {
                    let _ = tty.driver_write(b"\x08 \x08");
                }
            }
            return;
        }

        // Check for EOF
        if veof != 0 && ch == veof {
            // Flush buffer without adding the EOF character
            data.flush_canon_to_read();
            return;
        }

        // Check for newline - ends the line
        if ch == b'\n' {
            if termios.c_lflag & ECHO != 0 || termios.c_lflag & ECHONL != 0 {
                // Echo the newline with CR-NL translation
                if termios.c_oflag & OPOST != 0 && termios.c_oflag & ONLCR != 0 {
                    let _ = tty.driver_write(b"\r\n");
                } else {
                    let _ = tty.driver_write(b"\n");
                }
            }
            data.push_canon(ch);
            data.flush_canon_to_read();
            return;
        }

        // Regular character - add to canon buffer
        if data.push_canon(ch) && termios.c_lflag & ECHO != 0 {
            self.echo_char(tty, ch, termios);
        }
        // If buffer full, silently drop character
    }

    /// Process character in raw mode
    fn raw_char(&self, tty: &Tty, ch: u8, termios: &Termios, data: &mut NTtyData) {
        // Push directly to read buffer
        data.push_read(ch);

        // Echo if enabled
        if termios.c_lflag & ECHO != 0 {
            self.echo_char(tty, ch, termios);
        }
    }
}

impl LineDiscipline for NTtyLdisc {
    fn receive_char(&self, tty: &Tty, ch: u8) {
        let termios = tty.get_termios();
        let mut data = self.data.lock();

        // Input processing
        let processed = match self.process_input_char(ch, &termios) {
            Some(c) => c,
            None => return, // Character was ignored (e.g., IGNCR)
        };

        // Signal generation (ISIG)
        if termios.c_lflag & ISIG != 0
            && let Some(sig) = self.check_signal_char(processed, &termios, tty)
        {
            // Echo the character if ECHO is set
            if termios.c_lflag & ECHO != 0 {
                self.echo_char(tty, processed, &termios);
            }
            // Send signal to foreground process group
            if let Some(pgrp) = tty.get_foreground_pgrp() {
                crate::signal::send_signal_to_pgrp(pgrp as u64, sig);
            }
            // Don't queue the character when it generates a signal
            return;
        }

        // Canonical vs raw mode
        if termios.c_lflag & ICANON != 0 {
            self.canon_char(tty, processed, &termios, &mut data);
        } else {
            self.raw_char(tty, processed, &termios, &mut data);
        }
    }

    fn write(&self, tty: &Tty, buf: &[u8]) -> Result<usize, DeviceError> {
        let termios = tty.get_termios();
        let opost = termios.c_oflag & OPOST != 0;
        let onlcr = termios.c_oflag & ONLCR != 0;

        if opost && onlcr {
            // CR-NL translation
            for &byte in buf {
                if byte == b'\n' {
                    tty.driver_write(b"\r")?;
                }
                tty.driver_write(&[byte])?;
            }
            Ok(buf.len())
        } else {
            // Direct output
            tty.driver_write(buf)
        }
    }
}

/// Static N_TTY line discipline instance
pub static N_TTY_LDISC: NTtyLdisc = NTtyLdisc::new();

/// Get bytes available for reading from the N_TTY buffer
///
/// This is called by the TTY read implementation when using N_TTY.
pub fn n_tty_chars_available() -> usize {
    N_TTY_LDISC.data.lock().read_cnt()
}

/// Read from N_TTY buffer
///
/// For canonical mode, only returns data when a complete line is available.
/// For raw mode, returns any available data.
pub fn n_tty_read(tty: &Tty, buf: &mut [u8]) -> Result<usize, DeviceError> {
    let termios = tty.get_termios();
    let is_canon = termios.c_lflag & ICANON != 0;
    let mut data = N_TTY_LDISC.data.lock();

    // In canonical mode, only return data if we have a complete line
    if is_canon && data.canon_count == 0 {
        return Err(DeviceError::WouldBlock);
    }

    let mut count = 0;
    while count < buf.len() {
        if let Some(byte) = data.pop_read() {
            buf[count] = byte;
            count += 1;

            // In canonical mode, stop at newline and decrement line count
            if is_canon && byte == b'\n' {
                data.canon_count = data.canon_count.saturating_sub(1);
                break;
            }
        } else {
            break;
        }
    }

    if count == 0 {
        return Err(DeviceError::WouldBlock);
    }

    Ok(count)
}
