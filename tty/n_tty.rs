//! N_TTY line discipline (Linux drivers/tty/n_tty.c), the only one
//!
//! Input (`receive_buf`, from the flip thread): ISTRIP/IGNCR/ICRNL/INLCR,
//! ISIG signal characters, canonical line editing (ICANON: erase, kill,
//! word erase, EOF) and echo. Completed lines and raw input sit in the
//! per-tty read ring, `Tty.ldata`; `read` copies them out (one line at
//! a time in canonical mode, VMIN/VTIME otherwise) and sleeps on
//! `Tty.read_wait`. Output (`write`) does OPOST/ONLCR.
//!
//! Locking: `Tty.ldata` is a spin Mutex taken briefly in thread context;
//! echo is written to the driver and signals are sent after it is
//! dropped.

use alloc::vec::Vec;

use super::Tty;
use super::termios::*;
use crate::fs::File;
use crate::fs::flags::O_NONBLOCK;
use crate::task::percpu::MAX_SCHEDULE_TIMEOUT;
use crate::util::error::KernelError;

/// Read ring size (Linux N_TTY_BUF_SIZE)
const READ_BUF_SIZE: usize = 4096;

/// Longest line being edited: Linux n_tty takes N_TTY_BUF_SIZE - 1
/// (LINE_MAX, 255, is only what pathconf reports)
const LINE_MAX: usize = READ_BUF_SIZE - 1;

/// The EOF character's place in the ring: a line end that is not copied
/// out (Linux __DISABLED_CHAR); a real line end is never NUL
const EOF_MARK: u8 = 0;

/// Per-tty N_TTY state (Linux struct n_tty_data)
pub struct NTtyData {
    /// Input ready for readers; `head`/`tail` run free, index mod size
    buf: [u8; READ_BUF_SIZE],
    /// Line-end flags, one bit per `buf` slot (Linux read_flags)
    eol: [u64; READ_BUF_SIZE / 64],
    head: usize,
    tail: usize,
    /// Line ends in the ring
    lines: usize,
    /// The line being edited in canonical mode
    line: [u8; LINE_MAX],
    line_len: usize,
    /// ICANON as last set (Linux ldata->icanon): input, reads and
    /// polls use this, so a termios change is seen by all at once
    icanon: bool,
}

impl NTtyData {
    pub const fn new() -> Self {
        Self {
            buf: [0; READ_BUF_SIZE],
            eol: [0; READ_BUF_SIZE / 64],
            head: 0,
            tail: 0,
            lines: 0,
            line: [0; LINE_MAX],
            line_len: 0,
            icanon: true,
        }
    }

    /// Drop all input (Linux n_tty_flush_buffer)
    pub fn reset(&mut self) {
        self.tail = self.head;
        self.lines = 0;
        self.line_len = 0;
    }

    fn cnt(&self) -> usize {
        self.head.wrapping_sub(self.tail)
    }

    fn is_eol(&self, pos: usize) -> bool {
        let i = pos % READ_BUF_SIZE;
        self.eol[i / 64] & (1 << (i % 64)) != 0
    }

    /// Append `c` to the ring (dropped when full)
    fn push(&mut self, c: u8, eol: bool) {
        if self.cnt() == READ_BUF_SIZE {
            return;
        }
        let i = self.head % READ_BUF_SIZE;
        self.buf[i] = c;
        let bit = 1u64 << (i % 64);
        if eol {
            self.eol[i / 64] |= bit;
            self.lines += 1;
        } else {
            self.eol[i / 64] &= !bit;
        }
        self.head = self.head.wrapping_add(1);
    }

    /// Move the edited line, ended by `end` (a newline or EOF_MARK), to
    /// the ring; a line that does not fit is dropped
    fn commit_line(&mut self, end: u8) {
        if READ_BUF_SIZE - self.cnt() > self.line_len {
            for i in 0..self.line_len {
                self.push(self.line[i], false);
            }
            self.push(end, true);
        }
        self.line_len = 0;
    }

    /// Apply ICANON (Linux n_tty_set_termios): on a change, the line
    /// being edited becomes input, line ends are forgotten, and entering
    /// canonical mode makes what is queued one readable line
    pub fn set_icanon(&mut self, now: bool) {
        if now == self.icanon {
            return;
        }
        self.icanon = now;
        let len = core::mem::take(&mut self.line_len);
        for i in 0..len {
            self.push(self.line[i], false);
        }
        self.eol = [0; READ_BUF_SIZE / 64];
        self.lines = 0;
        if now && self.cnt() > 0 {
            let i = self.head.wrapping_sub(1) % READ_BUF_SIZE;
            self.eol[i / 64] |= 1 << (i % 64);
            self.lines = 1;
        }
    }

    /// Room for another input byte (Linux n_tty_receive_buf_common):
    /// canonical mode keeps space for the edited line and its end; a
    /// line too long for the ring (no complete line queued) is still
    /// taken, its excess dropped, so input never stalls with nothing
    /// readable
    fn room(&self) -> bool {
        if !self.icanon {
            return self.cnt() < READ_BUF_SIZE;
        }
        self.cnt() + self.line_len + 1 < READ_BUF_SIZE || self.lines == 0
    }

    /// Readable input: a line in canonical mode, else `min` bytes
    fn available(&self, min: usize) -> bool {
        if self.icanon {
            self.lines > 0
        } else {
            self.cnt() >= min.max(1)
        }
    }

    /// Bytes a read can return (TIOCINQ; Linux inq_canon)
    pub fn inq(&self) -> usize {
        if !self.icanon {
            return self.cnt();
        }
        let (mut n, mut pending) = (0, 0);
        let mut p = self.tail;
        while p != self.head {
            if self.is_eol(p) {
                n += pending + usize::from(self.buf[p % READ_BUF_SIZE] != EOF_MARK);
                pending = 0;
            } else {
                pending += 1;
            }
            p = p.wrapping_add(1);
        }
        n
    }

    /// Copy input out: canonical mode one line (None if there is none),
    /// else what there is (None if nothing); with the mode it used
    fn copy(&mut self, out: &mut [u8]) -> Option<(usize, bool)> {
        let canon = self.icanon;
        if !self.available(1) {
            return None;
        }
        let mut n = 0;
        while self.tail != self.head {
            let c = self.buf[self.tail % READ_BUF_SIZE];
            let eol = self.is_eol(self.tail);
            // An EOF mark is consumed but not copied, even with `out` full
            if eol && c == EOF_MARK {
                self.tail = self.tail.wrapping_add(1);
                self.lines -= 1;
                if canon {
                    break;
                }
                continue;
            }
            if n == out.len() {
                break;
            }
            out[n] = c;
            n += 1;
            self.tail = self.tail.wrapping_add(1);
            if eol {
                self.lines -= 1;
                if canon {
                    break;
                }
            }
        }
        Some((n, canon))
    }
}

impl Default for NTtyData {
    fn default() -> Self {
        Self::new()
    }
}

/// What input processing produced, acted on once `ldata` is dropped
#[derive(Default)]
struct Effects {
    echo: Vec<u8>,
    sigs: Vec<u32>,
}

/// Input bytes from the driver, in thread context (Linux
/// n_tty_receive_buf); wakes readers. The bytes taken: the rest wait in
/// the flip buffer until a read makes room
pub fn receive_buf(tty: &Tty, bytes: &[u8]) -> usize {
    let mut fx = Effects::default();
    let mut taken = 0;
    {
        // termios under ldata: set_termios changes both under it (Linux
        // termios_rwsem), so input never sees half a change
        let mut ld = tty.ldata.lock();
        let t = tty.get_termios();
        for &c in bytes {
            if !ld.room() {
                break;
            }
            receive_char(&mut ld, &t, c, &mut fx);
            taken += 1;
        }
    }
    if !fx.echo.is_empty() {
        let _ = tty.driver_write(&fx.echo);
    }
    if let Some(pg) = tty.pgrp() {
        for &sig in &fx.sigs {
            crate::signal::kill_pgrp_pid(&pg, sig);
        }
    }
    tty.read_wait.wake_all();
    taken
}

/// Input mapping (ISTRIP, IGNCR, ICRNL, INLCR); None drops the byte
fn map_input(c: u8, t: &Termios) -> Option<u8> {
    let c = if t.c_iflag & ISTRIP != 0 { c & 0x7f } else { c };
    match c {
        b'\r' if t.c_iflag & IGNCR != 0 => None,
        b'\r' if t.c_iflag & ICRNL != 0 => Some(b'\n'),
        b'\n' if t.c_iflag & INLCR != 0 => Some(b'\r'),
        _ => Some(c),
    }
}

/// The signal a character raises under ISIG
fn signal_char(c: u8, t: &Termios) -> Option<u32> {
    use crate::signal::{SIGINT, SIGQUIT, SIGTSTP};
    [(VINTR, SIGINT), (VQUIT, SIGQUIT), (VSUSP, SIGTSTP)]
        .into_iter()
        .find(|&(i, _)| t.c_cc[i] != 0 && t.c_cc[i] == c)
        .map(|(_, s)| s)
}

fn receive_char(ld: &mut NTtyData, t: &Termios, c: u8, fx: &mut Effects) {
    let Some(c) = map_input(c, t) else {
        return;
    };
    if t.c_lflag & ISIG != 0
        && let Some(sig) = signal_char(c, t)
    {
        // Linux isig: flush unless NOFLSH, echo, signal the group
        if t.c_lflag & NOFLSH == 0 {
            ld.reset();
        }
        if t.c_lflag & ECHO != 0 {
            echo_char(c, t, &mut fx.echo);
        }
        fx.sigs.push(sig);
        return;
    }
    if t.c_lflag & ICANON != 0 {
        canon_char(ld, t, c, &mut fx.echo);
    } else {
        ld.push(c, false);
        if t.c_lflag & ECHO != 0 {
            echo_char(c, t, &mut fx.echo);
        }
    }
}

/// A control character shows as ^X under ECHOCTL (not TAB or NL)
fn shows_caret(c: u8, t: &Termios) -> bool {
    t.c_lflag & ECHOCTL != 0 && (c < 0x20 || c == 0x7f) && c != b'\t' && c != b'\n'
}

/// Echo `c`: a control character as ^X with ECHOCTL, a newline through
/// OPOST/ONLCR
fn echo_char(c: u8, t: &Termios, echo: &mut Vec<u8>) {
    if c == b'\n' && t.c_oflag & OPOST != 0 && t.c_oflag & ONLCR != 0 {
        echo.extend_from_slice(b"\r\n");
    } else if shows_caret(c, t) {
        echo.extend_from_slice(&[b'^', c ^ 0x40]);
    } else {
        echo.push(c);
    }
}

/// Erase the last character of the edited line, echoing it away (ECHOE:
/// one column, two for a ^X)
fn erase(ld: &mut NTtyData, t: &Termios, echo: &mut Vec<u8>) -> bool {
    let Some(&c) = ld.line[..ld.line_len].last() else {
        return false;
    };
    ld.line_len -= 1;
    if t.c_lflag & ECHO != 0 && t.c_lflag & ECHOE != 0 {
        let cols = if shows_caret(c, t) { 2 } else { 1 };
        for _ in 0..cols {
            echo.extend_from_slice(b"\x08 \x08");
        }
    }
    true
}

fn is_blank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// A character in canonical mode (Linux n_tty_receive_char_canon)
fn canon_char(ld: &mut NTtyData, t: &Termios, c: u8, echo: &mut Vec<u8>) {
    let is = |i: usize| t.c_cc[i] != 0 && t.c_cc[i] == c;
    if is(VERASE) {
        erase(ld, t, echo);
    } else if is(VWERASE) && t.c_lflag & IEXTEN != 0 {
        // Trailing blanks, then the word
        while ld.line_len > 0 && is_blank(ld.line[ld.line_len - 1]) {
            erase(ld, t, echo);
        }
        while ld.line_len > 0 && !is_blank(ld.line[ld.line_len - 1]) {
            erase(ld, t, echo);
        }
    } else if is(VKILL) {
        if t.c_lflag & ECHO != 0 && t.c_lflag & ECHOK != 0 && t.c_lflag & ECHOKE == 0 {
            echo_char(c, t, echo);
            echo_char(b'\n', t, echo);
            ld.line_len = 0;
        } else {
            while erase(ld, t, echo) {}
        }
    } else if is(VEOF) {
        ld.commit_line(EOF_MARK);
    } else if c == b'\n' || is(VEOL) || is(VEOL2) {
        if t.c_lflag & (ECHO | ECHONL) != 0 {
            echo_char(c, t, echo);
        }
        ld.commit_line(c);
    } else if ld.line_len < LINE_MAX {
        ld.line[ld.line_len] = c;
        ld.line_len += 1;
        if t.c_lflag & ECHO != 0 {
            echo_char(c, t, echo);
        }
    }
}

/// Read (Linux n_tty_read): canonical mode returns one line; otherwise
/// VMIN bytes, VTIME the timeout (both 0: what there is). Sleeps unless
/// O_NONBLOCK (EAGAIN); a signal ends the sleep (ERESTARTSYS, or the
/// bytes read so far)
pub fn read(tty: &Tty, file: &File, out: &mut [u8]) -> Result<usize, KernelError> {
    if out.is_empty() {
        return Ok(0);
    }
    let t = tty.get_termios();
    let canon = t.c_lflag & ICANON != 0;
    let deci = |v: u8| crate::task::percpu::ms_to_ticks(u64::from(v) * 100);
    let (mut min, mut time, mut timeout) = (0, 0, MAX_SCHEDULE_TIMEOUT);
    if !canon {
        min = usize::from(t.c_cc[VMIN]);
        if min != 0 {
            time = deci(t.c_cc[VTIME]);
        } else {
            timeout = deci(t.c_cc[VTIME]);
            min = 1;
        }
    }
    let nonblock = file.get_flags() & O_NONBLOCK != 0;
    let ready = || tty.ldata.lock().available(1);
    let mut n = 0;
    loop {
        let got = tty.ldata.lock().copy(&mut out[n..]);
        if let Some((k, canon)) = got {
            n += k;
            // Room was made: input held in the flip buffer may go on
            // (Linux n_tty_kick_worker)
            super::flip::kick(tty);
            if canon || n >= min || n == out.len() {
                break;
            }
            if time != 0 {
                timeout = time;
            }
            continue;
        }
        if timeout == 0 {
            break;
        }
        if nonblock {
            if n == 0 {
                return Err(KernelError::WouldBlock);
            }
            break;
        }
        match tty
            .read_wait
            .wait_event_interruptible_timeout(ready, timeout)
        {
            Err(e) if n == 0 => return Err(e),
            Err(_) => break,
            Ok(left) if timeout != MAX_SCHEDULE_TIMEOUT => {
                timeout = if ready() { left } else { 0 };
            }
            Ok(_) => {}
        }
    }
    Ok(n)
}

/// Input a poll reports (Linux input_available_p for poll): a line, or
/// VMIN bytes when VTIME is 0
pub fn poll_in(tty: &Tty) -> bool {
    let ld = tty.ldata.lock();
    let t = tty.get_termios();
    let min = if t.c_cc[VTIME] == 0 {
        usize::from(t.c_cc[VMIN])
    } else {
        1
    };
    ld.available(min)
}

/// Write (Linux n_tty_write): OPOST with ONLCR maps NL to CR-NL
pub fn write(tty: &Tty, buf: &[u8]) -> Result<usize, KernelError> {
    let t = tty.get_termios();
    if t.c_oflag & OPOST == 0 || t.c_oflag & ONLCR == 0 {
        return tty.driver_write(buf);
    }
    for chunk in buf.split_inclusive(|&b| b == b'\n') {
        match chunk.split_last() {
            Some((b'\n', rest)) => {
                tty.driver_write(rest)?;
                tty.driver_write(b"\r\n")?;
            }
            _ => {
                tty.driver_write(chunk)?;
            }
        }
    }
    Ok(buf.len())
}
