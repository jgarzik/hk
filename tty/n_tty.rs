//! N_TTY line discipline (Linux drivers/tty/n_tty.c), the only one
//!
//! Input (`receive_buf`, from the flip thread): ISTRIP/IGNCR/ICRNL/INLCR,
//! ISIG signal characters, canonical line editing (ICANON: erase, kill,
//! word erase, EOF) and echo. Completed lines and raw input sit in the
//! per-tty read ring, `Tty.ldata`; `read` copies them out (one line at
//! a time in canonical mode, VMIN/VTIME otherwise) and sleeps on
//! `Tty.read_wait`. Output (`write`) does OPOST/ONLCR.
//!
//! Locking: `Tty.ldata` is a sleeping mutex (Linux termios_rwsem's
//! role for the line discipline), thread context only: input echoes
//! through a fixed ring written to the driver under it and sends ISIG
//! signals under it (Linux __isig under termios_rwsem). Its read, line
//! and commit heads are published in `Tty.avail` (atomics), so poll and
//! a reader's wait condition test for input without it (Linux
//! input_available_p): a poll may run under a spin lock.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::Tty;
use super::termios::*;
use crate::fs::File;
use crate::fs::flags::O_NONBLOCK;
use crate::fs::iov_iter::{IovDest, IovSource};
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

/// Echo ring size (Linux echo_buf, N_TTY_BUF_SIZE)
const ECHO_BUF_SIZE: usize = 4096;

/// Queued echo is written to the driver once this much is pending
/// (Linux ECHO_COMMIT_WATERMARK); the rest at the end of the input
const ECHO_COMMIT_WATERMARK: usize = 256;

/// Per-tty N_TTY state (Linux struct n_tty_data)
pub struct NTtyData {
    /// Input ready for readers; `head`/`tail` run free, index mod size
    buf: [u8; READ_BUF_SIZE],
    /// Line-end flags, one bit per `buf` slot (Linux read_flags)
    eol: [u64; READ_BUF_SIZE / 64],
    head: usize,
    tail: usize,
    /// Past the last line end in canonical mode (Linux canon_head): a
    /// line is readable while it differs from `tail`
    canon_head: usize,
    /// Echo not yet written to the driver (Linux echo_buf); `echo_head`
    /// and `echo_tail` run free, index mod size
    echo: [u8; ECHO_BUF_SIZE],
    echo_head: usize,
    echo_tail: usize,
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
            canon_head: 0,
            echo: [0; ECHO_BUF_SIZE],
            echo_head: 0,
            echo_tail: 0,
            line: [0; LINE_MAX],
            line_len: 0,
            icanon: true,
        }
    }

    /// Drop all input (Linux n_tty_flush_buffer)
    pub fn reset(&mut self) {
        self.tail = self.head;
        self.canon_head = self.head;
        self.line_len = 0;
    }

    /// A complete line is queued (canonical mode)
    fn has_line(&self) -> bool {
        self.canon_head != self.tail
    }

    /// Publish the heads for lock-free readers (Linux's smp_store_release
    /// of commit_head, canon_head and read_tail)
    fn publish(&self, av: &Avail) {
        av.icanon.store(self.icanon, Ordering::Release);
        av.canon_head.store(self.canon_head, Ordering::Release);
        av.head.store(self.head, Ordering::Release);
        av.tail.store(self.tail, Ordering::Release);
    }

    /// Queue an echo byte (Linux add_echo_byte); a full ring drops its
    /// oldest byte (Linux's echo discard)
    fn add_echo(&mut self, c: u8) {
        if self.echo_head.wrapping_sub(self.echo_tail) == ECHO_BUF_SIZE {
            self.echo_tail = self.echo_tail.wrapping_add(1);
        }
        self.echo[self.echo_head % ECHO_BUF_SIZE] = c;
        self.echo_head = self.echo_head.wrapping_add(1);
    }

    /// Drop queued echo (an ISIG flush; Linux isig clears echo_buf)
    fn clear_echo(&mut self) {
        self.echo_tail = self.echo_head;
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
            self.canon_head = self.head.wrapping_add(1);
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
        self.canon_head = self.tail;
        if now && self.cnt() > 0 {
            let i = self.head.wrapping_sub(1) % READ_BUF_SIZE;
            self.eol[i / 64] |= 1 << (i % 64);
            self.canon_head = self.head;
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
        self.cnt() + self.line_len + 1 < READ_BUF_SIZE || !self.has_line()
    }

    /// Readable input: a line in canonical mode, else `min` bytes
    fn available(&self, min: usize) -> bool {
        if self.icanon {
            self.has_line()
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

    /// Copy input out: canonical mode (up to the rest of) one line
    /// (None if there is none), else what there is (None if nothing);
    /// with the mode it used and whether a line ended
    fn copy(&mut self, out: &mut [u8]) -> Option<(usize, bool, bool)> {
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
                if canon {
                    return Some((n, canon, true));
                }
                continue;
            }
            if n == out.len() {
                break;
            }
            out[n] = c;
            n += 1;
            self.tail = self.tail.wrapping_add(1);
            if eol && canon {
                return Some((n, canon, true));
            }
        }
        Some((n, canon, false))
    }
}

/// Input availability for readers without `ldata` (Linux's commit_head,
/// canon_head, read_tail and icanon, which input_available_p reads with
/// no lock): stored under `ldata` by every holder as it lets go (`Ld`),
/// loaded by poll (possibly under an epoll IrqSpinlock) and by a
/// reader's wait condition (with its task state set). A hint only: what
/// is read is copied out under `ldata`.
pub struct Avail {
    head: AtomicUsize,
    canon_head: AtomicUsize,
    tail: AtomicUsize,
    icanon: AtomicBool,
}

impl Avail {
    pub const fn new() -> Self {
        Self {
            head: AtomicUsize::new(0),
            canon_head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            icanon: AtomicBool::new(true),
        }
    }

    /// Readable input (Linux input_available_p): a line in canonical
    /// mode, else `amt` bytes
    fn ready(&self, amt: usize) -> bool {
        let tail = self.tail.load(Ordering::Acquire);
        if self.icanon.load(Ordering::Acquire) {
            self.canon_head.load(Ordering::Acquire) != tail
        } else {
            self.head.load(Ordering::Acquire).wrapping_sub(tail) >= amt.max(1)
        }
    }
}

/// `Tty.ldata` held; its heads are published in `Tty.avail` as it is
/// released, so a lock-free reader sees each change
pub(super) struct Ld<'a> {
    g: crate::sync::MutexGuard<'a, NTtyData>,
    av: &'a Avail,
}

impl core::ops::Deref for Ld<'_> {
    type Target = NTtyData;
    fn deref(&self) -> &NTtyData {
        &self.g
    }
}

impl core::ops::DerefMut for Ld<'_> {
    fn deref_mut(&mut self) -> &mut NTtyData {
        &mut self.g
    }
}

impl Drop for Ld<'_> {
    fn drop(&mut self) {
        self.g.publish(self.av);
    }
}

/// Take `tty`'s line discipline lock (thread context; it sleeps)
pub(super) fn ldata(tty: &Tty) -> Ld<'_> {
    Ld {
        g: tty.ldata.lock(),
        av: &tty.avail,
    }
}

/// Write the queued echo to the driver (Linux __process_echoes: the
/// driver takes it all, its writes are synchronous)
fn process_echoes(tty: &Tty, ld: &mut NTtyData) {
    while ld.echo_tail != ld.echo_head {
        let i = ld.echo_tail % ECHO_BUF_SIZE;
        let n = ld
            .echo_head
            .wrapping_sub(ld.echo_tail)
            .min(ECHO_BUF_SIZE - i);
        let _ = tty.driver_write(&ld.echo[i..i + n]);
        ld.echo_tail = ld.echo_tail.wrapping_add(n);
    }
}

/// Write the queued echo once a watermark's worth is pending (Linux
/// commit_echoes)
fn commit_echoes(tty: &Tty, ld: &mut NTtyData) {
    if ld.echo_head.wrapping_sub(ld.echo_tail) >= ECHO_COMMIT_WATERMARK {
        process_echoes(tty, ld);
    }
}

/// Input bytes from the driver, in thread context (Linux
/// n_tty_receive_buf_common, under termios_rwsem); wakes readers. The
/// bytes taken: the rest wait in the flip buffer until a read makes
/// room
pub fn receive_buf(tty: &Tty, bytes: &[u8]) -> usize {
    // Input became readable: SIGIO POLL_IN (Linux kill_fasync at a
    // canonical line end, or after non-canonical input)
    let mut kill = false;
    let mut taken = 0;
    {
        // termios under ldata: set_termios changes both under it (Linux
        // termios_rwsem), so input never sees half a change
        let mut ld = ldata(tty);
        let t = tty.get_termios();
        for &c in bytes {
            if !ld.room() {
                break;
            }
            receive_char(tty, &mut ld, &t, c, &mut kill);
            taken += 1;
        }
        // Linux flush_echoes at the end of the input
        process_echoes(tty, &mut ld);
        // Linux n_tty_receive_buf_common: non-canonical input queued
        if t.c_lflag & ICANON == 0 && ld.cnt() > 0 {
            kill = true;
        }
    }
    if kill {
        tty.kill_input();
    }
    tty.read_wait.wake_poll(u32::from(
        crate::io::poll::POLLIN | crate::io::poll::POLLRDNORM,
    ));
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
fn signal_char(c: u8, t: &Termios) -> Option<crate::signal::Signal> {
    use crate::signal::{SIGINT, SIGQUIT, SIGTSTP};
    [(VINTR, SIGINT), (VQUIT, SIGQUIT), (VSUSP, SIGTSTP)]
        .into_iter()
        .find(|&(i, _)| t.c_cc[i] != 0 && t.c_cc[i] == c)
        .map(|(_, s)| s)
}

/// Signal the foreground group, then flush input and queued echo unless
/// NOFLSH (Linux isig, __isig)
fn isig(tty: &Tty, ld: &mut NTtyData, t: &Termios, sig: crate::signal::Signal) {
    if let Some(pg) = tty.pgrp() {
        crate::signal::kill_pgrp_pid(&pg, sig);
    }
    if t.c_lflag & NOFLSH == 0 {
        ld.clear_echo();
        ld.reset();
    }
}

fn receive_char(tty: &Tty, ld: &mut NTtyData, t: &Termios, c: u8, kill: &mut bool) {
    let Some(c) = map_input(c, t) else {
        return;
    };
    if t.c_lflag & ISIG != 0
        && let Some(sig) = signal_char(c, t)
    {
        // Linux n_tty_receive_signal_char: the signal, then its echo
        isig(tty, ld, t, sig);
        if t.c_lflag & ECHO != 0 {
            echo_char(ld, c, t);
        }
        commit_echoes(tty, ld);
        return;
    }
    if t.c_lflag & ICANON != 0 {
        let canon_head = ld.canon_head;
        canon_char(ld, t, c);
        // Linux n_tty_receive_handle_newline
        *kill |= ld.canon_head != canon_head;
    } else {
        ld.push(c, false);
        if t.c_lflag & ECHO != 0 {
            echo_char(ld, c, t);
        }
    }
    commit_echoes(tty, ld);
}

/// A control character shows as ^X under ECHOCTL (not TAB or NL)
fn shows_caret(c: u8, t: &Termios) -> bool {
    t.c_lflag & ECHOCTL != 0 && (c < 0x20 || c == 0x7f) && c != b'\t' && c != b'\n'
}

/// Echo `c`: a control character as ^X with ECHOCTL, a newline through
/// OPOST/ONLCR (Linux echo_char)
fn echo_char(ld: &mut NTtyData, c: u8, t: &Termios) {
    if c == b'\n' && t.c_oflag & OPOST != 0 && t.c_oflag & ONLCR != 0 {
        ld.add_echo(b'\r');
        ld.add_echo(b'\n');
    } else if shows_caret(c, t) {
        ld.add_echo(b'^');
        ld.add_echo(c ^ 0x40);
    } else {
        ld.add_echo(c);
    }
}

/// Erase the last character of the edited line, echoing it away (ECHOE:
/// one column, two for a ^X)
fn erase(ld: &mut NTtyData, t: &Termios) -> bool {
    let Some(&c) = ld.line[..ld.line_len].last() else {
        return false;
    };
    ld.line_len -= 1;
    if t.c_lflag & ECHO != 0 && t.c_lflag & ECHOE != 0 {
        let cols = if shows_caret(c, t) { 2 } else { 1 };
        for _ in 0..cols {
            for &b in b"\x08 \x08" {
                ld.add_echo(b);
            }
        }
    }
    true
}

fn is_blank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// A character in canonical mode (Linux n_tty_receive_char_canon)
fn canon_char(ld: &mut NTtyData, t: &Termios, c: u8) {
    let is = |i: usize| t.c_cc[i] != 0 && t.c_cc[i] == c;
    if is(VERASE) {
        erase(ld, t);
    } else if is(VWERASE) && t.c_lflag & IEXTEN != 0 {
        // Trailing blanks, then the word
        while ld.line_len > 0 && is_blank(ld.line[ld.line_len - 1]) {
            erase(ld, t);
        }
        while ld.line_len > 0 && !is_blank(ld.line[ld.line_len - 1]) {
            erase(ld, t);
        }
    } else if is(VKILL) {
        if t.c_lflag & ECHO != 0 && t.c_lflag & ECHOK != 0 && t.c_lflag & ECHOKE == 0 {
            echo_char(ld, c, t);
            echo_char(ld, b'\n', t);
            ld.line_len = 0;
        } else {
            while erase(ld, t) {}
        }
    } else if is(VEOF) {
        ld.commit_line(EOF_MARK);
    } else if c == b'\n' || is(VEOL) || is(VEOL2) {
        if t.c_lflag & (ECHO | ECHONL) != 0 {
            echo_char(ld, c, t);
        }
        ld.commit_line(c);
    } else if ld.line_len < LINE_MAX {
        ld.line[ld.line_len] = c;
        ld.line_len += 1;
        if t.c_lflag & ECHO != 0 {
            echo_char(ld, c, t);
        }
    }
}

/// Input moved out by one `copy_out`
struct Got {
    /// Bytes that reached the reader
    n: usize,
    /// Canonical mode
    canon: bool,
    /// A canonical line ended
    end: bool,
    /// The kernel buffer was filled: there may be more
    full: bool,
    /// The reader's buffer faulted: the rest of the copy is lost
    fault: bool,
}

/// Bytes moved per `copy_out` (Linux tty_read's kernel_buf)
const KBUF: usize = 64;

/// Move input to `to` through a small kernel buffer, so nothing is
/// copied to the reader under `ldata` (Linux tty_read); None if there
/// is none
fn copy_out(tty: &Tty, to: &mut IovDest<'_>) -> Option<Got> {
    let mut kbuf = [0u8; KBUF];
    let want = to.len().min(KBUF);
    let (k, canon, end) = ldata(tty).copy(&mut kbuf[..want])?;
    let n = to.copy_to(&kbuf[..k]).unwrap_or(0);
    Some(Got {
        n,
        canon,
        end,
        full: k == KBUF,
        fault: n < k,
    })
}

/// Read (Linux n_tty_read): canonical mode returns one line; otherwise
/// VMIN bytes, VTIME the timeout (both 0: what there is). Sleeps unless
/// O_NONBLOCK (EAGAIN); a signal ends the sleep (ERESTARTSYS, or the
/// bytes read so far). A fault on the reader's buffer ends the read
/// (EFAULT if nothing reached it); the input taken is lost (Linux).
pub fn read(tty: &Tty, file: &File, to: &mut IovDest<'_>) -> Result<usize, KernelError> {
    if to.is_empty() {
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
    // One reader at a time (Linux atomic_read_lock): EAGAIN if taken
    // and O_NONBLOCK, else a signal ends the wait
    let _reader = if nonblock {
        tty.read_lock.try_lock().ok_or(KernelError::WouldBlock)?
    } else {
        tty.read_lock.lock_interruptible()?
    };
    // Lock-free: the condition runs with the task state set (Linux
    // n_tty_read's input_available_p)
    let ready = || tty.avail.ready(1);
    let mut n = 0;
    loop {
        if let Some(g) = copy_out(tty, to) {
            n += g.n;
            // Room was made: input held in the flip buffer may go on
            // (Linux n_tty_kick_worker)
            super::flip::kick(tty);
            if g.fault {
                return if n > 0 {
                    Ok(n)
                } else {
                    Err(KernelError::BadAddress)
                };
            }
            if g.end || to.is_empty() || (!g.full && (g.canon || n >= min)) {
                break;
            }
            if time != 0 {
                timeout = time;
            }
            continue;
        }
        // What was there is out (a full kernel buffer went on)
        if n > 0 && n >= min {
            break;
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
/// VMIN bytes when VTIME is 0; takes no sleeping lock (a poll may run
/// under a spin lock)
pub fn poll_in(tty: &Tty) -> bool {
    let t = tty.get_termios();
    let min = if t.c_cc[VTIME] == 0 {
        usize::from(t.c_cc[VMIN])
    } else {
        1
    };
    tty.avail.ready(min)
}

/// Write (Linux iterate_tty_write + n_tty_write), under the tty's
/// write lock: through a kernel buffer a chunk at a time; a short chunk
/// ends it, an error after some bytes returns their count
pub fn write(tty: &Tty, from: &mut IovSource<'_>) -> Result<usize, KernelError> {
    let mut chunk = [0u8; 512];
    let mut done = 0;
    while !from.is_empty() {
        let r = from
            .copy_from(&mut chunk)
            .and_then(|c| Ok((write_chunk(tty, &chunk[..c])?, c)));
        match r {
            Ok((n, c)) => {
                done += n;
                if n < c {
                    break;
                }
            }
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(done)
}

/// Write one chunk: OPOST with ONLCR maps NL to CR-NL
fn write_chunk(tty: &Tty, buf: &[u8]) -> Result<usize, KernelError> {
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
