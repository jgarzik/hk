//! The kernel log as records, /dev/kmsg and syslog(2) reads (Linux
//! kernel/printk/printk.c, the log_buf of Linux 3.5-5.9)
//!
//! Every printk line becomes a record {seq, timestamp, facility/level,
//! text} in a ring of [`LOG_BUF_LEN`] bytes; the oldest records are
//! dropped to make room. printk output still goes to the console as
//! before (printk.rs keeps its byte ring for the boot-time flush).
//!
//! - Reading needs CAP_SYSLOG (dmesg_restrict = 1): every syslog(2)
//!   action, and opening /dev/kmsg other than write-only.
//! - /dev/kmsg (1:11): each open has its own cursor (seq + ring index,
//!   valid while seq >= the first record's). A read returns one record
//!   as `pri,seq,usec,-;text\n` (non-printable bytes as `\xNN`), EINVAL
//!   if the buffer is too small, EPIPE once if records were dropped
//!   under the cursor, EAGAIN or a wait at the end. lseek(0) with
//!   SEEK_SET/SEEK_DATA/SEEK_END moves to the first record, the first
//!   after the last syslog CLEAR, or the end. A write is one record:
//!   an optional `<N>` prefix (level N & 7, facility N >> 3, facility 0
//!   made LOG_USER), rate-limited to 10 per 5 s per open file.
//! - syslog(2) READ_ALL / READ_CLEAR / READ / SIZE_*: `<pri>[ts] text`
//!   lines.
//!
//! Locking: `LOG` is an IrqSpinlock leaf (printk runs in any context);
//! printk takes it under its OUTPUT_LOCK. Readers are woken from the
//! scheduler tick (printk may hold run-queue locks; Linux defers the
//! klogd wakeup through irq_work).

use core::sync::atomic::{AtomicBool, Ordering};

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::arch::IrqSpinlock;
use crate::error::KernelError;
use crate::waitqueue::WaitQueue;

/// Ring size in bytes
pub const LOG_BUF_LEN: usize = 1 << 17;
/// Longest record text (Linux LOG_LINE_MAX: 1024 - 32)
pub const LOG_LINE_MAX: usize = 992;
/// Level of printk lines without one (Linux MESSAGE_LOGLEVEL_DEFAULT)
pub const DEFAULT_LEVEL: u8 = 4;
/// syslog facility of user-written records (Linux LOG_USER)
const LOG_USER: u8 = 1;
/// Record header: len u16, text_len u16, pri u8, 3 pad, ts u64
const HDR: usize = 16;

/// One record as read from the ring
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rec<'a> {
    pub seq: u64,
    /// facility << 3 | level
    pub pri: u8,
    pub ts_ns: u64,
    pub text: &'a [u8],
}

/// The record ring (Linux log_buf with log_first_idx/log_next_idx)
pub struct LogBuf {
    data: [u8; LOG_BUF_LEN],
    first_idx: usize,
    next_idx: usize,
    first_seq: u64,
    next_seq: u64,
}

impl Default for LogBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl LogBuf {
    pub const fn new() -> Self {
        Self {
            data: [0; LOG_BUF_LEN],
            first_idx: 0,
            next_idx: 0,
            first_seq: 0,
            next_seq: 0,
        }
    }

    pub fn first_seq(&self) -> u64 {
        self.first_seq
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Ring index of the first record, and one past the last
    pub fn first_idx(&self) -> usize {
        self.first_idx
    }

    pub fn next_idx(&self) -> usize {
        self.next_idx
    }

    fn rd16(&self, at: usize) -> usize {
        u16::from_le_bytes([self.data[at], self.data[at + 1]]) as usize
    }

    /// The real start of a record at `idx`: a zero length or the end of
    /// the ring means it wrapped to 0
    fn unwrap_idx(&self, idx: usize) -> usize {
        if idx + HDR > LOG_BUF_LEN || self.rd16(idx) == 0 {
            0
        } else {
            idx
        }
    }

    /// The record `seq` at ring index `idx` (seq in first..next), and the
    /// index of the next one
    pub fn read(&self, seq: u64, idx: usize) -> Option<(Rec<'_>, usize)> {
        if seq < self.first_seq || seq >= self.next_seq {
            return None;
        }
        let at = self.unwrap_idx(idx);
        let len = self.rd16(at);
        let text_len = self.rd16(at + 2);
        let pri = self.data[at + 4];
        let ts = u64::from_le_bytes(self.data[at + 8..at + 16].try_into().unwrap());
        let text = &self.data[at + HDR..at + HDR + text_len];
        Some((
            Rec {
                seq,
                pri,
                ts_ns: ts,
                text,
            },
            at + len,
        ))
    }

    /// Room for a record of `size` bytes without dropping any
    fn has_space(&self, size: usize) -> bool {
        if self.first_seq == self.next_seq {
            return size <= LOG_BUF_LEN;
        }
        if self.next_idx >= self.first_idx {
            LOG_BUF_LEN - self.next_idx >= size || self.first_idx > size
        } else {
            self.first_idx - self.next_idx > size
        }
    }

    fn drop_oldest(&mut self) {
        let at = self.unwrap_idx(self.first_idx);
        self.first_idx = at + self.rd16(at);
        self.first_seq += 1;
        if self.first_seq == self.next_seq {
            self.first_idx = 0;
            self.next_idx = 0;
        }
    }

    /// Append a record (text cut at LOG_LINE_MAX), dropping the oldest
    /// ones as needed; returns its seq
    pub fn push(&mut self, pri: u8, ts_ns: u64, text: &[u8]) -> u64 {
        let text = &text[..text.len().min(LOG_LINE_MAX)];
        let size = (HDR + text.len() + 3) & !3;
        if self.first_seq == self.next_seq {
            self.first_idx = 0;
            self.next_idx = 0;
        }
        while !self.has_space(size) {
            self.drop_oldest();
        }
        if self.next_idx + size > LOG_BUF_LEN {
            // Mark the wrap and start over at 0
            if self.next_idx + 2 <= LOG_BUF_LEN {
                self.data[self.next_idx..self.next_idx + 2].fill(0);
            }
            self.next_idx = 0;
        }
        let at = self.next_idx;
        self.data[at..at + 2].copy_from_slice(&(size as u16).to_le_bytes());
        self.data[at + 2..at + 4].copy_from_slice(&(text.len() as u16).to_le_bytes());
        self.data[at + 4] = pri;
        self.data[at + 5..at + 8].fill(0);
        self.data[at + 8..at + 16].copy_from_slice(&ts_ns.to_le_bytes());
        self.data[at + HDR..at + HDR + text.len()].copy_from_slice(text);
        self.next_idx = at + size;
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }
}

/// The log: records, the partial line printk is building, and the
/// syslog cursors
struct Log {
    buf: LogBuf,
    line: [u8; LOG_LINE_MAX],
    line_len: usize,
    line_ts: u64,
    /// First record after the last SYSLOG_ACTION_CLEAR (seq, idx)
    clear: (u64, usize),
    /// syslog READ's destructive cursor
    syslog: (u64, usize),
}

static LOG: IrqSpinlock<Log> = IrqSpinlock::new(Log {
    buf: LogBuf::new(),
    line: [0; LOG_LINE_MAX],
    line_len: 0,
    line_ts: 0,
    clear: (0, 0),
    syslog: (0, 0),
});

/// Readers of /dev/kmsg and syslog READ
static WAITERS: WaitQueue = WaitQueue::new();
/// New records since the last wakeup of WAITERS
static WAKE_PENDING: AtomicBool = AtomicBool::new(false);

/// A cursor still pointing into the ring, else the first record
fn valid(buf: &LogBuf, c: (u64, usize)) -> (u64, usize) {
    if c.0 < buf.first_seq() {
        (buf.first_seq(), buf.first_idx())
    } else {
        c
    }
}

/// Feed printk output (any context): complete lines become records at
/// the default level, a `\x01N` (KERN_SOH) prefix sets the level
pub fn log_text(bytes: &[u8], panicking: bool) {
    let mut log = if panicking {
        match LOG.try_lock() {
            Some(l) => l,
            None => return,
        }
    } else {
        LOG.lock()
    };
    let now = crate::time::monotonic_ns();
    for &b in bytes {
        if log.line_len == 0 {
            log.line_ts = now;
        }
        if b == b'\n' {
            let Log {
                buf,
                line,
                line_len,
                line_ts,
                ..
            } = &mut *log;
            let (level, text) = match &line[..*line_len] {
                [1, l @ b'0'..=b'7', rest @ ..] => (l - b'0', rest),
                t => (DEFAULT_LEVEL, t),
            };
            buf.push(level, *line_ts, text);
            *line_len = 0;
            WAKE_PENDING.store(true, Ordering::Release);
        } else if log.line_len < LOG_LINE_MAX {
            let n = log.line_len;
            log.line[n] = b;
            log.line_len += 1;
        }
    }
}

/// Wake readers if records came in (the scheduler tick: no locks held)
pub fn tick() {
    if WAKE_PENDING.swap(false, Ordering::AcqRel) {
        WAITERS.wake_all();
    }
}

/// Add a record directly (a /dev/kmsg write) and show it on the console
fn emit(pri: u8, text: &[u8]) {
    LOG.lock().buf.push(pri, crate::time::monotonic_ns(), text);
    WAKE_PENDING.store(true, Ordering::Release);
    crate::printk::console_line(text);
}

/// Append `n` in decimal
fn push_num(out: &mut Vec<u8>, mut n: u64, width: usize) {
    let mut d = [0u8; 20];
    let mut i = d.len();
    loop {
        i -= 1;
        d[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    for _ in (d.len() - i)..width {
        out.push(b' ');
    }
    out.extend_from_slice(&d[i..]);
}

/// A record in /dev/kmsg form: `pri,seq,usec,-;text\n` (Linux
/// info_print_ext_header + msg_print_ext_body)
pub fn format_kmsg(r: &Rec<'_>, out: &mut Vec<u8>) {
    push_num(out, r.pri as u64, 0);
    out.push(b',');
    push_num(out, r.seq, 0);
    out.push(b',');
    push_num(out, r.ts_ns / 1000, 0);
    out.extend_from_slice(b",-;");
    for &c in r.text {
        if !(b' '..127).contains(&c) || c == b'\\' {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            out.extend_from_slice(&[b'\\', b'x', HEX[(c >> 4) as usize], HEX[(c & 15) as usize]]);
        } else {
            out.push(c);
        }
    }
    out.push(b'\n');
}

/// A record in syslog(2) form: `<pri>[ssss.uuuuuu] text\n`
fn format_syslog(r: &Rec<'_>, out: &mut Vec<u8>) {
    out.push(b'<');
    push_num(out, r.pri as u64, 0);
    out.extend_from_slice(b">[");
    push_num(out, r.ts_ns / 1_000_000_000, 5);
    out.push(b'.');
    let us = (r.ts_ns / 1000) % 1_000_000;
    for d in [100_000, 10_000, 1_000, 100, 10, 1] {
        out.push(b'0' + ((us / d) % 10) as u8);
    }
    out.extend_from_slice(b"] ");
    out.extend_from_slice(r.text);
    out.push(b'\n');
}

/// Most records the ring can hold (each at least a header)
const MAX_RECS: usize = LOG_BUF_LEN / HDR;
/// Longest formatted record: header text plus every byte escaped
const MAX_FMT: usize = 64 + 4 * LOG_LINE_MAX;

/// Whether the caller may read the log (Linux check_syslog_permissions
/// with dmesg_restrict = 1, CONFIG_SECURITY_DMESG_RESTRICT as in
/// Ubuntu's kernel): CAP_SYSLOG, or the deprecated CAP_SYS_ADMIN
pub fn syslog_read_allowed() -> bool {
    use crate::task::{CAP_SYS_ADMIN, CAP_SYSLOG, capable};
    capable(CAP_SYSLOG) || capable(CAP_SYS_ADMIN)
}

/// syslog(2) SIZE_BUFFER
pub fn syslog_size_buffer() -> usize {
    LOG_BUF_LEN
}

/// syslog(2) SIZE_UNREAD: bytes READ would return
pub fn syslog_size_unread() -> usize {
    let mut tmp = Vec::with_capacity(MAX_FMT);
    let log = LOG.lock();
    let (mut seq, mut idx) = valid(&log.buf, log.syslog);
    let mut n = 0;
    while let Some((r, next)) = log.buf.read(seq, idx) {
        tmp.clear();
        format_syslog(&r, &mut tmp);
        n += tmp.len();
        seq += 1;
        idx = next;
    }
    n
}

/// syslog(2) CLEAR: later READ_ALL starts after the current records
pub fn syslog_clear() {
    let mut log = LOG.lock();
    log.clear = (log.buf.next_seq(), log.buf.next_idx());
}

/// syslog(2) READ_ALL (and READ_CLEAR with `clear`): the newest records
/// since the last CLEAR that fit in `len` bytes, oldest first
pub fn syslog_read_all(len: usize, clear: bool) -> Vec<u8> {
    // Allocated before LOG (IRQs off) is taken, large enough not to grow
    let mut sizes = Vec::with_capacity(MAX_RECS);
    let mut tmp = Vec::with_capacity(MAX_FMT);
    let mut out = Vec::with_capacity(len.min(LOG_BUF_LEN + MAX_RECS * 64));
    let mut log = LOG.lock();
    let start = valid(&log.buf, log.clear);
    // Formatted sizes, to skip the oldest that do not fit
    let (mut seq, mut idx) = start;
    while let Some((r, next)) = log.buf.read(seq, idx) {
        tmp.clear();
        format_syslog(&r, &mut tmp);
        sizes.push(tmp.len());
        seq += 1;
        idx = next;
    }
    let mut total: usize = sizes.iter().sum();
    let (mut seq, mut idx) = start;
    let mut skip = 0;
    while total > len && skip < sizes.len() {
        total -= sizes[skip];
        skip += 1;
    }
    let mut i = 0;
    while let Some((r, next)) = log.buf.read(seq, idx) {
        if i >= skip {
            format_syslog(&r, &mut out);
        }
        i += 1;
        seq += 1;
        idx = next;
    }
    if clear {
        log.clear = (log.buf.next_seq(), log.buf.next_idx());
    }
    out
}

/// syslog(2) READ: records not yet read this way, as many as fit (at
/// least one record if any; waits for one if there are none)
pub fn syslog_read(len: usize) -> Result<Vec<u8>, KernelError> {
    WAITERS.wait_event_interruptible(|| {
        let log = LOG.lock();
        valid(&log.buf, log.syslog).0 < log.buf.next_seq()
    })?;
    let mut out = Vec::with_capacity(len.min(LOG_BUF_LEN + MAX_RECS * 64));
    let mut tmp = Vec::with_capacity(MAX_FMT);
    let mut log = LOG.lock();
    let (mut seq, mut idx) = valid(&log.buf, log.syslog);
    while let Some((r, next)) = log.buf.read(seq, idx) {
        tmp.clear();
        format_syslog(&r, &mut tmp);
        if out.len() + tmp.len() > len {
            break;
        }
        out.extend_from_slice(&tmp);
        seq += 1;
        idx = next;
    }
    log.syslog = (seq, idx);
    Ok(out)
}

// ============================================================================
// /dev/kmsg
// ============================================================================

/// One open of /dev/kmsg
struct KmsgUser {
    cur: crate::sync::spin::Mutex<(u64, usize)>,
    /// Writes in the current 5 s window, and when it began
    rate: crate::sync::spin::Mutex<(u32, u64)>,
}

fn user(file: &crate::fs::File) -> Result<&KmsgUser, KernelError> {
    file.private
        .get()
        .and_then(|p| p.downcast_ref::<KmsgUser>())
        .ok_or(KernelError::BadFd)
}

/// /dev/kmsg file operations (Linux devkmsg_fops)
pub struct KmsgFileOps;

pub static KMSG_FILE_OPS: KmsgFileOps = KmsgFileOps;

impl crate::fs::FileOps for KmsgFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn open(&self, file: &crate::fs::File) -> Result<(), KernelError> {
        // Linux devkmsg_open: reading needs syslog READ_ALL rights
        if file.get_flags() & crate::fs::flags::O_ACCMODE != crate::fs::flags::O_WRONLY
            && !syslog_read_allowed()
        {
            return Err(KernelError::NotPermitted);
        }
        let first = {
            let log = LOG.lock();
            (log.buf.first_seq(), log.buf.first_idx())
        };
        let u = KmsgUser {
            cur: crate::sync::spin::Mutex::new(first),
            rate: crate::sync::spin::Mutex::new((0, 0)),
        };
        file.private.call_once(|| Arc::new(u));
        Ok(())
    }

    fn read(&self, file: &crate::fs::File, buf: &mut [u8]) -> Result<usize, KernelError> {
        let u = user(file)?;
        let mut out = Vec::with_capacity(MAX_FMT);
        loop {
            // The cursor lock is a spinlock: never held across the wait
            let seq = {
                let mut cur = u.cur.lock();
                let log = LOG.lock();
                if cur.0 < log.buf.first_seq() {
                    // Records dropped under the cursor: say so once
                    *cur = (log.buf.first_seq(), log.buf.first_idx());
                    return Err(KernelError::BrokenPipe);
                }
                if let Some((r, next)) = log.buf.read(cur.0, cur.1) {
                    format_kmsg(&r, &mut out);
                    drop(log);
                    if out.len() > buf.len() {
                        return Err(KernelError::InvalidArgument);
                    }
                    buf[..out.len()].copy_from_slice(&out);
                    *cur = (cur.0 + 1, next);
                    return Ok(out.len());
                }
                cur.0
            };
            if file.get_flags() & crate::fs::flags::O_NONBLOCK != 0 {
                return Err(KernelError::WouldBlock);
            }
            WAITERS.wait_event_interruptible(|| LOG.lock().buf.next_seq() > seq)?;
        }
    }

    fn write(&self, file: &crate::fs::File, buf: &[u8]) -> Result<usize, KernelError> {
        let u = user(file)?;
        if buf.len() > LOG_LINE_MAX {
            return Err(KernelError::InvalidArgument);
        }
        // Linux printk.devkmsg=ratelimit: 10 records per 5 s per open,
        // the rest dropped silently
        {
            let now = crate::time::monotonic_ns();
            let mut r = u.rate.lock();
            if r.1 == 0 || now.saturating_sub(r.1) >= 5_000_000_000 {
                *r = (0, now.max(1));
            }
            r.0 += 1;
            if r.0 > 10 {
                return Ok(buf.len());
            }
        }
        let (mut fac, mut level, mut text) = (LOG_USER, DEFAULT_LEVEL, buf);
        if let [b'<', rest @ ..] = buf
            && let Some(end) = rest.iter().position(|&c| c == b'>')
            && end > 0
            && let Some(n) = core::str::from_utf8(&rest[..end])
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
        {
            level = (n & 7) as u8;
            fac = ((n >> 3) & 0xff) as u8;
            if fac == 0 {
                fac = LOG_USER;
            }
            text = &rest[end + 1..];
        }
        let text = text.strip_suffix(b"\n").unwrap_or(text);
        emit(fac << 3 | level, text);
        Ok(buf.len())
    }

    fn llseek(&self, file: &crate::fs::File, offset: i64, whence: i32) -> Result<u64, KernelError> {
        const SEEK_SET: i32 = 0;
        const SEEK_END: i32 = 2;
        const SEEK_DATA: i32 = 3;
        let u = user(file)?;
        if offset != 0 {
            return Err(KernelError::IllegalSeek);
        }
        // Lock order cur -> LOG, as in read and poll
        let mut cur = u.cur.lock();
        let log = LOG.lock();
        *cur = match whence {
            SEEK_SET => (log.buf.first_seq(), log.buf.first_idx()),
            SEEK_DATA => valid(&log.buf, log.clear),
            SEEK_END => (log.buf.next_seq(), log.buf.next_idx()),
            _ => return Err(KernelError::InvalidArgument),
        };
        Ok(0)
    }

    fn poll(&self, file: &crate::fs::File, pt: Option<&mut crate::poll::PollTable>) -> u16 {
        use crate::poll::{POLLERR, POLLIN, POLLPRI, POLLRDNORM};
        if let Some(pt) = pt {
            pt.poll_wait(&WAITERS);
        }
        let Ok(u) = user(file) else {
            return POLLERR;
        };
        let seq = u.cur.lock().0;
        let log = LOG.lock();
        if seq < log.buf.first_seq() {
            POLLIN | POLLRDNORM | POLLERR | POLLPRI
        } else if seq < log.buf.next_seq() {
            POLLIN | POLLRDNORM
        } else {
            0
        }
    }
}

/// /dev/kmsg as a character device: its own file operations
pub struct KmsgCharDevice;

impl crate::chardev::CharDevice for KmsgCharDevice {
    fn name(&self) -> &str {
        "kmsg"
    }

    fn read(&self, _buf: &mut [u8]) -> Result<usize, crate::chardev::DeviceError> {
        Err(crate::chardev::DeviceError::NotSupported)
    }

    fn write(&self, _buf: &[u8]) -> Result<usize, crate::chardev::DeviceError> {
        Err(crate::chardev::DeviceError::NotSupported)
    }

    fn fops(&self) -> Option<&'static dyn crate::fs::FileOps> {
        Some(&KMSG_FILE_OPS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;

    fn texts(b: &LogBuf) -> Vec<Vec<u8>> {
        let (mut s, mut i) = (b.first_seq(), b.first_idx());
        let mut v = Vec::new();
        while let Some((r, n)) = b.read(s, i) {
            v.push(r.text.to_vec());
            s += 1;
            i = n;
        }
        v
    }

    #[test]
    fn push_read() {
        let mut b = Box::new(LogBuf::new());
        b.push(6, 10, b"one");
        b.push(4, 20, b"two");
        assert_eq!(texts(&b), [b"one".to_vec(), b"two".to_vec()]);
        let (r, _) = b.read(1, 20).unwrap();
        assert_eq!((r.seq, r.pri, r.ts_ns), (1, 4, 20));
    }

    #[test]
    fn wraps_and_drops_oldest() {
        let mut b = Box::new(LogBuf::new());
        let line = [b'x'; 900];
        for i in 0..1000u64 {
            let mut t = line.to_vec();
            t[..8].copy_from_slice(&i.to_le_bytes());
            b.push(6, i, &t);
        }
        assert_eq!(b.next_seq(), 1000);
        assert!(b.first_seq() > 800, "first {}", b.first_seq());
        let all = texts(&b);
        assert_eq!(all.len() as u64, b.next_seq() - b.first_seq());
        for (k, t) in all.iter().enumerate() {
            let want = b.first_seq() + k as u64;
            assert_eq!(u64::from_le_bytes(t[..8].try_into().unwrap()), want);
        }
    }

    #[test]
    fn long_text_cut() {
        let mut b = Box::new(LogBuf::new());
        b.push(6, 0, &[b'a'; 5000]);
        assert_eq!(texts(&b)[0].len(), LOG_LINE_MAX);
    }

    #[test]
    fn kmsg_format() {
        let r = Rec {
            seq: 7,
            pri: 14,
            ts_ns: 1_500_000,
            text: b"a\tb\\",
        };
        let mut out = Vec::new();
        format_kmsg(&r, &mut out);
        assert_eq!(out, b"14,7,1500,-;a\\x09b\\x5c\n");
    }
}
