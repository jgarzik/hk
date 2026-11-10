//! Linux native AIO through raw syscalls (Linux fs/aio.c; libaio's ABI
//! and the user-space ring fast path some databases use: events read
//! straight from the mapped `struct aio_ring`)

pub mod bench;
pub mod dio;
pub mod life;
pub mod ops;
pub mod setup;

use core::sync::atomic::{AtomicU32, Ordering};

use crate::harness::check;
use crate::helpers::{msleep, read_file};
use hk_syscall::{
    O_RDWR, O_WRONLY, Timespec, sys_close, sys_io_destroy, sys_io_getevents, sys_io_setup,
    sys_io_submit, sys_open, sys_write,
};

pub const EINVAL: i64 = -22;
pub const EAGAIN: i64 = -11;
pub const EFAULT: i64 = -14;
pub const EBADF: i64 = -9;
pub const EINTR: i64 = -4;

pub const IOCB_CMD_PREAD: u16 = 0;
pub const IOCB_CMD_PWRITE: u16 = 1;
pub const IOCB_CMD_FSYNC: u16 = 2;
pub const IOCB_CMD_FDSYNC: u16 = 3;
pub const IOCB_CMD_POLL: u16 = 5;
pub const IOCB_CMD_NOOP: u16 = 6;
pub const IOCB_CMD_PREADV: u16 = 7;
pub const IOCB_CMD_PWRITEV: u16 = 8;
pub const IOCB_FLAG_RESFD: u32 = 1;

pub const AIO_RING_MAGIC: u32 = 0xa10a_10a1;

pub fn run_tests() {
    setup::run_tests();
    dio::run_tests();
    ops::run_tests();
    life::run_tests();
}

/// `struct iocb`
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Iocb {
    pub data: u64,
    pub key: u32,
    pub rw_flags: i32,
    pub opcode: u16,
    pub reqprio: i16,
    pub fildes: u32,
    pub buf: u64,
    pub nbytes: u64,
    pub offset: i64,
    pub reserved2: u64,
    pub flags: u32,
    pub resfd: u32,
}

/// `struct io_event`
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct IoEvent {
    pub data: u64,
    pub obj: u64,
    pub res: i64,
    pub res2: i64,
}

/// An iocb of `op` on `fd`: `len` bytes (or iovecs) at `buf`, offset `off`
pub fn iocb(op: u16, fd: i32, buf: u64, len: u64, off: i64, data: u64) -> Iocb {
    Iocb {
        data,
        opcode: op,
        fildes: fd as u32,
        buf,
        nbytes: len,
        offset: off,
        ..Iocb::default()
    }
}

/// An AIO context, destroyed when dropped (unless `forget`)
pub struct Ctx(pub u64);

impl Ctx {
    pub fn new(n: u32) -> Result<Self, (&'static [u8], i64)> {
        let mut id = 0u64;
        let r = sys_io_setup(n, &mut id);
        check(b"io_setup", r == 0 && id != 0, r)?;
        Ok(Self(id))
    }

    /// io_submit of the iocbs `p` points at
    pub fn submit(&self, p: &[*const Iocb]) -> i64 {
        sys_io_submit(self.0, p.len() as i64, p.as_ptr() as *const u64)
    }

    /// Submit one, which must be taken
    pub fn submit1(&self, cb: &Iocb) -> Result<(), (&'static [u8], i64)> {
        let n = self.submit(&[cb as *const Iocb]);
        check(b"io_submit", n == 1, n)
    }

    /// io_getevents for at least `min` into `ev`, waiting up to `ms` (None:
    /// forever)
    pub fn get(&self, min: usize, ev: &mut [IoEvent], ms: Option<i64>) -> i64 {
        let ts = ms.map(|m| Timespec {
            tv_sec: m / 1000,
            tv_nsec: (m % 1000) * 1_000_000,
        });
        let tp = ts.as_ref().map_or(0, |t| t as *const Timespec as u64);
        sys_io_getevents(
            self.0,
            min as i64,
            ev.len() as i64,
            ev.as_mut_ptr() as u64,
            tp,
        )
    }

    /// Wait (5 s at most) for exactly `ev.len()` events
    pub fn get_all(&self, ev: &mut [IoEvent]) -> Result<(), (&'static [u8], i64)> {
        let mut got = 0;
        while got < ev.len() {
            let n = self.get(ev.len() - got, &mut ev[got..], Some(5000));
            check(b"io_getevents", n > 0, n)?;
            got += n as usize;
        }
        Ok(())
    }

    /// Word `i` of the mapped `struct aio_ring` header
    pub fn word(&self, i: usize) -> &AtomicU32 {
        // SAFETY: the ring's first page is mapped at the context id
        unsafe { &*(self.0 as *const AtomicU32).add(i) }
    }

    pub fn nr(&self) -> u32 {
        self.word(1).load(Ordering::Relaxed)
    }

    /// Events in the ring (tail - head)
    pub fn ready(&self) -> u32 {
        let nr = self.nr();
        let h = self.word(2).load(Ordering::Acquire);
        let t = self.word(3).load(Ordering::Acquire);
        (t + nr - h) % nr
    }

    /// Take events straight from the ring (the user-space fast path): head
    /// and tail read, events copied, the new head stored
    pub fn ring_pop(&self, out: &mut [IoEvent]) -> usize {
        let nr = self.nr();
        let mut head = self.word(2).load(Ordering::Acquire);
        let tail = self.word(3).load(Ordering::Acquire);
        let mut n = 0;
        while head != tail && n < out.len() {
            let p = (self.0 + 32 + u64::from(head) * 32) as *const IoEvent;
            // SAFETY: event `head` of the mapped ring, published by the tail
            out[n] = unsafe { p.read_volatile() };
            head = (head + 1) % nr;
            n += 1;
        }
        self.word(2).store(head, Ordering::Release);
        n
    }

    /// Take `out.len()` events from the ring, waiting up to 5 s
    pub fn ring_pop_all(&self, out: &mut [IoEvent]) -> Result<(), (&'static [u8], i64)> {
        let mut got = 0;
        for _ in 0..5000 {
            got += self.ring_pop(&mut out[got..]);
            if got == out.len() {
                return Ok(());
            }
            msleep(1);
        }
        check(b"ring events", false, got as i64)
    }

    /// Leave it to the exit
    pub fn forget(mut self) {
        self.0 = 0;
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        if self.0 != 0 {
            sys_io_destroy(self.0);
        }
    }
}

/// /proc/sys/fs/<name> as a number
pub fn sysctl(name: &[u8]) -> i64 {
    let mut path = [0u8; 64];
    let pre = b"/proc/sys/fs/";
    path[..pre.len()].copy_from_slice(pre);
    path[pre.len()..pre.len() + name.len()].copy_from_slice(name);
    let mut b = [0u8; 32];
    let n = read_file(&path, &mut b);
    if n <= 0 {
        return -1;
    }
    b[..n as usize]
        .iter()
        .take_while(|c| c.is_ascii_digit())
        .fold(0i64, |v, &c| v * 10 + i64::from(c - b'0'))
}

/// Write `v` to /proc/sys/fs/<name> (NUL-terminated name)
pub fn set_sysctl(name: &[u8], v: i64) -> i64 {
    let mut path = [0u8; 64];
    let pre = b"/proc/sys/fs/";
    path[..pre.len()].copy_from_slice(pre);
    path[pre.len()..pre.len() + name.len()].copy_from_slice(name);
    let fd = sys_open(path.as_ptr(), O_WRONLY, 0);
    if fd < 0 {
        return fd;
    }
    let mut s = [0u8; 24];
    let mut i = s.len();
    let mut x = v as u64;
    loop {
        i -= 1;
        s[i] = b'0' + (x % 10) as u8;
        x /= 10;
        if x == 0 {
            break;
        }
    }
    let r = sys_write(fd as u64, s[i..].as_ptr(), (s.len() - i) as u64);
    sys_close(fd as u64);
    r
}

/// A scratch file on /tmp, read-write, truncated
pub fn tmp_file(path: &[u8]) -> Result<i32, (&'static [u8], i64)> {
    let fd = sys_open(
        path.as_ptr(),
        O_RDWR | hk_syscall::O_CREAT | hk_syscall::O_TRUNC,
        0o600,
    );
    check(b"open tmp", fd >= 0, fd)?;
    Ok(fd as i32)
}
