//! io_uring O_DIRECT on a block device (Linux io_uring/rw.c with
//! block/fops.c __blkdev_direct_IO_async), on vda3's pattern words
//! (tools/mkdisk.sh):
//! - IO_URING_DIO_ASYNC: 512 4 KiB reads in one io_uring_enter (more
//!   than the device's queue depth, so some go to io-wq workers) come
//!   back with the pattern
//! - IO_URING_DIO_WRITE: 16 64 KiB writes; a READV reads them back; the
//!   pattern is put back
//! - IO_URING_DIO_CUR_POS: offset -1 reads at the file position, which a
//!   request that went asynchronous does not move (Linux kiocb_done:
//!   REQ_F_CUR_POS only for an inline completion)
//! - IO_URING_DIO_HIPRI: RWF_HIPRI on a ring without IORING_SETUP_IOPOLL
//!   is EINVAL (Linux io_rw_init_file: polled I/O only on an IOPOLL
//!   ring)
//! - IO_URING_DIO_FUTEX: a timed futex wait while O_DIRECT reads end
//!   (their completions are run by the waiting task) times out; it is
//!   not ended with EINTR (Linux restarts it: -ERESTART_RESTARTBLOCK)
//! - IO_URING_DIO_NONOWAIT (hk only: no USB disk on the Linux
//!   references): an O_DIRECT read of a disk that cannot honor
//!   IOCB_NOWAIT (sda, bio-based) goes to a worker and completes (Linux
//!   io_file_supports_nowait)
//!
//! Reads use vda3's untouched first 7 MiB; writes 13..14 MiB.

use super::{Ring, sqe};
use crate::harness::{R, check, report_r};
use crate::helpers::{BlkDev, find_blkdev, host_mode, skip};
use hk_syscall::{
    IORING_OP_READ, IORING_OP_READV, IORING_OP_WRITE, IoVec, MAP_ANONYMOUS, MAP_PRIVATE, O_RDONLY,
    O_RDWR, PROT_READ, PROT_WRITE, SEEK_CUR, sys_close, sys_lseek, sys_mmap, sys_munmap, sys_open,
};

const O_DIRECT: u32 = hk_syscall::O_DIRECT;
const MIB: u64 = 1 << 20;
const WR: u64 = 13 * MIB;

pub fn run_tests() {
    let Some(p3) = find_blkdev(b"vd", 16384) else {
        report_r(b"IO_URING_DIO", check(b"no vda3", false, 0));
        return;
    };
    let cases: [(&[u8], fn(&BlkDev) -> R); 5] = [
        (b"IO_URING_DIO_ASYNC", async_reads),
        (b"IO_URING_DIO_WRITE", writes),
        (b"IO_URING_DIO_CUR_POS", cur_pos),
        (b"IO_URING_DIO_HIPRI", hipri),
        (b"IO_URING_DIO_FUTEX", futex),
    ];
    for (name, t) in cases {
        report_r(name, t(&p3));
    }
    if host_mode() {
        skip(b"IO_URING_DIO_NONOWAIT", b"no USB disk (/dev/sda) on host");
    } else {
        report_r(b"IO_URING_DIO_NONOWAIT", nonowait());
    }
}

/// Pattern byte of vda3 at `off`
pub fn pat(off: u64) -> u8 {
    let w = ((off / 4) as u32)
        .wrapping_mul(1103515245)
        .wrapping_add(12345);
    w.to_le_bytes()[(off % 4) as usize]
}

/// Anonymous page-aligned memory, unmapped when dropped
pub struct Buf {
    pub p: *mut u8,
    pub len: usize,
}

impl Buf {
    pub fn new(len: usize) -> Result<Self, (&'static [u8], i64)> {
        let p = sys_mmap(
            0,
            len as u64,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        check(b"mmap", p > 0, p)?;
        Ok(Self {
            p: p as *mut u8,
            len,
        })
    }

    pub fn bytes(&self, off: usize, n: usize) -> &mut [u8] {
        assert!(off + n <= self.len);
        // SAFETY: inside the live mapping
        unsafe { core::slice::from_raw_parts_mut(self.p.add(off), n) }
    }

    pub fn addr(&self, off: usize) -> u64 {
        self.p as u64 + off as u64
    }
}

impl Drop for Buf {
    fn drop(&mut self) {
        sys_munmap(self.p as u64, self.len as u64);
    }
}

/// `s` holds the pattern of device offset `dev`..
pub fn is_pat(s: &[u8], dev: u64) -> bool {
    s.iter().enumerate().all(|(i, &b)| b == pat(dev + i as u64))
}

/// vda3 opened with `flags`
pub fn open(d: &BlkDev, flags: u32) -> Result<i32, (&'static [u8], i64)> {
    let mut path = [0u8; 48];
    let fd = sys_open(d.path(&mut path).as_ptr(), flags, 0);
    check(b"open vda3", fd >= 0, fd)?;
    Ok(fd as i32)
}

/// Run `f` on vda3 opened with `flags`, then close it
fn with_fd(d: &BlkDev, flags: u32, f: impl FnOnce(i32) -> R) -> R {
    let fd = open(d, flags)?;
    let r = f(fd);
    sys_close(fd as u64);
    r
}

/// Submit `submit` queued SQEs and reap `n` CQEs (waiting for them),
/// checking each with `ok(user_data, res)`
fn reap(r: &Ring, submit: u32, n: u32, ok: &mut dyn FnMut(u64, i32) -> R) -> R {
    let w = r.submit_wait(submit, n);
    check(b"submit and wait", w == i64::from(submit), w)?;
    for _ in 0..n {
        let c = r.pop().ok_or((&b"missing cqe"[..], 0))?;
        ok(c.user_data, c.res)?;
    }
    Ok(())
}

fn async_reads(d: &BlkDev) -> R {
    with_fd(d, O_RDONLY | O_DIRECT, |fd| {
        const N: u32 = 512;
        let mut r = Ring::simple(N).map_err(|e| (&b"ring"[..], e))?;
        let b = Buf::new(N as usize * 4096)?;
        // Every other 4 KiB block of the first 4 MiB
        for i in 0..N {
            let off = u64::from(i) * 8192;
            r.push_at(
                sqe(
                    IORING_OP_READ,
                    fd,
                    b.addr(i as usize * 4096),
                    4096,
                    off,
                    u64::from(i),
                ),
                i,
            );
        }
        r.publish();
        let n = r.enter(N, 0, 0);
        check(b"submit", n == i64::from(N), n)?;
        reap(&r, 0, N, &mut |ud, res| {
            check(b"res", res == 4096, i64::from(res))?;
            check(
                b"data",
                is_pat(b.bytes(ud as usize * 4096, 4096), ud * 8192),
                ud as i64,
            )
        })
    })
}

/// Fill `s` with a byte pattern of its own (not vda3's)
fn mark(s: &mut [u8], seed: u8) {
    for (i, x) in s.iter_mut().enumerate() {
        *x = (i as u8).wrapping_mul(7).wrapping_add(seed);
    }
}

fn writes(d: &BlkDev) -> R {
    with_fd(d, O_RDWR | O_DIRECT, |fd| {
        const N: u32 = 16;
        const SZ: usize = 65536;
        let mut r = Ring::simple(N).map_err(|e| (&b"ring"[..], e))?;
        let b = Buf::new(N as usize * SZ)?;
        mark(b.bytes(0, N as usize * SZ), 3);
        for i in 0..N {
            let at = i as usize * SZ;
            let s = sqe(
                IORING_OP_WRITE,
                fd,
                b.addr(at),
                SZ as u32,
                WR + at as u64,
                u64::from(i),
            );
            r.push(s);
        }
        let n = r.enter(N, 0, 0);
        let w = reap(&r, 0, N, &mut |_, res| {
            check(b"write res", res == SZ as i32, i64::from(res))
        });
        let back = read_back(&mut r, fd, &b, N as usize * SZ);
        // Put the pattern back whatever happened
        let restore = put_pattern(&mut r, fd, &b, N as usize * SZ);
        check(b"submit", n == i64::from(N), n)?;
        w?;
        back?;
        restore
    })
}

/// READV the written range into the second half of a fresh buffer and
/// compare it with what was written
fn read_back(r: &mut Ring, fd: i32, b: &Buf, len: usize) -> R {
    let rb = Buf::new(len)?;
    let iov = [
        IoVec {
            iov_base: rb.p,
            iov_len: len / 2,
        },
        IoVec {
            iov_base: rb.addr(len / 2) as *mut u8,
            iov_len: len / 2,
        },
    ];
    r.push(sqe(IORING_OP_READV, fd, iov.as_ptr() as u64, 2, WR, 99));
    reap(r, 1, 1, &mut |_, res| {
        check(b"readv res", res == len as i32, i64::from(res))
    })?;
    check(b"read back", rb.bytes(0, len) == b.bytes(0, len), 0)
}

/// Write vda3's pattern back over the written range
fn put_pattern(r: &mut Ring, fd: i32, b: &Buf, len: usize) -> R {
    for (i, x) in b.bytes(0, len).iter_mut().enumerate() {
        *x = pat(WR + i as u64);
    }
    r.push(sqe(IORING_OP_WRITE, fd, b.addr(0), len as u32, WR, 7));
    reap(r, 1, 1, &mut |_, res| {
        check(b"restore res", res == len as i32, i64::from(res))
    })
}

fn cur_pos(d: &BlkDev) -> R {
    with_fd(d, O_RDONLY | O_DIRECT, |fd| {
        let mut r = Ring::simple(4).map_err(|e| (&b"ring"[..], e))?;
        let b = Buf::new(4096)?;
        let p = sys_lseek(fd, 65536, 0);
        check(b"lseek", p == 65536, p)?;
        r.push(sqe(IORING_OP_READ, fd, b.addr(0), 4096, u64::MAX, 1));
        let n = r.submit_wait(1, 1);
        check(b"enter", n == 1, n)?;
        let c = r.pop().ok_or((&b"no cqe"[..], 0))?;
        check(b"res", c.res == 4096, i64::from(c.res))?;
        check(b"data", is_pat(b.bytes(0, 4096), 65536), 0)?;
        let p = sys_lseek(fd, 0, SEEK_CUR);
        check(b"position", p == 65536, p)
    })
}

fn hipri(d: &BlkDev) -> R {
    with_fd(d, O_RDONLY | O_DIRECT, |fd| {
        let mut r = Ring::simple(4).map_err(|e| (&b"ring"[..], e))?;
        let b = Buf::new(4096)?;
        let mut s = sqe(IORING_OP_READ, fd, b.addr(0), 4096, 0, 1);
        // RWF_HIPRI
        s.op_flags = 1;
        r.push(s);
        let n = r.submit_wait(1, 1);
        check(b"enter", n == 1, n)?;
        let c = r.pop().ok_or((&b"no cqe"[..], 0))?;
        check(b"res", c.res == -22, i64::from(c.res))
    })
}

fn futex(d: &BlkDev) -> R {
    with_fd(d, O_RDONLY | O_DIRECT, |fd| {
        const N: u32 = 8;
        const SZ: usize = 1 << 20;
        let mut r = Ring::simple(N).map_err(|e| (&b"ring"[..], e))?;
        let b = Buf::new(N as usize * SZ)?;
        for i in 0..N {
            let at = i as usize * SZ;
            r.push(sqe(
                IORING_OP_READ,
                fd,
                b.addr(at),
                SZ as u32,
                at as u64 / 2,
                u64::from(i),
            ));
        }
        let n = r.enter(N, 0, 0);
        check(b"submit", n == i64::from(N), n)?;
        let word = 0u32;
        let ts = hk_syscall::Timespec {
            tv_sec: 0,
            tv_nsec: 200_000_000,
        };
        let w = hk_syscall::sys_futex(
            &word as *const u32 as *mut u32,
            hk_syscall::FUTEX_WAIT,
            0,
            &ts,
            core::ptr::null_mut(),
            0,
        );
        reap(&r, 0, N, &mut |_, res| {
            check(b"read", res == SZ as i32, i64::from(res))
        })?;
        // ETIMEDOUT, not EINTR
        check(b"futex wait", w == -110, w)
    })
}

fn nonowait() -> R {
    let fd = sys_open(b"/dev/sda\0".as_ptr(), O_RDONLY | O_DIRECT, 0);
    check(b"open sda", fd >= 0, fd)?;
    let fd = fd as i32;
    let r = (|| {
        let mut r = Ring::simple(4).map_err(|e| (&b"ring"[..], e))?;
        let b = Buf::new(4096)?;
        r.push(sqe(IORING_OP_READ, fd, b.addr(0), 4096, 0, 1));
        reap(&r, 1, 1, &mut |_, res| {
            check(b"res", res == 4096, i64::from(res))
        })
    })();
    sys_close(fd as u64);
    r
}
