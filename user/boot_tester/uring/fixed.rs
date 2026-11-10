//! Registered buffers (Linux io_uring/rsrc.c io_sqe_buffers_register,
//! io_import_reg_buf; rw.c io_read_fixed / io_write_fixed):
//! - IO_URING_FIXED_RW: READ_FIXED and WRITE_FIXED of O_DIRECT vda3
//!   through ranges of registered buffers (a sparse slot between them);
//!   the pattern is put back
//! - IO_URING_FIXED_EFAULT: a range outside its buffer, an empty slot or
//!   an index past the table completes with EFAULT
//! - IO_URING_REG_BUFFERS: registering twice is EBUSY, none EINVAL, a
//!   buffer past 1 GiB or a null one with a length EFAULT; unregistering
//!   with none is ENXIO
//! - IO_URING_MEMLOCK: without CAP_IPC_LOCK the pinned pages count
//!   against RLIMIT_MEMLOCK (ENOMEM past it)
//! - IO_URING_MEMLOCK_NTH (hk only: Linux 6.8 does not charge the
//!   rings, and its fail-nth needs CONFIG_FAULT_INJECTION): a ring or a
//!   buffer whose setup fails at any allocation gives back exactly what
//!   it charged, so the limit still holds afterwards

use super::dio::{Buf, is_pat, open, pat};
use super::{Ring, sqe};
use crate::harness::{R, check, report_code, report_r};
use crate::helpers::{BlkDev, find_blkdev, host_mode, skip};
use crate::io::fault_inject::{get, set};
use hk_syscall::{
    IORING_OP_READ_FIXED, IORING_OP_WRITE_FIXED, IORING_REGISTER_BUFFERS,
    IORING_UNREGISTER_BUFFERS, IoUringParams, IoVec, O_RDWR, RLIMIT_MEMLOCK, RLimit, sys_close,
    sys_exit, sys_fork, sys_io_uring_register, sys_io_uring_setup, sys_open, sys_setrlimit,
    sys_wait4,
};

const O_DIRECT: u32 = hk_syscall::O_DIRECT;
const EBUSY: i64 = -16;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOMEM: i64 = -12;
const ENXIO: i64 = -6;
const SZ: usize = 65536;
/// Written and put back (14 MiB of vda3)
const WR: u64 = 14 << 20;

pub fn run_tests() {
    match find_blkdev(b"vd", 16384) {
        Some(p3) => report_r(b"IO_URING_FIXED_RW", fixed_rw(&p3)),
        None => report_r(b"IO_URING_FIXED_RW", check(b"no vda3", false, 0)),
    }
    report_r(b"IO_URING_FIXED_EFAULT", efault());
    report_r(b"IO_URING_REG_BUFFERS", reg_errors());
    memlock();
    if host_mode() {
        skip(
            b"IO_URING_MEMLOCK_NTH",
            b"rings uncharged before Linux 6.13; fail-nth",
        );
    } else {
        child(b"IO_URING_MEMLOCK_NTH", memlock_failnth_child);
    }
}

fn register(r: &Ring, iov: &[IoVec]) -> i64 {
    sys_io_uring_register(
        r.fd as u32,
        IORING_REGISTER_BUFFERS,
        iov.as_ptr() as u64,
        iov.len() as u32,
    )
}

fn iov(base: u64, len: usize) -> IoVec {
    IoVec {
        iov_base: base as *mut u8,
        iov_len: len,
    }
}

/// Run `sqe` alone, its result
fn one(r: &mut Ring, s: hk_syscall::IoUringSqe) -> Result<i32, (&'static [u8], i64)> {
    r.push(s);
    let n = r.submit_wait(1, 1);
    check(b"enter", n == 1, n)?;
    Ok(r.pop().ok_or((&b"no cqe"[..], 0))?.res)
}

/// A ring with buffers 0 and 2 of `b`'s halves registered, 1 sparse
fn ring_with(b: &Buf) -> Result<Ring, (&'static [u8], i64)> {
    let r = Ring::simple(4).map_err(|e| (&b"ring"[..], e))?;
    let n = register(&r, &[iov(b.addr(0), SZ), iov(0, 0), iov(b.addr(SZ), SZ)]);
    check(b"register", n == 0, n)?;
    Ok(r)
}

fn fixed_rw(d: &BlkDev) -> R {
    let fd = open(d, O_RDWR | O_DIRECT)?;
    let r = fixed_rw_in(fd);
    sys_close(fd as u64);
    r
}

fn fixed_rw_in(fd: i32) -> R {
    let b = Buf::new(2 * SZ)?;
    let mut r = ring_with(&b)?;
    let rd = sqe(IORING_OP_READ_FIXED, fd, b.addr(4096), 8192, 1 << 20, 1);
    let n = one(&mut r, rd)?;
    check(b"read res", n == 8192, i64::from(n))?;
    check(b"read data", is_pat(b.bytes(4096, 8192), 1 << 20), 0)?;
    for (i, x) in b.bytes(SZ, 16384).iter_mut().enumerate() {
        *x = (i as u8).wrapping_mul(13).wrapping_add(5);
    }
    let mut wr = sqe(IORING_OP_WRITE_FIXED, fd, b.addr(SZ), 16384, WR, 2);
    wr.buf_index = 2;
    let w = one(&mut r, wr);
    let back = sqe(IORING_OP_READ_FIXED, fd, b.addr(0), 16384, WR, 3);
    let rb = one(&mut r, back);
    let same = b.bytes(0, 16384) == b.bytes(SZ, 16384);
    // Put the pattern back whatever happened
    for (i, x) in b.bytes(SZ, 16384).iter_mut().enumerate() {
        *x = pat(WR + i as u64);
    }
    let restore = one(&mut r, wr);
    check(b"write res", w? == 16384, 0)?;
    check(b"read back res", rb? == 16384, 0)?;
    check(b"read back data", same, 0)?;
    check(b"restore", restore? == 16384, 0)
}

fn efault() -> R {
    let b = Buf::new(2 * SZ)?;
    let mut r = ring_with(&b)?;
    // Placed by index, never touching a device: any fd will do
    let mut s = sqe(IORING_OP_READ_FIXED, 0, b.addr(SZ - 100), 4096, 0, 1);
    let n = one(&mut r, s)?;
    check(b"past the end", i64::from(n) == EFAULT, i64::from(n))?;
    s.addr = b.addr(SZ);
    s.buf_index = 1;
    let n = one(&mut r, s)?;
    check(b"empty slot", i64::from(n) == EFAULT, i64::from(n))?;
    s.buf_index = 5;
    let n = one(&mut r, s)?;
    check(b"past the table", i64::from(n) == EFAULT, i64::from(n))
}

fn reg_errors() -> R {
    let b = Buf::new(SZ)?;
    let r = Ring::simple(4).map_err(|e| (&b"ring"[..], e))?;
    let n = register(&r, &[]);
    check(b"none", n == EINVAL, n)?;
    let n = register(&r, &[iov(b.addr(0), 1 << 31)]);
    check(b"past 1 GiB", n == EFAULT, n)?;
    let n = register(&r, &[iov(0, 4096)]);
    check(b"null base", n == EFAULT, n)?;
    let n = register(&r, &[iov(b.addr(0), SZ)]);
    check(b"register", n == 0, n)?;
    let n = register(&r, &[iov(b.addr(0), SZ)]);
    check(b"twice", n == EBUSY, n)?;
    let unreg = || sys_io_uring_register(r.fd as u32, IORING_UNREGISTER_BUFFERS, 0, 0);
    let n = unreg();
    check(b"unregister", n == 0, n)?;
    let n = unreg();
    check(b"unregister none", n == ENXIO, n)
}

/// In a child: no capabilities, RLIMIT_MEMLOCK 64 KiB; a 256 KiB buffer
/// is ENOMEM, a 16 KiB one fits
fn memlock_child() -> i64 {
    let Ok(b) = Buf::new(4 * SZ) else { return 1 };
    let lim = RLimit {
        rlim_cur: SZ as u64,
        rlim_max: SZ as u64,
    };
    if !crate::net::netlink::drop_caps() || sys_setrlimit(RLIMIT_MEMLOCK, &lim) != 0 {
        return 2;
    }
    let Ok(r) = Ring::simple(4) else { return 3 };
    if register(&r, &[iov(b.addr(0), 4 * SZ)]) != ENOMEM {
        return 4;
    }
    if register(&r, &[iov(b.addr(0), 16384)]) != 0 {
        return 5;
    }
    0
}

fn memlock() {
    child(b"IO_URING_MEMLOCK", memlock_child);
}

/// Run `f` in a child; report its exit code as `name`
fn child(name: &[u8], f: fn() -> i64) {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(f() as u64);
    }
    let mut st = 0;
    let w = sys_wait4(pid, &mut st, 0, 0);
    let code = if pid < 0 || w != pid {
        -1
    } else {
        i64::from((st >> 8) & 0xff)
    };
    report_code(name, code);
}

/// `call` with each of its allocations failing in turn (fail-nth),
/// until it runs past the last; `undo` releases what a success made.
/// False if fail-nth cannot be used
fn each_failure(call: &mut dyn FnMut() -> i64, undo: &mut dyn FnMut(i64)) -> bool {
    let fd = sys_open(b"/proc/self/fail-nth\0".as_ptr(), O_RDWR, 0);
    if fd < 0 {
        return false;
    }
    let fd = fd as i32;
    for nth in 1..64 {
        set(fd, nth);
        let r = call();
        let left = get(fd);
        set(fd, 0);
        if r >= 0 {
            undo(r);
        }
        if left != 0 {
            break;
        }
    }
    sys_close(fd as u64);
    true
}

/// In a child: no capabilities, RLIMIT_MEMLOCK four pages, a ring of
/// two pages charged. Rings and buffers made with each allocation
/// failing in turn give back what they charged: two pages are left
fn memlock_failnth_child() -> i64 {
    let Ok(b) = Buf::new(4 * 4096) else { return 1 };
    let lim = RLimit {
        rlim_cur: 4 * 4096,
        rlim_max: 4 * 4096,
    };
    if !crate::net::netlink::drop_caps() || sys_setrlimit(RLIMIT_MEMLOCK, &lim) != 0 {
        return 2;
    }
    let Ok(r) = Ring::simple(4) else { return 3 };
    let mut p = IoUringParams::default();
    if !each_failure(&mut || sys_io_uring_setup(4, &mut p), &mut |fd| {
        sys_close(fd as u64);
    }) {
        return 4;
    }
    // Two pages charged, two left: three more do not fit
    if register(&r, &[iov(b.addr(0), 3 * 4096)]) != ENOMEM {
        return 5;
    }
    let mut unreg = |_: i64| {
        sys_io_uring_register(r.fd as u32, IORING_UNREGISTER_BUFFERS, 0, 0);
    };
    each_failure(&mut || register(&r, &[iov(b.addr(0), 4096)]), &mut unreg);
    if register(&r, &[iov(b.addr(0), 3 * 4096)]) != ENOMEM {
        return 6;
    }
    if register(&r, &[iov(b.addr(0), 4096)]) != 0 {
        return 7;
    }
    0
}
