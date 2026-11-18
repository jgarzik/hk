//! io_uring opens (Linux io_uring/openclose.c)
//!
//! - URING_OPENAT2: IORING_OP_OPENAT2 opens as openat2 does, its
//!   struct open_how at addr2 sized by len: shorter than the first
//!   version is EINVAL, unknown nonzero fields E2BIG, a struct longer
//!   than a page with a zero tail is fine (no openat2 page limit);
//!   RESOLVE_NO_SYMLINKS refuses a symlink (ELOOP). Both opens refuse a
//!   buffer index (EINVAL), a registered file (EBADF) and a direct
//!   descriptor slot with O_CLOEXEC (EINVAL)
//! - URING_OPEN_BATCH: a request failing its submission checks ends the
//!   batch (enter counts it, the next SQE stays queued); inside a chain
//!   it fails the chain (its own error, ECANCELED for the rest) and the
//!   batch goes on (Linux io_submit_fail_init); a batch ending inside a
//!   chain still runs (or fails) it
//! - URING_OPEN_DIRECT: an open into a registered slot (file_index):
//!   ENXIO with no table (ENFILE to allocate one); slot N installs there
//!   (0), EINVAL past the
//!   table, IORING_FILE_INDEX_ALLOC takes the next free slot and returns
//!   it, ENFILE once none is free (Linux io_fixed_fd_install); also as
//!   a chain member run within io_uring_enter

use super::{Ring, sqe};
use crate::harness::{R, check, report_r};
use hk_syscall::{
    AT_FDCWD, IORING_ENTER_GETEVENTS, IORING_OP_ASYNC_CANCEL, IORING_OP_NOP, IORING_OP_OPENAT,
    IORING_OP_OPENAT2, IORING_REGISTER_FILES, IOSQE_FIXED_FILE, IOSQE_IO_HARDLINK, IOSQE_IO_LINK,
    IoUringSqe, O_CLOEXEC, O_RDONLY, sys_close, sys_io_uring_register,
};

const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const ENOENT: i32 = -2;
const ENXIO: i32 = -6;
const E2BIG: i32 = -7;
const EBADF: i32 = -9;
const EINVAL: i32 = -22;
const ENFILE: i32 = -23;
const ELOOP: i32 = -40;
const ECANCELED: i32 = -125;
/// IORING_FILE_INDEX_ALLOC (~0U)
const FILE_INDEX_ALLOC: i32 = -1;
const NULL: &[u8] = b"/dev/null\0";

/// A struct open_how (flags, mode, resolve) with room past it
#[repr(C, align(8))]
struct How([u64; 1024]);

impl How {
    /// Flags, resolve and word `extra` (0: none) set to `v`, the rest 0
    fn new(flags: u32, resolve: u64, extra: usize, v: u64) -> Self {
        let mut h = How([0; 1024]);
        h.0[0] = u64::from(flags);
        h.0[2] = resolve;
        if extra != 0 {
            h.0[extra] = v;
        }
        h
    }

    /// An OPENAT2 SQE for `path` with this open_how of `len` bytes
    fn sqe(&self, path: &[u8], len: u32, ud: u64) -> IoUringSqe {
        let how = self.0.as_ptr() as u64;
        sqe(
            IORING_OP_OPENAT2,
            AT_FDCWD,
            path.as_ptr() as u64,
            len,
            how,
            ud,
        )
    }
}

pub fn run_tests() {
    report_r(b"URING_OPENAT2", openat2());
    report_r(b"URING_OPEN_BATCH", batch());
    report_r(b"URING_OPEN_DIRECT", direct());
}

/// One SQE through `r`: its CQE's result
fn run(r: &mut Ring, s: IoUringSqe) -> i32 {
    r.push(s);
    if r.submit_wait(1, 1) != 1 {
        return -1000;
    }
    r.pop().map_or(-1001, |c| c.res)
}

/// Wait for and take `n` (at most 4) CQEs: their (user_data, res)
fn reap(r: &Ring, n: u32) -> [(u64, i32); 4] {
    let mut out = [(0u64, 0i32); 4];
    if r.enter(0, n, IORING_ENTER_GETEVENTS) < 0 {
        return out;
    }
    for o in out.iter_mut().take(n as usize) {
        if let Some(c) = r.pop() {
            *o = (c.user_data, c.res);
        }
    }
    out
}

/// A result that is a descriptor is closed: whether it was one
fn opened(fd: i32) -> bool {
    if fd >= 0 {
        sys_close(fd as u64);
    }
    fd >= 0
}

fn openat2() -> R {
    let mut r = Ring::simple(4).map_err(|e| (&b"setup"[..], e))?;
    let plain = How::new(O_RDONLY, 0, 0, 0);
    let fd = run(&mut r, plain.sqe(NULL, 24, 1));
    check(b"open", opened(fd), i64::from(fd))?;
    let n = run(&mut r, plain.sqe(NULL, 8, 1));
    check(b"short", n == EINVAL, i64::from(n))?;
    let fd = run(&mut r, plain.sqe(NULL, 8192, 1));
    check(b"past a page", opened(fd), i64::from(fd))?;
    let n = run(&mut r, How::new(O_RDONLY, 0, 3, 1).sqe(NULL, 32, 1));
    check(b"unknown field", n == E2BIG, i64::from(n))?;
    let nosym = How::new(O_RDONLY, RESOLVE_NO_SYMLINKS, 0, 0);
    let n = run(&mut r, nosym.sqe(b"/proc/self/exe\0", 24, 1));
    check(b"no symlinks", n == ELOOP, i64::from(n))?;
    let mut s = plain.sqe(NULL, 24, 1);
    s.buf_index = 1;
    let n = run(&mut r, s);
    check(b"buf_index", n == EINVAL, i64::from(n))?;
    let mut s = sqe(IORING_OP_OPENAT, AT_FDCWD, NULL.as_ptr() as u64, 0, 0, 1);
    s.flags = IOSQE_FIXED_FILE;
    let n = run(&mut r, s);
    check(b"fixed file", n == EBADF, i64::from(n))?;
    let mut s = sqe(IORING_OP_OPENAT, AT_FDCWD, NULL.as_ptr() as u64, 0, 0, 1);
    s.op_flags = O_RDONLY | O_CLOEXEC;
    s.splice_fd_in = 1;
    let n = run(&mut r, s);
    check(b"slot with cloexec", n == EINVAL, i64::from(n))
}

fn batch() -> R {
    let mut r = Ring::simple(8).map_err(|e| (&b"setup"[..], e))?;
    let plain = How::new(O_RDONLY, 0, 0, 0);
    // A bad OPENAT2 then a NOP: one consumed, the NOP left queued
    r.push(plain.sqe(NULL, 8, 1));
    r.push(sqe(IORING_OP_NOP, 0, 0, 0, 0, 2));
    let n = r.enter(2, 0, 0);
    check(b"batch ends", n == 1, n)?;
    let c = reap(&r, 1);
    check(b"bad res", c[0] == (1, EINVAL), i64::from(c[0].1))?;
    let n = r.enter(1, 0, 0);
    check(b"nop next", n == 1, n)?;
    let c = reap(&r, 1);
    check(b"nop res", c[0] == (2, 0), i64::from(c[0].1))?;
    // A chain [NOP, bad OPENAT2, NOP] then a NOP: all four consumed
    let mut a = sqe(IORING_OP_NOP, 0, 0, 0, 0, 3);
    a.flags = IOSQE_IO_LINK;
    let mut b = plain.sqe(NULL, 8, 4);
    b.flags = IOSQE_IO_LINK;
    r.push(a);
    r.push(b);
    r.push(sqe(IORING_OP_NOP, 0, 0, 0, 0, 5));
    r.push(sqe(IORING_OP_NOP, 0, 0, 0, 0, 6));
    let n = r.enter(4, 0, 0);
    check(b"chain consumed", n == 4, n)?;
    let mut c = reap(&r, 4);
    c.sort_unstable();
    let want = [(3, ECANCELED), (4, EINVAL), (5, ECANCELED), (6, 0)];
    check(b"chain res", c == want, i64::from(c[1].1))?;
    // A batch ending inside a chain queues it as it is (Linux
    // io_submit_state_end): runs if whole, fails if a member failed
    let mut a = sqe(IORING_OP_NOP, 0, 0, 0, 0, 9);
    a.flags = IOSQE_IO_LINK;
    r.push(a);
    let n = r.enter(1, 0, 0);
    check(b"open chain", n == 1, n)?;
    let c = reap(&r, 1);
    check(b"open chain res", c[0] == (9, 0), i64::from(c[0].1))?;
    let mut a = sqe(IORING_OP_NOP, 0, 0, 0, 0, 10);
    a.flags = IOSQE_IO_LINK;
    let mut b = plain.sqe(NULL, 8, 11);
    b.flags = IOSQE_IO_LINK;
    r.push(a);
    r.push(b);
    let n = r.enter(2, 0, 0);
    check(b"failed open chain", n == 2, n)?;
    let mut c = reap(&r, 2);
    c[..2].sort_unstable();
    check(
        b"failed chain res",
        c[..2] == [(10, ECANCELED), (11, EINVAL)],
        i64::from(c[0].1),
    )
}

/// An OPENAT of /dev/null into `slot`
fn direct_open(r: &mut Ring, slot: i32) -> i32 {
    let mut s = sqe(IORING_OP_OPENAT, AT_FDCWD, NULL.as_ptr() as u64, 0, 0, 1);
    s.op_flags = O_RDONLY;
    s.splice_fd_in = slot;
    run(r, s)
}

fn direct() -> R {
    let mut r = Ring::simple(4).map_err(|e| (&b"setup"[..], e))?;
    let n = direct_open(&mut r, 1);
    check(b"no table", n == ENXIO, i64::from(n))?;
    let n = direct_open(&mut r, FILE_INDEX_ALLOC);
    check(b"alloc no table", n == ENFILE, i64::from(n))?;
    let empty = [-1i32; 2];
    let n = sys_io_uring_register(r.fd as u32, IORING_REGISTER_FILES, empty.as_ptr() as u64, 2);
    check(b"register", n == 0, n)?;
    let n = direct_open(&mut r, 1);
    check(b"slot 1", n == 0, i64::from(n))?;
    let n = direct_open(&mut r, 3);
    check(b"past table", n == EINVAL, i64::from(n))?;
    let n = direct_open(&mut r, FILE_INDEX_ALLOC);
    check(b"alloc", n == 1, i64::from(n))?;
    let n = direct_open(&mut r, FILE_INDEX_ALLOC);
    check(b"full", n == ENFILE, i64::from(n))?;
    direct_chain()
}

/// A hard-linked chain [ASYNC_CANCEL of nothing, direct open]: the
/// cancel's chain runs in io_uring_enter, the open installs in slot 0
fn direct_chain() -> R {
    let mut r = Ring::simple(4).map_err(|e| (&b"setup"[..], e))?;
    let empty = [-1i32; 2];
    let n = sys_io_uring_register(r.fd as u32, IORING_REGISTER_FILES, empty.as_ptr() as u64, 2);
    check(b"register", n == 0, n)?;
    let mut c = sqe(IORING_OP_ASYNC_CANCEL, -1, 0x5eed, 0, 0, 7);
    c.flags = IOSQE_IO_HARDLINK;
    let mut o = sqe(IORING_OP_OPENAT, AT_FDCWD, NULL.as_ptr() as u64, 0, 0, 8);
    o.op_flags = O_RDONLY;
    o.splice_fd_in = FILE_INDEX_ALLOC;
    r.push(c);
    r.push(o);
    let n = r.enter(2, 0, 0);
    check(b"chain submitted", n == 2, n)?;
    let mut got = reap(&r, 2);
    got[..2].sort_unstable();
    check(b"cancel", got[0] == (7, ENOENT), i64::from(got[0].1))?;
    check(b"chain open", got[1] == (8, 0), i64::from(got[1].1))
}
