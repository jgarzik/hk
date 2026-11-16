//! io_uring opens (Linux io_uring/openclose.c)
//!
//! - URING_OPENAT2: IORING_OP_OPENAT2 opens as openat2 does, its
//!   struct open_how at addr2 sized by len: shorter than the first
//!   version is EINVAL, unknown nonzero fields E2BIG, a struct longer
//!   than a page with a zero tail is fine (no openat2 page limit);
//!   RESOLVE_NO_SYMLINKS refuses a symlink (ELOOP). Both opens refuse a
//!   buffer index (EINVAL), a registered file (EBADF) and a direct
//!   descriptor slot with O_CLOEXEC (EINVAL)

use super::{Ring, sqe};
use crate::harness::{R, check, report_r};
use hk_syscall::{AT_FDCWD, IORING_OP_OPENAT, IoUringSqe, O_RDONLY, sys_close};

const IORING_OP_OPENAT2: u8 = 28;
const IOSQE_FIXED_FILE: u8 = 1;
const O_CLOEXEC: u64 = 0o2000000;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const EBADF: i32 = -9;
const EINVAL: i32 = -22;
const E2BIG: i32 = -7;
const ELOOP: i32 = -40;
const NULL: &[u8] = b"/dev/null\0";

/// A struct open_how (flags, mode, resolve) with room past it, zeroed
#[repr(C, align(8))]
struct How([u64; 1024]);

static mut HOW: How = How([0; 1024]);

pub fn run_tests() {
    report_r(b"URING_OPENAT2", openat2());
}

/// One SQE through `r`: its CQE's result
fn run(r: &mut Ring, s: IoUringSqe) -> i32 {
    r.push(s);
    if r.submit_wait(1, 1) != 1 {
        return -1000;
    }
    r.pop().map_or(-1001, |c| c.res)
}

/// An OPENAT2 SQE for `path` with the open_how of `len` bytes
fn op2(path: &[u8], len: u32) -> IoUringSqe {
    // The kernel reads it during the call
    let how = core::ptr::addr_of!(HOW) as u64;
    sqe(
        IORING_OP_OPENAT2,
        AT_FDCWD,
        path.as_ptr() as u64,
        len,
        how,
        1,
    )
}

/// Set the open_how's flags, resolve and word `extra` (0: none) to `v`
fn set_how(flags: u64, resolve: u64, extra: usize, v: u64) {
    // SAFETY: single-threaded test, no call in progress
    let h = unsafe { &mut *core::ptr::addr_of_mut!(HOW) };
    h.0.fill(0);
    h.0[0] = flags;
    h.0[2] = resolve;
    if extra != 0 {
        h.0[extra] = v;
    }
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
    set_how(u64::from(O_RDONLY), 0, 0, 0);
    let fd = run(&mut r, op2(NULL, 24));
    check(b"open", opened(fd), i64::from(fd))?;
    let n = run(&mut r, op2(NULL, 8));
    check(b"short", n == EINVAL, i64::from(n))?;
    let fd = run(&mut r, op2(NULL, 8192));
    check(b"past a page", opened(fd), i64::from(fd))?;
    set_how(u64::from(O_RDONLY), 0, 3, 1);
    let n = run(&mut r, op2(NULL, 32));
    check(b"unknown field", n == E2BIG, i64::from(n))?;
    set_how(u64::from(O_RDONLY), RESOLVE_NO_SYMLINKS, 0, 0);
    let n = run(&mut r, op2(b"/proc/self/exe\0", 24));
    check(b"no symlinks", n == ELOOP, i64::from(n))?;
    set_how(u64::from(O_RDONLY), 0, 0, 0);
    let mut s = op2(NULL, 24);
    s.buf_index = 1;
    let n = run(&mut r, s);
    check(b"buf_index", n == EINVAL, i64::from(n))?;
    let mut s = sqe(IORING_OP_OPENAT, AT_FDCWD, NULL.as_ptr() as u64, 0, 0, 1);
    s.flags = IOSQE_FIXED_FILE;
    let n = run(&mut r, s);
    check(b"fixed file", n == EBADF, i64::from(n))?;
    let mut s = sqe(IORING_OP_OPENAT, AT_FDCWD, NULL.as_ptr() as u64, 0, 0, 1);
    s.op_flags = (u64::from(O_RDONLY) | O_CLOEXEC) as u32;
    s.splice_fd_in = 1;
    let n = run(&mut r, s);
    check(b"slot with cloexec", n == EINVAL, i64::from(n))
}
