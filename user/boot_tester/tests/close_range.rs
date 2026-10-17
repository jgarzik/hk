//! close_range(2) (Linux fs/file.c): closes, or marks close-on-exec,
//! the open descriptors of a range of any width; CLOSE_RANGE_UNSHARE
//! leaves a table shared through CLONE_FILES intact for the others

use super::helpers::{print, print_num, println};
use hk_syscall::{
    O_RDONLY, sys_clone, sys_close_range, sys_dup3, sys_exit, sys_fcntl, sys_open, sys_wait4,
};

const F_GETFD: i32 = 1;
const FD_CLOEXEC: i64 = 1;
const CLONE_FILES: u64 = 0x400;
const SIGCHLD: u64 = 17;
const UNSHARE: u32 = 1 << 1;
const CLOEXEC: u32 = 1 << 2;
const EINVAL: i64 = -22;
const EBADF: i64 = -9;

pub fn run_tests() {
    let base = sys_open(b"/\0".as_ptr(), O_RDONLY, 0) as i32;
    if base < 0 {
        verdict(b"CLOSE_RANGE_OPEN", false, base as i64);
        return;
    }
    einval();
    basic(base);
    huge(base);
    cloexec(base);
    unshare(base, true);
    unshare(base, false);
    sys_close_range(base as u32, base as u32, 0);
}

fn verdict(name: &[u8], ok: bool, got: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL got ");
        print_num(got);
        println(b"");
    }
}

/// Is `fd` open? (F_GETFD is EBADF on a closed one)
fn open(fd: i32) -> bool {
    sys_fcntl(fd, F_GETFD, 0) >= 0
}

/// Install `base` at each of `fds`
fn dups(base: i32, fds: &[i32]) {
    for &fd in fds {
        sys_dup3(base, fd, 0);
    }
}

/// Unknown flags and fd > max_fd are EINVAL
fn einval() {
    let a = sys_close_range(0, 10, 1 << 0);
    let b = sys_close_range(0, 10, 1 << 3);
    let c = sys_close_range(11, 10, 0);
    let ok = a == EINVAL && b == EINVAL && c == EINVAL;
    let got = if a != EINVAL { a } else if b != EINVAL { b } else { c };
    verdict(b"CLOSE_RANGE_EINVAL", ok, got);
}

/// Exactly the descriptors inside the range are closed
fn basic(base: i32) {
    dups(base, &[100, 101, 102, 103]);
    let r = sys_close_range(101, 102, 0);
    let ok = r == 0 && open(100) && !open(101) && !open(102) && open(103);
    verdict(b"CLOSE_RANGE_BASIC", ok, r);
    sys_close_range(100, 103, 0);
    // A range with nothing open is fine
    let r = sys_close_range(100, 103, 0);
    verdict(b"CLOSE_RANGE_EMPTY", r == 0, r);
}

/// Ranges up to ~0U close everything above `lo` at once (a loop over
/// the whole range would take minutes)
fn huge(base: i32) {
    dups(base, &[200, 300, 1000]);
    let r = sys_close_range(300, u32::MAX, 0);
    let ok = r == 0 && open(200) && !open(300) && !open(1000);
    verdict(b"CLOSE_RANGE_HUGE", ok, r);
    let r = sys_close_range(0x8000_0000, u32::MAX, 0);
    verdict(b"CLOSE_RANGE_ABOVE_INT_MAX", r == 0 && open(200), r);
    sys_close_range(200, 200, 0);
}

/// CLOSE_RANGE_CLOEXEC marks without closing
fn cloexec(base: i32) {
    dups(base, &[110, 111]);
    let r = sys_close_range(110, u32::MAX, CLOEXEC);
    let a = sys_fcntl(110, F_GETFD, 0);
    let b = sys_fcntl(111, F_GETFD, 0);
    let c = sys_fcntl(base, F_GETFD, 0);
    let ok = r == 0 && a == FD_CLOEXEC && b == FD_CLOEXEC && c == 0;
    let got = if r != 0 { r } else { a * 100 + b * 10 + c };
    verdict(b"CLOSE_RANGE_CLOEXEC", ok, got);
    sys_close_range(110, 111, 0);
}

/// A CLONE_FILES child closes fd 120: with UNSHARE only in its own
/// copy, without it in the shared table too
fn unshare(base: i32, private: bool) {
    dups(base, &[120]);
    let pid = sys_clone(CLONE_FILES | SIGCHLD, 0, 0, 0, 0);
    if pid == 0 {
        let flags = if private { UNSHARE } else { 0 };
        let r = sys_close_range(120, 120, flags);
        sys_exit(if r == 0 && !open(120) { 0 } else { 1 });
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    let mine = sys_fcntl(120, F_GETFD, 0);
    let (name, ok): (&[u8], bool) = if private {
        (b"CLOSE_RANGE_UNSHARE", st == 0 && mine == 0)
    } else {
        (b"CLOSE_RANGE_SHARED", st == 0 && mine == EBADF)
    };
    verdict(name, ok, (st as i64) * 1000 + mine);
    sys_close_range(120, 120, 0);
}
