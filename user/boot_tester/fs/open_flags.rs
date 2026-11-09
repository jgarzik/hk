//! What an open file's flags say (Linux build_open_how,
//! build_open_flags, do_dentry_open, fcntl F_GETFL, fs/proc/fd.c):
//! unknown open flags are dropped, 64-bit opens add O_LARGEFILE,
//! __O_SYNC brings O_DSYNC, and O_CREAT, O_EXCL, O_NOCTTY, O_TRUNC and
//! O_CLOEXEC steer only the open (fdinfo adds O_CLOEXEC from the
//! descriptor)

use crate::fs::mountinfo::{field, octal, slurp_pub};
use crate::harness::{R, check, report_r};
use hk_syscall::{
    O_CLOEXEC, O_CREAT, O_EXCL, O_LARGEFILE, O_RDWR, O_TRUNC, O_WRONLY, sys_close, sys_fcntl,
    sys_open, sys_unlink,
};

const F_GETFL: i32 = 3;
const O_NOCTTY: u32 = 0o400;
const O_DSYNC: u32 = 0o10000;
const __O_SYNC: u32 = 0o4000000;
/// A bit no arch gives a meaning
const O_UNKNOWN: u32 = 1 << 28;
const F: &[u8] = b"/tmp/oflags\0";

pub fn run_tests() {
    report_r(b"OPEN_FLAGS_GETFL", getfl());
    report_r(b"OPEN_FLAGS_SYNC", sync());
    sys_unlink(F.as_ptr());
}

/// fdinfo's flags of descriptor `fd`
pub fn fdinfo_flags(fd: i64) -> Option<u64> {
    let mut path = *b"/proc/self/fdinfo/\0\0\0\0\0";
    let mut d = [0u8; 5];
    let (mut v, mut k) = (fd as u32, 0);
    loop {
        d[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 || k == d.len() {
            break;
        }
    }
    for i in 0..k {
        path[18 + i] = d[k - 1 - i];
    }
    let mut buf = [0u8; 512];
    let n = slurp_pub(&path, &mut buf);
    field(&buf[..n], b"flags").and_then(octal)
}

/// Every open-only flag and an unknown bit leave no trace in F_GETFL;
/// fdinfo shows the descriptor's O_CLOEXEC
fn getfl() -> R {
    sys_unlink(F.as_ptr());
    let fl = O_CREAT | O_EXCL | O_TRUNC | O_NOCTTY | O_CLOEXEC | O_RDWR | O_UNKNOWN;
    let fd = sys_open(F.as_ptr(), fl, 0o644);
    check(b"open", fd >= 0, fd)?;
    let got = sys_fcntl(fd as i32, F_GETFL, 0);
    let info = fdinfo_flags(fd);
    sys_close(fd as u64);
    check(b"F_GETFL", got == i64::from(O_RDWR | O_LARGEFILE), got)?;
    let want = u64::from(O_RDWR | O_LARGEFILE | O_CLOEXEC);
    check(b"fdinfo", info == Some(want), info.map_or(-1, |v| v as i64))
}

/// __O_SYNC alone is O_SYNC: O_DSYNC is set with it
fn sync() -> R {
    let fd = sys_open(F.as_ptr(), O_WRONLY | __O_SYNC, 0);
    check(b"open", fd >= 0, fd)?;
    let got = sys_fcntl(fd as i32, F_GETFL, 0);
    sys_close(fd as u64);
    let want = i64::from(O_WRONLY | O_LARGEFILE | __O_SYNC | O_DSYNC);
    check(b"F_GETFL", got == want, got)
}
