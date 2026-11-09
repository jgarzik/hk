//! O_EMPTYPATH (Linux 7.2, 31cf44efa6df: LOOKUP_EMPTY for open, openat
//! and openat2; cases from tools/testing/selftests/filesystems/openat2/
//! emptypath_test.c), on a fresh ramfs on both kernels: an empty path is
//! ENOENT without the flag; with it the open names dirfd's own file, so
//! an O_PATH descriptor reopens for I/O with may_open checked again, and
//! the flag stays in f_flags (O_PATH keeps it too). Before 7.2 an empty
//! path stays ENOENT with the bit (openat2 refuses it as unknown on
//! kernels where it is not __FMODE_NONOTIFY's).

use crate::harness::{R, check, report_r};
use crate::helpers::linux_at_least;
use hk_syscall::{
    O_CREAT, O_DIRECTORY, O_LARGEFILE, O_NOFOLLOW, O_PATH, O_RDONLY, O_WRONLY, sys_close, sys_exit,
    sys_fcntl, sys_fork, sys_mkdir, sys_mount, sys_open, sys_openat, sys_openat2, sys_read,
    sys_rmdir, sys_setuid, sys_symlink, sys_umount2, sys_unlink, sys_wait4, sys_write,
};

const ENOENT: i64 = -2;
const EACCES: i64 = -13;
const ENOTDIR: i64 = -20;
const EINVAL: i64 = -22;
const ELOOP: i64 = -40;
const O_EMPTYPATH: u32 = 1 << 26;
const F_GETFL: i32 = 3;

const DIR: &[u8] = b"/tmp/ep\0";
const F: &[u8] = b"/tmp/ep/f\0";
const S: &[u8] = b"/tmp/ep/s\0";

pub fn run_tests() {
    sys_mkdir(DIR.as_ptr(), 0o755);
    if sys_mount(b"none\0".as_ptr(), DIR.as_ptr(), b"ramfs\0".as_ptr(), 0, 0) != 0 {
        report_r(b"O_EMPTYPATH_MOUNT", Err((b"mount", -1)));
        return;
    }
    let fd = sys_open(F.as_ptr(), O_CREAT | O_WRONLY, 0o600);
    sys_write(fd as u64, b"abc".as_ptr(), 3);
    sys_close(fd as u64);
    sys_symlink(b"f\0".as_ptr(), S.as_ptr());
    report_r(b"O_EMPTYPATH_ENOENT", without_flag());
    report_r(b"O_EMPTYPATH_REOPEN", reopen());
    report_r(b"O_EMPTYPATH_PERM", perm());
    report_r(b"O_EMPTYPATH_OPATH", opath());
    report_r(b"O_EMPTYPATH_OPENAT2", openat2());
    report_r(b"O_EMPTYPATH_CHECKS", checks());
    for p in [F, S] {
        sys_unlink(p.as_ptr());
    }
    sys_umount2(DIR.as_ptr(), 0);
    sys_rmdir(DIR.as_ptr());
}

/// openat(fd, "", flags), closing what opened: the result
fn reopen_ret(fd: i64, flags: u32) -> i64 {
    let r = sys_openat(fd as i32, b"\0".as_ptr(), flags, 0);
    if r >= 0 {
        sys_close(r as u64);
    }
    r
}

/// An O_PATH descriptor of `p` (O_NOFOLLOW: a symlink itself)
fn opath_fd(p: &[u8], nofollow: bool) -> Result<i64, (&'static [u8], i64)> {
    let extra = if nofollow { O_NOFOLLOW } else { 0 };
    let fd = sys_open(p.as_ptr(), O_PATH | extra, 0);
    check(b"O_PATH open", fd >= 0, fd)?;
    Ok(fd)
}

/// An empty path without the flag is ENOENT
fn without_flag() -> R {
    let fd = opath_fd(F, false)?;
    let r = reopen_ret(fd, O_RDONLY);
    sys_close(fd as u64);
    check(b"empty path", r == ENOENT, r)
}

/// The O_PATH descriptor reopens for reading: the file's data, and
/// O_EMPTYPATH in F_GETFL
fn reopen() -> R {
    let fd = opath_fd(F, false)?;
    let r = sys_openat(fd as i32, b"\0".as_ptr(), O_RDONLY | O_EMPTYPATH, 0);
    sys_close(fd as u64);
    if !linux_at_least(7, 2) {
        return check(b"before 7.2", r == ENOENT, r);
    }
    check(b"reopen", r >= 0, r)?;
    let mut b = [0u8; 4];
    let n = sys_read(r as u64, b.as_mut_ptr(), 4);
    let fl = sys_fcntl(r as i32, F_GETFL, 0);
    sys_close(r as u64);
    check(b"read", n == 3 && &b[..3] == b"abc", n)?;
    let want = i64::from(O_RDONLY | O_LARGEFILE | O_EMPTYPATH);
    check(b"F_GETFL", fl == want, fl)
}

/// may_open is checked again: nobody's O_PATH handle on root's 0600
/// file does not reopen for reading (EACCES)
fn perm() -> R {
    let pid = sys_fork();
    if pid == 0 {
        if sys_setuid(65534) != 0 {
            sys_exit(1);
        }
        let fd = sys_open(F.as_ptr(), O_PATH, 0);
        if fd < 0 {
            sys_exit(2);
        }
        let want = if linux_at_least(7, 2) { EACCES } else { ENOENT };
        sys_exit(if reopen_ret(fd, O_RDONLY | O_EMPTYPATH) == want {
            0
        } else {
            3
        });
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    check(b"child step", st == 0, i64::from(st >> 8))
}

/// O_PATH|O_EMPTYPATH keeps the flag (it is in O_PATH_FLAGS) and names
/// dirfd's file, a symlink itself included
fn opath() -> R {
    let fd = opath_fd(S, true)?;
    let r = sys_openat(fd as i32, b"\0".as_ptr(), O_PATH | O_EMPTYPATH, 0);
    sys_close(fd as u64);
    if !linux_at_least(7, 2) {
        return check(b"before 7.2", r == ENOENT, r);
    }
    check(b"O_PATH", r >= 0, r)?;
    let fl = sys_fcntl(r as i32, F_GETFL, 0);
    let mut b = [0u8; 4];
    let n = hk_syscall::sys_readlinkat(r as i32, b"\0".as_ptr(), b.as_mut_ptr(), 4);
    sys_close(r as u64);
    check(b"F_GETFL", fl == i64::from(O_PATH | O_EMPTYPATH), fl)?;
    check(b"the symlink", n == 1 && b[0] == b'f', n)
}

/// openat2 takes it too
fn openat2() -> R {
    let fd = opath_fd(F, false)?;
    let mut how = [0u8; 24];
    how[..8].copy_from_slice(&u64::from(O_RDONLY | O_EMPTYPATH).to_ne_bytes());
    let r = sys_openat2(fd as i32, b"\0".as_ptr(), how.as_ptr(), 24);
    sys_close(fd as u64);
    if r >= 0 {
        sys_close(r as u64);
    }
    // Before 7.2 the bit is unknown to openat2 (EINVAL), or, before
    // fanotify's FMODE_NONOTIFY left f_flags, that flag's (6.8 takes it:
    // the empty path is then ENOENT)
    if !linux_at_least(7, 2) {
        return check(b"before 7.2", r == EINVAL || r == ENOENT, r);
    }
    check(b"openat2", r >= 0, r)
}

/// The open's checks still apply to dirfd's file: O_DIRECTORY on a
/// file is ENOTDIR, a symlink opened for reading ELOOP
fn checks() -> R {
    let fd = opath_fd(F, false)?;
    let d = reopen_ret(fd, O_RDONLY | O_DIRECTORY | O_EMPTYPATH);
    sys_close(fd as u64);
    let fd = opath_fd(S, true)?;
    let l = reopen_ret(fd, O_RDONLY | O_EMPTYPATH);
    sys_close(fd as u64);
    if !linux_at_least(7, 2) {
        return check(b"before 7.2", d == ENOENT && l == ENOENT, d * 1000 + l);
    }
    check(b"O_DIRECTORY", d == ENOTDIR, d)?;
    check(b"symlink", l == ELOOP, l)
}
