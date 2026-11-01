//! execveat (Linux do_execveat_common): dirfd-relative paths, fexecve
//! through AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW, flag checks
//!
//! Tests (each child execs busybox `true`; exit 0 means it ran):
//! - EXECVEAT_FEXECVE: an empty path with AT_EMPTY_PATH runs dirfd's own
//!   file (glibc fexecve)
//! - EXECVEAT_DIRFD: a relative path is resolved from dirfd
//! - EXECVEAT_NOFOLLOW: a final symlink with AT_SYMLINK_NOFOLLOW is ELOOP
//! - EXECVEAT_EMPTY: an empty path without AT_EMPTY_PATH is ENOENT
//! - EXECVEAT_FLAGS: unknown flags are EINVAL
//! - EXECVEAT_ENOTDIR: a relative path from a non-directory dirfd is
//!   ENOTDIR
//! - EXECVEAT_NOEXEC_FD: fexecve of a file on a noexec mount is EACCES
//!   even when the fd came from another mount namespace (over
//!   SCM_RIGHTS), where the caller cannot see that mount

use super::helpers::{print, print_num, println};
use super::sk::recv_msg;
use super::unix::{got_fds, send_fds};
use hk_syscall::{
    AF_UNIX, CLONE_NEWNS, O_CREAT, O_DIRECTORY, O_RDONLY, O_WRONLY, SOCK_STREAM, sys_close,
    sys_execveat, sys_exit, sys_fork, sys_mkdir, sys_mount, sys_open, sys_socketpair,
    sys_unshare, sys_wait4, sys_write,
};

const AT_FDCWD: i32 = -100;
const AT_EMPTY_PATH: i32 = 0x1000;
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
const ENOENT: i64 = 2;
const ENOTDIR: i64 = 20;
const EINVAL: i64 = 22;
const ELOOP: i64 = 40;
const EACCES: i64 = 13;
const MS_NOEXEC: u64 = 8;

pub fn run_tests() {
    let bb = sys_open(b"/bin/busybox\0".as_ptr(), O_RDONLY, 0) as i32;
    let bin = sys_open(b"/bin\0".as_ptr(), O_RDONLY | O_DIRECTORY, 0) as i32;
    if bb < 0 || bin < 0 {
        report(b"EXECVEAT_FEXECVE", false, bb.min(bin) as i64);
        return;
    }
    check(b"EXECVEAT_FEXECVE", bb, b"\0", AT_EMPTY_PATH, 0);
    check(b"EXECVEAT_DIRFD", bin, b"busybox\0", 0, 0);
    check(
        b"EXECVEAT_NOFOLLOW",
        AT_FDCWD,
        b"/bin/true\0",
        AT_SYMLINK_NOFOLLOW,
        ELOOP,
    );
    check(b"EXECVEAT_EMPTY", bb, b"\0", 0, ENOENT);
    check(b"EXECVEAT_FLAGS", AT_FDCWD, b"/bin/busybox\0", 0x1, EINVAL);
    check(b"EXECVEAT_ENOTDIR", bb, b"busybox\0", 0, ENOTDIR);
    sys_close(bb as u64);
    sys_close(bin as u64);
    noexec_fd();
}

/// A child in its own mount namespace makes a file on a noexec ramfs
/// and sends its fd back; fexecve of that fd here must be EACCES
fn noexec_fd() {
    let name = b"EXECVEAT_NOEXEC_FD";
    let mut sv = [0i32; 2];
    if sys_socketpair(AF_UNIX, SOCK_STREAM, 0, &mut sv) != 0 {
        report(name, false, -1);
        return;
    }
    let pid = sys_fork();
    if pid == 0 {
        sys_close(sv[0] as u64);
        sys_exit(noexec_child(sv[1]));
    }
    sys_close(sv[1] as u64);
    let mut buf = [0u8; 8];
    let mut ctl = [0u8; 64];
    let (n, _, clen) = recv_msg(sv[0], &mut buf, &mut ctl, 0);
    let (fd, _) = got_fds(&ctl, clen);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    sys_close(sv[0] as u64);
    if n != 1 || fd < 0 {
        report(name, false, -100 - ((st >> 8) & 0xff) as i64);
        return;
    }
    check(name, fd, b"\0", AT_EMPTY_PATH, EACCES);
    sys_close(fd as u64);
}

/// Child of noexec_fd: exit status is the failed step (0 on success)
fn noexec_child(sock: i32) -> u64 {
    if sys_unshare(CLONE_NEWNS) != 0 {
        return 1;
    }
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    sys_mkdir(b"/tmp/nxfd\0".as_ptr(), 0o755);
    let mnt = sys_mount(
        b"none\0".as_ptr(),
        b"/tmp/nxfd\0".as_ptr(),
        b"ramfs\0".as_ptr(),
        MS_NOEXEC,
        0,
    );
    if mnt != 0 {
        return 2;
    }
    let path = b"/tmp/nxfd/prog\0";
    let w = sys_open(path.as_ptr(), O_CREAT | O_WRONLY, 0o755);
    if w < 0 || sys_write(w as u64, b"\x7fELF".as_ptr(), 4) != 4 {
        return 3;
    }
    sys_close(w as u64);
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 || send_fds(sock, b"x", &[fd as i32]) != 1 {
        return 4;
    }
    0
}

fn report(name: &[u8], ok: bool, detail: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL ");
        print_num(detail);
        println(b"");
    }
}

/// execveat(dirfd, path, flags) in a child; `errno` 0 means it must run
/// `true` (exit 0), else fail with that errno (the child exits with it)
fn check(name: &[u8], dirfd: i32, path: &[u8], flags: i32, errno: i64) {
    let pid = sys_fork();
    if pid == 0 {
        let argv = [b"true\0".as_ptr(), core::ptr::null()];
        let envp = [core::ptr::null()];
        let r = sys_execveat(dirfd, path.as_ptr(), argv.as_ptr(), envp.as_ptr(), flags);
        sys_exit((-r) as u64 & 0xff);
    }
    let mut st = 0i32;
    if pid < 0 || sys_wait4(pid, &mut st, 0, 0) != pid {
        report(name, false, pid);
        return;
    }
    let code = if st & 0x7f == 0 { (st >> 8) & 0xff } else { -1 };
    report(name, code as i64 == errno, code as i64);
}
