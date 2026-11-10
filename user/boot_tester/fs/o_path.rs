//! O_PATH descriptors (Linux do_o_path, do_dentry_open's FMODE_PATH
//! branch, fdget vs fdget_raw, check_fcntl_cmd, filp_flush,
//! tid_fd_update_inode), on a fresh ramfs on both kernels: the open
//! only looks the name up (no permission, no FIFO wait, a symlink with
//! O_NOFOLLOW is the link itself), the file takes no I/O (EBADF) but
//! serves fstat, fstatfs, fchdir, dup, SCM_RIGHTS and every *at() call
//! as dirfd or AT_EMPTY_PATH, and its close drops no POSIX lock

use crate::fs::open_flags::fdinfo_flags;
use crate::harness::{R, check, report_r};
use crate::helpers::{msleep, reap};
use crate::net::sk::recv_msg;
use crate::net::unix::{got_fds, send_fds};
use hk_syscall::{
    __O_TMPFILE, AF_UNIX, AT_FDCWD, EpollEvent, Flock, LinuxStatFs, O_CLOEXEC, O_CREAT,
    O_DIRECTORY, O_NOFOLLOW, O_PATH, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, PollFd, SOCK_STREAM,
    Stat, sys_close, sys_dup, sys_epoll_create1, sys_epoll_ctl, sys_execveat, sys_exit, sys_fchdir,
    sys_fchmod, sys_fchmodat2, sys_fchown, sys_fchownat, sys_fcntl, sys_fgetxattr, sys_flock,
    sys_fork, sys_fstat, sys_fstatat, sys_fstatfs, sys_fsync, sys_ftruncate, sys_getdents64,
    sys_ioctl, sys_linkat, sys_lseek, sys_lstat, sys_mkdir, sys_mknod, sys_mmap, sys_mount,
    sys_open, sys_openat, sys_poll, sys_read, sys_readlinkat, sys_rmdir, sys_setuid,
    sys_socketpair, sys_stat, sys_symlink, sys_umount2, sys_unlink, sys_wait4, sys_write,
};

const EBADF: i64 = -9;
const EACCES: i64 = -13;
const ENOENT: i64 = -2;
const ENOTDIR: i64 = -20;
const ELOOP: i64 = -40;
const AT_EMPTY_PATH: i32 = 0x1000;
const S_IFMT: u32 = 0o170000;
const S_IFLNK: u32 = 0o120000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFIFO: u32 = 0o010000;
const F_DUPFD: i32 = 0;
const F_GETFD: i32 = 1;
const F_SETFD: i32 = 2;
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const F_GETLK: i32 = 5;
const F_SETLK: i32 = 6;
const F_SETOWN: i32 = 8;
const F_GETOWN: i32 = 9;
const F_GETSIG: i32 = 11;
const F_DUPFD_CLOEXEC: i32 = 1030;
const F_GET_SEALS: i32 = 1034;
const F_WRLCK: i16 = 1;
const FIONREAD: u64 = 0x541B;
const POLLNVAL: i16 = 0x20;
const LOCK_SH: i32 = 1;
const EPOLL_CTL_ADD: i32 = 1;

const DIR: &[u8] = b"/tmp/op\0";
const F: &[u8] = b"/tmp/op/f\0";
const S: &[u8] = b"/tmp/op/s\0";
const D: &[u8] = b"/tmp/op/d\0";
const P: &[u8] = b"/tmp/op/p\0";
const N: &[u8] = b"/tmp/op/n\0";
const L: &[u8] = b"/tmp/op/l\0";
const X: &[u8] = b"/tmp/op/d/x\0";
const MISSING: &[u8] = b"/tmp/op/missing\0";

pub fn run_tests() {
    sys_mkdir(DIR.as_ptr(), 0o755);
    if sys_mount(b"none\0".as_ptr(), DIR.as_ptr(), b"ramfs\0".as_ptr(), 0, 0) != 0 {
        report_r(b"O_PATH_MOUNT", Err((b"mount", -1)));
        return;
    }
    setup();
    report_r(b"O_PATH_GETFL", getfl());
    report_r(b"O_PATH_FCNTL", fcntl());
    report_r(b"O_PATH_STAT", stat());
    report_r(b"O_PATH_IO", io());
    report_r(b"O_PATH_NOPERM", child(noperm));
    report_r(b"O_PATH_FIFO", fifo());
    report_r(b"O_PATH_SYMLINK", symlink());
    report_r(b"O_PATH_LOOKUP", lookup());
    report_r(b"O_PATH_DIRFD", dirfd());
    report_r(b"O_PATH_PASS", pass());
    report_r(b"O_PATH_POSIX_LOCK", posix_lock());
    report_r(b"O_PATH_PROC_MODE", proc_mode());
    for p in [X, F, S, P, N, L, MISSING] {
        sys_unlink(p.as_ptr());
    }
    sys_rmdir(D.as_ptr());
    sys_umount2(DIR.as_ptr(), 0);
    sys_rmdir(DIR.as_ptr());
}

fn setup() {
    let fd = sys_open(F.as_ptr(), O_CREAT | O_WRONLY, 0o755);
    if fd >= 0 {
        sys_write(fd as u64, b"abc".as_ptr(), 3);
        sys_close(fd as u64);
    }
    sys_symlink(b"f\0".as_ptr(), S.as_ptr());
    sys_mkdir(D.as_ptr(), 0o755);
    sys_mknod(P.as_ptr(), S_IFIFO | 0o644, 0);
    let fd = sys_open(N.as_ptr(), O_CREAT | O_WRONLY, 0);
    if fd >= 0 {
        sys_close(fd as u64);
    }
}

fn opath(p: &[u8], extra: u32) -> Result<i32, (&'static [u8], i64)> {
    let fd = sys_open(p.as_ptr(), O_PATH | extra, 0);
    check(b"open O_PATH", fd >= 0, fd)?;
    Ok(fd as i32)
}

fn close(fd: i32) {
    sys_close(fd as u64);
}

/// Run `f` in a child: its exit code 0 passes, else it is the failed
/// step
fn child(f: fn() -> u64) -> R {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(f());
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    check(b"child step", st == 0, i64::from(st >> 8))
}

fn mode(s: &Stat) -> u32 {
    s.st_mode & S_IFMT
}

/// O_PATH keeps only O_DIRECTORY and O_NOFOLLOW: the access mode,
/// O_CREAT, O_TRUNC and O_LARGEFILE go; O_CLOEXEC is the descriptor's;
/// O_TMPFILE is O_PATH|O_DIRECTORY
fn getfl() -> R {
    let fl = O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW;
    let fd = opath(F, fl)?;
    let got = sys_fcntl(fd, F_GETFL, 0);
    let fdfl = sys_fcntl(fd, F_GETFD, 0);
    let info = fdinfo_flags(i64::from(fd));
    let mut st = Stat::default();
    sys_fstat(fd, &mut st);
    close(fd);
    check(b"F_GETFL", got == i64::from(O_PATH | O_NOFOLLOW), got)?;
    check(b"F_GETFD", fdfl == 1, fdfl)?;
    let want = u64::from(O_PATH | O_NOFOLLOW | O_CLOEXEC);
    check(b"fdinfo", info == Some(want), info.map_or(-1, |v| v as i64))?;
    check(b"no truncate", st.st_size == 3, st.st_size)?;
    let fd = opath(DIR, __O_TMPFILE | O_DIRECTORY | O_RDWR)?;
    let got = sys_fcntl(fd, F_GETFL, 0);
    sys_fstat(fd, &mut st);
    close(fd);
    check(
        b"O_TMPFILE F_GETFL",
        got == i64::from(O_PATH | O_DIRECTORY),
        got,
    )?;
    check(
        b"O_TMPFILE dir",
        mode(&st) == S_IFDIR,
        i64::from(st.st_mode),
    )
}

/// check_fcntl_cmd: the descriptor commands work, every other one is
/// EBADF (an unknown one too, not EINVAL)
fn fcntl() -> R {
    let fd = opath(F, 0)?;
    let r = fcntl_steps(fd);
    close(fd);
    r
}

fn fcntl_steps(fd: i32) -> R {
    let d = sys_fcntl(fd, F_DUPFD, 0);
    check(b"F_DUPFD", d >= 0, d)?;
    let dfl = sys_fcntl(d as i32, F_GETFL, 0);
    close(d as i32);
    check(b"dup is O_PATH", dfl == i64::from(O_PATH), dfl)?;
    let d = sys_fcntl(fd, F_DUPFD_CLOEXEC, 0);
    check(b"F_DUPFD_CLOEXEC", d >= 0, d)?;
    close(d as i32);
    let r = sys_fcntl(fd, F_SETFD, 1);
    check(b"F_SETFD", r == 0, r)?;
    let mut fl = Flock::default();
    let lk = &mut fl as *mut Flock as u64;
    for (cmd, arg) in [
        (F_SETFL, 0),
        (F_GETLK, lk),
        (F_SETLK, lk),
        (F_SETOWN, 0),
        (F_GETOWN, 0),
        (F_GETSIG, 0),
        (F_GET_SEALS, 0),
        (9999, 0),
    ] {
        let r = sys_fcntl(fd, cmd, arg);
        check(b"other cmd EBADF", r == EBADF, i64::from(cmd) * 1000 + r)?;
    }
    Ok(())
}

/// fstat and fstatfs work; fchmod/fchown are EBADF, but fchmodat2 and
/// fchownat with AT_EMPTY_PATH reach the file
fn stat() -> R {
    let fd = opath(F, 0)?;
    let r = stat_steps(fd);
    close(fd);
    r
}

fn stat_steps(fd: i32) -> R {
    let mut st = Stat::default();
    let r = sys_fstat(fd, &mut st);
    check(
        b"fstat",
        r == 0 && mode(&st) == S_IFREG && st.st_size == 3,
        r,
    )?;
    let mut sf = LinuxStatFs::default();
    let r = sys_fstatfs(fd, &mut sf);
    check(b"fstatfs", r == 0, r)?;
    let r = sys_fchmod(fd, 0o700);
    check(b"fchmod", r == EBADF, r)?;
    let r = sys_fchown(fd, 0, 0);
    check(b"fchown", r == EBADF, r)?;
    let r = sys_fchmodat2(fd, b"\0".as_ptr(), 0o751, AT_EMPTY_PATH);
    check(b"fchmodat2", r == 0, r)?;
    sys_stat(F.as_ptr(), &mut st);
    check(
        b"mode set",
        st.st_mode & 0o7777 == 0o751,
        i64::from(st.st_mode),
    )?;
    let r = sys_fchownat(fd, b"\0".as_ptr(), 0, 0, AT_EMPTY_PATH);
    check(b"fchownat", r == 0, r)
}

/// No I/O on the file: every data call is EBADF, poll sees POLLNVAL
fn io() -> R {
    let fd = opath(F, 0)?;
    let r = io_steps(fd);
    close(fd);
    r?;
    let dfd = opath(D, O_DIRECTORY)?;
    let mut buf = [0u8; 256];
    let r = sys_getdents64(dfd as u64, buf.as_mut_ptr(), 256);
    close(dfd);
    check(b"getdents64", r == EBADF, r)
}

fn io_steps(fd: i32) -> R {
    let mut b = [0u8; 8];
    let u = fd as u64;
    let r = sys_read(u, b.as_mut_ptr(), 8);
    check(b"read", r == EBADF, r)?;
    let r = sys_write(u, b.as_ptr(), 1);
    check(b"write", r == EBADF, r)?;
    let r = sys_lseek(fd, 0, 0);
    check(b"lseek", r == EBADF, r)?;
    let r = sys_fgetxattr(fd, b"user.x\0".as_ptr(), b.as_mut_ptr(), 8);
    check(b"fgetxattr", r == EBADF, r)?;
    let r = sys_mmap(0, 4096, 1, 2, fd, 0);
    check(b"mmap", r == EBADF, r)?;
    let mut n = 0i32;
    let r = sys_ioctl(fd, FIONREAD, &mut n as *mut i32 as u64);
    check(b"ioctl", r == EBADF, r)?;
    let r = sys_fsync(fd);
    check(b"fsync", r == EBADF, r)?;
    let r = sys_ftruncate(fd, 0);
    check(b"ftruncate", r == EBADF, r)?;
    let r = sys_flock(fd, LOCK_SH);
    check(b"flock", r == EBADF, r)?;
    io_poll(fd)
}

fn io_poll(fd: i32) -> R {
    let mut p = [PollFd::new(fd, 1)];
    let r = sys_poll(p.as_mut_ptr(), 1, 0);
    check(
        b"poll",
        r == 1 && p[0].revents == POLLNVAL,
        r * 1000 + i64::from(p[0].revents),
    )?;
    let ep = sys_epoll_create1(0);
    check(b"epoll_create1", ep >= 0, ep)?;
    let ev = EpollEvent::default();
    let r = sys_epoll_ctl(ep as i32, EPOLL_CTL_ADD, fd, &ev);
    close(ep as i32);
    check(b"epoll_ctl", r == EBADF, r)
}

/// No permission is needed: a mode-000 file opens O_PATH for nobody,
/// though a read open, also through /proc/self/fd, is EACCES
fn noperm() -> u64 {
    if sys_setuid(65534) != 0 {
        return 1;
    }
    let fd = sys_open(N.as_ptr(), O_PATH, 0);
    if fd < 0 {
        return 2;
    }
    if sys_open(N.as_ptr(), O_RDONLY, 0) != EACCES {
        return 3;
    }
    let mut p = *b"/proc/self/fd/\0\0\0\0";
    let k = fd_name(&mut p[14..], fd);
    p[14 + k] = 0;
    if sys_open(p.as_ptr(), O_RDONLY, 0) != EACCES {
        return 4;
    }
    0
}

/// Decimal `fd` into `b`: its length
fn fd_name(b: &mut [u8], fd: i64) -> usize {
    let mut d = [0u8; 8];
    let (mut v, mut k) = (fd as u32, 0);
    loop {
        d[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..k {
        b[i] = d[k - 1 - i];
    }
    k
}

/// A FIFO opens at once, with no reader or writer to wait for
fn fifo() -> R {
    let pid = sys_fork();
    if pid == 0 {
        let fd = sys_open(P.as_ptr(), O_PATH, 0);
        let mut st = Stat::default();
        let ok = fd >= 0 && sys_fstat(fd as i32, &mut st) == 0 && mode(&st) == S_IFIFO;
        sys_exit(u64::from(!ok));
    }
    for _ in 0..200 {
        let mut st = 0i32;
        if sys_wait4(pid, &mut st, 1, 0) == pid {
            return check(b"child", st == 0, i64::from(st >> 8));
        }
        msleep(10);
    }
    reap(pid);
    Err((b"open blocked", 0))
}

/// O_NOFOLLOW on a symlink gives the link itself: fstat, fstatat
/// AT_EMPTY_PATH and readlinkat(fd, "") work on it; without O_PATH
/// it stays ELOOP
fn symlink() -> R {
    let r = sys_open(S.as_ptr(), O_RDONLY | O_NOFOLLOW, 0);
    check(b"plain O_NOFOLLOW", r == ELOOP, r)?;
    let fd = opath(S, O_NOFOLLOW)?;
    let mut st = Stat::default();
    let r = sys_fstat(fd, &mut st);
    let at = sys_fstatat(fd, b"\0".as_ptr(), &mut Stat::default(), AT_EMPTY_PATH);
    let mut buf = [0u8; 16];
    let n = sys_readlinkat(fd, b"\0".as_ptr(), buf.as_mut_ptr(), 16);
    close(fd);
    check(
        b"fstat",
        r == 0 && mode(&st) == S_IFLNK,
        i64::from(st.st_mode),
    )?;
    check(b"fstatat", at == 0, at)?;
    check(b"readlinkat", n == 1 && buf[0] == b'f', n)?;
    let fd = opath(S, 0)?;
    let r = sys_fstat(fd, &mut st);
    close(fd);
    check(
        b"followed",
        r == 0 && mode(&st) == S_IFREG,
        i64::from(st.st_mode),
    )
}

/// O_DIRECTORY on a file is ENOTDIR; O_CREAT is dropped, so a missing
/// name is ENOENT and stays missing
fn lookup() -> R {
    let r = sys_open(F.as_ptr(), O_PATH | O_DIRECTORY, 0);
    check(b"O_DIRECTORY", r == ENOTDIR, r)?;
    let r = sys_open(MISSING.as_ptr(), O_PATH | O_CREAT, 0o644);
    check(b"O_CREAT", r == ENOENT, r)?;
    let r = sys_lstat(MISSING.as_ptr(), &mut Stat::default());
    check(b"not made", r == ENOENT, r)
}

/// A directory handle is a dirfd for *at() calls and fchdir; a file
/// handle links back (linkat AT_EMPTY_PATH) and runs (execveat)
fn dirfd() -> R {
    let dfd = opath(D, O_DIRECTORY)?;
    let r = dirfd_steps(dfd);
    close(dfd);
    r?;
    let fd = opath(F, 0)?;
    let r = sys_linkat(fd, b"\0".as_ptr(), AT_FDCWD, L.as_ptr(), AT_EMPTY_PATH);
    close(fd);
    check(b"linkat", r == 0, r)?;
    let bb = sys_open(b"/bin/busybox\0".as_ptr(), O_PATH, 0);
    check(b"busybox", bb >= 0, bb)?;
    let code = run_fd(bb as i32);
    close(bb as i32);
    check(b"execveat", code == 0, code)
}

fn dirfd_steps(dfd: i32) -> R {
    let fd = sys_openat(dfd, b"x\0".as_ptr(), O_CREAT | O_WRONLY, 0o644);
    check(b"openat", fd >= 0, fd)?;
    close(fd as i32);
    let r = sys_fstatat(dfd, b"x\0".as_ptr(), &mut Stat::default(), 0);
    check(b"fstatat", r == 0, r)?;
    let pid = sys_fork();
    if pid == 0 {
        let ok = sys_fchdir(dfd) == 0 && sys_stat(b"x\0".as_ptr(), &mut Stat::default()) == 0;
        sys_exit(u64::from(!ok));
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    check(b"fchdir", st == 0, i64::from(st))?;
    let d = sys_dup(dfd);
    check(b"dup", d >= 0, d)?;
    let fl = sys_fcntl(d as i32, F_GETFL, 0);
    close(d as i32);
    check(b"dup F_GETFL", fl == i64::from(O_PATH | O_DIRECTORY), fl)
}

/// execveat(fd, "", AT_EMPTY_PATH) of busybox `true` in a child: its
/// exit code
fn run_fd(fd: i32) -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        let argv = [b"true\0".as_ptr(), core::ptr::null()];
        let envp = [core::ptr::null()];
        let r = sys_execveat(
            fd,
            b"\0".as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            AT_EMPTY_PATH,
        );
        sys_exit((-r) as u64 & 0xff);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    if st & 0x7f == 0 {
        i64::from((st >> 8) & 0xff)
    } else {
        -1
    }
}

/// An O_PATH descriptor passes over SCM_RIGHTS and stays one
fn pass() -> R {
    let mut sv = [0i32; 2];
    let r = sys_socketpair(AF_UNIX, SOCK_STREAM, 0, &mut sv);
    check(b"socketpair", r == 0, r)?;
    let fd = opath(F, 0)?;
    let s = send_fds(sv[1], b"x", &[fd]);
    close(fd);
    let mut buf = [0u8; 4];
    let mut ctl = [0u8; 64];
    let (n, _, clen) = recv_msg(sv[0], &mut buf, &mut ctl, 0);
    let (got, _) = got_fds(&ctl, clen);
    let fl = if got >= 0 {
        sys_fcntl(got, F_GETFL, 0)
    } else {
        -1
    };
    close(got);
    close(sv[0]);
    close(sv[1]);
    check(b"sent", s == 1 && n == 1 && got >= 0, s * 1000 + n)?;
    check(b"F_GETFL", fl == i64::from(O_PATH), fl)
}

/// Closing an O_PATH descriptor of a file leaves the process's POSIX
/// locks on it (Linux filp_flush skips locks_remove_posix)
fn posix_lock() -> R {
    let fd = sys_open(F.as_ptr(), O_RDWR, 0);
    check(b"open", fd >= 0, fd)?;
    let mut fl = Flock {
        l_type: F_WRLCK,
        ..Flock::default()
    };
    let r = sys_fcntl(fd as i32, F_SETLK, &mut fl as *mut Flock as u64);
    check(b"F_SETLK", r == 0, r)?;
    let p = sys_open(F.as_ptr(), O_PATH, 0);
    close(p as i32);
    let r = child(lock_held);
    close(fd as i32);
    check(b"path open", p >= 0, p)?;
    r
}

/// The parent's write lock is still there
fn lock_held() -> u64 {
    let fd = sys_open(F.as_ptr(), O_RDWR, 0);
    let mut fl = Flock {
        l_type: F_WRLCK,
        ..Flock::default()
    };
    if fd < 0 || sys_fcntl(fd as i32, F_GETLK, &mut fl as *mut Flock as u64) != 0 {
        return 1;
    }
    u64::from(fl.l_type != F_WRLCK) * 2
}

/// /proc/self/fd/N's mode follows the access mode (Linux
/// tid_fd_update_inode): r-x for reading, -wx for writing, nothing for
/// O_PATH
fn proc_mode() -> R {
    for (fl, want) in [
        (O_RDONLY, 0o500),
        (O_WRONLY, 0o300),
        (O_RDWR, 0o700),
        (O_PATH, 0),
    ] {
        let fd = sys_open(F.as_ptr(), fl, 0);
        check(b"open", fd >= 0, fd)?;
        let mut p = *b"/proc/self/fd/\0\0\0\0";
        let k = fd_name(&mut p[14..], fd);
        p[14 + k] = 0;
        let mut st = Stat::default();
        let r = sys_lstat(p.as_ptr(), &mut st);
        close(fd as i32);
        check(b"lstat", r == 0, r)?;
        check(
            b"mode",
            st.st_mode == S_IFLNK | want,
            i64::from(fl) * 0o10000 + i64::from(st.st_mode & 0o777),
        )?;
    }
    Ok(())
}
