//! Polling a mount list (Linux mounts_poll): /proc/self/mountinfo is
//! always readable, and reports POLLERR|POLLPRI once after each change
//! of its namespace's mounts since the open or the last report: a
//! mount, an umount, a remount, a propagation change (Linux 7.3). A change in
//! another namespace is not reported. A poll that waits for POLLPRI
//! wakes when another process of the namespace mounts.
//!
//! In a child with its own mount namespace, all mounts private.

use crate::harness::{R, check, report_r};
use crate::helpers::linux_at_least;
use hk_syscall::{
    CLONE_NEWNS, O_RDONLY, PollFd, sys_close, sys_exit, sys_fork, sys_mkdir, sys_mount, sys_open,
    sys_poll, sys_rmdir, sys_umount2, sys_unshare, sys_wait4,
};

const MS_REMOUNT: u64 = 32;
const MS_BIND: u64 = 4096;
const MS_RDONLY: u64 = 1;
const MS_PRIVATE: u64 = 1 << 18;
const MS_SHARED: u64 = 1 << 20;
const MS_REC: u64 = 16384;
const POLLIN: i16 = 0x1;
const POLLPRI: i16 = 0x2;
const POLLERR: i16 = 0x8;
/// What a poll for POLLIN and POLLPRI sees: POLLRDNORM is not asked
/// for, POLLERR always reported
const READABLE: i16 = POLLIN;
const CHANGED: i16 = READABLE | POLLERR | POLLPRI;
const DIR: &[u8] = b"/tmp/mpoll\0";

pub fn run_tests() {
    report_r(b"MOUNT_POLL", in_child(poll_child));
}

/// The exit status of a child running `f` (0, or its failed step)
fn in_child(f: fn() -> i64) -> R {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(f() as u64);
    }
    check(b"fork", pid > 0, pid)?;
    let mut ws = 0i32;
    sys_wait4(pid, &mut ws, 0, 0);
    check(b"child step", ws == 0, i64::from(ws >> 8))
}

/// revents of a poll of `fd` for POLLIN and POLLPRI, waiting `ms`
fn revents(fd: i32, ms: i32) -> i16 {
    poll_for(fd, POLLIN | POLLPRI, ms)
}

/// revents of a poll of `fd` for `events`, waiting `ms`
fn poll_for(fd: i32, events: i16, ms: i32) -> i16 {
    let mut p = PollFd {
        fd,
        events,
        revents: 0,
    };
    let r = sys_poll(&mut p, 1, ms);
    if r < 0 { -1 } else { p.revents }
}

/// mount(2) with no source or type: remounts and propagation changes
fn remount(t: &[u8], flags: u64) -> i64 {
    let none = core::ptr::null();
    sys_mount(none, t.as_ptr(), none, flags, 0)
}

fn tmpfs(t: &[u8]) -> i64 {
    sys_mount(b"none\0".as_ptr(), t.as_ptr(), b"tmpfs\0".as_ptr(), 0, 0)
}

fn poll_child() -> i64 {
    if sys_unshare(CLONE_NEWNS) != 0 || remount(b"/\0", MS_REC | MS_PRIVATE) != 0 {
        return 1;
    }
    sys_mkdir(DIR.as_ptr(), 0o755);
    let fd = sys_open(b"/proc/self/mountinfo\0".as_ptr(), O_RDONLY, 0) as i32;
    if fd < 0 {
        return 2;
    }
    let r = steps(fd);
    sys_close(fd as u64);
    sys_umount2(DIR.as_ptr(), 0);
    sys_rmdir(DIR.as_ptr());
    r
}

/// Each change reported once; 0 or the failed step (10 + n)
fn steps(fd: i32) -> i64 {
    let mut n = 10;
    let mut step = |ok: bool| {
        n += 1;
        ok
    };
    let ok = step(revents(fd, 0) == READABLE)
        && step(tmpfs(DIR) == 0)
        && step(revents(fd, 0) == CHANGED)
        && step(revents(fd, 0) == READABLE)
        && step(remount(DIR, MS_REMOUNT | MS_BIND | MS_RDONLY) == 0)
        && step(revents(fd, 0) == CHANGED)
        && step(remount(DIR, MS_SHARED) == 0)
        && step(propagation_reported(revents(fd, 0)))
        && step(other_ns_mounts() == 0)
        && step(revents(fd, 0) == READABLE)
        && step(mount_wakes(fd) == POLLERR | POLLPRI)
        && step(sys_umount2(DIR.as_ptr(), 0) == 0)
        && step(revents(fd, 0) == CHANGED);
    if ok { 0 } else { n }
}

/// A propagation change is reported since Linux 7.3 (do_change_type's
/// touch_mnt_namespace); before, not
fn propagation_reported(r: i16) -> bool {
    r == CHANGED || (!linux_at_least(7, 3) && r == READABLE)
}

/// A child in a namespace of its own mounts and unmounts: 0 if it did
fn other_ns_mounts() -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        let ok = sys_unshare(CLONE_NEWNS) == 0
            && tmpfs(b"/tmp\0") == 0
            && sys_umount2(b"/tmp\0".as_ptr(), 0) == 0;
        sys_exit(if ok { 0 } else { 1 });
    }
    let mut ws = 0i32;
    sys_wait4(pid, &mut ws, 0, 0);
    i64::from(ws)
}

/// A wait for POLLPRI alone (POLLIN would end it at once) while a
/// child of this namespace mounts after a short sleep, so the poll is
/// asleep by then; the revents
fn mount_wakes(fd: i32) -> i16 {
    sys_umount2(DIR.as_ptr(), 0);
    revents(fd, 0);
    let pid = sys_fork();
    if pid == 0 {
        let ts = hk_syscall::Timespec {
            tv_sec: 0,
            tv_nsec: 100_000_000,
        };
        hk_syscall::sys_nanosleep(&ts, core::ptr::null_mut());
        sys_exit(if tmpfs(DIR) == 0 { 0 } else { 1 });
    }
    let r = poll_for(fd, POLLPRI, 10_000);
    let mut ws = 0i32;
    sys_wait4(pid, &mut ws, 0, 0);
    if ws != 0 { -2 } else { r }
}
