//! Polling a mount list (Linux mounts_poll): /proc/self/mountinfo is
//! always readable, and reports POLLERR|POLLPRI once after each change
//! of its namespace's mounts since the open or the last report: a
//! mount, an umount, a remount, a propagation change (Linux 7.3). A change in
//! another namespace is not reported. A poll that waits for POLLPRI
//! wakes when another process of the namespace mounts.
//!
//! In a child with its own mount namespace, all mounts private.
//!
//! MOUNTS_OPEN_NS: a mounts file shows the namespace it was opened on.
//! MOUNTS_REAPED: and reads it after its process is reaped.

use crate::harness::{R, check, report_r};
use crate::helpers::linux_at_least;
use hk_syscall::{
    CLONE_NEWNS, O_RDONLY, PollFd, sys_close, sys_exit, sys_fork, sys_mkdir, sys_mount, sys_open,
    sys_pipe, sys_poll, sys_read, sys_rmdir, sys_umount2, sys_unshare, sys_wait4, sys_write,
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
    report_r(b"MOUNTS_OPEN_NS", in_child(open_ns_child));
    report_r(b"MOUNTS_REAPED", in_child(reaped_child));
}

/// MOUNTS_REAPED: /proc/<pid>/mountinfo opened while the process lived
/// still reads its namespace after it is reaped (Linux m_start uses the
/// namespace and root the open took, not the task)
fn reaped_child() -> i64 {
    let (mut go, mut ready) = ([0i32; 2], [0i32; 2]);
    if sys_pipe(go.as_mut_ptr()) != 0 || sys_pipe(ready.as_mut_ptr()) != 0 {
        return 1;
    }
    // Made before the fork: the child mounts on it
    sys_mkdir(DIR.as_ptr(), 0o755);
    let pid = sys_fork();
    if pid == 0 {
        let ok = sys_unshare(CLONE_NEWNS) == 0
            && remount(b"/\0", MS_REC | MS_PRIVATE) == 0
            && tmpfs(DIR) == 0;
        sys_write(ready[1] as u64, [ok as u8].as_ptr(), 1);
        let mut b = [0u8; 1];
        sys_read(go[0] as u64, b.as_mut_ptr(), 1);
        sys_exit(0);
    }
    let mut b = [0u8; 1];
    if sys_read(ready[0] as u64, b.as_mut_ptr(), 1) != 1 || b[0] != 1 {
        return 2;
    }
    let mut pb = [0u8; 64];
    let p = crate::ns::pid_path(&mut pb, b"/proc/", pid, b"/mountinfo\0");
    let fd = sys_open(p.as_ptr(), O_RDONLY, 0) as i32;
    sys_write(go[1] as u64, b"g".as_ptr(), 1);
    let mut ws = 0i32;
    sys_wait4(pid, &mut ws, 0, 0);
    if fd < 0 {
        return 3;
    }
    let mut buf = [0u8; 16384];
    let n = read_all(fd, &mut buf);
    sys_close(fd as u64);
    sys_rmdir(DIR.as_ptr());
    if n == 0 {
        return 4;
    }
    if !contains(&buf[..n], b" /tmp/mpoll ") {
        return 5;
    }
    0
}

/// Whether `hay` holds `needle`
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// mountinfo read whole from `fd` into `buf`: its length
fn read_all(fd: i32, buf: &mut [u8]) -> usize {
    let mut n = 0;
    while n < buf.len() {
        let r = sys_read(fd as u64, buf[n..].as_mut_ptr(), (buf.len() - n) as u64);
        if r <= 0 {
            break;
        }
        n += r as usize;
    }
    n
}

/// MOUNTS_OPEN_NS: a mounts file lists the namespace it was opened on
/// (Linux mounts_open_common: proc_mounts.ns); after an unshare and a
/// mount in the new namespace it still does not show that mount, a
/// new open of it does
fn open_ns_child() -> i64 {
    let fd = sys_open(b"/proc/self/mountinfo\0".as_ptr(), O_RDONLY, 0) as i32;
    if fd < 0 {
        return 1;
    }
    if sys_unshare(CLONE_NEWNS) != 0 || remount(b"/\0", MS_REC | MS_PRIVATE) != 0 {
        return 2;
    }
    sys_mkdir(DIR.as_ptr(), 0o755);
    if tmpfs(DIR) != 0 {
        return 3;
    }
    let mut buf = [0u8; 16384];
    let n = read_all(fd, &mut buf);
    sys_close(fd as u64);
    let old = n == 0 || contains(&buf[..n], b" /tmp/mpoll ");
    let fd = sys_open(b"/proc/self/mountinfo\0".as_ptr(), O_RDONLY, 0) as i32;
    let n = if fd < 0 { 0 } else { read_all(fd, &mut buf) };
    sys_close(fd as u64);
    let new = contains(&buf[..n], b" /tmp/mpoll ");
    sys_umount2(DIR.as_ptr(), 0);
    sys_rmdir(DIR.as_ptr());
    match (!old, new) {
        (true, true) => 0,
        (false, _) => 4,
        (_, false) => 5,
    }
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
