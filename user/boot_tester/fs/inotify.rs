//! Inotify tests
//!
//! Tests:
//! - Test inotify_init1 creation
//! - Test inotify_add_watch
//! - Test inotify_rm_watch
//! - Test inotify close
//! - INOTIFY_MAX_USER_WATCHES: a user's watches stop at
//!   fs.inotify.max_user_watches (ENOSPC), and a removed watch frees
//!   its charge (Linux inc_inotify_watches)
//! - INOTIFY_CROSS_FS: a watch is on an inode, not an inode number: the
//!   roots of /proc and /sys (both inode 1 on Linux) and / get three
//!   watches; adding one again returns its wd, and removing one leaves
//!   the others (Linux: marks hang off the inode's fsnotify connector)
//! - INOTIFY_UNMOUNT: watches on a ramfs's root and on a file in it do
//!   not keep it mounted: umount succeeds, and each watch reads
//!   IN_UNMOUNT (with IN_ISDIR for the directory), then IN_IGNORED, and
//!   is gone (Linux fsnotify_sb_delete)
//! - INOTIFY_DELETE_SELF: unlinking a watched file's last name gives
//!   IN_DELETE_SELF then IN_IGNORED; for a file still open, only once
//!   it is closed (Linux dentry_unlink_inode -> fsnotify_inoderemove)

use crate::harness::pass;
use crate::helpers::{print, print_num, println};
use hk_syscall::{IN_CLOEXEC, IN_CREATE, IN_DELETE, IN_MODIFY, IN_NONBLOCK};
use hk_syscall::{sys_close, sys_inotify_add_watch, sys_inotify_init1, sys_inotify_rm_watch};

/// Run all inotify tests
pub fn run_tests() {
    test_inotify_init1();
    test_inotify_init1_flags();
    test_inotify_add_watch();
    test_inotify_rm_watch();
    test_inotify_invalid_fd();
    test_inotify_max_user_watches();
    test_inotify_cross_fs();
    test_inotify_unmount();
    test_inotify_delete_self();
}

/// Up to 8 queued events (wd, mask) of nonblocking inotify `fd`, and
/// how many there were
fn events(fd: i32) -> ([(i32, u32); 8], usize) {
    let mut out = [(0, 0); 8];
    let mut buf = [0u8; 1024];
    let n = hk_syscall::sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
    let mut k = 0;
    let mut off = 0;
    while n > 0 && off + 16 <= n as usize && k < 8 {
        let w = |at: usize| u32::from_ne_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]);
        out[k] = (w(off) as i32, w(off + 4));
        k += 1;
        off += 16 + w(off + 12) as usize;
    }
    (out, k)
}

/// The masks `ev` holds for `wd`, in order (up to 2), and how many
fn of(ev: &[(i32, u32)], wd: i64) -> ([u32; 2], usize) {
    let mut out = [0; 2];
    let mut k = 0;
    for &(w, m) in ev {
        if i64::from(w) == wd {
            if k < 2 {
                out[k] = m;
            }
            k += 1;
        }
    }
    (out, k)
}

const IN_DELETE_SELF: u32 = 0x400;
const IN_UNMOUNT: u32 = 0x2000;
const IN_IGNORED: u32 = 0x8000;
const IN_ISDIR: u32 = 0x4000_0000;

/// An empty file at `path`
fn touch(path: &[u8]) -> i64 {
    let fd = hk_syscall::sys_open(
        path.as_ptr(),
        hk_syscall::O_CREAT | hk_syscall::O_WRONLY,
        0o644,
    );
    if fd >= 0 {
        sys_close(fd as u64);
    }
    fd
}

fn test_inotify_unmount() {
    let mp = b"/tmp/inu\0";
    hk_syscall::sys_mkdir(mp.as_ptr(), 0o755);
    let fd = sys_inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    let r = unmount(fd as i32, mp);
    hk_syscall::sys_umount2(mp.as_ptr(), 0);
    hk_syscall::sys_rmdir(mp.as_ptr());
    if fd >= 0 {
        sys_close(fd as u64);
    }
    crate::harness::report_r(b"INOTIFY_UNMOUNT", r);
}

fn unmount(fd: i32, mp: &[u8]) -> crate::harness::R {
    use crate::harness::check;
    check(b"init1", fd >= 0, i64::from(fd))?;
    let m = hk_syscall::sys_mount(b"none\0".as_ptr(), mp.as_ptr(), b"ramfs\0".as_ptr(), 0, 0);
    check(b"mount", m == 0, m)?;
    check(b"create", touch(b"/tmp/inu/f\0") >= 0, -1)?;
    let wd_dir = sys_inotify_add_watch(fd, mp.as_ptr(), IN_CREATE);
    let wd_file = sys_inotify_add_watch(fd, b"/tmp/inu/f\0".as_ptr(), IN_MODIFY);
    check(b"watch dir", wd_dir > 0, wd_dir)?;
    check(b"watch file", wd_file > 0, wd_file)?;
    let (_, before) = events(fd);
    check(b"nothing before umount", before == 0, before as i64)?;
    let u = hk_syscall::sys_umount2(mp.as_ptr(), 0);
    check(b"umount", u == 0, u)?;
    let (ev, n) = events(fd);
    let ev = &ev[..n];
    let (d, nd) = of(ev, wd_dir);
    let (f, nf) = of(ev, wd_file);
    check(b"events", n == 4, n as i64)?;
    check(b"dir events", nd == 2, nd as i64)?;
    check(
        b"dir IN_UNMOUNT|IN_ISDIR",
        d[0] == IN_UNMOUNT | IN_ISDIR,
        i64::from(d[0]),
    )?;
    check(b"dir IN_IGNORED", d[1] == IN_IGNORED, i64::from(d[1]))?;
    check(b"file events", nf == 2, nf as i64)?;
    check(b"file IN_UNMOUNT", f[0] == IN_UNMOUNT, i64::from(f[0]))?;
    check(b"file IN_IGNORED", f[1] == IN_IGNORED, i64::from(f[1]))?;
    let rm = sys_inotify_rm_watch(fd, wd_dir as i32);
    check(b"watch gone", rm == -22, rm)
}

fn test_inotify_delete_self() {
    let fd = sys_inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    let r = delete_self(fd as i32);
    hk_syscall::sys_unlink(b"/tmp/inds_a\0".as_ptr());
    hk_syscall::sys_unlink(b"/tmp/inds_b\0".as_ptr());
    if fd >= 0 {
        sys_close(fd as u64);
    }
    crate::harness::report_r(b"INOTIFY_DELETE_SELF", r);
}

fn delete_self(fd: i32) -> crate::harness::R {
    use crate::harness::check;
    check(b"init1", fd >= 0, i64::from(fd))?;
    let (a, b) = (b"/tmp/inds_a\0", b"/tmp/inds_b\0");
    check(b"create", touch(a) >= 0 && touch(b) >= 0, -1)?;
    let wa = sys_inotify_add_watch(fd, a.as_ptr(), IN_DELETE_SELF);
    let wb = sys_inotify_add_watch(fd, b.as_ptr(), IN_DELETE_SELF);
    check(b"watch", wa > 0 && wb > 0 && wa != wb, wb)?;
    // a: no other holder
    check(b"unlink a", hk_syscall::sys_unlink(a.as_ptr()) == 0, -1)?;
    let (ev, n) = events(fd);
    let (m, k) = of(&ev[..n], wa);
    check(b"a events", n == 2 && k == 2, n as i64)?;
    check(b"a IN_DELETE_SELF", m[0] == IN_DELETE_SELF, i64::from(m[0]))?;
    check(b"a IN_IGNORED", m[1] == IN_IGNORED, i64::from(m[1]))?;
    // b: open across the unlink, so only its close lets the inode go
    let ob = hk_syscall::sys_open(b.as_ptr(), hk_syscall::O_RDONLY, 0);
    check(b"open b", ob >= 0, ob)?;
    check(b"unlink b", hk_syscall::sys_unlink(b.as_ptr()) == 0, -1)?;
    let (_, early) = events(fd);
    check(b"b open: no event", early == 0, early as i64)?;
    sys_close(ob as u64);
    let (ev, n) = events(fd);
    let (m, k) = of(&ev[..n], wb);
    check(b"b events", n == 2 && k == 2, n as i64)?;
    check(b"b IN_DELETE_SELF", m[0] == IN_DELETE_SELF, i64::from(m[0]))?;
    check(b"b IN_IGNORED", m[1] == IN_IGNORED, i64::from(m[1]))
}

/// Watches on the roots of three filesystems stay three
fn test_inotify_cross_fs() {
    let fd = sys_inotify_init1(IN_CLOEXEC);
    let r = cross_fs(fd as i32);
    if fd >= 0 {
        sys_close(fd as u64);
    }
    crate::harness::report_r(b"INOTIFY_CROSS_FS", r);
}

fn cross_fs(fd: i32) -> crate::harness::R {
    use crate::harness::check;
    check(b"init1", fd >= 0, i64::from(fd))?;
    let add = |p: &[u8]| sys_inotify_add_watch(fd, p.as_ptr(), IN_CREATE);
    let proc = add(b"/proc\0");
    let sys = add(b"/sys\0");
    let root = add(b"/\0");
    check(b"add /proc", proc > 0, proc)?;
    check(b"add /sys", sys > 0, sys)?;
    check(b"add /", root > 0, root)?;
    check(b"/sys has its own wd", sys != proc, sys)?;
    check(b"/ has its own wd", root != proc && root != sys, root)?;
    check(b"re-add /sys", add(b"/sys\0") == sys, add(b"/sys\0"))?;
    let rm = sys_inotify_rm_watch(fd, proc as i32);
    check(b"rm /proc", rm == 0, rm)?;
    check(b"/sys kept", add(b"/sys\0") == sys, add(b"/sys\0"))?;
    let again = add(b"/proc\0");
    check(
        b"new /proc wd",
        again > 0 && again != proc && again != sys,
        again,
    )
}

const MAX_WATCHES: &[u8] = b"/proc/sys/fs/inotify/max_user_watches\0";

fn write_str(path: &[u8], s: &[u8]) -> i64 {
    let fd = hk_syscall::sys_open(path.as_ptr(), hk_syscall::O_WRONLY, 0);
    if fd < 0 {
        return fd;
    }
    let r = hk_syscall::sys_write(fd as u64, s.as_ptr(), s.len() as u64);
    sys_close(fd as u64);
    r
}

/// Directories to watch, one file system (distinct inodes)
const WDIRS: [&[u8]; 4] = [b"/iw_a\0", b"/iw_b\0", b"/iw_c\0", b"/iw_d\0"];

/// As uid 4243 with a limit of 3: 3 watches, the 4th, then the 4th
/// again after one is removed
fn max_watches_child() -> i32 {
    const ENOSPC: i64 = -28;
    if hk_syscall::sys_setresuid(4243, 4243, 4243) != 0 {
        return 1;
    }
    let fd = sys_inotify_init1(0) as i32;
    let w = |p: &[u8]| sys_inotify_add_watch(fd, p.as_ptr(), IN_CREATE);
    let a = w(WDIRS[0]);
    if a < 0 || w(WDIRS[1]) < 0 || w(WDIRS[2]) < 0 {
        return 2;
    }
    if w(WDIRS[3]) != ENOSPC {
        return 3;
    }
    if sys_inotify_rm_watch(fd, a as i32) != 0 || w(WDIRS[3]) < 0 {
        return 4;
    }
    sys_close(fd as u64);
    0
}

fn test_inotify_max_user_watches() {
    let mut old = [0u8; 32];
    let n = crate::helpers::read_file(MAX_WATCHES, &mut old);
    if n <= 0 || write_str(MAX_WATCHES, b"3") < 0 {
        crate::harness::fail_why(b"INOTIFY_MAX_USER_WATCHES", b"sysctl", n);
        return;
    }
    for d in WDIRS {
        hk_syscall::sys_mkdir(d.as_ptr(), 0o755);
    }
    let pid = hk_syscall::sys_fork();
    if pid == 0 {
        hk_syscall::sys_exit(max_watches_child() as u64);
    }
    let mut st = 0i32;
    hk_syscall::sys_wait4(pid, &mut st, 0, 0);
    write_str(MAX_WATCHES, &old[..n as usize]);
    for d in WDIRS {
        hk_syscall::sys_rmdir(d.as_ptr());
    }
    crate::harness::report_step(
        b"INOTIFY_MAX_USER_WATCHES",
        i64::from(st >> 8) + i64::from(st & 0x7f) * 100,
    );
}

/// Test basic inotify_init1 creation
fn test_inotify_init1() {
    let fd = sys_inotify_init1(0);
    if fd < 0 {
        print(b"INOTIFY_INIT1:FAIL: returned ");
        print_num(fd);
        return;
    }

    let close_ret = sys_close(fd as u64);
    if close_ret != 0 {
        print(b"INOTIFY_INIT1:FAIL: close returned ");
        print_num(close_ret);
        return;
    }

    pass(b"INOTIFY_INIT1");
}

/// Test inotify_init1 with flags
fn test_inotify_init1_flags() {
    // Test with IN_NONBLOCK
    let fd = sys_inotify_init1(IN_NONBLOCK);
    if fd < 0 {
        print(b"INOTIFY_INIT1_FLAGS:FAIL: NONBLOCK returned ");
        print_num(fd);
        return;
    }
    sys_close(fd as u64);

    // Test with IN_CLOEXEC
    let fd = sys_inotify_init1(IN_CLOEXEC);
    if fd < 0 {
        print(b"INOTIFY_INIT1_FLAGS:FAIL: CLOEXEC returned ");
        print_num(fd);
        return;
    }
    sys_close(fd as u64);

    // Test with both flags
    let fd = sys_inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if fd < 0 {
        print(b"INOTIFY_INIT1_FLAGS:FAIL: both flags returned ");
        print_num(fd);
        return;
    }
    sys_close(fd as u64);

    // Test with invalid flags (should fail)
    let fd = sys_inotify_init1(0x12345678);
    if fd >= 0 {
        sys_close(fd as u64);
        println(b"INOTIFY_INIT1_FLAGS:FAIL: invalid flags should fail");
        return;
    }

    pass(b"INOTIFY_INIT1_FLAGS");
}

/// Test inotify_add_watch
fn test_inotify_add_watch() {
    let fd = sys_inotify_init1(0);
    if fd < 0 {
        print(b"INOTIFY_ADD_WATCH:FAIL: init1 returned ");
        print_num(fd);
        return;
    }

    // Watch /tmp directory
    let path = b"/tmp\0";
    let wd = sys_inotify_add_watch(fd as i32, path.as_ptr(), IN_CREATE | IN_DELETE | IN_MODIFY);
    if wd < 0 {
        print(b"INOTIFY_ADD_WATCH:FAIL: add_watch returned ");
        print_num(wd);
        sys_close(fd as u64);
        return;
    }

    // Watch descriptor should be positive
    if wd <= 0 {
        print(b"INOTIFY_ADD_WATCH:FAIL: expected positive wd, got ");
        print_num(wd);
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    pass(b"INOTIFY_ADD_WATCH");
}

/// Test inotify_rm_watch
fn test_inotify_rm_watch() {
    let fd = sys_inotify_init1(0);
    if fd < 0 {
        print(b"INOTIFY_RM_WATCH:FAIL: init1 returned ");
        print_num(fd);
        return;
    }

    // Add a watch first
    let path = b"/tmp\0";
    let wd = sys_inotify_add_watch(fd as i32, path.as_ptr(), IN_CREATE);
    if wd < 0 {
        print(b"INOTIFY_RM_WATCH:FAIL: add_watch returned ");
        print_num(wd);
        sys_close(fd as u64);
        return;
    }

    // Remove the watch
    let ret = sys_inotify_rm_watch(fd as i32, wd as i32);
    if ret != 0 {
        print(b"INOTIFY_RM_WATCH:FAIL: rm_watch returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    // Try to remove again - should fail with EINVAL
    let ret = sys_inotify_rm_watch(fd as i32, wd as i32);
    if ret != -22 {
        // EINVAL
        print(b"INOTIFY_RM_WATCH:FAIL: double rm_watch returned ");
        print_num(ret);
        print(b", expected -22");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    pass(b"INOTIFY_RM_WATCH");
}

/// Test inotify operations with invalid fd
fn test_inotify_invalid_fd() {
    // Try add_watch with invalid fd
    let path = b"/tmp\0";
    let ret = sys_inotify_add_watch(9999, path.as_ptr(), IN_CREATE);
    if ret != -9 {
        // EBADF
        print(b"INOTIFY_INVALID_FD:FAIL: add_watch bad fd returned ");
        print_num(ret);
        print(b", expected -9");
        return;
    }

    // Try rm_watch with invalid fd
    let ret = sys_inotify_rm_watch(9999, 1);
    if ret != -9 {
        // EBADF
        print(b"INOTIFY_INVALID_FD:FAIL: rm_watch bad fd returned ");
        print_num(ret);
        print(b", expected -9");
        return;
    }

    pass(b"INOTIFY_INVALID_FD");
}
