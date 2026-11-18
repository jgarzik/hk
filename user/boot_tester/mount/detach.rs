//! A name removed in one mount namespace takes along the mounts other
//! namespaces have on it (Linux vfs_rmdir, vfs_unlink, vfs_rename on
//! the replaced target: dont_mount, then detach_mounts)
//!
//! Tests:
//! - DETACH_RMDIR_OTHER_NS, DETACH_UNLINK_OTHER_NS,
//!   DETACH_RENAME_OTHER_NS: a child in its own namespace mounts on a
//!   directory and binds over two files; the parent removes the
//!   directory, unlinks one file and renames over the other; the
//!   child's mounts there are gone from its mountinfo
//! - DETACH_SUBMOUNT_HIDDEN: the detached directory's submount still
//!   hides what it covered from the child, which stands in the
//!   detached tree (Linux __detach_mounts: umount_tree with
//!   UMOUNT_COVER, a cover left at the unmounted parent; before 7.x
//!   UMOUNT_CONNECTED kept the submount itself)

use crate::harness::verdict;
use hk_syscall::{
    CLONE_NEWNS, O_CREAT, O_RDONLY, O_WRONLY, Stat, sys_chdir, sys_close, sys_exit, sys_fork,
    sys_fstatat, sys_mkdir, sys_mount, sys_open, sys_pipe, sys_read, sys_rename, sys_rmdir,
    sys_unlink, sys_unshare, sys_wait4, sys_write,
};

const MS_BIND: u64 = 4096;
const ENOENT: i64 = -2;
const AT_FDCWD: i32 = -100;
const MS_REC: u64 = 1 << 14;
const MS_PRIVATE: u64 = 1 << 18;

const DIR: &[u8] = b"/tmp/dt_d\0";
const FILE: &[u8] = b"/tmp/dt_f\0";
const REPL: &[u8] = b"/tmp/dt_r\0";
const SRC: &[u8] = b"/tmp/dt_s\0";

pub fn run_tests() {
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777); // hk boots without /tmp
    sys_mkdir(DIR.as_ptr(), 0o755);
    for f in [FILE, REPL, SRC] {
        touch(f);
    }
    let mut up = [0i32; 2];
    let mut down = [0i32; 2];
    sys_pipe(up.as_mut_ptr());
    sys_pipe(down.as_mut_ptr());
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(child(up[1], down[0]));
    }
    let mut c = [0u8; 1];
    let ready = sys_read(up[0] as u64, c.as_mut_ptr(), 1) == 1;
    let rm = sys_rmdir(DIR.as_ptr());
    let un = sys_unlink(FILE.as_ptr());
    let rn = sys_rename(SRC.as_ptr(), REPL.as_ptr());
    sys_write(down[1] as u64, b"g".as_ptr(), 1);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    let code = if ready { (st >> 8) as i64 } else { -1 };
    for fd in [up[0], up[1], down[0], down[1]] {
        sys_close(fd as u64);
    }
    sys_unlink(REPL.as_ptr());
    sys_rmdir(DIR.as_ptr());
    verdict(
        b"DETACH_RMDIR_OTHER_NS",
        rm == 0 && code >= 0 && code & 1 == 0,
        rm * 1000 + code,
    );
    verdict(
        b"DETACH_UNLINK_OTHER_NS",
        un == 0 && code >= 0 && code & 2 == 0,
        un * 1000 + code,
    );
    verdict(
        b"DETACH_RENAME_OTHER_NS",
        rn == 0 && code >= 0 && code & 4 == 0,
        rn * 1000 + code,
    );
    verdict(b"DETACH_SUBMOUNT_HIDDEN", code >= 0 && code & 8 == 0, code);
}

/// The child: its mounts, then what is left of them once the parent
/// removed the names (bit 0: the directory's two, bit 1: the unlinked
/// file's, bit 2: the replaced file's; bit 3: what the directory's
/// submount covered shows; 64: setup failed)
fn child(up: i32, down: i32) -> u64 {
    if sys_unshare(CLONE_NEWNS) != 0
        || sys_mount(
            core::ptr::null(),
            b"/\0".as_ptr(),
            core::ptr::null(),
            MS_REC | MS_PRIVATE,
            0,
        ) != 0
    {
        return 64;
    }
    if ramfs(DIR) != 0
        || sys_mkdir(b"/tmp/dt_d/sub\0".as_ptr(), 0o755) != 0
        || !touch(b"/tmp/dt_d/sub/hidden\0")
        || ramfs(b"/tmp/dt_d/sub\0") != 0
        || bind(SRC, FILE) != 0
        || bind(SRC, REPL) != 0
        || sys_chdir(DIR.as_ptr()) != 0
    {
        return 64;
    }
    let mut buf = [0u8; 16384];
    let before = [b"/tmp/dt_d".as_slice(), b"/tmp/dt_f", b"/tmp/dt_r"].map(|m| on(&mut buf, m));
    sys_write(up as u64, b"r".as_ptr(), 1);
    let mut c = [0u8; 1];
    sys_read(down as u64, c.as_mut_ptr(), 1);
    let after = [b"/tmp/dt_d".as_slice(), b"/tmp/dt_f", b"/tmp/dt_r"].map(|m| on(&mut buf, m));
    let want = [2, 1, 1];
    let mut code = 0;
    let mut st = Stat::default();
    if sys_fstatat(AT_FDCWD, b"sub/hidden\0".as_ptr(), &mut st, 0) != ENOENT {
        code |= 8;
    }
    for i in 0..3 {
        if before[i] != want[i] || after[i] != 0 {
            code |= 1 << i;
        }
    }
    code
}

/// Lines of the caller's mountinfo whose mount point is `mp` or under
/// it (a removed name shows with " (deleted)" after it)
fn on(buf: &mut [u8], mp: &[u8]) -> usize {
    let fd = sys_open(b"/proc/self/mountinfo\0".as_ptr(), O_RDONLY, 0);
    let mut n = 0usize;
    while fd >= 0 && n < buf.len() {
        let r = sys_read(fd as u64, buf[n..].as_mut_ptr(), (buf.len() - n) as u64);
        if r <= 0 {
            break;
        }
        n += r as usize;
    }
    sys_close(fd as u64);
    buf[..n]
        .split(|&c| c == b'\n')
        .filter_map(|l| l.split(|&c| c == b' ').nth(4))
        .filter(|f| f.starts_with(mp))
        .count()
}

fn touch(p: &[u8]) -> bool {
    let fd = sys_open(p.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd < 0 {
        return false;
    }
    sys_close(fd as u64);
    true
}

fn ramfs(t: &[u8]) -> i64 {
    sys_mount(b"none\0".as_ptr(), t.as_ptr(), b"ramfs\0".as_ptr(), 0, 0)
}

fn bind(s: &[u8], t: &[u8]) -> i64 {
    sys_mount(s.as_ptr(), t.as_ptr(), core::ptr::null(), MS_BIND, 0)
}
