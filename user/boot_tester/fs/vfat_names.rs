//! vfat names match without case or trailing dots in the dcache too
//! (Linux vfat_ci_dentry_ops: d_hash vfat_hashi, d_compare vfat_cmpi),
//! so every spelling of a name reaches the one cached dentry.
//!
//! - VFAT_CI_DENTRY: on vda1's vfat, "dir" is made and looked up; then
//!   a chdir to "DIR." stands in that dentry, which getcwd names by its
//!   cached spelling, and a ramfs mounted on "dir" is crossed into
//!   through "Dir".
//! - VFAT_RESOLVE_CACHED: vfat revalidates every cached dentry and asks
//!   ref mode (Linux vfat_revalidate_ci: ECHILD under LOOKUP_RCU), so
//!   openat2 RESOLVE_CACHED through vfat is EAGAIN, for a cached name
//!   and for one that failed.
//! - VFAT_NEG_DENTRY: a failed lookup leaves a negative dentry (Linux
//!   vfat_lookup, kept while the directory's version stands), which a
//!   create or rename target in another case drops (vfat_revalidate_ci:
//!   LOOKUP_CREATE, LOOKUP_RENAME_TARGET), so the new entry is named
//!   as the caller spelled it; a name made in the directory is found
//!   after a failed lookup of it.
//! - VFAT_RENAME_OVER: a rename onto an existing name replaces it
//!   (Linux vfat_rename reuses the target's entry): a file over a file
//!   (the name then has the moved file's inode and contents, the
//!   replaced one stays readable through an open descriptor), a
//!   directory over an empty directory in another directory, ENOTEMPTY
//!   over a non-empty one, EISDIR for a file over a directory and
//!   ENOTDIR for the reverse; after a remount the names and contents are
//!   as left.

use crate::harness::T;
use crate::helpers::{find_blkdev, read_file};
use hk_syscall::{
    O_CREAT, O_PATH, O_RDONLY, O_TRUNC, O_WRONLY, Stat, sys_chdir, sys_close, sys_getcwd,
    sys_mkdir, sys_mount, sys_open, sys_openat2, sys_pread64, sys_readlink, sys_rename, sys_rmdir,
    sys_stat, sys_umount2, sys_unlink, sys_write,
};

const DIR: &[u8] = b"/tmp/vci\0";

/// st_dev of `p`, or 0
fn dev(p: &[u8]) -> u64 {
    let mut st = Stat::default();
    if sys_stat(p.as_ptr(), &mut st) == 0 {
        st.st_dev
    } else {
        0
    }
}

pub fn run_tests() {
    let mut t = T::new(b"VFAT_CI_DENTRY");
    let Some(dev_) = find_blkdev(b"vd", 32768) else {
        t.ok(b"no vda1", false, 0);
        t.done();
        return;
    };
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    sys_mkdir(DIR.as_ptr(), 0o755);
    let mut p = [0u8; 48];
    let path = dev_.path(&mut p);
    let r = sys_mount(
        path.as_ptr(),
        DIR.as_ptr(),
        b"vfat\0".as_ptr(),
        0,
        b"iocharset=cp437\0".as_ptr() as u64,
    );
    if !t.eq(b"mount vfat", r, 0) {
        sys_rmdir(DIR.as_ptr());
        t.done();
        return;
    }
    sys_rmdir(b"/tmp/vci/dir\0".as_ptr());
    if t.eq(b"mkdir", sys_mkdir(b"/tmp/vci/dir\0".as_ptr(), 0o755), 0) {
        check(&mut t);
        cached();
        negative();
        sys_chdir(b"/\0".as_ptr());
        sys_rmdir(b"/tmp/vci/dir\0".as_ptr());
    }
    rename_over(path);
    sys_umount2(DIR.as_ptr(), 0);
    sys_rmdir(DIR.as_ptr());
    t.done();
}

fn check(t: &mut T) {
    let vfat = dev(b"/tmp/vci/dir\0");
    t.ok(b"stat dir", vfat != 0, 0);
    t.eq(b"chdir DIR.", sys_chdir(b"/tmp/vci/DIR.\0".as_ptr()), 0);
    let mut buf = [0u8; 64];
    let r = sys_getcwd(buf.as_mut_ptr(), buf.len());
    let want = b"/tmp/vci/dir\0";
    t.ok(
        b"getcwd",
        r == want.len() as i64 && buf[..want.len()] == want[..],
        r,
    );
    sys_chdir(b"/\0".as_ptr());
    let r = sys_mount(
        b"none\0".as_ptr(),
        b"/tmp/vci/dir\0".as_ptr(),
        b"ramfs\0".as_ptr(),
        0,
        0,
    );
    if t.eq(b"mount ramfs", r, 0) {
        let d = dev(b"/tmp/vci/Dir\0");
        t.ok(b"Dir crosses the mount", d != 0 && d != vfat, d as i64);
        sys_umount2(b"/tmp/vci/dir\0".as_ptr(), 0);
    }
}

/// openat2(AT_FDCWD, `p`, O_PATH, RESOLVE_CACHED)
fn open_cached(p: &[u8]) -> i64 {
    const RESOLVE_CACHED: u64 = 0x20;
    let mut how = [0u8; 24];
    how[..8].copy_from_slice(&u64::from(O_PATH).to_ne_bytes());
    how[16..].copy_from_slice(&RESOLVE_CACHED.to_ne_bytes());
    let r = sys_openat2(-100, p.as_ptr(), how.as_ptr(), how.len());
    if r >= 0 {
        sys_close(r as u64);
    }
    r
}

/// readlink(/proc/self/fd/`fd`) is `want` (NUL-terminated)
fn fd_is(fd: i64, want: &[u8]) -> bool {
    let mut p = *b"/proc/self/fd/\0\0\0\0";
    let mut n = 14;
    if fd >= 10 {
        p[n] = b'0' + (fd / 10 % 10) as u8;
        n += 1;
    }
    p[n] = b'0' + (fd % 10) as u8;
    let mut buf = [0u8; 64];
    let r = sys_readlink(p.as_ptr(), buf.as_mut_ptr(), buf.len() as u64);
    let w = &want[..want.len() - 1];
    r == w.len() as i64 && &buf[..w.len()] == w
}

fn negative() {
    const ENOENT: i64 = -2;
    let mut t = T::new(b"VFAT_NEG_DENTRY");
    let mut st = Stat::default();
    t.eq(
        b"miss",
        sys_stat(b"/tmp/vci/dir/foo\0".as_ptr(), &mut st),
        ENOENT,
    );
    t.eq(
        b"miss again",
        sys_stat(b"/tmp/vci/dir/fOo\0".as_ptr(), &mut st),
        ENOENT,
    );
    let fd = sys_open(b"/tmp/vci/dir/FOO\0".as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if t.ok(b"create FOO", fd >= 0, fd) {
        t.ok(b"named FOO", fd_is(fd, b"/tmp/vci/dir/FOO\0"), 0);
        sys_close(fd as u64);
    }
    t.eq(
        b"found as foo",
        sys_stat(b"/tmp/vci/dir/foo\0".as_ptr(), &mut st),
        0,
    );
    t.eq(b"unlink", sys_unlink(b"/tmp/vci/dir/foo\0".as_ptr()), 0);
    t.eq(
        b"gone",
        sys_stat(b"/tmp/vci/dir/Foo\0".as_ptr(), &mut st),
        ENOENT,
    );
    t.eq(
        b"miss bar",
        sys_stat(b"/tmp/vci/dir/bar\0".as_ptr(), &mut st),
        ENOENT,
    );
    t.eq(
        b"mkdir sub",
        sys_mkdir(b"/tmp/vci/dir/sub\0".as_ptr(), 0o755),
        0,
    );
    let r = sys_rename(
        b"/tmp/vci/dir/sub\0".as_ptr(),
        b"/tmp/vci/dir/BAR\0".as_ptr(),
    );
    t.eq(b"rename to BAR", r, 0);
    let fd = sys_open(b"/tmp/vci/dir/bar\0".as_ptr(), O_PATH, 0);
    if t.ok(b"open bar", fd >= 0, fd) {
        t.ok(b"named BAR", fd_is(fd, b"/tmp/vci/dir/BAR\0"), 0);
        sys_close(fd as u64);
    }
    sys_rmdir(b"/tmp/vci/dir/bar\0".as_ptr());
    t.done();
}

fn cached() {
    const EAGAIN: i64 = -11;
    let mut t = T::new(b"VFAT_RESOLVE_CACHED");
    t.ok(b"stat dir", dev(b"/tmp/vci/dir\0") != 0, 0);
    t.eq(b"cached dir", open_cached(b"/tmp/vci/dir\0"), EAGAIN);
    t.ok(b"stat nosuch", dev(b"/tmp/vci/nosuch\0") == 0, 0);
    t.eq(b"failed name", open_cached(b"/tmp/vci/nosuch\0"), EAGAIN);
    t.done();
}

/// Make `path` hold `data`
fn put(path: &[u8], data: &[u8]) -> i64 {
    let fd = sys_open(path.as_ptr(), O_CREAT | O_WRONLY | O_TRUNC, 0o644);
    if fd < 0 {
        return fd;
    }
    let r = sys_write(fd as u64, data.as_ptr(), data.len() as u64);
    sys_close(fd as u64);
    r
}

/// `path` holds exactly `want`
fn holds(path: &[u8], want: &[u8]) -> bool {
    let mut b = [0u8; 16];
    let n = read_file(path, &mut b);
    n == want.len() as i64 && &b[..want.len()] == want
}

/// st_ino of `p`, or 0
fn ino(p: &[u8]) -> u64 {
    let mut st = Stat::default();
    if sys_stat(p.as_ptr(), &mut st) == 0 {
        st.st_ino
    } else {
        0
    }
}

/// stat(`p`)'s result
fn stat_r(p: &[u8]) -> i64 {
    sys_stat(p.as_ptr(), &mut Stat::default())
}

const RO: &[u8] = b"/tmp/vci/ro\0";
const P1: &[u8] = b"/tmp/vci/ro/p1\0";
const P2: &[u8] = b"/tmp/vci/ro/p2\0";
const RA: &[u8] = b"/tmp/vci/ro/a\0";
const RB: &[u8] = b"/tmp/vci/ro/b\0";
const SUB: &[u8] = b"/tmp/vci/ro/p1/sub\0";
const SUB_F: &[u8] = b"/tmp/vci/ro/p1/sub/f\0";
const TGT: &[u8] = b"/tmp/vci/ro/p2/tgt\0";
const TGT_F: &[u8] = b"/tmp/vci/ro/p2/tgt/f\0";
const FULL: &[u8] = b"/tmp/vci/ro/p2/full\0";
const FULL_X: &[u8] = b"/tmp/vci/ro/p2/full/x\0";

/// VFAT_RENAME_OVER on the vfat mounted at DIR from device `dev`
fn rename_over(dev: &[u8]) {
    const ENOENT: i64 = -2;
    const ENOTEMPTY: i64 = -39;
    let mut t = T::new(b"VFAT_RENAME_OVER");
    for d in [RO, P1, P2] {
        sys_mkdir(d.as_ptr(), 0o755);
    }
    t.eq(b"put a", put(RA, b"AAA"), 3);
    t.eq(b"put b", put(RB, b"BBBBB"), 5);
    let ia = ino(RA);
    let fd = sys_open(RB.as_ptr(), O_RDONLY, 0);
    t.ok(b"open b", fd >= 0, fd);
    t.eq(b"rename a b", sys_rename(RA.as_ptr(), RB.as_ptr()), 0);
    t.eq(b"a gone", stat_r(RA), ENOENT);
    t.ok(b"b holds a's", holds(RB, b"AAA"), 0);
    t.ok(b"b is a's inode", ia != 0 && ino(RB) == ia, ino(RB) as i64);
    if fd >= 0 {
        let mut b = [0u8; 8];
        let n = sys_pread64(fd as i32, b.as_mut_ptr(), b.len() as u64, 0);
        t.ok(b"replaced readable", n == 5 && &b[..5] == b"BBBBB", n);
        sys_close(fd as u64);
    }
    t.eq(b"mkdir sub", sys_mkdir(SUB.as_ptr(), 0o755), 0);
    t.eq(b"put sub/f", put(SUB_F, b"SUB"), 3);
    t.eq(b"mkdir tgt", sys_mkdir(TGT.as_ptr(), 0o755), 0);
    t.eq(b"mkdir full", sys_mkdir(FULL.as_ptr(), 0o755), 0);
    t.eq(b"put full/x", put(FULL_X, b"X"), 1);
    t.eq(b"rename sub tgt", sys_rename(SUB.as_ptr(), TGT.as_ptr()), 0);
    t.eq(b"sub gone", stat_r(SUB), ENOENT);
    t.ok(b"tgt/f", holds(TGT_F, b"SUB"), 0);
    let r = sys_rename(TGT.as_ptr(), FULL.as_ptr());
    t.eq(b"over non-empty", r, ENOTEMPTY);
    // A type mismatch is the VFS's (may_delete), before vfat sees it
    t.eq(b"file over dir", sys_rename(RB.as_ptr(), TGT.as_ptr()), -21);
    t.eq(b"dir over file", sys_rename(TGT.as_ptr(), RB.as_ptr()), -20);
    // The disk as left, through a new superblock
    t.eq(b"umount", sys_umount2(DIR.as_ptr(), 0), 0);
    let r = sys_mount(
        dev.as_ptr(),
        DIR.as_ptr(),
        b"vfat\0".as_ptr(),
        0,
        b"iocharset=cp437\0".as_ptr() as u64,
    );
    t.eq(b"remount", r, 0);
    t.ok(b"b after remount", holds(RB, b"AAA"), 0);
    t.eq(b"a still gone", stat_r(RA), ENOENT);
    t.ok(b"tgt/f after remount", holds(TGT_F, b"SUB"), 0);
    t.eq(b"sub still gone", stat_r(SUB), ENOENT);
    for f in [RB, TGT_F, FULL_X] {
        sys_unlink(f.as_ptr());
    }
    for d in [TGT, FULL, P1, P2, RO] {
        sys_rmdir(d.as_ptr());
    }
    t.done();
}
