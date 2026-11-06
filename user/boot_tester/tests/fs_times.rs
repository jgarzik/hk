//! Inode timestamps (Linux file_update_time, do_truncate): what changes
//! a file sets its mtime and ctime to the current time. Each case first
//! sets the times far in the past (utimensat), so "changed" is a test
//! that does not depend on the clock advancing.
//!
//! - FS_TIMES_DATA: write, ftruncate and open(O_TRUNC), the last also
//!   when the size stays; truncate(2) to the same size changes nothing
//!   (Linux passes it no time attributes)
//! - FS_TIMES_DIR: create, mkdir, mknod, symlink, link, unlink, rmdir
//!   and rename set the parent's (both parents') mtime and ctime; link,
//!   unlink and rename also the inode's ctime

use super::helpers::{print, print_num, println};
use hk_syscall::{
    AT_FDCWD, O_CREAT, O_RDWR, O_TRUNC, O_WRONLY, Stat, Timespec, sys_close, sys_ftruncate,
    sys_link, sys_lstat, sys_mkdir, sys_mknod, sys_mount, sys_nanosleep, sys_open, sys_rename,
    sys_rmdir, sys_symlink, sys_truncate, sys_umount2, sys_unlink, sys_utimensat, sys_write,
};

const MP: &[u8] = b"/tmp/fst\0";
/// The time every case starts from: 1 s after the epoch (a guest
/// without an RTC starts its clock at the epoch, so "now" may be only
/// seconds past it)
const OLD: i64 = 1;

pub fn run_tests() {
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    sys_mkdir(MP.as_ptr(), 0o755);
    if sys_mount(b"none\0".as_ptr(), MP.as_ptr(), b"ramfs\0".as_ptr(), 0, 0) != 0 {
        println(b"FS_TIMES_MOUNT:FAIL");
        return;
    }
    data();
    dir();
    sys_umount2(MP.as_ptr(), 0);
    sys_rmdir(MP.as_ptr());
}

fn lstat(p: &[u8]) -> Stat {
    // SAFETY: Stat is plain integers
    let mut st: Stat = unsafe { core::mem::zeroed() };
    sys_lstat(p.as_ptr(), &mut st);
    st
}

/// atime and mtime of `p` become `a` and `m` seconds (nofollow)
fn set_times(p: &[u8], a: i64, m: i64) {
    let t = [
        Timespec {
            tv_sec: a,
            tv_nsec: 0,
        },
        Timespec {
            tv_sec: m,
            tv_nsec: 0,
        },
    ];
    sys_utimensat(AT_FDCWD, p.as_ptr(), t.as_ptr(), 0x100);
}

/// mtime moved off OLD and equals ctime (both from one clock read)
fn touched(p: &[u8]) -> bool {
    let st = lstat(p);
    st.st_mtime > OLD && st.st_mtime == st.st_ctime && st.st_mtime_nsec == st.st_ctime_nsec
}

/// One FAIL line per failed case, or one OK line
fn report(name: &[u8], cases: &[(&[u8], bool)]) {
    let mut ok = true;
    for (what, good) in cases {
        if !good {
            print(name);
            print(b":FAIL ");
            println(what);
            ok = false;
        }
    }
    if ok {
        print(name);
        print(b":OK (");
        print_num(cases.len() as i64);
        println(b" cases)");
    }
}

fn data() {
    let f = b"/tmp/fst/f\0";
    let fd = sys_open(f.as_ptr(), O_CREAT | O_RDWR, 0o644) as i32;
    set_times(f, OLD, OLD);
    sys_write(fd as u64, b"abcd".as_ptr(), 4);
    let write = touched(f);
    set_times(f, OLD, OLD);
    sys_ftruncate(fd, 2);
    let ftrunc = touched(f);
    set_times(f, OLD, OLD);
    sys_truncate(f.as_ptr(), 2);
    let trunc_same = !touched(f) && lstat(f).st_mtime == OLD;
    sys_close(fd as u64);
    set_times(f, OLD, OLD);
    let fd = sys_open(f.as_ptr(), O_WRONLY | O_TRUNC, 0);
    sys_close(fd as u64);
    let otrunc = touched(f);
    set_times(f, OLD, OLD);
    let fd = sys_open(f.as_ptr(), O_WRONLY | O_TRUNC, 0);
    sys_close(fd as u64);
    let otrunc_empty = touched(f);
    sys_unlink(f.as_ptr());
    report(
        b"FS_TIMES_DATA",
        &[
            (b"write", write),
            (b"ftruncate", ftrunc),
            (b"truncate same size kept", trunc_same),
            (b"O_TRUNC", otrunc),
            (b"O_TRUNC empty", otrunc_empty),
        ],
    );
}

/// ctime of `p` as (seconds, nanoseconds)
fn ctime(p: &[u8]) -> (i64, i64) {
    let st = lstat(p);
    (st.st_ctime, st.st_ctime_nsec as i64)
}

/// Sleep 20 ms: more than a coarse clock tick, so a new ctime differs
fn tick() {
    let t = Timespec {
        tv_sec: 0,
        tv_nsec: 20_000_000,
    };
    sys_nanosleep(&t, core::ptr::null_mut());
}

/// `op` on directory `d` (reset to OLD first) touched it
fn dir_op(d: &[u8], op: impl FnOnce()) -> bool {
    set_times(d, OLD, OLD);
    op();
    touched(d)
}

/// `op` set `p`'s ctime anew (`at`: where `p` is after it)
fn inode_op(p: &[u8], at: &[u8], op: impl FnOnce()) -> bool {
    let before = ctime(p);
    tick();
    op();
    ctime(at) > before
}

fn dir() {
    let a = b"/tmp/fst/a\0";
    let b = b"/tmp/fst/b\0";
    let f = b"/tmp/fst/a/f\0";
    let g = b"/tmp/fst/a/g\0";
    let moved = b"/tmp/fst/b/f\0";
    sys_mkdir(a.as_ptr(), 0o755);
    sys_mkdir(b.as_ptr(), 0o755);
    let create = dir_op(a, || {
        let fd = sys_open(f.as_ptr(), O_CREAT | O_WRONLY, 0o644);
        sys_close(fd as u64);
    });
    let mkdir = dir_op(a, || {
        sys_mkdir(b"/tmp/fst/a/d\0".as_ptr(), 0o755);
    });
    let rmdir = dir_op(a, || {
        sys_rmdir(b"/tmp/fst/a/d\0".as_ptr());
    });
    let mknod = dir_op(a, || {
        sys_mknod(b"/tmp/fst/a/p\0".as_ptr(), 0o010644, 0);
    });
    let symlink = dir_op(a, || {
        sys_symlink(b"f\0".as_ptr(), b"/tmp/fst/a/s\0".as_ptr());
    });
    let link = dir_op(a, || {
        sys_link(f.as_ptr(), g.as_ptr());
    });
    let link_c = inode_op(f, f, || {
        sys_link(f.as_ptr(), b"/tmp/fst/a/h\0".as_ptr());
    });
    let unlink = dir_op(a, || {
        sys_unlink(b"/tmp/fst/a/h\0".as_ptr());
    });
    let unlink_c = inode_op(f, f, || {
        sys_unlink(g.as_ptr());
    });
    set_times(b, OLD, OLD);
    let rename = dir_op(a, || {
        sys_rename(f.as_ptr(), moved.as_ptr());
    }) && touched(b);
    let rename_c = inode_op(moved, f, || {
        sys_rename(moved.as_ptr(), f.as_ptr());
    });
    for p in [&f[..], b"/tmp/fst/a/p\0", b"/tmp/fst/a/s\0"] {
        sys_unlink(p.as_ptr());
    }
    sys_rmdir(a.as_ptr());
    sys_rmdir(b.as_ptr());
    report(
        b"FS_TIMES_DIR",
        &[
            (b"create", create),
            (b"mkdir", mkdir),
            (b"rmdir", rmdir),
            (b"mknod", mknod),
            (b"symlink", symlink),
            (b"link", link),
            (b"link ctime", link_c),
            (b"unlink", unlink),
            (b"unlink ctime", unlink_c),
            (b"rename", rename),
            (b"rename ctime", rename_c),
        ],
    );
}
