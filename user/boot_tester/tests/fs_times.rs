//! Inode timestamps (Linux file_update_time, do_truncate): what changes
//! a file sets its mtime and ctime to the current time. Each case first
//! sets the times far in the past (utimensat), so "changed" is a test
//! that does not depend on the clock advancing.
//!
//! - FS_TIMES_DATA: write, ftruncate and open(O_TRUNC), the last also
//!   when the size stays; truncate(2) to the same size changes nothing
//!   (Linux passes it no time attributes)

use super::helpers::{print, print_num, println};
use hk_syscall::{
    AT_FDCWD, O_CREAT, O_RDWR, O_TRUNC, O_WRONLY, Stat, Timespec, sys_close, sys_ftruncate,
    sys_lstat, sys_mkdir, sys_mount, sys_open, sys_rmdir, sys_truncate, sys_umount2, sys_unlink,
    sys_utimensat, sys_write,
};

const MP: &[u8] = b"/tmp/fst\0";
/// The time every case starts from: 1000 s after the epoch
const OLD: i64 = 1000;

pub fn run_tests() {
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    sys_mkdir(MP.as_ptr(), 0o755);
    if sys_mount(b"none\0".as_ptr(), MP.as_ptr(), b"ramfs\0".as_ptr(), 0, 0) != 0 {
        println(b"FS_TIMES_MOUNT:FAIL");
        return;
    }
    data();
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
