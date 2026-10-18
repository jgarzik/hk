//! linkat(2) flags (Linux 6.8 do_linkat / filename_linkat), on a fresh
//! ramfs on both kernels: only AT_SYMLINK_FOLLOW and AT_EMPTY_PATH are
//! valid (EINVAL before the paths are read); a final symlink is linked
//! itself unless AT_SYMLINK_FOLLOW; AT_EMPTY_PATH links the descriptor's
//! file, needs CAP_DAC_READ_SEARCH (ENOENT without it) and never brings
//! back an unlinked file (ENOENT), even racing with unlinks

use super::helpers::{print, print_num, println};
use hk_syscall::{
    _LINUX_CAPABILITY_VERSION_3, AT_FDCWD, CapUserData, CapUserHeader, O_CREAT, O_RDONLY, O_WRONLY,
    Stat, sys_capget, sys_capset, sys_close, sys_exit, sys_fork, sys_fstat, sys_linkat, sys_lstat,
    sys_mkdir, sys_mount, sys_open, sys_pread64, sys_pwrite64, sys_rmdir, sys_stat, sys_symlink,
    sys_umount2, sys_unlink, sys_wait4,
};

const FOLLOW: i32 = 0x400;
const EMPTY: i32 = 0x1000;
const EINVAL: i64 = -22;
const ENOENT: i64 = -2;
const S_IFMT: u32 = 0o170000;
const S_IFLNK: u32 = 0o120000;
const S_IFREG: u32 = 0o100000;
const CAP_DAC_READ_SEARCH: u32 = 2;

const DIR: &[u8] = b"/tmp/lk\0";
const F: &[u8] = b"/tmp/lk/f\0";
const G: &[u8] = b"/tmp/lk/g\0";
const S: &[u8] = b"/tmp/lk/s\0";
const R: &[u8] = b"/tmp/lk/r\0";
const E: &[u8] = b"/tmp/lk/e\0";
const O_RDWR: u32 = 2;
const NAMES: [&[u8]; 6] = [
    b"/tmp/lk/l1\0",
    b"/tmp/lk/l2\0",
    b"/tmp/lk/l3\0",
    b"/tmp/lk/l4\0",
    b"/tmp/lk/l5\0",
    b"/tmp/lk/l6\0",
];

pub fn run_tests() {
    sys_mkdir(DIR.as_ptr(), 0o755);
    let r = sys_mount(b"none\0".as_ptr(), DIR.as_ptr(), b"ramfs\0".as_ptr(), 0, 0);
    if r != 0 {
        verdict(b"LINKAT_MOUNT", false, r);
        return;
    }
    touch(F);
    sys_symlink(F.as_ptr(), S.as_ptr());
    bad_flags();
    symlinks();
    empty_path();
    empty_nocap();
    empty_unlinked();
    race_unlink();
    for p in [F, G, S, R, E].iter().chain(NAMES.iter()) {
        sys_unlink(p.as_ptr());
    }
    sys_umount2(DIR.as_ptr(), 0);
    sys_rmdir(DIR.as_ptr());
}

fn verdict(name: &[u8], ok: bool, got: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL got ");
        print_num(got);
        println(b"");
    }
}

fn touch(p: &[u8]) {
    let fd = sys_open(p.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd >= 0 {
        sys_close(fd as u64);
    }
}

fn link(dirfd: i32, old: &[u8], new: &[u8], flags: i32) -> i64 {
    sys_linkat(dirfd, old.as_ptr(), AT_FDCWD, new.as_ptr(), flags)
}

/// (inode, file type) of `p` itself (`lstat`) or what it names
fn st(p: &[u8], nofollow: bool) -> (i64, u32) {
    let mut s: Stat = unsafe { core::mem::zeroed() };
    let r = if nofollow {
        sys_lstat(p.as_ptr(), &mut s)
    } else {
        sys_stat(p.as_ptr(), &mut s)
    };
    if r < 0 {
        (r, 0)
    } else {
        (s.st_ino as i64, s.st_mode & S_IFMT)
    }
}

/// Unknown flags (AT_SYMLINK_NOFOLLOW is not one of linkat's) are
/// EINVAL, even with a bad path pointer
fn bad_flags() {
    let a = link(AT_FDCWD, F, NAMES[0], 0x100);
    let b = link(AT_FDCWD, F, NAMES[0], 1);
    let c = sys_linkat(AT_FDCWD, 1 as *const u8, AT_FDCWD, 1 as *const u8, 0x2);
    let ok = a == EINVAL && b == EINVAL && c == EINVAL && st(NAMES[0], true).0 == ENOENT;
    verdict(
        b"LINKAT_EINVAL",
        ok,
        if a != EINVAL { a } else { b * 1000 + c },
    );
}

/// Without AT_SYMLINK_FOLLOW the new name is the symlink, with it the
/// file it points to
fn symlinks() {
    let r1 = link(AT_FDCWD, S, NAMES[0], 0);
    let l1 = st(NAMES[0], true);
    let r2 = link(AT_FDCWD, S, NAMES[1], FOLLOW);
    let l2 = st(NAMES[1], true);
    let ok1 = r1 == 0 && l1.1 == S_IFLNK && l1.0 == st(S, true).0;
    let ok2 = r2 == 0 && l2.1 == S_IFREG && l2.0 == st(F, true).0;
    verdict(b"LINKAT_SYMLINK_NOFOLLOW", ok1, r1);
    verdict(b"LINKAT_SYMLINK_FOLLOW", ok2, r2);
}

/// AT_EMPTY_PATH links an open file (root has CAP_DAC_READ_SEARCH); an
/// empty path without it is ENOENT
fn empty_path() {
    let fd = sys_open(F.as_ptr(), O_RDONLY, 0) as i32;
    let r1 = link(fd, b"\0", NAMES[3], 0);
    let r2 = link(fd, b"\0", NAMES[2], EMPTY);
    sys_close(fd as u64);
    let ok = r1 == ENOENT && r2 == 0 && st(NAMES[2], true).0 == st(F, true).0;
    verdict(b"LINKAT_EMPTY_PATH", ok, r1 * 1000 + r2);
}

/// Drop CAP_DAC_READ_SEARCH from the effective set
fn drop_dac_read_search() -> bool {
    let mut h = CapUserHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut d = [CapUserData::default(); 2];
    if sys_capget(&mut h, d.as_mut_ptr()) != 0 {
        return false;
    }
    d[0].effective &= !(1 << CAP_DAC_READ_SEARCH);
    sys_capset(&h, d.as_ptr()) == 0
}

/// Without CAP_DAC_READ_SEARCH, AT_EMPTY_PATH is ENOENT
fn empty_nocap() {
    let fd = sys_open(F.as_ptr(), O_RDONLY, 0) as i32;
    let pid = sys_fork();
    if pid == 0 {
        if !drop_dac_read_search() {
            sys_exit(2);
        }
        let r = link(fd, b"\0", NAMES[3], EMPTY);
        sys_exit(if r == ENOENT { 0 } else { 1 });
    }
    let mut status = 0;
    sys_wait4(pid, &mut status, 0, 0);
    sys_close(fd as u64);
    let ok = status == 0 && st(NAMES[3], true).0 == ENOENT;
    verdict(b"LINKAT_EMPTY_PATH_NOCAP", ok, status as i64);
}

/// An open but unlinked file stays unlinked
fn empty_unlinked() {
    touch(G);
    let fd = sys_open(G.as_ptr(), O_RDONLY, 0) as i32;
    sys_unlink(G.as_ptr());
    let r = link(fd, b"\0", NAMES[4], EMPTY);
    sys_close(fd as u64);
    verdict(b"LINKAT_EMPTY_PATH_UNLINKED", r == ENOENT, r);
}

/// One child keeps unlinking and relinking (AT_EMPTY_PATH) one name,
/// another does the same with a second name, both through an O_RDWR fd
/// of one file: link counts must stay consistent with the names that
/// exist, and the data must survive (a link racing the last unlink must
/// never bring back a file its file system already let go)
fn race_unlink() {
    let mut h = CapUserHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut d = [CapUserData::default(); 2];
    if sys_capget(&mut h, d.as_mut_ptr()) != 0 || d[0].effective & (1 << CAP_DAC_READ_SEARCH) == 0 {
        super::helpers::skip(b"LINKAT_RACE_UNLINK", b"no CAP_DAC_READ_SEARCH");
        return;
    }
    touch(R);
    let fd = sys_open(R.as_ptr(), O_RDWR, 0) as i32;
    let pat = [0x5au8; 512];
    sys_pwrite64(fd, pat.as_ptr(), pat.len() as u64, 0);
    let ino = st(R, true).0;
    let mut pids = [0i64; 2];
    for (k, name) in [R, E].iter().enumerate() {
        let pid = sys_fork();
        if pid == 0 {
            for _ in 0..2000 {
                let r = link(fd, b"\0", name, EMPTY);
                if r != 0 && r != ENOENT && r != -17 {
                    sys_exit(1);
                }
                sys_unlink(name.as_ptr());
            }
            sys_exit(0);
        }
        pids[k] = pid;
    }
    let mut bad = 0;
    for pid in pids {
        let mut st = 0;
        sys_wait4(pid, &mut st, 0, 0);
        bad |= st;
    }
    // Leave at most the names that exist, then compare
    let names = [R, E].iter().filter(|n| st(n, true).0 == ino).count() as u64;
    let mut s: Stat = unsafe { core::mem::zeroed() };
    sys_fstat(fd, &mut s);
    let mut back = [0u8; 512];
    let n = sys_pread64(fd, back.as_mut_ptr(), back.len() as u64, 0);
    sys_close(fd as u64);
    let ok = bad == 0 && s.st_nlink as u64 == names && n == 512 && back == pat;
    verdict(
        b"LINKAT_RACE_UNLINK",
        ok,
        bad as i64 * 1000 + s.st_nlink as i64 * 10 + names as i64,
    );
}
