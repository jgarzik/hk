//! renameat2(2) flags (Linux filename_renameat2, __start_renaming,
//! simple_rename), on a fresh ramfs on both kernels: unknown flags and
//! bad combinations are EINVAL before the paths are read; NOREPLACE is
//! EEXIST on an existing target; EXCHANGE swaps two names and is ENOENT
//! without a target; ramfs makes no whiteouts (EINVAL); no rename or
//! exchange may move a directory under itself (EINVAL, or ENOTEMPTY for
//! a plain rename onto an ancestor). On arm64,
//! renameat (38) stays wired, as in Linux (arm64 keeps it).

use super::helpers::{print, print_num, println};
use hk_syscall::{
    AT_FDCWD, O_CREAT, O_WRONLY, Stat, sys_close, sys_mkdir, sys_mount, sys_open, sys_renameat2,
    sys_rmdir, sys_stat, sys_umount2, sys_unlink,
};

const NOREPLACE: u32 = 1 << 0;
const EXCHANGE: u32 = 1 << 1;
const WHITEOUT: u32 = 1 << 2;
const EINVAL: i64 = -22;
const EEXIST: i64 = -17;
const ENOENT: i64 = -2;
const ENOTEMPTY: i64 = -39;

const DIR: &[u8] = b"/tmp/rn2\0";
const A: &[u8] = b"/tmp/rn2/a\0";
const B: &[u8] = b"/tmp/rn2/b\0";
const C: &[u8] = b"/tmp/rn2/c\0";

pub fn run_tests() {
    sys_mkdir(DIR.as_ptr(), 0o755);
    let r = sys_mount(b"none\0".as_ptr(), DIR.as_ptr(), b"ramfs\0".as_ptr(), 0, 0);
    if r != 0 {
        verdict(b"RENAME2_MOUNT", false, r);
        return;
    }
    touch(A);
    touch(B);
    bad_flags();
    noreplace();
    exchange();
    whiteout();
    for p in [A, B, C] {
        sys_unlink(p.as_ptr());
    }
    trap();
    exchange_dirs();
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

fn rn(old: &[u8], new: &[u8], flags: u32) -> i64 {
    sys_renameat2(AT_FDCWD, old.as_ptr(), AT_FDCWD, new.as_ptr(), flags)
}

/// Inode number at `p`, or the errno
fn ino(p: &[u8]) -> i64 {
    let mut st: Stat = unsafe { core::mem::zeroed() };
    let r = sys_stat(p.as_ptr(), &mut st);
    if r < 0 { r } else { st.st_ino as i64 }
}

/// Unknown flags and EXCHANGE with NOREPLACE or WHITEOUT are EINVAL,
/// even with a bad path pointer
fn bad_flags() {
    let cases = [
        1u32 << 3,
        1 << 31,
        NOREPLACE | EXCHANGE,
        WHITEOUT | EXCHANGE,
    ];
    let mut bad = 0;
    for (i, &f) in cases.iter().enumerate() {
        if rn(A, B, f) != EINVAL {
            bad = i as i64 + 1;
        }
    }
    let r = sys_renameat2(AT_FDCWD, 1 as *const u8, AT_FDCWD, 1 as *const u8, 1 << 3);
    if r != EINVAL {
        bad = 10;
    }
    let intact = ino(A) > 0 && ino(B) > 0;
    verdict(b"RENAME2_EINVAL", bad == 0 && intact, bad);
}

/// NOREPLACE: EEXIST over b, a plain rename to the free name c
fn noreplace() {
    let a = ino(A);
    let r1 = rn(A, B, NOREPLACE);
    let r2 = rn(A, C, NOREPLACE);
    let ok = r1 == EEXIST && r2 == 0 && ino(A) == ENOENT && ino(C) == a;
    verdict(b"RENAME2_NOREPLACE", ok, r1 * 100 + r2);
}

/// EXCHANGE swaps b and c; with no target it is ENOENT
fn exchange() {
    let (b, c) = (ino(B), ino(C));
    let r1 = rn(B, C, EXCHANGE);
    let swapped = ino(B) == c && ino(C) == b;
    let r2 = rn(B, A, EXCHANGE);
    let ok = r1 == 0 && swapped && r2 == ENOENT && ino(B) == c;
    verdict(b"RENAME2_EXCHANGE", ok, r1 * 100 + r2);
}

/// ramfs has no whiteouts
fn whiteout() {
    let r = rn(B, A, WHITEOUT);
    let ok = r == EINVAL && ino(B) > 0 && ino(A) == ENOENT;
    verdict(b"RENAME2_WHITEOUT", ok, r);
}

const T: [&[u8]; 4] = [
    b"/tmp/rn2/t\0",
    b"/tmp/rn2/t/a\0",
    b"/tmp/rn2/t/a/b\0",
    b"/tmp/rn2/t/a/b/c\0",
];

/// Exchanges and renames that would move a directory under itself are
/// refused and leave the tree as it was
fn trap() {
    for d in T {
        sys_mkdir(d.as_ptr(), 0o755);
    }
    let before = T.map(ino);
    let (a, c) = (T[1], T[3]);
    let r = [
        rn(c, a, EXCHANGE),
        rn(a, c, EXCHANGE),
        rn(c, a, 0),
        rn(a, c, 0),
    ];
    let want = [EINVAL, EINVAL, ENOTEMPTY, EINVAL];
    let parent_ok =
        ino(b"/tmp/rn2/t/a/b/c/..\0") == before[2] && ino(b"/tmp/rn2/t/a/b/..\0") == before[1];
    let intact = T.map(ino) == before && parent_ok;
    let bad = (0..4).find(|&i| r[i] != want[i]);
    let got = bad.map_or(if intact { 0 } else { 99 }, |i| r[i] * 10 - i as i64);
    verdict(b"RENAME2_TRAP", bad.is_none() && intact, got);
    for d in T.iter().rev() {
        sys_rmdir(d.as_ptr());
    }
}

/// Two directories in different parents trade places; each one's ".."
/// is its new parent
fn exchange_dirs() {
    let dirs: [&[u8]; 4] = [
        b"/tmp/rn2/p1\0",
        b"/tmp/rn2/p2\0",
        b"/tmp/rn2/p1/d\0",
        b"/tmp/rn2/p2/e\0",
    ];
    for d in dirs {
        sys_mkdir(d.as_ptr(), 0o755);
    }
    let before = dirs.map(ino);
    let r = rn(dirs[2], dirs[3], EXCHANGE);
    let ok = r == 0
        && ino(dirs[2]) == before[3]
        && ino(dirs[3]) == before[2]
        && ino(b"/tmp/rn2/p1/d/..\0") == before[0]
        && ino(b"/tmp/rn2/p2/e/..\0") == before[1];
    verdict(b"RENAME2_EXCHANGE_DIRS", ok, r);
    for d in dirs.iter().rev() {
        sys_rmdir(d.as_ptr());
    }
}
