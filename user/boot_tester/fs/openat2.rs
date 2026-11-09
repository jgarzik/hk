//! openat2(2)'s request (Linux sys_openat2, build_open_flags; cases
//! from tools/testing/selftests/filesystems/openat2/openat2_test.c), on
//! a fresh ramfs on both kernels: the struct's size rules
//! (copy_struct_from_user), the strict flag, mode and resolve checks,
//! RESOLVE_CACHED's EAGAIN for an open that would create or truncate,
//! and OPENAT2_REGULAR (Linux 7.2: EFTYPE for anything but a regular
//! file; EINVAL before)

use crate::harness::{R, check, report_r};
use crate::helpers::linux_at_least;
use hk_syscall::{
    __O_TMPFILE, O_CLOEXEC, O_CREAT, O_DIRECT, O_DIRECTORY, O_EXCL, O_LARGEFILE, O_NOFOLLOW,
    O_PATH, O_RDONLY, O_RDWR, O_TRUNC, sys_close, sys_fcntl, sys_mkdir, sys_mknod, sys_mount,
    sys_open, sys_openat, sys_openat2, sys_rmdir, sys_symlink, sys_umount2, sys_unlink,
};

const EINVAL: i64 = -22;
const E2BIG: i64 = -7;
const EAGAIN: i64 = -11;
const EFTYPE: i64 = -134;
const O_NOCTTY: u32 = 0o400;
const O_TMPFILE: u64 = (__O_TMPFILE | O_DIRECTORY) as u64;
const F_GETFL: i32 = 3;
const F_GETFD: i32 = 1;
const S_IFIFO: u32 = 0o010000;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;
const RESOLVE_CACHED: u64 = 0x20;
const OPENAT2_REGULAR: u64 = 1 << 32;
/// open(2)'s int can hold this one: openat ignores it, openat2 does not
const O_REGULAR_CARRIER: u32 = 1 << 30;
const HOW: usize = 24;
/// open_how and 260 bytes of "future fields"
const BIG: usize = HOW + 4 + 128 + 4 + 128;

const DIR: &[u8] = b"/tmp/o2\0";
const C: &[u8] = b"/tmp/o2/c\0";
const F: &[u8] = b"/tmp/o2/f\0";
const P: &[u8] = b"/tmp/o2/p\0";
const S: &[u8] = b"/tmp/o2/s\0";

pub fn run_tests() {
    sys_mkdir(DIR.as_ptr(), 0o755);
    if sys_mount(b"none\0".as_ptr(), DIR.as_ptr(), b"ramfs\0".as_ptr(), 0, 0) != 0 {
        report_r(b"OPENAT2_MOUNT", Err((b"mount", -1)));
        return;
    }
    let fd = sys_open(F.as_ptr(), O_CREAT | O_RDWR, 0o644);
    sys_close(fd as u64);
    sys_mknod(P.as_ptr(), S_IFIFO | 0o644, 0);
    sys_symlink(b"f\0".as_ptr(), S.as_ptr());
    let dfd = sys_open(DIR.as_ptr(), O_RDONLY | O_DIRECTORY, 0) as i32;
    report_r(b"OPENAT2_SIZE", sizes(dfd));
    report_r(b"OPENAT2_FLAGS", flags(dfd));
    report_r(b"OPENAT2_REGULAR", regular(dfd));
    sys_close(dfd as u64);
    for p in [C, F, P, S] {
        sys_unlink(p.as_ptr());
    }
    sys_umount2(DIR.as_ptr(), 0);
    sys_rmdir(DIR.as_ptr());
}

/// openat2 of `p` from `dfd` with `how`
fn open2(dfd: i32, p: &[u8], flags: u64, mode: u64, resolve: u64) -> i64 {
    let mut b = [0u8; HOW];
    b[..8].copy_from_slice(&flags.to_ne_bytes());
    b[8..16].copy_from_slice(&mode.to_ne_bytes());
    b[16..].copy_from_slice(&resolve.to_ne_bytes());
    sys_openat2(dfd, p.as_ptr(), b.as_ptr(), HOW)
}

/// openat2 of "." from `dfd` with an O_RDONLY open_how of `size` bytes
/// at `misalign` in a 0xff-filled buffer, `extra` the byte offsets past
/// the struct set nonzero
fn sized(dfd: i32, size: usize, misalign: usize, extra: Option<usize>) -> i64 {
    let mut buf = [0xffu8; BIG + 32];
    let s = &mut buf[misalign..misalign + BIG];
    s.fill(0);
    if let Some(at) = extra {
        s[at] = 0x5a;
    }
    let r = sys_openat2(dfd, b".\0".as_ptr(), s.as_ptr(), size);
    if r >= 0 {
        sys_close(r as u64);
    }
    r
}

/// The first version's size and a bigger zeroed struct work at any
/// alignment; shorter is EINVAL; nonzero future fields, or more than a
/// page, E2BIG
fn sizes(dfd: i32) -> R {
    for m in [0, 1, 3, 7, 17] {
        let tag = m as i64 * 1000;
        check(b"normal", sized(dfd, HOW, m, None) >= 0, tag)?;
        check(b"bigger zeroed", sized(dfd, BIG, m, None) >= 0, tag)?;
        check(b"zero size", sized(dfd, 0, m, None) == EINVAL, tag)?;
        check(b"smaller", sized(dfd, HOW - 1, m, None) == EINVAL, tag)?;
        for at in [HOW, HOW + 4 + 128, BIG - 4] {
            let r = sized(dfd, BIG, m, Some(at));
            check(b"nonzero future field", r == E2BIG, tag + at as i64)?;
        }
    }
    let big = [0u8; 4097];
    let r = sys_openat2(dfd, b".\0".as_ptr(), big.as_ptr(), 4097);
    check(b"over a page", r == E2BIG, r)
}

/// One flag_validation case: an error, or success with F_GETFL (plus
/// O_CLOEXEC from F_GETFD and the O_CREAT it hides, less an O_LARGEFILE
/// not asked for) equal to the flags asked
fn case(dfd: i32, flags: u64, mode: u64, resolve: u64, want: i64) -> R {
    let p: &[u8] = if flags & u64::from(O_CREAT) != 0 {
        sys_unlink(C.as_ptr());
        b"c\0"
    } else {
        b".\0"
    };
    let fd = open2(dfd, p, flags, mode, resolve);
    let tag = (flags & 0xffff_ffff) as i64;
    if want != 0 || fd < 0 {
        if fd >= 0 {
            sys_close(fd as u64);
        }
        return check(b"errno", fd == want, tag * 1000 + fd);
    }
    let mut got = sys_fcntl(fd as i32, F_GETFL, 0) as u64;
    if sys_fcntl(fd as i32, F_GETFD, 0) & 1 != 0 {
        got |= u64::from(O_CLOEXEC);
    }
    sys_close(fd as u64);
    got |= flags & u64::from(O_CREAT);
    if flags & u64::from(O_LARGEFILE) == 0 {
        got &= !u64::from(O_LARGEFILE);
    }
    check(b"F_GETFL", got == flags, tag * 1000 + got as i64)
}

fn flags(dfd: i32) -> R {
    let f = |v: u32| u64::from(v);
    let tmp = O_TMPFILE | f(O_RDWR);
    let cases: [(u64, u64, u64, i64); 29] = [
        (tmp | f(O_PATH), 0, 0, EINVAL),
        (tmp | f(O_CREAT), 0, 0, EINVAL),
        (f(O_PATH | O_CLOEXEC), 0, 0, 0),
        (f(O_PATH | O_DIRECTORY), 0, 0, 0),
        (f(O_PATH | O_NOFOLLOW), 0, 0, 0),
        (f(O_PATH | O_RDWR), 0, 0, EINVAL),
        (f(O_PATH | O_CREAT), 0, 0, EINVAL),
        (f(O_PATH | O_EXCL), 0, 0, EINVAL),
        (f(O_PATH | O_NOCTTY), 0, 0, EINVAL),
        (f(O_PATH | O_DIRECT), 0, 0, EINVAL),
        (f(O_PATH | O_LARGEFILE), 0, 0, EINVAL),
        (f(O_RDONLY), 0o600, 0, EINVAL),
        (f(O_PATH), 0o600, 0, EINVAL),
        (f(O_CREAT), 0o600, 0, 0),
        (tmp, 0o600, 0, 0),
        (f(O_CREAT), 0xffff, 0, EINVAL),
        (f(O_CREAT), 0xc000_0000_0000_0000, 0, EINVAL),
        (tmp, 0x1337, 0, EINVAL),
        (tmp, 0x0000_a000_0000_0000, 0, EINVAL),
        (0, 0, RESOLVE_BENEATH | RESOLVE_IN_ROOT, EINVAL),
        (0, 0, 0x1337, EINVAL),
        (f(O_CREAT), 0, 0x1337, EINVAL),
        (tmp, 0, 0x1337, EINVAL),
        (f(O_PATH), 0, 0x1337, EINVAL),
        (1 << 63, 0, 0, EINVAL),
        (f(O_REGULAR_CARRIER), 0, 0, EINVAL),
        (f(O_CREAT), 0o600, RESOLVE_CACHED, EAGAIN),
        (f(O_TRUNC | O_RDWR), 0, RESOLVE_CACHED, EAGAIN),
        (tmp, 0o600, RESOLVE_CACHED, EAGAIN),
    ];
    for (i, &(fl, mode, res, want)) in cases.iter().enumerate() {
        case(dfd, fl, mode, res, want).map_err(|(w, g)| (w, i as i64 * 1_000_000_000 + g))?;
    }
    Ok(())
}

/// OPENAT2_REGULAR: a regular file opens (nothing shows in F_GETFL),
/// is created with O_CREAT; anything else is EFTYPE, a FIFO without
/// waiting, a symlink before O_NOFOLLOW's ELOOP; with O_DIRECTORY (so
/// O_TMPFILE) or O_PATH it is EINVAL. open(2) ignores the kernel's
/// carrier bit for it. Before Linux 7.2 the flag is EINVAL.
fn regular(dfd: i32) -> R {
    let rd = u64::from(O_RDONLY);
    let legacy = sys_openat(dfd, b"f\0".as_ptr(), O_RDONLY | O_REGULAR_CARRIER, 0);
    check(b"openat carrier bit", legacy >= 0, legacy)?;
    let got = sys_fcntl(legacy as i32, F_GETFL, 0);
    sys_close(legacy as u64);
    check(b"carrier hidden", got == i64::from(O_LARGEFILE), got)?;
    if !linux_at_least(7, 2) {
        let r = open2(dfd, b"f\0", OPENAT2_REGULAR | rd, 0, 0);
        return check(b"before 7.2", r == EINVAL, r);
    }
    let fd = open2(dfd, b"f\0", OPENAT2_REGULAR | rd, 0, 0);
    check(b"regular file", fd >= 0, fd)?;
    let got = sys_fcntl(fd as i32, F_GETFL, 0);
    sys_close(fd as u64);
    check(b"F_GETFL", got == i64::from(O_LARGEFILE), got)?;
    sys_unlink(C.as_ptr());
    let fd = open2(dfd, b"c\0", OPENAT2_REGULAR | u64::from(O_CREAT), 0o600, 0);
    check(b"O_CREAT", fd >= 0, fd)?;
    sys_close(fd as u64);
    let refused: [(&[u8], u64, i64); 7] = [
        (b"/dev/null\0", rd, EFTYPE),
        (b"p\0", rd, EFTYPE),
        (b"p\0", u64::from(O_CREAT), EFTYPE),
        (b".\0", rd, EFTYPE),
        (b"s\0", u64::from(O_NOFOLLOW), EFTYPE),
        (b".\0", u64::from(O_DIRECTORY), EINVAL),
        (b"f\0", u64::from(O_PATH), EINVAL),
    ];
    for (i, &(p, fl, want)) in refused.iter().enumerate() {
        let r = open2(dfd, p, OPENAT2_REGULAR | fl, 0, 0);
        if r >= 0 {
            sys_close(r as u64);
        }
        check(b"refused", r == want, i as i64 * 1000 + r)?;
    }
    let r = open2(
        dfd,
        b".\0",
        OPENAT2_REGULAR | O_TMPFILE | u64::from(O_RDWR),
        0o600,
        0,
    );
    check(b"O_TMPFILE", r == EINVAL, r)
}
