//! Path name rules shared by every path argument (Linux getname,
//! path_init, filename_parentat, filename_create): an empty name is
//! ENOENT unless AT_EMPTY_PATH, a name without a NUL in PATH_MAX bytes is
//! ENAMETOOLONG, a dirfd must be an open directory unless the path is
//! absolute, a trailing slash asks for a directory, and a last name of
//! "/", "." or ".." gets each call's own errno

use super::helpers::{print, print_num, println};
use hk_syscall::{
    O_CREAT, O_RDONLY, O_WRONLY, Stat, sys_chdir, sys_close, sys_execve, sys_fstatat, sys_link,
    sys_lstat, sys_mkdir, sys_open, sys_rename, sys_renameat2, sys_rmdir, sys_stat, sys_symlink,
    sys_unlink,
};

const ENOENT: i64 = -2;
const EBADF: i64 = -9;
const EBUSY: i64 = -16;
const EEXIST: i64 = -17;
const ENOTDIR: i64 = -20;
const EISDIR: i64 = -21;
const EINVAL: i64 = -22;
const ENAMETOOLONG: i64 = -36;
const ENOTEMPTY: i64 = -39;
const AT_FDCWD: i32 = -100;
const AT_EMPTY_PATH: i32 = 0x1000;
const RENAME_NOREPLACE: u32 = 1;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;

pub fn run_tests() {
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777); // hk boots without /tmp
    report(b"PATH_EMPTY", check_empty());
    report(b"PATH_TOOLONG", check_toolong());
    report(b"PATH_TRAILING_SLASH", trailing());
    report(b"DOTDOT_LAST_NAME", dots());
}

type R = Result<(), (&'static [u8], i64)>;

fn report(name: &[u8], r: R) {
    print(name);
    match r {
        Ok(()) => println(b":OK"),
        Err((why, got)) => {
            print(b":FAIL ");
            print(why);
            print(b" got ");
            print_num(got);
            println(b"");
        }
    }
}

/// `got` must be `want`
fn want(what: &'static [u8], got: i64, want: i64) -> R {
    if got == want { Ok(()) } else { Err((what, got)) }
}

fn zst() -> Stat {
    // SAFETY: Stat is plain integers
    unsafe { core::mem::zeroed() }
}

fn check_empty() -> R {
    let e = b"\0".as_ptr();
    let mut st = zst();
    want(b"stat", sys_stat(e, &mut st), ENOENT)?;
    want(b"chdir", sys_chdir(e), ENOENT)?;
    want(b"mkdir", sys_mkdir(e, 0o755), ENOENT)?;
    want(b"open", sys_open(e, O_RDONLY, 0), ENOENT)?;
    want(b"unlink", sys_unlink(e), ENOENT)?;
    want(b"symlink target", sys_symlink(e, b"/tmp/pe_l\0".as_ptr()), ENOENT)?;
    let argv = [core::ptr::null::<u8>()];
    want(b"execve", sys_execve(e, argv.as_ptr(), argv.as_ptr()), ENOENT)?;
    want(b"fstatat empty cwd", sys_fstatat(AT_FDCWD, e, &mut st, AT_EMPTY_PATH), 0)?;
    // dirfd: EBADF, ENOTDIR for a file, unused for an absolute path,
    // any fd with AT_EMPTY_PATH
    let fd = sys_open(b"/tmp/pe_f\0".as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd < 0 {
        return Err((b"create", fd));
    }
    let r = (|| {
        let x = b"x\0".as_ptr();
        want(b"bad dirfd", sys_fstatat(999, x, &mut st, 0), EBADF)?;
        want(b"file dirfd", sys_fstatat(fd as i32, x, &mut st, 0), ENOTDIR)?;
        want(b"absolute bad dirfd", sys_fstatat(999, b"/\0".as_ptr(), &mut st, 0), 0)?;
        want(b"file empty path", sys_fstatat(fd as i32, e, &mut st, AT_EMPTY_PATH), 0)
    })();
    sys_close(fd as u64);
    sys_unlink(b"/tmp/pe_f\0".as_ptr());
    r
}

fn check_toolong() -> R {
    // PATH_MAX bytes and no NUL among them; then one 256-byte component
    let mut p = [b'a'; 4097];
    p[4096] = 0;
    let mut st = zst();
    want(b"stat", sys_stat(p.as_ptr(), &mut st), ENAMETOOLONG)?;
    want(b"open", sys_open(p.as_ptr(), O_CREAT | O_WRONLY, 0o644), ENAMETOOLONG)?;
    want(b"mkdir", sys_mkdir(p.as_ptr(), 0o755), ENAMETOOLONG)?;
    want(b"unlink", sys_unlink(p.as_ptr()), ENAMETOOLONG)?;
    want(b"rename", sys_rename(p.as_ptr(), b"/tmp/x\0".as_ptr()), ENAMETOOLONG)?;
    want(b"chdir", sys_chdir(p.as_ptr()), ENAMETOOLONG)?;
    let mut c = [b'b'; 262];
    c[..5].copy_from_slice(b"/tmp/");
    c[261] = 0;
    want(b"long name", sys_open(c.as_ptr(), O_CREAT | O_WRONLY, 0o644), ENAMETOOLONG)
}

fn trailing() -> R {
    let f = b"/tmp/ts_f\0".as_ptr();
    let fd = sys_open(f, O_CREAT | O_WRONLY, 0o644);
    if fd < 0 {
        return Err((b"create", fd));
    }
    sys_close(fd as u64);
    sys_mkdir(b"/tmp/ts_d\0".as_ptr(), 0o755);
    sys_symlink(b"ts_d\0".as_ptr(), b"/tmp/ts_l\0".as_ptr());
    let r = trailing_ops();
    for p in [&b"/tmp/ts_f\0"[..], b"/tmp/ts_l\0", b"/tmp/ts_g\0"] {
        sys_unlink(p.as_ptr());
    }
    for p in [&b"/tmp/ts_d\0"[..], b"/tmp/ts_e\0", b"/tmp/ts_m\0"] {
        sys_rmdir(p.as_ptr());
    }
    r
}

fn trailing_ops() -> R {
    let fs = b"/tmp/ts_f/\0".as_ptr();
    let mut st = zst();
    want(b"stat file/", sys_stat(fs, &mut st), ENOTDIR)?;
    want(b"open file/", sys_open(fs, O_RDONLY, 0), ENOTDIR)?;
    want(b"creat file/", sys_open(fs, O_CREAT | O_WRONLY, 0o644), EISDIR)?;
    let new = b"/tmp/ts_n/\0".as_ptr();
    want(b"creat new/", sys_open(new, O_CREAT | O_WRONLY, 0o644), EISDIR)?;
    want(b"mkdir new/", sys_mkdir(b"/tmp/ts_m/\0".as_ptr(), 0o755), 0)?;
    want(b"symlink new/", sys_symlink(b"x\0".as_ptr(), new), ENOENT)?;
    want(b"symlink file/", sys_symlink(b"x\0".as_ptr(), fs), EEXIST)?;
    want(b"link to new/", sys_link(b"/tmp/ts_f\0".as_ptr(), new), ENOENT)?;
    want(b"unlink file/", sys_unlink(fs), ENOTDIR)?;
    want(b"unlink dir/", sys_unlink(b"/tmp/ts_d/\0".as_ptr()), EISDIR)?;
    // lstat through a trailing slash follows the link to its directory
    want(b"lstat link/", sys_lstat(b"/tmp/ts_l/\0".as_ptr(), &mut st), 0)?;
    want(b"lstat link/ type", (st.st_mode & S_IFMT) as i64, S_IFDIR as i64)?;
    let g = b"/tmp/ts_g\0".as_ptr();
    want(b"rename file/", sys_rename(fs, g), ENOTDIR)?;
    want(b"rename to new/", sys_rename(b"/tmp/ts_f\0".as_ptr(), b"/tmp/ts_g/\0".as_ptr()), ENOTDIR)?;
    let (d, e) = (b"/tmp/ts_d/\0".as_ptr(), b"/tmp/ts_e/\0".as_ptr());
    want(b"rename dir/ dir/", sys_rename(d, e), 0)?;
    want(b"rename back", sys_rename(e, d), 0)
}

fn dots() -> R {
    sys_mkdir(b"/tmp/dl\0".as_ptr(), 0o755);
    let fd = sys_open(b"/tmp/dl_f\0".as_ptr(), O_CREAT | O_WRONLY, 0o644);
    sys_close(fd as u64);
    let r = dots_ops();
    sys_unlink(b"/tmp/dl_f\0".as_ptr());
    sys_unlink(b"/tmp/dl/x\0".as_ptr());
    sys_rmdir(b"/tmp/dl\0".as_ptr());
    r
}

fn dots_ops() -> R {
    let (dot, dotdot, root) = (
        b"/tmp/dl/.\0".as_ptr(),
        b"/tmp/dl/..\0".as_ptr(),
        b"/\0".as_ptr(),
    );
    want(b"mkdir .", sys_mkdir(dot, 0o755), EEXIST)?;
    want(b"mkdir ..", sys_mkdir(dotdot, 0o755), EEXIST)?;
    want(b"mkdir /", sys_mkdir(root, 0o755), EEXIST)?;
    want(b"mkdir missing/..", sys_mkdir(b"/tmp/dl_none/..\0".as_ptr(), 0o755), ENOENT)?;
    want(b"rmdir .", sys_rmdir(dot), EINVAL)?;
    want(b"rmdir ..", sys_rmdir(dotdot), ENOTEMPTY)?;
    want(b"rmdir /", sys_rmdir(root), EBUSY)?;
    want(b"unlink .", sys_unlink(dot), EISDIR)?;
    want(b"unlink /", sys_unlink(root), EISDIR)?;
    want(b"symlink ..", sys_symlink(b"x\0".as_ptr(), dotdot), EEXIST)?;
    want(b"creat .", sys_open(dot, O_CREAT | O_WRONLY, 0o644), EISDIR)?;
    let f = b"/tmp/dl_f\0".as_ptr();
    want(b"rename . src", sys_rename(dot, b"/tmp/dl/x\0".as_ptr()), EBUSY)?;
    want(b"rename .. dst", sys_rename(f, dotdot), EBUSY)?;
    let r = sys_renameat2(AT_FDCWD, f, AT_FDCWD, dotdot, RENAME_NOREPLACE);
    want(b"rename .. noreplace", r, EEXIST)
}
