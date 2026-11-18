//! Path name rules shared by every path argument (Linux getname,
//! path_init, filename_parentat, filename_create): an empty name is
//! ENOENT unless AT_EMPTY_PATH, a name without a NUL in PATH_MAX bytes is
//! ENAMETOOLONG, a dirfd must be an open directory unless the path is
//! absolute, a trailing slash asks for a directory, a last name of
//! "/", "." or ".." gets each call's own errno, and ".." never leaves a
//! bind mount through a directory renamed out of it

use crate::harness::{R, report_r};
use hk_syscall::{
    O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW, O_RDONLY, O_WRONLY, Stat, sys_chdir, sys_close,
    sys_dup3, sys_execve, sys_fstatat, sys_link, sys_lstat, sys_mkdir, sys_mount, sys_open,
    sys_openat, sys_openat2, sys_rename, sys_renameat2, sys_rmdir, sys_stat, sys_symlink,
    sys_umount2, sys_unlink,
};

const ENOENT: i64 = -2;
const EAGAIN: i64 = -11;
const EXDEV: i64 = -18;
const EBADF: i64 = -9;
const EBUSY: i64 = -16;
const EEXIST: i64 = -17;
const ENOTDIR: i64 = -20;
const EISDIR: i64 = -21;
const EINVAL: i64 = -22;
const ENAMETOOLONG: i64 = -36;
const ELOOP: i64 = -40;
const ENOTEMPTY: i64 = -39;
const AT_FDCWD: i32 = -100;
const AT_EMPTY_PATH: i32 = 0x1000;
const RENAME_NOREPLACE: u32 = 1;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;

pub fn run_tests() {
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777); // hk boots without /tmp
    report_r(b"PATH_EMPTY", check_empty());
    report_r(b"PATH_TOOLONG", check_toolong());
    report_r(b"PATH_TRAILING_SLASH", trailing());
    report_r(b"DOTDOT_LAST_NAME", dots());
    report_r(b"CREAT_DANGLING_LINK", creat_dangling());
    report_r(b"CREAT_LAST_NAME", creat_last());
    report_r(b"CREAT_LINK_COUNT", creat_links());
    report_r(b"CREAT_RESOLVE_SCOPED", creat_scoped());
    report_r(b"NEG_DENTRY_CREATE", negative());
    report_r(b"DOTDOT_DISCONNECTED", disconnected());
    report_r(b"LINK_STACK_UNLAZY", link_stack());
    report_r(b"LINK_STACK_REF", link_stack_ref());
}

/// `got` must be `want`
fn want(what: &'static [u8], got: i64, want: i64) -> R {
    if got == want {
        Ok(())
    } else {
        Err((what, got))
    }
}

fn check_empty() -> R {
    let e = b"\0".as_ptr();
    let mut st = Stat::default();
    want(b"stat", sys_stat(e, &mut st), ENOENT)?;
    want(b"chdir", sys_chdir(e), ENOENT)?;
    want(b"mkdir", sys_mkdir(e, 0o755), ENOENT)?;
    want(b"open", sys_open(e, O_RDONLY, 0), ENOENT)?;
    want(b"unlink", sys_unlink(e), ENOENT)?;
    want(
        b"symlink target",
        sys_symlink(e, b"/tmp/pe_l\0".as_ptr()),
        ENOENT,
    )?;
    let argv = [core::ptr::null::<u8>()];
    want(
        b"execve",
        sys_execve(e, argv.as_ptr(), argv.as_ptr()),
        ENOENT,
    )?;
    want(
        b"fstatat empty cwd",
        sys_fstatat(AT_FDCWD, e, &mut st, AT_EMPTY_PATH),
        0,
    )?;
    // dirfd: EBADF, ENOTDIR for a file, unused for an absolute path,
    // any fd with AT_EMPTY_PATH
    let fd = sys_open(b"/tmp/pe_f\0".as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd < 0 {
        return Err((b"create", fd));
    }
    let r = (|| {
        let x = b"x\0".as_ptr();
        want(b"bad dirfd", sys_fstatat(999, x, &mut st, 0), EBADF)?;
        want(
            b"file dirfd",
            sys_fstatat(fd as i32, x, &mut st, 0),
            ENOTDIR,
        )?;
        want(
            b"absolute bad dirfd",
            sys_fstatat(999, b"/\0".as_ptr(), &mut st, 0),
            0,
        )?;
        want(
            b"file empty path",
            sys_fstatat(fd as i32, e, &mut st, AT_EMPTY_PATH),
            0,
        )
    })();
    sys_close(fd as u64);
    sys_unlink(b"/tmp/pe_f\0".as_ptr());
    r
}

fn check_toolong() -> R {
    // PATH_MAX bytes and no NUL among them; then one 256-byte component
    let mut p = [b'a'; 4097];
    p[4096] = 0;
    let mut st = Stat::default();
    want(b"stat", sys_stat(p.as_ptr(), &mut st), ENAMETOOLONG)?;
    want(
        b"open",
        sys_open(p.as_ptr(), O_CREAT | O_WRONLY, 0o644),
        ENAMETOOLONG,
    )?;
    want(b"mkdir", sys_mkdir(p.as_ptr(), 0o755), ENAMETOOLONG)?;
    want(b"unlink", sys_unlink(p.as_ptr()), ENAMETOOLONG)?;
    want(
        b"rename",
        sys_rename(p.as_ptr(), b"/tmp/x\0".as_ptr()),
        ENAMETOOLONG,
    )?;
    want(b"chdir", sys_chdir(p.as_ptr()), ENAMETOOLONG)?;
    let mut c = [b'b'; 262];
    c[..5].copy_from_slice(b"/tmp/");
    c[261] = 0;
    want(
        b"long name",
        sys_open(c.as_ptr(), O_CREAT | O_WRONLY, 0o644),
        ENAMETOOLONG,
    )
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
    let mut st = Stat::default();
    want(b"stat file/", sys_stat(fs, &mut st), ENOTDIR)?;
    want(b"open file/", sys_open(fs, O_RDONLY, 0), ENOTDIR)?;
    want(
        b"creat file/",
        sys_open(fs, O_CREAT | O_WRONLY, 0o644),
        EISDIR,
    )?;
    let new = b"/tmp/ts_n/\0".as_ptr();
    want(
        b"creat new/",
        sys_open(new, O_CREAT | O_WRONLY, 0o644),
        EISDIR,
    )?;
    want(b"mkdir new/", sys_mkdir(b"/tmp/ts_m/\0".as_ptr(), 0o755), 0)?;
    want(b"symlink new/", sys_symlink(b"x\0".as_ptr(), new), ENOENT)?;
    want(b"symlink file/", sys_symlink(b"x\0".as_ptr(), fs), EEXIST)?;
    want(
        b"link to new/",
        sys_link(b"/tmp/ts_f\0".as_ptr(), new),
        ENOENT,
    )?;
    want(b"unlink file/", sys_unlink(fs), ENOTDIR)?;
    want(b"unlink dir/", sys_unlink(b"/tmp/ts_d/\0".as_ptr()), EISDIR)?;
    // lstat through a trailing slash follows the link to its directory
    want(
        b"lstat link/",
        sys_lstat(b"/tmp/ts_l/\0".as_ptr(), &mut st),
        0,
    )?;
    want(
        b"lstat link/ type",
        (st.st_mode & S_IFMT) as i64,
        S_IFDIR as i64,
    )?;
    let g = b"/tmp/ts_g\0".as_ptr();
    want(b"rename file/", sys_rename(fs, g), ENOTDIR)?;
    want(
        b"rename to new/",
        sys_rename(b"/tmp/ts_f\0".as_ptr(), b"/tmp/ts_g/\0".as_ptr()),
        ENOTDIR,
    )?;
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
    want(
        b"mkdir missing/..",
        sys_mkdir(b"/tmp/dl_none/..\0".as_ptr(), 0o755),
        ENOENT,
    )?;
    want(b"rmdir .", sys_rmdir(dot), EINVAL)?;
    want(b"rmdir ..", sys_rmdir(dotdot), ENOTEMPTY)?;
    want(b"rmdir /", sys_rmdir(root), EBUSY)?;
    want(b"unlink .", sys_unlink(dot), EISDIR)?;
    want(b"unlink /", sys_unlink(root), EISDIR)?;
    want(b"symlink ..", sys_symlink(b"x\0".as_ptr(), dotdot), EEXIST)?;
    want(b"creat .", sys_open(dot, O_CREAT | O_WRONLY, 0o644), EISDIR)?;
    let f = b"/tmp/dl_f\0".as_ptr();
    want(
        b"rename . src",
        sys_rename(dot, b"/tmp/dl/x\0".as_ptr()),
        EBUSY,
    )?;
    want(b"rename .. dst", sys_rename(f, dotdot), EBUSY)?;
    let r = sys_renameat2(AT_FDCWD, f, AT_FDCWD, dotdot, RENAME_NOREPLACE);
    want(b"rename .. noreplace", r, EEXIST)
}

/// A failed lookup never hides what is made later: after ENOENT on a
/// name, a create, mkdir, symlink or rename to it is found; after an
/// unlink the name is ENOENT again (Linux negative dentries)
fn negative() -> R {
    let mut st = Stat::default();
    let p = b"/tmp/nd_x\0".as_ptr();
    let r = (|| {
        want(b"absent", sys_stat(p, &mut st), ENOENT)?;
        want(b"absent again", sys_stat(p, &mut st), ENOENT)?;
        let fd = sys_open(p, O_CREAT | O_WRONLY, 0o644);
        if fd < 0 {
            return Err((&b"create"[..], fd));
        }
        sys_close(fd as u64);
        want(b"created", sys_stat(p, &mut st), 0)?;
        want(b"unlink", sys_unlink(p), 0)?;
        want(b"unlinked", sys_stat(p, &mut st), ENOENT)?;
        want(b"mkdir", sys_mkdir(p, 0o755), 0)?;
        want(
            b"dir found",
            sys_stat(b"/tmp/nd_x/.\0".as_ptr(), &mut st),
            0,
        )?;
        want(
            b"miss inside",
            sys_stat(b"/tmp/nd_x/y\0".as_ptr(), &mut st),
            ENOENT,
        )?;
        want(b"rmdir", sys_rmdir(p), 0)?;
        want(b"rmdir gone", sys_stat(p, &mut st), ENOENT)?;
        want(b"symlink", sys_symlink(b"tgt\0".as_ptr(), p), 0)?;
        want(b"link found", sys_lstat(p, &mut st), 0)?;
        want(b"unlink link", sys_unlink(p), 0)?;
        let fd = sys_open(b"/tmp/nd_y\0".as_ptr(), O_CREAT | O_WRONLY, 0o644);
        sys_close(fd as u64);
        want(b"rename in", sys_rename(b"/tmp/nd_y\0".as_ptr(), p), 0)?;
        want(b"renamed found", sys_stat(p, &mut st), 0)?;
        want(
            b"source gone",
            sys_stat(b"/tmp/nd_y\0".as_ptr(), &mut st),
            ENOENT,
        )
    })();
    sys_unlink(p);
    sys_unlink(b"/tmp/nd_y\0".as_ptr());
    r
}

/// ".." from a directory a rename took out of the bind mount it was
/// reached through is ENOENT, not its new parent outside the mount's
/// root (Linux follow_dotdot: path_connected)
fn disconnected() -> R {
    const MS_BIND: u64 = 4096;
    for d in [
        &b"/tmp/pc\0"[..],
        b"/tmp/pc/a\0",
        b"/tmp/pc/a/b\0",
        b"/tmp/pc/a/b/c\0",
        b"/tmp/pc/m\0",
    ] {
        sys_mkdir(d.as_ptr(), 0o755);
    }
    let null = core::ptr::null();
    let r = (|| {
        let m = sys_mount(
            b"/tmp/pc/a/b\0".as_ptr(),
            b"/tmp/pc/m\0".as_ptr(),
            null,
            MS_BIND,
            0,
        );
        want(b"bind", m, 0)?;
        let fd = sys_open(b"/tmp/pc/m/c\0".as_ptr(), O_RDONLY | O_DIRECTORY, 0);
        if fd < 0 {
            return Err((&b"open"[..], fd));
        }
        let up = sys_openat(fd as i32, b"..\0".as_ptr(), O_RDONLY | O_DIRECTORY, 0);
        let r = (|| {
            want(b"dotdot inside", up.min(0), 0)?;
            want(
                b"rename out",
                sys_rename(b"/tmp/pc/a/b/c\0".as_ptr(), b"/tmp/pc/a/c\0".as_ptr()),
                0,
            )?;
            let out = sys_openat(fd as i32, b"..\0".as_ptr(), O_RDONLY | O_DIRECTORY, 0);
            if out >= 0 {
                sys_close(out as u64);
            }
            want(b"dotdot outside", out, ENOENT)
        })();
        if up >= 0 {
            sys_close(up as u64);
        }
        sys_close(fd as u64);
        r
    })();
    sys_umount2(b"/tmp/pc/m\0".as_ptr(), 0);
    for d in [
        &b"/tmp/pc/a/c\0"[..],
        b"/tmp/pc/a/b/c\0",
        b"/tmp/pc/a/b\0",
        b"/tmp/pc/a\0",
        b"/tmp/pc/m\0",
        b"/tmp/pc\0",
    ] {
        sys_rmdir(d.as_ptr());
    }
    r
}

/// Symlinks nested three deep whose last body leads into procfs, which
/// computes its entries behind the dcache: the walk follows the links,
/// then must look a name up the slow way inside the innermost body
/// (Linux: try_to_unlazy with the link stack legitimized) and lands
/// where the plain path does
fn link_stack() -> R {
    let links: [(&[u8], &[u8]); 6] = [
        (b"/proc/self/stat\0", b"/tmp/ls_a\0"),
        (b"/tmp/ls_a\0", b"/tmp/ls_b\0"),
        (b"/tmp/ls_b\0", b"/tmp/ls_c\0"),
        (b"/proc/self/fd\0", b"/tmp/ls_d\0"),
        (b"/tmp/ls_d/\0", b"/tmp/ls_e\0"),
        (b"/tmp/ls_e\0", b"/tmp/ls_f\0"),
    ];
    for (t, l) in links {
        sys_unlink(l.as_ptr());
        sys_symlink(t.as_ptr(), l.as_ptr());
    }
    let (mut a, mut b) = (Stat::default(), Stat::default());
    let r1 = sys_stat(b"/tmp/ls_c\0".as_ptr(), &mut a);
    let r2 = sys_stat(b"/proc/self/stat\0".as_ptr(), &mut b);
    let same = a.st_ino == b.st_ino && a.st_dev == b.st_dev;
    let (mut c, mut d) = (Stat::default(), Stat::default());
    let r3 = sys_stat(b"/tmp/ls_f/0\0".as_ptr(), &mut c);
    let r4 = sys_stat(b"/proc/self/fd/0\0".as_ptr(), &mut d);
    let same2 = c.st_ino == d.st_ino && c.st_dev == d.st_dev;
    for (_, l) in links {
        sys_unlink(l.as_ptr());
    }
    want(b"stat link", r1, 0)?;
    want(b"stat path", r2, 0)?;
    want(b"same file", same as i64, 1)?;
    want(b"stat dir link", r3, 0)?;
    want(b"stat fd path", r4, 0)?;
    want(b"same fd", same2 as i64, 1)
}

/// `pre` + two decimal digits of `i` + `post` + NUL, in `b`
fn numbered<'a>(b: &'a mut [u8; 64], pre: &[u8], i: usize, post: &[u8]) -> &'a [u8] {
    let digits = [b'0' + (i / 10 % 10) as u8, b'0' + (i % 10) as u8];
    let mut n = 0;
    for &c in pre.iter().chain(&digits).chain(post) {
        b[n] = c;
        n += 1;
    }
    b[n] = 0;
    &b[..=n]
}

/// A chain of `n` relative links /tmp/lsr/`c`NN, each body the next
/// link with "/." after it (a body with a rest still to walk), the
/// last's "d/."
fn chain(c: u8, n: usize) {
    let (mut lb, mut tb) = ([0u8; 64], [0u8; 64]);
    for i in 0..n {
        let l = numbered(
            &mut lb,
            &[b'/', b't', b'm', b'p', b'/', b'l', b's', b'r', b'/', c],
            i,
            b"",
        );
        let t: &[u8] = if i + 1 == n {
            b"d/.\0"
        } else {
            numbered(&mut tb, &[c], i + 1, b"/.")
        };
        sys_unlink(l.as_ptr());
        sys_symlink(t.as_ptr(), l.as_ptr());
    }
}

fn unchain(c: u8, n: usize) {
    let mut lb = [0u8; 64];
    for i in 0..n {
        let l = numbered(
            &mut lb,
            &[b'/', b't', b'm', b'p', b'/', b'l', b's', b'r', b'/', c],
            i,
            b"",
        );
        sys_unlink(l.as_ptr());
    }
}

/// Links followed in ref mode (a fresh link's atime update makes the
/// walk leave RCU mode at the first): 40 nested bodies, each with a
/// rest walked after its inner ones (Linux nd->stack, each link held
/// until its body is walked), resolve; 41 are ELOOP; a body whose last
/// component has a slash after it, onto a file, is ENOTDIR; a magic
/// link (/proc/self/fd/N) mid-path goes on from its object
fn link_stack_ref() -> R {
    sys_mkdir(b"/tmp/lsr\0".as_ptr(), 0o755);
    sys_mkdir(b"/tmp/lsr/d\0".as_ptr(), 0o755);
    let fd = sys_open(b"/tmp/lsr/d/f\0".as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd >= 0 {
        sys_close(fd as u64);
    }
    chain(b'n', 40);
    chain(b'm', 41);
    sys_symlink(b"d/f/\0".as_ptr(), b"/tmp/lsr/tf\0".as_ptr());
    let (mut a, mut b) = (Stat::default(), Stat::default());
    let r1 = sys_stat(b"/tmp/lsr/n00/f\0".as_ptr(), &mut a);
    let r2 = sys_stat(b"/tmp/lsr/d/f\0".as_ptr(), &mut b);
    let same = a.st_ino == b.st_ino && a.st_dev == b.st_dev;
    let r3 = sys_stat(b"/tmp/lsr/m00/f\0".as_ptr(), &mut a);
    let r4 = sys_stat(b"/tmp/lsr/tf\0".as_ptr(), &mut a);
    // Descriptor 42, a two-digit name
    let fd = sys_open(b"/tmp/lsr/d\0".as_ptr(), O_DIRECTORY | O_RDONLY, 0);
    let dfd = if fd >= 0 {
        sys_dup3(fd as i32, 42, 0)
    } else {
        fd
    };
    if fd >= 0 {
        sys_close(fd as u64);
    }
    let r5 = sys_stat(b"/proc/self/fd/42/f\0".as_ptr(), &mut a);
    let same2 = a.st_ino == b.st_ino && a.st_dev == b.st_dev;
    if dfd >= 0 {
        sys_close(dfd as u64);
    }
    unchain(b'n', 40);
    unchain(b'm', 41);
    sys_unlink(b"/tmp/lsr/tf\0".as_ptr());
    sys_unlink(b"/tmp/lsr/d/f\0".as_ptr());
    sys_rmdir(b"/tmp/lsr/d\0".as_ptr());
    sys_rmdir(b"/tmp/lsr\0".as_ptr());
    want(b"40 links", r1, 0)?;
    want(b"plain path", r2, 0)?;
    want(b"same file", same as i64, 1)?;
    want(b"41 links", r3, ELOOP)?;
    want(b"slash after body", r4, ENOTDIR)?;
    want(b"dirfd", dfd, 42)?;
    want(b"magic link", r5, 0)?;
    want(b"magic same file", same2 as i64, 1)
}

/// open(O_CREAT) through a dangling symlink creates its target (Linux
/// open_last_lookups follows the link); with O_EXCL it is EEXIST
fn creat_dangling() -> R {
    let link = b"/tmp/dangle\0";
    let target = b"/tmp/dangle_target\0";
    sys_unlink(target.as_ptr());
    sys_symlink(target.as_ptr(), link.as_ptr());
    let ex = sys_open(
        link.as_ptr(),
        O_CREAT | hk_syscall::O_EXCL | O_WRONLY,
        0o644,
    );
    let fd = sys_open(link.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd >= 0 {
        sys_close(fd as u64);
    }
    let mut st = Stat::default();
    let made = sys_stat(target.as_ptr(), &mut st);
    sys_unlink(link.as_ptr());
    sys_unlink(target.as_ptr());
    if ex != -17 {
        return Err((b"O_EXCL", ex));
    }
    if fd < 0 {
        return Err((b"O_CREAT", fd));
    }
    if made != 0 {
        return Err((b"target made", made));
    }
    Ok(())
}

/// `path` opened with `flags`: the errno, or 0 (the file closed)
fn open_err(path: &[u8], flags: u32) -> i64 {
    let fd = sys_open(path.as_ptr(), flags, 0o644);
    if fd >= 0 {
        sys_close(fd as u64);
        return 0;
    }
    fd
}

/// open(O_CREAT)'s last name (Linux open_last_lookups, do_open): a
/// symlink is followed unless O_EXCL or O_NOFOLLOW (O_EXCL: EEXIST, a
/// dangling one too; O_NOFOLLOW: the link itself, ELOOP); a relative
/// dangling body is created where it points; a body or name with a
/// slash after its last component, ".", or a directory is EISDIR;
/// RESOLVE_CACHED is EAGAIN
fn creat_last() -> R {
    sys_mkdir(b"/tmp/cl\0".as_ptr(), 0o755);
    sys_mkdir(b"/tmp/cl/d\0".as_ptr(), 0o755);
    open_err(b"/tmp/cl/f\0", O_CREAT | O_WRONLY);
    let links: [(&[u8], &[u8]); 6] = [
        (b"f\0", b"/tmp/cl/lf\0"),
        (b"d\0", b"/tmp/cl/ld\0"),
        (b"d/new\0", b"/tmp/cl/ln\0"),
        (b"d/x/\0", b"/tmp/cl/ls\0"),
        (b".\0", b"/tmp/cl/lo\0"),
        (b"d/nf\0", b"/tmp/cl/lx\0"),
    ];
    for (t, l) in links {
        sys_symlink(t.as_ptr(), l.as_ptr());
    }
    let r = creat_last_ops();
    for (_, l) in links {
        sys_unlink(l.as_ptr());
    }
    for p in [&b"/tmp/cl/f\0"[..], b"/tmp/cl/d/new\0", b"/tmp/cl/d/nf\0"] {
        sys_unlink(p.as_ptr());
    }
    sys_rmdir(b"/tmp/cl/d\0".as_ptr());
    sys_rmdir(b"/tmp/cl\0".as_ptr());
    r
}

fn creat_last_ops() -> R {
    let (c, x, nf) = (O_CREAT | O_WRONLY, O_CREAT | O_EXCL | O_WRONLY, O_NOFOLLOW);
    let mut st = Stat::default();
    want(b"existing", open_err(b"/tmp/cl/f\0", c), 0)?;
    want(b"excl existing", open_err(b"/tmp/cl/f\0", x), EEXIST)?;
    want(b"via link", open_err(b"/tmp/cl/lf\0", c), 0)?;
    want(b"excl link", open_err(b"/tmp/cl/lf\0", x), EEXIST)?;
    want(b"excl dangling", open_err(b"/tmp/cl/ln\0", x), EEXIST)?;
    want(b"nofollow link", open_err(b"/tmp/cl/lf\0", c | nf), ELOOP)?;
    want(
        b"nofollow dangling",
        open_err(b"/tmp/cl/lx\0", c | nf),
        ELOOP,
    )?;
    let r = sys_lstat(b"/tmp/cl/d/nf\0".as_ptr(), &mut st);
    want(b"not made", r, ENOENT)?;
    want(b"dangling", open_err(b"/tmp/cl/ln\0", c), 0)?;
    want(b"made", sys_lstat(b"/tmp/cl/d/new\0".as_ptr(), &mut st), 0)?;
    want(b"made again", open_err(b"/tmp/cl/ln\0", c), 0)?;
    want(b"dir", open_err(b"/tmp/cl/d\0", c), EISDIR)?;
    want(b"dir/", open_err(b"/tmp/cl/d/\0", c), EISDIR)?;
    want(b"link to dir", open_err(b"/tmp/cl/ld\0", c), EISDIR)?;
    want(b"body slash", open_err(b"/tmp/cl/ls\0", c), EISDIR)?;
    want(b"body dot", open_err(b"/tmp/cl/lo\0", c), EISDIR)?;
    want(b"root", open_err(b"/\0", c), EISDIR)?;
    // RESOLVE_CACHED never tries a create (Linux build_open_flags)
    let mut how = [0u8; 24];
    how[..8].copy_from_slice(&u64::from(c).to_ne_bytes());
    how[8..16].copy_from_slice(&0o644u64.to_ne_bytes());
    how[16..].copy_from_slice(&0x20u64.to_ne_bytes());
    let p = b"/tmp/cl/f\0".as_ptr();
    let r = sys_openat2(AT_FDCWD, p, how.as_ptr(), how.len());
    want(b"cached", r, EAGAIN)
}

/// A chain of `n` links /tmp/cc/tNN, each body "s/" and the next link
/// (s: a link to "."), the last's "s/new": 2n symlinks in all. An
/// O_CREAT open counts the trailing links and the ones on the way in one
/// lookup (Linux nd->total_link_count, MAXSYMLINKS): 40 make "new", 42
/// are ELOOP, as for an open without O_CREAT
fn creat_links() -> R {
    sys_mkdir(b"/tmp/cc\0".as_ptr(), 0o755);
    sys_symlink(b".\0".as_ptr(), b"/tmp/cc/s\0".as_ptr());
    let r = (|| {
        cc_chain(21);
        let c = O_CREAT | O_WRONLY;
        want(b"42 links", open_err(b"/tmp/cc/t00\0", c), ELOOP)?;
        let r = open_err(b"/tmp/cc/t00\0", O_RDONLY);
        want(b"42 links plain", r, ELOOP)?;
        cc_unchain(21);
        cc_chain(20);
        want(b"40 links", open_err(b"/tmp/cc/t00\0", c), 0)?;
        let mut st = Stat::default();
        want(b"made", sys_lstat(b"/tmp/cc/new\0".as_ptr(), &mut st), 0)?;
        want(b"40 links plain", open_err(b"/tmp/cc/t00\0", O_RDONLY), 0)
    })();
    cc_unchain(21);
    sys_unlink(b"/tmp/cc/new\0".as_ptr());
    sys_unlink(b"/tmp/cc/s\0".as_ptr());
    sys_rmdir(b"/tmp/cc\0".as_ptr());
    r
}

fn cc_chain(n: usize) {
    let (mut lb, mut tb) = ([0u8; 64], [0u8; 64]);
    for i in 0..n {
        let l = numbered(&mut lb, b"/tmp/cc/t", i, b"");
        let t: &[u8] = if i + 1 == n {
            b"s/new\0"
        } else {
            numbered(&mut tb, b"s/t", i + 1, b"")
        };
        sys_unlink(l.as_ptr());
        sys_symlink(t.as_ptr(), l.as_ptr());
    }
}

fn cc_unchain(n: usize) {
    let mut lb = [0u8; 64];
    for i in 0..n {
        sys_unlink(numbered(&mut lb, b"/tmp/cc/t", i, b"").as_ptr());
    }
}

/// openat2 of `p` from `dfd` with `flags` (mode 0644) and `resolve`:
/// the errno, or 0 (the file closed)
fn open2_err(dfd: i32, p: &[u8], flags: u32, resolve: u64) -> i64 {
    let mut how = [0u8; 24];
    how[..8].copy_from_slice(&u64::from(flags).to_ne_bytes());
    how[8..16].copy_from_slice(&0o644u64.to_ne_bytes());
    how[16..].copy_from_slice(&resolve.to_ne_bytes());
    let fd = sys_openat2(dfd, p.as_ptr(), how.as_ptr(), how.len());
    if fd >= 0 {
        sys_close(fd as u64);
        return 0;
    }
    fd
}

/// An O_CREAT open scoped to its dirfd (Linux: the walk keeps the scope,
/// handle_dots and nd_jump_root under LOOKUP_IS_SCOPED; do_open skips
/// complete_walk for a made file): RESOLVE_BENEATH through "..", an
/// absolute symlink or a symlink with ".." in it is EXDEV and makes
/// nothing; RESOLVE_IN_ROOT makes the file inside the root
fn creat_scoped() -> R {
    const BENEATH: u64 = 0x08;
    const IN_ROOT: u64 = 0x10;
    sys_mkdir(b"/tmp/cs\0".as_ptr(), 0o755);
    sys_mkdir(b"/tmp/cs/d\0".as_ptr(), 0o755);
    let links: [(&[u8], &[u8]); 3] = [
        (b"/tmp/cs/o2\0", b"/tmp/cs/d/abs\0"),
        (b"../o3\0", b"/tmp/cs/d/up\0"),
        (b"/n2\0", b"/tmp/cs/d/root\0"),
    ];
    for (t, l) in links {
        sys_symlink(t.as_ptr(), l.as_ptr());
    }
    let dfd = sys_open(b"/tmp/cs/d\0".as_ptr(), O_DIRECTORY | O_RDONLY, 0);
    let r = (|| {
        if dfd < 0 {
            return Err((&b"dirfd"[..], dfd));
        }
        let (d, c) = (dfd as i32, O_CREAT | O_WRONLY);
        let mut st = Stat::default();
        want(b"beneath ..", open2_err(d, b"../o1\0", c, BENEATH), EXDEV)?;
        want(b"beneath abs", open2_err(d, b"abs\0", c, BENEATH), EXDEV)?;
        want(b"beneath up", open2_err(d, b"up\0", c, BENEATH), EXDEV)?;
        for p in [&b"/tmp/cs/o1\0"[..], b"/tmp/cs/o2\0", b"/tmp/cs/o3\0"] {
            want(b"nothing made", sys_lstat(p.as_ptr(), &mut st), ENOENT)?;
        }
        want(b"in root ..", open2_err(d, b"../n1\0", c, IN_ROOT), 0)?;
        want(b"in root abs", open2_err(d, b"root\0", c, IN_ROOT), 0)?;
        want(b"in root up", open2_err(d, b"up\0", c, IN_ROOT), 0)?;
        for p in [&b"/tmp/cs/d/n1\0"[..], b"/tmp/cs/d/n2\0", b"/tmp/cs/d/o3\0"] {
            want(b"made inside", sys_lstat(p.as_ptr(), &mut st), 0)?;
        }
        let r = sys_lstat(b"/tmp/cs/o3\0".as_ptr(), &mut st);
        want(b"none outside", r, ENOENT)
    })();
    if dfd >= 0 {
        sys_close(dfd as u64);
    }
    for (_, l) in links {
        sys_unlink(l.as_ptr());
    }
    for p in [
        &b"/tmp/cs/o1\0"[..],
        b"/tmp/cs/o2\0",
        b"/tmp/cs/o3\0",
        b"/tmp/cs/d/n1\0",
        b"/tmp/cs/d/n2\0",
        b"/tmp/cs/d/o3\0",
    ] {
        sys_unlink(p.as_ptr());
    }
    sys_rmdir(b"/tmp/cs/d\0".as_ptr());
    sys_rmdir(b"/tmp/cs\0".as_ptr());
    r
}
