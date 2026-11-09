//! openat2(2)'s RESOLVE_* walk (Linux path_init, nd_jump_root,
//! follow_dotdot, handle_mounts, pick_link, nd_jump_link, LOOKUP_CACHED;
//! cases from tools/testing/selftests/filesystems/openat2/resolve_test.c),
//! on a fresh ramfs with a tmpfs inside, on both kernels:
//!
//! - BENEATH: leaving dirfd ("..", an absolute path or symlink) is EXDEV
//! - IN_ROOT: dirfd is the root: ".." stops there, absolute paths and
//!   symlinks start there, O_CREAT included
//! - NO_XDEV: crossing a mount, down, up, by symlink or magic link, is
//!   EXDEV; a magic link within the mount is fine
//! - NO_MAGICLINKS: a /proc magic link is ELOOP unless it is the last
//!   component and not followed
//! - NO_SYMLINKS: any symlink is ELOOP unless last and not followed
//! - CACHED: the dcache alone, else EAGAIN
//!
//! The root directory:
//! ```text
//! procexe -> /proc/self/exe      procroot -> /proc/self/root
//! root/   mnt/ [tmpfs]: self -> ../mnt/, absself -> /mnt/
//! etc/passwd     creatlink -> /newfile3
//! reletc -> etc/   relsym -> etc/passwd   absetc -> /etc/
//! abssym -> /etc/passwd   abscheeky -> /cheeky
//! cheeky/: absself -> /, self -> ../../root/, garbageself -> /../../root/,
//!   passwd -> ../cheeky/../etc/../etc/passwd,
//!   abspasswd -> /../cheeky/../etc/../etc/passwd,
//!   dotdotlink -> ../../../../../../../../../../../../../../etc/passwd,
//!   garbagelink -> /../../../../../../../../../../../../../../etc/passwd
//! ```

use crate::harness::{R, check, report_r};
use hk_syscall::{
    O_CREAT, O_DIRECTORY, O_NOFOLLOW, O_PATH, O_RDONLY, O_WRONLY, Stat, sys_close, sys_dup,
    sys_fstat, sys_getpid, sys_mkdir, sys_mount, sys_open, sys_openat, sys_openat2, sys_rmdir,
    sys_symlink, sys_umount2,
};

const EXDEV: i64 = -18;
const ELOOP: i64 = -40;
const EAGAIN: i64 = -11;
const ENOENT: i64 = -2;
const NO_XDEV: u64 = 0x01;
const NO_MAGICLINKS: u64 = 0x02;
const NO_SYMLINKS: u64 = 0x04;
const BENEATH: u64 = 0x08;
const IN_ROOT: u64 = 0x10;
const CACHED: u64 = 0x20;

const TOP: &[u8] = b"/tmp/rs\0";
const ROOT: &[u8] = b"/tmp/rs/root\0";
const MNT: &[u8] = b"/tmp/rs/root/mnt\0";

/// Where a case must end, or its errno
#[derive(Clone, Copy)]
enum Want {
    /// The root (dirfd) itself
    Root,
    /// This path under the root
    At(&'static [u8]),
    /// This absolute path
    Abs(&'static [u8]),
    No(i64),
}
use Want::*;

/// One resolve_test case: the dirfd (None: the root), the path, extra
/// open flags, the resolve flags and the result
type Case = (Option<&'static [u8]>, &'static [u8], u32, u64, Want);

pub fn run_tests() {
    sys_mkdir(TOP.as_ptr(), 0o755);
    if sys_mount(b"none\0".as_ptr(), TOP.as_ptr(), b"ramfs\0".as_ptr(), 0, 0) != 0 {
        report_r(b"RESOLVE_SETUP", Err((b"mount", -1)));
        return;
    }
    let r = setup();
    let rootfd = sys_open(ROOT.as_ptr(), O_PATH | O_DIRECTORY, 0) as i32;
    if r.is_err() || rootfd < 0 {
        report_r(b"RESOLVE_SETUP", r.and(Err((b"rootfd", i64::from(rootfd)))));
    } else {
        run(rootfd);
    }
    sys_close(rootfd as u64);
    sys_umount2(MNT.as_ptr(), 0);
    sys_umount2(TOP.as_ptr(), 0);
    sys_rmdir(TOP.as_ptr());
}

fn run(rootfd: i32) {
    report_r(b"RESOLVE_BENEATH", cases(rootfd, &BENEATH_CASES));
    report_r(b"RESOLVE_IN_ROOT", cases(rootfd, &IN_ROOT_CASES));
    report_r(b"RESOLVE_IN_ROOT_CREAT", cases(rootfd, &CREAT_CASES));
    report_r(b"RESOLVE_NO_XDEV", no_xdev(rootfd));
    report_r(b"RESOLVE_NO_MAGICLINKS", no_magiclinks(rootfd));
    report_r(b"RESOLVE_NO_SYMLINKS", cases(rootfd, &NO_SYMLINKS_CASES));
    report_r(b"RESOLVE_CACHED", cached(rootfd));
}

/// "/tmp/rs/root/<p>\0" in `b`
fn at<'a>(b: &'a mut [u8; 128], p: &[u8]) -> &'a [u8] {
    let base = &ROOT[..ROOT.len() - 1];
    b[..base.len()].copy_from_slice(base);
    b[base.len()] = b'/';
    let n = base.len() + 1;
    b[n..n + p.len()].copy_from_slice(p);
    b[n + p.len()] = 0;
    &b[..=n + p.len()]
}

fn setup() -> R {
    let r = sys_mkdir(ROOT.as_ptr(), 0o755);
    check(b"mkdir root", r == 0, r)?;
    let mut b = [0u8; 128];
    for d in [&b"root"[..], b"mnt", b"etc", b"cheeky"] {
        let r = sys_mkdir(at(&mut b, d).as_ptr(), 0o755);
        check(b"mkdir", r == 0, r)?;
    }
    let r = sys_mount(b"tmpfs\0".as_ptr(), MNT.as_ptr(), b"tmpfs\0".as_ptr(), 0, 0);
    check(b"mount tmpfs", r == 0, r)?;
    let fd = sys_open(
        at(&mut b, b"etc/passwd").as_ptr(),
        O_CREAT | O_WRONLY,
        0o644,
    );
    check(b"passwd", fd >= 0, fd)?;
    sys_close(fd as u64);
    let links: [(&[u8], &[u8]); 17] = [
        (b"/proc/self/exe\0", b"procexe"),
        (b"/proc/self/root\0", b"procroot"),
        (b"../mnt/\0", b"mnt/self"),
        (b"/mnt/\0", b"mnt/absself"),
        (b"/newfile3\0", b"creatlink"),
        (b"etc/\0", b"reletc"),
        (b"etc/passwd\0", b"relsym"),
        (b"/etc/\0", b"absetc"),
        (b"/etc/passwd\0", b"abssym"),
        (b"/cheeky\0", b"abscheeky"),
        (b"/\0", b"cheeky/absself"),
        (b"../../root/\0", b"cheeky/self"),
        (b"/../../root/\0", b"cheeky/garbageself"),
        (b"../cheeky/../etc/../etc/passwd\0", b"cheeky/passwd"),
        (b"/../cheeky/../etc/../etc/passwd\0", b"cheeky/abspasswd"),
        (
            b"../../../../../../../../../../../../../../etc/passwd\0",
            b"cheeky/dotdotlink",
        ),
        (
            b"/../../../../../../../../../../../../../../etc/passwd\0",
            b"cheeky/garbagelink",
        ),
    ];
    for (target, name) in links {
        let r = sys_symlink(target.as_ptr(), at(&mut b, name).as_ptr());
        check(b"symlink", r == 0, r)?;
    }
    Ok(())
}

/// openat2 from `dfd` with `flags`, `mode` and `resolve`
fn open2(dfd: i32, p: &[u8], flags: u64, mode: u64, resolve: u64) -> i64 {
    let mut b = [0u8; 24];
    b[..8].copy_from_slice(&flags.to_ne_bytes());
    b[8..16].copy_from_slice(&mode.to_ne_bytes());
    b[16..].copy_from_slice(&resolve.to_ne_bytes());
    sys_openat2(dfd, p.as_ptr(), b.as_ptr(), 24)
}

/// (st_dev, st_ino) of `fd`; closes it
fn id(fd: i64) -> (u64, u64) {
    let mut st = Stat::default();
    sys_fstat(fd as i32, &mut st);
    sys_close(fd as u64);
    (st.st_dev, st.st_ino)
}

/// The identity `w` names
fn want_id(rootfd: i32, w: Want) -> (u64, u64) {
    let fd = match w {
        Root => sys_dup(rootfd),
        At(p) => sys_openat(rootfd, p.as_ptr(), O_PATH | O_NOFOLLOW, 0),
        Abs(p) => sys_open(p.as_ptr(), O_PATH, 0),
        No(_) => return (0, 0),
    };
    if fd < 0 { (0, fd as u64) } else { id(fd) }
}

/// Run one case (O_PATH unless O_CREAT, as resolve_test.c): its index
/// and errno or wrong result on failure
fn one(rootfd: i32, c: &Case) -> Result<(), i64> {
    let (dir, path, extra, resolve, want) = *c;
    let dfd = match dir {
        Some(d) => sys_openat(rootfd, d.as_ptr(), O_PATH | O_DIRECTORY, 0) as i32,
        None => sys_dup(rootfd) as i32,
    };
    if dfd < 0 {
        return Err(1000 + i64::from(dfd));
    }
    let flags = if extra & O_CREAT != 0 {
        extra
    } else {
        extra | O_PATH
    };
    let mode = if extra & O_CREAT != 0 { 0o700 } else { 0 };
    let fd = open2(dfd, path, u64::from(flags), mode, resolve);
    sys_close(dfd as u64);
    match want {
        No(e) => {
            if fd >= 0 {
                sys_close(fd as u64);
            }
            if fd == e { Ok(()) } else { Err(fd) }
        }
        w if fd < 0 => {
            let _ = w;
            Err(fd)
        }
        w => {
            if id(fd) == want_id(rootfd, w) {
                Ok(())
            } else {
                Err(2000)
            }
        }
    }
}

fn cases(rootfd: i32, list: &[Case]) -> R {
    for (i, c) in list.iter().enumerate() {
        one(rootfd, c).map_err(|e| (&b"case"[..], i as i64 * 100_000 + e))?;
    }
    Ok(())
}

const BENEATH_CASES: [Case; 24] = [
    (None, b"/\0", 0, BENEATH, No(EXDEV)),
    (None, b"cheeky/absself\0", 0, BENEATH, No(EXDEV)),
    (None, b"abscheeky/absself\0", 0, BENEATH, No(EXDEV)),
    (None, b"..\0", 0, BENEATH, No(EXDEV)),
    (None, b"../root/\0", 0, BENEATH, No(EXDEV)),
    (None, b"cheeky/self\0", 0, BENEATH, No(EXDEV)),
    (None, b"abscheeky/self\0", 0, BENEATH, No(EXDEV)),
    (None, b"cheeky/garbageself\0", 0, BENEATH, No(EXDEV)),
    (None, b"abscheeky/garbageself\0", 0, BENEATH, No(EXDEV)),
    (None, b"root\0", 0, BENEATH, At(b"root\0")),
    (None, b"etc\0", 0, BENEATH, At(b"etc\0")),
    (None, b"etc/passwd\0", 0, BENEATH, At(b"etc/passwd\0")),
    (None, b"relsym\0", 0, BENEATH, At(b"etc/passwd\0")),
    (None, b"cheeky/passwd\0", 0, BENEATH, At(b"etc/passwd\0")),
    (None, b"abscheeky/passwd\0", 0, BENEATH, No(EXDEV)),
    (None, b"abssym\0", 0, BENEATH, No(EXDEV)),
    (None, b"/etc/passwd\0", 0, BENEATH, No(EXDEV)),
    (None, b"cheeky/abspasswd\0", 0, BENEATH, No(EXDEV)),
    (None, b"abscheeky/abspasswd\0", 0, BENEATH, No(EXDEV)),
    (None, b"cheeky/dotdotlink\0", 0, BENEATH, No(EXDEV)),
    (None, b"abscheeky/dotdotlink\0", 0, BENEATH, No(EXDEV)),
    (None, b"cheeky/garbagelink\0", 0, BENEATH, No(EXDEV)),
    (None, b"abscheeky/garbagelink\0", 0, BENEATH, No(EXDEV)),
    (Some(b"/proc\0"), b"self/cwd\0", 0, BENEATH, No(EXDEV)),
];

const IN_ROOT_CASES: [Case; 25] = [
    (None, b"/\0", 0, IN_ROOT, Root),
    (None, b"cheeky/absself\0", 0, IN_ROOT, Root),
    (None, b"abscheeky/absself\0", 0, IN_ROOT, Root),
    (None, b"..\0", 0, IN_ROOT, Root),
    (None, b"../root/\0", 0, IN_ROOT, At(b"root\0")),
    (None, b"cheeky/self\0", 0, IN_ROOT, At(b"root\0")),
    (None, b"cheeky/garbageself\0", 0, IN_ROOT, At(b"root\0")),
    (None, b"abscheeky/garbageself\0", 0, IN_ROOT, At(b"root\0")),
    (None, b"root\0", 0, IN_ROOT, At(b"root\0")),
    (None, b"etc\0", 0, IN_ROOT, At(b"etc\0")),
    (None, b"etc/passwd\0", 0, IN_ROOT, At(b"etc/passwd\0")),
    (None, b"relsym\0", 0, IN_ROOT, At(b"etc/passwd\0")),
    (None, b"cheeky/passwd\0", 0, IN_ROOT, At(b"etc/passwd\0")),
    (None, b"abscheeky/passwd\0", 0, IN_ROOT, At(b"etc/passwd\0")),
    (None, b"abssym\0", 0, IN_ROOT, At(b"etc/passwd\0")),
    (None, b"/etc/passwd\0", 0, IN_ROOT, At(b"etc/passwd\0")),
    (None, b"cheeky/abspasswd\0", 0, IN_ROOT, At(b"etc/passwd\0")),
    (
        None,
        b"abscheeky/abspasswd\0",
        0,
        IN_ROOT,
        At(b"etc/passwd\0"),
    ),
    (
        None,
        b"cheeky/dotdotlink\0",
        0,
        IN_ROOT,
        At(b"etc/passwd\0"),
    ),
    (
        None,
        b"abscheeky/dotdotlink\0",
        0,
        IN_ROOT,
        At(b"etc/passwd\0"),
    ),
    (
        None,
        b"/../../../../abscheeky/dotdotlink\0",
        0,
        IN_ROOT,
        At(b"etc/passwd\0"),
    ),
    (
        None,
        b"cheeky/garbagelink\0",
        0,
        IN_ROOT,
        At(b"etc/passwd\0"),
    ),
    (
        None,
        b"abscheeky/garbagelink\0",
        0,
        IN_ROOT,
        At(b"etc/passwd\0"),
    ),
    (
        None,
        b"/../../../../abscheeky/garbagelink\0",
        0,
        IN_ROOT,
        At(b"etc/passwd\0"),
    ),
    // A magic link is no way out either
    (Some(b"/proc\0"), b"self/root\0", 0, IN_ROOT, No(EXDEV)),
];

/// O_CREAT follows a trailing symlink inside the root
const CREAT_CASES: [Case; 3] = [
    (None, b"newfile1\0", O_CREAT, IN_ROOT, At(b"newfile1\0")),
    (None, b"/newfile2\0", O_CREAT, IN_ROOT, At(b"newfile2\0")),
    (None, b"/creatlink\0", O_CREAT, IN_ROOT, At(b"newfile3\0")),
];

const NO_XDEV_CASES: [Case; 12] = [
    (None, b"mnt\0", 0, NO_XDEV, No(EXDEV)),
    (None, b"mnt/\0", 0, NO_XDEV, No(EXDEV)),
    (None, b"mnt/.\0", 0, NO_XDEV, No(EXDEV)),
    (Some(b"mnt\0"), b".\0", 0, NO_XDEV, At(b"mnt\0")),
    (Some(b"mnt\0"), b"..\0", 0, NO_XDEV, No(EXDEV)),
    (Some(b"mnt\0"), b"../mnt\0", 0, NO_XDEV, No(EXDEV)),
    (Some(b"mnt\0"), b"self\0", 0, NO_XDEV, No(EXDEV)),
    (Some(b"mnt\0"), b"absself\0", 0, NO_XDEV, No(EXDEV)),
    (Some(b"mnt\0"), b"/\0", 0, NO_XDEV, Abs(b"/\0")),
    (Some(b"/\0"), b"/\0", 0, NO_XDEV, Abs(b"/\0")),
    (None, b"/proc/1\0", 0, NO_XDEV, No(EXDEV)),
    (None, b"/tmp/rs\0", 0, NO_XDEV, No(EXDEV)),
];

/// The table, then magic links: to another mount EXDEV, within /proc
/// fine (an fd of /proc itself)
fn no_xdev(rootfd: i32) -> R {
    cases(rootfd, &NO_XDEV_CASES)?;
    let proc = sys_open(b"/proc\0".as_ptr(), O_PATH | O_DIRECTORY, 0) as i32;
    check(b"/proc", proc >= 0, i64::from(proc))?;
    let r = magic_xdev(rootfd, proc);
    sys_close(proc as u64);
    r
}

fn magic_xdev(rootfd: i32, proc: i32) -> R {
    for p in [&b"self/root\0"[..], b"self/cwd\0"] {
        let r = open2(proc, p, u64::from(O_PATH), 0, NO_XDEV);
        if r >= 0 {
            sys_close(r as u64);
        }
        check(b"magic to /", r == EXDEV, r)?;
    }
    let hard = sys_dup(proc);
    let mut name = *b"self/fd/\0\0\0\0\0\0";
    let k = decimal(&mut name[8..], hard);
    name[8 + k] = 0;
    let fd = open2(proc, &name, u64::from(O_PATH), 0, NO_XDEV);
    sys_close(hard as u64);
    check(b"magic in /proc", fd >= 0, fd)?;
    let same = id(fd) == want_id(rootfd, Abs(b"/proc\0"));
    check(b"magic in /proc: /proc", same, 0)
}

/// Decimal `v` into `b`: its length
fn decimal(b: &mut [u8], v: i64) -> usize {
    let mut d = [0u8; 12];
    let (mut v, mut k) = (v as u64, 0);
    loop {
        d[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..k {
        b[i] = d[k - 1 - i];
    }
    k
}

const NO_MAGICLINKS_CASES: [Case; 6] = [
    (None, b"relsym\0", 0, NO_MAGICLINKS, At(b"etc/passwd\0")),
    (None, b"procexe\0", 0, NO_MAGICLINKS, No(ELOOP)),
    (None, b"/proc/self/exe\0", 0, NO_MAGICLINKS, No(ELOOP)),
    (None, b"procroot/etc\0", 0, NO_MAGICLINKS, No(ELOOP)),
    (None, b"/proc/self/root/etc\0", 0, NO_MAGICLINKS, No(ELOOP)),
    (
        None,
        b"/proc/self/root/etc\0",
        O_NOFOLLOW,
        NO_MAGICLINKS,
        No(ELOOP),
    ),
];

/// The table, then /proc/self/exe with O_NOFOLLOW: the link itself
fn no_magiclinks(rootfd: i32) -> R {
    cases(rootfd, &NO_MAGICLINKS_CASES)?;
    let fd = open2(
        rootfd,
        b"/proc/self/exe\0",
        u64::from(O_PATH | O_NOFOLLOW),
        0,
        NO_MAGICLINKS,
    );
    check(b"O_NOFOLLOW", fd >= 0, fd)?;
    let mut p = *b"/proc/\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    let k = decimal(&mut p[6..], sys_getpid());
    p[6 + k..6 + k + 5].copy_from_slice(b"/exe\0");
    let mut st = Stat::default();
    let link = sys_open(p.as_ptr(), O_PATH | O_NOFOLLOW, 0);
    sys_fstat(link as i32, &mut st);
    sys_close(link as u64);
    let same = id(fd) == (st.st_dev, st.st_ino);
    check(b"O_NOFOLLOW: the link", link >= 0 && same, link)
}

const NO_SYMLINKS_CASES: [Case; 16] = [
    (None, b".\0", 0, NO_SYMLINKS, Root),
    (None, b"root\0", 0, NO_SYMLINKS, At(b"root\0")),
    (None, b"etc\0", 0, NO_SYMLINKS, At(b"etc\0")),
    (None, b"etc/passwd\0", 0, NO_SYMLINKS, At(b"etc/passwd\0")),
    (None, b"relsym\0", 0, NO_SYMLINKS, No(ELOOP)),
    (None, b"reletc/passwd\0", 0, NO_SYMLINKS, No(ELOOP)),
    (None, b"abssym\0", 0, NO_SYMLINKS, No(ELOOP)),
    (None, b"absetc/passwd\0", 0, NO_SYMLINKS, No(ELOOP)),
    (None, b"cheeky/garbagelink\0", 0, NO_SYMLINKS, No(ELOOP)),
    (None, b"abscheeky/garbagelink\0", 0, NO_SYMLINKS, No(ELOOP)),
    (None, b"abscheeky/absself\0", 0, NO_SYMLINKS, No(ELOOP)),
    (None, b"relsym\0", O_NOFOLLOW, NO_SYMLINKS, At(b"relsym\0")),
    (None, b"abssym\0", O_NOFOLLOW, NO_SYMLINKS, At(b"abssym\0")),
    (
        None,
        b"cheeky/garbagelink\0",
        O_NOFOLLOW,
        NO_SYMLINKS,
        At(b"cheeky/garbagelink\0"),
    ),
    (
        None,
        b"abscheeky/absself\0",
        O_NOFOLLOW,
        NO_SYMLINKS,
        No(ELOOP),
    ),
    (
        None,
        b"abscheeky/garbagelink\0",
        O_NOFOLLOW,
        NO_SYMLINKS,
        No(ELOOP),
    ),
];

/// RESOLVE_CACHED: a path the dcache holds opens; a name never looked
/// up is EAGAIN, and stays so after a failed lookup (ramfs keeps no
/// negative entry: always_delete_dentry); a /proc fd link (revalidated,
/// and magic) is EAGAIN
fn cached(rootfd: i32) -> R {
    let mut b = [0u8; 128];
    let fd = sys_open(at(&mut b, b"etc/passwd").as_ptr(), O_RDONLY, 0);
    check(b"warm", fd >= 0, fd)?;
    sys_close(fd as u64);
    let fd = open2(rootfd, b"etc/passwd\0", u64::from(O_PATH), 0, CACHED);
    check(b"cached path", fd >= 0, fd)?;
    let same = id(fd) == want_id(rootfd, At(b"etc/passwd\0"));
    check(b"cached path: same file", same, 0)?;
    let r = open2(rootfd, b"etc/nosuch\0", u64::from(O_PATH), 0, CACHED);
    check(b"never looked up", r == EAGAIN, r)?;
    let r = sys_open(at(&mut b, b"etc/nosuch").as_ptr(), O_RDONLY, 0);
    check(b"lookup", r == ENOENT, r)?;
    let r = open2(rootfd, b"etc/nosuch\0", u64::from(O_PATH), 0, CACHED);
    check(b"no negative entry", r == EAGAIN, r)?;
    let r = open2(rootfd, b"/proc/self/fd/0\0", u64::from(O_PATH), 0, CACHED);
    if r >= 0 {
        sys_close(r as u64);
    }
    check(b"/proc fd", r == EAGAIN, r)
}
