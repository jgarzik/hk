//! Mount tree semantics (Linux fs/namespace.c): a walk lands on the
//! topmost mount stacked on a directory, mounts nest inside mounts, and
//! a namespace copy's umount leaves the original namespace alone. Test
//! mounts are ramfs on both kernels.

use super::helpers::{print, print_num, println};
use hk_syscall::{CLONE_NEWNS, O_CREAT, O_WRONLY, Stat, sys_chdir, sys_close, sys_exit, sys_fork, sys_getcwd, sys_link, sys_mkdir, sys_mount, sys_open, sys_readlink, sys_rename, sys_rmdir, sys_stat, sys_symlink, sys_umount2, sys_unlink, sys_unshare, sys_wait4};

const ENOENT: i64 = -2;
const EBUSY: i64 = -16;
const EXDEV: i64 = -18;
const EINVAL: i64 = -22;

pub fn run_tests() {
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777); // hk boots without /tmp
    report(b"MOUNT_NESTED", nested());
    report(b"UNSHARE_UMOUNT_ISOLATED", unshare_umount());
    report(b"RENAME_PINNED_TRAP", pinned_trap());
    report(b"RENAME_ANCESTOR_MOUNT", ancestor_mount());
    report(b"DOTDOT_MOUNT", dotdot_mount());
    report(b"GETCWD_IN_MOUNT", getcwd_in_mount());
    report(b"MOUNT_NESTED_BUSY", nested_busy());
    report(b"EXDEV_SAME_SB", exdev_same_sb());
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

fn ramfs(target: &[u8]) -> i64 {
    sys_mount(b"none\0".as_ptr(), target.as_ptr(), b"ramfs\0".as_ptr(), 0, 0)
}

/// st_dev of `p`, or the errno
fn dev(p: &[u8]) -> Result<u64, i64> {
    // SAFETY: Stat is plain integers
    let mut st: Stat = unsafe { core::mem::zeroed() };
    match sys_stat(p.as_ptr(), &mut st) {
        0 => Ok(st.st_dev),
        e => Err(e),
    }
}

fn touch(p: &[u8]) -> i64 {
    let fd = sys_open(p.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd >= 0 {
        sys_close(fd as u64);
    }
    fd
}

fn check(what: &'static [u8], ok: bool, got: i64) -> R {
    if ok { Ok(()) } else { Err((what, got)) }
}

fn nested() -> R {
    let mn = b"/tmp/mn\0";
    sys_mkdir(mn.as_ptr(), 0o755);
    let r = nested_ops(mn);
    // Whatever is still mounted, innermost first
    sys_umount2(b"/tmp/mn/sub\0".as_ptr(), 0);
    for _ in 0..2 {
        sys_umount2(mn.as_ptr(), 0);
    }
    sys_rmdir(mn.as_ptr());
    r
}

fn nested_ops(mn: &[u8]) -> R {
    let d0 = dev(b"/tmp\0").map_err(|e| (&b"stat /tmp"[..], e))?;
    check(b"mount 1", ramfs(mn) == 0, -1)?;
    let d1 = dev(mn).map_err(|e| (&b"stat 1"[..], e))?;
    check(b"dev 1", d1 != d0, d1 as i64)?;
    check(b"touch a", touch(b"/tmp/mn/a\0") >= 0, -1)?;
    // A second mount on the same directory covers the first
    check(b"mount 2", ramfs(mn) == 0, -1)?;
    let d2 = dev(mn).map_err(|e| (&b"stat 2"[..], e))?;
    check(b"dev 2", d2 != d1 && d2 != d0, d2 as i64)?;
    check(b"a hidden", dev(b"/tmp/mn/a\0") == Err(ENOENT), -1)?;
    // A mount inside the top one
    sys_mkdir(b"/tmp/mn/sub\0".as_ptr(), 0o755);
    check(b"mount sub", ramfs(b"/tmp/mn/sub\0") == 0, -1)?;
    let d3 = dev(b"/tmp/mn/sub\0").map_err(|e| (&b"stat sub"[..], e))?;
    check(b"dev sub", d3 != d2, d3 as i64)?;
    check(b"umount sub", sys_umount2(b"/tmp/mn/sub\0".as_ptr(), 0) == 0, -1)?;
    check(b"sub uncovered", dev(b"/tmp/mn/sub\0") == Ok(d2), -1)?;
    sys_rmdir(b"/tmp/mn/sub\0".as_ptr());
    // Unmounting the top one uncovers the first, with its file
    let r = sys_umount2(mn.as_ptr(), 0);
    check(b"umount 2", r == 0, r)?;
    check(b"dev 1 again", dev(mn) == Ok(d1), -1)?;
    check(b"a back", dev(b"/tmp/mn/a\0") == Ok(d1), -1)?;
    let r = sys_umount2(mn.as_ptr(), 0);
    check(b"umount 1", r == 0, r)?;
    check(b"dev 0 again", dev(mn) == Ok(d0), -1)
}

fn unshare_umount() -> R {
    let ui = b"/tmp/ui\0";
    sys_mkdir(ui.as_ptr(), 0o755);
    if ramfs(ui) != 0 {
        sys_rmdir(ui.as_ptr());
        return Err((b"mount", -1));
    }
    let r = unshare_umount_ops(ui);
    sys_umount2(ui.as_ptr(), 0);
    sys_rmdir(ui.as_ptr());
    r
}

fn unshare_umount_ops(ui: &[u8]) -> R {
    check(b"touch", touch(b"/tmp/ui/f\0") >= 0, -1)?;
    let pid = sys_fork();
    if pid == 0 {
        // The copy's umount hides the file in this namespace only
        let code = if sys_unshare(CLONE_NEWNS) != 0 {
            1
        } else if sys_umount2(ui.as_ptr(), 0) != 0 {
            2
        } else if dev(b"/tmp/ui/f\0") != Err(ENOENT) {
            3
        } else {
            0
        };
        sys_exit(code);
    }
    let mut ws = 0i32;
    sys_wait4(pid, &mut ws, 0, 0);
    check(b"child", ws == 0, (ws >> 8) as i64)?;
    check(b"still mounted here", dev(b"/tmp/ui/f\0").is_ok(), -1)
}

/// A rename moves the dentry a cwd holds (Linux d_move): from inside
/// t/a/b, after a -> c, moving c into "z" (its own subtree) is EINVAL,
/// and getcwd shows the new path
fn pinned_trap() -> R {
    for p in [&b"/tmp/t\0"[..], b"/tmp/t/a\0", b"/tmp/t/a/b\0"] {
        sys_mkdir(p.as_ptr(), 0o755);
    }
    let r = pinned_trap_ops();
    sys_chdir(b"/\0".as_ptr());
    for p in [&b"/tmp/t/c/b/z\0"[..], b"/tmp/t/c/b\0", b"/tmp/t/c\0", b"/tmp/t/a/b\0"] {
        sys_rmdir(p.as_ptr());
    }
    sys_rmdir(b"/tmp/t/a\0".as_ptr());
    sys_rmdir(b"/tmp/t\0".as_ptr());
    r
}

fn pinned_trap_ops() -> R {
    let r = sys_chdir(b"/tmp/t/a/b\0".as_ptr());
    check(b"chdir", r == 0, r)?;
    let r = sys_rename(b"/tmp/t/a\0".as_ptr(), b"/tmp/t/c\0".as_ptr());
    check(b"rename a c", r == 0, r)?;
    let r = sys_rename(b"/tmp/t/c\0".as_ptr(), b"z\0".as_ptr());
    check(b"rename into own subtree", r == EINVAL, r)?;
    let mut buf = [0u8; 64];
    let n = sys_getcwd(buf.as_mut_ptr(), buf.len());
    let want = b"/tmp/t/c/b\0";
    check(b"getcwd", n == want.len() as i64 && buf[..want.len()] == *want, n)
}

/// A mount below a renamed directory stays reachable at the new path
fn ancestor_mount() -> R {
    for p in [&b"/tmp/ra\0"[..], b"/tmp/ra/x\0", b"/tmp/ra/x/m\0"] {
        sys_mkdir(p.as_ptr(), 0o755);
    }
    let r = ancestor_mount_ops();
    for p in [&b"/tmp/ra/y/m\0"[..], b"/tmp/ra/x/m\0"] {
        sys_unlink(b"/tmp/ra/y/m/f\0".as_ptr());
        sys_umount2(p.as_ptr(), 0);
        sys_rmdir(p.as_ptr());
    }
    for p in [&b"/tmp/ra/y\0"[..], b"/tmp/ra/x\0", b"/tmp/ra\0"] {
        sys_rmdir(p.as_ptr());
    }
    r
}

fn ancestor_mount_ops() -> R {
    check(b"mount", ramfs(b"/tmp/ra/x/m\0") == 0, -1)?;
    let dm = dev(b"/tmp/ra/x/m\0").map_err(|e| (&b"stat m"[..], e))?;
    check(b"touch", touch(b"/tmp/ra/x/m/f\0") >= 0, -1)?;
    let r = sys_rename(b"/tmp/ra/x\0".as_ptr(), b"/tmp/ra/y\0".as_ptr());
    check(b"rename x y", r == 0, r)?;
    check(b"m still mounted", dev(b"/tmp/ra/y/m\0") == Ok(dm), -1)?;
    check(b"file reachable", dev(b"/tmp/ra/y/m/f\0") == Ok(dm), -1)
}

/// st_dev and st_ino of `p`
fn id(p: &[u8]) -> Result<(u64, u64), i64> {
    // SAFETY: Stat is plain integers
    let mut st: Stat = unsafe { core::mem::zeroed() };
    match sys_stat(p.as_ptr(), &mut st) {
        0 => Ok((st.st_dev, st.st_ino)),
        e => Err(e),
    }
}

/// `want` (NUL included) is what getcwd returns
fn cwd_is(want: &[u8]) -> bool {
    let mut buf = [0u8; 64];
    let n = sys_getcwd(buf.as_mut_ptr(), buf.len());
    n == want.len() as i64 && buf[..want.len()] == *want
}

/// ".." at a mount's root leaves the mount (Linux follow_dotdot): to
/// the directory holding the mountpoint, by stat, chdir and getcwd
fn dotdot_mount() -> R {
    let dm = b"/tmp/dm\0";
    sys_mkdir(dm.as_ptr(), 0o755);
    let r = (|| {
        check(b"mount", ramfs(dm) == 0, -1)?;
        let tmp = id(b"/tmp\0").map_err(|e| (&b"stat /tmp"[..], e))?;
        check(b"stat dm/..", id(b"/tmp/dm/..\0") == Ok(tmp), -1)?;
        let root = id(b"/\0").map_err(|e| (&b"stat /"[..], e))?;
        check(b"stat /proc/..", id(b"/proc/..\0") == Ok(root), -1)?;
        check(b"chdir dm", sys_chdir(dm.as_ptr()) == 0, -1)?;
        check(b"chdir ..", sys_chdir(b"..\0".as_ptr()) == 0, -1)?;
        check(b"getcwd", cwd_is(b"/tmp\0"), -1)
    })();
    sys_chdir(b"/\0".as_ptr());
    sys_umount2(dm.as_ptr(), 0);
    sys_rmdir(dm.as_ptr());
    r
}

/// getcwd and /proc/self/fd links name files inside a mount by their
/// full path (Linux d_path climbs mounts); a removed file's link says
/// " (deleted)", a removed cwd is ENOENT
fn getcwd_in_mount() -> R {
    let gm = b"/tmp/gm\0";
    sys_mkdir(gm.as_ptr(), 0o755);
    let r = (|| {
        check(b"mount", ramfs(gm) == 0, -1)?;
        sys_mkdir(b"/tmp/gm/sub\0".as_ptr(), 0o755);
        check(b"chdir", sys_chdir(b"/tmp/gm/sub\0".as_ptr()) == 0, -1)?;
        check(b"getcwd", cwd_is(b"/tmp/gm/sub\0"), -1)?;
        let fd = sys_open(b"f\0".as_ptr(), O_CREAT | O_WRONLY, 0o644);
        check(b"create", fd >= 0, fd)?;
        let mut link = *b"/proc/self/fd/\0\0\0\0";
        let mut n = fd as u32;
        let mut digits = [0u8; 4];
        let mut k = 0;
        loop {
            digits[k] = b'0' + (n % 10) as u8;
            k += 1;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        for i in 0..k {
            link[14 + i] = digits[k - 1 - i];
        }
        let mut buf = [0u8; 64];
        let r = sys_readlink(link.as_ptr(), buf.as_mut_ptr(), buf.len() as u64);
        let want = b"/tmp/gm/sub/f";
        let ok = r == want.len() as i64 && buf[..want.len()] == *want;
        sys_unlink(b"f\0".as_ptr());
        let r2 = sys_readlink(link.as_ptr(), buf.as_mut_ptr(), buf.len() as u64);
        let del = b"/tmp/gm/sub/f (deleted)";
        let ok2 = r2 == del.len() as i64 && buf[..del.len()] == *del;
        sys_close(fd as u64);
        check(b"PROC_FD_LINK_MOUNT", ok, r)?;
        check(b"fd link deleted", ok2, r2)?;
        sys_rmdir(b"/tmp/gm/sub\0".as_ptr());
        let mut b2 = [0u8; 64];
        let r = sys_getcwd(b2.as_mut_ptr(), b2.len());
        check(b"getcwd removed", r == ENOENT, r)
    })();
    sys_chdir(b"/\0".as_ptr());
    sys_rmdir(b"/tmp/gm/sub\0".as_ptr());
    sys_umount2(gm.as_ptr(), 0);
    sys_rmdir(gm.as_ptr());
    r
}

/// A mount with a mount inside it is busy (Linux may_umount_tree)
fn nested_busy() -> R {
    let nb = b"/tmp/nb\0";
    sys_mkdir(nb.as_ptr(), 0o755);
    let r = (|| {
        check(b"mount", ramfs(nb) == 0, -1)?;
        sys_mkdir(b"/tmp/nb/in\0".as_ptr(), 0o755);
        check(b"mount in", ramfs(b"/tmp/nb/in\0") == 0, -1)?;
        let r = sys_umount2(nb.as_ptr(), 0);
        check(b"umount outer", r == EBUSY, r)?;
        let r = sys_umount2(b"/tmp/nb/in\0".as_ptr(), 0);
        check(b"umount inner", r == 0, r)?;
        let r = sys_umount2(nb.as_ptr(), 0);
        check(b"umount outer after", r == 0, r)
    })();
    sys_umount2(b"/tmp/nb/in\0".as_ptr(), 0);
    sys_umount2(nb.as_ptr(), 0);
    sys_rmdir(b"/tmp/nb/in\0".as_ptr());
    sys_rmdir(nb.as_ptr());
    r
}

/// link and rename across two mounts of one superblock (devtmpfs, a
/// single instance on both kernels) are EXDEV (Linux compares mounts);
/// EXDEV comes before the source lookup, so nothing in /dev changes
fn exdev_same_sb() -> R {
    let (a, b) = (b"/tmp/x1\0", b"/tmp/x2\0");
    sys_mkdir(a.as_ptr(), 0o755);
    sys_mkdir(b.as_ptr(), 0o755);
    let dt = |t: &[u8]| sys_mount(b"devtmpfs\0".as_ptr(), t.as_ptr(), b"devtmpfs\0".as_ptr(), 0, 0);
    let r = (|| {
        check(b"mount 1", dt(a) == 0, -1)?;
        check(b"mount 2", dt(b) == 0, -1)?;
        let r = sys_link(b"/tmp/x1/null\0".as_ptr(), b"/tmp/x2/hk_exdev\0".as_ptr());
        check(b"link", r == EXDEV, r)?;
        let r = sys_rename(b"/tmp/x1/hk_none\0".as_ptr(), b"/tmp/x2/hk_none2\0".as_ptr());
        check(b"rename", r == EXDEV, r)?;
        let r = sys_rename(b"/tmp/x1/hk_none\0".as_ptr(), b"/tmp/x1/hk_none2\0".as_ptr());
        check(b"same mount", r == ENOENT, r)
    })();
    sys_umount2(a.as_ptr(), 0);
    sys_umount2(b.as_ptr(), 0);
    sys_rmdir(a.as_ptr());
    sys_rmdir(b.as_ptr());
    r
}
