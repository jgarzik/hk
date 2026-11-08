//! Mount tree semantics (Linux fs/namespace.c): a walk lands on the
//! topmost mount stacked on a directory, mounts nest inside mounts, and
//! a namespace copy's umount leaves the original namespace alone. Test
//! mounts are ramfs on both kernels.

use crate::harness::{R, check, report_r};
use hk_syscall::{
    CLONE_NEWNS, O_CREAT, O_RDONLY, O_RDWR, O_WRONLY, Stat, sys_chdir, sys_chroot, sys_close,
    sys_exit, sys_faccessat, sys_fork, sys_getcwd, sys_link, sys_mkdir, sys_mount, sys_open,
    sys_pipe2, sys_pivot_root, sys_read, sys_readlink, sys_rename, sys_rmdir, sys_stat,
    sys_umount2, sys_unlink, sys_unshare, sys_wait4, sys_write,
};

const ENOENT: i64 = -2;
const EBUSY: i64 = -16;
const EXDEV: i64 = -18;
const ENOTDIR: i64 = -20;
const EINVAL: i64 = -22;
const EROFS: i64 = -30;
const MS_RDONLY: u64 = 1;
const MS_REMOUNT: u64 = 32;
const MS_BIND: u64 = 4096;
const MS_MOVE: u64 = 8192;
const MNT_FORCE: u64 = 1;
const MNT_DETACH: u64 = 2;
const MNT_EXPIRE: u64 = 4;
const EAGAIN: i64 = -11;
const ELOOP: i64 = -40;
const MS_REC: u64 = 1 << 14;
const MS_UNBINDABLE: u64 = 1 << 17;

pub fn run_tests() {
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777); // hk boots without /tmp
    report_r(b"MOUNT_NESTED", nested());
    report_r(b"UNSHARE_UMOUNT_ISOLATED", unshare_umount());
    report_r(b"RENAME_PINNED_TRAP", pinned_trap());
    report_r(b"RENAME_ANCESTOR_MOUNT", ancestor_mount());
    report_r(b"DOTDOT_MOUNT", dotdot_mount());
    report_r(b"GETCWD_IN_MOUNT", getcwd_in_mount());
    report_r(b"MOUNT_NESTED_BUSY", nested_busy());
    report_r(b"EXDEV_SAME_SB", exdev_same_sb());
    report_r(b"BIND_VIEW", bind_view());
    report_r(b"RBIND", rbind());
    report_r(b"BIND_RO_REMOUNT", bind_ro());
    report_r(b"BIND_UNBINDABLE", bind_unbindable());
    report_r(b"MOVE_MOUNT", move_mount());
    report_r(b"LAZY_UMOUNT", lazy_umount());
    report_r(b"PIVOT_ROOT_REAL", pivot_real());
    report_r(b"RAMFS_MOUNT_MODE", ramfs_mode());
    report_r(b"UMOUNT_BUSY_CWD", busy_cwd());
    report_r(b"UMOUNT_EXPIRE_BUSY", expire_busy());
    report_r(b"MOUNT_HARDLINK", hardlink());
}

fn ramfs(target: &[u8]) -> i64 {
    sys_mount(
        b"none\0".as_ptr(),
        target.as_ptr(),
        b"ramfs\0".as_ptr(),
        0,
        0,
    )
}

/// st_dev of `p`, or the errno
fn dev(p: &[u8]) -> Result<u64, i64> {
    let mut st = Stat::default();
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
    check(
        b"umount sub",
        sys_umount2(b"/tmp/mn/sub\0".as_ptr(), 0) == 0,
        -1,
    )?;
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
    for p in [
        &b"/tmp/t/c/b/z\0"[..],
        b"/tmp/t/c/b\0",
        b"/tmp/t/c\0",
        b"/tmp/t/a/b\0",
    ] {
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
    check(
        b"getcwd",
        n == want.len() as i64 && buf[..want.len()] == *want,
        n,
    )
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
    let mut st = Stat::default();
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
    let dt = |t: &[u8]| {
        sys_mount(
            b"devtmpfs\0".as_ptr(),
            t.as_ptr(),
            b"devtmpfs\0".as_ptr(),
            0,
            0,
        )
    };
    let r = (|| {
        check(b"mount 1", dt(a) == 0, -1)?;
        check(b"mount 2", dt(b) == 0, -1)?;
        let r = sys_link(b"/tmp/x1/null\0".as_ptr(), b"/tmp/x2/hk_exdev\0".as_ptr());
        check(b"link", r == EXDEV, r)?;
        let r = sys_rename(
            b"/tmp/x1/hk_none\0".as_ptr(),
            b"/tmp/x2/hk_none2\0".as_ptr(),
        );
        check(b"rename", r == EXDEV, r)?;
        let r = sys_rename(
            b"/tmp/x1/hk_none\0".as_ptr(),
            b"/tmp/x1/hk_none2\0".as_ptr(),
        );
        check(b"same mount", r == ENOENT, r)
    })();
    sys_umount2(a.as_ptr(), 0);
    sys_umount2(b.as_ptr(), 0);
    sys_rmdir(a.as_ptr());
    sys_rmdir(b.as_ptr());
    r
}

fn bind(src: &[u8], dst: &[u8], extra: u64) -> i64 {
    sys_mount(
        src.as_ptr(),
        dst.as_ptr(),
        core::ptr::null(),
        MS_BIND | extra,
        0,
    )
}

/// A bind mount shows the source directory (or file) at the target:
/// same inodes both ways, the source's path as its mountinfo root, a
/// directory only on a directory (ENOTDIR), EXDEV between the two
fn bind_view() -> R {
    for p in [&b"/tmp/bs\0"[..], b"/tmp/bs/sub\0", b"/tmp/bt\0"] {
        sys_mkdir(p.as_ptr(), 0o755);
    }
    touch(b"/tmp/bs/sub/f\0");
    touch(b"/tmp/bfile\0");
    touch(b"/tmp/btgt\0");
    let r = (|| {
        check(b"bind", bind(b"/tmp/bs/sub\0", b"/tmp/bt\0", 0) == 0, -1)?;
        let a = id(b"/tmp/bs/sub/f\0").map_err(|e| (&b"stat src"[..], e))?;
        check(b"same inode", id(b"/tmp/bt/f\0") == Ok(a), -1)?;
        check(b"create through", touch(b"/tmp/bt/g\0") >= 0, -1)?;
        check(b"seen at source", id(b"/tmp/bs/sub/g\0").is_ok(), -1)?;
        let r = sys_rename(b"/tmp/bt/g\0".as_ptr(), b"/tmp/bs/sub/g2\0".as_ptr());
        check(b"rename across", r == EXDEV, r)?;
        let mut buf = [0u8; 8192];
        let n = crate::fs::mountinfo::slurp_pub(b"/proc/self/mountinfo\0", &mut buf);
        let root_ok = buf[..n]
            .split(|&c| c == b'\n')
            .find(|l| l.split(|&c| c == b' ').nth(4) == Some(b"/tmp/bt"))
            .is_some_and(|l| l.split(|&c| c == b' ').nth(3) == Some(b"/tmp/bs/sub"));
        check(b"mountinfo root", root_ok, n as i64)?;
        check(
            b"file on file",
            bind(b"/tmp/bfile\0", b"/tmp/btgt\0", 0) == 0,
            -1,
        )?;
        let r = bind(b"/tmp/bs\0", b"/tmp/bfile\0", 0);
        check(b"dir on file", r == ENOTDIR, r)
    })();
    sys_umount2(b"/tmp/btgt\0".as_ptr(), 0);
    sys_umount2(b"/tmp/bt\0".as_ptr(), 0);
    for p in [
        &b"/tmp/bs/sub/f\0"[..],
        b"/tmp/bs/sub/g\0",
        b"/tmp/bfile\0",
        b"/tmp/btgt\0",
    ] {
        sys_unlink(p.as_ptr());
    }
    for p in [&b"/tmp/bs/sub\0"[..], b"/tmp/bs\0", b"/tmp/bt\0"] {
        sys_rmdir(p.as_ptr());
    }
    r
}

/// MS_BIND copies one mount; MS_BIND|MS_REC the mounts below it too
fn rbind() -> R {
    for p in [
        &b"/tmp/rb_s\0"[..],
        b"/tmp/rb_s/m\0",
        b"/tmp/rb_t\0",
        b"/tmp/rb_u\0",
    ] {
        sys_mkdir(p.as_ptr(), 0o755);
    }
    let r = (|| {
        check(b"mount", ramfs(b"/tmp/rb_s/m\0") == 0, -1)?;
        check(b"touch", touch(b"/tmp/rb_s/m/x\0") >= 0, -1)?;
        check(b"bind", bind(b"/tmp/rb_s\0", b"/tmp/rb_t\0", 0) == 0, -1)?;
        check(
            b"bind: not below",
            dev(b"/tmp/rb_t/m/x\0") == Err(ENOENT),
            -1,
        )?;
        check(
            b"rbind",
            bind(b"/tmp/rb_s\0", b"/tmp/rb_u\0", MS_REC) == 0,
            -1,
        )?;
        check(b"rbind: below", dev(b"/tmp/rb_u/m/x\0").is_ok(), -1)
    })();
    for p in [&b"/tmp/rb_u/m\0"[..], b"/tmp/rb_u\0", b"/tmp/rb_t\0"] {
        sys_umount2(p.as_ptr(), 0);
    }
    sys_unlink(b"/tmp/rb_s/m/x\0".as_ptr());
    sys_umount2(b"/tmp/rb_s/m\0".as_ptr(), 0);
    for p in [
        &b"/tmp/rb_s/m\0"[..],
        b"/tmp/rb_s\0",
        b"/tmp/rb_t\0",
        b"/tmp/rb_u\0",
    ] {
        sys_rmdir(p.as_ptr());
    }
    r
}

/// MS_REMOUNT|MS_BIND|MS_RDONLY makes one mount read-only, not its
/// filesystem; EBUSY while a file is open for writing through it
fn bind_ro() -> R {
    for p in [&b"/tmp/ro_s\0"[..], b"/tmp/ro_t\0"] {
        sys_mkdir(p.as_ptr(), 0o755);
    }
    touch(b"/tmp/ro_s/f\0");
    let r = (|| {
        check(b"bind", bind(b"/tmp/ro_s\0", b"/tmp/ro_t\0", 0) == 0, -1)?;
        let fd = sys_open(b"/tmp/ro_t/f\0".as_ptr(), O_WRONLY, 0);
        check(b"open w", fd >= 0, fd)?;
        let r = bind(b"none\0", b"/tmp/ro_t\0", MS_REMOUNT | MS_RDONLY);
        sys_close(fd as u64);
        check(b"busy", r == -16, r)?;
        let r = bind(b"none\0", b"/tmp/ro_t\0", MS_REMOUNT | MS_RDONLY);
        check(b"remount ro", r == 0, r)?;
        let r = touch(b"/tmp/ro_t/h\0");
        check(b"create via ro", r == EROFS, r)?;
        let r = sys_faccessat(-100, b"/tmp/ro_t/f\0".as_ptr(), 2);
        check(b"access W_OK", r == EROFS, r)?;
        check(b"source still rw", touch(b"/tmp/ro_s/h\0") >= 0, -1)?;
        let r = bind(b"none\0", b"/tmp/ro_t\0", MS_REMOUNT);
        check(b"remount rw", r == 0, r)?;
        let r = touch(b"/tmp/ro_t/h2\0");
        check(b"create via rw", r >= 0, r)
    })();
    sys_umount2(b"/tmp/ro_t\0".as_ptr(), 0);
    for p in [&b"/tmp/ro_s/f\0"[..], b"/tmp/ro_s/h\0", b"/tmp/ro_s/h2\0"] {
        sys_unlink(p.as_ptr());
    }
    for p in [&b"/tmp/ro_s\0"[..], b"/tmp/ro_t\0"] {
        sys_rmdir(p.as_ptr());
    }
    r
}

/// An unbindable mount cannot be bound (EINVAL) and is left out of an
/// rbind of a tree holding it
fn bind_unbindable() -> R {
    for p in [
        &b"/tmp/ubp\0"[..],
        b"/tmp/ubp/u\0",
        b"/tmp/ubq\0",
        b"/tmp/ub2\0",
    ] {
        sys_mkdir(p.as_ptr(), 0o755);
    }
    let r = (|| {
        check(b"mount", ramfs(b"/tmp/ubp/u\0") == 0, -1)?;
        let r = sys_mount(
            core::ptr::null(),
            b"/tmp/ubp/u\0".as_ptr(),
            core::ptr::null(),
            MS_UNBINDABLE,
            0,
        );
        check(b"make unbindable", r == 0, r)?;
        let r = bind(b"/tmp/ubp/u\0", b"/tmp/ub2\0", 0);
        check(b"bind it", r == EINVAL, r)?;
        check(
            b"rbind parent",
            bind(b"/tmp/ubp\0", b"/tmp/ubq\0", MS_REC) == 0,
            -1,
        )?;
        let top = dev(b"/tmp/ubq\0").map_err(|e| (&b"stat"[..], e))?;
        check(b"left out", dev(b"/tmp/ubq/u\0") == Ok(top), -1)
    })();
    sys_umount2(b"/tmp/ubq\0".as_ptr(), 0);
    sys_umount2(b"/tmp/ub2\0".as_ptr(), 0);
    sys_umount2(b"/tmp/ubp/u\0".as_ptr(), 0);
    for p in [
        &b"/tmp/ubp/u\0"[..],
        b"/tmp/ubp\0",
        b"/tmp/ubq\0",
        b"/tmp/ub2\0",
    ] {
        sys_rmdir(p.as_ptr());
    }
    r
}

fn mv(src: &[u8], dst: &[u8]) -> i64 {
    sys_mount(src.as_ptr(), dst.as_ptr(), core::ptr::null(), MS_MOVE, 0)
}

/// MS_MOVE takes a mount (with what is in it) to a new place; not into
/// its own subtree (ELOOP), only a mount's root moves, and a directory
/// only onto a directory (EINVAL, Linux do_move_mount)
fn move_mount() -> R {
    for p in [&b"/tmp/mv_a\0"[..], b"/tmp/mv_b\0"] {
        sys_mkdir(p.as_ptr(), 0o755);
    }
    touch(b"/tmp/mv_file\0");
    let r = (|| {
        check(b"mount", ramfs(b"/tmp/mv_a\0") == 0, -1)?;
        check(b"touch", touch(b"/tmp/mv_a/f\0") >= 0, -1)?;
        let r = mv(b"/tmp/mv_a\0", b"/tmp/mv_b\0");
        check(b"move", r == 0, r)?;
        check(b"there", dev(b"/tmp/mv_b/f\0").is_ok(), -1)?;
        check(b"gone here", dev(b"/tmp/mv_a/f\0") == Err(ENOENT), -1)?;
        let r = mv(b"/tmp/mv_b\0", b"/tmp/mv_file\0");
        check(b"dir onto file", r == EINVAL, r)?;
        sys_mkdir(b"/tmp/mv_b/in\0".as_ptr(), 0o755);
        let r = mv(b"/tmp/mv_b\0", b"/tmp/mv_b/in\0");
        check(b"into itself", r == ELOOP, r)?;
        let r = mv(b"/tmp/mv_b/in\0", b"/tmp/mv_a\0");
        check(b"not a mount root", r == EINVAL, r)
    })();
    sys_unlink(b"/tmp/mv_b/f\0".as_ptr());
    sys_unlink(b"/tmp/mv_file\0".as_ptr());
    sys_rmdir(b"/tmp/mv_b/in\0".as_ptr());
    sys_umount2(b"/tmp/mv_b\0".as_ptr(), 0);
    sys_umount2(b"/tmp/mv_a\0".as_ptr(), 0);
    for p in [&b"/tmp/mv_a\0"[..], b"/tmp/mv_b\0"] {
        sys_rmdir(p.as_ptr());
    }
    r
}

/// umount2: a busy tree is EBUSY, with MNT_FORCE too; MNT_DETACH takes
/// it all away at once while an open file keeps working; MNT_EXPIRE
/// marks first (EAGAIN), then unmounts, and is EINVAL with MNT_DETACH
fn lazy_umount() -> R {
    sys_mkdir(b"/tmp/lz\0".as_ptr(), 0o755);
    sys_mkdir(b"/tmp/ex\0".as_ptr(), 0o755);
    let r = (|| {
        check(b"mount", ramfs(b"/tmp/lz\0") == 0, -1)?;
        sys_mkdir(b"/tmp/lz/sub\0".as_ptr(), 0o755);
        check(b"mount sub", ramfs(b"/tmp/lz/sub\0") == 0, -1)?;
        let fd = sys_open(b"/tmp/lz/sub/f\0".as_ptr(), O_CREAT | O_RDWR, 0o644);
        check(b"open", fd >= 0, fd)?;
        let r = sys_umount2(b"/tmp/lz\0".as_ptr(), 0);
        check(b"busy", r == EBUSY, r)?;
        let r = sys_umount2(b"/tmp/lz\0".as_ptr(), MNT_FORCE);
        check(b"force busy", r == EBUSY, r)?;
        let r = sys_umount2(b"/tmp/lz\0".as_ptr(), MNT_DETACH);
        check(b"detach", r == 0, r)?;
        check(b"tree gone", dev(b"/tmp/lz/sub\0") == Err(ENOENT), -1)?;
        let w = sys_write(fd as u64, b"x".as_ptr(), 1);
        sys_close(fd as u64);
        check(b"fd still works", w == 1, w)?;
        check(b"mount ex", ramfs(b"/tmp/ex\0") == 0, -1)?;
        let ex = b"/tmp/ex\0".as_ptr();
        let r = sys_umount2(ex, MNT_EXPIRE | MNT_DETACH);
        check(b"expire+detach", r == EINVAL, r)?;
        let r = sys_umount2(ex, MNT_EXPIRE);
        check(b"expire mark", r == EAGAIN, r)?;
        let r = sys_umount2(ex, MNT_EXPIRE);
        check(b"expire", r == 0, r)
    })();
    sys_umount2(b"/tmp/lz/sub\0".as_ptr(), MNT_DETACH);
    sys_umount2(b"/tmp/lz\0".as_ptr(), MNT_DETACH);
    sys_umount2(b"/tmp/ex\0".as_ptr(), 0);
    sys_rmdir(b"/tmp/lz\0".as_ptr());
    sys_rmdir(b"/tmp/ex\0".as_ptr());
    r
}

/// pivot_root in a fresh namespace (Linux 6.8 refuses a root mount with
/// no parent, so the root is first a mount moved onto "/" and chrooted
/// into): the new root's mount becomes "/", the old one appears at
/// put_old, and the caller's root and cwd follow
fn pivot_real() -> R {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(pivot_child() as u64);
    }
    let mut ws = 0i32;
    sys_wait4(pid, &mut ws, 0, 0);
    check(b"child", ws == 0, (ws >> 8) as i64)
}

/// 0, or the step that failed
fn pivot_child() -> i32 {
    if sys_unshare(CLONE_NEWNS) != 0 {
        return 1;
    }
    sys_mkdir(b"/tmp/pr\0".as_ptr(), 0o755);
    if ramfs(b"/tmp/pr\0") != 0 || sys_chdir(b"/tmp/pr\0".as_ptr()) != 0 {
        return 2;
    }
    if mv(b".\0", b"/\0") != 0 || sys_chroot(b".\0".as_ptr()) != 0 {
        return 3;
    }
    sys_mkdir(b"/new\0".as_ptr(), 0o755);
    if ramfs(b"/new\0") != 0 {
        return 4;
    }
    sys_mkdir(b"/new/old\0".as_ptr(), 0o755);
    touch(b"/new/marker\0");
    let old_dev = dev(b"/\0");
    if sys_pivot_root(b"/new\0".as_ptr(), b"/new/old\0".as_ptr()) != 0 {
        return 5;
    }
    if dev(b"/marker\0").is_err() {
        return 6;
    }
    // The old root, with its "new" directory now uncovered
    if dev(b"/old\0") != old_dev || dev(b"/old/new/marker\0") != Err(ENOENT) {
        return 7;
    }
    let mut buf = [0u8; 8];
    if sys_getcwd(buf.as_mut_ptr(), buf.len()) != 2 || buf[0] != b'/' {
        return 8;
    }
    0
}

/// ramfs takes mode= for its root (Linux ramfs_parse_param) and
/// ignores options it does not know
fn ramfs_mode() -> R {
    let d = b"/tmp/rm\0";
    sys_mkdir(d.as_ptr(), 0o755);
    let opts = b"mode=0710,whatever=1\0";
    let r = sys_mount(
        b"none\0".as_ptr(),
        d.as_ptr(),
        b"ramfs\0".as_ptr(),
        0,
        opts.as_ptr() as u64,
    );
    let mut st = Stat::default();
    let s = sys_stat(d.as_ptr(), &mut st);
    sys_umount2(d.as_ptr(), 0);
    sys_rmdir(d.as_ptr());
    check(b"mount", r == 0, r)?;
    check(b"mode", s == 0 && st.st_mode == 0o40710, st.st_mode as i64)
}

/// A process standing in a mount (its cwd) makes it busy (Linux counts
/// every reference: the fs struct's path pins the mount)
fn busy_cwd() -> R {
    let d = b"/tmp/ubc\0";
    sys_mkdir(d.as_ptr(), 0o755);
    if ramfs(d) != 0 {
        sys_rmdir(d.as_ptr());
        return Err((b"mount", -1));
    }
    let (mut go, mut ready) = ([0i32; 2], [0i32; 2]);
    sys_pipe2(go.as_mut_ptr(), 0);
    sys_pipe2(ready.as_mut_ptr(), 0);
    let pid = sys_fork();
    if pid == 0 {
        let mut b = [0u8; 1];
        sys_chdir(d.as_ptr());
        sys_write(ready[1] as u64, b"r".as_ptr(), 1);
        sys_read(go[0] as u64, b.as_mut_ptr(), 1);
        sys_exit(0);
    }
    let mut b = [0u8; 1];
    sys_read(ready[0] as u64, b.as_mut_ptr(), 1);
    let busy = sys_umount2(d.as_ptr(), 0);
    sys_write(go[1] as u64, b"g".as_ptr(), 1);
    let mut ws = 0i32;
    sys_wait4(pid, &mut ws, 0, 0);
    for f in [go[0], go[1], ready[0], ready[1]] {
        sys_close(f as u64);
    }
    let after = sys_umount2(d.as_ptr(), 0);
    sys_rmdir(d.as_ptr());
    check(b"busy", busy == EBUSY, busy)?;
    check(b"umount after", after == 0, after)
}

/// MNT_EXPIRE: a busy mount is EBUSY (not marked); use between the two
/// calls (an open, a lookup) clears the mark (Linux mntput), so the
/// next one marks again
fn expire_busy() -> R {
    let d = b"/tmp/exb\0";
    sys_mkdir(d.as_ptr(), 0o755);
    if ramfs(d) != 0 {
        sys_rmdir(d.as_ptr());
        return Err((b"mount", -1));
    }
    let r = (|| {
        let fd = sys_open(b"/tmp/exb/f\0".as_ptr(), O_CREAT | O_WRONLY, 0o644);
        let busy = sys_umount2(d.as_ptr(), MNT_EXPIRE);
        sys_close(fd as u64);
        check(b"busy", busy == EBUSY, busy)?;
        let r = sys_umount2(d.as_ptr(), MNT_EXPIRE);
        check(b"mark", r == EAGAIN, r)?;
        let fd = sys_open(b"/tmp/exb/f\0".as_ptr(), O_RDONLY, 0);
        sys_close(fd as u64);
        let r = sys_umount2(d.as_ptr(), MNT_EXPIRE);
        check(b"used: marked again", r == EAGAIN, r)?;
        // A path lookup is a use too (path_put), not only an open file
        // SAFETY: Stat is plain integers
        let mut st = Stat::default();
        sys_stat(b"/tmp/exb/f\0".as_ptr(), &mut st);
        let r = sys_umount2(d.as_ptr(), MNT_EXPIRE);
        check(b"stat: marked again", r == EAGAIN, r)?;
        let r = sys_umount2(d.as_ptr(), MNT_EXPIRE);
        check(b"expire", r == 0, r)
    })();
    sys_umount2(d.as_ptr(), 0);
    sys_rmdir(d.as_ptr());
    r
}

/// Hard links are different mountpoints: a bind on one leaves the other
/// showing the file, and it can be unlinked
fn hardlink() -> R {
    touch(b"/tmp/hl_a\0");
    sys_link(b"/tmp/hl_a\0".as_ptr(), b"/tmp/hl_b\0".as_ptr());
    let fd = sys_open(b"/tmp/hl_src\0".as_ptr(), O_CREAT | O_WRONLY, 0o644);
    sys_write(fd as u64, b"S".as_ptr(), 1);
    sys_close(fd as u64);
    let r = (|| {
        check(b"bind", bind(b"/tmp/hl_src\0", b"/tmp/hl_a\0", 0) == 0, -1)?;
        let mut b = [0u8; 4];
        let fd = sys_open(b"/tmp/hl_b\0".as_ptr(), O_RDONLY, 0);
        let n = sys_read(fd as u64, b.as_mut_ptr(), 4);
        sys_close(fd as u64);
        check(b"other link unbound", n == 0, n)?;
        let r = sys_unlink(b"/tmp/hl_b\0".as_ptr());
        check(b"unlink other", r == 0, r)
    })();
    sys_umount2(b"/tmp/hl_a\0".as_ptr(), 0);
    for p in [&b"/tmp/hl_a\0"[..], b"/tmp/hl_b\0", b"/tmp/hl_src\0"] {
        sys_unlink(p.as_ptr());
    }
    r
}
