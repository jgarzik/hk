//! Mount tree semantics (Linux fs/namespace.c): a walk lands on the
//! topmost mount stacked on a directory, mounts nest inside mounts, and
//! a namespace copy's umount leaves the original namespace alone. Test
//! mounts are ramfs on both kernels.

use super::helpers::{print, print_num, println};
use hk_syscall::{
    CLONE_NEWNS, O_CREAT, O_WRONLY, Stat, sys_close, sys_exit, sys_fork, sys_mkdir, sys_mount,
    sys_open, sys_rmdir, sys_stat, sys_umount2, sys_unshare, sys_wait4,
};

const ENOENT: i64 = -2;

pub fn run_tests() {
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777); // hk boots without /tmp
    report(b"MOUNT_NESTED", nested());
    report(b"UNSHARE_UMOUNT_ISOLATED", unshare_umount());
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
