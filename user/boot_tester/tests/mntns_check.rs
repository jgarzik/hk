//! Mount operations on another namespace's mounts (Linux check_mnt)
//!
//! A child that unshares its mount namespace and reaches a mount of the
//! parent's namespace through a directory fd opened before the unshare
//! gets EINVAL from MS_MOVE, MS_BIND, umount, remount and a new mount
//! on it; the parent's mount is untouched. A propagation change needs
//! only a mount in some namespace (Linux may_change_propagation).

use super::helpers::{print, print_num, println};
use hk_syscall::{
    CLONE_NEWNS, O_CREAT, O_DIRECTORY, O_RDONLY, O_RDWR, sys_close, sys_exit, sys_fchdir, sys_fork,
    sys_mkdir, sys_mount, sys_open, sys_rmdir, sys_umount2, sys_unshare, sys_wait4,
};

const MS_RDONLY: u64 = 1;
const MS_REMOUNT: u64 = 32;
const MS_BIND: u64 = 4096;
const MS_MOVE: u64 = 8192;
const MS_PRIVATE: u64 = 1 << 18;
const MS_REC: u64 = 16384;
const MNT_DETACH: u64 = 2;
const EINVAL: i64 = -22;

pub fn run_tests() {
    test_foreign_mount();
}

/// Child: each foreign-mount operation must be EINVAL; exit status is a
/// bitmask of the ones that were not
fn foreign_child(fd: i32) -> ! {
    if sys_unshare(CLONE_NEWNS) != 0 {
        sys_exit(64);
    }
    // Keep the parent's tree out of reach of propagation either way
    sys_mount(
        b"none\0".as_ptr(),
        b"/\0".as_ptr(),
        core::ptr::null(),
        MS_REC | MS_PRIVATE,
        0,
    );
    if sys_fchdir(fd) != 0 {
        sys_exit(65);
    }
    let mut bad = 0;
    let dot = b".\0".as_ptr();
    let dst = b"/tmp/mntns_b\0".as_ptr();
    if sys_mount(dot, dst, core::ptr::null(), MS_MOVE, 0) != EINVAL {
        bad |= 1;
    }
    if sys_mount(dot, dst, core::ptr::null(), MS_BIND, 0) != EINVAL {
        bad |= 2;
    }
    if sys_mount(b"none\0".as_ptr(), dot, b"ramfs\0".as_ptr(), 0, 0) != EINVAL {
        bad |= 4;
    }
    if sys_umount2(dot, MNT_DETACH) != EINVAL {
        bad |= 8;
    }
    let none = core::ptr::null();
    if sys_mount(none, dot, none, MS_REMOUNT | MS_BIND | MS_RDONLY, 0) != EINVAL {
        bad |= 16;
    }
    if sys_mount(none, dot, none, MS_REMOUNT | MS_RDONLY, 0) != EINVAL {
        bad |= 32;
    }
    if sys_mount(none, dot, none, MS_PRIVATE, 0) != 0 {
        bad |= 64;
    }
    sys_exit(bad);
}

fn test_foreign_mount() {
    sys_mkdir(b"/tmp/mntns_a\0".as_ptr(), 0o755);
    sys_mkdir(b"/tmp/mntns_b\0".as_ptr(), 0o755);
    let r = sys_mount(
        b"none\0".as_ptr(),
        b"/tmp/mntns_a\0".as_ptr(),
        b"ramfs\0".as_ptr(),
        0,
        0,
    );
    if r != 0 {
        print(b"MNTNS_FOREIGN:FAIL mount ");
        print_num(r);
        println(b"");
        return;
    }
    let marker = sys_open(b"/tmp/mntns_a/marker\0".as_ptr(), O_RDWR | O_CREAT, 0o644);
    sys_close(marker as u64);
    let fd = sys_open(b"/tmp/mntns_a\0".as_ptr(), O_RDONLY | O_DIRECTORY, 0) as i32;
    let child = sys_fork();
    if child == 0 {
        foreign_child(fd);
    }
    sys_close(fd as u64);
    let mut status = 0i32;
    sys_wait4(child, &mut status, 0, 0);
    // The parent's mount is still there, with its file
    let still = sys_open(b"/tmp/mntns_a/marker\0".as_ptr(), O_RDONLY, 0);
    if still >= 0 {
        sys_close(still as u64);
    }
    let gone = sys_umount2(b"/tmp/mntns_a\0".as_ptr(), 0);
    sys_rmdir(b"/tmp/mntns_a\0".as_ptr());
    sys_rmdir(b"/tmp/mntns_b\0".as_ptr());
    if status == 0 && still >= 0 && gone == 0 {
        println(b"MNTNS_FOREIGN:OK");
    } else {
        print(b"MNTNS_FOREIGN:FAIL status=");
        print_num(status as i64);
        print(b" marker=");
        print_num(still);
        print(b" umount=");
        print_num(gone);
        println(b"");
    }
}
