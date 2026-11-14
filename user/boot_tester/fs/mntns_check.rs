//! Mount operations on another namespace's mounts (Linux check_mnt),
//! locked mounts of a namespace copied for another user namespace
//! (Linux lock_mnt_tree), and SO_PRIORITY above 6 with CAP_NET_RAW
//! alone (Linux sk_set_prio_allowed)
//!
//! A child that unshares its mount namespace and reaches a mount of the
//! parent's namespace through a directory fd opened before the unshare
//! gets EINVAL from MS_MOVE, MS_BIND, umount, remount and a new mount
//! on it; the parent's mount is untouched. A propagation change needs
//! only a mount in some namespace (Linux may_change_propagation).
//!
//! In a namespace copied with a new user namespace, a submount cannot
//! be unmounted or moved, nor its parent bound without it (EINVAL), and
//! a remount may not drop its read-only, nosuid or atime flags (EPERM);
//! a mount propagated into such a namespace is locked the same way.

use crate::harness::{R, check, fail_num, pass, report_r};
use crate::helpers::{print, print_num, println};
use hk_syscall::{
    _LINUX_CAPABILITY_VERSION_3, AF_INET, CLONE_NEWNS, CLONE_NEWUSER, CapUserData, CapUserHeader,
    O_CREAT, O_DIRECTORY, O_RDONLY, O_RDWR, SOCK_DGRAM, sys_capset, sys_close, sys_exit,
    sys_fchdir, sys_fork, sys_mkdir, sys_mount, sys_open, sys_pipe, sys_read, sys_rmdir,
    sys_setsockopt, sys_socket, sys_umount2, sys_unshare, sys_wait4, sys_write,
};

const MS_RDONLY: u64 = 1;
const MS_NOSUID: u64 = 2;
const MS_NOATIME: u64 = 1024;
const MS_SHARED: u64 = 1 << 20;
const EPERM: i64 = -1;
const MS_REMOUNT: u64 = 32;
const MS_BIND: u64 = 4096;
const MS_MOVE: u64 = 8192;
const MS_PRIVATE: u64 = 1 << 18;
const MS_REC: u64 = 16384;
const MNT_DETACH: u64 = 2;
const EINVAL: i64 = -22;

pub fn run_tests() {
    test_foreign_mount();
    report_r(b"MNT_LOCKED_USERNS", locked_userns());
    report_r(b"MNT_LOCKED_PROPAGATED", locked_propagated());
    test_prio_net_raw();
}

/// A new mount (ramfs on both kernels) on `t`
fn ramfs(t: &[u8]) -> i64 {
    sys_mount(b"none\0".as_ptr(), t.as_ptr(), b"ramfs\0".as_ptr(), 0, 0)
}

/// mount(2) with no source or type: remounts and propagation changes
fn remount(t: &[u8], flags: u64) -> i64 {
    let none = core::ptr::null();
    sys_mount(none, t.as_ptr(), none, flags, 0)
}

/// The exit status of a child running `f`: the number of its first
/// failed check, 0 if all passed
fn in_child(f: fn() -> u8) -> R {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(u64::from(f()));
    }
    check(b"fork", pid > 0, pid)?;
    let mut ws = 0i32;
    sys_wait4(pid, &mut ws, 0, 0);
    check(b"child step", ws == 0, i64::from(ws >> 8))
}

/// The first of `steps` that is false, numbered from 1; 0 if none
fn first_bad(steps: &[bool]) -> u8 {
    steps.iter().position(|ok| !ok).map_or(0, |i| i as u8 + 1)
}

/// A private namespace with /tmp/ml (ramfs) holding /tmp/ml/sub, a
/// read-only nosuid ramfs over a file `secret`, and an empty /tmp/ml/b
fn locked_setup() -> bool {
    if sys_unshare(CLONE_NEWNS) != 0 || remount(b"/\0", MS_REC | MS_PRIVATE) != 0 {
        return false;
    }
    sys_mkdir(b"/tmp/ml\0".as_ptr(), 0o755);
    if ramfs(b"/tmp/ml\0") != 0 {
        return false;
    }
    sys_mkdir(b"/tmp/ml/sub\0".as_ptr(), 0o755);
    sys_mkdir(b"/tmp/ml/b\0".as_ptr(), 0o755);
    let fd = sys_open(b"/tmp/ml/sub/secret\0".as_ptr(), O_RDWR | O_CREAT, 0o644);
    sys_close(fd as u64);
    fd >= 0
        && ramfs(b"/tmp/ml/sub\0") == 0
        && remount(
            b"/tmp/ml/sub\0",
            MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID,
        ) == 0
}

/// Child of MNT_LOCKED_USERNS (Linux copy_mnt_ns' lock_mnt_tree for a
/// copy owned by another user namespace)
fn locked_child() -> u8 {
    if !locked_setup() {
        return 100;
    }
    if sys_unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0 {
        return 101;
    }
    let sub = b"/tmp/ml/sub\0";
    let bind = MS_REMOUNT | MS_BIND;
    first_bad(&[
        // MNT_LOCKED: can_umount, lazy or not
        sys_umount2(sub.as_ptr(), 0) == EINVAL,
        sys_umount2(sub.as_ptr(), MNT_DETACH) == EINVAL,
        // MNT_LOCK_*: keeping every locked flag is fine
        remount(sub, bind | MS_RDONLY | MS_NOSUID) == 0,
        remount(sub, bind | MS_NOSUID) == EPERM,
        remount(sub, bind | MS_RDONLY) == EPERM,
        remount(sub, bind | MS_RDONLY | MS_NOSUID | MS_NOATIME) == EPERM,
        remount(sub, MS_REMOUNT | MS_NOSUID) == EPERM,
        // A lone bind would uncover the secret; a locked mount stays put
        sys_mount(
            b"/tmp/ml\0".as_ptr(),
            b"/tmp/ml/b\0".as_ptr(),
            core::ptr::null(),
            MS_BIND,
            0,
        ) == EINVAL,
        sys_mount(
            sub.as_ptr(),
            b"/tmp/ml/b\0".as_ptr(),
            core::ptr::null(),
            MS_MOVE,
            0,
        ) == EINVAL,
        // What is mounted over a locked mount comes and goes freely
        ramfs(sub) == 0,
        sys_umount2(sub.as_ptr(), 0) == 0,
        sys_umount2(sub.as_ptr(), 0) == EINVAL,
    ])
}

/// A namespace copied with a new user namespace is locked: its
/// submounts stay, with the flags they had
fn locked_userns() -> R {
    in_child(locked_child)
}

/// Child of MNT_LOCKED_PROPAGATED: /tmp/mp is shared, a grandchild in a
/// new user namespace holds a slave copy; a tree bound under /tmp/mp
/// reaches the grandchild with its submount locked (Linux
/// attach_recursive_mnt: lock_mnt_tree across user namespaces)
fn propagated_child() -> u8 {
    if sys_unshare(CLONE_NEWNS) != 0 || remount(b"/\0", MS_REC | MS_PRIVATE) != 0 {
        return 100;
    }
    for d in [&b"/tmp/mp\0"[..], b"/tmp/mt\0"] {
        sys_mkdir(d.as_ptr(), 0o755);
    }
    if ramfs(b"/tmp/mp\0") != 0 || remount(b"/tmp/mp\0", MS_SHARED) != 0 {
        return 101;
    }
    if ramfs(b"/tmp/mt\0") != 0 {
        return 102;
    }
    sys_mkdir(b"/tmp/mt/x\0".as_ptr(), 0o755);
    sys_mkdir(b"/tmp/mp/t\0".as_ptr(), 0o755);
    if ramfs(b"/tmp/mt/x\0") != 0 {
        return 103;
    }
    let (mut ready, mut go) = ([0i32; 2], [0i32; 2]);
    if sys_pipe(ready.as_mut_ptr()) != 0 || sys_pipe(go.as_mut_ptr()) != 0 {
        return 104;
    }
    let pid = sys_fork();
    if pid == 0 {
        let ok = sys_unshare(CLONE_NEWUSER | CLONE_NEWNS) == 0;
        sys_write(ready[1] as u64, [u8::from(ok)].as_ptr(), 1);
        let mut b = [0u8; 1];
        sys_read(go[0] as u64, b.as_mut_ptr(), 1);
        let code = first_bad(&[
            ok,
            sys_umount2(b"/tmp/mp/t/x\0".as_ptr(), 0) == EINVAL,
            sys_umount2(b"/tmp/mp/t/x\0".as_ptr(), MNT_DETACH) == EINVAL,
        ]);
        sys_exit(u64::from(code));
    }
    let mut b = [0u8; 1];
    sys_read(ready[0] as u64, b.as_mut_ptr(), 1);
    let bound = sys_mount(
        b"/tmp/mt\0".as_ptr(),
        b"/tmp/mp/t\0".as_ptr(),
        core::ptr::null(),
        MS_BIND | MS_REC,
        0,
    );
    sys_write(go[1] as u64, b"g".as_ptr(), 1);
    let mut ws = 0i32;
    sys_wait4(pid, &mut ws, 0, 0);
    if bound != 0 {
        return 105;
    }
    if ws != 0 {
        return 10 + (ws >> 8) as u8;
    }
    0
}

/// A tree propagated into a namespace of another user namespace has
/// its submounts locked there
fn locked_propagated() -> R {
    in_child(propagated_child)
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
        fail_num(b"MNTNS_FOREIGN:FAIL mount ", r);
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
        pass(b"MNTNS_FOREIGN");
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

const CAP_NET_RAW: u32 = 13;

/// SO_PRIORITY 7 needs CAP_NET_RAW or CAP_NET_ADMIN: with NET_RAW alone
/// it succeeds, with neither it is EPERM
fn test_prio_net_raw() {
    let child = sys_fork();
    if child == 0 {
        let s = sys_socket(AF_INET, SOCK_DGRAM, 0) as i32;
        if !caps(1 << CAP_NET_RAW) {
            sys_exit(2);
        }
        if set_prio(s) != 0 {
            sys_exit(1);
        }
        if !caps(0) {
            sys_exit(2);
        }
        sys_exit(if set_prio(s) == -1 { 0 } else { 3 });
    }
    let mut status = 0i32;
    sys_wait4(child, &mut status, 0, 0);
    if status == 0 {
        pass(b"SO_PRIORITY_NET_RAW");
    } else {
        fail_num(b"SO_PRIORITY_NET_RAW:FAIL status=", status as i64);
    }
}

/// Effective and permitted capabilities become exactly `low` (caps 0..31)
fn caps(low: u32) -> bool {
    let hdr = CapUserHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapUserData::default(); 2];
    data[0].effective = low;
    data[0].permitted = low;
    sys_capset(&hdr, data.as_ptr()) == 0
}

/// setsockopt(SO_PRIORITY, 7)
fn set_prio(s: i32) -> i64 {
    const SOL_SOCKET: i32 = 1;
    const SO_PRIORITY: i32 = 12;
    let prio = 7i32;
    sys_setsockopt(
        s,
        SOL_SOCKET,
        SO_PRIORITY,
        (&raw const prio).cast::<u8>(),
        4,
    )
}
