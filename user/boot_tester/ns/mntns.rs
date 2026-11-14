//! Mount namespace files in the mount tree (Linux fs/namespace.c
//! mnt_ns_loop, copy_tree's CL_COPY_MNT_NS_FILE)
//!
//! MNTNS_FILE_LOOP: binding the caller's own mount namespace file is
//! EINVAL (the namespace's tree would hold itself), a newer
//! namespace's file binds; a new namespace copied from the caller's
//! leaves that mount out, a recursive bind copies it, and a bind that
//! would propagate it to a peer is EINVAL (another namespace file
//! propagates).
//!
//! MOUNT_TOO_REVEALING: in a mount namespace of a new user namespace a
//! new proc mounts while the copied /proc is fully visible, and is
//! EPERM once a mount over a non-empty directory of it (locked in the
//! copy) hides part of it (Linux mount_too_revealing).

use super::{first_bad, in_child, ns_link, pid_path, stat};
use crate::harness::verdict_detail;
use hk_syscall::{
    CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER, O_CREAT, O_WRONLY, sys_close, sys_exit, sys_fork,
    sys_mkdir, sys_mount, sys_open, sys_pipe, sys_read, sys_unshare, sys_wait4, sys_write,
};

const EINVAL: i64 = -22;
const EPERM: i64 = -1;
const MS_BIND: u64 = 4096;
const MS_REC: u64 = 16384;
const MS_PRIVATE: u64 = 1 << 18;
const MS_SHARED: u64 = 1 << 20;

pub fn run_tests() {
    let r = in_child(loop_child);
    verdict_detail(b"MNTNS_FILE_LOOP", r == 0, r);
    let r = in_child(reveal_child);
    verdict_detail(b"MOUNT_TOO_REVEALING", r == 0, r);
}

fn bind(src: &[u8], dst: &[u8], flags: u64) -> i64 {
    sys_mount(
        src.as_ptr(),
        dst.as_ptr(),
        core::ptr::null(),
        MS_BIND | flags,
        0,
    )
}

fn touch(p: &[u8]) -> bool {
    let fd = sys_open(p.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    sys_close(fd as u64);
    fd >= 0
}

fn ino(p: &[u8]) -> u64 {
    stat(p).map_or(0, |s| s.st_ino)
}

/// A private namespace with a ramfs at /tmp/nsl holding files f and g
fn setup() -> bool {
    let none = core::ptr::null();
    if sys_unshare(CLONE_NEWNS) != 0
        || sys_mount(none, b"/\0".as_ptr(), none, MS_REC | MS_PRIVATE, 0) != 0
    {
        return false;
    }
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    for d in [&b"/tmp/nsl\0"[..], b"/tmp/nsl2\0", b"/tmp/nsl3\0"] {
        sys_mkdir(d.as_ptr(), 0o755);
    }
    sys_mount(
        b"none\0".as_ptr(),
        b"/tmp/nsl\0".as_ptr(),
        b"ramfs\0".as_ptr(),
        0,
        0,
    ) == 0
        && touch(b"/tmp/nsl/f\0")
        && touch(b"/tmp/nsl/g\0")
}

/// A child in a new mount namespace of its own, until `down` closes
fn newer_ns(up: [i32; 2], down: [i32; 2]) -> i64 {
    let c = sys_fork();
    if c == 0 {
        sys_close(up[0] as u64);
        sys_close(down[1] as u64);
        let ok = sys_unshare(CLONE_NEWNS) == 0;
        sys_write(up[1] as u64, b"x".as_ptr(), u64::from(ok));
        let mut x = 0u8;
        sys_read(down[0] as u64, &mut x, 1);
        sys_exit(0);
    }
    c
}

/// Child of MNTNS_FILE_LOOP
fn loop_child() -> u8 {
    if !setup() {
        return 100;
    }
    let (mut up, mut down) = ([0i32; 2], [0i32; 2]);
    if sys_pipe(up.as_mut_ptr()) != 0 || sys_pipe(down.as_mut_ptr()) != 0 {
        return 101;
    }
    let c = newer_ns(up, down);
    sys_close(up[1] as u64);
    sys_close(down[0] as u64);
    let mut x = 0u8;
    if c < 0 || sys_read(up[0] as u64, &mut x, 1) != 1 {
        return 102;
    }
    let mut b = [0u8; 64];
    let theirs = pid_path(&mut b, b"/proc/", c, b"/ns/mnt");
    let inum = ns_link(theirs, b"mnt");
    let own = bind(b"/proc/self/ns/mnt\0", b"/tmp/nsl/f\0", 0);
    let newer = bind(theirs, b"/tmp/nsl/f\0", 0);
    // A copy of this namespace leaves the namespace file out: there
    // /tmp/nsl/f is the ramfs file (the child exits 1 if it is not)
    let d = sys_fork();
    if d == 0 {
        let left_out = sys_unshare(CLONE_NEWNS) == 0 && ino(b"/tmp/nsl/f\0") != inum;
        sys_exit(u64::from(!left_out));
    }
    let mut ws = 0;
    let copy_ok = d > 0 && sys_wait4(d, &mut ws, 0, 0) == d && ws == 0;
    // A recursive bind copies it
    let rbind = bind(b"/tmp/nsl\0", b"/tmp/nsl3\0", MS_REC);
    // /tmp/nsl2 a peer of /tmp/nsl: what is mounted in one propagates
    let none = core::ptr::null();
    let shared = sys_mount(none, b"/tmp/nsl\0".as_ptr(), none, MS_SHARED, 0) == 0
        && bind(b"/tmp/nsl\0", b"/tmp/nsl2\0", 0) == 0;
    let net = ns_link(b"/proc/self/ns/net\0", b"net");
    let steps = [
        inum != 0,
        own == EINVAL,
        newer == 0,
        ino(b"/tmp/nsl/f\0") == inum,
        copy_ok,
        rbind == 0 && ino(b"/tmp/nsl3/f\0") == inum,
        shared,
        bind(theirs, b"/tmp/nsl/g\0", 0) == EINVAL,
        bind(b"/proc/self/ns/net\0", b"/tmp/nsl/g\0", 0) == 0,
        net != 0 && ino(b"/tmp/nsl2/g\0") == net,
    ];
    sys_close(down[1] as u64);
    sys_wait4(c, &mut ws, 0, 0);
    first_bad(&steps)
}

/// In a new user, mount and pid namespace (as a child, the new pid
/// namespace's init): mount(2) of a new proc on /tmp/rv gives `want`
fn proc_in_userns(want: i64) -> bool {
    let q = sys_fork();
    if q == 0 {
        let ns = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID;
        if sys_unshare(ns) != 0 {
            sys_exit(2);
        }
        let r = sys_fork();
        if r == 0 {
            let got = sys_mount(
                b"proc\0".as_ptr(),
                b"/tmp/rv\0".as_ptr(),
                b"proc\0".as_ptr(),
                0,
                0,
            );
            sys_exit(u64::from(got != want));
        }
        let mut ws = 0;
        let ok = r > 0 && sys_wait4(r, &mut ws, 0, 0) == r && ws == 0;
        sys_exit(u64::from(!ok));
    }
    let mut ws = 0;
    q > 0 && sys_wait4(q, &mut ws, 0, 0) == q && ws == 0
}

/// Child of MOUNT_TOO_REVEALING
fn reveal_child() -> u8 {
    let none = core::ptr::null();
    if sys_unshare(CLONE_NEWNS) != 0
        || sys_mount(none, b"/\0".as_ptr(), none, MS_REC | MS_PRIVATE, 0) != 0
    {
        return 100;
    }
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    sys_mkdir(b"/tmp/rv\0".as_ptr(), 0o755);
    let visible = proc_in_userns(0);
    // A mount over the non-empty /proc/sys, locked in the copy for the
    // new user namespace, hides what a new proc would show
    let covered = sys_mount(
        b"none\0".as_ptr(),
        b"/proc/sys\0".as_ptr(),
        b"ramfs\0".as_ptr(),
        0,
        0,
    ) == 0;
    first_bad(&[visible, covered, covered && proc_in_userns(EPERM)])
}
