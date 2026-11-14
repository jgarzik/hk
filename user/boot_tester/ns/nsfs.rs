//! Namespace files (Linux fs/nsfs.c) and setns(2) through them
//!
//! NSFS_INODE: /proc/<pid>/ns/<type> leads to one nsfs inode per
//! namespace, S_IFREG | 0444, numbered as its link reads; every open
//! and every process sharing the namespace sees the same st_dev and
//! st_ino. pid_for_children reads "pid:[...]".
//!
//! NSFS_PIN: a namespace file holds its namespace, not a task: after
//! the last task in a UTS namespace exits, an fd opened earlier and a
//! bind mount of its file each still join it with setns, which sees
//! its hostname; a mismatched nstype or a file that is no namespace
//! file is EINVAL.
//!
//! NSFS_PIDFD: setns with a pidfd joins the namespaces its flags name
//! of that task (Linux validate_nsset); no flags or a flag that is no
//! namespace type is EINVAL, a reaped task ESRCH.
//!
//! NSFS_IOCTL: NS_GET_NSTYPE, NS_GET_USERNS and NS_GET_PARENT (new
//! O_CLOEXEC descriptors of the owner or parent, EPERM past what the
//! caller's own namespace may see, EINVAL for a type with no parent),
//! NS_GET_OWNER_UID (as the caller's user namespace maps it).
//!
//! NSFS_IDS: namespace ids (NS_GET_ID, NS_GET_MNTNS_ID, the initial
//! namespaces' fixed ones), struct mnt_ns_info (NS_MNT_GET_INFO) and
//! the mount namespaces next to one in id order (NS_MNT_GET_NEXT/PREV).
//! NSFS_PIDNS_XLATE: pid numbers between pid namespaces
//! (NS_GET_{PID,TGID}_{FROM,IN}_PIDNS). Each from the Linux release
//! that added it, ENOTTY before. NSFS_PIN also finds the bound file's
//! mount root in mountinfo as "uts:[<inum>]".

use super::{first_bad, fstat, in_child, ns_link, pid_path, stat};
use crate::harness::verdict_detail;
use crate::helpers::linux_at_least;
use hk_syscall::{
    CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS, O_CREAT, O_RDONLY,
    O_WRONLY, UtsName, sys_close, sys_exit, sys_fork, sys_getpid, sys_mkdir, sys_mount, sys_open,
    sys_pipe, sys_read, sys_sethostname, sys_setns, sys_uname, sys_unshare, sys_wait4, sys_write,
};

const EINVAL: i64 = -22;
const ESRCH: i64 = -3;
const MS_BIND: u64 = 4096;
const MS_REC: u64 = 16384;
const MS_PRIVATE: u64 = 1 << 18;

pub fn run_tests() {
    let r = in_child(inode_child);
    verdict_detail(b"NSFS_INODE", r == 0, r);
    let r = in_child(pin_child);
    verdict_detail(b"NSFS_PIN", r == 0, r);
    let r = in_child(pidfd_child);
    verdict_detail(b"NSFS_PIDFD", r == 0, r);
    let r = in_child(ioctl_child);
    verdict_detail(b"NSFS_IOCTL", r == 0, r);
    let r = in_child(ids_child);
    verdict_detail(b"NSFS_IDS", r == 0, r);
    let r = in_child(xlate_child);
    verdict_detail(b"NSFS_PIDNS_XLATE", r == 0, r);
}

/// Each link's name and what it reads
const LINKS: [(&[u8], &[u8]); 8] = [
    (b"net", b"net"),
    (b"uts", b"uts"),
    (b"ipc", b"ipc"),
    (b"pid", b"pid"),
    (b"pid_for_children", b"pid"),
    (b"user", b"user"),
    (b"mnt", b"mnt"),
    (b"cgroup", b"cgroup"),
];

/// st_dev and st_ino of /proc/<pid>/ns/<name>, (0, 0) on error
fn ns_id(pid: i64, name: &[u8]) -> (u64, u64) {
    let mut b = [0u8; 64];
    let mut post = [0u8; 32];
    post[..4].copy_from_slice(b"/ns/");
    post[4..4 + name.len()].copy_from_slice(name);
    let p = pid_path(&mut b, b"/proc/", pid, &post[..4 + name.len()]);
    stat(p).map_or((0, 0), |s| (s.st_dev, s.st_ino))
}

/// Child of NSFS_INODE
fn inode_child() -> u8 {
    let mut dev = 0;
    for (k, (name, real)) in LINKS.iter().enumerate() {
        let step = 10 * (k as u8 + 1);
        let mut path = [0u8; 40];
        let pre = b"/proc/self/ns/";
        path[..pre.len()].copy_from_slice(pre);
        path[pre.len()..pre.len() + name.len()].copy_from_slice(name);
        let p = &path[..=pre.len() + name.len()];
        let inum = ns_link(p, real);
        let Some(st) = stat(p) else { return step };
        let fa = sys_open(p.as_ptr(), O_RDONLY, 0);
        let fb = sys_open(p.as_ptr(), O_RDONLY, 0);
        let (sa, sb) = (fstat(fa), fstat(fb));
        sys_close(fa as u64);
        sys_close(fb as u64);
        let same = |s: Option<hk_syscall::Stat>| {
            s.is_some_and(|s| s.st_ino == inum && s.st_dev == st.st_dev)
        };
        if dev == 0 {
            dev = st.st_dev;
        }
        let bad = first_bad(&[
            inum != 0,
            st.st_ino == inum,
            st.st_mode == 0o100444,
            st.st_dev == dev,
            same(sa),
            same(sb),
            ns_id(sys_getpid(), name) == (dev, inum),
        ]);
        if bad != 0 {
            return step + bad;
        }
    }
    // A child shares every namespace: the same files, by its parent's
    // links and its own
    let parent = sys_getpid();
    let c = sys_fork();
    if c == 0 {
        let ok = LINKS
            .iter()
            .all(|(n, _)| ns_id(parent, n) == ns_id(sys_getpid(), n) && ns_id(parent, n).1 != 0);
        sys_exit(u64::from(!ok));
    }
    let mut ws = 0;
    if c < 0 || sys_wait4(c, &mut ws, 0, 0) != c || ws != 0 {
        return 1;
    }
    0
}

/// The UTS namespace's hostname is `want`
fn hostname_is(want: &[u8]) -> bool {
    let mut u = UtsName::default();
    sys_uname(&mut u) == 0 && &u.nodename[..want.len()] == want && u.nodename[want.len()] == 0
}

/// A child that makes a UTS namespace named "nsfspin", says so on
/// `up`, and exits when `down` is written or closed
fn pinned_task(up: [i32; 2], down: [i32; 2]) -> i64 {
    let c = sys_fork();
    if c == 0 {
        sys_close(up[0] as u64);
        sys_close(down[1] as u64);
        let ok = sys_unshare(CLONE_NEWUTS | CLONE_NEWNET) == 0
            && sys_sethostname(b"nsfspin".as_ptr(), 7) == 0;
        sys_write(up[1] as u64, b"x".as_ptr(), u64::from(ok));
        sys_close(up[1] as u64);
        let mut x = 0u8;
        sys_read(down[0] as u64, &mut x, 1);
        sys_exit(0);
    }
    c
}

/// Child of NSFS_PIN, in a mount namespace of its own
fn pin_child() -> u8 {
    let none = core::ptr::null();
    if sys_unshare(CLONE_NEWNS) != 0
        || sys_mount(none, b"/\0".as_ptr(), none, MS_REC | MS_PRIVATE, 0) != 0
    {
        return 100;
    }
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    sys_mkdir(b"/tmp/nsfs\0".as_ptr(), 0o755);
    if sys_mount(
        b"none\0".as_ptr(),
        b"/tmp/nsfs\0".as_ptr(),
        b"ramfs\0".as_ptr(),
        0,
        0,
    ) != 0
    {
        return 101;
    }
    let f = b"/tmp/nsfs/uts\0";
    let fd = sys_open(f.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    sys_close(fd as u64);
    let (mut up, mut down) = ([0i32; 2], [0i32; 2]);
    if fd < 0 || sys_pipe(up.as_mut_ptr()) != 0 || sys_pipe(down.as_mut_ptr()) != 0 {
        return 102;
    }
    let c = pinned_task(up, down);
    sys_close(up[1] as u64);
    sys_close(down[0] as u64);
    let mut x = 0u8;
    if c < 0 || sys_read(up[0] as u64, &mut x, 1) != 1 {
        return 103;
    }
    let mut b = [0u8; 64];
    let link = pid_path(&mut b, b"/proc/", c, b"/ns/uts");
    let inum = ns_link(link, b"uts");
    let held = sys_open(link.as_ptr(), O_RDONLY, 0);
    let bound = sys_mount(link.as_ptr(), f.as_ptr(), none, MS_BIND, 0);
    // The last task in the namespace exits and is reaped
    sys_close(down[1] as u64);
    let mut ws = 0;
    let reaped = sys_wait4(c, &mut ws, 0, 0) == c;
    let st = stat(f);
    // The fd still joins it, in a child (this task stays put)
    let g = sys_fork();
    if g == 0 {
        let ok = sys_setns(held as i32, CLONE_NEWNET as i32) == EINVAL
            && sys_setns(held as i32, CLONE_NEWUTS as i32) == 0
            && hostname_is(b"nsfspin");
        sys_exit(u64::from(!ok));
    }
    let mut gs = 0;
    let fd_ok = g > 0 && sys_wait4(g, &mut gs, 0, 0) == g && gs == 0;
    let held_ino = fstat(held).map_or(0, |s| s.st_ino);
    sys_close(held as u64);
    // The bind mount alone holds it now
    let byb = sys_open(f.as_ptr(), O_RDONLY, 0);
    let reg = sys_open(b"/proc/self/status\0".as_ptr(), O_RDONLY, 0);
    let steps = [
        inum != 0 && held >= 0,
        bound == 0,
        reaped,
        st.is_some_and(|s| s.st_ino == inum && s.st_mode == 0o100444)
            && mountinfo_has(b"uts", inum),
        fd_ok,
        held_ino == inum,
        byb >= 0 && fstat(byb).is_some_and(|s| s.st_ino == inum),
        sys_setns(reg as i32, 0) == EINVAL,
        sys_setns(byb as i32, 0) == 0,
        hostname_is(b"nsfspin"),
    ];
    first_bad(&steps)
}

/// Child of NSFS_PIDFD
fn pidfd_child() -> u8 {
    let (mut up, mut down) = ([0i32; 2], [0i32; 2]);
    if sys_pipe(up.as_mut_ptr()) != 0 || sys_pipe(down.as_mut_ptr()) != 0 {
        return 100;
    }
    let c = pinned_task(up, down);
    sys_close(up[1] as u64);
    sys_close(down[0] as u64);
    let mut x = 0u8;
    if c < 0 || sys_read(up[0] as u64, &mut x, 1) != 1 {
        return 101;
    }
    let mut b = [0u8; 64];
    let net = ns_link(pid_path(&mut b, b"/proc/", c, b"/ns/net"), b"net");
    let pfd = hk_syscall::sys_pidfd_open(c as i32, 0);
    let fd = pfd as i32;
    let steps1 = [
        pfd >= 0 && net != 0,
        sys_setns(fd, 0) == EINVAL,
        sys_setns(fd, (CLONE_NEWUTS | 1) as i32) == EINVAL,
        sys_setns(fd, (CLONE_NEWUTS | CLONE_NEWNET) as i32) == 0,
        hostname_is(b"nsfspin"),
        ns_link(b"/proc/self/ns/net\0", b"net") == net,
    ];
    sys_close(down[1] as u64);
    let mut ws = 0;
    let reaped = sys_wait4(c, &mut ws, 0, 0) == c;
    let bad = first_bad(&steps1);
    if bad != 0 {
        return bad;
    }
    match first_bad(&[reaped, sys_setns(fd, CLONE_NEWUTS as i32) == ESRCH]) {
        0 => 0,
        n => 10 + n,
    }
}

const NS_GET_USERNS: u64 = 0xb701;
const NS_GET_PARENT: u64 = 0xb702;
const NS_GET_NSTYPE: u64 = 0xb703;
const NS_GET_OWNER_UID: u64 = 0xb704;
const EPERM: i64 = -1;
const ENOTTY: i64 = -25;

/// ioctl(2) on a namespace file with no argument
fn nsio(fd: i64, cmd: u64) -> i64 {
    hk_syscall::sys_ioctl(fd as i32, cmd, 0)
}

/// st_ino of `fd`, 0 on error
fn ino(fd: i64) -> u64 {
    fstat(fd).map_or(0, |s| s.st_ino)
}

/// NS_GET_OWNER_UID of `fd`: the uid, or the error
fn owner_uid(fd: i64) -> i64 {
    let mut uid = u32::MAX;
    let r = hk_syscall::sys_ioctl(fd as i32, NS_GET_OWNER_UID, (&raw mut uid) as u64);
    if r < 0 { r } else { i64::from(uid) }
}

/// Child of NSFS_IOCTL
fn ioctl_child() -> u8 {
    let user = ns_link(b"/proc/self/ns/user\0", b"user");
    let uts = sys_open(b"/proc/self/ns/uts\0".as_ptr(), O_RDONLY, 0);
    let pid = sys_open(b"/proc/self/ns/pid\0".as_ptr(), O_RDONLY, 0);
    let u = nsio(uts, NS_GET_USERNS);
    let steps = [
        user != 0 && uts >= 0 && pid >= 0,
        nsio(uts, NS_GET_NSTYPE) == CLONE_NEWUTS as i64,
        u >= 0 && ino(u) == user,
        hk_syscall::sys_fcntl(u as i32, 1, 0) == 1,
        nsio(u, NS_GET_NSTYPE) == CLONE_NEWUSER as i64,
        // The initial namespaces have no owner or parent to give
        nsio(u, NS_GET_USERNS) == EPERM,
        nsio(u, NS_GET_PARENT) == EPERM,
        nsio(pid, NS_GET_PARENT) == EPERM,
        nsio(uts, NS_GET_PARENT) == EINVAL,
        owner_uid(uts) == EINVAL,
        owner_uid(u) == 0,
        nsio(uts, 0xb7ff) == ENOTTY,
    ];
    let bad = first_bad(&steps);
    if bad != 0 {
        return bad;
    }
    child_ns_ioctls(user)
}

/// The grandchild of NSFS_IOCTL: in a new pid namespace, it makes new
/// user and UTS namespaces and checks them from inside; exits 0 if
/// all passed once `down` is closed
fn ioctl_grandchild(user: u64, up: [i32; 2], down: [i32; 2]) -> ! {
    sys_close(up[0] as u64);
    sys_close(down[1] as u64);
    let mine = |p: &[u8]| sys_open(p.as_ptr(), O_RDONLY, 0);
    let pid = mine(b"/proc/self/ns/pid\0");
    let new_user = sys_unshare(CLONE_NEWUSER | CLONE_NEWUTS) == 0;
    let uts = mine(b"/proc/self/ns/uts\0");
    let u = mine(b"/proc/self/ns/user\0");
    let me = ns_link(b"/proc/self/ns/user\0", b"user");
    let o = nsio(uts, NS_GET_USERNS);
    let code = first_bad(&[
        new_user && me != 0 && me != user,
        o >= 0 && ino(o) == me,
        // Its parent is outside what it may see; its creator's uid has
        // no mapping in it
        nsio(u, NS_GET_PARENT) == EPERM,
        nsio(u, NS_GET_USERNS) == EPERM,
        owner_uid(u) == 65534,
        nsio(pid, NS_GET_PARENT) == EPERM,
    ]);
    sys_write(up[1] as u64, b"x".as_ptr(), 1);
    let mut x = 0u8;
    sys_read(down[0] as u64, &mut x, 1);
    sys_exit(u64::from(code));
}

/// NSFS_IOCTL on a child's new user, UTS and pid namespaces, seen from
/// inside and from here
fn child_ns_ioctls(user: u64) -> u8 {
    let pidns = ns_link(b"/proc/self/ns/pid\0", b"pid");
    if sys_unshare(CLONE_NEWPID) != 0 {
        return 50;
    }
    let (mut up, mut down) = ([0i32; 2], [0i32; 2]);
    if sys_pipe(up.as_mut_ptr()) != 0 || sys_pipe(down.as_mut_ptr()) != 0 {
        return 51;
    }
    let c = sys_fork();
    if c == 0 {
        ioctl_grandchild(user, up, down);
    }
    sys_close(up[1] as u64);
    sys_close(down[0] as u64);
    let mut x = 0u8;
    if c < 0 || sys_read(up[0] as u64, &mut x, 1) != 1 {
        return 52;
    }
    let mut b = [0u8; 64];
    let u = sys_open(
        pid_path(&mut b, b"/proc/", c, b"/ns/user").as_ptr(),
        O_RDONLY,
        0,
    );
    let p = sys_open(
        pid_path(&mut b, b"/proc/", c, b"/ns/pid").as_ptr(),
        O_RDONLY,
        0,
    );
    let (pu, pp) = (nsio(u, NS_GET_PARENT), nsio(p, NS_GET_PARENT));
    let steps = [
        pu >= 0 && ino(pu) == user,
        owner_uid(u) == 0,
        nsio(p, NS_GET_NSTYPE) == CLONE_NEWPID as i64,
        pp >= 0 && ino(pp) == pidns,
    ];
    sys_close(down[1] as u64);
    let mut ws = 0;
    if sys_wait4(c, &mut ws, 0, 0) != c {
        return 53;
    }
    match first_bad(&steps) {
        0 if ws == 0 => 0,
        0 => 70 + ((ws >> 8) & 0xff) as u8,
        n => 60 + n,
    }
}

const NS_GET_MNTNS_ID: u64 = 0x8008_b705;
const NS_GET_PID_FROM_PIDNS: u64 = 0x8004_b706;
const NS_GET_TGID_FROM_PIDNS: u64 = 0x8004_b707;
const NS_GET_PID_IN_PIDNS: u64 = 0x8004_b708;
const NS_GET_TGID_IN_PIDNS: u64 = 0x8004_b709;
const NS_MNT_GET_INFO: u64 = 0x8010_b70a;
const NS_MNT_GET_NEXT: u64 = 0x8010_b70b;
const NS_MNT_GET_PREV: u64 = 0x8010_b70c;
const NS_GET_ID: u64 = 0x8008_b70d;
const ENOENT: i64 = -2;

/// An id ioctl's u64 result, or the error
fn get_id(fd: i64, cmd: u64) -> Result<u64, i64> {
    let mut id = 0u64;
    match hk_syscall::sys_ioctl(fd as i32, cmd, (&raw mut id) as u64) {
        0 => Ok(id),
        r => Err(r),
    }
}

/// struct mnt_ns_info (size, nr_mounts, mnt_ns_id) an NS_MNT_GET_*
/// ioctl fills, with its return
fn mnt_info(fd: i64, cmd: u64) -> (i64, [u32; 2], u64) {
    let mut b = [0u64; 2];
    let r = hk_syscall::sys_ioctl(fd as i32, cmd, b.as_mut_ptr() as u64);
    (r, [b[0] as u32, (b[0] >> 32) as u32], b[1])
}

/// Child of NSFS_IDS: NS_GET_ID (Linux 6.18; the initial namespaces'
/// fixed ids from 6.19), NS_GET_MNTNS_ID (6.11), NS_MNT_GET_INFO,
/// NS_MNT_GET_NEXT and NS_MNT_GET_PREV (6.12); ENOTTY before
fn ids_child() -> u8 {
    let open = |p: &[u8]| sys_open(p.as_ptr(), O_RDONLY, 0);
    let mnt = open(b"/proc/self/ns/mnt\0");
    let uts = open(b"/proc/self/ns/uts\0");
    if mnt < 0 || uts < 0 {
        return 1;
    }
    let want = |v: bool, cmd_ok: bool, r: i64| if v { cmd_ok } else { r == ENOTTY };
    let mid = get_id(mnt, NS_GET_MNTNS_ID);
    let v611 = linux_at_least(6, 11);
    let v612 = linux_at_least(6, 12);
    let v618 = linux_at_least(6, 18);
    let err = |r: Result<u64, i64>| r.err().unwrap_or(0);
    let mut steps = [true; 11];
    steps[0] = want(v611, mid.is_ok_and(|i| i != 0), err(mid));
    steps[1] = want(
        v611,
        err(get_id(uts, NS_GET_MNTNS_ID)) == EINVAL,
        err(get_id(uts, NS_GET_MNTNS_ID)),
    );
    let gid = get_id(mnt, NS_GET_ID);
    steps[2] = want(v618, gid.is_ok() && gid == mid, err(gid));
    if linux_at_least(6, 19) {
        // The initial namespaces' fixed ids (uapi init_ns_id)
        let fixed: [(&[u8], u64); 6] = [
            (b"/proc/self/ns/ipc\0", 1),
            (b"/proc/self/ns/uts\0", 2),
            (b"/proc/self/ns/user\0", 3),
            (b"/proc/self/ns/pid\0", 4),
            (b"/proc/self/ns/cgroup\0", 5),
            (b"/proc/self/ns/mnt\0", 8),
        ];
        steps[3] = fixed
            .iter()
            .all(|(p, id)| get_id(open(p), NS_GET_ID) == Ok(*id));
    }
    let (r, [size, nr], id) = mnt_info(mnt, NS_MNT_GET_INFO);
    steps[4] = want(v612, r == 0 && size == 16 && Ok(id) == mid, r);
    // A new mount namespace: a higher id; one more mount, one more counted
    let none = core::ptr::null();
    let new_ok = sys_unshare(CLONE_NEWNS) == 0
        && sys_mount(none, b"/\0".as_ptr(), none, MS_REC | MS_PRIVATE, 0) == 0;
    let mine = open(b"/proc/self/ns/mnt\0");
    let nid = get_id(mine, NS_GET_MNTNS_ID);
    steps[5] = new_ok && want(v611, nid.is_ok_and(|n| mid.is_ok_and(|m| n > m)), err(nid));
    let (_, [_, nr0], _) = mnt_info(mine, NS_MNT_GET_INFO);
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    sys_mkdir(b"/tmp/nsid\0".as_ptr(), 0o755);
    let ramfs = sys_mount(
        b"none\0".as_ptr(),
        b"/tmp/nsid\0".as_ptr(),
        b"ramfs\0".as_ptr(),
        0,
        0,
    ) == 0;
    let (r, [_, nr1], _) = mnt_info(mine, NS_MNT_GET_INFO);
    steps[6] = ramfs && want(v612, nr1 == nr0 + 1 && nr > 0, r);
    // Neighbours in id order, each a new descriptor with its info
    let (r, _, nxt) = mnt_info(mnt, NS_MNT_GET_NEXT);
    steps[7] = want(
        v612,
        r >= 0 && mid.is_ok_and(|m| nxt > m) && get_id(r, NS_GET_MNTNS_ID) == Ok(nxt),
        r,
    );
    let (r, _, prv) = mnt_info(mine, NS_MNT_GET_PREV);
    steps[8] = want(v612, r >= 0 && nid.is_ok_and(|n| prv < n), r);
    // Nothing before the initial one
    let (r, _, _) = mnt_info(mnt, NS_MNT_GET_PREV);
    steps[9] = want(v612, r == ENOENT, r);
    steps[10] = want(
        v612,
        mnt_info(uts, NS_MNT_GET_INFO).0 == EINVAL,
        mnt_info(uts, NS_MNT_GET_INFO).0,
    );
    first_bad(&steps)
}

/// Child of NSFS_PIDNS_XLATE: NS_GET_{PID,TGID}_{FROM,IN}_PIDNS (Linux
/// 6.11; ENOTTY before) between a new pid namespace and this one; and
/// NS_MNT_GET_NEXT needs the initial pid namespace (EPERM)
fn xlate_child() -> u8 {
    if sys_unshare(CLONE_NEWPID) != 0 {
        return 50;
    }
    let (mut up, mut down) = ([0i32; 2], [0i32; 2]);
    if sys_pipe(up.as_mut_ptr()) != 0 || sys_pipe(down.as_mut_ptr()) != 0 {
        return 51;
    }
    let c = sys_fork();
    if c == 0 {
        sys_close(up[0] as u64);
        sys_close(down[1] as u64);
        let mnt = sys_open(b"/proc/self/ns/mnt\0".as_ptr(), O_RDONLY, 0);
        let r = mnt_info(mnt, NS_MNT_GET_NEXT).0;
        let ok = if linux_at_least(6, 12) {
            r == EPERM
        } else {
            r == ENOTTY
        };
        sys_write(up[1] as u64, b"x".as_ptr(), 1);
        let mut x = 0u8;
        sys_read(down[0] as u64, &mut x, 1);
        sys_exit(u64::from(!ok));
    }
    sys_close(up[1] as u64);
    sys_close(down[0] as u64);
    let mut x = 0u8;
    if c < 0 || sys_read(up[0] as u64, &mut x, 1) != 1 {
        return 52;
    }
    let mut b = [0u8; 64];
    let p = sys_open(
        pid_path(&mut b, b"/proc/", c, b"/ns/pid").as_ptr(),
        O_RDONLY,
        0,
    );
    let uts = sys_open(b"/proc/self/ns/uts\0".as_ptr(), O_RDONLY, 0);
    let io = |fd: i64, cmd: u64, arg: i64| hk_syscall::sys_ioctl(fd as i32, cmd, arg as u64);
    let me = sys_getpid();
    let checks: [(i64, u64, i64, i64); 7] = [
        (p, NS_GET_PID_IN_PIDNS, c, 1),
        (p, NS_GET_TGID_IN_PIDNS, c, 1),
        (p, NS_GET_PID_FROM_PIDNS, 1, c),
        (p, NS_GET_TGID_FROM_PIDNS, 1, c),
        (p, NS_GET_PID_IN_PIDNS, me, ESRCH),
        (p, NS_GET_PID_FROM_PIDNS, 99999, ESRCH),
        (uts, NS_GET_PID_IN_PIDNS, me, EINVAL),
    ];
    let v = linux_at_least(6, 11);
    let mut steps = [false; 8];
    for (k, (fd, cmd, arg, want)) in checks.iter().enumerate() {
        let r = io(*fd, *cmd, *arg);
        steps[k] = if v { r == *want } else { r == ENOTTY };
    }
    sys_close(down[1] as u64);
    let mut ws = 0;
    steps[7] = sys_wait4(c, &mut ws, 0, 0) == c && ws == 0;
    match first_bad(&[p >= 0 && uts >= 0]) {
        0 => first_bad(&steps),
        n => 60 + n,
    }
}

/// /proc/self/mountinfo names a mount's root "<ty>:[<inum>]" (Linux
/// nsfs_show_path)
fn mountinfo_has(ty: &[u8], inum: u64) -> bool {
    let mut needle = [0u8; 40];
    let mut n = ty.len();
    needle[..n].copy_from_slice(ty);
    needle[n..n + 2].copy_from_slice(b":[");
    n += 2;
    let mut d = [0u8; 20];
    let (mut k, mut v) = (0, inum);
    loop {
        d[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    while k > 0 {
        k -= 1;
        needle[n] = d[k];
        n += 1;
    }
    needle[n] = b']';
    n += 1;
    let mut buf = [0u8; 8192];
    let len = crate::helpers::read_file(b"/proc/self/mountinfo\0", &mut buf);
    len > 0 && buf[..len as usize].windows(n).any(|w| w == &needle[..n])
}
