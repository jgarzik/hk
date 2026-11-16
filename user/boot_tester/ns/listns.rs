//! listns(2) (Linux kernel/nstree.c, 6.19+): namespace ids in id order
//!
//! LISTNS_ALL: every type lists the caller's own namespaces, ascending;
//! one type only its own; several types those; paging by `ns_id` gives
//! the same ids as one call; LISTNS_CURRENT_USER those the caller's user
//! namespace owns (not itself), and a user namespace's id those it owns.
//!
//! LISTNS_ACTIVE: a namespace is listed while something holds it in
//! active use. A UTS namespace a child unshares is listed; once the
//! child is reaped an fd to its /proc/<pid>/ns/uts still keeps it
//! listed, and after that fd closes it is gone.
//!
//! LISTNS_UNPRIV: a caller without CAP_SYS_ADMIN (setuid to nobody)
//! sees only its own namespaces, by type or by its user namespace.
//!
//! LISTNS_ERRNO: EINVAL for flags, a short size, `spare` or an unknown
//! user namespace; E2BIG past a page or with nonzero unknown fields;
//! EOPNOTSUPP for an unknown type; EOVERFLOW past a million ids; ENOENT
//! past the last id; EFAULT for the request or the id buffer.
//!
//! Skipped before Linux 6.19, which has no listns.

use super::{first_bad, in_child, pid_path};
use crate::harness::verdict_detail;
use crate::helpers::{linux_at_least, skip};
use hk_syscall::{
    CLONE_NEWIPC, CLONE_NEWNS, CLONE_NEWUSER, CLONE_NEWUTS, O_RDONLY, sys_close, sys_exit,
    sys_fork, sys_listns, sys_open, sys_pipe, sys_read, sys_setgid, sys_setuid, sys_unshare,
    sys_wait4, sys_write,
};

const EINVAL: i64 = -22;
const E2BIG: i64 = -7;
const EFAULT: i64 = -14;
const ENOENT: i64 = -2;
const EOVERFLOW: i64 = -75;
const EOPNOTSUPP: i64 = -95;
const NS_GET_ID: u64 = 0x8008_b70d;
const LISTNS_CURRENT_USER: u64 = u64::MAX;
const CLONE_NEWCGROUP: u64 = 0x0200_0000;
const CLONE_NEWPID: u64 = 0x2000_0000;
const CLONE_NEWNET: u64 = 0x4000_0000;
/// Room for every id a test lists
const MAX: usize = 256;

pub fn run_tests() {
    if !linux_at_least(6, 19) {
        for t in [
            &b"LISTNS_ALL"[..],
            b"LISTNS_ACTIVE",
            b"LISTNS_UNPRIV",
            b"LISTNS_ERRNO",
        ] {
            skip(t, b"no listns before Linux 6.19");
        }
        return;
    }
    let r = in_child(all_child);
    verdict_detail(b"LISTNS_ALL", r == 0, r);
    let r = in_child(active_child);
    verdict_detail(b"LISTNS_ACTIVE", r == 0, r);
    let r = in_child(unpriv_child);
    verdict_detail(b"LISTNS_UNPRIV", r == 0, r);
    let r = in_child(errno_child);
    verdict_detail(b"LISTNS_ERRNO", r == 0, r);
}

/// struct ns_id_req, with room past it for a longer version
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Req {
    size: u32,
    spare: u32,
    ns_id: u64,
    ns_type: u32,
    spare2: u32,
    user_ns_id: u64,
    more: [u64; 2],
}

fn req(ns_id: u64, ns_type: u64, user_ns_id: u64) -> Req {
    Req {
        size: 32,
        ns_id,
        ns_type: ns_type as u32,
        user_ns_id,
        ..Req::default()
    }
}

/// listns(2) of `r` into `ids` (all of it)
fn listns(r: &Req, ids: &mut [u64]) -> i64 {
    sys_listns(
        (r as *const Req) as u64,
        ids.as_mut_ptr() as u64,
        ids.len() as u64,
        0,
    )
}

/// The ids listns gives for `r`, None on an error
fn list(r: &Req, ids: &mut [u64; MAX]) -> Option<usize> {
    let n = listns(r, ids);
    (n >= 0 && (n as usize) < MAX).then_some(n as usize)
}

/// Strictly ascending
fn ascending(ids: &[u64]) -> bool {
    ids.windows(2).all(|w| w[0] < w[1])
}

/// NS_GET_ID of `fd`, 0 on error
fn fd_id(fd: i64) -> u64 {
    let mut id = 0u64;
    if hk_syscall::sys_ioctl(fd as i32, NS_GET_ID, (&raw mut id) as u64) != 0 {
        return 0;
    }
    id
}

/// NS_GET_ID of the namespace file `path` (NUL-terminated), 0 on error
fn path_id(path: &[u8]) -> u64 {
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return 0;
    }
    let id = fd_id(fd);
    sys_close(fd as u64);
    id
}

/// The caller's own namespaces' ids: mnt, uts, ipc, net, pid, user,
/// cgroup (each nonzero)
fn own() -> [u64; 7] {
    [
        path_id(b"/proc/self/ns/mnt\0"),
        path_id(b"/proc/self/ns/uts\0"),
        path_id(b"/proc/self/ns/ipc\0"),
        path_id(b"/proc/self/ns/net\0"),
        path_id(b"/proc/self/ns/pid\0"),
        path_id(b"/proc/self/ns/user\0"),
        path_id(b"/proc/self/ns/cgroup\0"),
    ]
}

/// Index of the user namespace in [`own`]
const USER: usize = 5;

/// Every type, one, several, paging, by user namespace (as root in the
/// initial namespaces)
fn all_child() -> u8 {
    let mine = own();
    let [mnt, uts, ipc, _, _, user, _] = mine;
    let mut a = [0u64; MAX];
    let Some(n) = list(&req(0, 0, 0), &mut a) else {
        return 100;
    };
    let all = &a[..n];
    let mut t = [0u64; MAX];
    let Some(nt) = list(&req(0, CLONE_NEWUTS, 0), &mut t) else {
        return 101;
    };
    let uts_only = &t[..nt];
    let mut m = [0u64; MAX];
    let Some(nm) = list(&req(0, CLONE_NEWUTS | CLONE_NEWIPC, 0), &mut m) else {
        return 102;
    };
    let multi = &m[..nm];
    let mut u = [0u64; MAX];
    let Some(nu) = list(&req(0, 0, LISTNS_CURRENT_USER), &mut u) else {
        return 103;
    };
    let by_user = &u[..nu];
    let mut i = [0u64; MAX];
    let Some(ni) = list(&req(0, 0, user), &mut i) else {
        return 104;
    };
    first_bad(&[
        mine.iter().all(|&id| id != 0),
        ascending(all) && mine.iter().all(|id| all.contains(id)),
        ascending(uts_only) && uts_only.contains(&uts) && !uts_only.contains(&mnt),
        nt < n && uts_only.iter().all(|id| all.contains(id)),
        multi.contains(&uts) && multi.contains(&ipc) && !multi.contains(&mnt),
        paging(),
        // The initial user namespace owns all but itself
        ascending(by_user) && !by_user.contains(&user),
        mine.iter()
            .enumerate()
            .all(|(k, id)| k == USER || by_user.contains(id)),
        &i[..ni] == by_user,
        // Nothing asked for, nothing listed
        listns(&req(0, 0, 0), &mut a[..0]) == 0,
    ])
}

/// One UTS namespace per call, each resuming past the last id, gives
/// what one call does; past the last one is ENOENT (Linux: no namespace
/// after the last id). Two more UTS namespaces are made first, one held
/// by an fd, one the caller's: UTS namespaces leave the tree as they go
/// inactive, so the walk meets no inactive one.
fn paging() -> bool {
    let made = sys_unshare(CLONE_NEWUTS) == 0;
    let held = sys_open(b"/proc/self/ns/uts\0".as_ptr(), O_RDONLY, 0);
    let made = made && held >= 0 && sys_unshare(CLONE_NEWUTS) == 0;
    let mut full = [0u64; MAX];
    let nf = list(&req(0, CLONE_NEWUTS, 0), &mut full).unwrap_or(0);
    let mut p = [0u64; MAX];
    let mut np = 0;
    let mut end = false;
    while np < MAX {
        let last = if np == 0 { 0 } else { p[np - 1] };
        match listns(&req(last, CLONE_NEWUTS, 0), &mut p[np..=np]) {
            1 => np += 1,
            ENOENT if np > 0 => {
                end = true;
                break;
            }
            _ => break,
        }
    }
    made && nf >= 3 && end && p[..np] == full[..nf]
}

/// Read one id from `fd`, 0 on error
fn read_id(fd: i32) -> u64 {
    let mut b = [0u8; 8];
    if sys_read(fd as u64, b.as_mut_ptr(), 8) != 8 {
        return 0;
    }
    u64::from_ne_bytes(b)
}

/// `id` is listed among every UTS namespace
fn uts_listed(id: u64) -> bool {
    let mut t = [0u64; MAX];
    list(&req(0, CLONE_NEWUTS, 0), &mut t).is_some_and(|n| t[..n].contains(&id))
}

/// A child's new UTS namespace: listed while the child lives, then
/// while an fd to its namespace file is open, gone after
fn active_child() -> u8 {
    let (mut up, mut down) = ([0i32; 2], [0i32; 2]);
    if sys_pipe(up.as_mut_ptr()) != 0 || sys_pipe(down.as_mut_ptr()) != 0 {
        return 100;
    }
    let c = sys_fork();
    if c == 0 {
        sys_close(up[0] as u64);
        sys_close(down[1] as u64);
        let id = if sys_unshare(CLONE_NEWUTS) == 0 {
            path_id(b"/proc/self/ns/uts\0")
        } else {
            0
        };
        // It sees its own new namespace listed
        let seen = id != 0 && uts_listed(id);
        let v = if seen { id } else { 0 };
        sys_write(up[1] as u64, v.to_ne_bytes().as_ptr(), 8);
        let mut x = 0u8;
        sys_read(down[0] as u64, &mut x, 1);
        sys_exit(0);
    }
    sys_close(up[1] as u64);
    sys_close(down[0] as u64);
    if c < 0 {
        return 101;
    }
    let id = read_id(up[0]);
    let mut b = [0u8; 64];
    let held = sys_open(
        pid_path(&mut b, b"/proc/", c, b"/ns/uts").as_ptr(),
        O_RDONLY,
        0,
    );
    let listed = uts_listed(id);
    // The child exits and is reaped: the fd alone holds it active
    sys_close(down[1] as u64);
    let mut ws = 0;
    let reaped = sys_wait4(c, &mut ws, 0, 0) == c;
    let pinned = uts_listed(id);
    let same = fd_id(held) == id;
    sys_close(held as u64);
    let gone = !uts_listed(id);
    first_bad(&[id != 0, held >= 0 && same, listed, reaped && pinned, gone])
}

/// Without CAP_SYS_ADMIN: only the caller's own namespaces
fn unpriv_child() -> u8 {
    let mine = own();
    if mine.contains(&0) || sys_setgid(65534) != 0 || sys_setuid(65534) != 0 {
        return 100;
    }
    // Its time namespaces count as its own too where they exist
    let time = path_id(b"/proc/self/ns/time\0");
    let ok_id = |id: &u64| mine.contains(id) || (time != 0 && *id == time);
    let mut a = [0u64; MAX];
    let Some(n) = list(&req(0, 0, 0), &mut a) else {
        return 101;
    };
    let all = &a[..n];
    let mut u = [0u64; MAX];
    let Some(nu) = list(&req(0, 0, LISTNS_CURRENT_USER), &mut u) else {
        return 102;
    };
    let by_user = &u[..nu];
    let mut t = [0u64; MAX];
    let types = CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWPID | CLONE_NEWCGROUP | CLONE_NEWUSER;
    let Some(nt) = list(&req(0, types, 0), &mut t) else {
        return 103;
    };
    first_bad(&[
        all.iter().all(ok_id) && mine.iter().all(|id| all.contains(id)),
        by_user.iter().all(ok_id) && !by_user.contains(&mine[USER]),
        mine.iter()
            .enumerate()
            .all(|(k, id)| k == USER || by_user.contains(id)),
        nt == 5 && [0, 3, 4, 5, 6].iter().all(|&k| t[..nt].contains(&mine[k])),
    ])
}

/// listns(2) of `r` with `nr` ids at `ids` and `flags`
fn raw(r: u64, ids: u64, nr: u64, flags: u32) -> i64 {
    sys_listns(r, ids, nr, flags)
}

fn errno_child() -> u8 {
    let mut ids = [0u64; 4];
    let p = ids.as_mut_ptr() as u64;
    let ok = req(0, 0, 0);
    let at = |r: &Req| (r as *const Req) as u64;
    let with = |f: fn(&mut Req)| {
        let mut r = req(0, 0, 0);
        f(&mut r);
        r
    };
    let short = with(|r| r.size = 24);
    let page = with(|r| r.size = 8192);
    let spare = with(|r| r.spare = 1);
    let longer = with(|r| r.size = 40);
    let unknown = with(|r| {
        r.size = 40;
        r.more[0] = 1;
    });
    let bad_type = with(|r| r.ns_type = 1);
    let past = req(1 << 62, 0, 0);
    let no_user = req(0, 0, 1 << 62);
    first_bad(&[
        raw(at(&ok), p, 4, 1) == EINVAL,
        raw(at(&ok), p, 1_000_001, 0) == EOVERFLOW,
        raw(at(&short), p, 4, 0) == EINVAL,
        raw(at(&page), p, 4, 0) == E2BIG,
        raw(at(&spare), p, 4, 0) == EINVAL,
        raw(at(&longer), p, 4, 0) == 4,
        raw(at(&unknown), p, 4, 0) == E2BIG,
        raw(at(&bad_type), p, 4, 0) == EOPNOTSUPP,
        raw(at(&past), p, 4, 0) == ENOENT,
        raw(at(&no_user), p, 4, 0) == EINVAL,
        raw(0, p, 4, 0) == EFAULT,
        // The id buffer: outside user space (access_ok), then unmapped
        raw(at(&ok), u64::MAX - 7, 1, 0) == EFAULT,
        raw(at(&ok), 0x1000, 4, 0) == EFAULT,
    ])
}
