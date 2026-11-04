//! Privilege is a capability, not uid 0 (Linux capable() at each check).
//!
//! - SETID_CAPS: root without CAP_SETUID/CAP_SETGID in its effective set
//!   is refused setuid/setgid/setresuid/setreuid (EPERM); a uid-1000
//!   process that kept CAP_SETUID (PR_SET_KEEPCAPS) may setuid to any
//!   uid, but not setgid without CAP_SETGID (Linux kernel/sys.c
//!   ns_capable_setid).
//! - NS_CAPS: root without CAP_SYS_ADMIN is refused sethostname,
//!   setdomainname, unshare(CLONE_NEWUTS) and setns (EPERM); uid 1000
//!   holding CAP_SYS_ADMIN may unshare a UTS namespace and name it.
//! - PRLIMIT_PERM: prlimit64 on another task needs matching ids or
//!   CAP_SYS_RESOURCE (Linux check_prlimit_permission), even to read: a
//!   uid-1000 process gets EPERM for a root task, 0 for its own child;
//!   root may read anyone's.
//! - SETRLIMIT_EFAULT_FIRST: setrlimit copies the limit in before it
//!   looks at the resource (EFAULT, not EINVAL).

use super::helpers::{print, print_num, println};
use hk_syscall::{
    _LINUX_CAPABILITY_VERSION_3, CapUserData, CapUserHeader, PR_SET_KEEPCAPS, sys_capget,
    sys_capset, sys_exit, sys_fork, sys_getuid, sys_prctl, sys_setgid, sys_setresuid, sys_setreuid,
    sys_setuid, sys_wait4,
};

const EPERM: i64 = -1;
const CAP_SETGID: u32 = 6;
const CAP_SETUID: u32 = 7;
const CAP_SYS_ADMIN: u32 = 21;
const CLONE_NEWUTS: u64 = 0x0400_0000;

pub fn run_tests() {
    report(b"SETID_CAPS_DROPPED", in_child(setid_dropped));
    report(b"SETID_CAPS_KEPT", in_child(setid_kept));
    report(b"NS_CAPS_DROPPED", in_child(ns_dropped));
    report(b"NS_CAPS_KEPT", in_child(ns_kept));
    report(b"PRLIMIT_PERM", prlimit_perm());
    let r = hk_syscall::sys_setrlimit(9999, core::ptr::null());
    report(b"SETRLIMIT_EFAULT_FIRST", (r != -14) as u64);
}

fn report(name: &[u8], step: u64) {
    print(name);
    if step == 0 {
        println(b":OK");
    } else {
        print(b":FAIL step ");
        print_num(step as i64);
        println(b"");
    }
}

/// `f`'s verdict from a child (0 OK, else the failing step)
fn in_child(f: fn() -> u64) -> u64 {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(f());
    }
    let mut ws = 0;
    if pid < 0 || sys_wait4(pid, &mut ws, 0, 0) != pid {
        return 100;
    }
    if ws & 0x7f != 0 {
        101
    } else {
        (ws >> 8) as u64 & 0xff
    }
}

/// Set this process's effective set to exactly `caps` (a mask of
/// capabilities below 32), permitted and inheritable unchanged
fn set_effective(caps: u32) -> bool {
    let mut h = CapUserHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut d = [CapUserData::default(); 2];
    if sys_capget(&mut h, d.as_mut_ptr()) != 0 {
        return false;
    }
    d[0].effective = caps;
    d[1].effective = 0;
    sys_capset(&h, d.as_ptr()) == 0
}

/// Root minus CAP_SETUID and CAP_SETGID
fn setid_dropped() -> u64 {
    let all_but = !(1u32 << CAP_SETUID | 1 << CAP_SETGID);
    if !set_effective(all_but) {
        return 1;
    }
    if sys_setuid(1000) != EPERM {
        return 2;
    }
    if sys_setgid(1000) != EPERM {
        return 3;
    }
    if sys_setresuid(1000, 1000, 1000) != EPERM {
        return 4;
    }
    if sys_setreuid(1000, u32::MAX) != EPERM {
        return 5;
    }
    0
}

/// uid 1000 that kept its capabilities, CAP_SETUID back in effective
fn setid_kept() -> u64 {
    if sys_prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0 {
        return 1;
    }
    if sys_setresuid(1000, 1000, 1000) != 0 {
        return 2;
    }
    if !set_effective(1 << CAP_SETUID) {
        return 3;
    }
    if sys_setuid(2000) != 0 || sys_getuid() != 2000 {
        return 4;
    }
    if sys_setgid(3000) != EPERM {
        return 5;
    }
    0
}

/// Root minus CAP_SYS_ADMIN
fn ns_dropped() -> u64 {
    if !set_effective(!(1u32 << CAP_SYS_ADMIN)) {
        return 1;
    }
    let name = b"nocap";
    if hk_syscall::sys_sethostname(name.as_ptr(), name.len() as u64) != EPERM {
        return 2;
    }
    if hk_syscall::sys_setdomainname(name.as_ptr(), name.len() as u64) != EPERM {
        return 3;
    }
    if hk_syscall::sys_unshare(CLONE_NEWUTS) != EPERM {
        return 4;
    }
    let fd = hk_syscall::sys_open(b"/proc/self/ns/uts\0".as_ptr(), hk_syscall::O_RDONLY, 0);
    if fd < 0 {
        return 5;
    }
    if hk_syscall::sys_setns(fd as i32, CLONE_NEWUTS as i32) != EPERM {
        return 6;
    }
    0
}

/// uid 1000 that kept its capabilities, CAP_SYS_ADMIN in effective
fn ns_kept() -> u64 {
    if sys_prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0 || sys_setresuid(1000, 1000, 1000) != 0 {
        return 1;
    }
    if !set_effective(1 << CAP_SYS_ADMIN) {
        return 2;
    }
    if hk_syscall::sys_unshare(CLONE_NEWUTS) != 0 {
        return 3;
    }
    let name = b"capns";
    if hk_syscall::sys_sethostname(name.as_ptr(), name.len() as u64) != 0 {
        return 4;
    }
    0
}

const RLIMIT_NOFILE: u32 = 7;

fn prlimit_get(pid: i64) -> i64 {
    let mut old = hk_syscall::RLimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    hk_syscall::sys_prlimit64(pid as i32, RLIMIT_NOFILE, core::ptr::null(), &mut old)
}

/// A child that sleeps until killed
fn sleeper() -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        loop {
            hk_syscall::sys_pause();
        }
    }
    pid
}

fn reap(pid: i64) {
    hk_syscall::sys_kill(pid, 9);
    let mut ws = 0;
    sys_wait4(pid, &mut ws, 0, 0);
}

/// As uid 1000: EPERM for root's `root_task`, 0 for its own child
fn prlimit_user(root_task: i64) -> u64 {
    if sys_setresuid(1000, 1000, 1000) != 0 {
        return 1;
    }
    if prlimit_get(root_task) != EPERM {
        return 2;
    }
    let mine = sleeper();
    let new = hk_syscall::RLimit {
        rlim_cur: 64,
        rlim_max: 64,
    };
    let r = hk_syscall::sys_prlimit64(mine as i32, RLIMIT_NOFILE, &new, core::ptr::null_mut());
    reap(mine);
    if r != 0 {
        return 3;
    }
    0
}

fn prlimit_perm() -> u64 {
    let root_task = sleeper();
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(prlimit_user(root_task));
    }
    let mut ws = 0;
    sys_wait4(pid, &mut ws, 0, 0);
    let step = if ws & 0x7f != 0 {
        101
    } else {
        (ws >> 8) as u64 & 0xff
    };
    // Root reads a uid-1000 task's limits (CAP_SYS_RESOURCE)
    let user = sys_fork();
    if user == 0 {
        sys_setresuid(1000, 1000, 1000);
        loop {
            hk_syscall::sys_pause();
        }
    }
    // Allowed whether or not it has dropped to uid 1000 yet
    let r = prlimit_get(user);
    reap(user);
    reap(root_task);
    if step != 0 {
        return step;
    }
    if r != 0 { 10 } else { 0 }
}
