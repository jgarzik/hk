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
//! - IPC_CAPS: SysV permissions as Linux ipcperms (a supplementary group
//!   grants group bits; CAP_IPC_OWNER overrides) and IPC_RMID as
//!   ipcctl_obtain_check (CAP_SYS_ADMIN for a non-owner); POSIX queues
//!   as generic_permission (CAP_DAC_OVERRIDE) with mq_unlink under the
//!   sticky rule of the mqueue root (EPERM for another's queue).
//! - KEYS_NO_ROOT_BYPASS: key permissions as Linux key_task_permission,
//!   with no root bypass: a root-owned key with no permission bits is
//!   unreadable even by root (EACCES); KEYCTL_SETPERM refuses unknown
//!   bits (EINVAL); KEYCTL_CHOWN gives the key away (root) and is
//!   EACCES for an owner without CAP_SYS_ADMIN.
//! - CLONE3_ERROR_NO_LEAK: clone3 that fails late (CLONE_INTO_CGROUP with
//!   a file that is no cgroup: EBADF; CLONE_NEWNS with CLONE_FS: EINVAL)
//!   leaves no child behind to wait for (Linux copy_process checks
//!   these before the child exists); the second is EINVAL even for an
//!   unprivileged caller.

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
    report(b"IPC_CAPS", ipc_caps());
    report(b"KEYS_NO_ROOT_BYPASS", in_child(keys_no_root_bypass));
    report(b"CLONE3_ERROR_NO_LEAK", in_child(clone3_error_no_leak));
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

const EACCES: i64 = -13;
const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_RMID: i32 = 0;
const GETVAL: i32 = 12;
const CAP_DAC_OVERRIDE: u32 = 1;
const CAP_DAC_READ_SEARCH: u32 = 2;
const CAP_IPC_OWNER: u32 = 15;
const MQ_NAME: &[u8] = b"caps_checks_q\0";

/// uid/gid 1000 in supplementary group 500, keeping capabilities, with
/// effective set `caps`
fn become_user(caps: u32) -> bool {
    let groups = [500u32];
    sys_prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == 0
        && hk_syscall::sys_setgroups(1, groups.as_ptr()) == 0
        && hk_syscall::sys_setresgid(1000, 1000, 1000) == 0
        && sys_setresuid(1000, 1000, 1000) == 0
        && set_effective(caps)
}

/// Root-owned 0600 set `own`, root-owned 0060 set `grp` of group 500,
/// root's 0600 queue: what uid 1000 may do with and without capabilities
fn ipc_user(own: i32, grp: i32) -> u64 {
    let getval = |id| hk_syscall::sys_semctl(id, 0, GETVAL, 0);
    // No capabilities: the owner's bits refuse it, the group's admit it
    let none = in_child_with(|| {
        if !become_user(0) {
            return 1;
        }
        if getval(own) != EACCES {
            return 2;
        }
        if getval(grp) != 0 {
            return 3;
        }
        if hk_syscall::sys_semctl(own, 0, IPC_RMID, 0) != EPERM {
            return 4;
        }
        let q = hk_syscall::sys_mq_open(
            MQ_NAME.as_ptr(),
            hk_syscall::O_RDWR as i32,
            0,
            core::ptr::null(),
        );
        if q != EACCES {
            return 5;
        }
        if hk_syscall::sys_mq_unlink(MQ_NAME.as_ptr()) != EPERM {
            return 6;
        }
        0
    });
    if none != 0 {
        return none;
    }
    // CAP_IPC_OWNER, CAP_DAC_OVERRIDE and CAP_SYS_ADMIN
    let caps =
        1 << CAP_IPC_OWNER | 1 << CAP_DAC_OVERRIDE | 1 << CAP_DAC_READ_SEARCH | 1 << CAP_SYS_ADMIN;
    in_child_with(move || {
        if !become_user(caps) {
            return 11;
        }
        if getval(own) != 0 {
            return 12;
        }
        let q = hk_syscall::sys_mq_open(
            MQ_NAME.as_ptr(),
            hk_syscall::O_RDWR as i32,
            0,
            core::ptr::null(),
        );
        if q < 0 {
            return 13;
        }
        hk_syscall::sys_close(q as u64);
        if hk_syscall::sys_semctl(own, 0, IPC_RMID, 0) != 0 {
            return 14;
        }
        0
    })
}

/// `f`'s verdict from a child
fn in_child_with(f: impl Fn() -> u64) -> u64 {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(f());
    }
    let mut ws = 0;
    sys_wait4(pid, &mut ws, 0, 0);
    if ws & 0x7f != 0 {
        101
    } else {
        (ws >> 8) as u64 & 0xff
    }
}

fn ipc_caps() -> u64 {
    let own = hk_syscall::sys_semget(IPC_PRIVATE, 1, IPC_CREAT | 0o600) as i32;
    let grp = hk_syscall::sys_semget(IPC_PRIVATE, 1, IPC_CREAT | 0o600) as i32;
    if own < 0 || grp < 0 {
        return 90;
    }
    // grp: group 500, mode 0060 (IPC_STAT, then IPC_SET with them)
    let mut ds = [0u32; 32];
    hk_syscall::sys_semctl(grp, 0, 2, ds.as_mut_ptr() as u64);
    ds[2] = 500; // sem_perm.gid
    ds[5] = 0o060; // sem_perm.mode
    if hk_syscall::sys_semctl(grp, 0, 1, ds.as_ptr() as u64) != 0 {
        return 91;
    }
    hk_syscall::sys_mq_unlink(MQ_NAME.as_ptr());
    let q = hk_syscall::sys_mq_open(
        MQ_NAME.as_ptr(),
        hk_syscall::O_RDWR as i32 | hk_syscall::O_CREAT as i32,
        0o600,
        core::ptr::null(),
    );
    if q < 0 {
        return 92;
    }
    hk_syscall::sys_close(q as u64);
    let r = ipc_user(own, grp);
    hk_syscall::sys_semctl(own, 0, IPC_RMID, 0);
    hk_syscall::sys_semctl(grp, 0, IPC_RMID, 0);
    hk_syscall::sys_mq_unlink(MQ_NAME.as_ptr());
    r
}

const KEYCTL_CHOWN: i32 = 4;
const KEYCTL_SETPERM: i32 = 5;
const KEYCTL_DESCRIBE: i32 = 6;
const KEYCTL_READ: i32 = 11;
const KEY_SPEC_PROCESS_KEYRING: i32 = -2;
const KEY_USR_ALL: u64 = 0x003f_0000;

fn add_key(desc: &[u8]) -> i64 {
    let payload = b"secret";
    hk_syscall::sys_add_key(
        b"user\0".as_ptr(),
        desc.as_ptr(),
        payload.as_ptr(),
        payload.len(),
        KEY_SPEC_PROCESS_KEYRING,
    )
}

fn keyctl(cmd: i32, a2: u64, a3: u64, a4: u64) -> i64 {
    hk_syscall::sys_keyctl(cmd, a2, a3, a4, 0)
}

/// In a child (its own process keyring)
fn keys_no_root_bypass() -> u64 {
    let k = add_key(b"nobypass\0");
    if k <= 0 {
        return 1;
    }
    let mut buf = [0u8; 64];
    // Unknown permission bits
    if keyctl(KEYCTL_SETPERM, k as u64, 0x4000_0000, 0) != -22 {
        return 2;
    }
    // No bits at all: root reads nothing
    if keyctl(KEYCTL_SETPERM, k as u64, 0, 0) != 0 {
        return 3;
    }
    if keyctl(
        KEYCTL_READ,
        k as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    ) != EACCES
    {
        return 4;
    }
    // A key the user may set attributes on, given to uid 1000
    let k2 = add_key(b"chown\0");
    if keyctl(KEYCTL_SETPERM, k2 as u64, KEY_USR_ALL | 0x3f, 0) != 0 {
        return 5;
    }
    if keyctl(KEYCTL_CHOWN, k2 as u64, 1000, u32::MAX as u64) != 0 {
        return 6;
    }
    let n = keyctl(
        KEYCTL_DESCRIBE,
        k2 as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    );
    if n <= 0 || !buf.starts_with(b"user;1000;") {
        return 7;
    }
    // Its new owner, without CAP_SYS_ADMIN, may not give it away
    if sys_setresuid(1000, 1000, 1000) != 0 {
        return 8;
    }
    if keyctl(KEYCTL_CHOWN, k2 as u64, 0, u32::MAX as u64) != EACCES {
        return 9;
    }
    0
}

/// In a child with no children of its own
fn clone3_error_no_leak() -> u64 {
    const CLONE_FS: u64 = 0x200;
    const CLONE_NEWNS: u64 = 0x2_0000;
    const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;
    const SIGCHLD: u64 = 17;
    let fd = hk_syscall::sys_open(b"/proc/self/status\0".as_ptr(), hk_syscall::O_RDONLY, 0);
    if fd < 0 {
        return 1;
    }
    let mut args = hk_syscall::CloneArgs {
        flags: CLONE_INTO_CGROUP,
        pidfd: 0,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: SIGCHLD,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: fd as u64,
    };
    let size = core::mem::size_of::<hk_syscall::CloneArgs>();
    let r = hk_syscall::sys_clone3(&args, size);
    if r == 0 {
        sys_exit(0);
    }
    if r != -9 {
        return 2;
    }
    args.flags = CLONE_NEWNS | CLONE_FS;
    let r = hk_syscall::sys_clone3(&args, size);
    if r == 0 {
        sys_exit(0);
    }
    if r != -22 {
        return 3;
    }
    // Nothing to wait for
    let mut ws = 0;
    if hk_syscall::sys_wait4(-1, &mut ws, 1, 0) != -10 {
        return 4;
    }
    // The flag combination is EINVAL before any capability check
    if sys_setresuid(1000, 1000, 1000) != 0 {
        return 5;
    }
    let r = hk_syscall::sys_clone3(&args, size);
    if r == 0 {
        sys_exit(0);
    }
    if r != -22 {
        return 6;
    }
    0
}
