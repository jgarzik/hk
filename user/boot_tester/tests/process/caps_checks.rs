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
//! - RLIMIT_RAISE_RACE: an unprivileged process lowers its hard
//!   RLIMIT_NOFILE while a thread keeps setting the old hard value:
//!   once lowered it stays lowered (a set that saw the old value but
//!   stored after the lower would be an unprivileged raise; Linux
//!   do_prlimit decides and stores under task_lock). 30 rounds.
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
//! - KEY_REVOKE_UPDATE: an update after a revoke is EKEYREVOKED, and a
//!   thread updating in a loop while the key is revoked never revives
//!   it (Linux: key_update and key_revoke under key->sem).

use crate::tests::harness::fail_num;
use crate::tests::helpers::{print, println};
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
    report(b"RLIMIT_RAISE_RACE", rlimit_raise_race());
    let r = hk_syscall::sys_setrlimit(9999, core::ptr::null());
    report(b"SETRLIMIT_EFAULT_FIRST", (r != -14) as u64);
    report(b"IPC_CAPS", ipc_caps());
    report(b"KEYS_NO_ROOT_BYPASS", in_child(keys_no_root_bypass));
    report(b"CLONE3_ERROR_NO_LEAK", in_child(clone3_error_no_leak));
    report(b"KEY_REVOKE_UPDATE", in_child_with(key_revoke_update));
    report(b"SIGNAL_PERM", signal_perm());
    report(b"KEY_CYCLE_EDEADLK", key_cycle());
    report(b"KEY_DEPTH_ELOOP", key_depth());
    report(b"KEY_SEARCH_NESTED_PERM", key_search_nested());
    report(b"KEY_FORK_KEYRINGS", in_child(key_fork_keyrings));
    report(b"KEY_LINK_PERM", key_link_perm());
    report(b"KEY_QUOTA", key_quota());
    report(b"KEY_GC", key_gc());
    report(b"KEY_UPDATE_QUOTA", key_update_quota());
    report(b"BPF_UNPRIV_EPERM", in_child(bpf_unpriv));
    report(b"BPF_UNPRIV_SYSCTL", bpf_sysctl());
}

fn report(name: &[u8], step: u64) {
    print(name);
    if step == 0 {
        println(b":OK");
    } else {
        fail_num(b":FAIL step ", step as i64);
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

/// An unprivileged process without CAP_KILL cannot signal a process it
/// does not own (Linux check_kill_permission): kill and tgkill both
/// return EPERM. The attacker drops to uid 1000 with no capabilities;
/// the victim stays root.
fn signal_perm() -> u64 {
    const SIGKILL: u32 = 9;
    let victim = sleeper();
    if victim < 0 {
        return 90;
    }
    let att = sys_fork();
    if att == 0 {
        const CAP_KILL: u32 = 5;
        // Drop CAP_KILL while still root (capset can only shrink), then
        // become uid 1000: now neither capability nor ownership permits
        // signaling the root victim
        let code = if !set_effective(!(1 << CAP_KILL)) {
            2
        } else if sys_setresuid(1000, 1000, 1000) != 0 {
            3
        } else if hk_syscall::sys_kill(victim, SIGKILL) != EPERM {
            4
        } else if hk_syscall::sys_tgkill(victim, victim, SIGKILL) != EPERM {
            5
        } else {
            0
        };
        sys_exit(code);
    }
    let mut st = 0i32;
    sys_wait4(att, &mut st, 0, 0);
    reap(victim);
    if st & 0x7f != 0 {
        return 80;
    }
    ((st >> 8) & 0xff) as u64
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

const KEYCTL_LINK: i32 = 8;
const EDEADLK: i64 = -35;

/// A "keyring" key in the process keyring
/// A cycle found within the search depth is EDEADLK; a link whose
/// check must go past 6 nested keyrings is ELOOP (Linux
/// keyring_detect_cycle with KEYRING_SEARCH_DETECT_TOO_DEEP)
fn key_depth() -> u64 {
    const ELOOP: i64 = -40;
    let mut k = [0i64; 9];
    for (i, r) in k.iter_mut().enumerate() {
        let desc = [b'd', b'e', b'p', b'0' + i as u8, 0];
        *r = add_keyring(&desc);
        if *r <= 0 {
            return 1;
        }
    }
    // K[i + 1] linked into K[i]: a chain nine deep
    for i in 0..8 {
        if keyctl(KEYCTL_LINK, k[i + 1] as u64, k[i] as u64, 0) != 0 {
            return 2;
        }
    }
    if keyctl(KEYCTL_LINK, k[0] as u64, k[7] as u64, 0) != EDEADLK {
        return 3;
    }
    if keyctl(KEYCTL_LINK, k[0] as u64, k[8] as u64, 0) != ELOOP {
        return 4;
    }
    0
}

/// KEYCTL_SEARCH checks SEARCH on every nested keyring and on the key
/// it finds (Linux search_nested_keyrings): a denied nested keyring is
/// skipped (ENOKEY), a denied match is EACCES
fn key_search_nested() -> u64 {
    const KEYCTL_SEARCH: i32 = 10;
    const ENOKEY: i64 = -126;
    const EACCES: i64 = -13;
    const ALL: u64 = 0x3f3f_0000;
    const NO_SEARCH: u64 = 0x3737_0000;
    let outer = add_keyring(b"ns_outer\0");
    let inner = hk_syscall::sys_add_key(
        b"keyring\0".as_ptr(),
        b"ns_inner\0".as_ptr(),
        core::ptr::null(),
        0,
        outer as i32,
    );
    let key = hk_syscall::sys_add_key(
        b"user\0".as_ptr(),
        b"ns_key\0".as_ptr(),
        b"x".as_ptr(),
        1,
        inner as i32,
    );
    if outer <= 0 || inner <= 0 || key <= 0 {
        return 1;
    }
    let search = || {
        keyctl(
            KEYCTL_SEARCH,
            outer as u64,
            b"user\0".as_ptr() as u64,
            b"ns_key\0".as_ptr() as u64,
        )
    };
    if search() != key {
        return 2;
    }
    if keyctl(KEYCTL_SETPERM, inner as u64, NO_SEARCH, 0) != 0 {
        return 3;
    }
    if search() != ENOKEY {
        return 4;
    }
    if keyctl(KEYCTL_SETPERM, inner as u64, ALL, 0) != 0
        || keyctl(KEYCTL_SETPERM, key as u64, NO_SEARCH, 0) != 0
    {
        return 5;
    }
    if search() != EACCES {
        return 6;
    }
    0
}

/// A forked process inherits its parent's session keyring but not its
/// process keyring (Linux copy_creds)
fn key_fork_keyrings() -> u64 {
    const KEYCTL_GET_KEYRING_ID: i32 = 0;
    const SESSION: u64 = -3i64 as u64;
    const PROCESS: u64 = -2i64 as u64;
    const ENOKEY: i64 = -126;
    let ses = keyctl(KEYCTL_GET_KEYRING_ID, SESSION, 1, 0);
    let proc_ = keyctl(KEYCTL_GET_KEYRING_ID, PROCESS, 1, 0);
    if ses <= 0 || proc_ <= 0 {
        return 1;
    }
    let pid = sys_fork();
    if pid == 0 {
        if keyctl(KEYCTL_GET_KEYRING_ID, SESSION, 0, 0) != ses {
            sys_exit(2);
        }
        if keyctl(KEYCTL_GET_KEYRING_ID, PROCESS, 0, 0) != ENOKEY {
            sys_exit(3);
        }
        sys_exit(0);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    if st & 0x7f != 0 {
        return 80;
    }
    ((st >> 8) & 0xff) as u64
}

fn add_keyring(desc: &[u8]) -> i64 {
    hk_syscall::sys_add_key(
        b"keyring\0".as_ptr(),
        desc.as_ptr(),
        core::ptr::null(),
        0,
        KEY_SPEC_PROCESS_KEYRING,
    )
}

/// Serial of a key the parent creates, read by the forked child
static mut VICTIM_KEY: i64 = 0;

const EDQUOT: i64 = -122;

/// An unprivileged user cannot pin unbounded keys: past the per-user
/// limit (Linux key_user maxkeys 200), add_key is EDQUOT.
fn key_quota() -> u64 {
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(2);
        }
        let mut made = 0i32;
        // Unique descriptions; well past the 200-key cap
        let mut desc = *b"kq0000\0";
        for i in 0..260i32 {
            desc[2] = b'0' + (i / 100 % 10) as u8;
            desc[3] = b'0' + (i / 10 % 10) as u8;
            desc[4] = b'0' + (i % 10) as u8;
            let r = hk_syscall::sys_add_key(
                b"user\0".as_ptr(),
                desc.as_ptr(),
                b"x".as_ptr(),
                1,
                KEY_SPEC_PROCESS_KEYRING,
            );
            if r == EDQUOT {
                // The cap is 200/user; keyrings this uid owns count too
                // on Linux, so allow some slack
                sys_exit(if made >= 190 { 0 } else { 3 });
            }
            if r <= 0 {
                sys_exit(4);
            }
            made += 1;
        }
        // Never hit the quota
        sys_exit(5);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    if st & 0x7f != 0 {
        return 80;
    }
    ((st >> 8) & 0xff) as u64
}

/// KEYCTL_UPDATE charges the payload's new size (Linux
/// key_payload_reserve): growing six 1-byte keys to 4000 bytes passes the
/// 20000-byte user quota (EDQUOT)
fn key_update_quota() -> u64 {
    const KEYCTL_UPDATE: i32 = 2;
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(2);
        }
        let big = [b'y'; 4000];
        let mut keys = [0i64; 6];
        // Earlier tests' uid-1000 keys may still await Linux's
        // asynchronous key GC: wait out EDQUOT for up to 2 s
        let ts = hk_syscall::Timespec {
            tv_sec: 0,
            tv_nsec: 10_000_000,
        };
        for (i, k) in keys.iter_mut().enumerate() {
            let desc = [b'k', b'u', b'q', b'0' + i as u8, 0];
            for _ in 0..200 {
                *k = hk_syscall::sys_add_key(
                    b"user\0".as_ptr(),
                    desc.as_ptr(),
                    b"x".as_ptr(),
                    1,
                    KEY_SPEC_PROCESS_KEYRING,
                );
                if *k != EDQUOT {
                    break;
                }
                hk_syscall::sys_nanosleep(&ts, core::ptr::null_mut());
            }
            if *k <= 0 {
                sys_exit(3);
            }
        }
        for k in keys {
            let r = keyctl(
                KEYCTL_UPDATE,
                k as u64,
                big.as_ptr() as u64,
                big.len() as u64,
            );
            if r == EDQUOT {
                sys_exit(0);
            }
            if r != 0 {
                sys_exit(4);
            }
        }
        sys_exit(5);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    if st & 0x7f != 0 {
        return 80;
    }
    ((st >> 8) & 0xff) as u64
}

/// Unlinked keys are freed and their quota returned (Linux key_put and
/// the key GC, which runs asynchronously: retried for up to 2 s)
fn key_gc() -> u64 {
    const KEYCTL_CLEAR: i32 = 7;
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(2);
        }
        let mut desc = *b"kg0000\0";
        let mut add = |i: i32| {
            desc[2] = b'0' + (i / 100 % 10) as u8;
            desc[3] = b'0' + (i / 10 % 10) as u8;
            desc[4] = b'0' + (i % 10) as u8;
            hk_syscall::sys_add_key(
                b"user\0".as_ptr(),
                desc.as_ptr(),
                b"x".as_ptr(),
                1,
                KEY_SPEC_PROCESS_KEYRING,
            )
        };
        let mut i = 0;
        while add(i) > 0 {
            i += 1;
            if i > 260 {
                sys_exit(3);
            }
        }
        if add(i) != EDQUOT {
            sys_exit(4);
        }
        if keyctl(KEYCTL_CLEAR, KEY_SPEC_PROCESS_KEYRING as u64, 0, 0) != 0 {
            sys_exit(5);
        }
        let ts = hk_syscall::Timespec {
            tv_sec: 0,
            tv_nsec: 10_000_000,
        };
        for _ in 0..200 {
            if add(i) > 0 {
                sys_exit(0);
            }
            hk_syscall::sys_nanosleep(&ts, core::ptr::null_mut());
        }
        sys_exit(6);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    if st & 0x7f != 0 {
        return 80;
    }
    ((st >> 8) & 0xff) as u64
}

/// Linking a keyring into itself or into one it already reaches is
/// EDEADLK (Linux keyring_detect_cycle), so a search cannot recurse
/// forever
fn key_cycle() -> u64 {
    let a = add_keyring(b"cyc_a\0");
    let b = add_keyring(b"cyc_b\0");
    if a <= 0 || b <= 0 {
        return 1;
    }
    if keyctl(KEYCTL_LINK, a as u64, a as u64, 0) != EDEADLK {
        return 2; // self-link
    }
    if keyctl(KEYCTL_LINK, a as u64, b as u64, 0) != 0 {
        return 3; // a into b: fine
    }
    if keyctl(KEYCTL_LINK, b as u64, a as u64, 0) != EDEADLK {
        return 4; // b into a would cycle
    }
    0
}

/// An unprivileged process cannot link a key it does not own: the key's
/// LINK permission is checked (Linux lookup_user_key KEY_NEED_LINK)
fn key_link_perm() -> u64 {
    // Parent (root) makes a key with default (owner-only) permissions
    let victim = add_key(b"linkperm\0");
    if victim <= 0 {
        return 1;
    }
    // SAFETY: written before the fork; the child reads its own copy
    unsafe { core::ptr::write_volatile(&raw mut VICTIM_KEY, victim) };
    let pid = sys_fork();
    if pid == 0 {
        const CAP_SETUID: u32 = 7;
        // Keep CAP_SETUID to change uid, drop the rest (no key override)
        if !set_effective(1 << CAP_SETUID) || sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(2);
        }
        let ring = add_keyring(b"lp_ring\0");
        if ring <= 0 {
            sys_exit(3);
        }
        // SAFETY: the parent's value, copied by fork
        let v = unsafe { core::ptr::read_volatile(&raw const VICTIM_KEY) };
        let r = keyctl(KEYCTL_LINK, v as u64, ring as u64, 0);
        sys_exit(if r == EACCES { 0 } else { 4 });
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    if st & 0x7f != 0 {
        return 80;
    }
    ((st >> 8) & 0xff) as u64
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

const KEYCTL_UPDATE: i32 = 2;
const KEYCTL_REVOKE: i32 = 3;
const EKEYREVOKED: i64 = -128;

#[repr(C, align(16))]
struct KStack([u8; 16384]);
static mut KSTACK: KStack = KStack([0; 16384]);
static mut KCTID: u32 = 0;
static mut KSERIAL: i64 = 0;

/// Set the hard NOFILE limit back to 100, over and over (EPERM once the
/// main thread lowered it)
extern "C" fn raiser(_: u64) -> ! {
    let r = hk_syscall::RLimit {
        rlim_cur: 20,
        rlim_max: 100,
    };
    for _ in 0..300 {
        hk_syscall::sys_setrlimit(RLIMIT_NOFILE, &r);
    }
    sys_exit(0)
}

/// One round in a fresh process: hard 100, unprivileged, then lowered
/// to 50 while `raiser` runs: it must end at 50
fn rlimit_round(spins: u64) -> u64 {
    let start = hk_syscall::RLimit {
        rlim_cur: 20,
        rlim_max: 100,
    };
    if hk_syscall::sys_setrlimit(RLIMIT_NOFILE, &start) != 0 || sys_setresuid(1000, 1000, 1000) != 0
    {
        return 1;
    }
    // SAFETY: the thread runs on the file's static stack (free while
    // this test runs) and clears KCTID when it exits
    let t = unsafe {
        core::ptr::write_volatile(&raw mut KCTID, 1);
        let top = (&raw mut KSTACK as *mut u8).add(16384) as u64;
        crate::tests::mm::fork_mm::spawn_thread(top, raiser, 0, &raw mut KCTID)
    };
    if t <= 0 {
        return 2;
    }
    for _ in 0..spins {
        hk_syscall::sys_sched_yield();
    }
    let low = hk_syscall::RLimit {
        rlim_cur: 20,
        rlim_max: 50,
    };
    if hk_syscall::sys_setrlimit(RLIMIT_NOFILE, &low) != 0 {
        return 3;
    }
    // SAFETY: KCTID is the thread's clear-child-tid word
    while unsafe { core::ptr::read_volatile(&raw const KCTID) } != 0 {
        hk_syscall::sys_sched_yield();
    }
    let mut now = hk_syscall::RLimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    hk_syscall::sys_getrlimit(RLIMIT_NOFILE, &mut now);
    if now.rlim_max != 50 { 4 } else { 0 }
}

fn rlimit_raise_race() -> u64 {
    for round in 0..30u64 {
        let r = in_child_with(|| rlimit_round(round % 6));
        if r != 0 {
            return r * 100 + round;
        }
    }
    0
}

/// Update the key over and over (its errors are expected once revoked)
extern "C" fn updater(_: u64) -> ! {
    // SAFETY: KSERIAL is set before this thread exists
    let k = unsafe { KSERIAL };
    let p = b"v";
    for _ in 0..2000 {
        keyctl(KEYCTL_UPDATE, k as u64, p.as_ptr() as u64, 1);
    }
    hk_syscall::sys_exit(0)
}

/// In a child (its own process keyring)
fn key_revoke_update() -> u64 {
    let k = add_key(b"revoke1\0");
    if k <= 0 {
        return 1;
    }
    keyctl(KEYCTL_REVOKE, k as u64, 0, 0);
    let p = b"v";
    if keyctl(KEYCTL_UPDATE, k as u64, p.as_ptr() as u64, 1) != EKEYREVOKED {
        return 2;
    }
    let mut buf = [0u8; 16];
    if keyctl(KEYCTL_READ, k as u64, buf.as_mut_ptr() as u64, 16) != EKEYREVOKED {
        return 3;
    }
    // A revoke racing a stream of updates
    let k2 = add_key(b"revoke2\0");
    if k2 <= 0 {
        return 4;
    }
    // SAFETY: set before the thread exists; the thread runs on its own
    // static stack and its tid word is CTID
    let t = unsafe {
        KSERIAL = k2;
        let top = (&raw mut KSTACK as *mut u8).add(16384) as u64;
        crate::tests::mm::fork_mm::spawn_thread(top, updater, 0, &raw mut KCTID)
    };
    if t <= 0 {
        return 5;
    }
    keyctl(KEYCTL_REVOKE, k2 as u64, 0, 0);
    // Wait for the updater (CLONE_CHILD_CLEARTID clears KCTID)
    // SAFETY: KCTID is the thread's clear-child-tid word
    while unsafe { core::ptr::read_volatile(&raw const KCTID) } != 0 {
        hk_syscall::sys_sched_yield();
    }
    if keyctl(KEYCTL_READ, k2 as u64, buf.as_mut_ptr() as u64, 16) != EKEYREVOKED {
        return 6;
    }
    0
}

const BPF_MAP_CREATE: i32 = 0;
const BPF_PROG_LOAD: i32 = 5;
const UNPRIV_BPF: &[u8] = b"/proc/sys/kernel/unprivileged_bpf_disabled\0";

/// An array map of one 4-byte value
fn bpf_map() -> i64 {
    let attr = [2u32, 4, 4, 1, 0, 0, 0, 0];
    hk_syscall::sys_bpf(BPF_MAP_CREATE, attr.as_ptr() as u64, 32)
}

/// A socket filter "r0 = 0; exit"
fn bpf_prog() -> i64 {
    let insns = [0xb7u64, 0x95];
    let license = b"GPL\0";
    let attr = [
        1u32, // BPF_PROG_TYPE_SOCKET_FILTER
        2,
        insns.as_ptr() as u64 as u32,
        (insns.as_ptr() as u64 >> 32) as u32,
        license.as_ptr() as u64 as u32,
        (license.as_ptr() as u64 >> 32) as u32,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    hk_syscall::sys_bpf(BPF_PROG_LOAD, attr.as_ptr() as u64, 48)
}

/// With unprivileged BPF disabled (the default), root may create maps
/// and load programs but uid 1000 without capabilities may not (EPERM)
fn bpf_unpriv() -> u64 {
    let mut b = [0u8; 4];
    if crate::tests::helpers::read_file(UNPRIV_BPF, &mut b) < 1 || b[0] == b'0' {
        return 1;
    }
    for fd in [bpf_map(), bpf_prog()] {
        if fd < 0 {
            return 2;
        }
        hk_syscall::sys_close(fd as u64);
    }
    if sys_setresuid(1000, 1000, 1000) != 0 {
        return 3;
    }
    if bpf_map() != EPERM {
        return 4;
    }
    if bpf_prog() != EPERM {
        return 5;
    }
    0
}

/// kernel.unprivileged_bpf_disabled takes 0..2 (EINVAL past it)
fn bpf_sysctl() -> u64 {
    let write = |v: &[u8]| {
        let fd = hk_syscall::sys_open(UNPRIV_BPF.as_ptr(), 1, 0);
        if fd < 0 {
            return fd;
        }
        let r = hk_syscall::sys_write(fd as u64, v.as_ptr(), v.len() as u64);
        hk_syscall::sys_close(fd as u64);
        r
    };
    if write(b"3") != -22 {
        return 1;
    }
    if write(b"-1") != -22 {
        return 2;
    }
    if write(b"2") != 1 {
        return 3;
    }
    0
}
