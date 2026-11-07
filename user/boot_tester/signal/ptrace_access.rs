//! Who may attach to, or read the memory of, another process (Linux
//! __ptrace_may_access, PTRACE_MODE_ATTACH_REALCREDS, for PTRACE_ATTACH
//! and process_vm_readv): same real uid/gid as all of the target's ids,
//! and a dumpable target, unless the caller has CAP_SYS_PTRACE
//!
//! PTRACE_ATTACH_OWN_GROUP: attaching to a thread of one's own thread
//! group is EPERM (Linux ptrace_attach: same_thread_group), though the
//! credentials would allow it
//!
//! KCMP_PIDFD_GETFD_PERM: kcmp (PTRACE_MODE_READ_REALCREDS on both) and
//! pidfd_getfd (PTRACE_MODE_ATTACH_REALCREDS) of a root process are
//! EPERM for nobody; kcmp of one's own process works

use crate::harness::fail_num;
use crate::helpers::reap;
use crate::helpers::{print, println};
use crate::mm::fork_mm::{join, spawn_thread};
use core::sync::atomic::{AtomicI64, Ordering};
use hk_syscall::{
    IoVec, sys_close, sys_exit, sys_fork, sys_pause, sys_pipe2, sys_prctl, sys_process_vm_readv,
    sys_ptrace, sys_read, sys_setresgid, sys_setresuid, sys_wait4, sys_write,
};

const PTRACE_ATTACH: i64 = 16;
const PTRACE_DETACH: i64 = 17;
const PR_SET_DUMPABLE: i32 = 4;
const EPERM: i64 = -1;
const UID: u32 = 1000;

static SECRET: [u8; 8] = *b"hksecret";

pub fn run_tests() {
    report(b"PTRACE_ACCESS_SAME_UID", in_prober(own_child, 1), 0);
    report(b"PTRACE_ACCESS_NONDUMPABLE", in_prober(own_child, 0), 1);
    report(b"PTRACE_ACCESS_OTHER_UID", other_uid(), 1);
    report(b"PTRACE_ATTACH_OWN_GROUP", in_prober(own_group, 0), 0);
    kcmp_pidfd_perm();
}

fn kcmp_pidfd_perm() {
    use hk_syscall::{sys_getpid, sys_kcmp, sys_pidfd_getfd, sys_pidfd_open};
    const KCMP_FILE: i32 = 0;
    const KCMP_VM: i32 = 1;
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    // A root process that waits
    let target = sys_fork();
    if target == 0 {
        sys_close(p[1] as u64);
        let mut c = [0u8; 1];
        sys_read(p[0] as u64, c.as_mut_ptr(), 1);
        sys_exit(0);
    }
    let prober = sys_fork();
    if prober == 0 {
        if sys_setresuid(65534, 65534, 65534) != 0 {
            sys_exit(1);
        }
        let me = sys_getpid() as u64;
        let k = sys_kcmp(target as u64, me, KCMP_FILE, 0, 0);
        let own = sys_kcmp(me, me, KCMP_VM, 0, 0);
        let pfd = sys_pidfd_open(target as i32, 0);
        let g = if pfd >= 0 {
            sys_pidfd_getfd(pfd as i32, 0, 0)
        } else {
            -1000
        };
        sys_exit(if k != EPERM {
            2
        } else if own != 0 {
            3
        } else if g != EPERM {
            4
        } else {
            0
        });
    }
    let mut st = 0i32;
    sys_wait4(prober, &mut st, 0, 0);
    sys_close(p[1] as u64);
    sys_close(p[0] as u64);
    let mut t = 0i32;
    sys_wait4(target, &mut t, 0, 0);
    print(b"KCMP_PIDFD_GETFD_PERM");
    if st == 0 {
        println(b":OK");
    } else {
        fail_num(b":FAIL status ", st as i64);
    }
}

static SIB_RESULT: AtomicI64 = AtomicI64::new(1);

#[repr(C, align(16))]
struct SibStack([u8; 16384]);
static mut SIB_STACK: SibStack = SibStack([0; 16384]);
static mut SIB_CTID: u32 = 0;

/// Second thread: PTRACE_ATTACH to its own thread group leader
extern "C" fn sibling(_: u64) -> ! {
    let r = sys_ptrace(PTRACE_ATTACH, hk_syscall::sys_getpid(), 0, 0);
    SIB_RESULT.store(r, Ordering::Relaxed);
    sys_exit(0)
}

/// In a fresh process: a second thread attaches to the first; exit 0
/// if that is EPERM
fn own_group(_: u64) -> u64 {
    // Dumpable again after the uid change, so only the thread-group
    // rule can refuse
    sys_prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    unsafe {
        let top = (&raw mut SIB_STACK as *mut u8).add(16384) as u64;
        let ctid = &raw mut SIB_CTID;
        core::ptr::write_volatile(ctid, 1);
        if spawn_thread(top, sibling, 0, ctid) < 0 || !join(ctid) {
            return 2;
        }
    }
    if SIB_RESULT.load(Ordering::Relaxed) == EPERM {
        0
    } else {
        3
    }
}

fn report(name: &[u8], st: i32, want: i32) {
    print(name);
    if st & 0x7f == 0 && (st >> 8) & 0xff == want {
        println(b":OK");
    } else {
        fail_num(b":FAIL status ", st as i64);
    }
}

/// Become uid `uid` (gid 1000) for good
fn drop_to(uid: u32) {
    sys_setresgid(UID, UID, UID);
    sys_setresuid(uid, uid, uid);
}

/// Wait status of a child that becomes uid 1000 and exits with `f(arg)`
fn in_prober(f: fn(u64) -> u64, arg: u64) -> i32 {
    let pid = sys_fork();
    if pid == 0 {
        drop_to(UID);
        sys_exit(f(arg));
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    st
}

/// A child that becomes `uid` (unless already) with dumpability
/// `dumpable` and blocks; it is ready when this returns
fn target(uid: u32, dumpable: u64) -> i64 {
    let mut ready = [0i32; 2];
    sys_pipe2(ready.as_mut_ptr(), 0);
    let pid = sys_fork();
    if pid == 0 {
        drop_to(uid);
        sys_prctl(PR_SET_DUMPABLE, dumpable, 0, 0, 0);
        sys_write(ready[1] as u64, b"x".as_ptr(), 1);
        loop {
            sys_pause();
        }
    }
    let mut b = [0u8; 1];
    sys_read(ready[0] as u64, b.as_mut_ptr(), 1);
    sys_close(ready[0] as u64);
    sys_close(ready[1] as u64);
    pid
}

/// Probe a same-uid child of the prober (a descendant, so Yama's
/// relational ptrace_scope allows it on Linux)
fn own_child(dumpable: u64) -> u64 {
    let t = target(UID, dumpable);
    let r = attempt(t);
    reap(t);
    r
}

/// Probe, as uid 1000, a process of uid 1001
fn other_uid() -> i32 {
    let t = target(UID + 1, 1);
    static mut T: i64 = 0;
    unsafe { T = t };
    let st = in_prober(|_| attempt(unsafe { T }), 0);
    reap(t);
    st
}

/// Read `SECRET` from `pid` and attach to it: 0 if both work, 1 if both
/// are EPERM, 2/3 if they disagree
fn attempt(pid: i64) -> u64 {
    let mut buf = [0u8; 8];
    let local = IoVec {
        iov_base: buf.as_mut_ptr(),
        iov_len: 8,
    };
    let remote = IoVec {
        iov_base: SECRET.as_ptr(),
        iov_len: 8,
    };
    let vm = sys_process_vm_readv(pid as i32, &local, 1, &remote, 1, 0);
    let at = sys_ptrace(PTRACE_ATTACH, pid, 0, 0);
    if at == 0 {
        sys_ptrace(PTRACE_DETACH, pid, 0, 0);
    }
    match (vm, at) {
        (8, 0) if buf == SECRET => 0,
        (EPERM, EPERM) => 1,
        (8, _) => 2,
        _ => 3,
    }
}
