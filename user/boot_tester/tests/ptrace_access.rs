//! Who may attach to, or read the memory of, another process (Linux
//! __ptrace_may_access, PTRACE_MODE_ATTACH_REALCREDS, for PTRACE_ATTACH
//! and process_vm_readv): same real uid/gid as all of the target's ids,
//! and a dumpable target, unless the caller has CAP_SYS_PTRACE

use super::helpers::{print, print_num, println};
use hk_syscall::{
    IoVec, sys_close, sys_exit, sys_fork, sys_kill, sys_pause, sys_pipe2, sys_prctl,
    sys_process_vm_readv, sys_ptrace, sys_read, sys_setresgid, sys_setresuid, sys_wait4,
    sys_write,
};

const PTRACE_ATTACH: i64 = 16;
const PTRACE_DETACH: i64 = 17;
const PR_SET_DUMPABLE: i32 = 4;
const SIGKILL: u32 = 9;
const EPERM: i64 = -1;
const UID: u32 = 1000;

static SECRET: [u8; 8] = *b"hksecret";

pub fn run_tests() {
    report(b"PTRACE_ACCESS_SAME_UID", in_prober(own_child, 1), 0);
    report(b"PTRACE_ACCESS_NONDUMPABLE", in_prober(own_child, 0), 1);
    report(b"PTRACE_ACCESS_OTHER_UID", other_uid(), 1);
}

fn report(name: &[u8], st: i32, want: i32) {
    print(name);
    if st & 0x7f == 0 && (st >> 8) & 0xff == want {
        println(b":OK");
    } else {
        print(b":FAIL status ");
        print_num(st as i64);
        println(b"");
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

fn reap(pid: i64) {
    sys_kill(pid, SIGKILL);
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
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
