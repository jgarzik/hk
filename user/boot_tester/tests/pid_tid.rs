//! Process and thread ids (Linux: a process's pid is its leader's tid)
//!
//! - the leader's getpid() equals its gettid();
//! - fork returns the child's pid, which is also the child's tid;
//! - a thread's tid, as clone returns it and CLONE_PARENT_SETTID stores
//!   it, names /proc/self/task/<tid>;
//! - a non-leader thread that execs keeps the pid and becomes its tid
//!   (de_thread's exchange_tids).

use super::fork_mm::{join, spawn_thread_ptid};
use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_close, sys_dup3, sys_execve, sys_exit, sys_faccessat, sys_fork, sys_getpid, sys_gettid,
    sys_pipe2, sys_read, sys_wait4, sys_write,
};

const AT_FDCWD: i32 = -100;

pub fn run_tests() {
    leader();
    fork_ids();
    thread_ids();
    exec_thread();
}

fn report(name: &[u8], ok: bool, v: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL got ");
        print_num(v);
        println(b"");
    }
}

fn leader() {
    let (pid, tid) = (sys_getpid(), sys_gettid());
    report(b"PID_TID_LEADER", pid == tid, tid - pid);
}

/// The child sends its getpid and gettid
fn fork_ids() {
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    let ret = sys_fork();
    if ret == 0 {
        let ids = [sys_getpid(), sys_gettid()];
        sys_write(p[1] as u64, ids.as_ptr() as *const u8, 16);
        sys_exit(0);
    }
    let mut ids = [0i64; 2];
    let n = sys_read(p[0] as u64, ids.as_mut_ptr() as *mut u8, 16);
    sys_close(p[0] as u64);
    sys_close(p[1] as u64);
    let mut st = 0;
    sys_wait4(ret, &mut st, 0, 0);
    report(
        b"PID_TID_FORK",
        n == 16 && ids[0] == ret && ids[1] == ret,
        ids[1] - ret,
    );
}

#[repr(C, align(16))]
struct Stack([u8; 16384]);
static mut STACK: Stack = Stack([0; 16384]);
static mut CTID: u32 = 0;
static mut PTID: u32 = 0;
static mut SEEN: i64 = 0;
static mut GO: u32 = 0;

/// The thread records its own tid and stays until the test is done
extern "C" fn record(_: u64) -> ! {
    unsafe { core::ptr::write_volatile(&raw mut SEEN, sys_gettid()) };
    while unsafe { core::ptr::read_volatile(&raw const GO) } == 0 {
        hk_syscall::sys_sched_yield();
    }
    sys_exit(0)
}

/// /proc/self/task/<tid>
fn task_path(tid: i64, buf: &mut [u8; 48]) -> *const u8 {
    let pre = b"/proc/self/task/";
    buf[..pre.len()].copy_from_slice(pre);
    let mut digits = [0u8; 20];
    let mut n = 0;
    let mut v = tid as u64;
    loop {
        digits[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..n {
        buf[pre.len() + i] = digits[n - 1 - i];
    }
    buf[pre.len() + n] = 0;
    buf.as_ptr()
}

/// clone's return, CLONE_PARENT_SETTID's word and the thread's gettid
/// agree, differ from the pid, and name a /proc/self/task entry
fn thread_ids() {
    unsafe {
        core::ptr::write_volatile(&raw mut CTID, 0);
        core::ptr::write_volatile(&raw mut PTID, 0);
        core::ptr::write_volatile(&raw mut SEEN, 0);
        core::ptr::write_volatile(&raw mut GO, 0);
    }
    let top = unsafe { (&raw mut STACK as *mut u8).add(16384) as u64 };
    let tid = unsafe { spawn_thread_ptid(top, record, 0, &raw mut CTID, &raw mut PTID) };
    // CLONE_CHILD_CLEARTID clears the word at exit: it must hold the
    // tid first (the thread waits for GO)
    unsafe { core::ptr::write_volatile(&raw mut CTID, tid as u32) };
    // The task entry exists while the thread does: check before join
    let mut buf = [0u8; 48];
    let listed = tid > 0 && sys_faccessat(AT_FDCWD, task_path(tid, &mut buf), 0) == 0;
    unsafe { core::ptr::write_volatile(&raw mut GO, 1) };
    let joined = tid > 0 && join(&raw mut CTID);
    let ptid = unsafe { core::ptr::read_volatile(&raw const PTID) } as i64;
    let seen = unsafe { core::ptr::read_volatile(&raw const SEEN) };
    let ok = tid > 0 && joined && ptid == tid && seen == tid && tid != sys_getpid() && listed;
    report(b"PID_TID_THREAD", ok, tid);
}

extern "C" fn exec_ids(_: u64) -> ! {
    let argv: [*const u8; 3] = [b"boot_tester2\0".as_ptr(), b"ids\0".as_ptr(), core::ptr::null()];
    let envp: [*const u8; 1] = [core::ptr::null()];
    sys_execve(b"/bin/boot_tester2\0".as_ptr(), argv.as_ptr(), envp.as_ptr());
    sys_exit(127)
}

/// A non-leader execs: the new image runs with the old pid as both its
/// pid and tid
fn exec_thread() {
    let mut p = [0i32; 2];
    let mut block = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    sys_pipe2(block.as_mut_ptr(), 0);
    let pid = sys_fork();
    if pid == 0 {
        sys_dup3(p[1], 3, 0);
        let top = unsafe { (&raw mut STACK as *mut u8).add(16384) as u64 };
        unsafe { spawn_thread_ptid(top, exec_ids, 0, &raw mut CTID, core::ptr::null_mut()) };
        // The leader waits (on a pipe of its own) to be ended by the exec
        let mut c = [0u8; 1];
        loop {
            sys_read(block[0] as u64, c.as_mut_ptr(), 1);
        }
    }
    sys_close(block[0] as u64);
    sys_close(block[1] as u64);
    sys_close(p[1] as u64);
    let mut ids = [0i64; 2];
    let n = sys_read(p[0] as u64, ids.as_mut_ptr() as *mut u8, 16);
    sys_close(p[0] as u64);
    let mut st = 0;
    let w = sys_wait4(pid, &mut st, 0, 0);
    report(
        b"PID_TID_EXEC_THREAD",
        n == 16 && ids[0] == pid && ids[1] == pid && w == pid,
        ids[1] - pid,
    );
}
