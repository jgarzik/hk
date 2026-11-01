//! Concurrent exec in one thread group (Linux fs/exec.c: cred_guard_mutex
//! is taken interruptibly in prepare_bprm_creds, de_thread)
//!
//! Tests:
//! - EXEC_CRED_RACE: two threads of one process call execve at the same
//!   moment; one exec wins and the other thread is killed, even when
//!   it was already waiting for the group's cred_guard (which the
//!   winner holds while it waits for the other threads to die). The
//!   process ends with the new image's exit status, every round.

use super::fork_mm::spawn_thread;
use super::helpers::{print, print_num, println};
use super::sk::now_ms;
use core::sync::atomic::{AtomicU32, Ordering};
use hk_syscall::{
    Timespec, sys_execve, sys_exit, sys_fork, sys_kill, sys_nanosleep, sys_wait4,
};

const ROUNDS: usize = 20;
const TIMEOUT_MS: u64 = 10_000;
const SIGKILL: u32 = 9;
const WNOHANG: i32 = 1;

static GO: AtomicU32 = AtomicU32::new(0);
static mut STACK: [u8; 16384] = [0; 16384];
static mut CTID: u32 = 0;

pub fn run_tests() {
    let mut fail = 0;
    for i in 0..ROUNDS {
        let r = round();
        if r != 0 {
            fail = i as i64 * 1000 + r;
            break;
        }
    }
    print(b"EXEC_CRED_RACE");
    if fail == 0 {
        println(b":OK");
    } else {
        print(b":FAIL round*1000+step ");
        print_num(fail);
        println(b"");
    }
}

fn exec_true() -> ! {
    let argv: [*const u8; 2] = [b"true\0".as_ptr(), core::ptr::null()];
    let envp: [*const u8; 1] = [core::ptr::null()];
    sys_execve(b"/bin/busybox\0".as_ptr(), argv.as_ptr(), envp.as_ptr());
    sys_exit(127)
}

extern "C" fn racer(_: u64) -> ! {
    while GO.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
    }
    exec_true()
}

/// One process whose two threads exec at once: 0, or a failure step
fn round() -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        let top = unsafe { (&raw mut STACK as *mut u8).add(16384) as u64 };
        if unsafe { spawn_thread(top, racer, 0, &raw mut CTID) } < 0 {
            sys_exit(126);
        }
        GO.store(1, Ordering::Release);
        exec_true()
    }
    if pid < 0 {
        return 1;
    }
    let t0 = now_ms();
    let mut st = 0i32;
    loop {
        let w = sys_wait4(pid, &mut st, WNOHANG, 0);
        if w == pid {
            break;
        }
        if w < 0 {
            return 2;
        }
        if now_ms() - t0 > TIMEOUT_MS {
            // Stuck: both threads wait on each other
            sys_kill(pid, SIGKILL);
            return 3;
        }
        let ts = Timespec {
            tv_sec: 0,
            tv_nsec: 10_000_000,
        };
        sys_nanosleep(&ts, core::ptr::null_mut());
    }
    if st != 0 { 4 } else { 0 }
}
