//! The global init (pid 1, this boot tester) is not killed by signals
//! whose action is SIG_DFL (Linux SIGNAL_UNKILLABLE, sig_task_ignored).
//! A failure here kills init, which ends the boot with a panic.
//!
//! Tests:
//! - INIT_UNKILLABLE: a child sends pid 1 SIGTERM, SIGINT, SIGUSR1,
//!   SIGPIPE and SIGKILL (as root); init lives on
//! - INIT_HANDLED: a signal init has a handler for is still delivered

use super::helpers::{print, print_num, println};
use core::sync::atomic::{AtomicU32, Ordering};
use hk_syscall::{Timespec, sys_exit, sys_fork, sys_kill, sys_nanosleep, sys_rt_sigaction, sys_wait4};

const SA_RESTORER: u64 = 0x0400_0000;
const SA_RESTART: u64 = 0x1000_0000;

const SIGINT: u32 = 2;
const SIGKILL: u32 = 9;
const SIGUSR1: u32 = 10;
const SIGUSR2: u32 = 12;
const SIGPIPE: u32 = 13;
const SIGTERM: u32 = 15;

static GOT: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_usr2(_sig: i32) {
    GOT.store(GOT.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
}

pub fn run_tests() {
    unkillable();
    handled();
}

fn settle() {
    let ts = Timespec {
        tv_sec: 0,
        tv_nsec: 50_000_000,
    };
    sys_nanosleep(&ts, core::ptr::null_mut());
}

/// A child sends each signal to pid 1; its exit status is the first
/// kill() that failed
fn send_to_init(sigs: &[u32]) -> i32 {
    let pid = sys_fork();
    if pid == 0 {
        for (i, &s) in sigs.iter().enumerate() {
            if sys_kill(1, s) != 0 {
                sys_exit(i as u64 + 1);
            }
        }
        sys_exit(0);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    st
}

fn unkillable() {
    let st = send_to_init(&[SIGTERM, SIGINT, SIGUSR1, SIGPIPE, SIGKILL]);
    settle();
    // Still running: we print
    print(b"INIT_UNKILLABLE");
    if st == 0 {
        println(b":OK");
    } else {
        print(b":FAIL kill step ");
        print_num((st >> 8) as i64);
        println(b"");
    }
}

fn handled() {
    let act: [u64; 4] = [
        on_usr2 as *const () as u64,
        SA_RESTORER | SA_RESTART,
        super::signals::restorer_addr(),
        0,
    ];
    let mut old = [0u64; 4];
    sys_rt_sigaction(SIGUSR2, act.as_ptr() as u64, old.as_mut_ptr() as u64, 8);
    GOT.store(0, Ordering::Relaxed);
    let st = send_to_init(&[SIGUSR2]);
    settle();
    let got = GOT.load(Ordering::Relaxed);
    sys_rt_sigaction(SIGUSR2, old.as_ptr() as u64, 0, 8);
    print(b"INIT_HANDLED");
    if st == 0 && got == 1 {
        println(b":OK");
    } else {
        print(b":FAIL got ");
        print_num(got as i64);
        println(b"");
    }
}
