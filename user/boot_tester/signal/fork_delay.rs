//! Signals during fork (Linux copy_process, run on hk and real Linux)
//!
//! - FORK_PGRP_SIGNAL: a process-group signal sent while its process
//!   forks over and over reaches every child already forked and, in
//!   most rounds, the one being forked when it came (Linux delays a
//!   multiprocess signal for the child of a fork in progress,
//!   signal->multiprocess; it is lost to that child only if it came
//!   between the parent's last check and the fork's start). The parent
//!   blocks it, so no fork restarts, and checks after each fork whether
//!   it came; a large address space makes each fork spend its time
//!   copying page tables before the child joins the group.

use crate::harness::verdict;
use hk_syscall::{
    SigInfo, Timespec, Zeroable, sys_exit, sys_exit_group, sys_fork, sys_kill, sys_mmap,
    sys_nanosleep, sys_rt_sigpending, sys_rt_sigprocmask, sys_rt_sigtimedwait, sys_setpgid,
    sys_wait4,
};

const SIGUSR1: u32 = 10;
const SIGUSR2: u32 = 12;
const SIG_BLOCK: i32 = 0;
const ROUNDS: usize = 8;
const MAX_KIDS: usize = 128;
const MAP_BYTES: u64 = 32 << 20;

pub fn run_tests() {
    let c = sys_fork();
    if c == 0 {
        sys_exit_group(run() as u64);
    }
    let mut st = 0i32;
    sys_wait4(c, &mut st, 0, 0);
    verdict(b"FORK_PGRP_SIGNAL", st == 0, (st >> 8) as i64);
}

fn bit(sig: u32) -> u64 {
    1 << (sig - 1)
}

fn sleep_us(us: i64) {
    let t = Timespec {
        tv_sec: us / 1_000_000,
        tv_nsec: (us % 1_000_000) * 1000,
    };
    sys_nanosleep(&t, core::ptr::null_mut());
}

fn pending() -> u64 {
    let mut set = 0u64;
    sys_rt_sigpending(&mut set as *mut u64 as u64, 8);
    set
}

/// sigtimedwait for `mask` up to `secs`: the signal or -errno
fn wait_sig(mask: u64, secs: i64) -> i64 {
    let ts = [secs, 0i64];
    let mut i = SigInfo::zeroed();
    sys_rt_sigtimedwait(
        &mask as *const u64 as u64,
        &mut i as *mut SigInfo as u64,
        ts.as_ptr() as u64,
        8,
    )
}

/// In a process group of its own, SIGUSR1 and SIGUSR2 blocked: 0 if
/// every round's earlier children got the signal and at least half the
/// rounds' in-flight child did, else the failed step
fn run() -> i32 {
    sys_setpgid(0, 0);
    let m = bit(SIGUSR1) | bit(SIGUSR2);
    sys_rt_sigprocmask(SIG_BLOCK, &m as *const u64 as u64, 0, 8);
    // PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS
    let a = sys_mmap(0, MAP_BYTES, 3, 0x22, -1, 0);
    if a < 0 {
        return 1;
    }
    for off in (0..MAP_BYTES).step_by(4096) {
        // SAFETY: inside the mapping just made
        unsafe { core::ptr::write_volatile((a as u64 + off) as *mut u8, 1) };
    }
    let mut hits = 0;
    for r in 0..ROUNDS {
        match round(r) {
            Err(code) => return code,
            Ok(true) => hits += 1,
            Ok(false) => {}
        }
    }
    if hits * 2 >= ROUNDS {
        0
    } else {
        40 + hits as i32
    }
}

/// A child of the round: 1 if SIGUSR1 reached it, 0 if SIGUSR2 (the
/// parent's end of the round) did first
fn kid() -> ! {
    let r = wait_sig(bit(SIGUSR1) | bit(SIGUSR2), 20);
    sys_exit(match r {
        r if r == SIGUSR1 as i64 => 1,
        r if r == SIGUSR2 as i64 => 0,
        _ => 2,
    })
}

/// One round: a sender kills the group with SIGUSR1 after a delay
/// while this process forks until it sees the signal pending. Every
/// child forked before the one after which it showed must have it;
/// Ok(whether that last one has it too)
fn round(r: usize) -> Result<bool, i32> {
    let sender = sys_fork();
    if sender == 0 {
        sleep_us(1000 + r as i64 * 500);
        sys_kill(0, SIGUSR1);
        sys_exit(0);
    }
    let mut kids = [0i64; MAX_KIDS];
    let mut n = 0;
    let mut last = None;
    while n < MAX_KIDS {
        let c = sys_fork();
        if c == 0 {
            kid();
        }
        if c < 0 {
            break;
        }
        kids[n] = c;
        n += 1;
        if pending() & bit(SIGUSR1) != 0 {
            last = Some(n - 1);
            break;
        }
    }
    // The sender's kill is over: every child it reached has the signal
    let mut st = 0i32;
    sys_wait4(sender, &mut st, 0, 0);
    let mut got = [false; MAX_KIDS];
    for (k, &c) in kids[..n].iter().enumerate() {
        sys_kill(c, SIGUSR2);
        sys_wait4(c, &mut st, 0, 0);
        got[k] = st == 1 << 8;
    }
    if wait_sig(bit(SIGUSR1), 0) != SIGUSR1 as i64 {
        return Err(2);
    }
    let Some(last) = last else {
        return Err(3);
    };
    if got[..last].iter().any(|g| !g) {
        return Err(10 + r as i32);
    }
    Ok(got[last])
}
