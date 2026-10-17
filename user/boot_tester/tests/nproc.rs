//! RLIMIT_NPROC counts every task of a real uid, threads included
//! (Linux copy_process / ucounts): over the limit fork and clone fail
//! with EAGAIN; exited and reaped tasks give their slot back, and failed
//! clones never leak one.

use super::helpers::{print, print_num, println};
use hk_syscall::{
    CLONE_SIGHAND, CLONE_VM, RLIMIT_NPROC, RLimit, Timespec, sys_clone, sys_execve, sys_exit,
    sys_fork, sys_kill, sys_nanosleep, sys_sched_yield, sys_setrlimit, sys_setuid, sys_wait4,
};

const EAGAIN: i64 = -11;
const CLONE_THREAD: u64 = 0x0001_0000;
const SIGKILL: u32 = 9;
/// A uid no other test runs as: Linux counts all of its tasks
const UID: u32 = 4242;

pub fn run_tests() {
    run(b"RLIMIT_NPROC", nproc);
    run(b"RLIMIT_NPROC_ROOT_EXEMPT", root_exempt);
    run(b"RLIMIT_NPROC_SETUID_EXEC", setuid_exec);
    run(b"RLIMIT_NPROC_CHURN", churn);
}

/// 2000 processes and 2000 threads created and released under a low
/// limit leave the count where it started
fn churn() -> u64 {
    if sys_setuid(4244) != 0 {
        return 1;
    }
    // One extra task at a time: the threads share one static stack
    let lim = RLimit {
        rlim_cur: 2,
        rlim_max: 3,
    };
    if sys_setrlimit(RLIMIT_NPROC, &lim) != 0 {
        return 2;
    }
    for _ in 0..2000 {
        // The previous thread may still be exiting: retry while busy
        let mut tries = 0;
        let pid = loop {
            let pid = sys_fork();
            if pid != EAGAIN {
                break pid;
            }
            tries += 1;
            if tries > 100_000 {
                return 3;
            }
            sys_sched_yield();
        };
        if pid == 0 {
            sys_exit(0);
        }
        if pid < 0 {
            return 7;
        }
        sys_wait4(pid, core::ptr::null_mut(), 0, 0);
        let mut tries = 0;
        while thread() == EAGAIN {
            tries += 1;
            if tries > 100_000 {
                return 4;
            }
            sys_sched_yield();
        }
    }
    // Wait for the last thread's slot, then the count is back to 1
    let mut tries = 0;
    loop {
        let pid = sys_fork();
        if pid > 0 {
            sys_wait4(pid, core::ptr::null_mut(), 0, 0);
            break;
        }
        if pid == 0 {
            sys_exit(0);
        }
        tries += 1;
        if tries > 100_000 {
            return 5;
        }
        sys_sched_yield();
    }
    let lim = RLimit {
        rlim_cur: 3,
        rlim_max: 3,
    };
    sys_setrlimit(RLIMIT_NPROC, &lim);
    let a = sleeper();
    let b = sleeper();
    let c = sys_fork();
    let ok = a > 0 && b > 0 && c == EAGAIN;
    for k in [a, b] {
        if k > 0 {
            sys_kill(k, SIGKILL);
            sys_wait4(k, core::ptr::null_mut(), 0, 0);
        }
    }
    if c == 0 {
        sys_exit(0);
    }
    if ok { 0 } else { 6 }
}

/// Run `f` in a child; it returns the failed step, 0 on success
fn run(name: &[u8], f: fn() -> u64) {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(f());
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    print(name);
    if st == 0 {
        println(b":OK");
    } else {
        print(b":FAIL step ");
        print_num((st >> 8) as i64);
        println(b"");
    }
}

/// A child that sleeps until killed
fn sleeper() -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        let ts = Timespec {
            tv_sec: 30,
            tv_nsec: 0,
        };
        sys_nanosleep(&ts, core::ptr::null_mut());
        sys_exit(0);
    }
    pid
}

/// A thread clone: the child (if the clone succeeds) exits at once
fn thread() -> i64 {
    #[repr(C, align(16))]
    struct Stack([u8; 4096]);
    static mut STACK: Stack = Stack([0; 4096]);
    let top = unsafe { (&raw mut STACK as *mut u8).add(4096) } as u64;
    let r = sys_clone(CLONE_VM | CLONE_SIGHAND | CLONE_THREAD, top, 0, 0, 0);
    if r == 0 {
        sys_exit(0); // exit(2): this thread only
    }
    r
}

/// Root's user is exempt: fork beyond the limit works
fn root_exempt() -> u64 {
    let lim = RLimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    if sys_setrlimit(RLIMIT_NPROC, &lim) != 0 {
        return 1;
    }
    let a = sleeper();
    if a <= 0 {
        return 2;
    }
    sys_kill(a, SIGKILL);
    sys_wait4(a, core::ptr::null_mut(), 0, 0);
    0
}

/// setuid into a user already over the limit succeeds, then execve
/// fails with EAGAIN (Linux PF_NPROC_EXCEEDED)
fn setuid_exec() -> u64 {
    const U: u32 = 4243;
    let mut kids = [0i64; 2];
    for k in kids.iter_mut() {
        let pid = sys_fork();
        if pid == 0 {
            sys_setuid(U);
            let ts = Timespec {
                tv_sec: 30,
                tv_nsec: 0,
            };
            sys_nanosleep(&ts, core::ptr::null_mut());
            sys_exit(0);
        }
        *k = pid;
    }
    // Let both children become uid U
    let ts = Timespec {
        tv_sec: 0,
        tv_nsec: 200_000_000,
    };
    sys_nanosleep(&ts, core::ptr::null_mut());
    let lim = RLimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    let mut step = 0;
    if sys_setrlimit(RLIMIT_NPROC, &lim) != 0 {
        step = 1;
    } else if sys_setuid(U) != 0 {
        step = 2;
    } else {
        let argv: [*const u8; 2] = [b"boot_tester2\0".as_ptr(), core::ptr::null()];
        let envp: [*const u8; 1] = [core::ptr::null()];
        let r = sys_execve(
            b"/bin/boot_tester2\0".as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
        );
        if r != EAGAIN {
            step = 3;
        }
    }
    for k in kids {
        sys_kill(k, SIGKILL);
        sys_wait4(k, core::ptr::null_mut(), 0, 0);
    }
    step
}

/// Step number of the first failed check, 0 if all pass
fn nproc() -> u64 {
    if sys_setuid(UID) != 0 {
        return 1;
    }
    // This task plus two children fill a limit of 3
    let lim = RLimit {
        rlim_cur: 3,
        rlim_max: 3,
    };
    if sys_setrlimit(RLIMIT_NPROC, &lim) != 0 {
        return 2;
    }
    let a = sleeper();
    let b = sleeper();
    if a <= 0 || b <= 0 {
        return 3;
    }
    if sys_fork() != EAGAIN {
        return 4;
    }
    if thread() != EAGAIN {
        return 5;
    }
    // Failing clones must not leak a slot
    for _ in 0..1000 {
        if sys_fork() != EAGAIN || thread() != EAGAIN {
            return 6;
        }
    }
    sys_kill(a, SIGKILL);
    sys_kill(b, SIGKILL);
    sys_wait4(a, core::ptr::null_mut(), 0, 0);
    sys_wait4(b, core::ptr::null_mut(), 0, 0);
    // Reaped: both slots are back
    let c = sleeper();
    let d = sleeper();
    if c <= 0 || d <= 0 {
        return 7;
    }
    sys_kill(c, SIGKILL);
    sys_kill(d, SIGKILL);
    sys_wait4(c, core::ptr::null_mut(), 0, 0);
    sys_wait4(d, core::ptr::null_mut(), 0, 0);
    0
}
