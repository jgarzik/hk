//! Timing, blocking and wakeup tests (run on hk and real Linux)
//!
//! - poll()/nanosleep() timeouts measured against CLOCK_MONOTONIC
//! - a signal interrupts a blocked pipe read: -EINTR without SA_RESTART,
//!   transparent restart with SA_RESTART
//! - pause() returns -EINTR after a handler runs
//! - SIGKILL wakes a task in rt_sigsuspend; wait4/waitid report the kill
//! - wake/wait stress through pipes (several children) and futexes
//!
//! Bounds are loose (TCG). Every wait on a child is bounded so a kernel bug
//! shows up as FAIL instead of hanging the whole boot test.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_clock_gettime, sys_clone, sys_close, sys_exit, sys_fork, sys_futex, sys_kill,
    sys_nanosleep, sys_pause, sys_pipe, sys_poll, sys_read, sys_rt_sigaction, sys_rt_sigprocmask, sys_rt_sigsuspend,
    sys_wait4, sys_waitid, sys_write, PollFd, SigInfo, Timespec, CLOCK_MONOTONIC, CLONE_VM,
    FUTEX_WAIT, FUTEX_WAKE, P_PID, SA_RESTART, SA_RESTORER, SIGALRM, SIGCHLD, SIGKILL, SIGUSR1,
    SIG_DFL, SIG_SETMASK, SIG_UNBLOCK,
};

const EINTR: i64 = -4;
const WNOHANG: i32 = 1;
const WEXITED: i32 = 4;
const CLD_KILLED: i32 = 2;
const POLLIN: i16 = 1;

/// Accepted range for a 300 ms sleep (loose: TCG, slow CI hosts)
const SLEEP_MIN_MS: u64 = 290;
const SLEEP_MAX_MS: u64 = 1500;

pub fn run_tests() {
    // Earlier tests may leave signals blocked (and pending); children
    // inherit the mask. Catch anything pending harmlessly, then unblock.
    set_handler(SIGUSR1, 0);
    set_handler(SIGALRM, 0);
    let ours: u64 = (1 << (SIGUSR1 - 1)) | (1 << (SIGALRM - 1));
    let mut saved: u64 = 0;
    sys_rt_sigprocmask(SIG_UNBLOCK, &ours as *const u64 as u64, &mut saved as *mut u64 as u64, 8);
    reset_handler(SIGUSR1);
    reset_handler(SIGALRM);
    test_poll_timeout();
    test_nanosleep_timeout();
    test_poll_pipe_timeout();
    test_pipe_read_eintr();
    test_pipe_read_restart();
    test_pause_eintr();
    test_sigsuspend_sigkill();
    test_waitid_cld_killed();
    test_pipe_wake_stress();
    test_futex_wake_stress();
    sys_rt_sigprocmask(SIG_SETMASK, &saved as *const u64 as u64, 0, 8);
}

// ============================================================================
// Helpers
// ============================================================================

#[repr(C)]
struct SigActionData {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn restorer() -> ! {
    core::arch::naked_asm!("mov rax, 15", "syscall", "ud2")
}

#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
unsafe extern "C" fn restorer() -> ! {
    core::arch::naked_asm!("mov x8, 139", "svc 0", "brk 0")
}

/// CLOCK_MONOTONIC in milliseconds
fn now_ms() -> u64 {
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    sys_clock_gettime(CLOCK_MONOTONIC, &mut ts);
    ts.tv_sec as u64 * 1000 + ts.tv_nsec as u64 / 1_000_000
}

fn sleep_ms(ms: u64) {
    let req = Timespec { tv_sec: (ms / 1000) as i64, tv_nsec: ((ms % 1000) * 1_000_000) as i64 };
    sys_nanosleep(&req, core::ptr::null_mut());
}

/// Handler bookkeeping (per process: each forked child has its own copy)
static HANDLER_RUNS: AtomicU32 = AtomicU32::new(0);
static HANDLER_TIME_MS: AtomicU64 = AtomicU64::new(0);

extern "C" fn record_handler(_sig: i32) {
    HANDLER_RUNS.store(HANDLER_RUNS.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
    HANDLER_TIME_MS.store(now_ms(), Ordering::Relaxed);
}

fn set_handler(sig: u32, flags: u64) {
    let act = SigActionData {
        handler: record_handler as *const () as u64,
        flags: flags | SA_RESTORER,
        restorer: restorer as *const () as u64,
        mask: 0,
    };
    sys_rt_sigaction(sig, &act as *const SigActionData as u64, 0, 8);
}

fn reset_handler(sig: u32) {
    let act = SigActionData { handler: SIG_DFL, flags: 0, restorer: 0, mask: 0 };
    sys_rt_sigaction(sig, &act as *const SigActionData as u64, 0, 8);
}

/// Reap `pid`, giving up after `ms` (returns the wait status)
fn reap_within(pid: i64, ms: u64) -> Option<i32> {
    let start = now_ms();
    loop {
        let mut status: i32 = 0;
        let r = sys_wait4(pid, &mut status, WNOHANG, 0);
        if r == pid {
            return Some(status);
        }
        if r < 0 || now_ms().saturating_sub(start) > ms {
            return None;
        }
        sleep_ms(10);
    }
}

/// Last resort for a stuck child: SIGKILL and reap (bounded)
fn kill_and_reap(pid: i64) {
    sys_kill(pid, SIGKILL);
    let _ = reap_within(pid, 2000);
}

/// Print `NAME:OK` if `status` is a clean exit(0), else `NAME:FAIL ...`
fn report_child(name: &[u8], status: Option<i32>, codes: &[(i32, &[u8])]) {
    print(name);
    match status {
        None => println(b":FAIL child did not finish (blocked/lost wakeup)"),
        Some(st) if st & 0x7f != 0 => {
            print(b":FAIL child killed by signal ");
            print_num((st & 0x7f) as i64);
            println(b"");
        }
        Some(st) => {
            let code = (st >> 8) & 0xff;
            if code == 0 {
                println(b":OK");
                return;
            }
            print(b":FAIL child exit ");
            print_num(code as i64);
            for (c, what) in codes {
                if *c == code {
                    print(b" (");
                    print(what);
                    print(b")");
                }
            }
            println(b"");
        }
    }
}

fn check_elapsed(name: &[u8], ret: i64, expect_ret: i64, elapsed: u64) {
    print(name);
    if ret == expect_ret && (SLEEP_MIN_MS..=SLEEP_MAX_MS).contains(&elapsed) {
        println(b":OK");
    } else {
        print(b":FAIL ret=");
        print_num(ret);
        print(b" elapsed_ms=");
        print_num(elapsed as i64);
        println(b" (want 290..1500)");
    }
}

// ============================================================================
// Timeouts
// ============================================================================

/// poll(NULL, 0, 300) sleeps ~300 ms of CLOCK_MONOTONIC time
fn test_poll_timeout() {
    let t0 = now_ms();
    let r = sys_poll(core::ptr::null_mut(), 0, 300);
    check_elapsed(b"TIMING_POLL_300MS", r, 0, now_ms() - t0);
}

/// nanosleep(300 ms) sleeps ~300 ms of CLOCK_MONOTONIC time
fn test_nanosleep_timeout() {
    let req = Timespec { tv_sec: 0, tv_nsec: 300_000_000 };
    let t0 = now_ms();
    let r = sys_nanosleep(&req, core::ptr::null_mut());
    check_elapsed(b"TIMING_NANOSLEEP_300MS", r, 0, now_ms() - t0);
}

/// poll() on a pipe that never becomes readable times out after ~300 ms
fn test_poll_pipe_timeout() {
    let mut fds = [0i32; 2];
    if sys_pipe(fds.as_mut_ptr()) != 0 {
        println(b"TIMING_POLL_PIPE_300MS:FAIL pipe");
        return;
    }
    let mut pfd = PollFd { fd: fds[0], events: POLLIN, revents: 0 };
    let t0 = now_ms();
    let r = sys_poll(&mut pfd, 1, 300);
    check_elapsed(b"TIMING_POLL_PIPE_300MS", r, 0, now_ms() - t0);
    sys_close(fds[0] as u64);
    sys_close(fds[1] as u64);
}

// ============================================================================
// Signals interrupting blocked syscalls
// ============================================================================

/// A child blocked in read() on an empty pipe gets SIGALRM (handler, no
/// SA_RESTART): read returns -EINTR after the handler ran.
fn test_pipe_read_eintr() {
    let mut fds = [0i32; 2];
    if sys_pipe(fds.as_mut_ptr()) != 0 {
        println(b"SIGNAL_PIPE_READ_EINTR:FAIL pipe");
        return;
    }
    HANDLER_RUNS.store(0, Ordering::Relaxed);
    set_handler(SIGALRM, 0);
    let pid = sys_fork();
    if pid == 0 {
        let mut b = [0u8; 1];
        let r = sys_read(fds[0] as u64, b.as_mut_ptr(), 1);
        let ran = HANDLER_RUNS.load(Ordering::Relaxed);
        sys_exit(if r == EINTR && ran == 1 {
            0
        } else if r == EINTR {
            2
        } else if r == 1 {
            3
        } else {
            4
        });
    }
    sleep_ms(150);
    sys_kill(pid, SIGALRM);
    let mut st = reap_within(pid, 3000);
    if st.is_none() {
        // Unblock a child that never noticed the signal, so it can report
        sys_write(fds[1] as u64, b"x".as_ptr(), 1);
        st = reap_within(pid, 3000);
        if st.is_none() {
            kill_and_reap(pid);
        }
    }
    reset_handler(SIGALRM);
    sys_close(fds[0] as u64);
    sys_close(fds[1] as u64);
    report_child(
        b"SIGNAL_PIPE_READ_EINTR",
        st,
        &[
            (2, b"EINTR but handler did not run"),
            (3, b"read not interrupted: got data only after unblock"),
            (4, b"unexpected read result"),
        ],
    );
}

/// Same with SA_RESTART: the handler runs while the read is blocked, then
/// the read restarts and returns the data written ~300 ms later.
fn test_pipe_read_restart() {
    let mut fds = [0i32; 2];
    if sys_pipe(fds.as_mut_ptr()) != 0 {
        println(b"SIGNAL_PIPE_READ_SA_RESTART:FAIL pipe");
        return;
    }
    HANDLER_RUNS.store(0, Ordering::Relaxed);
    HANDLER_TIME_MS.store(0, Ordering::Relaxed);
    set_handler(SIGALRM, SA_RESTART);
    let pid = sys_fork();
    if pid == 0 {
        let mut b = [0u8; 1];
        let r = sys_read(fds[0] as u64, b.as_mut_ptr(), 1);
        let t_read = now_ms();
        let ran = HANDLER_RUNS.load(Ordering::Relaxed);
        let t_handler = HANDLER_TIME_MS.load(Ordering::Relaxed);
        sys_exit(if r != 1 {
            if r == EINTR { 2 } else { 3 }
        } else if ran != 1 {
            4
        } else if t_read.saturating_sub(t_handler) < 150 {
            5
        } else {
            0
        });
    }
    sleep_ms(150);
    sys_kill(pid, SIGALRM);
    sleep_ms(300);
    sys_write(fds[1] as u64, b"x".as_ptr(), 1);
    let st = reap_within(pid, 3000);
    if st.is_none() {
        kill_and_reap(pid);
    }
    reset_handler(SIGALRM);
    sys_close(fds[0] as u64);
    sys_close(fds[1] as u64);
    report_child(
        b"SIGNAL_PIPE_READ_SA_RESTART",
        st,
        &[
            (2, b"read returned EINTR despite SA_RESTART"),
            (3, b"unexpected read result"),
            (4, b"handler did not run exactly once"),
            (5, b"handler ran only when read completed, not while blocked"),
        ],
    );
}

/// pause() blocks until a handled signal arrives, then returns -EINTR
fn test_pause_eintr() {
    HANDLER_RUNS.store(0, Ordering::Relaxed);
    set_handler(SIGUSR1, 0);
    let pid = sys_fork();
    if pid == 0 {
        let t0 = now_ms();
        let r = sys_pause();
        let waited = now_ms().saturating_sub(t0);
        let ran = HANDLER_RUNS.load(Ordering::Relaxed);
        sys_exit(if r != EINTR {
            2
        } else if ran != 1 {
            3
        } else if waited < 50 {
            4
        } else {
            0
        });
    }
    sleep_ms(150);
    sys_kill(pid, SIGUSR1);
    let st = reap_within(pid, 3000);
    if st.is_none() {
        kill_and_reap(pid);
    }
    reset_handler(SIGUSR1);
    report_child(
        b"PAUSE_EINTR",
        st,
        &[
            (2, b"pause did not return -EINTR"),
            (3, b"handler did not run exactly once"),
            (4, b"pause returned before the signal was sent"),
        ],
    );
}

/// A child sleeping in rt_sigsuspend is killed by SIGKILL from its parent;
/// wait4 reports WIFSIGNALED with WTERMSIG == SIGKILL.
fn test_sigsuspend_sigkill() {
    let pid = sys_fork();
    if pid == 0 {
        let mask: u64 = 0;
        sys_rt_sigsuspend(&mask as *const u64 as u64, 8);
        sys_exit(7);
    }
    sleep_ms(150);
    sys_kill(pid, SIGKILL);
    let st = reap_within(pid, 3000);
    print(b"SIGSUSPEND_SIGKILL");
    match st {
        Some(s) if s & 0x7f == SIGKILL as i32 => println(b":OK"),
        Some(s) => {
            print(b":FAIL wstatus=");
            print_num(s as i64);
            println(b" (want WIFSIGNALED, WTERMSIG=9)");
        }
        None => println(b":FAIL child not reaped (SIGKILL did not wake sigsuspend)"),
    }
}

/// waitid() reports a SIGKILLed child as CLD_KILLED with si_status = 9
fn test_waitid_cld_killed() {
    let pid = sys_fork();
    if pid == 0 {
        let mask: u64 = 0;
        sys_rt_sigsuspend(&mask as *const u64 as u64, 8);
        sys_exit(7);
    }
    sleep_ms(150);
    sys_kill(pid, SIGKILL);
    let start = now_ms();
    let mut info: SigInfo = unsafe { core::mem::zeroed() };
    let mut got = false;
    while now_ms() - start < 3000 {
        info = unsafe { core::mem::zeroed() };
        let r = sys_waitid(P_PID, pid as u64, &mut info, WEXITED | WNOHANG, 0);
        if r == 0 && info.si_pid as i64 == pid {
            got = true;
            break;
        }
        if r < 0 {
            break;
        }
        sleep_ms(10);
    }
    print(b"WAITID_CLD_KILLED");
    if !got {
        println(b":FAIL child not reaped");
        kill_and_reap(pid);
    } else if info.si_code == CLD_KILLED && info.si_status == SIGKILL as i32 {
        println(b":OK");
    } else {
        print(b":FAIL si_code=");
        print_num(info.si_code as i64);
        print(b" si_status=");
        print_num(info.si_status as i64);
        println(b" (want CLD_KILLED=2, 9)");
    }
}

// ============================================================================
// Wake/wait stress
// ============================================================================

const PIPE_CHILDREN: usize = 3;
const PIPE_ROUNDS: usize = 300;

/// Several children ping-pong one byte with the parent: each child blocks in
/// read(); the parent blocks in poll() with a timeout. A lost wakeup shows up
/// as a poll timeout.
fn test_pipe_wake_stress() {
    let mut to_child = [[0i32; 2]; PIPE_CHILDREN];
    let mut to_parent = [[0i32; 2]; PIPE_CHILDREN];
    let mut pids = [0i64; PIPE_CHILDREN];
    for k in 0..PIPE_CHILDREN {
        if sys_pipe(to_child[k].as_mut_ptr()) != 0 || sys_pipe(to_parent[k].as_mut_ptr()) != 0 {
            println(b"WAKE_STRESS_PIPE:FAIL pipe");
            return;
        }
    }
    for k in 0..PIPE_CHILDREN {
        let pid = sys_fork();
        if pid == 0 {
            let mut b = [0u8; 1];
            for _ in 0..PIPE_ROUNDS {
                if sys_read(to_child[k][0] as u64, b.as_mut_ptr(), 1) != 1 {
                    sys_exit(2);
                }
                if sys_write(to_parent[k][1] as u64, b.as_ptr(), 1) != 1 {
                    sys_exit(3);
                }
            }
            sys_exit(0);
        }
        pids[k] = pid;
    }
    let mut failed_round: i64 = -1;
    'rounds: for round in 0..PIPE_ROUNDS {
        for fds in &to_child {
            sys_write(fds[1] as u64, b"p".as_ptr(), 1);
        }
        for fds in &to_parent {
            let mut pfd = PollFd { fd: fds[0], events: POLLIN, revents: 0 };
            let mut b = [0u8; 1];
            if sys_poll(&mut pfd, 1, 3000) != 1 || sys_read(fds[0] as u64, b.as_mut_ptr(), 1) != 1 {
                failed_round = round as i64;
                break 'rounds;
            }
        }
    }
    let mut bad_child = false;
    for &pid in &pids {
        match reap_within(pid, 3000) {
            Some(0) => {}
            Some(_) => bad_child = true,
            None => {
                bad_child = true;
                kill_and_reap(pid);
            }
        }
    }
    for k in 0..PIPE_CHILDREN {
        for fd in to_child[k].iter().chain(to_parent[k].iter()) {
            sys_close(*fd as u64);
        }
    }
    if failed_round < 0 && !bad_child {
        println(b"WAKE_STRESS_PIPE:OK");
    } else {
        print(b"WAKE_STRESS_PIPE:FAIL lost wakeup at round ");
        print_num(failed_round);
        if bad_child {
            print(b" (child failed)");
        }
        println(b"");
    }
}

const FUTEX_ROUNDS: u32 = 300;

/// Whose turn it is: 0 = parent, 1 = child (shared via CLONE_VM)
static TURN: AtomicU32 = AtomicU32::new(0);
static CHILD_FAILED: AtomicU32 = AtomicU32::new(0);

#[repr(C, align(16))]
struct FutexStack([u8; 16384]);
static mut FUTEX_CHILD_STACK: FutexStack = FutexStack([0; 16384]);

/// Wait (shared futex, so it works across the CLONE_VM process pair) until
/// TURN == me; false if that takes more than 3 s (lost wakeup)
fn futex_wait_turn(me: u32) -> bool {
    let start = now_ms();
    let timeout = Timespec { tv_sec: 0, tv_nsec: 500_000_000 };
    while TURN.load(Ordering::Acquire) != me {
        sys_futex(TURN.as_ptr(), FUTEX_WAIT, 1 - me, &timeout, core::ptr::null_mut(), 0);
        if now_ms().saturating_sub(start) > 3000 {
            return false;
        }
    }
    true
}

fn futex_pass_turn(to: u32) {
    TURN.store(to, Ordering::Release);
    sys_futex(TURN.as_ptr(), FUTEX_WAKE, 1, core::ptr::null(), core::ptr::null_mut(), 0);
}

#[inline(never)]
fn futex_child() -> ! {
    for _ in 0..FUTEX_ROUNDS {
        if !futex_wait_turn(1) {
            CHILD_FAILED.store(1, Ordering::Relaxed);
            sys_exit(2);
        }
        futex_pass_turn(0);
    }
    sys_exit(0);
}

/// Parent and a CLONE_VM child hand a turn back and forth with
/// FUTEX_WAIT/FUTEX_WAKE; a lost wakeup stalls one side past its timeout.
fn test_futex_wake_stress() {
    TURN.store(0, Ordering::Relaxed);
    CHILD_FAILED.store(0, Ordering::Relaxed);
    let stack_top = unsafe { (&raw mut FUTEX_CHILD_STACK as *mut u8).add(16384) as u64 };
    let pid = sys_clone(CLONE_VM | SIGCHLD as u64, stack_top, 0, 0, 0);
    if pid == 0 {
        futex_child();
    }
    if pid < 0 {
        print(b"WAKE_STRESS_FUTEX:FAIL clone ");
        print_num(pid);
        println(b"");
        return;
    }
    let mut ok = true;
    for _ in 0..FUTEX_ROUNDS {
        futex_pass_turn(1);
        if !futex_wait_turn(0) {
            ok = false;
            break;
        }
    }
    let st = reap_within(pid, 3000);
    if st.is_none() {
        kill_and_reap(pid);
    }
    if ok && st == Some(0) && CHILD_FAILED.load(Ordering::Relaxed) == 0 {
        println(b"WAKE_STRESS_FUTEX:OK");
    } else {
        print(b"WAKE_STRESS_FUTEX:FAIL");
        if !ok {
            print(b" parent stalled (lost wakeup)");
        }
        if CHILD_FAILED.load(Ordering::Relaxed) != 0 {
            print(b" child stalled (lost wakeup)");
        }
        if st.is_none() {
            print(b" child not reaped");
        }
        println(b"");
    }
}
