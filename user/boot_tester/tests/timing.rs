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
    CLOCK_MONOTONIC, CLONE_VM, FUTEX_WAIT, FUTEX_WAKE, P_PID, PollFd, SA_RESTART, SA_RESTORER,
    SIG_DFL, SIG_SETMASK, SIG_UNBLOCK, SIGALRM, SIGCHLD, SIGKILL, SIGUSR1, SigInfo, Timespec,
    sys_clock_gettime, sys_clone, sys_close, sys_exit, sys_fork, sys_futex, sys_kill,
    sys_nanosleep, sys_pause, sys_pipe, sys_poll, sys_read, sys_rt_sigaction, sys_rt_sigprocmask,
    sys_rt_sigsuspend, sys_wait4, sys_waitid, sys_write,
};
use hk_syscall::{
    CLOCK_REALTIME, EPOLL_CTL_ADD, EPOLLIN, EpollEvent, IPC_CREAT, IPC_PRIVATE, IPC_RMID, O_CREAT,
    O_RDWR, Sembuf, sys_epoll_create1, sys_epoll_ctl, sys_epoll_wait, sys_getppid, sys_mq_open,
    sys_mq_timedreceive, sys_mq_unlink, sys_msgctl, sys_msgget, sys_msgrcv, sys_msgsnd,
    sys_rt_sigtimedwait, sys_semctl, sys_semget, sys_semop,
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
    sys_rt_sigprocmask(
        SIG_UNBLOCK,
        &ours as *const u64 as u64,
        &mut saved as *mut u64 as u64,
        8,
    );
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
    test_sigframe_bad_stack();
    test_sigreturn_bad_frame();
    test_user_fault_kills();
    test_kernel_pointer_efault();
    test_timerfd_huge_values();
    test_posix_timer_huge_values();
    test_epoll_block();
    test_sigtimedwait_block();
    test_mq_timeout();
    test_msgrcv_block();
    test_semop_block();
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
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(CLOCK_MONOTONIC, &mut ts);
    ts.tv_sec as u64 * 1000 + ts.tv_nsec as u64 / 1_000_000
}

fn sleep_ms(ms: u64) {
    let req = Timespec {
        tv_sec: (ms / 1000) as i64,
        tv_nsec: ((ms % 1000) * 1_000_000) as i64,
    };
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
    let act = SigActionData {
        handler: SIG_DFL,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
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
    let req = Timespec {
        tv_sec: 0,
        tv_nsec: 300_000_000,
    };
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
    let mut pfd = PollFd {
        fd: fds[0],
        events: POLLIN,
        revents: 0,
    };
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
            (
                5,
                b"handler ran only when read completed, not while blocked",
            ),
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
            let mut pfd = PollFd {
                fd: fds[0],
                events: POLLIN,
                revents: 0,
            };
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
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: 500_000_000,
    };
    while TURN.load(Ordering::Acquire) != me {
        sys_futex(
            TURN.as_ptr(),
            FUTEX_WAIT,
            1 - me,
            &timeout,
            core::ptr::null_mut(),
            0,
        );
        if now_ms().saturating_sub(start) > 3000 {
            return false;
        }
    }
    true
}

fn futex_pass_turn(to: u32) {
    TURN.store(to, Ordering::Release);
    sys_futex(
        TURN.as_ptr(),
        FUTEX_WAKE,
        1,
        core::ptr::null(),
        core::ptr::null_mut(),
        0,
    );
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

// ============================================================================
// Signal frames on hostile user stack pointers
// ============================================================================

/// With SP = 64, raise SIGUSR1 (handled) via raw kill(): the kernel cannot
/// place a signal frame and must kill the task with SIGSEGV (not panic).
#[cfg(target_arch = "x86_64")]
fn kill_self_with_tiny_stack(pid: i64) -> ! {
    unsafe {
        core::arch::asm!(
            "mov rsp, 64",
            "syscall",
            "ud2",
            in("rax") 62u64, // kill
            in("rdi") pid,
            in("rsi") SIGUSR1 as u64,
            options(noreturn)
        )
    }
}

#[cfg(target_arch = "aarch64")]
fn kill_self_with_tiny_stack(pid: i64) -> ! {
    unsafe {
        core::arch::asm!(
            "mov x9, 64",
            "mov sp, x9",
            "svc 0",
            "brk 0",
            in("x8") 129u64, // kill
            in("x0") pid,
            in("x1") SIGUSR1 as u64,
            options(noreturn)
        )
    }
}

/// rt_sigreturn with SP = 64: no readable frame, Linux badframe -> SIGSEGV
#[cfg(target_arch = "x86_64")]
fn sigreturn_with_tiny_stack() -> ! {
    unsafe { core::arch::asm!("mov rsp, 64", "syscall", "ud2", in("rax") 15u64, options(noreturn)) }
}

#[cfg(target_arch = "aarch64")]
fn sigreturn_with_tiny_stack() -> ! {
    unsafe {
        core::arch::asm!(
            "mov x9, 64",
            "mov sp, x9",
            "svc 0",
            "brk 0",
            in("x8") 139u64,
            options(noreturn)
        )
    }
}

fn expect_sigsegv(name: &[u8], pid: i64) {
    expect_killed_by(name, pid, 11);
}

fn expect_killed_by(name: &[u8], pid: i64, sig: i32) {
    let st = reap_within(pid, 3000);
    print(name);
    match st {
        Some(s) if s & 0x7f == sig => println(b":OK"),
        Some(s) => {
            print(b":FAIL wstatus=");
            print_num(s as i64);
            print(b" (want WTERMSIG=");
            print_num(sig as i64);
            println(b")");
        }
        None => {
            println(b":FAIL child not reaped");
            kill_and_reap(pid);
        }
    }
}

/// A handled signal with an unusable user stack kills the task with SIGSEGV
fn test_sigframe_bad_stack() {
    set_handler(SIGUSR1, 0);
    let pid = sys_fork();
    if pid == 0 {
        kill_self_with_tiny_stack(hk_syscall::sys_getpid());
    }
    reset_handler(SIGUSR1);
    expect_sigsegv(b"SIGFRAME_BAD_STACK_SIGSEGV", pid);
}

/// rt_sigreturn on an unreadable frame kills the task with SIGSEGV
fn test_sigreturn_bad_frame() {
    let pid = sys_fork();
    if pid == 0 {
        sigreturn_with_tiny_stack();
    }
    expect_sigsegv(b"SIGRETURN_BAD_FRAME_SIGSEGV", pid);
}

/// An illegal instruction in user mode kills the task with SIGILL (default
/// disposition) and leaves the kernel running
fn test_user_fault_kills() {
    let pid = sys_fork();
    if pid == 0 {
        unsafe {
            #[cfg(target_arch = "x86_64")]
            core::arch::asm!("ud2", options(noreturn));
            #[cfg(target_arch = "aarch64")]
            core::arch::asm!("udf #0", options(noreturn));
        }
    }
    expect_killed_by(b"USER_FAULT_SIGILL", pid, 4);
}

/// A user pointer into the kernel half (the direct map of the kernel
/// image on hk) must fail with EFAULT (access_ok), not read kernel memory
fn test_kernel_pointer_efault() {
    const KADDR: u64 = super::layout::KERNEL_ADDR;
    let mut fds = [0i32; 2];
    if sys_pipe(fds.as_mut_ptr()) != 0 {
        println(b"UACCESS_KERNEL_PTR_EFAULT:FAIL pipe");
        return;
    }
    let r = sys_write(fds[1] as u64, KADDR as *const u8, 16);
    sys_close(fds[0] as u64);
    sys_close(fds[1] as u64);
    if r == -14 {
        println(b"UACCESS_KERNEL_PTR_EFAULT:OK");
    } else {
        print(b"UACCESS_KERNEL_PTR_EFAULT:FAIL write returned ");
        print_num(r);
        println(b" (want -14 EFAULT)");
    }
}

// ============================================================================
// Timers with enormous user-supplied values
// ============================================================================

const HUGE_SEC: i64 = i64::MAX / 2;

/// timerfd with a 1 ms first expiry and an interval of ~i64::MAX/2 seconds:
/// fires once, then never again (Linux clamps to KTIME_MAX); a huge first
/// value never fires; negative seconds are EINVAL. The kernel must neither
/// panic nor livelock re-arming the timer.
fn test_timerfd_huge_values() {
    use hk_syscall::{ITimerSpec, TFD_NONBLOCK, sys_timerfd_create, sys_timerfd_settime};
    let fd = sys_timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if fd < 0 {
        println(b"TIMERFD_HUGE_INTERVAL:FAIL timerfd_create");
        return;
    }
    let fd = fd as i32;
    let mut count = [0u8; 8];
    let read_count = |buf: &mut [u8; 8]| sys_read(fd as u64, buf.as_mut_ptr(), 8);

    // Huge interval: one expiry, then effectively never
    let spec = ITimerSpec {
        it_interval: Timespec {
            tv_sec: HUGE_SEC,
            tv_nsec: 999_999_999,
        },
        it_value: Timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        },
    };
    let r_set = sys_timerfd_settime(fd, 0, &spec, core::ptr::null_mut());
    sleep_ms(50);
    let r1 = read_count(&mut count);
    let n1 = u64::from_ne_bytes(count);
    sleep_ms(50);
    let r2 = read_count(&mut count);
    print(b"TIMERFD_HUGE_INTERVAL");
    if r_set == 0 && r1 == 8 && n1 == 1 && r2 == -11 {
        println(b":OK");
    } else {
        print(b":FAIL set=");
        print_num(r_set);
        print(b" read1=");
        print_num(r1);
        print(b" n=");
        print_num(n1 as i64);
        print(b" read2=");
        print_num(r2);
        println(b"");
    }

    // Huge first expiry: armed, never fires
    let spec = ITimerSpec {
        it_interval: Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: Timespec {
            tv_sec: HUGE_SEC,
            tv_nsec: 0,
        },
    };
    let r_set = sys_timerfd_settime(fd, 0, &spec, core::ptr::null_mut());
    sleep_ms(20);
    let r = read_count(&mut count);
    print(b"TIMERFD_HUGE_VALUE");
    if r_set == 0 && r == -11 {
        println(b":OK");
    } else {
        print(b":FAIL set=");
        print_num(r_set);
        print(b" read=");
        print_num(r);
        println(b"");
    }

    // Negative seconds are invalid
    let spec = ITimerSpec {
        it_interval: Timespec {
            tv_sec: -1,
            tv_nsec: 0,
        },
        it_value: Timespec {
            tv_sec: 1,
            tv_nsec: 0,
        },
    };
    let r = sys_timerfd_settime(fd, 0, &spec, core::ptr::null_mut());
    print(b"TIMERFD_NEGATIVE_EINVAL");
    if r == -22 {
        println(b":OK");
    } else {
        print(b":FAIL got ");
        print_num(r);
        println(b"");
    }
    sys_close(fd as u64);
}

/// POSIX timer (SIGEV_NONE) with a tiny value and a huge interval: settime
/// succeeds and the kernel keeps running (no re-arm livelock)
fn test_posix_timer_huge_values() {
    use hk_syscall::{
        ITimerSpec, SigEvent, sys_timer_create, sys_timer_delete, sys_timer_gettime,
        sys_timer_settime,
    };
    let sev = SigEvent::none();
    let mut id: i32 = 0;
    if sys_timer_create(CLOCK_MONOTONIC, &sev, &mut id) != 0 {
        println(b"POSIX_TIMER_HUGE_INTERVAL:FAIL timer_create");
        return;
    }
    let spec = ITimerSpec {
        it_interval: Timespec {
            tv_sec: HUGE_SEC,
            tv_nsec: 0,
        },
        it_value: Timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        },
    };
    let r_set = sys_timer_settime(id, 0, &spec, core::ptr::null_mut());
    sleep_ms(50);
    let mut cur = ITimerSpec {
        it_interval: Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    let r_get = sys_timer_gettime(id, &mut cur);
    let bad = ITimerSpec {
        it_interval: Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: Timespec {
            tv_sec: -5,
            tv_nsec: 0,
        },
    };
    let r_neg = sys_timer_settime(id, 0, &bad, core::ptr::null_mut());
    sys_timer_delete(id);
    print(b"POSIX_TIMER_HUGE_INTERVAL");
    if r_set == 0 && r_get == 0 && r_neg == -22 {
        println(b":OK");
    } else {
        print(b":FAIL set=");
        print_num(r_set);
        print(b" get=");
        print_num(r_get);
        print(b" neg=");
        print_num(r_neg);
        println(b"");
    }
}

// ============================================================================
// Blocking waits woken by another process (formerly one-tick polling)
// ============================================================================

/// Fork a child that sleeps `ms` then runs `f`; returns its pid
fn later(ms: u64, f: fn()) -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        sleep_ms(ms);
        f();
        sys_exit(0);
    }
    pid
}

static mut WAKE_FD: i32 = -1;
static mut WAKE_ID: i32 = -1;

fn write_wake_fd() {
    sys_write(unsafe { WAKE_FD } as u64, b"x".as_ptr(), 1);
}

/// epoll_wait(-1) sleeps until another process makes a fd readable
fn test_epoll_block() {
    const N: &[u8] = b"TIMING_EPOLL_BLOCK";
    let mut p = [0i32; 2];
    sys_pipe(p.as_mut_ptr());
    let ep = sys_epoll_create1(0) as i32;
    let ev = EpollEvent::new(EPOLLIN, 7);
    sys_epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev);
    unsafe { WAKE_FD = p[1] };
    let pid = later(100, write_wake_fd);
    let mut out = [EpollEvent::empty(); 2];
    let r = sys_epoll_wait(ep, out.as_mut_ptr(), 2, -1);
    let _ = reap_within(pid, 5000);
    for f in [p[0], p[1], ep] {
        sys_close(f as u64);
    }
    print(N);
    if r == 1 {
        println(b":OK");
    } else {
        print(b":FAIL ret=");
        print_num(r);
        println(b"");
    }
}

fn kill_parent_usr1() {
    sys_kill(sys_getppid(), SIGUSR1);
}

/// rt_sigtimedwait sleeps: a 300 ms timeout is EAGAIN after ~300 ms; a
/// blocked signal sent later is returned
fn test_sigtimedwait_block() {
    let set: u64 = 1 << (SIGUSR1 - 1);
    let mut old: u64 = 0;
    sys_rt_sigprocmask(
        0, /* SIG_BLOCK */
        &set as *const u64 as u64,
        &mut old as *mut u64 as u64,
        8,
    );
    let ts = Timespec {
        tv_sec: 0,
        tv_nsec: 300_000_000,
    };
    let t0 = now_ms();
    let r = sys_rt_sigtimedwait(
        &set as *const u64 as u64,
        0,
        &ts as *const Timespec as u64,
        8,
    );
    check_elapsed(b"TIMING_SIGTIMEDWAIT_TIMEOUT", r, -11, now_ms() - t0);
    let pid = later(100, kill_parent_usr1);
    let r = sys_rt_sigtimedwait(&set as *const u64 as u64, 0, 0, 8);
    let _ = reap_within(pid, 5000);
    sys_rt_sigprocmask(SIG_SETMASK, &old as *const u64 as u64, 0, 8);
    print(b"TIMING_SIGTIMEDWAIT_BLOCK");
    if r == SIGUSR1 as i64 {
        println(b":OK");
    } else {
        print(b":FAIL ret=");
        print_num(r);
        println(b"");
    }
}

/// mq_timedreceive on an empty queue: ETIMEDOUT after the absolute
/// CLOCK_REALTIME timeout (~300 ms)
fn test_mq_timeout() {
    let name = b"hk_timing_mq\0";
    let fd = sys_mq_open(
        name.as_ptr(),
        (O_CREAT | O_RDWR) as i32,
        0o600,
        core::ptr::null(),
    ) as i32;
    if fd < 0 {
        print(b"TIMING_MQ_TIMEOUT:FAIL mq_open ");
        print_num(fd as i64);
        println(b"");
        return;
    }
    let mut now = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(CLOCK_REALTIME, &mut now);
    let mut abs = Timespec {
        tv_sec: now.tv_sec,
        tv_nsec: now.tv_nsec + 300_000_000,
    };
    if abs.tv_nsec >= 1_000_000_000 {
        abs.tv_sec += 1;
        abs.tv_nsec -= 1_000_000_000;
    }
    let mut buf = [0u8; 8192];
    let t0 = now_ms();
    let r = sys_mq_timedreceive(fd, buf.as_mut_ptr(), buf.len(), core::ptr::null_mut(), &abs);
    check_elapsed(b"TIMING_MQ_TIMEOUT", r, -110, now_ms() - t0);
    sys_close(fd as u64);
    sys_mq_unlink(name.as_ptr());
}

fn send_wake_msg() {
    let m: [u8; 16] = [1, 0, 0, 0, 0, 0, 0, 0, b'h', b'i', 0, 0, 0, 0, 0, 0];
    sys_msgsnd(unsafe { WAKE_ID }, m.as_ptr(), 2, 0);
}

/// msgrcv sleeps until another process sends
fn test_msgrcv_block() {
    let id = sys_msgget(IPC_PRIVATE, IPC_CREAT | 0o600) as i32;
    unsafe { WAKE_ID = id };
    let pid = later(100, send_wake_msg);
    let mut m = [0u8; 16];
    let r = sys_msgrcv(id, m.as_mut_ptr(), 8, 0, 0);
    let _ = reap_within(pid, 5000);
    sys_msgctl(id, IPC_RMID, 0);
    print(b"TIMING_MSGRCV_BLOCK");
    if r == 2 && &m[8..10] == b"hi" {
        println(b":OK");
    } else {
        print(b":FAIL ret=");
        print_num(r);
        println(b"");
    }
}

fn sem_post() {
    let op = Sembuf {
        sem_num: 0,
        sem_op: 1,
        sem_flg: 0,
    };
    sys_semop(unsafe { WAKE_ID }, &op, 1);
}

/// semop(-1) sleeps until another process increments
fn test_semop_block() {
    let id = sys_semget(IPC_PRIVATE, 1, IPC_CREAT | 0o600) as i32;
    unsafe { WAKE_ID = id };
    let pid = later(100, sem_post);
    let op = Sembuf {
        sem_num: 0,
        sem_op: -1,
        sem_flg: 0,
    };
    let r = sys_semop(id, &op, 1);
    let _ = reap_within(pid, 5000);
    sys_semctl(id, 0, IPC_RMID, 0);
    print(b"TIMING_SEMOP_BLOCK");
    if r == 0 {
        println(b":OK");
    } else {
        print(b":FAIL ret=");
        print_num(r);
        println(b"");
    }
}
