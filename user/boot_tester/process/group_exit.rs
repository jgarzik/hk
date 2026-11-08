//! Thread-group exit (Linux do_group_exit, zap_other_threads,
//! delay_group_leader, de_thread): exit_group and a fatal signal to any
//! thread end every thread, blocked ones included; the leader is reaped
//! only once all threads are gone; execve from any thread ends the
//! others, and keeps the process's pid when it leads its own process
//! group and a traced sibling is left a zombie (the exec waits for its
//! tracer to reap it). A process whose
//! threads all exit at once tells its parent once. Each child's threads hold the write end of a pipe (in their
//! shared descriptor table): EOF on it after the reap shows that none
//! is left.

use crate::harness::verdict;
use crate::helpers::sleep_ms;
use crate::mm::fork_mm::spawn_thread;
use hk_syscall::{
    P_PID, SigInfo, WEXITED, sys_close, sys_execve, sys_exit, sys_exit_group, sys_fork, sys_kill,
    sys_pipe2, sys_read, sys_tgkill, sys_wait4, sys_waitid, sys_write,
};

const SIGKILL: u32 = 9;
const SIGTERM: u32 = 15;
const WNOHANG: i32 = 1;
const O_NONBLOCK: u32 = 0o4000;
const BB: &[u8] = b"/bin/busybox\0";

pub fn run_tests() {
    test_exit_group();
    test_fatal_signal();
    test_leader_delay();
    test_kill_zombie_leader();
    test_kill_dead_group();
    test_exec_leader();
    test_exec_thread();
    test_exec_traced_sibling();
    test_notify_once();
}

#[repr(C, align(16))]
struct Stack([u8; 16384]);
static mut STACKS: [Stack; 3] = [const { Stack([0; 16384]) }; 3];
static mut CTIDS: [u32; 3] = [0; 3];

/// Start `f(arg)` on stack `i` (in the calling process); the tid
fn start(i: usize, f: extern "C" fn(u64) -> !, arg: u64) -> i64 {
    unsafe {
        let top = (&raw mut STACKS[i] as *mut u8).add(16384) as u64;
        let ctid = &raw mut CTIDS[i];
        spawn_thread(top, f, arg, ctid)
    }
}

/// Block in read() on `fd` (a pipe nobody writes), then exit the thread
extern "C" fn reader(fd: u64) -> ! {
    let mut c = [0u8; 1];
    sys_read(fd, c.as_mut_ptr(), 1);
    sys_exit(0)
}

/// Sleep for a minute, then exit the thread
extern "C" fn sleeper(_: u64) -> ! {
    sleep_ms(60_000);
    sys_exit(0)
}

/// A child's pipes: `hold` (the threads keep its write end), `block`
/// (readers block on it), `tids` (thread ids sent to the parent)
struct Pipes {
    hold: [i32; 2],
    block: [i32; 2],
    tids: [i32; 2],
}

fn pipes() -> Pipes {
    let mut p = Pipes {
        hold: [0; 2],
        block: [0; 2],
        tids: [0; 2],
    };
    sys_pipe2(p.hold.as_mut_ptr(), O_NONBLOCK);
    sys_pipe2(p.block.as_mut_ptr(), 0);
    sys_pipe2(p.tids.as_mut_ptr(), 0);
    p
}

/// In the child: a reader and a sleeper thread, their tids sent up
fn spawn_blocked(p: &Pipes) {
    send_tids(
        p,
        [start(0, reader, p.block[0] as u64), start(1, sleeper, 0)],
    );
    // Let them block
    sleep_ms(50);
}

/// In the child: tell the parent its thread ids
fn send_tids(p: &Pipes, tids: [i64; 2]) {
    sys_write(p.tids[1] as u64, tids.as_ptr() as *const u8, 16);
}

/// In the parent: the child's thread ids, the child's ends closed
/// (Our write ends go first: a child whose exec ends the thread that
/// would send the tids leaves only EOF to read.)
fn parent_side(p: &Pipes) -> [i64; 2] {
    let mut tids = [0i64; 2];
    sys_close(p.hold[1] as u64);
    sys_close(p.tids[1] as u64);
    sys_read(p.tids[0] as u64, tids.as_mut_ptr() as *mut u8, 16);
    sys_close(p.tids[0] as u64);
    tids
}

/// Reap `pid` within 5 s: its wait status, or None (it is then killed
/// and reaped anyway); then whether every thread is gone (EOF on the
/// hold pipe). The pipes are closed.
fn reap(pid: i64, p: &Pipes) -> (Option<i32>, bool) {
    let mut st = 0i32;
    let mut got = None;
    for _ in 0..500 {
        if sys_wait4(pid, &mut st, WNOHANG, 0) == pid {
            got = Some(st);
            break;
        }
        sleep_ms(10);
    }
    let mut c = [0u8; 1];
    let gone = sys_read(p.hold[0] as u64, c.as_mut_ptr(), 1) == 0;
    if got.is_none() {
        sys_kill(pid, SIGKILL);
        sys_wait4(pid, &mut st, 0, 0);
    }
    for fd in [p.hold[0], p.block[0], p.block[1]] {
        sys_close(fd as u64);
    }
    (got, gone)
}

/// exit_group from the main thread ends blocked siblings; the status
/// is the group's
fn test_exit_group() {
    let p = pipes();
    let pid = sys_fork();
    if pid == 0 {
        spawn_blocked(&p);
        sys_exit_group(7);
    }
    parent_side(&p);
    let (st, gone) = reap(pid, &p);
    verdict(
        b"GROUP_EXIT_ALL_THREADS",
        st == Some(7 << 8) && gone,
        st.unwrap_or(-1) as i64 * if gone { 1 } else { -1 },
    );
}

/// A fatal signal sent to one (non-leader) thread kills the group,
/// the main thread blocked in read() included
fn test_fatal_signal() {
    let p = pipes();
    let pid = sys_fork();
    if pid == 0 {
        spawn_blocked(&p);
        reader(p.block[0] as u64);
    }
    let tids = parent_side(&p);
    sleep_ms(50);
    sys_tgkill(pid, tids[1], SIGTERM);
    let (st, gone) = reap(pid, &p);
    verdict(
        b"GROUP_FATAL_SIGNAL",
        st == Some(SIGTERM as i32) && gone,
        st.unwrap_or(-1) as i64 * if gone { 1 } else { -1 },
    );
}

/// Wait for a byte, then exit_group(9)
extern "C" fn late_exit(fd: u64) -> ! {
    let mut c = [0u8; 1];
    sys_read(fd, c.as_mut_ptr(), 1);
    sys_exit_group(9)
}

/// The main thread exits alone (exit, not exit_group): the process is
/// not reaped while its other thread runs; that thread's exit_group
/// sets the status
fn test_leader_delay() {
    let p = pipes();
    let pid = sys_fork();
    if pid == 0 {
        send_tids(&p, [start(0, late_exit, p.block[0] as u64), 0]);
        sleep_ms(20);
        sys_exit(4);
    }
    parent_side(&p);
    sleep_ms(100);
    let mut st = 0i32;
    let early = sys_wait4(pid, &mut st, WNOHANG, 0);
    sys_write(p.block[1] as u64, b"x".as_ptr(), 1);
    let (st, gone) = reap(pid, &p);
    verdict(
        b"GROUP_LEADER_DELAY",
        early == 0 && st == Some(9 << 8) && gone,
        if early != 0 {
            -1000 - early
        } else {
            st.unwrap_or(-1) as i64
        },
    );
}

/// SIGKILL to a process whose main thread has exited reaches the
/// thread still running
fn test_kill_zombie_leader() {
    let p = pipes();
    let pid = sys_fork();
    if pid == 0 {
        send_tids(&p, [start(0, reader, p.block[0] as u64), 0]);
        sleep_ms(20);
        sys_exit(0);
    }
    parent_side(&p);
    sleep_ms(100);
    sys_kill(pid, SIGKILL);
    let (st, gone) = reap(pid, &p);
    verdict(
        b"GROUP_KILL_ZOMBIE_LEADER",
        st == Some(SIGKILL as i32) && gone,
        st.unwrap_or(-1) as i64 * if gone { 1 } else { -1 },
    );
}

/// Sleep, then end this thread alone with status 5
extern "C" fn thread_exit5(_: u64) -> ! {
    sleep_ms(20);
    sys_exit(5)
}

/// A process whose threads all exit one by one (exit, not exit_group)
/// reports the last thread's status (Linux 6.x do_exit: the last of
/// the group's threads sets the group exit code); a SIGKILL to it
/// before the reap changes nothing
fn test_kill_dead_group() {
    let mut got = [0i64; 2];
    for (i, kill) in [false, true].into_iter().enumerate() {
        let pid = sys_fork();
        if pid == 0 {
            start(0, thread_exit5, 0);
            sys_exit(3);
        }
        sleep_ms(200);
        let k = if kill { sys_kill(pid, SIGKILL) } else { 0 };
        let mut st = 0i32;
        let w = sys_wait4(pid, &mut st, 0, 0);
        got[i] = if k != 0 || w != pid { -1 } else { st as i64 };
    }
    verdict(b"GROUP_LAST_THREAD_STATUS", got[0] == 5 << 8, got[0]);
    verdict(b"GROUP_KILL_DEAD_STATUS", got[1] == 5 << 8, got[1]);
}

/// exec `busybox sh -c "exit <code>"`
fn exec_exit(code: &[u8]) -> ! {
    let argv: [*const u8; 5] = [
        BB.as_ptr(),
        b"sh\0".as_ptr(),
        b"-c\0".as_ptr(),
        code.as_ptr(),
        core::ptr::null(),
    ];
    let envp: [*const u8; 1] = [core::ptr::null()];
    sys_execve(BB.as_ptr(), argv.as_ptr(), envp.as_ptr());
    sys_exit_group(127)
}

/// execve from the main thread ends its blocked siblings
fn test_exec_leader() {
    let p = pipes();
    let pid = sys_fork();
    if pid == 0 {
        spawn_blocked(&p);
        exec_exit(b"exit 3\0");
    }
    parent_side(&p);
    let (st, gone) = reap(pid, &p);
    verdict(
        b"GROUP_EXEC_LEADER",
        st == Some(3 << 8) && gone,
        st.unwrap_or(-1) as i64 * if gone { 1 } else { -1 },
    );
}

extern "C" fn exec_thread(_: u64) -> ! {
    exec_exit(b"exit 5\0")
}

/// execve from a non-leader thread ends the main thread (blocked in
/// read) and takes over the process: the parent reaps the new image
fn test_exec_thread() {
    let p = pipes();
    let pid = sys_fork();
    if pid == 0 {
        send_tids(&p, [start(0, exec_thread, 0), 0]);
        reader(p.block[0] as u64);
    }
    parent_side(&p);
    let (st, gone) = reap(pid, &p);
    verdict(
        b"GROUP_EXEC_THREAD",
        st == Some(5 << 8) && gone,
        st.unwrap_or(-1) as i64 * if gone { 1 } else { -1 },
    );
}

/// Read one byte from fd `go`, then exec `busybox sh -c "sleep 1; exit 7"`
extern "C" fn exec_on_go(go: u64) -> ! {
    let mut c = [0u8; 1];
    sys_read(go, c.as_mut_ptr(), 1);
    exec_exit(b"sleep 1; exit 7\0")
}

/// Wait up to 5 s for traced thread `tid` to be a zombie, leaving it
/// waitable (waitid WNOWAIT): whether it became one
fn peek_zombie(tid: i64) -> bool {
    const WNOWAIT: i32 = 0x0100_0000;
    const WALL: i32 = 0x4000_0000;
    for _ in 0..500 {
        let mut info: SigInfo = unsafe { core::mem::zeroed() };
        let r = sys_waitid(
            P_PID,
            tid as u64,
            &mut info,
            WEXITED | WNOWAIT | WNOHANG | WALL,
            0,
        );
        if r < 0 {
            return false;
        }
        if info.si_pid as i64 == tid {
            return true;
        }
        sleep_ms(10);
    }
    false
}

/// A process leading its own process group (its pgid is its pid): a
/// thread traced by the parent is ended by a sibling's execve and left
/// a zombie for its tracer; the exec waits until the tracer reaps it
/// (Linux de_thread: notify_count drops at release_task). The new
/// image keeps the pid: kill(pid, 0) finds it and /proc/<pid>/stat
/// shows its new name (Linux de_thread: exchange_tids and transfer_pid
/// before the old leader is released; a pid is freed only when no task
/// uses it in any role)
fn test_exec_traced_sibling() {
    const PTRACE_SEIZE: i64 = 0x4206;
    const WALL: i32 = 0x4000_0000;
    let p = pipes();
    let pid = sys_fork();
    if pid == 0 {
        hk_syscall::sys_setpgid(0, 0);
        let traced = start(0, sleeper, 0);
        send_tids(&p, [traced, start(1, exec_on_go, p.block[0] as u64)]);
        reader(p.hold[0] as u64);
    }
    let tids = parent_side(&p);
    let seized = hk_syscall::sys_ptrace(PTRACE_SEIZE, tids[0], 0, 0);
    sys_write(p.block[1] as u64, b"x".as_ptr(), 1);
    let stat = crate::exec::exec_identity::proc_path(pid, b"stat\0");
    let mut buf = [0u8; 64];
    let execd = |buf: &mut [u8; 64]| {
        let n = crate::helpers::read_file(&stat, buf);
        n > 0 && buf[..n as usize].windows(9).any(|w| w == b"(busybox)")
    };
    // The killed sibling is the tracer's zombie: the exec is held until
    // it is reaped (its exit status 0: a thread an exec ends). Wait for
    // the zombie without reaping it, then the exec must still be held
    let zombie = peek_zombie(tids[0]);
    sleep_ms(100);
    let held = zombie && !execd(&mut buf);
    let mut st = -1i32;
    let mut r = 0;
    for _ in 0..500 {
        r = sys_wait4(tids[0], &mut st, WNOHANG | WALL, 0);
        if r != 0 {
            break;
        }
        sleep_ms(10);
    }
    let reaped = r == tids[0] && st == 0;
    let mut done = false;
    for _ in 0..200 {
        if execd(&mut buf) {
            done = true;
            break;
        }
        sleep_ms(10);
    }
    let alive = sys_kill(pid, 0);
    let (st, gone) = reap(pid, &p);
    let ok = seized == 0 && held && reaped && done && alive == 0 && st == Some(7 << 8) && gone;
    let v = if seized != 0 {
        seized
    } else if !held {
        -1001
    } else if !reaped {
        -2000 + r
    } else if !done {
        -1000
    } else if alive != 0 {
        alive
    } else {
        st.unwrap_or(-1) as i64
    };
    verdict(b"GROUP_EXEC_TRACED_SIBLING", ok, v);
}

const SIGRT: u32 = 40;
const RTMASK: u64 = 1 << (SIGRT - 1);
const SIG_BLOCK: i32 = 0;
const SIG_UNBLOCK: i32 = 1;
static mut NSTACKS: [Stack; 6] = [const { Stack([0; 16384]) }; 6];
static mut NCTIDS: [u32; 6] = [0; 6];
/// The helper thread's step: 0 idle, 1 open the window, 2 a long
/// window, 3 exit
static PHASE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Start `f(arg)` on notice-test stack `i`; the tid
fn nstart(i: usize, f: extern "C" fn(u64) -> !, arg: u64) -> i64 {
    unsafe {
        let top = (&raw mut NSTACKS[i] as *mut u8).add(16384) as u64;
        spawn_thread(top, f, arg, &raw mut NCTIDS[i])
    }
}

/// Block (`how` 0) or unblock (1) SIGRTMIN+6 in this thread
fn rt_mask(how: i32) {
    hk_syscall::sys_rt_sigprocmask(how, &RTMASK as *const u64 as u64, 0, 8);
}

/// Pending SIGRTMIN+6 instances taken now
fn rt_drain() -> i64 {
    let ts = [0i64, 0];
    let mut n = 0;
    while hk_syscall::sys_rt_sigtimedwait(&RTMASK as *const u64 as u64, 0, ts.as_ptr() as u64, 8)
        == SIGRT as i64
    {
        n += 1;
    }
    n
}

/// Yield `n` times, then exit_group(0)
extern "C" fn quitter(n: u64) -> ! {
    for _ in 0..n {
        hk_syscall::sys_sched_yield();
    }
    sys_exit_group(0)
}

/// The window thread: SIGRTMIN+6 is blocked but while the main thread
/// asks (PHASE 1: a few yields, 2: 100 ms), when its child is reaped
/// and its notice taken, so a notice sent late (or its wakeup done
/// late) finds a thread that takes it and the process dies of it
extern "C" fn window(_: u64) -> ! {
    use core::sync::atomic::Ordering::SeqCst;
    loop {
        match PHASE.load(SeqCst) {
            1 | 2 => {
                rt_mask(SIG_UNBLOCK);
                if PHASE.load(SeqCst) == 2 {
                    sleep_ms(100);
                } else {
                    for _ in 0..20 {
                        hk_syscall::sys_sched_yield();
                    }
                }
                rt_mask(SIG_BLOCK);
                PHASE.store(0, SeqCst);
            }
            3 => sys_exit(0),
            _ => {
                hk_syscall::sys_sched_yield();
            }
        }
    }
}

/// Have the window thread open `phase` and wait until it closes
fn open_window(phase: u32) {
    use core::sync::atomic::Ordering::SeqCst;
    PHASE.store(phase, SeqCst);
    while PHASE.load(SeqCst) != 0 {
        hk_syscall::sys_sched_yield();
    }
}

/// Child `i` of the notice loop: 0..=4 sleeping threads; the leader
/// calls exit_group, or a thread does while the leader sleeps, or the
/// leader exits first and a thread ends the group later
fn notice_child(i: usize) -> ! {
    for k in 0..i % 5 {
        nstart(k, sleeper, 0);
    }
    match i % 3 {
        0 => sys_exit_group(0),
        1 => {
            nstart(4, quitter, 0);
            sleep_ms(60_000);
            sys_exit(0)
        }
        _ => {
            nstart(4, quitter, 20);
            sys_exit(0)
        }
    }
}

/// The notice loop, in a process of its own: 0, or 1 + 2 * iteration
/// for a reap without exactly one notice (+1: more than one), or 255
/// for a notice left once all are reaped
fn notice_loop() -> u64 {
    const WALL: i32 = 0x4000_0000;
    const N: usize = 300;
    rt_mask(SIG_BLOCK);
    nstart(5, window, 0);
    let mut code = 0;
    for i in 0..N {
        let c = hk_syscall::sys_clone(SIGRT as u64, 0, 0, 0, 0);
        if c == 0 {
            notice_child(i);
        }
        let mut st = 0i32;
        sys_wait4(c, &mut st, WALL, 0);
        let n = rt_drain();
        if n != 1 {
            code = 1 + 2 * (i as u64 % 120) + u64::from(n > 1);
            break;
        }
        open_window(1);
    }
    if code == 0 {
        open_window(2);
        if rt_drain() != 0 {
            code = 255;
        }
    }
    PHASE.store(3, core::sync::atomic::Ordering::SeqCst);
    code
}

/// 300 times: a child (exit signal SIGRTMIN+6, which queues every
/// instance; 0 to 5 threads, ended by exit_group from the leader or a
/// thread, the leader first or not) is reaped and exactly one exit
/// signal is pending then (Linux exit_notify and release_task decide
/// "group empty" under tasklist_lock and queue it there: the leader's
/// exit or its last thread's release reports it, once, before the wait
/// can reap it); none comes later, nor does a late wakeup find a thread
/// of the parent that now takes it. In a process of its own, so a
/// stray one kills that process, not init.
fn test_notify_once() {
    let p = sys_fork();
    if p == 0 {
        sys_exit_group(notice_loop());
    }
    let mut st = -1i32;
    sys_wait4(p, &mut st, 0, 0);
    verdict(b"GROUP_NOTIFY_ONCE", st == 0, st as i64);
}
