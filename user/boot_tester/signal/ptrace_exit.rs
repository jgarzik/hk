//! A traced task's exit (run on hk and real Linux)
//!
//! - PTRACE_ZOMBIE_REAP: a traced non-leader thread's zombie is its
//!   tracer's to reap, without __WCLONE (Linux eligible_child: traced
//!   by us), and holds back its exited leader until then
//!   (delay_group_leader); its release tells the leader's parent
//!   (release_task). A tracer that exits without waiting releases it
//!   (exit_ptrace), and the leader's parent, now a subreaper, is told
//! - PTRACE_REAL_PARENT_NOTIFY: a child traced by another process is,
//!   once a zombie, hidden from its real parent (no SIGCHLD; WNOHANG
//!   gives 0, not ECHILD) until its tracer reaps it (Linux
//!   wait_task_zombie: EXIT_TRACE) or exits (__ptrace_detach); then the
//!   real parent gets SIGCHLD and reaps it
//! - PTRACE_EXITKILL: a tracee seized with PTRACE_O_EXITKILL dies of
//!   SIGKILL when its tracer exits (Linux exit_ptrace)
//! - PTRACE_EXIT_IGNORED_ZOMBIE: a tracer ignoring SIGCHLD that exits
//!   with its own traced child a zombie releases it (exit_ptrace runs
//!   before the children are handed on); the subreaper never sees it

use crate::harness::verdict;
use crate::helpers::{read_file, sleep_ms};
use hk_syscall::{
    SigInfo, Zeroable, sys_close, sys_exit, sys_exit_group, sys_fork, sys_kill, sys_pipe2,
    sys_prctl, sys_ptrace, sys_read, sys_rt_sigprocmask, sys_rt_sigtimedwait, sys_tgkill,
    sys_wait4, sys_write,
};

const PTRACE_SEIZE: i64 = 0x4206;
const PR_SET_CHILD_SUBREAPER: i32 = 36;
const SIGKILL: u32 = 9;
const SIGCHLD: u32 = 17;
const WNOHANG: i32 = 1;
const WALL: i32 = 0x4000_0000;
const ESRCH: i64 = -3;

pub fn run_tests() {
    test_zombie_reap();
    test_real_parent_notify();
    in_child(b"PTRACE_EXITKILL", exitkill);
    in_child(b"PTRACE_EXIT_IGNORED_ZOMBIE", exit_ignored_zombie);
}

/// PTRACE_EXITKILL: a middle process seizes its sleeping child with
/// PTRACE_O_EXITKILL and exits; the child, reparented to this
/// subreaper, is reaped killed by SIGKILL; 0, else the failed step
fn exitkill() -> i32 {
    const PTRACE_O_EXITKILL: u64 = 1 << 20;
    sys_prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
    let up = pipe();
    let h = sys_fork();
    if h == 0 {
        let c = sys_fork();
        if c == 0 {
            loop {
                sleep_ms(1000);
            }
        }
        let r = sys_ptrace(PTRACE_SEIZE, c, 0, PTRACE_O_EXITKILL);
        put(up[1], if r == 0 { c } else { -c });
        sys_exit_group(0);
    }
    let c = get(up[0]);
    let mut st = 0i32;
    sys_wait4(h, &mut st, 0, 0);
    close(&[up]);
    if c <= 0 {
        // -1: no word came; else the seize failed for child -c
        if c < -1 {
            kill_reap(-c);
        }
        return 1;
    }
    let (r, st) = reap_within(c, 0);
    if r != c {
        kill_reap(c);
        return 2;
    }
    if st != SIGKILL as i32 { 3 } else { 0 }
}

#[repr(C, align(16))]
struct Stack([u8; 16384]);
static mut STACK: Stack = Stack([0; 16384]);
static mut CTID: u32 = 0;

/// Start `f(arg)` as a thread of the calling process; its tid
fn start(f: extern "C" fn(u64) -> !, arg: u64) -> i64 {
    // SAFETY: the stack is this process's own copy, used by one thread
    let top = unsafe { (&raw mut STACK as *mut u8).add(16384) as u64 };
    // SAFETY: `f` only reads a pipe and exits
    unsafe { crate::mm::fork_mm::spawn_thread(top, f, arg, &raw mut CTID) }
}

/// Read a byte from `fd`, then exit the thread with 5
extern "C" fn read_exit5(fd: u64) -> ! {
    wait_go(fd as i32);
    sys_exit(5)
}

fn pipe() -> [i32; 2] {
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    p
}

fn close(fds: &[[i32; 2]]) {
    for p in fds {
        sys_close(p[0] as u64);
        sys_close(p[1] as u64);
    }
}

fn put(fd: i32, v: i64) {
    sys_write(fd as u64, (&v as *const i64).cast(), 8);
}

/// The next value on `fd`, -1 at EOF
fn get(fd: i32) -> i64 {
    let mut v = 0i64;
    if sys_read(fd as u64, (&mut v as *mut i64).cast(), 8) != 8 {
        return -1;
    }
    v
}

fn go(fd: i32) {
    sys_write(fd as u64, b"x".as_ptr(), 1);
}

fn wait_go(fd: i32) {
    let mut b = [0u8; 1];
    sys_read(fd as u64, b.as_mut_ptr(), 1);
}

fn block_chld() {
    let m: u64 = 1 << (SIGCHLD - 1);
    sys_rt_sigprocmask(0, &m as *const u64 as u64, 0, 8);
}

/// A SIGCHLD taken within `ms` (0: only one already pending); its si_pid
fn take_chld(ms: i64) -> Option<i64> {
    let m: u64 = 1 << (SIGCHLD - 1);
    let ts = [ms / 1000, (ms % 1000) * 1_000_000];
    let mut i = SigInfo::zeroed();
    let r = sys_rt_sigtimedwait(
        &m as *const u64 as u64,
        &mut i as *mut SigInfo as u64,
        ts.as_ptr() as u64,
        8,
    );
    (r == SIGCHLD as i64).then_some(i.si_pid as i64)
}

/// A SIGCHLD from `pid` within 5 s (others taken meanwhile are dropped)
fn chld_from(pid: i64) -> bool {
    for _ in 0..50 {
        if take_chld(100) == Some(pid) {
            return true;
        }
    }
    false
}

/// A SIGCHLD from `pid` is pending (every pending one is taken)
fn chld_pending(pid: i64) -> bool {
    let mut seen = false;
    while let Some(p) = take_chld(0) {
        seen |= p == pid;
    }
    seen
}

/// The state letter in /proc/<pid>/stat, or 0
fn stat_state(pid: i64) -> u8 {
    let path = crate::exec::exec_identity::proc_path(pid, b"stat\0");
    let mut b = [0u8; 128];
    let n = read_file(&path, &mut b);
    if n <= 0 {
        return 0;
    }
    let b = &b[..n as usize];
    match b.iter().rposition(|&c| c == b')') {
        Some(i) if i + 2 < b.len() => b[i + 2],
        _ => 0,
    }
}

/// `pid` is a zombie within 5 s
fn zombie(pid: i64) -> bool {
    for _ in 0..500 {
        if stat_state(pid) == b'Z' {
            return true;
        }
        sleep_ms(10);
    }
    false
}

/// wait4(`pid`, WNOHANG | `flags`) until it reaps, within 5 s: the
/// result and status
fn reap_within(pid: i64, flags: i32) -> (i64, i32) {
    let mut st = 0i32;
    let mut r = 0;
    for _ in 0..500 {
        r = sys_wait4(pid, &mut st, WNOHANG | flags, 0);
        if r != 0 {
            break;
        }
        sleep_ms(10);
    }
    (r, st)
}

/// A failed step's leftovers: `pid` killed, its threads reaped as far
/// as they go within a moment
fn kill_reap(pid: i64) {
    sys_kill(pid, SIGKILL);
    let mut st = 0i32;
    for _ in 0..100 {
        if sys_wait4(-1, &mut st, WNOHANG | WALL, 0) < 0 {
            break;
        }
        sleep_ms(10);
    }
}

/// fork, the child's exit sending no signal (exit signal 0: its parent
/// waits with __WALL); a parent's SIGCHLD then is another child's
fn quiet_fork() -> i64 {
    hk_syscall::sys_clone(0, 0, 0, 0, 0)
}

/// Run `f` in a child, SIGCHLD blocked; NAME:OK if it returns 0, else
/// NAME:FAIL with its failed step
fn in_child(name: &[u8], f: fn() -> i32) {
    let s = sys_fork();
    if s == 0 {
        block_chld();
        sys_exit_group(f() as u64);
    }
    let mut st = 0i32;
    sys_wait4(s, &mut st, 0, 0);
    verdict(name, st == 0, (st >> 8) as i64);
}

fn test_zombie_reap() {
    in_child(b"PTRACE_ZOMBIE_REAP", || {
        sys_prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
        match tracer_reaps() {
            0 => tracer_exits(),
            r => r,
        }
    });
}

/// The traced process: a thread that exits 5 once `a` is readable, its
/// tid sent on `up`; the leader exits 3 alone once `b` is
fn traced_child(a: [i32; 2], b: [i32; 2], up: [i32; 2]) -> ! {
    put(up[1], start(read_exit5, a[0] as u64));
    wait_go(b[0]);
    sys_exit(3)
}

/// This process traces its child's thread, which exits after the
/// leader; the leader waits for the tracer's reap of it
fn tracer_reaps() -> i32 {
    let (a, b, up) = (pipe(), pipe(), pipe());
    let c = sys_fork();
    if c == 0 {
        traced_child(a, b, up);
    }
    let t = get(up[0]);
    let r = if sys_ptrace(PTRACE_SEIZE, t, 0, 0) != 0 {
        1
    } else {
        reap_steps(c, t, a, b)
    };
    if r != 0 {
        kill_reap(c);
    }
    close(&[a, b, up]);
    r
}

fn reap_steps(c: i64, t: i64, a: [i32; 2], b: [i32; 2]) -> i32 {
    let mut st = 0i32;
    go(b[1]);
    if !zombie(c) {
        return 2;
    }
    // The thread's exit: a zombie for its tracer, which is told
    go(a[1]);
    if !chld_from(t) {
        return 3;
    }
    // Its leader waits for its release
    if sys_wait4(c, &mut st, WNOHANG, 0) != 0 {
        return 4;
    }
    if sys_wait4(t, &mut st, WNOHANG, 0) != t || st != 5 << 8 {
        return 5;
    }
    // The release tells the leader's parent, which reaps it
    if !chld_from(c) {
        return 6;
    }
    // The group's status: its last thread's (Linux
    // synchronize_group_exit)
    if sys_wait4(c, &mut st, WNOHANG, 0) != c || st != 5 << 8 {
        return 7;
    }
    0
}

/// A child of this subreaper traces its own child's thread, which
/// exits, then that child's leader; the tracer exits without waiting:
/// the thread is released, the leader (reparented here) reported
fn tracer_exits() -> i32 {
    let (a, b, up, ids) = (pipe(), pipe(), pipe(), pipe());
    let r = quiet_fork();
    if r == 0 {
        let c = sys_fork();
        if c == 0 {
            traced_child(a, b, up);
        }
        let t = get(up[0]);
        put(ids[1], c);
        put(ids[1], t);
        sys_exit_group(trace_and_leave(c, t, a, b) as u64);
    }
    let (c, t) = (get(ids[0]), get(ids[0]));
    close(&[a, b, up, ids]);
    let mut st = 0i32;
    sys_wait4(r, &mut st, WALL, 0);
    let res = if st != 0 {
        10 + (st >> 8)
    } else if !chld_from(c) {
        20
    } else if sys_wait4(c, &mut st, WNOHANG, 0) != c || st != 3 << 8 {
        21
    } else if sys_tgkill(c, t, 0) != ESRCH {
        22
    } else {
        0
    };
    if res != 0 {
        kill_reap(c);
    }
    res
}

/// Trace thread `t` of child `c`; let it exit, then the leader
fn trace_and_leave(c: i64, t: i64, a: [i32; 2], b: [i32; 2]) -> i32 {
    if sys_ptrace(PTRACE_SEIZE, t, 0, 0) != 0 {
        return 1;
    }
    go(a[1]);
    if !chld_from(t) {
        return 2;
    }
    go(b[1]);
    if !zombie(c) {
        return 3;
    }
    0
}

fn test_real_parent_notify() {
    in_child(b"PTRACE_REAL_PARENT_NOTIFY", || match hidden_until(false) {
        0 => hidden_until(true),
        r => r,
    });
}

/// A child traced by a sibling process is hidden from this, its real
/// parent, until the tracer reaps it (`exits`: exits without waiting)
fn hidden_until(exits: bool) -> i32 {
    let base = if exits { 20 } else { 0 };
    let (gc, cmd, up) = (pipe(), pipe(), pipe());
    let c = sys_fork();
    if c == 0 {
        wait_go(gc[0]);
        sys_exit_group(7);
    }
    let r = quiet_fork();
    if r == 0 {
        sys_exit_group(tracer(c, exits, cmd, up) as u64);
    }
    let res = hidden_steps(c, gc, cmd, up);
    let mut st = 0i32;
    if res != 0 {
        kill_reap(c);
        sys_kill(r, SIGKILL);
    }
    sys_wait4(r, &mut st, WALL, 0);
    close(&[gc, cmd, up]);
    match (res, st) {
        (0, 0) => 0,
        (0, st) => base + 10 + (st >> 8),
        (res, _) => base + res,
    }
}

fn hidden_steps(c: i64, gc: [i32; 2], cmd: [i32; 2], up: [i32; 2]) -> i32 {
    let mut st = 0i32;
    if get(up[0]) != 0 {
        return 1;
    }
    go(gc[1]);
    if !zombie(c) {
        return 2;
    }
    // The tracer's zombie: no notice here, and not reapable yet
    sleep_ms(20);
    if sys_wait4(c, &mut st, WNOHANG, 0) != 0 {
        return 3;
    }
    if chld_pending(c) {
        return 4;
    }
    go(cmd[1]);
    if !chld_from(c) {
        return 5;
    }
    if sys_wait4(c, &mut st, WNOHANG, 0) != c || st != 7 << 8 {
        return 6;
    }
    0
}

/// The tracer: seize `c` (the result sent on `up`), then on `cmd` reap
/// it, or exit at once if `exits`
fn tracer(c: i64, exits: bool, cmd: [i32; 2], up: [i32; 2]) -> i32 {
    let s = sys_ptrace(PTRACE_SEIZE, c, 0, 0);
    put(up[1], s);
    if s != 0 {
        return 1;
    }
    wait_go(cmd[0]);
    if exits {
        return 0;
    }
    match reap_within(c, 0) {
        (r, st) if r == c && st == 7 << 8 => 0,
        _ => 2,
    }
}

/// PTRACE_EXIT_IGNORED_ZOMBIE: a tracer that ignores SIGCHLD exits
/// leaving its own child, a traced zombie, unreaped. Linux
/// forget_original_parent runs exit_ptrace first, while the child's
/// real parent is still the tracer, so __ptrace_detach releases it
/// (ignoring_children); the subreaper above never sees it (ECHILD once
/// the tracer is reaped)
fn exit_ignored_zombie() -> i32 {
    use hk_syscall::{P_PID, WEXITED, sys_rt_sigaction, sys_waitid};
    const WNOWAIT: i32 = 0x0100_0000;
    const PTRACE_TRACEME: i64 = 0;
    const SIG_IGN: u64 = 1;
    const ECHILD: i64 = -10;
    sys_prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
    let tracer = sys_fork();
    if tracer == 0 {
        let ign: [u64; 4] = [SIG_IGN, 0, 0, 0];
        sys_rt_sigaction(SIGCHLD, ign.as_ptr() as u64, 0, 8);
        let child = sys_fork();
        if child == 0 {
            sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
            sys_exit(0);
        }
        // Its zombie, left in place (a tracee's exit is not autoreaped)
        // SAFETY: SigInfo is plain integers
        let mut info = SigInfo::zeroed();
        let r = sys_waitid(P_PID, child as u64, &mut info, WEXITED | WNOWAIT, 0);
        sys_exit(if r == 0 { 0 } else { 1 });
    }
    let mut st = 0i32;
    if sys_wait4(tracer, &mut st, 0, 0) != tracer || st != 0 {
        return 2;
    }
    match sys_wait4(-1, &mut st, 0, 0) {
        ECHILD => 0,
        _ => 3,
    }
}
