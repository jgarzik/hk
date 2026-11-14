//! Job control: group stop and continue (run on hk and real Linux)
//!
//! - JOBCTL_STOP_CONT: SIGSTOP to a three-thread process stops every
//!   thread ('T' in /proc); wait4(WUNTRACED) reports (SIGSTOP << 8) |
//!   0x7f once; the parent gets SIGCHLD with CLD_STOPPED, si_status
//!   SIGSTOP. SIGCONT continues every thread; wait4(WCONTINUED) reports
//!   0xffff once; SIGCHLD with CLD_CONTINUED, si_status SIGCONT
//! - JOBCTL_WAITID: waitid(WSTOPPED) gives CLD_STOPPED with the stop
//!   signal and the child's uid, kept by WNOWAIT, consumed otherwise;
//!   waitid(WCONTINUED) gives CLD_CONTINUED; no WEXITED, WSTOPPED or
//!   WCONTINUED is EINVAL
//! - JOBCTL_ORPHAN_TSTP: SIGTSTP does nothing to a process in an
//!   orphaned process group, and stops one whose group has a parent in
//!   another group of its session
//! - JOBCTL_PTRACE_STOP: a tracee resumed with SIGSTOP from its
//!   signal-delivery stop enters a group-stop trap: reported as
//!   SIGSTOP, with no siginfo (PTRACE_GETSIGINFO EINVAL) unless seized,
//!   where it is PTRACE_EVENT_STOP (status (SIGSTOP | 0x80 << 8) << 8 |
//!   0x7f, si_code SIGSTOP | PTRACE_EVENT_STOP << 8)
//! - JOBCTL_ATTACH_EXIT: a tracer that exits without waiting for the
//!   stop of PTRACE_ATTACH's SIGSTOP leaves the tracee group-stopped
//!   (Linux __ptrace_unlink keeps exit_code), which its parent's
//!   wait4(WUNTRACED) reports
//! - JOBCTL_PTRACE_IGNORED: a signal ignored by default (SIGWINCH,
//!   SIGCHLD) still reaches a tracee's signal-delivery stop (Linux
//!   sig_ignored: only SIGKILL is ignored for a traced task)
//! - JOBCTL_RUSAGE: wait4(WUNTRACED), wait4(WCONTINUED) and
//!   waitid(WSTOPPED) fill the rusage argument with the child's CPU time
//!   (Linux wait_task_stopped / wait_task_continued: getrusage(p,
//!   RUSAGE_BOTH))

use crate::harness::verdict;
use crate::helpers::sleep_ms;
use crate::signal::ptrace_exit::stat_state;
use hk_syscall::{
    P_PID, SigInfo, Zeroable, sys_close, sys_exit, sys_exit_group, sys_fork, sys_kill, sys_pipe2,
    sys_ptrace, sys_read, sys_rt_sigprocmask, sys_rt_sigtimedwait, sys_setpgid, sys_setsid,
    sys_wait4, sys_waitid, sys_write,
};

const SIGKILL: u32 = 9;
const SIGCHLD: u32 = 17;
const SIGCONT: u32 = 18;
const SIGSTOP: u32 = 19;
const SIGTSTP: u32 = 20;
const WNOHANG: i32 = 1;
const WUNTRACED: i32 = 2;
const WCONTINUED: i32 = 8;
const WNOWAIT: i32 = 0x0100_0000;
const CLD_STOPPED: i32 = 5;
const CLD_CONTINUED: i32 = 6;
const STOPPED_SIGSTOP: i32 = ((SIGSTOP as i32) << 8) | 0x7f;

pub fn run_tests() {
    in_child(b"JOBCTL_STOP_CONT", stop_cont);
    in_child(b"JOBCTL_WAITID", waitid_steps);
    in_child(b"JOBCTL_ORPHAN_TSTP", orphan_tstp);
    in_child(b"JOBCTL_PTRACE_STOP", || match ptrace_gstop(false) {
        0 => ptrace_gstop(true),
        r => r,
    });
    in_child(b"JOBCTL_ATTACH_EXIT", attach_exit);
    in_child(b"JOBCTL_PTRACE_IGNORED", ptrace_ignored);
    in_child(b"JOBCTL_RUSAGE", rusage);
}

/// Run `f` in a child with SIGCHLD blocked; NAME:OK if it returns 0,
/// else NAME:FAIL with its failed step
pub(crate) fn in_child(name: &[u8], f: fn() -> i32) {
    let s = sys_fork();
    if s == 0 {
        let m: u64 = 1 << (SIGCHLD - 1);
        sys_rt_sigprocmask(0, &m as *const u64 as u64, 0, 8);
        sys_exit_group(f() as u64);
    }
    let mut st = 0i32;
    sys_wait4(s, &mut st, 0, 0);
    verdict(name, st == 0, (st >> 8) as i64);
}

#[repr(C, align(16))]
struct Stack([u8; 16384]);
static mut STACKS: [Stack; 2] = [const { Stack([0; 16384]) }; 2];
static mut CTIDS: [u32; 2] = [0; 2];

/// Sleep in a loop forever (a thread)
extern "C" fn idle(_: u64) -> ! {
    loop {
        sleep_ms(5);
    }
}

fn pipe() -> [i32; 2] {
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    p
}

/// A child of three threads that idle; its thread ids
fn spawn_three() -> (i64, [i64; 3]) {
    let p = pipe();
    let c = sys_fork();
    if c == 0 {
        let mut tids = [0i64; 2];
        for (i, t) in tids.iter_mut().enumerate() {
            // SAFETY: this process's own stacks, one per thread
            *t = unsafe {
                let top = (&raw mut STACKS[i] as *mut u8).add(16384) as u64;
                crate::mm::fork_mm::spawn_thread(top, idle, 0, &raw mut CTIDS[i])
            };
        }
        sys_write(p[1] as u64, tids.as_ptr().cast(), 16);
        loop {
            sleep_ms(5);
        }
    }
    let mut tids = [0i64; 2];
    sys_read(p[0] as u64, tids.as_mut_ptr().cast(), 16);
    sys_close(p[0] as u64);
    sys_close(p[1] as u64);
    (c, [c, tids[0], tids[1]])
}

/// The state letter of thread `tid` of `pid`, or 0
fn thread_state(pid: i64, tid: i64) -> u8 {
    if pid == tid {
        return stat_state(pid);
    }
    let mut path = [0u8; 64];
    let mut n = 0;
    for part in [&b"/proc/"[..]] {
        path[n..n + part.len()].copy_from_slice(part);
        n += part.len();
    }
    n += put_num(&mut path[n..], pid);
    path[n..n + 6].copy_from_slice(b"/task/");
    n += 6;
    n += put_num(&mut path[n..], tid);
    path[n..n + 6].copy_from_slice(b"/stat\0");
    let mut b = [0u8; 128];
    let r = crate::helpers::read_file(&path, &mut b);
    if r <= 0 {
        return 0;
    }
    let b = &b[..r as usize];
    match b.iter().rposition(|&c| c == b')') {
        Some(i) if i + 2 < b.len() => b[i + 2],
        _ => 0,
    }
}

/// Decimal `v` into `out`; its length
fn put_num(out: &mut [u8], v: i64) -> usize {
    let mut d = [0u8; 20];
    let (mut n, mut v) = (0, v as u64);
    loop {
        d[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..n {
        out[i] = d[n - 1 - i];
    }
    n
}

/// Every thread of `pid` is ('T') or is not stopped, within 5 s
fn all_threads(pid: i64, tids: &[i64], stopped: bool) -> bool {
    for _ in 0..500 {
        if tids
            .iter()
            .all(|&t| (thread_state(pid, t) == b'T') == stopped)
        {
            return true;
        }
        sleep_ms(10);
    }
    false
}

/// A SIGCHLD within 5 s: (si_code, si_status, si_pid)
fn take_chld() -> Option<(i32, i32, i64)> {
    let m: u64 = 1 << (SIGCHLD - 1);
    let ts = [5i64, 0];
    let mut i = SigInfo::zeroed();
    let r = sys_rt_sigtimedwait(
        &m as *const u64 as u64,
        &mut i as *mut SigInfo as u64,
        ts.as_ptr() as u64,
        8,
    );
    (r == SIGCHLD as i64).then_some((i.si_code, i.si_status, i.si_pid as i64))
}

/// wait4(`pid`, `flags`) within 5 s, so a stop or continue that never
/// comes fails instead of hanging: its result (0: none yet)
pub(crate) fn wait_within(pid: i64, st: &mut i32, flags: i32) -> i64 {
    for _ in 0..500 {
        let r = sys_wait4(pid, st, flags | WNOHANG, 0);
        if r != 0 {
            return r;
        }
        sleep_ms(10);
    }
    0
}

pub(crate) fn kill_reap(pid: i64) {
    sys_kill(pid, SIGKILL);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
}

fn stop_cont() -> i32 {
    let (c, tids) = spawn_three();
    let r = stop_cont_steps(c, &tids);
    kill_reap(c);
    r
}

fn stop_cont_steps(c: i64, tids: &[i64; 3]) -> i32 {
    let mut st = 0i32;
    sys_kill(c, SIGSTOP);
    if wait_within(c, &mut st, WUNTRACED) != c || st != STOPPED_SIGSTOP {
        return 1;
    }
    if take_chld() != Some((CLD_STOPPED, SIGSTOP as i32, c)) {
        return 2;
    }
    if !all_threads(c, tids, true) {
        return 3;
    }
    // Reported once
    if sys_wait4(c, &mut st, WUNTRACED | WNOHANG, 0) != 0 {
        return 4;
    }
    sys_kill(c, SIGCONT);
    if wait_within(c, &mut st, WCONTINUED) != c || st != 0xffff {
        return 5;
    }
    if take_chld() != Some((CLD_CONTINUED, SIGCONT as i32, c)) {
        return 6;
    }
    if !all_threads(c, tids, false) {
        return 7;
    }
    if sys_wait4(c, &mut st, WCONTINUED | WUNTRACED | WNOHANG, 0) != 0 {
        return 8;
    }
    0
}

fn waitid_steps() -> i32 {
    let (c, tids) = spawn_three();
    let r = waitid_body(c, &tids);
    kill_reap(c);
    r
}

/// waitid(P_PID, `c`, `options`): (result, si_code, si_status, si_pid,
/// si_uid)
fn waitid(c: i64, options: i32) -> (i64, i32, i32, i64, u32) {
    let mut i = SigInfo::zeroed();
    let r = sys_waitid(P_PID, c as u64, &mut i, options, 0);
    (r, i.si_code, i.si_status, i.si_pid as i64, i.si_uid)
}

fn waitid_body(c: i64, tids: &[i64; 3]) -> i32 {
    const WSTOPPED: i32 = 2;
    const EINVAL: i64 = -22;
    if waitid(c, WNOHANG).0 != EINVAL {
        return 1;
    }
    sys_kill(c, SIGSTOP);
    if !all_threads(c, tids, true) {
        return 2;
    }
    let want = (0, CLD_STOPPED, SIGSTOP as i32, c, 0);
    if waitid(c, WSTOPPED | WNOWAIT) != want || waitid(c, WSTOPPED | WNOWAIT) != want {
        return 3;
    }
    if waitid(c, WSTOPPED) != want {
        return 4;
    }
    // Consumed: WNOHANG finds nothing (si_pid 0)
    if waitid(c, WSTOPPED | WNOHANG) != (0, 0, 0, 0, 0) {
        return 5;
    }
    sys_kill(c, SIGCONT);
    if waitid(c, WCONTINUED) != (0, CLD_CONTINUED, SIGCONT as i32, c, 0) {
        return 6;
    }
    0
}

/// struct rusage: the two times (struct timeval), then 14 longs
#[repr(C)]
struct Rusage {
    times: [i64; 4],
    rest: [i64; 14],
}

impl Rusage {
    /// Every field -1, as no kernel writes it
    fn poisoned() -> Self {
        Self {
            times: [-1; 4],
            rest: [-1; 14],
        }
    }

    /// user + system time in ms, None if any field was left unwritten
    fn cpu_ms(&self) -> Option<i64> {
        let t = &self.times;
        if t.iter().chain(self.rest.iter()).any(|&v| v < 0) {
            return None;
        }
        Some((t[0] + t[2]) * 1000 + (t[1] + t[3]) / 1000)
    }
}

/// The calling process's CPU time in ms
fn process_cpu_ms() -> i64 {
    let mut ts = hk_syscall::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // CLOCK_PROCESS_CPUTIME_ID
    hk_syscall::sys_clock_gettime(2, &mut ts);
    ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000
}

/// The CPU a child burns before it stops itself
const BURN_MS: i64 = 100;

fn rusage() -> i32 {
    let c = sys_fork();
    if c == 0 {
        while process_cpu_ms() < BURN_MS {
            core::hint::spin_loop();
        }
        sys_kill(hk_syscall::sys_getpid(), SIGSTOP);
        loop {
            sleep_ms(5);
        }
    }
    let r = rusage_steps(c);
    kill_reap(c);
    r
}

/// Each report's rusage has every field written and at least the CPU
/// time the child burned before stopping
fn rusage_steps(c: i64) -> i32 {
    const WSTOPPED: i32 = 2;
    let burned = |ru: &Rusage| ru.cpu_ms().is_some_and(|ms| ms >= BURN_MS * 8 / 10);
    let mut st = 0i32;
    let mut ru = Rusage::poisoned();
    let mut got = 0;
    for _ in 0..500 {
        got = sys_wait4(c, &mut st, WUNTRACED | WNOHANG, &raw mut ru as u64);
        if got != 0 {
            break;
        }
        sleep_ms(10);
    }
    if got != c || st != STOPPED_SIGSTOP {
        return 1;
    }
    if !burned(&ru) {
        return 2;
    }
    sys_kill(c, SIGCONT);
    let mut ru = Rusage::poisoned();
    for _ in 0..500 {
        got = sys_wait4(c, &mut st, WCONTINUED | WNOHANG, &raw mut ru as u64);
        if got != 0 {
            break;
        }
        sleep_ms(10);
    }
    if got != c || st != 0xffff {
        return 3;
    }
    if !burned(&ru) {
        return 4;
    }
    sys_kill(c, SIGSTOP);
    let mut ru = Rusage::poisoned();
    let mut i = SigInfo::zeroed();
    if sys_waitid(P_PID, c as u64, &mut i, WSTOPPED, &raw mut ru as u64) != 0
        || i.si_code != CLD_STOPPED
    {
        return 5;
    }
    if !burned(&ru) {
        return 6;
    }
    0
}

/// SIGTSTP to a child of a new session's leader: ignored while the
/// child shares the leader's (orphaned) group; a stop once it has a
/// group of its own
fn orphan_tstp() -> i32 {
    sys_setsid();
    let mut st = 0i32;
    let (c, tids) = spawn_three();
    sys_kill(c, SIGTSTP);
    sleep_ms(100);
    let ignored = sys_wait4(c, &mut st, WUNTRACED | WNOHANG, 0) == 0
        && tids.iter().all(|&t| thread_state(c, t) != b'T');
    kill_reap(c);
    if !ignored {
        return 1;
    }
    let p = pipe();
    let c = sys_fork();
    if c == 0 {
        sys_setpgid(0, 0);
        sys_write(p[1] as u64, b"x".as_ptr(), 1);
        loop {
            sleep_ms(5);
        }
    }
    let mut b = [0u8; 1];
    sys_read(p[0] as u64, b.as_mut_ptr(), 1);
    sys_kill(c, SIGTSTP);
    let r = wait_within(c, &mut st, WUNTRACED);
    kill_reap(c);
    if r != c || st != ((SIGTSTP as i32) << 8) | 0x7f {
        return 2;
    }
    0
}

/// A traced child resumed with SIGSTOP from its SIGSTOP's
/// signal-delivery stop traps for the group stop (`seize`: seized, as
/// PTRACE_EVENT_STOP), then runs on when continued
fn ptrace_gstop(seize: bool) -> i32 {
    const PTRACE_TRACEME: i64 = 0;
    const PTRACE_CONT: i64 = 7;
    const PTRACE_GETSIGINFO: i64 = 0x4202;
    const PTRACE_SEIZE: i64 = 0x4206;
    const EVENT_STOP: i32 = 128;
    const EINVAL: i64 = -22;
    let base = if seize { 10 } else { 0 };
    let c = sys_fork();
    if c == 0 {
        if !seize {
            sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
            sys_kill(hk_syscall::sys_getpid(), SIGSTOP);
            sys_exit(5);
        }
        loop {
            sleep_ms(5);
        }
    }
    if seize && sys_ptrace(PTRACE_SEIZE, c, 0, 0) != 0 {
        kill_reap(c);
        return base + 1;
    }
    if seize {
        sys_kill(c, SIGSTOP);
    }
    let mut st = 0i32;
    let step = |n: i32| {
        kill_reap(c);
        base + n
    };
    if wait_within(c, &mut st, 0) != c || st != STOPPED_SIGSTOP {
        return step(2);
    }
    let mut si = [0u64; 16];
    if sys_ptrace(PTRACE_GETSIGINFO, c, 0, si.as_mut_ptr() as u64) != 0 {
        return step(3);
    }
    sys_ptrace(PTRACE_CONT, c, 0, SIGSTOP as u64);
    let want = if seize {
        ((SIGSTOP as i32 | (EVENT_STOP << 8)) << 8) | 0x7f
    } else {
        STOPPED_SIGSTOP
    };
    if wait_within(c, &mut st, 0) != c || st != want {
        return step(4);
    }
    let r = sys_ptrace(PTRACE_GETSIGINFO, c, 0, si.as_mut_ptr() as u64);
    if seize {
        let code = si[1] as i32;
        if r != 0 || si[0] as i32 != SIGSTOP as i32 || code != SIGSTOP as i32 | (EVENT_STOP << 8) {
            return step(5);
        }
        kill_reap(c);
        return 0;
    }
    if r != EINVAL {
        return step(6);
    }
    sys_ptrace(PTRACE_CONT, c, 0, 0);
    if wait_within(c, &mut st, 0) != c || st != 5 << 8 {
        return base + 7;
    }
    0
}

/// A sibling attaches to an idle child (PTRACE_ATTACH's SIGSTOP), sees
/// it stop for that SIGSTOP and exits without waiting: the child,
/// untraced, takes the SIGSTOP and stops for its group
fn attach_exit() -> i32 {
    const PTRACE_ATTACH: i64 = 16;
    let (c, tids) = spawn_three();
    let t = hk_syscall::sys_clone(0, 0, 0, 0, 0);
    if t == 0 {
        if sys_ptrace(PTRACE_ATTACH, c, 0, 0) != 0 {
            sys_exit_group(1);
        }
        for _ in 0..500 {
            if stat_state(c) == b't' {
                sys_exit_group(0);
            }
            sleep_ms(10);
        }
        sys_exit_group(2);
    }
    let mut st = 0i32;
    sys_wait4(t, &mut st, 0x4000_0000, 0);
    let r = if st != 0 {
        10 + (st >> 8)
    } else if wait_within(c, &mut st, WUNTRACED) != c || st != STOPPED_SIGSTOP {
        3
    } else if !all_threads(c, &tids, true) {
        4
    } else {
        0
    };
    kill_reap(c);
    r
}

/// A seized child stops for its tracer on SIGWINCH and SIGCHLD, both
/// ignored by default, then runs on when continued
fn ptrace_ignored() -> i32 {
    const PTRACE_SEIZE: i64 = 0x4206;
    const SIGWINCH: u32 = 28;
    let c = sys_fork();
    if c == 0 {
        let none = 0u64;
        sys_rt_sigprocmask(2, &none as *const u64 as u64, 0, 8);
        loop {
            sleep_ms(5);
        }
    }
    let r = if sys_ptrace(PTRACE_SEIZE, c, 0, 0) != 0 {
        1
    } else {
        ptrace_ignored_steps(c, &[SIGWINCH, SIGCHLD])
    };
    kill_reap(c);
    r
}

fn ptrace_ignored_steps(c: i64, sigs: &[u32]) -> i32 {
    const PTRACE_CONT: i64 = 7;
    let mut st = 0i32;
    for (i, &sig) in sigs.iter().enumerate() {
        sys_kill(c, sig);
        if wait_within(c, &mut st, 0) != c || st != ((sig as i32) << 8) | 0x7f {
            return 2 + i as i32;
        }
        sys_ptrace(PTRACE_CONT, c, 0, 0);
    }
    0
}
