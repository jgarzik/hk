//! PID namespaces (Linux kernel/pid.c, kernel/pid_namespace.c,
//! kernel/signal.c, net/core/scm.c): a task sees every number in its
//! own namespace; one outside it is 0 in what the kernel reports and
//! ESRCH as an argument
//!
//! Each test runs in a forked process X (so the numbers outside are
//! not init's) that makes a child Y in a new namespace; Y is pid 1
//! there and its children 2, 3, ...
//! - PIDNS_GETPID_1: Y's getpid and gettid are 1;
//! - PIDNS_GETPPID_0: Y's parent is outside (getppid 0), its child's
//!   is 1;
//! - PIDNS_CHILD_NUMBERS: X sees Y by its outer number (clone return,
//!   CLONE_PARENT_SETTID, wait4); Y's children are 2 and 3, and
//!   CLONE_CHILD_SETTID writes the child's own number;
//! - PIDNS_SET_TID: clone3 set_tid names the number in each level,
//!   innermost first; a taken one is EEXIST, more levels than exist
//!   EINVAL;
//! - PIDNS_KILL: inside, kill and tgkill reach 1 and si_pid is the
//!   sender's inner number; X's number is ESRCH;
//! - PIDNS_SIGINFO: a signal from X reaches Y with si_pid 0; Y's
//!   SIGCHLD reaches X with Y's outer number;
//! - PIDNS_WAIT: wait4, waitid and SIGCHLD inside report inner numbers;
//! - PIDNS_PGRP: X's group and session are 0 inside; setsid, setpgid,
//!   getpgid, getsid use inner numbers;
//! - PIDNS_SCM: SO_PEERCRED of X's socket is pid 0 in Y; Y may claim
//!   its own inner pid in SCM_CREDENTIALS and X receives the outer
//!   one; X's credentials reach Y as pid 0;
//! - PIDNS_UNSHARE: after unshare(CLONE_NEWPID) the caller keeps its
//!   pid, its next child is 1 there with parent 0; a thread cannot be
//!   made in another namespace (EINVAL).

use crate::harness::report_step;
use crate::helpers::println;
use crate::mm::fork_mm::{join, spawn_thread};
use crate::net::sk::{SOL_SOCKET, cmsg_find, recv_msg, send, setint};
use crate::net::unix::send_cmsg;
use hk_syscall::{
    AF_UNIX, CLONE_CHILD_SETTID, CLONE_NEWPID, CLONE_PARENT_SETTID, CloneArgs, P_PID, SOCK_DGRAM,
    SigInfo, Timespec, WEXITED, sys_clone, sys_clone3, sys_exit, sys_fork, sys_getpgid, sys_getpid,
    sys_getppid, sys_getsid, sys_getsockopt, sys_gettid, sys_kill, sys_pipe2, sys_read,
    sys_rt_sigprocmask, sys_rt_sigtimedwait, sys_setpgid, sys_setsid, sys_socketpair, sys_tgkill,
    sys_unshare, sys_wait4, sys_waitid, sys_write,
};

const SIGCHLD: u64 = 17;
const SIGUSR1: u32 = 10;
const SIG_BLOCK: i32 = 0;
const ESRCH: i64 = -3;
const ECHILD: i64 = -10;
const EEXIST: i64 = -17;
const EINVAL: i64 = -22;
const SO_PASSCRED: i32 = 16;
const SO_PEERCRED: i32 = 17;
const SCM_CREDENTIALS: i32 = 2;

pub fn run_tests() {
    println(b"[PIDNS TESTS]");
    outer(b"PIDNS_GETPID_1", getpid_1);
    outer(b"PIDNS_GETPPID_0", getppid_0);
    outer(b"PIDNS_CHILD_NUMBERS", child_numbers);
    outer(b"PIDNS_SET_TID", set_tid);
    outer(b"PIDNS_KILL", kill);
    outer(b"PIDNS_SIGINFO", siginfo);
    outer(b"PIDNS_WAIT", wait);
    outer(b"PIDNS_PGRP", pgrp);
    outer(b"PIDNS_SCM", scm);
    outer(b"PIDNS_UNSHARE", unshare);
    super::pidns_init::run_tests();
}

/// Run `f` in a forked process X: its exit status is the failing step
pub(super) fn outer(name: &[u8], f: fn() -> i32) {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(f() as u64);
    }
    report_step(name, status(pid));
}

/// Reap `pid`: its exit code, 100 + a killing signal, 200 if the wait
/// fails
pub(super) fn status(pid: i64) -> i64 {
    let mut st = 0;
    if pid <= 0 || sys_wait4(pid, &mut st, 0, 0) != pid {
        return 200;
    }
    if st & 0x7f != 0 {
        100 + i64::from(st & 0x7f)
    } else {
        i64::from((st >> 8) & 0xff)
    }
}

/// A child Y in a new pid namespace running `f`; its pid as the caller
/// sees it
pub(super) fn ns_child(f: fn() -> i32) -> i64 {
    let pid = sys_clone(CLONE_NEWPID | SIGCHLD, 0, 0, 0, 0);
    if pid == 0 {
        sys_exit(f() as u64);
    }
    pid
}

/// A forked child running `f`
pub(super) fn child(f: fn() -> i32) -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(f() as u64);
    }
    pid
}

/// Block `sig` (one bit)
fn block(sig: u32) {
    let set: u64 = 1 << (sig - 1);
    sys_rt_sigprocmask(SIG_BLOCK, &set as *const u64 as u64, 0, 8);
}

/// Take blocked `sig` within 5 s: (return, info)
fn take(sig: u32) -> (i64, SigInfo) {
    let set: u64 = 1 << (sig - 1);
    // SAFETY: SigInfo is plain integers
    let mut info: SigInfo = unsafe { core::mem::zeroed() };
    let ts = Timespec {
        tv_sec: 5,
        tv_nsec: 0,
    };
    let r = sys_rt_sigtimedwait(
        &set as *const u64 as u64,
        &mut info as *mut SigInfo as u64,
        &ts as *const Timespec as u64,
        8,
    );
    (r, info)
}

/// The first of `steps` that fails (its 1-based index), 0 if none
pub(super) fn first_fail(steps: &[bool]) -> i32 {
    steps.iter().position(|ok| !ok).map_or(0, |i| i as i32 + 1)
}

fn getpid_1() -> i32 {
    status(ns_child(|| {
        first_fail(&[sys_getpid() == 1, sys_gettid() == 1])
    })) as i32
}

fn getppid_0() -> i32 {
    status(ns_child(|| {
        if sys_getppid() != 0 {
            return 1;
        }
        let c = child(|| i32::from(sys_getppid() != 1));
        if status(c) != 0 { 2 } else { 0 }
    })) as i32
}

fn child_numbers() -> i32 {
    let me = sys_getpid();
    let mut ptid: i32 = 0;
    let mut ctid: i32 = 0;
    let flags = CLONE_NEWPID | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | SIGCHLD;
    let p = sys_clone(flags, 0, &raw mut ptid as u64, &raw mut ctid as u64, 0);
    if p == 0 {
        // SAFETY: a local, written by the kernel at the child's start
        let own = unsafe { core::ptr::read_volatile(&raw const ctid) };
        let g = child(|| i32::from(sys_getpid() != 2 || sys_getppid() != 1));
        let gs = status(g);
        let mut c2: i32 = 0;
        let g2 = sys_clone(CLONE_CHILD_SETTID | SIGCHLD, 0, 0, &raw mut c2 as u64, 0);
        if g2 == 0 {
            // SAFETY: as above
            sys_exit(u64::from(
                unsafe { core::ptr::read_volatile(&raw const c2) } != 3,
            ));
        }
        let ok = [own == 1, g == 2, gs == 0, g2 == 3, status(g2) == 0];
        sys_exit(first_fail(&ok) as u64);
    }
    if p <= 1 || p == me {
        return 20;
    }
    // SAFETY: written by the kernel before clone returned
    if unsafe { core::ptr::read_volatile(&raw const ptid) } as i64 != p {
        return 21;
    }
    status(p) as i32
}

fn set_tid() -> i32 {
    let mut tids: [i32; 3] = [1, 0, 0];
    let mut args = CloneArgs {
        flags: CLONE_NEWPID,
        exit_signal: SIGCHLD,
        set_tid: tids.as_ptr() as u64,
        set_tid_size: 2,
        ..CloneArgs::default()
    };
    let size = core::mem::size_of::<CloneArgs>();
    // An outer number nothing holds (skip ones in use)
    let mut p = EEXIST;
    let mut n = 23000 + (sys_getpid() as i32 % 1000);
    while p == EEXIST && n < 30000 {
        n += 7;
        tids[1] = n;
        p = sys_clone3(&args, size);
        if p == 0 {
            sys_exit(u64::from(sys_getpid() != 1));
        }
    }
    let again = sys_clone3(&args, size);
    if again == 0 {
        sys_exit(0);
    }
    args.set_tid_size = 3;
    let deep = sys_clone3(&args, size);
    if deep == 0 {
        sys_exit(0);
    }
    args.set_tid_size = 1;
    args.set_tid = 0;
    let null = sys_clone3(&args, size);
    if null == 0 {
        sys_exit(0);
    }
    let ok = [
        p == i64::from(n),
        again == EEXIST,
        deep == EINVAL,
        null == EINVAL,
        status(p) == 0,
    ];
    first_fail(&ok)
}

/// X's pid, for its children to name
static mut OUTER: i64 = 0;

fn outer_pid() -> i64 {
    // SAFETY: written once by X before its children exist
    unsafe { core::ptr::read_volatile(&raw const OUTER) }
}

fn set_outer() {
    // SAFETY: X alone, before any child
    unsafe { core::ptr::write_volatile(&raw mut OUTER, sys_getpid()) };
}

fn kill() -> i32 {
    set_outer();
    status(ns_child(|| {
        block(SIGUSR1);
        let c = child(|| {
            let ok = [
                sys_kill(1, SIGUSR1) == 0,
                sys_kill(outer_pid(), 0) == ESRCH,
                sys_tgkill(1, 1, 0) == 0,
                sys_tgkill(outer_pid(), outer_pid(), 0) == ESRCH,
            ];
            first_fail(&ok)
        });
        let (r, info) = take(SIGUSR1);
        let ok = [
            c == 2,
            r == i64::from(SIGUSR1),
            info.si_pid == 2,
            info.si_code == 0,
            status(c) == 0,
        ];
        first_fail(&ok)
    })) as i32
}

/// X's pipe, for Y
static mut PIPE: [i32; 2] = [-1, -1];

fn pipe_fd(i: usize) -> u64 {
    // SAFETY: written by X before its child exists
    unsafe { core::ptr::read_volatile(&raw const PIPE)[i] as u64 }
}

fn siginfo() -> i32 {
    if sys_pipe2((&raw mut PIPE).cast::<i32>(), 0) != 0 {
        return 20;
    }
    block(SIGCHLD as u32);
    let y = ns_child(|| {
        block(SIGUSR1);
        sys_write(pipe_fd(1), b"r".as_ptr(), 1);
        let (r, info) = take(SIGUSR1);
        first_fail(&[r == i64::from(SIGUSR1), info.si_pid == 0, info.si_code == 0])
    });
    let mut b = [0u8; 1];
    if y <= 0 || sys_read(pipe_fd(0), b.as_mut_ptr(), 1) != 1 {
        return 21;
    }
    if sys_kill(y, SIGUSR1) != 0 {
        return 22;
    }
    let (r, info) = take(SIGCHLD as u32);
    if r != SIGCHLD as i64 || i64::from(info.si_pid) != y {
        return 23;
    }
    status(y) as i32
}

fn wait() -> i32 {
    set_outer();
    status(ns_child(|| {
        block(SIGCHLD as u32);
        let c = child(|| 7);
        let (r, info) = take(SIGCHLD as u32);
        let mut st = 0;
        let w = sys_wait4(-1, &mut st, 0, 0);
        let c2 = child(|| 0);
        // SAFETY: SigInfo is plain integers
        let mut wi: SigInfo = unsafe { core::mem::zeroed() };
        let wr = sys_waitid(P_PID, c2 as u64, &mut wi, WEXITED, 0);
        let c3 = child(|| 0);
        let w3 = sys_wait4(c3, core::ptr::null_mut(), 0, 0);
        let ok = [
            c == 2,
            r == SIGCHLD as i64 && info.si_pid == 2 && info.si_status == 7,
            w == 2 && (st >> 8) & 0xff == 7,
            c2 == 3 && wr == 0 && wi.si_pid == 3,
            c3 == 4 && w3 == 4,
            sys_wait4(outer_pid(), core::ptr::null_mut(), 0, 0) == ECHILD,
        ];
        first_fail(&ok)
    })) as i32
}

fn pgrp() -> i32 {
    set_outer();
    if sys_pipe2((&raw mut PIPE).cast::<i32>(), 0) != 0 {
        return 20;
    }
    status(ns_child(|| {
        let before = [sys_getpgid(0) == 0, sys_getsid(0) == 0];
        let s = sys_setsid();
        let c = child(|| {
            let mut b = [0u8; 1];
            sys_read(pipe_fd(0), b.as_mut_ptr(), 1);
            0
        });
        let ok = [
            before[0],
            before[1],
            s == 1,
            sys_getpgid(0) == 1 && sys_getsid(0) == 1,
            c == 2 && sys_setpgid(2, 2) == 0,
            sys_getpgid(2) == 2 && sys_getsid(2) == 1,
            sys_setpgid(2, 1) == 0 && sys_getpgid(2) == 1,
            sys_getpgid(outer_pid() as u64) == ESRCH,
            sys_getsid(outer_pid() as u64) == ESRCH,
        ];
        sys_write(pipe_fd(1), b"g".as_ptr(), 1);
        let r = first_fail(&ok);
        if status(c) != 0 && r == 0 { 20 } else { r }
    })) as i32
}

/// The pid of the struct ucred in `ctl[..len]`'s SCM_CREDENTIALS
fn cred_pid(ctl: &[u8], len: usize) -> Option<i32> {
    let d = cmsg_find(ctl, len, SOL_SOCKET, SCM_CREDENTIALS)?;
    Some(i32::from_ne_bytes(d.get(..4)?.try_into().ok()?))
}

/// The pid SO_PEERCRED reports for `fd`
fn peer_pid(fd: i32) -> i64 {
    let mut b = [0u8; 12];
    let mut len = 12u32;
    let r = sys_getsockopt(fd, SOL_SOCKET, SO_PEERCRED, b.as_mut_ptr(), &mut len);
    if r != 0 {
        return r;
    }
    i64::from(i32::from_ne_bytes(b[..4].try_into().unwrap()))
}

/// X's socket pair: X uses [0], Y [1]
static mut PAIR: [i32; 2] = [-1, -1];

fn pair_fd(i: usize) -> i32 {
    // SAFETY: written by X before its child exists
    unsafe { core::ptr::read_volatile(&raw const PAIR)[i] }
}

fn scm() -> i32 {
    let me = sys_getpid();
    // SAFETY: X alone, before any child
    if sys_socketpair(AF_UNIX, SOCK_DGRAM, 0, unsafe { &mut *(&raw mut PAIR) }) != 0 {
        return 20;
    }
    setint(pair_fd(0), SOL_SOCKET, SO_PASSCRED, 1);
    setint(pair_fd(1), SOL_SOCKET, SO_PASSCRED, 1);
    let y = ns_child(|| {
        let b = pair_fd(1);
        let peer = peer_pid(b);
        let mut cr = [0u8; 12];
        cr[..4].copy_from_slice(&1i32.to_ne_bytes());
        let sent = send_cmsg(b, b"y", SOL_SOCKET, SCM_CREDENTIALS, &cr, 0);
        let mut buf = [0u8; 4];
        let mut ctl = [0u8; 64];
        let (r, _, clen) = recv_msg(b, &mut buf, &mut ctl, 0);
        first_fail(&[
            peer == 0,
            sent == 1,
            r == 1 && cred_pid(&ctl, clen) == Some(0),
        ])
    });
    let a = pair_fd(0);
    let mut buf = [0u8; 4];
    let mut ctl = [0u8; 64];
    let (r, _, clen) = recv_msg(a, &mut buf, &mut ctl, 0);
    let got = cred_pid(&ctl, clen).map_or(-1, i64::from);
    send(a, b"x", 0);
    let ok = [peer_pid(a) == me, r == 1 && got == y];
    match first_fail(&ok) {
        0 => status(y) as i32,
        f => {
            status(y);
            20 + f
        }
    }
}

/// A stack for the thread [`unshare`] must not get, and its
/// CLONE_CHILD_CLEARTID word
static mut STACK: [u64; 512] = [0; 512];
static mut CTID: u32 = 0;

fn stack_top() -> u64 {
    (&raw mut STACK) as u64 + 512 * 8
}

extern "C" fn quit(_: u64) -> ! {
    sys_exit(0)
}

fn unshare() -> i32 {
    let me = sys_getpid();
    if sys_unshare(CLONE_NEWPID) != 0 {
        return 1;
    }
    if sys_getpid() != me {
        return 2;
    }
    let ctid = &raw mut CTID;
    // SAFETY: the thread runs `quit` on a stack of its own; `ctid` is
    // a static it clears at exit
    let thread = unsafe {
        core::ptr::write_volatile(ctid, 1);
        spawn_thread(stack_top(), quit, 0, ctid)
    };
    if thread != EINVAL {
        // Gone before this thread decides the process's status
        if thread > 0 {
            join(ctid);
        }
        return 3;
    }
    let c = child(|| first_fail(&[sys_getpid() == 1, sys_getppid() == 0]));
    if c <= 1 || c == me {
        return 4;
    }
    match status(c) {
        0 => 0,
        s => 10 + s as i32,
    }
}
