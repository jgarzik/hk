//! A pid namespace's init (Linux kernel/exit.c find_child_reaper,
//! kernel/pid_namespace.c zap_pid_ns_processes, kernel/signal.c
//! SIGNAL_UNKILLABLE, kernel/pid.c alloc_pid)
//!
//! As in `pidns`, each test runs in a forked process X whose child Y
//! is pid 1 of a new namespace.
//! - PIDNS_REAPER: an orphan inside is adopted by Y (getppid 1), which
//!   reaps it;
//! - PIDNS_INIT_EXIT: Y's exit kills the rest of its namespace, and
//!   X's wait for Y returns once they are gone (a pipe they hold reads
//!   EOF); after a namespace's init died, fork into it is ENOMEM;
//! - PIDNS_INIT_SIGNAL: from inside, SIGTERM and SIGKILL do not reach
//!   Y while their action is SIG_DFL, SIGTERM with a handler does; from
//!   X, SIGTERM does not either and SIGKILL kills it;
//! - PIDNS_SET_TID_1: clone3 set_tid into a namespace with no init yet
//!   must name 1 (another number is EINVAL); once its init runs, a free
//!   number works and 1 is EEXIST;
//! - PIDNS_REBOOT: reboot(2) inside kills Y, which X sees killed by
//!   SIGHUP (restart) or SIGINT (power off); an unknown command is
//!   EINVAL there. Only ever called inside a namespace.

use super::pidns::{child, first_fail, ns_child, outer, status};
use crate::helpers::{msleep, println};
use crate::signal::signals::restorer_addr;
use hk_syscall::{
    CLONE_NEWPID, CloneArgs, LINUX_REBOOT_CMD_POWER_OFF, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
    O_NONBLOCK, SA_RESTART, SA_RESTORER, SIGKILL, SIGTERM, sys_clone3, sys_close, sys_exit,
    sys_fork, sys_getpid, sys_getppid, sys_kill, sys_pipe2, sys_read, sys_reboot_ret,
    sys_rt_sigaction, sys_rt_sigpending, sys_unshare, sys_wait4, sys_write,
};

const SIGCHLD: u64 = 17;
const SIGHUP: i64 = 1;
const SIGINT: i64 = 2;
const ENOMEM: i64 = -12;
const EEXIST: i64 = -17;
const EINVAL: i64 = -22;
const LINUX_REBOOT_CMD_RESTART: u64 = 0x0123_4567;
const LINUX_REBOOT_CMD_CAD_ON: u64 = 0x89ab_cdef;

pub fn run_tests() {
    println(b"[PIDNS INIT TESTS]");
    outer(b"PIDNS_REAPER", reaper);
    outer(b"PIDNS_INIT_EXIT", init_exit);
    outer(b"PIDNS_INIT_SIGNAL", init_signal);
    outer(b"PIDNS_SET_TID_1", set_tid_1);
    outer(b"PIDNS_REBOOT", reboot);
}

/// Sleep until killed
fn hold() -> i32 {
    loop {
        msleep(1000);
    }
}

fn reaper() -> i32 {
    status(ns_child(|| {
        // A (2) forks the orphan B (3) and exits at once
        let a = child(|| i32::from(child(orphan) != 3));
        let sa = status(a);
        let mut st = -1;
        let w = sys_wait4(-1, &mut st, 0, 0);
        first_fail(&[a == 2, sa == 0, w == 3, st == 0])
    })) as i32
}

/// Within 5 s, this process's parent is the namespace's init
fn orphan() -> i32 {
    for _ in 0..500 {
        if sys_getppid() == 1 {
            return 0;
        }
        msleep(10);
    }
    1
}

/// X's pipe: [0] X reads (nonblocking), [1] the namespace holds
static mut HOLD: [i32; 2] = [-1, -1];

fn hold_fd(i: usize) -> u64 {
    // SAFETY: written by X before its children exist
    unsafe { core::ptr::read_volatile(&raw const HOLD)[i] as u64 }
}

fn init_exit() -> i32 {
    if sys_pipe2((&raw mut HOLD).cast::<i32>(), O_NONBLOCK) != 0 {
        return 20;
    }
    let y = ns_child(|| {
        // Two children and a grandchild, each holding the pipe
        let a = child(hold);
        let b = child(|| {
            child(hold);
            hold()
        });
        if a != 2 || b != 3 {
            return 1;
        }
        5
    });
    sys_close(hold_fd(1));
    let st = status(y);
    // Every writer is gone: EOF, not EAGAIN
    let mut c = [0u8; 1];
    let eof = sys_read(hold_fd(0), c.as_mut_ptr(), 1);
    first_fail(&[st == 5, eof == 0, fork_dead_ns() == ENOMEM])
}

/// unshare(CLONE_NEWPID), make the namespace's init and let it exit;
/// then fork again: its result
fn fork_dead_ns() -> i64 {
    if sys_unshare(CLONE_NEWPID) != 0 {
        return 1;
    }
    if status(child(|| 0)) != 0 {
        return 2;
    }
    let p = sys_fork();
    if p == 0 {
        sys_exit(0);
    }
    if p > 0 {
        status(p);
    }
    p
}

#[repr(C)]
struct SigAct {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

/// Times the SIGTERM handler ran
static mut TERMS: u32 = 0;

extern "C" fn on_term(_: i32) {
    // SAFETY: this process's counter, the handler its only writer
    unsafe { core::ptr::write_volatile(&raw mut TERMS, terms() + 1) };
}

fn terms() -> u32 {
    // SAFETY: as above
    unsafe { core::ptr::read_volatile(&raw const TERMS) }
}

/// SIGTERM's action: `on_term`, or SIG_DFL
fn set_term(handled: bool) {
    let act = SigAct {
        handler: if handled {
            on_term as *const () as u64
        } else {
            0
        },
        flags: SA_RESTART | SA_RESTORER,
        restorer: restorer_addr(),
        mask: 0,
    };
    sys_rt_sigaction(SIGTERM, &act as *const SigAct as u64, 0, 8);
}

/// Y to X, X to Y
static mut UP: [i32; 2] = [-1, -1];
static mut DOWN: [i32; 2] = [-1, -1];

fn up(i: usize) -> u64 {
    // SAFETY: written by X before its child exists
    unsafe { core::ptr::read_volatile(&raw const UP)[i] as u64 }
}

fn down(i: usize) -> u64 {
    // SAFETY: as above
    unsafe { core::ptr::read_volatile(&raw const DOWN)[i] as u64 }
}

/// Y: signals from inside, then from X
fn signalled_init() -> i32 {
    // SIG_DFL: ignored on arrival, not even pending
    let c1 = child(|| i32::from(sys_kill(1, SIGTERM) != 0 || sys_kill(1, SIGKILL) != 0));
    let s1 = status(c1);
    let mut pending: u64 = 0;
    sys_rt_sigpending(&mut pending as *mut u64 as u64, 8);
    // A handler: delivered
    set_term(true);
    let c2 = child(|| i32::from(sys_kill(1, SIGTERM) != 0));
    let s2 = status(c2);
    for _ in 0..500 {
        if terms() != 0 {
            break;
        }
        msleep(10);
    }
    set_term(false);
    let ok = [s1 == 0, pending == 0, s2 == 0, terms() == 1];
    let r = [first_fail(&ok) as u8];
    sys_write(up(1), r.as_ptr(), 1);
    // X's SIGTERM comes now; still here once it says so
    let mut b = [0u8; 1];
    sys_read(down(0), b.as_mut_ptr(), 1);
    sys_write(up(1), b"a".as_ptr(), 1);
    hold()
}

fn init_signal() -> i32 {
    if sys_pipe2((&raw mut UP).cast::<i32>(), 0) != 0
        || sys_pipe2((&raw mut DOWN).cast::<i32>(), 0) != 0
    {
        return 20;
    }
    let y = ns_child(signalled_init);
    sys_close(up(1));
    sys_close(down(0));
    let mut b = [0u8; 1];
    if y <= 0 || sys_read(up(0), b.as_mut_ptr(), 1) != 1 {
        return 21;
    }
    if b[0] != 0 {
        sys_kill(y, SIGKILL);
        status(y);
        return 30 + i32::from(b[0]);
    }
    let term = sys_kill(y, SIGTERM);
    sys_write(down(1), b"g".as_ptr(), 1);
    let alive = sys_read(up(0), b.as_mut_ptr(), 1) == 1 && b[0] == b'a';
    let kill = sys_kill(y, SIGKILL);
    let st = status(y);
    first_fail(&[term == 0, alive, kill == 0, st == 100 + i64::from(SIGKILL)])
}

/// clone3 with `flags` and the one set_tid number `nr`
fn clone_tid(flags: u64, nr: i32) -> i64 {
    let tids = [nr];
    let args = CloneArgs {
        flags,
        exit_signal: SIGCHLD,
        set_tid: tids.as_ptr() as u64,
        set_tid_size: 1,
        ..CloneArgs::default()
    };
    let p = sys_clone3(&args, core::mem::size_of::<CloneArgs>());
    if p == 0 {
        sys_exit(u64::from(sys_getpid() != i64::from(nr)));
    }
    p
}

/// X's pipe, held by the namespace's init until X writes
static mut GATE: [i32; 2] = [-1, -1];

fn gate(i: usize) -> u64 {
    // SAFETY: written by X before its children exist
    unsafe { core::ptr::read_volatile(&raw const GATE)[i] as u64 }
}

fn set_tid_1() -> i32 {
    // A new namespace starts at 1
    let two = clone_tid(CLONE_NEWPID, 2);
    let one = clone_tid(CLONE_NEWPID, 1);
    let s1 = status(one);
    if two > 0 {
        status(two);
    }
    // After unshare, the namespace has no init until its first child
    if sys_unshare(CLONE_NEWPID) != 0 || sys_pipe2((&raw mut GATE).cast::<i32>(), 0) != 0 {
        return 20;
    }
    let early = clone_tid(0, 3);
    if early > 0 {
        status(early);
    }
    let init = child(|| {
        let mut b = [0u8; 1];
        sys_read(gate(0), b.as_mut_ptr(), 1);
        0
    });
    let seven = clone_tid(0, 7);
    let s7 = status(seven);
    let dup = clone_tid(0, 1);
    if dup > 0 {
        status(dup);
    }
    sys_write(gate(1), b"x".as_ptr(), 1);
    let si = status(init);
    first_fail(&[
        two == EINVAL,
        one > 0 && s1 == 0,
        early == EINVAL,
        init > 0 && si == 0,
        seven > 0 && s7 == 0,
        dup == EEXIST,
    ])
}

fn reboot() -> i32 {
    let restart = status(ns_child(|| rebooted_init(rebooter_restart)));
    let off = status(ns_child(|| rebooted_init(rebooter_off)));
    first_fail(&[restart == 100 + SIGHUP, off == 100 + SIGINT])
}

/// Y: a child reboots, which kills Y; if the child exits instead, Y
/// does with 40 + its status
fn rebooted_init(f: fn() -> i32) -> i32 {
    40 + status(child(f)) as i32
}

/// Reboot with `cmd` from pid 2 of a child namespace (never elsewhere):
/// it does not return
fn rebooter(cmd: u64) -> i32 {
    if sys_getpid() != 2 || sys_getppid() != 1 {
        return 1;
    }
    let bad = sys_reboot_ret(
        LINUX_REBOOT_MAGIC1,
        LINUX_REBOOT_MAGIC2,
        LINUX_REBOOT_CMD_CAD_ON,
    );
    if bad != EINVAL {
        return 2;
    }
    sys_reboot_ret(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, cmd);
    3
}

fn rebooter_restart() -> i32 {
    rebooter(LINUX_REBOOT_CMD_RESTART)
}

fn rebooter_off() -> i32 {
    rebooter(LINUX_REBOOT_CMD_POWER_OFF)
}
