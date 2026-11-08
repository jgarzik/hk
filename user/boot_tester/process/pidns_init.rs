//! A pid namespace's init (Linux kernel/exit.c find_child_reaper,
//! kernel/pid_namespace.c zap_pid_ns_processes, reboot_pid_ns)
//!
//! As in `pidns`, each test runs in a forked process X whose child Y
//! is pid 1 of a new namespace.
//! - PIDNS_REAPER: an orphan inside is adopted by Y (getppid 1), which
//!   reaps it;
//! - PIDNS_INIT_EXIT: Y's exit kills the rest of its namespace, and
//!   X's wait for Y returns once they are gone (a pipe they hold reads
//!   EOF); after a namespace's init died, fork into it is ENOMEM;
//! - PIDNS_REBOOT: reboot(2) inside kills Y, which X sees killed by
//!   SIGHUP (restart) or SIGINT (power off); an unknown command is
//!   EINVAL there. Only ever called inside a namespace.

use super::pidns::{child, first_fail, ns_child, outer, status};
use crate::helpers::{msleep, println};
use hk_syscall::{
    CLONE_NEWPID, LINUX_REBOOT_CMD_POWER_OFF, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, O_NONBLOCK,
    sys_close, sys_exit, sys_fork, sys_getpid, sys_getppid, sys_pipe2, sys_read, sys_reboot_ret,
    sys_unshare, sys_wait4,
};

const SIGHUP: i64 = 1;
const SIGINT: i64 = 2;
const ENOMEM: i64 = -12;
const EINVAL: i64 = -22;
const LINUX_REBOOT_CMD_RESTART: u64 = 0x0123_4567;
const LINUX_REBOOT_CMD_CAD_ON: u64 = 0x89ab_cdef;

pub fn run_tests() {
    println(b"[PIDNS INIT TESTS]");
    outer(b"PIDNS_REAPER", reaper);
    outer(b"PIDNS_INIT_EXIT", init_exit);
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
