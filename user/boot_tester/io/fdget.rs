//! Descriptor lookups with no lock (Linux fs/file.c fdget,
//! __fget_files_rcu): a table shared through CLONE_FILES grows and
//! changes under another task's lookups
//!
//! Tests:
//! - FDGET_SHARED_GROW: while a CLONE_FILES child grows the table
//!   (dup2 to ever higher descriptors) and closes what it made, the
//!   parent's walks from a directory descriptor it keeps open
//!   (fstatat, openat) never fail

use crate::harness::verdict;
use hk_syscall::{
    O_DIRECTORY, O_RDONLY, Stat, sys_clone, sys_close, sys_dup3, sys_exit, sys_fork, sys_fstatat,
    sys_open, sys_openat, sys_wait4,
};

const CLONE_FILES: u64 = 0x400;
const SIGCHLD: u64 = 17;
/// Rounds, each in a new process whose copied table starts small
const ROUNDS: usize = 8;
/// Lookups per round
const LOOKUPS: usize = 4000;

pub fn run_tests() {
    let mut bad = 0i64;
    for _ in 0..ROUNDS {
        let pid = sys_fork();
        if pid == 0 {
            sys_exit(round() as u64);
        }
        let mut st = 0;
        sys_wait4(pid, &mut st, 0, 0);
        if st != 0 {
            bad = st as i64;
            break;
        }
    }
    verdict(b"FDGET_SHARED_GROW", bad == 0, bad);
}

/// One round: 0, or what went wrong
fn round() -> i64 {
    let dir = sys_open(b"/\0".as_ptr(), O_RDONLY | O_DIRECTORY, 0) as i32;
    if dir < 0 {
        return 1;
    }
    let pid = sys_clone(CLONE_FILES | SIGCHLD, 0, 0, 0, 0);
    if pid == 0 {
        sys_exit(grow(dir));
    }
    let mut st: Stat = unsafe { core::mem::zeroed() };
    let mut r = 0;
    for i in 0..LOOKUPS {
        let n = if i % 2 == 0 {
            sys_fstatat(dir, b"dev\0".as_ptr(), &mut st, 0)
        } else {
            let fd = sys_openat(dir, b"dev\0".as_ptr(), O_RDONLY, 0);
            if fd >= 0 {
                sys_close(fd as u64);
            }
            fd.min(0)
        };
        if n < 0 {
            r = 1000 - n;
            break;
        }
    }
    let mut cst = 0;
    sys_wait4(pid, &mut cst, 0, 0);
    if r == 0 && cst != 0 { 2 } else { r }
}

/// The child: grow the shared table step by step, closing as it goes
fn grow(dir: i32) -> u64 {
    let mut fd = 70;
    while fd < 1000 {
        if sys_dup3(dir, fd, 0) != fd as i64 {
            return 3;
        }
        if fd % 3 == 0 {
            sys_close(fd as u64);
        }
        fd += 37;
    }
    0
}
