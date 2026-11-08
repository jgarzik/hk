//! A directory chain far deeper than any kernel stack (Linux dcache:
//! dentry_kill frees parents iteratively)
//!
//! Tests:
//! - DEEP_CHAIN: 20000 nested directories, entered one by one; getcwd at
//!   the bottom is ENAMETOOLONG (past PATH_MAX); with the bottom held
//!   open, every directory is removed from the bottom up, then the
//!   descriptor closed, which frees the whole chain at once

use crate::harness::report_step;
use hk_syscall::{
    O_DIRECTORY, O_RDONLY, sys_chdir, sys_close, sys_exit, sys_fork, sys_getcwd, sys_mkdir,
    sys_open, sys_rmdir, sys_wait4,
};

/// Levels: far past any kernel stack on hk; on a host kernel (emulated
/// in the gate, where 20000 levels cost tens of seconds) enough to pass
/// PATH_MAX, which is all its run checks
const DEPTH: usize = 20000;
const HOST_DEPTH: usize = 2500;
const ENAMETOOLONG: i64 = -36;

pub fn run_tests() {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(chain() as u64);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    report_step(
        b"DEEP_CHAIN",
        i64::from(st >> 8) + i64::from(st & 0x7f) * 100,
    );
}

/// The test, in a child (its cwd moves): 0, or the failed step
fn chain() -> i32 {
    let d = b"d\0".as_ptr();
    if sys_chdir(b"/\0".as_ptr()) != 0 || sys_mkdir(b"dchain\0".as_ptr(), 0o755) != 0 {
        return 1;
    }
    if sys_chdir(b"dchain\0".as_ptr()) != 0 {
        return 2;
    }
    let depth = if crate::helpers::host_mode() {
        HOST_DEPTH
    } else {
        DEPTH
    };
    for _ in 0..depth {
        if sys_mkdir(d, 0o755) != 0 || sys_chdir(d) != 0 {
            return 3;
        }
    }
    let mut buf = [0u8; 4096];
    if sys_getcwd(buf.as_mut_ptr(), buf.len()) != ENAMETOOLONG {
        return 4;
    }
    let fd = sys_open(b".\0".as_ptr(), O_RDONLY | O_DIRECTORY, 0);
    if fd < 0 {
        return 5;
    }
    for _ in 0..depth {
        if sys_chdir(b"..\0".as_ptr()) != 0 || sys_rmdir(d) != 0 {
            return 6;
        }
    }
    if sys_chdir(b"..\0".as_ptr()) != 0 || sys_rmdir(b"dchain\0".as_ptr()) != 0 {
        return 7;
    }
    sys_close(fd as u64);
    0
}
