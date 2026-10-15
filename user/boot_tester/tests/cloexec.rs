//! Close-on-exec (Linux do_close_on_exec): O_CLOEXEC sets FD_CLOEXEC,
//! execve closes exactly the FD_CLOEXEC descriptors, and a table shared
//! through CLONE_FILES is unshared first, so the other sharers keep
//! their descriptors. `/bin/boot_tester2 fdcheck` checks the exec side:
//! fd 10 (close-on-exec) must be gone, fd 11 must remain.

use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_clone, sys_close, sys_dup3, sys_execve, sys_exit, sys_fcntl, sys_fork, sys_open,
    sys_wait4, O_CLOEXEC, O_RDONLY,
};

const F_GETFD: i32 = 1;
const FD_CLOEXEC: i64 = 1;
const CLONE_FILES: u64 = 0x400;
const SIGCHLD: u64 = 17;

pub fn run_tests() {
    test_open_flag();
    test_exec(b"CLOEXEC_EXEC", false);
    test_exec(b"CLOEXEC_SHARED_FILES", true);
}

fn verdict(name: &[u8], ok: bool, got: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL got ");
        print_num(got);
        println(b"");
    }
}

/// open(O_CLOEXEC) sets FD_CLOEXEC; a plain open does not
fn test_open_flag() {
    let a = sys_open(b"/test.txt\0".as_ptr(), O_RDONLY | O_CLOEXEC, 0);
    let b = sys_open(b"/test.txt\0".as_ptr(), O_RDONLY, 0);
    let fa = sys_fcntl(a as i32, F_GETFD, 0);
    let fb = sys_fcntl(b as i32, F_GETFD, 0);
    sys_close(a as u64);
    sys_close(b as u64);
    verdict(b"CLOEXEC_OPEN_FLAG", fa == FD_CLOEXEC && fb == 0, fa * 10 + fb);
}

/// fd 10 close-on-exec, fd 11 not, both on /test.txt
fn setup_fds() {
    let a = sys_open(b"/test.txt\0".as_ptr(), O_RDONLY | O_CLOEXEC, 0);
    let b = sys_open(b"/test.txt\0".as_ptr(), O_RDONLY, 0);
    sys_dup3(a as i32, 10, O_CLOEXEC);
    sys_dup3(b as i32, 11, 0);
    sys_close(a as u64);
    sys_close(b as u64);
}

fn exec_fdcheck() -> ! {
    let argv: [*const u8; 3] = [
        b"boot_tester2\0".as_ptr(),
        b"fdcheck\0".as_ptr(),
        core::ptr::null(),
    ];
    let envp: [*const u8; 1] = [core::ptr::null()];
    sys_execve(b"/bin/boot_tester2\0".as_ptr(), argv.as_ptr(), envp.as_ptr());
    sys_exit(99);
}

/// exec closes fd 10 and keeps fd 11; with `shared` the child shares
/// the parent's table (CLONE_FILES) and the parent's fd 10 survives
fn test_exec(name: &[u8], shared: bool) {
    let pid = if shared {
        setup_fds();
        sys_clone(CLONE_FILES | SIGCHLD, 0, 0, 0, 0)
    } else {
        sys_fork()
    };
    if pid == 0 {
        if !shared {
            setup_fds();
        }
        exec_fdcheck();
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    let mine = if shared {
        sys_fcntl(10, F_GETFD, 0)
    } else {
        FD_CLOEXEC
    };
    if shared {
        sys_close(10);
        sys_close(11);
    }
    verdict(name, pid > 0 && st == 0 && mine == FD_CLOEXEC, (st as i64) * 100 + mine);
}
