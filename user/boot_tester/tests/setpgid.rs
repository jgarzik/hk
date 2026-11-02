//! setpgid on a child, and pid_t arguments (Linux kernel/sys.c
//! sys_setpgid, getpgid, getsid; kernel/kcmp.c)
//!
//! Tests:
//! - SETPGID_CHILD: a parent moves its child into a new group of its
//!   own and back into the parent's group (what a shell does for each
//!   job); a process that is not its child is ESRCH
//! - SETPGID_CHILD_EXEC: once the child has exec'd it is EACCES
//!   (PF_FORKNOEXEC cleared)
//! - SETPGID_INT_ARGS: pid_t arguments use the low 32 bits of their
//!   register: -1 with the upper half zero is EINVAL as setpgid's pgid,
//!   ESRCH as getpgid's, getsid's and kcmp's pid

use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_close, sys_execve, sys_exit, sys_fork, sys_getpgid, sys_getpid, sys_getppid, sys_getsid,
    sys_kcmp, sys_kill, sys_pipe2, sys_read, sys_setpgid, sys_wait4,
};

const EINVAL: i64 = -22;
const ESRCH: i64 = -3;
const EACCES: i64 = -13;
const O_CLOEXEC: u32 = 0o2000000;
/// -1 as a 32-bit int in a 64-bit register, upper half zero
const MINUS_ONE_32: u64 = 0xffff_ffff;

pub fn run_tests() {
    child();
    child_exec();
    int_args();
}

fn report(name: &[u8], step: i64) {
    print(name);
    if step == 0 {
        println(b":OK");
    } else {
        print(b":FAIL step ");
        print_num(step);
        println(b"");
    }
}

fn child() {
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    let pid = sys_fork();
    if pid == 0 {
        sys_close(p[1] as u64);
        // Not our child: the parent
        let other = sys_setpgid(sys_getppid() as u64, sys_getppid() as u64);
        let mut c = [0u8; 1];
        sys_read(p[0] as u64, c.as_mut_ptr(), 1);
        sys_exit(if other == ESRCH { 0 } else { 1 });
    }
    sys_close(p[0] as u64);
    let mine = sys_getpgid(0);
    let step = if sys_setpgid(pid as u64, pid as u64) != 0 {
        1
    } else if sys_getpgid(pid as u64) != pid {
        2
    } else if sys_setpgid(pid as u64, mine as u64) != 0 || sys_getpgid(pid as u64) != mine {
        3
    } else {
        0
    };
    sys_close(p[1] as u64);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    report(
        b"SETPGID_CHILD",
        if step == 0 && st != 0 { 4 } else { step },
    );
}

fn child_exec() {
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), O_CLOEXEC);
    let pid = sys_fork();
    if pid == 0 {
        sys_close(p[0] as u64);
        let argv: [*const u8; 4] = [
            b"sleep\0".as_ptr(),
            b"10\0".as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
        ];
        let envp: [*const u8; 1] = [core::ptr::null()];
        sys_execve(b"/bin/busybox\0".as_ptr(), argv.as_ptr(), envp.as_ptr());
        sys_exit(127);
    }
    sys_close(p[1] as u64);
    // EOF once the exec closed the write end
    let mut c = [0u8; 1];
    let eof = sys_read(p[0] as u64, c.as_mut_ptr(), 1);
    sys_close(p[0] as u64);
    let r = sys_setpgid(pid as u64, pid as u64);
    sys_kill(pid, 9);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    report(
        b"SETPGID_CHILD_EXEC",
        if eof != 0 {
            1
        } else if r != EACCES {
            2
        } else {
            0
        },
    );
}

fn int_args() {
    let me = sys_getpid() as u64;
    let step = if sys_setpgid(0, MINUS_ONE_32) != EINVAL {
        1
    } else if sys_getpgid(MINUS_ONE_32) != ESRCH {
        2
    } else if sys_getsid(MINUS_ONE_32) != ESRCH {
        3
    } else if sys_kcmp(MINUS_ONE_32, me, 0, 0, 0) != ESRCH {
        4
    } else {
        0
    };
    report(b"SETPGID_INT_ARGS", step);
}
