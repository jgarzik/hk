//! execve's argument and environment limits (Linux
//! do_execveat_common, bprm_stack_limits, copy_strings): any number of
//! strings up to MAX_ARG_STRINGS, each at most MAX_ARG_STRLEN (32
//! pages, NUL included), all of them within a quarter of RLIMIT_STACK
//! (at most 6 MB, at least 32 pages) less the pointers; past that
//! E2BIG
//!
//! EXEC_ARGS_MANY: 2000 arguments all reach the program
//! EXEC_ARGS_100K: one 100 KiB argument reaches the program
//! EXEC_ARGS_STRLEN_MAX / _OVER: an argument of MAX_ARG_STRLEN - 1 bytes runs, one
//! byte more is E2BIG
//! EXEC_ARGS_RLIMIT_FITS / _OVER: with RLIMIT_STACK at 1 MiB (a 256 KiB limit), two
//! 100 KiB arguments run and three are E2BIG
//! EXEC_ARGC0_NULL / _EMPTY: argv NULL or {NULL} starts the program
//! with argc 1 and argv[0] "" (Linux 5.18+), not argc 0

use crate::harness::fail_num;
use crate::helpers::{print, println};
use core::ptr;
use hk_syscall::{RLIMIT_STACK, RLimit, sys_execve, sys_exit, sys_fork, sys_setrlimit, sys_wait4};

const E2BIG: i64 = 7;
const MAX_ARG_STRLEN: usize = 32 * 4096;
const BUSYBOX: &[u8] = b"/bin/busybox\0";
const MANY: usize = 2000;

/// Argument bytes, shared by the cases (NUL-terminated where a case
/// ends a string); each case runs in its own child
static mut BIG: [u8; MAX_ARG_STRLEN + 1] = [b'a'; MAX_ARG_STRLEN + 1];
static mut ARGV: [*const u8; MANY + 1] = [ptr::null(); MANY + 1];

pub fn run_tests() {
    argc0(b"EXEC_ARGC0_NULL", false);
    argc0(b"EXEC_ARGC0_EMPTY", true);
    // sh -c SCRIPT $0 ARGS...: $# counts ARGS
    case(b"EXEC_ARGS_MANY", 0, |argv| {
        argv[0] = b"sh\0".as_ptr();
        argv[1] = b"-c\0".as_ptr();
        argv[2] = b"[ $# -eq 1996 ]\0".as_ptr();
        for a in argv.iter_mut().take(MANY).skip(3) {
            *a = b"x\0".as_ptr();
        }
        MANY
    });
    case(b"EXEC_ARGS_100K", 0, |argv| {
        let big = big(100 * 1024);
        argv[..5].copy_from_slice(&[
            b"sh\0".as_ptr(),
            b"-c\0".as_ptr(),
            b"[ ${#1} -eq 102400 ]\0".as_ptr(),
            b"sh\0".as_ptr(),
            big,
        ]);
        5
    });
    case(b"EXEC_ARGS_STRLEN_MAX", 0, |argv| {
        argv[..2].copy_from_slice(&[b"true\0".as_ptr(), big(MAX_ARG_STRLEN - 1)]);
        2
    });
    case(b"EXEC_ARGS_STRLEN_OVER", E2BIG, |argv| {
        argv[..2].copy_from_slice(&[b"true\0".as_ptr(), big(MAX_ARG_STRLEN)]);
        2
    });
    let rl = || {
        let r = RLimit {
            rlim_cur: 1 << 20,
            rlim_max: u64::MAX,
        };
        sys_setrlimit(RLIMIT_STACK, &r);
    };
    case_rl(b"EXEC_ARGS_RLIMIT_FITS", 0, rl, |argv| hundreds(argv, 2));
    case_rl(b"EXEC_ARGS_RLIMIT_OVER", E2BIG, rl, |argv| {
        hundreds(argv, 3)
    });
}

/// `true` with `n` arguments of 100 KiB
fn hundreds(argv: &mut [*const u8], n: usize) -> usize {
    argv[0] = b"true\0".as_ptr();
    let b = big(100 * 1024);
    for a in argv.iter_mut().skip(1).take(n) {
        *a = b;
    }
    n + 1
}

/// BIG as a string of `len` bytes
fn big(len: usize) -> *const u8 {
    // SAFETY: only this (single-threaded) child touches BIG
    let b = unsafe { &mut *ptr::addr_of_mut!(BIG) };
    b.fill(b'a');
    b[len] = 0;
    b.as_ptr()
}

/// Exec boot_tester2 with no arguments (a NULL `argv`, or an empty
/// array if `array`): it exits 123 when it got argc 1, 7 for argc 0
fn argc0(name: &[u8], array: bool) {
    let pid = sys_fork();
    if pid == 0 {
        let empty: [*const u8; 1] = [ptr::null()];
        let argv = if array { empty.as_ptr() } else { ptr::null() };
        let envp: [*const u8; 1] = [ptr::null()];
        let r = sys_execve(b"/bin/boot_tester2\0".as_ptr(), argv, envp.as_ptr());
        sys_exit((-r) as u64 & 0xff);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    print(name);
    if st & 0x7f == 0 && (st >> 8) & 0xff == 123 {
        println(b":OK");
    } else {
        fail_num(b":FAIL wstatus=", i64::from(st));
    }
}

fn case(name: &[u8], want: i64, build: fn(&mut [*const u8]) -> usize) {
    case_rl(name, want, || {}, build);
}

/// In a child: `setup`, then exec busybox with the argv `build` makes;
/// the child's exit code must be `want` (0: the program's success, else
/// the errno execve returned)
fn case_rl(name: &[u8], want: i64, setup: fn(), build: fn(&mut [*const u8]) -> usize) {
    let pid = sys_fork();
    if pid == 0 {
        setup();
        // SAFETY: only this (single-threaded) child touches ARGV
        let argv = unsafe { &mut *ptr::addr_of_mut!(ARGV) };
        let n = build(&mut argv[..MANY]);
        argv[n] = ptr::null();
        let envp: [*const u8; 1] = [ptr::null()];
        let r = sys_execve(BUSYBOX.as_ptr(), argv.as_ptr(), envp.as_ptr());
        sys_exit((-r) as u64 & 0xff);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    print(name);
    if st & 0x7f == 0 && i64::from((st >> 8) & 0xff) == want {
        println(b":OK");
    } else {
        fail_num(b":FAIL wstatus=", i64::from(st));
    }
}
