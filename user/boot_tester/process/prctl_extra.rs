//! Additional prctl tests
//!
//! Tests for PR_SET/GET_KEEPCAPS, PR_SET/GET_CHILD_SUBREAPER, PR_SET/GET_THP_DISABLE,
//! x86-64 specific PR_SET/GET_TSC, and x86-64 arch_prctl(ARCH_GET/SET_CPUID)
//!
//! The subreaper flag is the process's (Linux signal->is_child_subreaper):
//! set by a thread that then exits, it stays, every thread reads it, a
//! forked child does not inherit it, and an orphan goes to a live
//! thread of the subreaper process.

use crate::harness::{fail_num, pass, verdict};
use crate::helpers::{print, print_num, println};
use crate::mm::fork_mm::{join, spawn_thread};
#[cfg(target_arch = "x86_64")]
use hk_syscall::{
    ARCH_GET_CPUID, ARCH_SET_CPUID, PR_GET_TSC, PR_SET_TSC, PR_TSC_ENABLE, PR_TSC_SIGSEGV,
    sys_arch_prctl,
};
use hk_syscall::{
    PR_GET_CHILD_SUBREAPER, PR_GET_KEEPCAPS, PR_GET_THP_DISABLE, PR_SET_CHILD_SUBREAPER,
    PR_SET_KEEPCAPS, PR_SET_THP_DISABLE, sys_close, sys_exit, sys_fork, sys_getpid, sys_getppid,
    sys_pipe2, sys_prctl, sys_read, sys_wait4, sys_write,
};

/// Run all prctl extra tests
pub fn run_tests() {
    test_keepcaps_default();
    test_keepcaps_set_get();
    test_keepcaps_invalid();
    test_child_subreaper_default();
    test_child_subreaper_set_get();
    test_child_subreaper_thread();

    // THP disable test (all architectures)
    test_thp_disable();

    // x86-64 specific tests
    #[cfg(target_arch = "x86_64")]
    {
        test_tsc_mode();
        test_cpuid_fault();
    }
}

/// Test: KEEPCAPS defaults to 0
fn test_keepcaps_default() {
    let ret = sys_prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0);
    if ret == 0 {
        pass(b"PRCTL_KEEPCAPS_DEFAULT");
    } else {
        fail_num(b"PRCTL_KEEPCAPS_DEFAULT:FAIL: expected 0, got ", ret);
    }
}

/// Test: Set and get KEEPCAPS
fn test_keepcaps_set_get() {
    // Set to 1
    let ret = sys_prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
    if ret != 0 {
        fail_num(b"PRCTL_KEEPCAPS_SET:FAIL: set returned ", ret);
        return;
    }

    // Get - should be 1
    let ret = sys_prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0);
    if ret != 1 {
        print(b"PRCTL_KEEPCAPS_SET:FAIL: get returned ");
        print_num(ret);
        println(b" expected 1");
        return;
    }

    // Set back to 0
    let ret = sys_prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0);
    if ret != 0 {
        fail_num(b"PRCTL_KEEPCAPS_SET:FAIL: clear returned ", ret);
        return;
    }

    // Get - should be 0
    let ret = sys_prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0);
    if ret != 0 {
        fail_num(b"PRCTL_KEEPCAPS_SET:FAIL: get after clear returned ", ret);
        return;
    }

    pass(b"PRCTL_KEEPCAPS_SET");
}

/// Test: KEEPCAPS with invalid value returns EINVAL
fn test_keepcaps_invalid() {
    // Value > 1 should fail
    let ret = sys_prctl(PR_SET_KEEPCAPS, 2, 0, 0, 0);
    if ret == -22 {
        // EINVAL
        pass(b"PRCTL_KEEPCAPS_INVALID");
    } else {
        fail_num(b"PRCTL_KEEPCAPS_INVALID:FAIL: expected -22, got ", ret);
    }
}

/// Test: CHILD_SUBREAPER defaults to 0
fn test_child_subreaper_default() {
    // PR_GET_CHILD_SUBREAPER returns value via pointer
    let mut value: i32 = -1;
    let ret = sys_prctl(
        PR_GET_CHILD_SUBREAPER,
        &mut value as *mut i32 as u64,
        0,
        0,
        0,
    );
    if ret != 0 {
        fail_num(b"PRCTL_SUBREAPER_DEFAULT:FAIL: get returned ", ret);
        return;
    }
    if value == 0 {
        pass(b"PRCTL_SUBREAPER_DEFAULT");
    } else {
        fail_num(
            b"PRCTL_SUBREAPER_DEFAULT:FAIL: expected 0, got ",
            value as i64,
        );
    }
}

/// Test: Set and get CHILD_SUBREAPER
fn test_child_subreaper_set_get() {
    // Set to 1
    let ret = sys_prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
    if ret != 0 {
        fail_num(b"PRCTL_SUBREAPER_SET:FAIL: set returned ", ret);
        return;
    }

    // Get - should be 1
    let mut value: i32 = -1;
    let ret = sys_prctl(
        PR_GET_CHILD_SUBREAPER,
        &mut value as *mut i32 as u64,
        0,
        0,
        0,
    );
    if ret != 0 {
        fail_num(b"PRCTL_SUBREAPER_SET:FAIL: get returned ", ret);
        return;
    }
    if value != 1 {
        fail_num(b"PRCTL_SUBREAPER_SET:FAIL: expected 1, got ", value as i64);
        return;
    }

    // Set back to 0
    let ret = sys_prctl(PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0);
    if ret != 0 {
        fail_num(b"PRCTL_SUBREAPER_SET:FAIL: clear returned ", ret);
        return;
    }

    // Get - should be 0
    let mut value: i32 = -1;
    let ret = sys_prctl(
        PR_GET_CHILD_SUBREAPER,
        &mut value as *mut i32 as u64,
        0,
        0,
        0,
    );
    if ret != 0 || value != 0 {
        fail_num(b"PRCTL_SUBREAPER_SET:FAIL: after clear, got ", value as i64);
        return;
    }

    pass(b"PRCTL_SUBREAPER_SET");
}

#[repr(C, align(16))]
struct Stack([u8; 16384]);
static mut STACK: Stack = Stack([0; 16384]);
static mut CTID: u32 = 0;

/// PR_GET_CHILD_SUBREAPER of the calling thread
fn subreaper() -> i32 {
    let mut v: i32 = -1;
    sys_prctl(PR_GET_CHILD_SUBREAPER, &raw mut v as u64, 0, 0, 0);
    v
}

/// A second thread makes the process a subreaper and exits
extern "C" fn set_subreaper(_: u64) -> ! {
    sys_prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
    sys_exit(0)
}

/// SUBREAPER_THREAD: in a helper process, a thread sets the flag and
/// exits; the main thread reads 1, a forked child 0, and the child's
/// orphan is reparented to the helper, which reaps it
fn test_child_subreaper_thread() {
    let h = sys_fork();
    if h == 0 {
        sys_exit(subreaper_thread() as u64);
    }
    let mut st = 0i32;
    sys_wait4(h, &mut st, 0, 0);
    verdict(b"SUBREAPER_THREAD", st == 0, i64::from(st));
}

/// [`test_child_subreaper_thread`]'s helper: 0, else the first failed
/// step
fn subreaper_thread() -> i32 {
    let me = sys_getpid();
    let top = unsafe { (&raw mut STACK as *mut u8).add(16384) as u64 };
    let ctid = &raw mut CTID;
    // Nonzero until the thread's exit clears it (no CLONE_CHILD_SETTID)
    unsafe { core::ptr::write_volatile(ctid, 1) };
    if unsafe { spawn_thread(top, set_subreaper, 0, ctid) } <= 0 || !join(ctid) {
        return 1;
    }
    // The flag outlives the thread that set it, read from another
    if subreaper() != 1 {
        return 2;
    }
    let mut p = [0i32; 2];
    let mut go = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    sys_pipe2(go.as_mut_ptr(), 0);
    let child = sys_fork();
    if child == 0 {
        let gc = sys_fork();
        if gc == 0 {
            // Once the middle process is gone, report the new parent
            let mut c = [0u8; 1];
            sys_read(go[0] as u64, c.as_mut_ptr(), 1);
            let v = [sys_getppid()];
            sys_write(p[1] as u64, v.as_ptr() as *const u8, 8);
            sys_exit(7);
        }
        // Not inherited (Linux copy_signal: is_child_subreaper is not)
        let v = [gc, i64::from(subreaper())];
        sys_write(p[1] as u64, v.as_ptr() as *const u8, 16);
        sys_exit(0);
    }
    let mut v = [0i64; 2];
    sys_read(p[0] as u64, v.as_mut_ptr() as *mut u8, 16);
    let mut st = 0;
    sys_wait4(child, &mut st, 0, 0);
    sys_write(go[1] as u64, b"g".as_ptr(), 1);
    let mut ppid = [0i64; 1];
    let n = sys_read(p[0] as u64, ppid.as_mut_ptr() as *mut u8, 8);
    let w = sys_wait4(v[0], &mut st, 0, 0);
    for fd in [p[0], p[1], go[0], go[1]] {
        sys_close(fd as u64);
    }
    if v[1] != 0 {
        3
    } else if n != 8 || ppid[0] != me {
        4
    } else if w != v[0] || (st >> 8) & 0xff != 7 {
        5
    } else {
        0
    }
}

/// Test: THP_DISABLE set and get
fn test_thp_disable() {
    // Get default (should be 0)
    let ret = sys_prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0);
    if ret != 0 {
        fail_num(b"PRCTL_THP_DISABLE:FAIL: default not 0, got ", ret);
        return;
    }

    // Set THP_DISABLE to 1
    let ret = sys_prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0);
    if ret != 0 {
        fail_num(b"PRCTL_THP_DISABLE:FAIL: set returned ", ret);
        return;
    }

    // Get - should be 1
    let ret = sys_prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0);
    if ret != 1 {
        print(b"PRCTL_THP_DISABLE:FAIL: get returned ");
        print_num(ret);
        println(b" expected 1");
        return;
    }

    // Set back to 0
    let ret = sys_prctl(PR_SET_THP_DISABLE, 0, 0, 0, 0);
    if ret != 0 {
        fail_num(b"PRCTL_THP_DISABLE:FAIL: clear returned ", ret);
        return;
    }

    // Get - should be 0
    let ret = sys_prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0);
    if ret != 0 {
        fail_num(b"PRCTL_THP_DISABLE:FAIL: after clear returned ", ret);
        return;
    }

    pass(b"PRCTL_THP_DISABLE");
}

/// Test: TSC mode set and get (x86-64 only)
#[cfg(target_arch = "x86_64")]
fn test_tsc_mode() {
    // Get default (should be PR_TSC_ENABLE = 1)
    // PR_GET_TSC returns the value via a pointer in arg2
    let mut tsc_mode: i32 = -1;
    let ret = sys_prctl(PR_GET_TSC, &mut tsc_mode as *mut i32 as u64, 0, 0, 0);
    if ret != 0 || tsc_mode != PR_TSC_ENABLE {
        print(b"PRCTL_TSC:FAIL: default not PR_TSC_ENABLE, ret=");
        print_num(ret);
        print(b", tsc_mode=");
        print_num(tsc_mode as i64);
        println(b"");
        return;
    }

    // Set TSC mode to SIGSEGV (disable RDTSC)
    let ret = sys_prctl(PR_SET_TSC, PR_TSC_SIGSEGV as u64, 0, 0, 0);
    if ret != 0 {
        fail_num(b"PRCTL_TSC:FAIL: set SIGSEGV returned ", ret);
        return;
    }

    // Get - should be PR_TSC_SIGSEGV = 2
    let mut tsc_mode: i32 = -1;
    let ret = sys_prctl(PR_GET_TSC, &mut tsc_mode as *mut i32 as u64, 0, 0, 0);
    if ret != 0 || tsc_mode != PR_TSC_SIGSEGV {
        print(b"PRCTL_TSC:FAIL: get returned ret=");
        print_num(ret);
        print(b", tsc_mode=");
        print_num(tsc_mode as i64);
        println(b" expected 2");
        return;
    }

    // Set back to ENABLE
    let ret = sys_prctl(PR_SET_TSC, PR_TSC_ENABLE as u64, 0, 0, 0);
    if ret != 0 {
        fail_num(b"PRCTL_TSC:FAIL: set ENABLE returned ", ret);
        return;
    }

    pass(b"PRCTL_TSC");
}

/// Test: CPUID faulting via arch_prctl(ARCH_GET/SET_CPUID) (x86-64 only)
///
/// Linux (arch/x86/kernel/process.c): ARCH_GET_CPUID returns 1 when CPUID
/// is enabled (the default), 0 when it faults. ARCH_SET_CPUID returns
/// -ENODEV when the CPU lacks CPUID faulting. There is no prctl() for this:
/// prctl options 48/49 are unassigned and must fail with EINVAL.
#[cfg(target_arch = "x86_64")]
fn test_cpuid_fault() {
    const ENODEV: i64 = -19;
    const EINVAL: i64 = -22;

    // prctl(48/49) are not CPUID controls on Linux
    for opt in [48, 49] {
        let ret = sys_prctl(opt, 0, 0, 0, 0);
        if ret != EINVAL {
            print(b"PRCTL_CPUID:FAIL: prctl(");
            print_num(opt as i64);
            print(b") returned ");
            print_num(ret);
            println(b" expected -EINVAL");
            return;
        }
    }

    // Default: CPUID enabled
    let ret = sys_arch_prctl(ARCH_GET_CPUID, 0);
    if ret != 1 {
        print(b"PRCTL_CPUID:FAIL: ARCH_GET_CPUID default returned ");
        print_num(ret);
        println(b" expected 1");
        return;
    }

    // Disable CPUID (fault). ENODEV if the CPU lacks CPUID faulting.
    let ret = sys_arch_prctl(ARCH_SET_CPUID, 0);
    if ret == ENODEV {
        // Without the feature, the mode must stay "enabled"
        let ret = sys_arch_prctl(ARCH_GET_CPUID, 0);
        if ret != 1 {
            fail_num(b"PRCTL_CPUID:FAIL: after ENODEV, get returned ", ret);
            return;
        }
        pass(b"PRCTL_CPUID");
        return;
    }
    if ret != 0 {
        fail_num(b"PRCTL_CPUID:FAIL: ARCH_SET_CPUID(0) returned ", ret);
        return;
    }

    let ret = sys_arch_prctl(ARCH_GET_CPUID, 0);
    if ret != 0 {
        print(b"PRCTL_CPUID:FAIL: get after disable returned ");
        print_num(ret);
        println(b" expected 0");
        sys_arch_prctl(ARCH_SET_CPUID, 1);
        return;
    }

    // Re-enable CPUID
    let ret = sys_arch_prctl(ARCH_SET_CPUID, 1);
    if ret != 0 {
        fail_num(b"PRCTL_CPUID:FAIL: ARCH_SET_CPUID(1) returned ", ret);
        return;
    }

    pass(b"PRCTL_CPUID");
}
