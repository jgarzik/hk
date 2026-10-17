//! Additional prctl tests
//!
//! Tests for PR_SET/GET_KEEPCAPS, PR_SET/GET_CHILD_SUBREAPER, PR_SET/GET_THP_DISABLE,
//! x86-64 specific PR_SET/GET_TSC, and x86-64 arch_prctl(ARCH_GET/SET_CPUID)

use super::helpers::{print, print_num, println};
#[cfg(target_arch = "x86_64")]
use hk_syscall::{
    ARCH_GET_CPUID, ARCH_SET_CPUID, PR_GET_TSC, PR_SET_TSC, PR_TSC_ENABLE, PR_TSC_SIGSEGV,
    sys_arch_prctl,
};
use hk_syscall::{
    PR_GET_CHILD_SUBREAPER, PR_GET_KEEPCAPS, PR_GET_THP_DISABLE, PR_SET_CHILD_SUBREAPER,
    PR_SET_KEEPCAPS, PR_SET_THP_DISABLE, sys_prctl,
};

/// Run all prctl extra tests
pub fn run_tests() {
    test_keepcaps_default();
    test_keepcaps_set_get();
    test_keepcaps_invalid();
    test_child_subreaper_default();
    test_child_subreaper_set_get();

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
        println(b"PRCTL_KEEPCAPS_DEFAULT:OK");
    } else {
        print(b"PRCTL_KEEPCAPS_DEFAULT:FAIL: expected 0, got ");
        print_num(ret);
        println(b"");
    }
}

/// Test: Set and get KEEPCAPS
fn test_keepcaps_set_get() {
    // Set to 1
    let ret = sys_prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_KEEPCAPS_SET:FAIL: set returned ");
        print_num(ret);
        println(b"");
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
        print(b"PRCTL_KEEPCAPS_SET:FAIL: clear returned ");
        print_num(ret);
        println(b"");
        return;
    }

    // Get - should be 0
    let ret = sys_prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_KEEPCAPS_SET:FAIL: get after clear returned ");
        print_num(ret);
        println(b"");
        return;
    }

    println(b"PRCTL_KEEPCAPS_SET:OK");
}

/// Test: KEEPCAPS with invalid value returns EINVAL
fn test_keepcaps_invalid() {
    // Value > 1 should fail
    let ret = sys_prctl(PR_SET_KEEPCAPS, 2, 0, 0, 0);
    if ret == -22 {
        // EINVAL
        println(b"PRCTL_KEEPCAPS_INVALID:OK");
    } else {
        print(b"PRCTL_KEEPCAPS_INVALID:FAIL: expected -22, got ");
        print_num(ret);
        println(b"");
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
        print(b"PRCTL_SUBREAPER_DEFAULT:FAIL: get returned ");
        print_num(ret);
        println(b"");
        return;
    }
    if value == 0 {
        println(b"PRCTL_SUBREAPER_DEFAULT:OK");
    } else {
        print(b"PRCTL_SUBREAPER_DEFAULT:FAIL: expected 0, got ");
        print_num(value as i64);
        println(b"");
    }
}

/// Test: Set and get CHILD_SUBREAPER
fn test_child_subreaper_set_get() {
    // Set to 1
    let ret = sys_prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_SUBREAPER_SET:FAIL: set returned ");
        print_num(ret);
        println(b"");
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
        print(b"PRCTL_SUBREAPER_SET:FAIL: get returned ");
        print_num(ret);
        println(b"");
        return;
    }
    if value != 1 {
        print(b"PRCTL_SUBREAPER_SET:FAIL: expected 1, got ");
        print_num(value as i64);
        println(b"");
        return;
    }

    // Set back to 0
    let ret = sys_prctl(PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_SUBREAPER_SET:FAIL: clear returned ");
        print_num(ret);
        println(b"");
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
        print(b"PRCTL_SUBREAPER_SET:FAIL: after clear, got ");
        print_num(value as i64);
        println(b"");
        return;
    }

    println(b"PRCTL_SUBREAPER_SET:OK");
}

/// Test: THP_DISABLE set and get
fn test_thp_disable() {
    // Get default (should be 0)
    let ret = sys_prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_THP_DISABLE:FAIL: default not 0, got ");
        print_num(ret);
        println(b"");
        return;
    }

    // Set THP_DISABLE to 1
    let ret = sys_prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_THP_DISABLE:FAIL: set returned ");
        print_num(ret);
        println(b"");
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
        print(b"PRCTL_THP_DISABLE:FAIL: clear returned ");
        print_num(ret);
        println(b"");
        return;
    }

    // Get - should be 0
    let ret = sys_prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0);
    if ret != 0 {
        print(b"PRCTL_THP_DISABLE:FAIL: after clear returned ");
        print_num(ret);
        println(b"");
        return;
    }

    println(b"PRCTL_THP_DISABLE:OK");
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
        print(b"PRCTL_TSC:FAIL: set SIGSEGV returned ");
        print_num(ret);
        println(b"");
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
        print(b"PRCTL_TSC:FAIL: set ENABLE returned ");
        print_num(ret);
        println(b"");
        return;
    }

    println(b"PRCTL_TSC:OK");
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
            print(b"PRCTL_CPUID:FAIL: after ENODEV, get returned ");
            print_num(ret);
            println(b"");
            return;
        }
        println(b"PRCTL_CPUID:OK");
        return;
    }
    if ret != 0 {
        print(b"PRCTL_CPUID:FAIL: ARCH_SET_CPUID(0) returned ");
        print_num(ret);
        println(b"");
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
        print(b"PRCTL_CPUID:FAIL: ARCH_SET_CPUID(1) returned ");
        print_num(ret);
        println(b"");
        return;
    }

    println(b"PRCTL_CPUID:OK");
}
