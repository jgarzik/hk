//! Resource limits (rlimit) tests
//!
//! Tests for getrlimit, setrlimit, and prlimit64 syscalls.

use super::helpers::{print, println, print_num};
use crate::syscall::{
    sys_getrlimit, sys_setrlimit, sys_prlimit64,
    RLimit, RLIMIT_NOFILE, RLIMIT_MEMLOCK, RLIMIT_STACK,
    RLIM_NLIMITS, RLIM_INFINITY,
};
use core::ptr;

/// Run all rlimit tests
pub fn run_tests() {
    println(b"=== Resource Limits Tests ===");
    test_getrlimit_basic();
    test_getrlimit_all_resources();
    test_getrlimit_einval();
    test_setrlimit_lower_soft();
    test_setrlimit_raise_to_hard();
    test_setrlimit_einval_cur_gt_max();
    test_prlimit64_get_only();
    test_prlimit64_set_only();
    test_prlimit64_get_and_set();
    test_prlimit64_self_pid_zero();
    println(b"=== Resource Limits Tests Complete ===");
}

/// Test: Basic getrlimit for RLIMIT_NOFILE
fn test_getrlimit_basic() {
    let mut rlim = RLimit { rlim_cur: 0, rlim_max: 0 };
    let ret = sys_getrlimit(RLIMIT_NOFILE, &mut rlim);

    if ret != 0 {
        print(b"GETRLIMIT_BASIC:FAIL ret=");
        print_num(ret);
        println(b"");
        return;
    }

    // Check that we got reasonable values (soft <= hard)
    if rlim.rlim_cur > rlim.rlim_max && rlim.rlim_max != RLIM_INFINITY {
        print(b"GETRLIMIT_BASIC:FAIL cur > max");
        println(b"");
        return;
    }

    println(b"GETRLIMIT_BASIC:OK");
}

/// Test: getrlimit for all 16 resources should succeed
fn test_getrlimit_all_resources() {
    let mut rlim = RLimit { rlim_cur: 0, rlim_max: 0 };

    for resource in 0..RLIM_NLIMITS {
        let ret = sys_getrlimit(resource, &mut rlim);
        if ret != 0 {
            print(b"GETRLIMIT_ALL:FAIL resource=");
            print_num(resource as i64);
            print(b" ret=");
            print_num(ret);
            println(b"");
            return;
        }
    }

    println(b"GETRLIMIT_ALL:OK");
}

/// Test: getrlimit with invalid resource returns EINVAL
fn test_getrlimit_einval() {
    let mut rlim = RLimit { rlim_cur: 0, rlim_max: 0 };

    // Resource 100 is way out of range
    let ret = sys_getrlimit(100, &mut rlim);

    if ret == -22 { // EINVAL
        println(b"GETRLIMIT_EINVAL:OK");
    } else {
        print(b"GETRLIMIT_EINVAL:FAIL expected -22, got ");
        print_num(ret);
        println(b"");
    }
}

/// Test: setrlimit can lower the soft limit
fn test_setrlimit_lower_soft() {
    let mut rlim = RLimit { rlim_cur: 0, rlim_max: 0 };

    // Get current limits
    let ret = sys_getrlimit(RLIMIT_NOFILE, &mut rlim);
    if ret != 0 {
        print(b"SETRLIMIT_LOWER:FAIL getrlimit ret=");
        print_num(ret);
        println(b"");
        return;
    }

    // Lower soft limit by half (if not already 0)
    let new_soft = if rlim.rlim_cur > 1 {
        rlim.rlim_cur / 2
    } else {
        rlim.rlim_cur
    };

    let new_rlim = RLimit { rlim_cur: new_soft, rlim_max: rlim.rlim_max };
    let ret = sys_setrlimit(RLIMIT_NOFILE, &new_rlim);

    if ret != 0 {
        print(b"SETRLIMIT_LOWER:FAIL setrlimit ret=");
        print_num(ret);
        println(b"");
        return;
    }

    // Verify it took effect
    let mut verify = RLimit { rlim_cur: 0, rlim_max: 0 };
    sys_getrlimit(RLIMIT_NOFILE, &mut verify);

    if verify.rlim_cur == new_soft {
        // Restore original
        sys_setrlimit(RLIMIT_NOFILE, &rlim);
        println(b"SETRLIMIT_LOWER:OK");
    } else {
        print(b"SETRLIMIT_LOWER:FAIL verify cur=");
        print_num(verify.rlim_cur as i64);
        println(b"");
    }
}

/// Test: setrlimit can raise soft limit to hard limit
fn test_setrlimit_raise_to_hard() {
    let mut rlim = RLimit { rlim_cur: 0, rlim_max: 0 };

    // Get current limits
    let ret = sys_getrlimit(RLIMIT_NOFILE, &mut rlim);
    if ret != 0 {
        print(b"SETRLIMIT_RAISE:FAIL getrlimit ret=");
        print_num(ret);
        println(b"");
        return;
    }

    let original_soft = rlim.rlim_cur;

    // Try to raise soft to hard (should always succeed)
    let new_rlim = RLimit { rlim_cur: rlim.rlim_max, rlim_max: rlim.rlim_max };
    let ret = sys_setrlimit(RLIMIT_NOFILE, &new_rlim);

    if ret != 0 {
        print(b"SETRLIMIT_RAISE:FAIL setrlimit ret=");
        print_num(ret);
        println(b"");
        return;
    }

    // Restore original
    let restore = RLimit { rlim_cur: original_soft, rlim_max: rlim.rlim_max };
    sys_setrlimit(RLIMIT_NOFILE, &restore);

    println(b"SETRLIMIT_RAISE:OK");
}

/// Test: setrlimit with cur > max returns EINVAL
fn test_setrlimit_einval_cur_gt_max() {
    let new_rlim = RLimit { rlim_cur: 2000, rlim_max: 1000 };
    let ret = sys_setrlimit(RLIMIT_NOFILE, &new_rlim);

    if ret == -22 { // EINVAL
        println(b"SETRLIMIT_EINVAL:OK");
    } else {
        print(b"SETRLIMIT_EINVAL:FAIL expected -22, got ");
        print_num(ret);
        println(b"");
    }
}

/// Test: prlimit64 with only old_rlim (get only)
fn test_prlimit64_get_only() {
    let mut old_rlim = RLimit { rlim_cur: 0, rlim_max: 0 };

    // pid=0 means current process, new_rlim=NULL means get only
    let ret = sys_prlimit64(0, RLIMIT_STACK, ptr::null(), &mut old_rlim);

    if ret != 0 {
        print(b"PRLIMIT64_GET:FAIL ret=");
        print_num(ret);
        println(b"");
        return;
    }

    // Check that we got reasonable values
    if old_rlim.rlim_cur > old_rlim.rlim_max && old_rlim.rlim_max != RLIM_INFINITY {
        print(b"PRLIMIT64_GET:FAIL cur > max");
        println(b"");
        return;
    }

    println(b"PRLIMIT64_GET:OK");
}

/// Test: prlimit64 with only new_rlim (set only)
fn test_prlimit64_set_only() {
    // First get current limits
    let mut old_rlim = RLimit { rlim_cur: 0, rlim_max: 0 };
    sys_prlimit64(0, RLIMIT_MEMLOCK, ptr::null(), &mut old_rlim);

    // Set new limits (lower soft by 1 if possible)
    let new_soft = if old_rlim.rlim_cur > 0 { old_rlim.rlim_cur - 1 } else { old_rlim.rlim_cur };
    let new_rlim = RLimit { rlim_cur: new_soft, rlim_max: old_rlim.rlim_max };

    // Set only (old_rlim = NULL)
    let ret = sys_prlimit64(0, RLIMIT_MEMLOCK, &new_rlim, ptr::null_mut());

    if ret != 0 {
        print(b"PRLIMIT64_SET:FAIL ret=");
        print_num(ret);
        println(b"");
        // Restore
        sys_prlimit64(0, RLIMIT_MEMLOCK, &old_rlim, ptr::null_mut());
        return;
    }

    // Verify
    let mut verify = RLimit { rlim_cur: 0, rlim_max: 0 };
    sys_prlimit64(0, RLIMIT_MEMLOCK, ptr::null(), &mut verify);

    if verify.rlim_cur == new_soft {
        // Restore
        sys_prlimit64(0, RLIMIT_MEMLOCK, &old_rlim, ptr::null_mut());
        println(b"PRLIMIT64_SET:OK");
    } else {
        print(b"PRLIMIT64_SET:FAIL verify cur=");
        print_num(verify.rlim_cur as i64);
        println(b"");
    }
}

/// Test: prlimit64 with both new and old (get and set atomically)
fn test_prlimit64_get_and_set() {
    // First get current limits
    let mut orig_rlim = RLimit { rlim_cur: 0, rlim_max: 0 };
    sys_prlimit64(0, RLIMIT_NOFILE, ptr::null(), &mut orig_rlim);

    // Set new and get old atomically
    let new_soft = if orig_rlim.rlim_cur > 1 { orig_rlim.rlim_cur - 1 } else { orig_rlim.rlim_cur };
    let new_rlim = RLimit { rlim_cur: new_soft, rlim_max: orig_rlim.rlim_max };
    let mut old_rlim = RLimit { rlim_cur: 0, rlim_max: 0 };

    let ret = sys_prlimit64(0, RLIMIT_NOFILE, &new_rlim, &mut old_rlim);

    if ret != 0 {
        print(b"PRLIMIT64_BOTH:FAIL ret=");
        print_num(ret);
        println(b"");
        return;
    }

    // Check that old_rlim matches original
    if old_rlim.rlim_cur != orig_rlim.rlim_cur {
        print(b"PRLIMIT64_BOTH:FAIL old_cur mismatch");
        println(b"");
        // Restore
        sys_prlimit64(0, RLIMIT_NOFILE, &orig_rlim, ptr::null_mut());
        return;
    }

    // Restore and verify
    sys_prlimit64(0, RLIMIT_NOFILE, &orig_rlim, ptr::null_mut());
    println(b"PRLIMIT64_BOTH:OK");
}

/// Test: prlimit64 with pid=0 targets current process
fn test_prlimit64_self_pid_zero() {
    let mut rlim0 = RLimit { rlim_cur: 0, rlim_max: 0 };
    let mut rlim1 = RLimit { rlim_cur: 0, rlim_max: 0 };

    // Get with pid=0
    let ret0 = sys_prlimit64(0, RLIMIT_NOFILE, ptr::null(), &mut rlim0);

    // Get with explicit pid=1 (our pid is 1 for init)
    let ret1 = sys_prlimit64(1, RLIMIT_NOFILE, ptr::null(), &mut rlim1);

    if ret0 != 0 || ret1 != 0 {
        print(b"PRLIMIT64_SELF:FAIL ret0=");
        print_num(ret0);
        print(b" ret1=");
        print_num(ret1);
        println(b"");
        return;
    }

    // Both should return the same values
    if rlim0.rlim_cur == rlim1.rlim_cur && rlim0.rlim_max == rlim1.rlim_max {
        println(b"PRLIMIT64_SELF:OK");
    } else {
        print(b"PRLIMIT64_SELF:FAIL values differ");
        println(b"");
    }
}
