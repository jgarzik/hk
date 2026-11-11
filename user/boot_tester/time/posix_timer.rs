//! POSIX timer tests
//!
//! Tests:
//! - Test timer_create with CLOCK_MONOTONIC
//! - Test timer_create with CLOCK_REALTIME
//! - Test timer_create with invalid clock (EINVAL)
//! - Test timer_settime and timer_gettime
//! - Test timer_disarm (set it_value to 0)
//! - Test timer_delete
//! - Test timer_getoverrun (initial value is 0)
//! - Test multiple timers
//! - timer_create whose id cannot be stored leaves no timer

use crate::harness::{pass, verdict};
use crate::helpers::{print, print_num};
use hk_syscall::{
    CLOCK_MONOTONIC, CLOCK_REALTIME, ITimerSpec, Timespec, sys_exit, sys_fork, sys_timer_create,
    sys_timer_delete, sys_timer_getoverrun, sys_timer_gettime, sys_timer_settime, sys_wait4,
};

/// Run all POSIX timer tests
pub fn run_tests() {
    test_timer_create_monotonic();
    test_timer_create_realtime();
    test_timer_create_invalid_clock();
    test_timer_settime_and_gettime();
    test_timer_disarm();
    test_timer_delete();
    test_timer_getoverrun_initial();
    test_timer_create_multiple();
    test_timer_settime_old_value();
    test_timer_create_efault();
}

/// timer_create with a timerid it cannot write is EFAULT and leaves no
/// timer: the id it took is not one (Linux do_timer_create unhashes it
/// after the failed copy_to_user), and the next timer takes the id
/// after it. In a fork child, whose ids start at 0.
fn test_timer_create_efault() {
    let pid = sys_fork();
    if pid == 0 {
        let mut bad = 0u64;
        // NULL, then an unmapped address
        if sys_timer_create(CLOCK_MONOTONIC, core::ptr::null(), core::ptr::null_mut()) != -14 {
            bad |= 1;
        }
        if sys_timer_create(CLOCK_MONOTONIC, core::ptr::null(), 8 as *mut i32) != -14 {
            bad |= 2;
        }
        let mut id: i32 = -1;
        if sys_timer_create(CLOCK_MONOTONIC, core::ptr::null(), &mut id) != 0 || id != 2 {
            bad |= 4;
        }
        if sys_timer_delete(0) != -22 || sys_timer_delete(1) != -22 {
            bad |= 8;
        }
        let mut cur = ITimerSpec::default();
        if sys_timer_gettime(1, &mut cur) != -22 {
            bad |= 16;
        }
        if sys_timer_delete(id) != 0 {
            bad |= 32;
        }
        sys_exit(bad);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    verdict(b"TIMER_CREATE_EFAULT", st == 0, (st >> 8) as i64);
}

/// Test timer_create with CLOCK_MONOTONIC
fn test_timer_create_monotonic() {
    let mut timerid: i32 = -1;
    let ret = sys_timer_create(CLOCK_MONOTONIC, core::ptr::null(), &mut timerid);
    if ret < 0 {
        print(b"TIMER_CREATE_MONOTONIC:FAIL: returned ");
        print_num(ret);
        return;
    }

    if timerid < 0 {
        print(b"TIMER_CREATE_MONOTONIC:FAIL: invalid timerid ");
        print_num(timerid as i64);
        return;
    }

    // Clean up
    let del_ret = sys_timer_delete(timerid);
    if del_ret != 0 {
        print(b"TIMER_CREATE_MONOTONIC:FAIL: delete returned ");
        print_num(del_ret);
        return;
    }

    pass(b"TIMER_CREATE_MONOTONIC");
}

/// Test timer_create with CLOCK_REALTIME
fn test_timer_create_realtime() {
    let mut timerid: i32 = -1;
    let ret = sys_timer_create(CLOCK_REALTIME, core::ptr::null(), &mut timerid);
    if ret < 0 {
        print(b"TIMER_CREATE_REALTIME:FAIL: returned ");
        print_num(ret);
        return;
    }

    sys_timer_delete(timerid);
    pass(b"TIMER_CREATE_REALTIME");
}

/// Test timer_create with invalid clockid returns EINVAL
fn test_timer_create_invalid_clock() {
    let mut timerid: i32 = -1;
    let ret = sys_timer_create(99, core::ptr::null(), &mut timerid); // Invalid clock ID
    if ret == -22 {
        // EINVAL
        pass(b"TIMER_CREATE_INVALID");
    } else {
        print(b"TIMER_CREATE_INVALID:FAIL: expected -22, got ");
        print_num(ret);
    }
}

/// Test timer_settime and timer_gettime
fn test_timer_settime_and_gettime() {
    let mut timerid: i32 = -1;
    let ret = sys_timer_create(CLOCK_MONOTONIC, core::ptr::null(), &mut timerid);
    if ret < 0 {
        print(b"TIMER_SETTIME:FAIL: create returned ");
        print_num(ret);
        return;
    }

    // Set a 1-second one-shot timer
    let new_value = ITimerSpec {
        it_value: Timespec {
            tv_sec: 1,
            tv_nsec: 0,
        },
        it_interval: Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    let mut old_value = ITimerSpec::default();

    let ret = sys_timer_settime(timerid, 0, &new_value, &mut old_value);
    if ret != 0 {
        print(b"TIMER_SETTIME:FAIL: settime returned ");
        print_num(ret);
        sys_timer_delete(timerid);
        return;
    }

    // Get current timer value - should show remaining time close to 1 second
    let mut curr_value = ITimerSpec::default();
    let ret = sys_timer_gettime(timerid, &mut curr_value);
    if ret != 0 {
        print(b"TIMER_SETTIME:FAIL: gettime returned ");
        print_num(ret);
        sys_timer_delete(timerid);
        return;
    }

    // Remaining time should be > 0 and <= 1 second
    if curr_value.it_value.tv_sec >= 0 && curr_value.it_value.tv_sec <= 1 {
        pass(b"TIMER_SETTIME");
    } else {
        print(b"TIMER_SETTIME:FAIL: unexpected remaining time ");
        print_num(curr_value.it_value.tv_sec);
    }

    sys_timer_delete(timerid);
}

/// Test timer disarm (set it_value to 0)
fn test_timer_disarm() {
    let mut timerid: i32 = -1;
    let ret = sys_timer_create(CLOCK_MONOTONIC, core::ptr::null(), &mut timerid);
    if ret < 0 {
        print(b"TIMER_DISARM:FAIL: create returned ");
        print_num(ret);
        return;
    }

    // First arm the timer
    let arm_value = ITimerSpec {
        it_value: Timespec {
            tv_sec: 10,
            tv_nsec: 0,
        },
        it_interval: Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    let arm_ret = sys_timer_settime(timerid, 0, &arm_value, core::ptr::null_mut());
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    if arm_ret != 0 {
        print(b"TIMER_DISARM:FAIL: arm settime returned ");
        print_num(arm_ret);
        sys_timer_delete(timerid);
        return;
    }

    // Now disarm it
    let disarm_value = ITimerSpec {
        it_value: Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_interval: Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    let mut old_value = ITimerSpec::default();
    let ret = sys_timer_settime(timerid, 0, &disarm_value, &mut old_value);
    if ret != 0 {
        print(b"TIMER_DISARM:FAIL: settime returned ");
        print_num(ret);
        sys_timer_delete(timerid);
        return;
    }

    // Old value should have had ~10 seconds remaining
    if old_value.it_value.tv_sec >= 9 && old_value.it_value.tv_sec <= 10 {
        // Verify timer is now disarmed
        let mut curr_value = ITimerSpec::default();
        let gettime_ret = sys_timer_gettime(timerid, &mut curr_value);
        if gettime_ret != 0 {
            print(b"TIMER_DISARM:FAIL: gettime returned ");
            print_num(gettime_ret);
        } else if curr_value.it_value.tv_sec == 0 && curr_value.it_value.tv_nsec == 0 {
            pass(b"TIMER_DISARM");
        } else {
            print(b"TIMER_DISARM:FAIL: curr_value.tv_sec=");
            print_num(curr_value.it_value.tv_sec);
            print(b" tv_nsec=");
            print_num(curr_value.it_value.tv_nsec);
        }
    } else {
        print(b"TIMER_DISARM:FAIL: old_value was ");
        print_num(old_value.it_value.tv_sec);
    }

    sys_timer_delete(timerid);
}

/// Test timer_delete
fn test_timer_delete() {
    let mut timerid: i32 = -1;
    let ret = sys_timer_create(CLOCK_MONOTONIC, core::ptr::null(), &mut timerid);
    if ret < 0 {
        print(b"TIMER_DELETE:FAIL: create returned ");
        print_num(ret);
        return;
    }

    // Set a timer
    let new_value = ITimerSpec {
        it_value: Timespec {
            tv_sec: 10,
            tv_nsec: 0,
        },
        it_interval: Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    sys_timer_settime(timerid, 0, &new_value, core::ptr::null_mut());

    // Delete the timer
    let del_ret = sys_timer_delete(timerid);
    if del_ret != 0 {
        print(b"TIMER_DELETE:FAIL: delete returned ");
        print_num(del_ret);
        return;
    }

    // Subsequent operations on deleted timer should return EINVAL
    let mut curr_value = ITimerSpec::default();
    let get_ret = sys_timer_gettime(timerid, &mut curr_value);
    if get_ret == -22 {
        // EINVAL
        pass(b"TIMER_DELETE");
    } else {
        print(b"TIMER_DELETE:FAIL: gettime after delete returned ");
        print_num(get_ret);
    }
}

/// Test timer_getoverrun returns 0 initially
fn test_timer_getoverrun_initial() {
    let mut timerid: i32 = -1;
    let ret = sys_timer_create(CLOCK_MONOTONIC, core::ptr::null(), &mut timerid);
    if ret < 0 {
        print(b"TIMER_GETOVERRUN:FAIL: create returned ");
        print_num(ret);
        return;
    }

    // Check initial overrun count
    let overrun = sys_timer_getoverrun(timerid);
    if overrun == 0 {
        pass(b"TIMER_GETOVERRUN");
    } else {
        print(b"TIMER_GETOVERRUN:FAIL: expected 0, got ");
        print_num(overrun);
    }

    sys_timer_delete(timerid);
}

/// Test creating multiple timers
fn test_timer_create_multiple() {
    let mut timerid1: i32 = -1;
    let mut timerid2: i32 = -1;
    let mut timerid3: i32 = -1;

    let ret1 = sys_timer_create(CLOCK_MONOTONIC, core::ptr::null(), &mut timerid1);
    let ret2 = sys_timer_create(CLOCK_MONOTONIC, core::ptr::null(), &mut timerid2);
    let ret3 = sys_timer_create(CLOCK_MONOTONIC, core::ptr::null(), &mut timerid3);

    if ret1 < 0 || ret2 < 0 || ret3 < 0 {
        print(b"TIMER_CREATE_MULTIPLE:FAIL: create returned ");
        print_num(ret1);
        print(b", ");
        print_num(ret2);
        print(b", ");
        print_num(ret3);
        return;
    }

    // Each should have a unique timer ID
    if timerid1 != timerid2 && timerid2 != timerid3 && timerid1 != timerid3 {
        pass(b"TIMER_CREATE_MULTIPLE");
    } else {
        print(b"TIMER_CREATE_MULTIPLE:FAIL: duplicate timer IDs ");
        print_num(timerid1 as i64);
        print(b", ");
        print_num(timerid2 as i64);
        print(b", ");
        print_num(timerid3 as i64);
    }

    sys_timer_delete(timerid1);
    sys_timer_delete(timerid2);
    sys_timer_delete(timerid3);
}

/// Test timer_settime returns old value correctly
fn test_timer_settime_old_value() {
    let mut timerid: i32 = -1;
    let ret = sys_timer_create(CLOCK_MONOTONIC, core::ptr::null(), &mut timerid);
    if ret < 0 {
        print(b"TIMER_SETTIME_OLD:FAIL: create returned ");
        print_num(ret);
        return;
    }

    // First arm the timer for 5 seconds
    let first_value = ITimerSpec {
        it_value: Timespec {
            tv_sec: 5,
            tv_nsec: 0,
        },
        it_interval: Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    sys_timer_settime(timerid, 0, &first_value, core::ptr::null_mut());

    // Re-arm for 10 seconds and capture old value
    let second_value = ITimerSpec {
        it_value: Timespec {
            tv_sec: 10,
            tv_nsec: 0,
        },
        it_interval: Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    let mut old_value = ITimerSpec::default();
    let ret = sys_timer_settime(timerid, 0, &second_value, &mut old_value);

    if ret != 0 {
        print(b"TIMER_SETTIME_OLD:FAIL: settime returned ");
        print_num(ret);
        sys_timer_delete(timerid);
        return;
    }

    // Old value should have had ~5 seconds remaining
    if old_value.it_value.tv_sec >= 4 && old_value.it_value.tv_sec <= 5 {
        pass(b"TIMER_SETTIME_OLD");
    } else {
        print(b"TIMER_SETTIME_OLD:FAIL: old_value was ");
        print_num(old_value.it_value.tv_sec);
    }

    sys_timer_delete(timerid);
}
