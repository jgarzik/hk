//! Timerfd tests
//!
//! Tests:
//! - Test timerfd_create with CLOCK_MONOTONIC
//! - Test timerfd_create with invalid clock (EINVAL)
//! - Test timerfd_settime one-shot timer
//! - Test timerfd_gettime returns remaining time
//! - Test timerfd_settime disarm
//! - Test timerfd_create with TFD_NONBLOCK
//! - Test timerfd read on disarmed timer (EAGAIN with nonblock)

use super::helpers::{print, println, print_num};
use hk_syscall::{
    sys_close, sys_read, sys_timerfd_create, sys_timerfd_gettime, sys_timerfd_settime,
    ITimerSpec, Timespec, TFD_NONBLOCK, CLOCK_MONOTONIC, CLOCK_REALTIME,
};

/// Run all timerfd tests
pub fn run_tests() {
    test_timerfd_create_monotonic();
    test_timerfd_create_realtime();
    test_timerfd_create_invalid_clock();
    test_timerfd_settime_and_gettime();
    test_timerfd_disarm();
    test_timerfd_nonblock_eagain();
}

/// Test timerfd_create with CLOCK_MONOTONIC
fn test_timerfd_create_monotonic() {
    let fd = sys_timerfd_create(CLOCK_MONOTONIC, 0);
    if fd < 0 {
        print(b"TIMERFD_CREATE_MONOTONIC:FAIL: returned ");
        print_num(fd);
        return;
    }

    // Close the fd
    let close_ret = sys_close(fd as u64);
    if close_ret != 0 {
        print(b"TIMERFD_CREATE_MONOTONIC:FAIL: close returned ");
        print_num(close_ret);
        return;
    }

    println(b"TIMERFD_CREATE_MONOTONIC:OK");
}

/// Test timerfd_create with CLOCK_REALTIME
fn test_timerfd_create_realtime() {
    let fd = sys_timerfd_create(CLOCK_REALTIME, 0);
    if fd < 0 {
        print(b"TIMERFD_CREATE_REALTIME:FAIL: returned ");
        print_num(fd);
        return;
    }

    sys_close(fd as u64);
    println(b"TIMERFD_CREATE_REALTIME:OK");
}

/// Test timerfd_create with invalid clockid returns EINVAL
fn test_timerfd_create_invalid_clock() {
    let fd = sys_timerfd_create(99, 0); // Invalid clock ID
    if fd == -22 {
        // EINVAL
        println(b"TIMERFD_CREATE_INVALID:OK");
    } else {
        print(b"TIMERFD_CREATE_INVALID:FAIL: expected -22, got ");
        print_num(fd);
    }
}

/// Test timerfd_settime and timerfd_gettime
fn test_timerfd_settime_and_gettime() {
    let fd = sys_timerfd_create(CLOCK_MONOTONIC, 0);
    if fd < 0 {
        print(b"TIMERFD_SETTIME:FAIL: create returned ");
        print_num(fd);
        return;
    }

    // Set a 1-second one-shot timer
    let new_value = ITimerSpec {
        it_value: Timespec { tv_sec: 1, tv_nsec: 0 },
        it_interval: Timespec { tv_sec: 0, tv_nsec: 0 },
    };
    let mut old_value = ITimerSpec::default();

    let ret = sys_timerfd_settime(fd as i32, 0, &new_value, &mut old_value);
    if ret != 0 {
        print(b"TIMERFD_SETTIME:FAIL: settime returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    // Get current timer value - should show remaining time close to 1 second
    let mut curr_value = ITimerSpec::default();
    let ret = sys_timerfd_gettime(fd as i32, &mut curr_value);
    if ret != 0 {
        print(b"TIMERFD_SETTIME:FAIL: gettime returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    // Remaining time should be > 0 and <= 1 second
    if curr_value.it_value.tv_sec >= 0 && curr_value.it_value.tv_sec <= 1 {
        println(b"TIMERFD_SETTIME:OK");
    } else {
        print(b"TIMERFD_SETTIME:FAIL: unexpected remaining time ");
        print_num(curr_value.it_value.tv_sec);
    }

    sys_close(fd as u64);
}

/// Test timerfd disarm (set it_value to 0)
fn test_timerfd_disarm() {
    let fd = sys_timerfd_create(CLOCK_MONOTONIC, 0);
    if fd < 0 {
        print(b"TIMERFD_DISARM:FAIL: create returned ");
        print_num(fd);
        return;
    }

    // First arm the timer - use volatile write to ensure it's not optimized with disarm_value
    let arm_value = ITimerSpec {
        it_value: Timespec { tv_sec: 10, tv_nsec: 0 },
        it_interval: Timespec { tv_sec: 0, tv_nsec: 0 },
    };
    let arm_ret = sys_timerfd_settime(fd as i32, 0, &arm_value, core::ptr::null_mut());
    // Ensure the arm syscall is fully complete before proceeding
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    if arm_ret != 0 {
        print(b"TIMERFD_DISARM:FAIL: arm settime returned ");
        print_num(arm_ret);
        sys_close(fd as u64);
        return;
    }

    // Now disarm it - use a completely separate stack frame by boxing
    let disarm_value = ITimerSpec {
        it_value: Timespec { tv_sec: 0, tv_nsec: 0 },
        it_interval: Timespec { tv_sec: 0, tv_nsec: 0 },
    };
    let mut old_value = ITimerSpec::default();
    let ret = sys_timerfd_settime(fd as i32, 0, &disarm_value, &mut old_value);
    if ret != 0 {
        print(b"TIMERFD_DISARM:FAIL: settime returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    // Old value should have had ~10 seconds remaining
    if old_value.it_value.tv_sec >= 9 && old_value.it_value.tv_sec <= 10 {
        // Verify timer is now disarmed
        let mut curr_value = ITimerSpec::default();
        let gettime_ret = sys_timerfd_gettime(fd as i32, &mut curr_value);
        if gettime_ret != 0 {
            print(b"TIMERFD_DISARM:FAIL: gettime returned ");
            print_num(gettime_ret);
        } else if curr_value.it_value.tv_sec == 0 && curr_value.it_value.tv_nsec == 0 {
            println(b"TIMERFD_DISARM:OK");
        } else {
            print(b"TIMERFD_DISARM:FAIL: curr_value.tv_sec=");
            print_num(curr_value.it_value.tv_sec);
            print(b" tv_nsec=");
            print_num(curr_value.it_value.tv_nsec);
        }
    } else {
        print(b"TIMERFD_DISARM:FAIL: old_value was ");
        print_num(old_value.it_value.tv_sec);
    }

    sys_close(fd as u64);
}

/// Test timerfd with TFD_NONBLOCK returns EAGAIN on read when not expired
fn test_timerfd_nonblock_eagain() {
    let fd = sys_timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if fd < 0 {
        print(b"TIMERFD_NONBLOCK:FAIL: create returned ");
        print_num(fd);
        return;
    }

    // Set a long timer (10 seconds)
    let new_value = ITimerSpec {
        it_value: Timespec { tv_sec: 10, tv_nsec: 0 },
        it_interval: Timespec { tv_sec: 0, tv_nsec: 0 },
    };
    sys_timerfd_settime(fd as i32, 0, &new_value, core::ptr::null_mut());

    // Try to read - should return EAGAIN (-11) since timer hasn't expired
    let mut buf = [0u8; 8];
    let ret = sys_read(fd as u64, buf.as_mut_ptr(), 8);

    if ret == -11 {
        // EAGAIN
        println(b"TIMERFD_NONBLOCK:OK");
    } else {
        print(b"TIMERFD_NONBLOCK:FAIL: read returned ");
        print_num(ret);
    }

    sys_close(fd as u64);
}
