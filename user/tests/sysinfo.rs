//! System information tests
//!
//! Tests:
//! - Test 70: uname() - get system identification
//! - Test 71: sethostname() - set hostname
//! - Test 72: setdomainname() - set domain name
//! - Test 73: sethostname() EINVAL - too long name
//! - Test 74: clock_settime() - set realtime clock
//! - Test 75: clock_settime() EINVAL - cannot set CLOCK_MONOTONIC
//! - Test 76: clock_settime() EINVAL - invalid nsec value
//! - Test 77: settimeofday() - set time (x86_64 only)
//! - Test 78: settimeofday() EINVAL - invalid usec (x86_64 only)

use super::helpers::{print, println, print_num, print_cstr, starts_with};
use crate::syscall::{sys_sethostname, sys_setdomainname, sys_uname, sys_clock_settime, sys_clock_gettime, UtsName, Timespec};
#[cfg(target_arch = "x86_64")]
use crate::syscall::{sys_settimeofday, sys_gettimeofday, Timeval};

// Clock IDs
const CLOCK_REALTIME: i32 = 0;
const CLOCK_MONOTONIC: i32 = 1;

/// Run all sysinfo tests
pub fn run_tests() {
    test_uname();
    test_sethostname();
    test_setdomainname();
    test_sethostname_einval();
    test_clock_settime_basic();
    test_clock_settime_monotonic_fails();
    test_clock_settime_invalid_nsec();
    #[cfg(target_arch = "x86_64")]
    {
        test_settimeofday_basic();
        test_settimeofday_invalid_usec();
    }
}

/// Test 70: uname() - get system identification
fn test_uname() {

    let mut uts = UtsName::default();
    let ret = sys_uname(&mut uts as *mut UtsName);
    if ret != 0 {
        print(b"UNAME:FAIL: uname() returned ");
        print_num(ret);
    } else {
        // Print the uname values
        print(b"sysname: ");
        print_cstr(&uts.sysname);
        print(b"nodename: ");
        print_cstr(&uts.nodename);
        print(b"release: ");
        print_cstr(&uts.release);
        print(b"machine: ");
        print_cstr(&uts.machine);

        // Verify sysname is "hk"
        if uts.sysname[0] == b'h' && uts.sysname[1] == b'k' && uts.sysname[2] == 0 {
            println(b"UNAME:OK");
        } else {
            println(b"UNAME:FAIL: sysname should be 'hk'");
        }
    }
}

/// Test 71: sethostname() - set hostname
fn test_sethostname() {

    let hostname = b"testhost";
    let ret = sys_sethostname(hostname.as_ptr(), hostname.len() as u64);
    if ret != 0 {
        print(b"SETHOSTNAME:FAIL: sethostname() returned ");
        print_num(ret);
    } else {
        // Verify via uname
        let mut uts2 = UtsName::default();
        let ret2 = sys_uname(&mut uts2 as *mut UtsName);
        if ret2 != 0 {
            print(b"SETHOSTNAME:FAIL: uname() returned ");
            print_num(ret2);
        } else {
            if starts_with(&uts2.nodename, b"testhost") {
                println(b"SETHOSTNAME:OK");
            } else {
                print(b"SETHOSTNAME:FAIL: nodename is '");
                print_cstr(&uts2.nodename);
                println(b"'");
            }
        }
    }
}

/// Test 72: setdomainname() - set domain name
fn test_setdomainname() {

    let domain = b"testdomain";
    let ret = sys_setdomainname(domain.as_ptr(), domain.len() as u64);
    if ret != 0 {
        print(b"SETDOMAINNAME:FAIL: setdomainname() returned ");
        print_num(ret);
    } else {
        // Verify via uname
        let mut uts3 = UtsName::default();
        let ret3 = sys_uname(&mut uts3 as *mut UtsName);
        if ret3 != 0 {
            print(b"SETDOMAINNAME:FAIL: uname() returned ");
            print_num(ret3);
        } else {
            if starts_with(&uts3.domainname, b"testdomain") {
                println(b"SETDOMAINNAME:OK");
            } else {
                print(b"SETDOMAINNAME:FAIL: domainname is '");
                print_cstr(&uts3.domainname);
                println(b"'");
            }
        }
    }
}

/// Test 73: sethostname() with too-long name (should fail with EINVAL)
fn test_sethostname_einval() {

    // 65 bytes is > 64 (max length)
    let long_name = [b'x'; 65];
    let ret = sys_sethostname(long_name.as_ptr(), 65);
    if ret == -22 {
        // EINVAL
        println(b"SETHOSTNAME_EINVAL:OK");
    } else {
        print(b"SETHOSTNAME_EINVAL:FAIL: expected -22 (EINVAL), got ");
        print_num(ret);
    }
}

/// Test 74: clock_settime() - set realtime clock
fn test_clock_settime_basic() {
    // Get current time
    let mut ts_before = Timespec { tv_sec: 0, tv_nsec: 0 };
    let ret = sys_clock_gettime(CLOCK_REALTIME, &mut ts_before);
    if ret != 0 {
        print(b"CLOCK_SETTIME:FAIL: clock_gettime() returned ");
        print_num(ret);
        return;
    }

    // Set time to a specific value (current time + 100 seconds)
    let new_time = Timespec {
        tv_sec: ts_before.tv_sec + 100,
        tv_nsec: 0,
    };
    let ret = sys_clock_settime(CLOCK_REALTIME, &new_time);
    if ret != 0 {
        print(b"CLOCK_SETTIME:FAIL: clock_settime() returned ");
        print_num(ret);
        return;
    }

    // Read back and verify
    let mut ts_after = Timespec { tv_sec: 0, tv_nsec: 0 };
    let ret = sys_clock_gettime(CLOCK_REALTIME, &mut ts_after);
    if ret != 0 {
        print(b"CLOCK_SETTIME:FAIL: clock_gettime() after set returned ");
        print_num(ret);
        return;
    }

    // The new time should be close to what we set (within a few seconds)
    let diff = ts_after.tv_sec - new_time.tv_sec;
    if diff >= 0 && diff < 5 {
        println(b"CLOCK_SETTIME:OK");
    } else {
        print(b"CLOCK_SETTIME:FAIL: time difference too large: ");
        print_num(diff);
    }
}

/// Test 75: clock_settime() EINVAL - cannot set CLOCK_MONOTONIC
fn test_clock_settime_monotonic_fails() {
    let ts = Timespec { tv_sec: 1000, tv_nsec: 0 };
    let ret = sys_clock_settime(CLOCK_MONOTONIC, &ts);
    if ret == -22 {
        // EINVAL
        println(b"CLOCK_SETTIME_MONOTONIC:OK");
    } else {
        print(b"CLOCK_SETTIME_MONOTONIC:FAIL: expected -22 (EINVAL), got ");
        print_num(ret);
    }
}

/// Test 76: clock_settime() EINVAL - invalid nsec value
fn test_clock_settime_invalid_nsec() {
    let ts = Timespec { tv_sec: 1000, tv_nsec: 1_000_000_000 }; // nsec out of range
    let ret = sys_clock_settime(CLOCK_REALTIME, &ts);
    if ret == -22 {
        // EINVAL
        println(b"CLOCK_SETTIME_INVALID_NSEC:OK");
    } else {
        print(b"CLOCK_SETTIME_INVALID_NSEC:FAIL: expected -22 (EINVAL), got ");
        print_num(ret);
    }
}

/// Test 77: settimeofday() - set time (x86_64 only)
#[cfg(target_arch = "x86_64")]
fn test_settimeofday_basic() {
    // Get current time
    let mut tv_before = Timeval { tv_sec: 0, tv_usec: 0 };
    let ret = sys_gettimeofday(&mut tv_before, core::ptr::null_mut());
    if ret != 0 {
        print(b"SETTIMEOFDAY:FAIL: gettimeofday() returned ");
        print_num(ret);
        return;
    }

    // Set time to current + 200 seconds
    let new_time = Timeval {
        tv_sec: tv_before.tv_sec + 200,
        tv_usec: 0,
    };
    let ret = sys_settimeofday(&new_time, core::ptr::null());
    if ret != 0 {
        print(b"SETTIMEOFDAY:FAIL: settimeofday() returned ");
        print_num(ret);
        return;
    }

    // Read back and verify
    let mut tv_after = Timeval { tv_sec: 0, tv_usec: 0 };
    let ret = sys_gettimeofday(&mut tv_after, core::ptr::null_mut());
    if ret != 0 {
        print(b"SETTIMEOFDAY:FAIL: gettimeofday() after set returned ");
        print_num(ret);
        return;
    }

    // The new time should be close to what we set
    let diff = tv_after.tv_sec - new_time.tv_sec;
    if diff >= 0 && diff < 5 {
        println(b"SETTIMEOFDAY:OK");
    } else {
        print(b"SETTIMEOFDAY:FAIL: time difference too large: ");
        print_num(diff);
    }
}

/// Test 78: settimeofday() EINVAL - invalid usec (x86_64 only)
#[cfg(target_arch = "x86_64")]
fn test_settimeofday_invalid_usec() {
    let tv = Timeval { tv_sec: 1000, tv_usec: 1_000_000 }; // usec out of range
    let ret = sys_settimeofday(&tv, core::ptr::null());
    if ret == -22 {
        // EINVAL
        println(b"SETTIMEOFDAY_INVALID_USEC:OK");
    } else {
        print(b"SETTIMEOFDAY_INVALID_USEC:FAIL: expected -22 (EINVAL), got ");
        print_num(ret);
    }
}
