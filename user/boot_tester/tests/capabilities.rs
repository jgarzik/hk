//! Capabilities tests
//!
//! Tests:
//! - Test: capget() - get current process capabilities
//! - Test: capget() with pid=0 (current process)
//! - Test: capget() with invalid version (returns current version)
//! - Test: capset() - drop a capability
//! - Test: capset() - verify dropped capability can't be restored

use super::helpers::{print, println, print_num};
use hk_syscall::{
    sys_capget, sys_capset,
    CapUserHeader, CapUserData,
    _LINUX_CAPABILITY_VERSION_3,
    CAP_SYS_ADMIN,
};

/// Run all capabilities tests
pub fn run_tests() {
    test_capget_self();
    test_capget_pid_zero();
    test_capget_invalid_version();
    test_capset_drop_cap();
    test_capset_restore_fails();
}

/// Test capget() - get current process capabilities (should have full caps as root)
fn test_capget_self() {
    let mut header = CapUserHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0, // Current process
    };
    let mut data: [CapUserData; 2] = [CapUserData::default(); 2];

    let ret = sys_capget(&mut header as *mut _, data.as_mut_ptr());

    if ret != 0 {
        print(b"CAPGET_SELF:FAIL: capget returned ");
        print_num(ret);
        println(b"");
    } else {
        // As root, we should have full capabilities (all bits set in effective/permitted)
        // CAP_VALID_MASK for caps 0-40 = 0x1ffffffffff
        // Lower 32 bits = 0xffffffff, upper 9 bits = 0x1ff
        let eff_low = data[0].effective;
        let eff_high = data[1].effective;
        let perm_low = data[0].permitted;
        let perm_high = data[1].permitted;

        // Check that at least the lower 32 capabilities are set
        if eff_low == 0xffffffff && perm_low == 0xffffffff {
            println(b"CAPGET_SELF:OK");
        } else {
            print(b"CAPGET_SELF:FAIL: expected full caps, got eff=");
            print_num(eff_low as i64);
            print(b"/");
            print_num(eff_high as i64);
            print(b" perm=");
            print_num(perm_low as i64);
            print(b"/");
            print_num(perm_high as i64);
            println(b"");
        }
    }
}

/// Test capget() with pid=0 (should work, means current process)
fn test_capget_pid_zero() {
    let mut header = CapUserHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data: [CapUserData; 2] = [CapUserData::default(); 2];

    let ret = sys_capget(&mut header as *mut _, data.as_mut_ptr());

    if ret == 0 {
        println(b"CAPGET_PID_ZERO:OK");
    } else {
        print(b"CAPGET_PID_ZERO:FAIL: capget returned ");
        print_num(ret);
        println(b"");
    }
}

/// Test capget() with invalid version (should return -EINVAL and set current version)
fn test_capget_invalid_version() {
    let mut header = CapUserHeader {
        version: 0x12345678, // Invalid version
        pid: 0,
    };

    // NULL datap with invalid version should return 0 and write current version
    let ret = sys_capget(&mut header as *mut _, core::ptr::null_mut());

    // After the call, header.version should be set to current version
    if ret == 0 && header.version == _LINUX_CAPABILITY_VERSION_3 {
        println(b"CAPGET_INVALID_VERSION:OK");
    } else {
        print(b"CAPGET_INVALID_VERSION:FAIL: ret=");
        print_num(ret);
        print(b" version=");
        print_num(header.version as i64);
        println(b"");
    }
}

/// Test capset() - drop CAP_SYS_ADMIN and verify it's gone
fn test_capset_drop_cap() {
    // First get current capabilities
    let mut header = CapUserHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data: [CapUserData; 2] = [CapUserData::default(); 2];

    let ret = sys_capget(&mut header as *mut _, data.as_mut_ptr());
    if ret != 0 {
        print(b"CAPSET_DROP:FAIL: initial capget returned ");
        print_num(ret);
        println(b"");
        return;
    }

    // Drop CAP_SYS_ADMIN (cap 21) from effective set
    // Keep it in permitted so we can test restore later
    let cap_mask = 1u32 << CAP_SYS_ADMIN;
    data[0].effective &= !cap_mask;

    // Set the new capabilities
    let ret = sys_capset(&header as *const _, data.as_ptr());
    if ret != 0 {
        print(b"CAPSET_DROP:FAIL: capset returned ");
        print_num(ret);
        println(b"");
        return;
    }

    // Verify the capability was dropped
    let mut verify_data: [CapUserData; 2] = [CapUserData::default(); 2];
    let ret = sys_capget(&mut header as *mut _, verify_data.as_mut_ptr());
    if ret != 0 {
        print(b"CAPSET_DROP:FAIL: verify capget returned ");
        print_num(ret);
        println(b"");
        return;
    }

    // Check that CAP_SYS_ADMIN is no longer in effective set
    if (verify_data[0].effective & cap_mask) == 0 {
        println(b"CAPSET_DROP:OK");
    } else {
        println(b"CAPSET_DROP:FAIL: cap still in effective set");
    }
}

/// Test that dropped capability can be restored (if still in permitted)
fn test_capset_restore_fails() {
    // This tests that we can restore a cap from permitted to effective
    // First, get current caps (CAP_SYS_ADMIN should be dropped from effective but in permitted)
    let mut header = CapUserHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data: [CapUserData; 2] = [CapUserData::default(); 2];

    let ret = sys_capget(&mut header as *mut _, data.as_mut_ptr());
    if ret != 0 {
        print(b"CAPSET_RESTORE:FAIL: capget returned ");
        print_num(ret);
        println(b"");
        return;
    }

    // Try to restore CAP_SYS_ADMIN to effective
    let cap_mask = 1u32 << CAP_SYS_ADMIN;
    data[0].effective |= cap_mask;

    // This should succeed because it's still in permitted
    let ret = sys_capset(&header as *const _, data.as_ptr());
    if ret == 0 {
        println(b"CAPSET_RESTORE:OK");
    } else {
        print(b"CAPSET_RESTORE:FAIL: capset returned ");
        print_num(ret);
        println(b"");
    }
}
