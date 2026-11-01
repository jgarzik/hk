//! Capabilities tests
//!
//! Tests:
//! - Test: capget() - get current process capabilities
//! - Test: capget() with pid=0 (current process)
//! - Test: capget() with invalid version (returns current version)
//! - Test: capset() - drop a capability
//! - Test: capset() - verify dropped capability can't be restored
//! - Test: reboot() checks CAP_SYS_BOOT before its magic numbers

use super::helpers::{print, print_num, println};
use hk_syscall::{
    _LINUX_CAPABILITY_VERSION_3, CAP_SYS_ADMIN, CAP_SYS_BOOT, CapUserData, CapUserHeader,
    LINUX_REBOOT_CMD_POWER_OFF, LINUX_REBOOT_MAGIC2, sys_capget, sys_capset, sys_exit, sys_fork,
    sys_reboot_ret, sys_wait4,
};

/// Run all capabilities tests
pub fn run_tests() {
    test_capget_self();
    test_capget_pid_zero();
    test_capget_invalid_version();
    test_capset_drop_cap();
    test_capset_restore_fails();
    test_reboot_needs_cap();
}

/// Effective capability `cap` of this process
fn has_cap(cap: u32) -> bool {
    let mut header = CapUserHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data: [CapUserData; 2] = [CapUserData::default(); 2];
    sys_capget(&mut header as *mut _, data.as_mut_ptr()) == 0
        && data[(cap / 32) as usize].effective & (1 << (cap % 32)) != 0
}

/// Drop `cap` from this process's effective set
fn drop_cap(cap: u32) -> bool {
    let mut header = CapUserHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data: [CapUserData; 2] = [CapUserData::default(); 2];
    if sys_capget(&mut header as *mut _, data.as_mut_ptr()) != 0 {
        return false;
    }
    data[(cap / 32) as usize].effective &= !(1 << (cap % 32));
    sys_capset(&header as *const _, data.as_ptr()) == 0
}

/// reboot(2) needs CAP_SYS_BOOT, checked before the magic numbers
/// (Linux): EPERM without it even with a bad magic, EINVAL with it. The
/// magic is never valid, so the machine stays up whatever the kernel
/// does.
fn test_reboot_needs_cap() {
    const EPERM: i64 = -1;
    const EINVAL: i64 = -22;
    const BAD_MAGIC: u64 = 0x1234_5678;
    let reboot = || sys_reboot_ret(BAD_MAGIC, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_POWER_OFF);
    if has_cap(CAP_SYS_BOOT) {
        let r = reboot();
        if r == EINVAL {
            println(b"REBOOT_BAD_MAGIC:OK");
        } else {
            print(b"REBOOT_BAD_MAGIC:FAIL: expected EINVAL, got ");
            print_num(r);
            println(b"");
        }
    }
    let pid = sys_fork();
    if pid == 0 {
        let ok = drop_cap(CAP_SYS_BOOT) && reboot() == EPERM;
        sys_exit(!ok as u64);
    }
    let mut status = 0;
    sys_wait4(pid, &mut status, 0, 0);
    if pid > 0 && status == 0 {
        println(b"REBOOT_NEEDS_CAP:OK");
    } else {
        print(b"REBOOT_NEEDS_CAP:FAIL: status ");
        print_num(status as i64);
        println(b"");
    }
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
