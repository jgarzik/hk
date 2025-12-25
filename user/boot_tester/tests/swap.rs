//! Swap subsystem tests
//!
//! Tests for swapon/swapoff syscalls.
//!
//! Note: Full swap functionality testing requires a mkswap-formatted swap device.
//! These tests focus on error handling and permission checks.

use super::helpers::{print, println};
use hk_syscall::{sys_swapon, sys_swapoff};

#[allow(dead_code)]
const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EINVAL: i64 = -22;

/// Run all swap tests
pub fn run_tests() {
    println(b"=== Swap Tests ===");

    test_swapon_enoent();
    test_swapoff_einval();
    test_swapon_invalid_header();
}

/// Test: swapon on non-existent path returns ENOENT
fn test_swapon_enoent() {
    print(b"  swapon ENOENT: ");
    let path = b"/nonexistent_swap\0";
    let ret = sys_swapon(path.as_ptr(), 0);
    if ret == ENOENT {
        println(b"PASS");
    } else {
        print(b"FAIL (got ");
        print_num(ret);
        println(b")");
    }
}

/// Test: swapoff on non-active path returns EINVAL
fn test_swapoff_einval() {
    print(b"  swapoff EINVAL: ");
    let path = b"/nonexistent_swap\0";
    let ret = sys_swapoff(path.as_ptr());
    if ret == EINVAL {
        println(b"PASS");
    } else {
        print(b"FAIL (got ");
        print_num(ret);
        println(b")");
    }
}

/// Test: swapon on file without valid mkswap header returns EINVAL
fn test_swapon_invalid_header() {
    print(b"  swapon invalid header: ");
    // Create a file with invalid swap header
    use hk_syscall::{sys_close, sys_open, sys_write, O_CREAT, O_WRONLY};

    let path = b"/tmp/invalid_swap\0";

    // Create file with invalid content
    let fd = sys_open(path.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd < 0 {
        println(b"SKIP (cannot create file)");
        return;
    }

    // Write some garbage data
    let garbage = [0u8; 4096];
    sys_write(fd as u64, garbage.as_ptr(), garbage.len() as u64);
    sys_close(fd as u64);

    // Try to swapon on it - should fail with EINVAL due to missing magic
    let ret = sys_swapon(path.as_ptr(), 0);
    if ret == EINVAL {
        println(b"PASS");
    } else {
        print(b"FAIL (got ");
        print_num(ret);
        println(b")");
    }

    // Cleanup
    hk_syscall::sys_unlink(path.as_ptr());
}

fn print_num(n: i64) {
    let mut buf = [0u8; 21];
    let mut idx = 20;
    let mut val = if n < 0 { -n as u64 } else { n as u64 };

    if val == 0 {
        print(b"0");
        return;
    }

    while val > 0 && idx > 0 {
        idx -= 1;
        buf[idx] = b'0' + (val % 10) as u8;
        val /= 10;
    }

    if n < 0 && idx > 0 {
        idx -= 1;
        buf[idx] = b'-';
    }

    print(&buf[idx..21]);
}
