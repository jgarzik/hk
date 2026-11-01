//! Swap subsystem tests
//!
//! Tests for swapon/swapoff syscalls.
//!
//! Note: Full swap functionality testing requires a mkswap-formatted swap device.
//! These tests focus on error handling and permission checks.

use super::helpers::{print, println};
use hk_syscall::{sys_swapoff, sys_swapon};

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
    test_swapon_size();
}

/// A 256-page file whose swap header says the area ends at `last_page`
fn swap_file(path: &[u8], last_page: u32) -> bool {
    use hk_syscall::{O_CREAT, O_TRUNC, O_WRONLY, sys_close, sys_ftruncate, sys_open, sys_write};
    let fd = sys_open(path.as_ptr(), O_CREAT | O_TRUNC | O_WRONLY, 0o600);
    if fd < 0 {
        return false;
    }
    let mut hdr = [0u8; 4096];
    // union swap_header: info.version at 1024, info.last_page at 1028
    hdr[1024..1028].copy_from_slice(&1u32.to_ne_bytes());
    hdr[1028..1032].copy_from_slice(&last_page.to_ne_bytes());
    hdr[4086..].copy_from_slice(b"SWAPSPACE2");
    let ok = sys_write(fd as u64, hdr.as_ptr(), 4096) == 4096
        && sys_ftruncate(fd as i32, 256 * 4096) == 0;
    sys_close(fd as u64);
    ok
}

/// swapon checks the header against the file (Linux read_swap_header):
/// last_page 0 is EINVAL, an area longer than the file is EINVAL (not
/// clamped), however long it says it is; one that fits works (hk only:
/// Linux tmpfs and ramfs files cannot be swap files)
fn test_swapon_size() {
    use super::helpers::{host_mode, print_num as num};
    let path = b"/tmp/size_swap\0";
    let mut got = [0i64; 4];
    for (i, last) in [0u32, 256, 0x7fff_ffff, 255].into_iter().enumerate() {
        if i == 3 && host_mode() {
            got[i] = 0;
            break;
        }
        got[i] = if swap_file(path, last) {
            sys_swapon(path.as_ptr(), 0)
        } else {
            -1000
        };
        if got[i] == 0 {
            sys_swapoff(path.as_ptr());
        }
    }
    hk_syscall::sys_unlink(path.as_ptr());
    let ok = got[0] == EINVAL && got[1] == EINVAL && got[2] == EINVAL && got[3] == 0;
    print(b"SWAPON_SIZE");
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL got");
        for g in got {
            print(b" ");
            num(g);
        }
        println(b"");
    }
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

/// Test: swapoff on a nonexistent path is ENOENT (Linux opens it first),
/// on an existing non-swap file EINVAL
fn test_swapoff_einval() {
    print(b"  swapoff EINVAL: ");
    let missing = sys_swapoff(b"/nonexistent_swap\0".as_ptr());
    let ret = sys_swapoff(b"/test.txt\0".as_ptr());
    if missing == -2 && ret == EINVAL {
        println(b"PASS");
    } else {
        print(b"FAIL (got ");
        print_num(missing);
        print(b" / ");
        print_num(ret);
        println(b", expected -2 / -22)");
    }
}

/// Test: swapon on file without valid mkswap header returns EINVAL
fn test_swapon_invalid_header() {
    print(b"  swapon invalid header: ");
    // Create a file with invalid swap header
    use hk_syscall::{O_CREAT, O_WRONLY, sys_close, sys_open, sys_write};

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
