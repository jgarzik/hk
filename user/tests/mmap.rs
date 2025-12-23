//! Memory mapping tests
//!
//! Tests for mmap and munmap syscalls:
//! - Anonymous mmap (MAP_ANONYMOUS | MAP_PRIVATE)
//! - Write/read to mmap'd memory
//! - munmap to release memory
//! - Large anonymous mmap with demand paging
//! - mlock/mlock2/munlock/mlockall/munlockall

use super::helpers::{print, println, print_num};
use crate::syscall::{
    sys_mmap, sys_mprotect, sys_munmap, sys_mlock, sys_mlock2, sys_munlock,
    sys_mlockall, sys_munlockall,
    MAP_ANONYMOUS, MAP_LOCKED, MAP_PRIVATE, MAP_SHARED,
    PROT_READ, PROT_WRITE, PROT_EXEC,
    MLOCK_ONFAULT, MCL_CURRENT, MCL_ONFAULT,
};

/// Run all mmap tests
pub fn run_tests() {
    test_anonymous_mmap();
    test_mmap_write_read();
    test_munmap();
    test_large_anonymous_mmap();
    test_mmap_locked();
    // mprotect tests
    test_mprotect_add_write();
    test_mprotect_zero_len();
    test_mprotect_invalid_addr();
    // MAP_SHARED tests
    test_mmap_shared_anon();
    // mlock tests
    test_mlock_basic();
    test_mlock2_onfault();
    test_mlock2_invalid_flags();
    test_mlockall_current();
    test_mlockall_invalid_flags();
    test_munlockall();
}

/// Test: Basic anonymous mmap
fn test_anonymous_mmap() {

    // Map one page (4096 bytes) of anonymous memory
    let ptr = sys_mmap(
        0,                              // addr (let kernel choose)
        4096,                           // length
        PROT_READ | PROT_WRITE,         // prot
        MAP_PRIVATE | MAP_ANONYMOUS,    // flags
        -1,                             // fd (unused for anonymous)
        0,                              // offset
    );

    if ptr < 0 {
        print(b"MMAP_ANON:FAIL errno=");
        print_num(-ptr);
        return;
    }

    print(b"mmap returned ");
    print_num(ptr);

    // Clean up
    let ret = sys_munmap(ptr as u64, 4096);
    if ret == 0 {
        println(b"MMAP_ANON:OK");
    } else {
        print(b"MMAP_ANON:FAIL munmap errno=");
        print_num(-ret);
    }
}

/// Test: Write to and read from mmap'd memory
fn test_mmap_write_read() {

    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MMAP_RW:FAIL mmap errno=");
        print_num(-ptr);
        return;
    }

    // Write a pattern
    let pattern: u32 = 0xDEADBEEF;
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, pattern);
    }

    // Read it back
    let read_val = unsafe {
        core::ptr::read_volatile(ptr as *const u32)
    };

    if read_val == pattern {
        println(b"MMAP_RW:OK");
    } else {
        print(b"MMAP_RW:FAIL expected 0xDEADBEEF got ");
        print_num(read_val as i64);
    }

    sys_munmap(ptr as u64, 4096);
}

/// Test: munmap releases memory
fn test_munmap() {

    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MUNMAP:FAIL mmap errno=");
        print_num(-ptr);
        return;
    }

    // Unmap the memory
    let ret = sys_munmap(ptr as u64, 4096);
    if ret == 0 {
        println(b"MUNMAP:OK");
    } else {
        print(b"MUNMAP:FAIL errno=");
        print_num(-ret);
    }
}

/// Test: Large anonymous mmap with demand paging
fn test_large_anonymous_mmap() {

    let size: u64 = 1024 * 1024; // 1MB
    let ptr = sys_mmap(
        0,
        size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MMAP_LARGE:FAIL mmap errno=");
        print_num(-ptr);
        return;
    }

    // Touch multiple pages to trigger demand paging
    // Write a byte to every 16th page (every 64KB)
    let base = ptr as u64;
    let mut success = true;
    for i in 0..16u64 {
        let offset = i * 4096 * 16; // Every 16 pages = 64KB
        let addr = base + offset;
        let expected_val = (i & 0xFF) as u8;

        // Write
        unsafe {
            core::ptr::write_volatile(addr as *mut u8, expected_val);
        }

        // Read back and verify
        let read_val = unsafe {
            core::ptr::read_volatile(addr as *const u8)
        };

        if read_val != expected_val {
            print(b"MMAP_LARGE:FAIL page ");
            print_num(i as i64);
            print(b" expected ");
            print_num(expected_val as i64);
            print(b" got ");
            print_num(read_val as i64);
            success = false;
            break;
        }
    }

    // Clean up
    sys_munmap(base, size);

    if success {
        println(b"MMAP_LARGE:OK");
    }
}

/// Test: mmap with MAP_LOCKED flag (Linux ABI compliance)
fn test_mmap_locked() {
    // Map with MAP_LOCKED - pages should be locked in memory
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MMAP_LOCKED:FAIL mmap errno=");
        print_num(-ptr);
        println(b"");
        return;
    }

    // Write to verify it's accessible (should be locked/populated)
    unsafe {
        core::ptr::write_volatile(ptr as *mut u8, 42);
    }

    let val = unsafe { core::ptr::read_volatile(ptr as *const u8) };
    if val != 42 {
        print(b"MMAP_LOCKED:FAIL read mismatch got ");
        print_num(val as i64);
        println(b"");
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    println(b"MMAP_LOCKED:OK");
}

// ============================================================================
// mlock tests
// ============================================================================

/// Test: Basic mlock on anonymous mmap'd region
fn test_mlock_basic() {
    // mmap a page
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MLOCK_BASIC:FAIL mmap errno=");
        print_num(-ptr);
        println(b"");
        return;
    }

    // Lock it
    let ret = sys_mlock(ptr as u64, 4096);
    if ret != 0 {
        print(b"MLOCK_BASIC:FAIL mlock errno=");
        print_num(-ret);
        println(b"");
        sys_munmap(ptr as u64, 4096);
        return;
    }

    // Write to verify it's accessible (pages should be populated after mlock)
    unsafe {
        core::ptr::write_volatile(ptr as *mut u8, 42);
    }

    // Read it back
    let val = unsafe { core::ptr::read_volatile(ptr as *const u8) };
    if val != 42 {
        print(b"MLOCK_BASIC:FAIL read mismatch got ");
        print_num(val as i64);
        println(b"");
        sys_munmap(ptr as u64, 4096);
        return;
    }

    // Unlock
    let ret = sys_munlock(ptr as u64, 4096);
    if ret != 0 {
        print(b"MLOCK_BASIC:FAIL munlock errno=");
        print_num(-ret);
        println(b"");
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    println(b"MLOCK_BASIC:OK");
}

/// Test: mlock2 with MLOCK_ONFAULT flag
fn test_mlock2_onfault() {
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MLOCK2_ONFAULT:FAIL mmap errno=");
        print_num(-ptr);
        println(b"");
        return;
    }

    // Lock with MLOCK_ONFAULT - pages are locked on first access
    let ret = sys_mlock2(ptr as u64, 4096, MLOCK_ONFAULT);
    if ret != 0 {
        print(b"MLOCK2_ONFAULT:FAIL mlock2 errno=");
        print_num(-ret);
        println(b"");
        sys_munmap(ptr as u64, 4096);
        return;
    }

    // Write should trigger fault and lock
    unsafe {
        core::ptr::write_volatile(ptr as *mut u8, 42);
    }

    // Verify read
    let val = unsafe { core::ptr::read_volatile(ptr as *const u8) };
    if val != 42 {
        print(b"MLOCK2_ONFAULT:FAIL read mismatch got ");
        print_num(val as i64);
        println(b"");
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munlock(ptr as u64, 4096);
    sys_munmap(ptr as u64, 4096);
    println(b"MLOCK2_ONFAULT:OK");
}

/// Test: mlock2 with invalid flags returns EINVAL
fn test_mlock2_invalid_flags() {
    // Map a page first
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MLOCK2_EINVAL:FAIL mmap errno=");
        print_num(-ptr);
        println(b"");
        return;
    }

    // Try mlock2 with invalid flags (0x1000 is not a valid flag)
    let ret = sys_mlock2(ptr as u64, 4096, 0x1000);
    if ret == -22 {
        // EINVAL
        sys_munmap(ptr as u64, 4096);
        println(b"MLOCK2_EINVAL:OK");
    } else {
        print(b"MLOCK2_EINVAL:FAIL expected -22, got ");
        print_num(ret);
        println(b"");
        sys_munmap(ptr as u64, 4096);
    }
}

/// Test: mlockall with MCL_CURRENT locks all current mappings
fn test_mlockall_current() {
    // First mmap something
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MLOCKALL_CURRENT:FAIL mmap errno=");
        print_num(-ptr);
        println(b"");
        return;
    }

    // Lock all current
    let ret = sys_mlockall(MCL_CURRENT);
    if ret != 0 {
        print(b"MLOCKALL_CURRENT:FAIL mlockall errno=");
        print_num(-ret);
        println(b"");
        sys_munmap(ptr as u64, 4096);
        return;
    }

    // Write to the region to verify it's accessible
    unsafe {
        core::ptr::write_volatile(ptr as *mut u8, 123);
    }

    // Unlock all
    let ret = sys_munlockall();
    if ret != 0 {
        print(b"MLOCKALL_CURRENT:FAIL munlockall errno=");
        print_num(-ret);
        println(b"");
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    println(b"MLOCKALL_CURRENT:OK");
}

/// Test: mlockall with invalid flags returns EINVAL
fn test_mlockall_invalid_flags() {
    // 0 is invalid
    let ret = sys_mlockall(0);
    if ret != -22 {
        print(b"MLOCKALL_EINVAL_ZERO:FAIL expected -22, got ");
        print_num(ret);
        println(b"");
        return;
    }

    // MCL_ONFAULT alone is invalid (must be combined with MCL_CURRENT or MCL_FUTURE)
    let ret = sys_mlockall(MCL_ONFAULT);
    if ret != -22 {
        print(b"MLOCKALL_EINVAL_ONFAULT:FAIL expected -22, got ");
        print_num(ret);
        println(b"");
        return;
    }

    println(b"MLOCKALL_EINVAL:OK");
}

/// Test: munlockall unlocks all mappings
fn test_munlockall() {
    // Just verify munlockall returns success
    let ret = sys_munlockall();
    if ret == 0 {
        println(b"MUNLOCKALL:OK");
    } else {
        print(b"MUNLOCKALL:FAIL errno=");
        print_num(-ret);
        println(b"");
    }
}

// ============================================================================
// mprotect tests
// ============================================================================

/// Test: mprotect to add write permission (R -> RW)
fn test_mprotect_add_write() {
    // Map a read-only page
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ, // Initially read-only
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MPROTECT_ADD_WRITE:FAIL mmap errno=");
        print_num(-ptr);
        println(b"");
        return;
    }

    // Change to read-write
    let ret = sys_mprotect(ptr as u64, 4096, PROT_READ | PROT_WRITE);
    if ret != 0 {
        print(b"MPROTECT_ADD_WRITE:FAIL mprotect errno=");
        print_num(-ret);
        println(b"");
        sys_munmap(ptr as u64, 4096);
        return;
    }

    // Should now be able to write
    unsafe {
        core::ptr::write_volatile(ptr as *mut u8, 42);
    }

    // Read it back
    let val = unsafe { core::ptr::read_volatile(ptr as *const u8) };
    if val != 42 {
        print(b"MPROTECT_ADD_WRITE:FAIL read mismatch got ");
        print_num(val as i64);
        println(b"");
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    println(b"MPROTECT_ADD_WRITE:OK");
}

/// Test: mprotect with zero length is a no-op (success)
fn test_mprotect_zero_len() {
    // Map a page
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MPROTECT_ZERO_LEN:FAIL mmap errno=");
        print_num(-ptr);
        println(b"");
        return;
    }

    // mprotect with zero length should succeed (no-op per Linux)
    let ret = sys_mprotect(ptr as u64, 0, PROT_READ);
    if ret == 0 {
        sys_munmap(ptr as u64, 4096);
        println(b"MPROTECT_ZERO_LEN:OK");
    } else {
        print(b"MPROTECT_ZERO_LEN:FAIL expected 0, got ");
        print_num(ret);
        println(b"");
        sys_munmap(ptr as u64, 4096);
    }
}

/// Test: mprotect with unaligned address returns EINVAL
fn test_mprotect_invalid_addr() {
    // Map a page first
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MPROTECT_EINVAL:FAIL mmap errno=");
        print_num(-ptr);
        println(b"");
        return;
    }

    // Try mprotect with unaligned address (add 1 to make it unaligned)
    let ret = sys_mprotect(ptr as u64 + 1, 4096, PROT_READ);
    if ret == -22 {
        // EINVAL
        sys_munmap(ptr as u64, 4096);
        println(b"MPROTECT_EINVAL:OK");
    } else {
        print(b"MPROTECT_EINVAL:FAIL expected -22, got ");
        print_num(ret);
        println(b"");
        sys_munmap(ptr as u64, 4096);
    }
}

// ============================================================================
// MAP_SHARED tests
// ============================================================================

/// Test: MAP_SHARED | MAP_ANONYMOUS mapping
fn test_mmap_shared_anon() {
    // Map a shared anonymous page
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MMAP_SHARED_ANON:FAIL mmap errno=");
        print_num(-ptr);
        println(b"");
        return;
    }

    // Write to verify it's accessible
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0xCAFEBABE);
    }

    // Read it back
    let val = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    if val != 0xCAFEBABE {
        print(b"MMAP_SHARED_ANON:FAIL read mismatch got ");
        print_num(val as i64);
        println(b"");
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    println(b"MMAP_SHARED_ANON:OK");
}
