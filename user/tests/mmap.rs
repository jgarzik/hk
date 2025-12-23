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
    MAP_ANONYMOUS, MAP_DENYWRITE, MAP_EXECUTABLE, MAP_GROWSDOWN, MAP_LOCKED,
    MAP_NONBLOCK, MAP_POPULATE, MAP_PRIVATE, MAP_SHARED, MAP_STACK,
    PROT_GROWSDOWN, PROT_GROWSUP, PROT_READ, PROT_WRITE, PROT_EXEC,
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
    // MAP_DENYWRITE tests (deprecated flag, should be accepted but ignored)
    test_mmap_denywrite();
    // MAP_EXECUTABLE tests (deprecated flag, should be accepted but ignored)
    test_mmap_executable();
    // MAP_GROWSDOWN tests
    test_mmap_growsdown_basic();
    test_mmap_growsdown_expand();
    // PROT_GROWSDOWN/PROT_GROWSUP tests
    test_mprotect_growsdown();
    test_mprotect_growsup_fails();
    test_mprotect_grows_both_fails();
    // mlock tests
    test_mlock_basic();
    test_mlock2_onfault();
    test_mlock2_invalid_flags();
    test_mlockall_current();
    test_mlockall_invalid_flags();
    test_munlockall();
    // MAP_POPULATE, MAP_NONBLOCK, MAP_STACK tests
    test_mmap_populate();
    test_mmap_populate_nonblock();
    test_mmap_nonblock_alone();
    test_mmap_stack();
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

// ============================================================================
// MAP_DENYWRITE tests (deprecated flag - accepted but ignored per Linux)
// ============================================================================

/// Test: MAP_DENYWRITE is accepted (but ignored per Linux behavior)
fn test_mmap_denywrite() {
    // MAP_DENYWRITE should be accepted without returning an error
    // Linux explicitly ignores this flag for ABI compatibility
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_DENYWRITE,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MMAP_DENYWRITE:FAIL mmap errno=");
        print_num(-ptr);
        println(b"");
        return;
    }

    // Verify the mapping works normally (flag is ignored)
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0xDEADC0DE);
    }

    let val = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    if val != 0xDEADC0DE {
        print(b"MMAP_DENYWRITE:FAIL read mismatch got ");
        print_num(val as i64);
        println(b"");
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    println(b"MMAP_DENYWRITE:OK");
}

// ============================================================================
// MAP_EXECUTABLE tests (deprecated flag - accepted but ignored per Linux)
// ============================================================================

/// Test: MAP_EXECUTABLE is accepted (but ignored per Linux behavior)
fn test_mmap_executable() {
    // MAP_EXECUTABLE should be accepted without returning an error
    // Linux explicitly ignores this flag for ABI compatibility
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_EXECUTABLE,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MMAP_EXECUTABLE:FAIL mmap errno=");
        print_num(-ptr);
        println(b"");
        return;
    }

    // Verify the mapping works normally (flag is ignored)
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0xE0ECC0DE);
    }

    let val = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    if val != 0xE0ECC0DE {
        print(b"MMAP_EXECUTABLE:FAIL read mismatch got ");
        print_num(val as i64);
        println(b"");
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    println(b"MMAP_EXECUTABLE:OK");
}

// ============================================================================
// MAP_GROWSDOWN tests (stack-like downward expansion)
// ============================================================================

/// Test: MAP_GROWSDOWN basic - mmap with flag succeeds
fn test_mmap_growsdown_basic() {
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MMAP_GROWSDOWN_BASIC:FAIL mmap errno=");
        print_num(-ptr);
        println(b"");
        return;
    }

    // Write to allocated page
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0xDEADBEEF);
    }

    let val = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    if val != 0xDEADBEEF {
        print(b"MMAP_GROWSDOWN_BASIC:FAIL value=");
        print_num(val as i64);
        println(b"");
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    println(b"MMAP_GROWSDOWN_BASIC:OK");
}

/// Test: MAP_GROWSDOWN expansion - access below VMA expands it
fn test_mmap_growsdown_expand() {
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MMAP_GROWSDOWN_EXPAND:FAIL mmap errno=");
        print_num(-ptr);
        println(b"");
        return;
    }

    // Write to original page
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0xAAAAAAAA);
    }

    // Access one page BELOW - should trigger stack expansion
    let below = (ptr as u64).wrapping_sub(4096) as *mut u32;
    unsafe {
        core::ptr::write_volatile(below, 0xBBBBBBBB);
    }

    // Verify both pages work
    let val1 = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    let val2 = unsafe { core::ptr::read_volatile(below as *const u32) };

    if val1 != 0xAAAAAAAA || val2 != 0xBBBBBBBB {
        print(b"MMAP_GROWSDOWN_EXPAND:FAIL val1=");
        print_num(val1 as i64);
        print(b" val2=");
        print_num(val2 as i64);
        println(b"");
        sys_munmap((ptr as u64).wrapping_sub(4096), 8192);
        return;
    }

    // Unmap expanded region (start at the lower address)
    sys_munmap((ptr as u64).wrapping_sub(4096), 8192);
    println(b"MMAP_GROWSDOWN_EXPAND:OK");
}

// ============================================================================
// PROT_GROWSDOWN/PROT_GROWSUP tests
// ============================================================================

/// Test: PROT_GROWSDOWN extends mprotect to VMA start
fn test_mprotect_growsdown() {
    // Create a 2-page growsdown mapping
    let ptr = sys_mmap(
        0,
        8192, // 2 pages
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MPROTECT_GROWSDOWN:FAIL mmap errno=");
        print_num(-ptr);
        println(b"");
        return;
    }

    // mprotect upper page with PROT_GROWSDOWN - should extend to whole VMA
    let result = sys_mprotect(ptr as u64 + 4096, 4096, PROT_READ | PROT_GROWSDOWN);
    if result < 0 {
        print(b"MPROTECT_GROWSDOWN:FAIL errno=");
        print_num(-result);
        println(b"");
        sys_munmap(ptr as u64, 8192);
        return;
    }

    sys_munmap(ptr as u64, 8192);
    println(b"MPROTECT_GROWSDOWN:OK");
}

/// Test: PROT_GROWSUP fails on non-growsup VMA (always on x86-64/aarch64)
fn test_mprotect_growsup_fails() {
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MPROTECT_GROWSUP:FAIL mmap errno=");
        print_num(-ptr);
        println(b"");
        return;
    }

    // PROT_GROWSUP should fail with EINVAL (no VM_GROWSUP on x86-64/aarch64)
    let result = sys_mprotect(ptr as u64, 4096, PROT_READ | PROT_GROWSUP);
    if result != -22 {
        // EINVAL = 22
        print(b"MPROTECT_GROWSUP:FAIL expected -22 got ");
        print_num(result);
        println(b"");
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    println(b"MPROTECT_GROWSUP:OK");
}

/// Test: PROT_GROWSDOWN | PROT_GROWSUP together fails
fn test_mprotect_grows_both_fails() {
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MPROTECT_GROWS_BOTH:FAIL mmap errno=");
        print_num(-ptr);
        println(b"");
        return;
    }

    // Both flags together should fail with EINVAL
    let result = sys_mprotect(ptr as u64, 4096, PROT_READ | PROT_GROWSDOWN | PROT_GROWSUP);
    if result != -22 {
        // EINVAL
        print(b"MPROTECT_GROWS_BOTH:FAIL expected -22 got ");
        print_num(result);
        println(b"");
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    println(b"MPROTECT_GROWS_BOTH:OK");
}

// ============================================================================
// MAP_POPULATE, MAP_NONBLOCK, MAP_STACK tests
// ============================================================================

/// Test: MAP_POPULATE prefaults pages immediately
fn test_mmap_populate() {
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MMAP_POPULATE:FAIL errno=");
        print_num(-ptr);
        println(b"");
        return;
    }

    // Page should already be mapped - write should not need to fault
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0xDEADBEEF);
    }

    let val = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    if val != 0xDEADBEEF {
        print(b"MMAP_POPULATE:FAIL value mismatch got ");
        print_num(val as i64);
        println(b"");
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    println(b"MMAP_POPULATE:OK");
}

/// Test: MAP_POPULATE | MAP_NONBLOCK - populate is skipped (non-blocking)
fn test_mmap_populate_nonblock() {
    // When both flags are set, populate is skipped (Linux behavior)
    // Mapping should still succeed, pages demand-faulted instead
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_NONBLOCK,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MMAP_POPULATE_NONBLOCK:FAIL errno=");
        print_num(-ptr);
        println(b"");
        return;
    }

    // Should still work via demand paging
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0xCAFEBABE);
    }

    let val = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    if val != 0xCAFEBABE {
        print(b"MMAP_POPULATE_NONBLOCK:FAIL value mismatch got ");
        print_num(val as i64);
        println(b"");
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    println(b"MMAP_POPULATE_NONBLOCK:OK");
}

/// Test: MAP_NONBLOCK alone is accepted (no-op without MAP_POPULATE)
fn test_mmap_nonblock_alone() {
    // MAP_NONBLOCK alone should be silently accepted
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NONBLOCK,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MMAP_NONBLOCK_ALONE:FAIL errno=");
        print_num(-ptr);
        println(b"");
        return;
    }

    // Verify mapping works
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0x12345678);
    }

    let val = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    if val != 0x12345678 {
        print(b"MMAP_NONBLOCK_ALONE:FAIL value mismatch got ");
        print_num(val as i64);
        println(b"");
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    println(b"MMAP_NONBLOCK_ALONE:OK");
}

/// Test: MAP_STACK hint flag is accepted (no-op on systems without THP)
fn test_mmap_stack() {
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"MMAP_STACK:FAIL errno=");
        print_num(-ptr);
        println(b"");
        return;
    }

    // Verify mapping works normally (flag is just a hint)
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0x57ACE000);
    }

    let val = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    if val != 0x57ACE000 {
        print(b"MMAP_STACK:FAIL value mismatch got ");
        print_num(val as i64);
        println(b"");
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    println(b"MMAP_STACK:OK");
}
