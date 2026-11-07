//! Memory mapping tests
//!
//! Tests for mmap and munmap syscalls:
//! - Anonymous mmap (MAP_ANONYMOUS | MAP_PRIVATE)
//! - Write/read to mmap'd memory
//! - munmap to release memory
//! - Large anonymous mmap with demand paging
//! - mlock/mlock2/munlock/mlockall/munlockall

use crate::harness::{fail_num, pass};
use crate::helpers::{print, print_num, println};
use hk_syscall::{
    MADV_COLD, MADV_DONTNEED, MADV_KEEPONFORK, MADV_NORMAL, MADV_PAGEOUT, MADV_RANDOM,
    MADV_WILLNEED, MADV_WIPEONFORK, MAP_ANONYMOUS, MAP_DENYWRITE, MAP_EXECUTABLE, MAP_FIXED,
    MAP_FIXED_NOREPLACE, MAP_GROWSDOWN, MAP_LOCKED, MAP_NONBLOCK, MAP_POPULATE, MAP_PRIVATE,
    MAP_SHARED, MAP_STACK, MCL_CURRENT, MCL_ONFAULT, MLOCK_ONFAULT, MREMAP_FIXED, MREMAP_MAYMOVE,
    MS_ASYNC, MS_SYNC, O_DIRECTORY, PROT_GROWSDOWN, PROT_GROWSUP, PROT_READ, PROT_WRITE, Timespec,
    UtsName, sys_clock_gettime, sys_close, sys_exit, sys_fork, sys_madvise, sys_mincore, sys_mlock,
    sys_mlock2, sys_mlockall, sys_mmap, sys_mprotect, sys_mremap, sys_msync, sys_munlock,
    sys_munlockall, sys_munmap, sys_open, sys_pipe2, sys_read, sys_uname, sys_wait4, sys_write,
};

/// Run all mmap tests
pub fn run_tests() {
    test_mmap_offset_overflow();
    test_uaccess_demand_fault();
    test_uaccess_efault();
    test_uaccess_cow_child();
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
    test_growsdown_moved_pgoff();
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
    // MAP_FIXED_NOREPLACE tests
    test_mmap_fixed_noreplace_success();
    test_mmap_fixed_noreplace_collision();
    // MAP_NORESERVE test
    test_mmap_noreserve();
    test_mmap_nodev();
    // msync tests
    test_msync_basic();
    test_msync_invalid_flags();
    // madvise tests
    test_madvise_normal();
    test_madvise_dontneed();
    test_madvise_willneed();
    test_madvise_invalid();
    // mincore tests
    test_mincore_basic();
    test_mincore_invalid_addr();
    // mremap tests
    test_mremap_shrink();
    test_mremap_expand_inplace();
    test_mremap_expand_maymove();
    test_mremap_einval();
    // VMA merging tests (Tier 3 optimization)
    test_vma_merge_adjacent_anonymous();
    test_vma_no_merge_different_prot();
    test_vma_merge_after_mprotect();
    test_vma_merge_multiple();
    // VMA splitting tests
    test_mprotect_partial_vma();
    // New madvise hints
    test_madvise_cold();
    test_madvise_pageout();
    test_madvise_wipeonfork();
}

/// Test: Basic anonymous mmap
fn test_anonymous_mmap() {
    // Map one page (4096 bytes) of anonymous memory
    let ptr = sys_mmap(
        0,                           // addr (let kernel choose)
        4096,                        // length
        PROT_READ | PROT_WRITE,      // prot
        MAP_PRIVATE | MAP_ANONYMOUS, // flags
        -1,                          // fd (unused for anonymous)
        0,                           // offset
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
        pass(b"MMAP_ANON");
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
    let read_val = unsafe { core::ptr::read_volatile(ptr as *const u32) };

    if read_val == pattern {
        pass(b"MMAP_RW");
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
        pass(b"MUNMAP");
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
        let read_val = unsafe { core::ptr::read_volatile(addr as *const u8) };

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
        pass(b"MMAP_LARGE");
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
        fail_num(b"MMAP_LOCKED:FAIL mmap errno=", -ptr);
        return;
    }

    // Write to verify it's accessible (should be locked/populated)
    unsafe {
        core::ptr::write_volatile(ptr as *mut u8, 42);
    }

    let val = unsafe { core::ptr::read_volatile(ptr as *const u8) };
    if val != 42 {
        fail_num(b"MMAP_LOCKED:FAIL read mismatch got ", val as i64);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MMAP_LOCKED");
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
        fail_num(b"MLOCK_BASIC:FAIL mmap errno=", -ptr);
        return;
    }

    // Lock it
    let ret = sys_mlock(ptr as u64, 4096);
    if ret != 0 {
        fail_num(b"MLOCK_BASIC:FAIL mlock errno=", -ret);
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
        fail_num(b"MLOCK_BASIC:FAIL read mismatch got ", val as i64);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    // Unlock
    let ret = sys_munlock(ptr as u64, 4096);
    if ret != 0 {
        fail_num(b"MLOCK_BASIC:FAIL munlock errno=", -ret);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MLOCK_BASIC");
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
        fail_num(b"MLOCK2_ONFAULT:FAIL mmap errno=", -ptr);
        return;
    }

    // Lock with MLOCK_ONFAULT - pages are locked on first access
    let ret = sys_mlock2(ptr as u64, 4096, MLOCK_ONFAULT);
    if ret != 0 {
        fail_num(b"MLOCK2_ONFAULT:FAIL mlock2 errno=", -ret);
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
        fail_num(b"MLOCK2_ONFAULT:FAIL read mismatch got ", val as i64);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munlock(ptr as u64, 4096);
    sys_munmap(ptr as u64, 4096);
    pass(b"MLOCK2_ONFAULT");
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
        fail_num(b"MLOCK2_EINVAL:FAIL mmap errno=", -ptr);
        return;
    }

    // Try mlock2 with invalid flags (0x1000 is not a valid flag)
    let ret = sys_mlock2(ptr as u64, 4096, 0x1000);
    if ret == -22 {
        // EINVAL
        sys_munmap(ptr as u64, 4096);
        pass(b"MLOCK2_EINVAL");
    } else {
        fail_num(b"MLOCK2_EINVAL:FAIL expected -22, got ", ret);
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
        fail_num(b"MLOCKALL_CURRENT:FAIL mmap errno=", -ptr);
        return;
    }

    // Lock all current
    let ret = sys_mlockall(MCL_CURRENT);
    if ret != 0 {
        fail_num(b"MLOCKALL_CURRENT:FAIL mlockall errno=", -ret);
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
        fail_num(b"MLOCKALL_CURRENT:FAIL munlockall errno=", -ret);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MLOCKALL_CURRENT");
}

/// Test: mlockall with invalid flags returns EINVAL
fn test_mlockall_invalid_flags() {
    // 0 is invalid
    let ret = sys_mlockall(0);
    if ret != -22 {
        fail_num(b"MLOCKALL_EINVAL_ZERO:FAIL expected -22, got ", ret);
        return;
    }

    // MCL_ONFAULT alone is invalid (must be combined with MCL_CURRENT or MCL_FUTURE)
    let ret = sys_mlockall(MCL_ONFAULT);
    if ret != -22 {
        fail_num(b"MLOCKALL_EINVAL_ONFAULT:FAIL expected -22, got ", ret);
        return;
    }

    pass(b"MLOCKALL_EINVAL");
}

/// Test: munlockall unlocks all mappings
fn test_munlockall() {
    // Just verify munlockall returns success
    let ret = sys_munlockall();
    if ret == 0 {
        pass(b"MUNLOCKALL");
    } else {
        fail_num(b"MUNLOCKALL:FAIL errno=", -ret);
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
        fail_num(b"MPROTECT_ADD_WRITE:FAIL mmap errno=", -ptr);
        return;
    }

    // Change to read-write
    let ret = sys_mprotect(ptr as u64, 4096, PROT_READ | PROT_WRITE);
    if ret != 0 {
        fail_num(b"MPROTECT_ADD_WRITE:FAIL mprotect errno=", -ret);
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
        fail_num(b"MPROTECT_ADD_WRITE:FAIL read mismatch got ", val as i64);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MPROTECT_ADD_WRITE");
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
        fail_num(b"MPROTECT_ZERO_LEN:FAIL mmap errno=", -ptr);
        return;
    }

    // mprotect with zero length should succeed (no-op per Linux)
    let ret = sys_mprotect(ptr as u64, 0, PROT_READ);
    if ret == 0 {
        sys_munmap(ptr as u64, 4096);
        pass(b"MPROTECT_ZERO_LEN");
    } else {
        fail_num(b"MPROTECT_ZERO_LEN:FAIL expected 0, got ", ret);
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
        fail_num(b"MPROTECT_EINVAL:FAIL mmap errno=", -ptr);
        return;
    }

    // Try mprotect with unaligned address (add 1 to make it unaligned)
    let ret = sys_mprotect(ptr as u64 + 1, 4096, PROT_READ);
    if ret == -22 {
        // EINVAL
        sys_munmap(ptr as u64, 4096);
        pass(b"MPROTECT_EINVAL");
    } else {
        fail_num(b"MPROTECT_EINVAL:FAIL expected -22, got ", ret);
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
        fail_num(b"MMAP_SHARED_ANON:FAIL mmap errno=", -ptr);
        return;
    }

    // Write to verify it's accessible
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0xCAFEBABE);
    }

    // Read it back
    let val = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    if val != 0xCAFEBABE {
        fail_num(b"MMAP_SHARED_ANON:FAIL read mismatch got ", val as i64);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MMAP_SHARED_ANON");
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
        fail_num(b"MMAP_DENYWRITE:FAIL mmap errno=", -ptr);
        return;
    }

    // Verify the mapping works normally (flag is ignored)
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0xDEADC0DE);
    }

    let val = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    if val != 0xDEADC0DE {
        fail_num(b"MMAP_DENYWRITE:FAIL read mismatch got ", val as i64);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MMAP_DENYWRITE");
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
        fail_num(b"MMAP_EXECUTABLE:FAIL mmap errno=", -ptr);
        return;
    }

    // Verify the mapping works normally (flag is ignored)
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0xE0ECC0DE);
    }

    let val = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    if val != 0xE0ECC0DE {
        fail_num(b"MMAP_EXECUTABLE:FAIL read mismatch got ", val as i64);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MMAP_EXECUTABLE");
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
        fail_num(b"MMAP_GROWSDOWN_BASIC:FAIL mmap errno=", -ptr);
        return;
    }

    // Write to allocated page
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0xDEADBEEF);
    }

    let val = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    if val != 0xDEADBEEF {
        fail_num(b"MMAP_GROWSDOWN_BASIC:FAIL value=", val as i64);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MMAP_GROWSDOWN_BASIC");
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
        fail_num(b"MMAP_GROWSDOWN_EXPAND:FAIL mmap errno=", -ptr);
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
    pass(b"MMAP_GROWSDOWN_EXPAND");
}

/// A growsdown VMA mremap moved up keeps its page offset (Linux
/// vm_pgoff): it grows down by at most that many pages (Linux
/// expand_downwards: grow <= vm_pgoff), beyond is SIGSEGV
fn test_growsdown_moved_pgoff() {
    const LOW: u64 = 0x10_0000; // pgoff 256
    const HIGH: u64 = 0x7000_0000_0000;
    let pid = sys_fork();
    if pid == 0 {
        let p = sys_mmap(
            LOW,
            4096,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_FIXED,
            -1,
            0,
        );
        // Faulted before the move: Linux re-bases the pgoff of a VMA
        // with no pages yet (copy_vma)
        if p == LOW as i64 {
            unsafe { core::ptr::write_volatile(LOW as *mut u8, 1) };
        }
        let m = sys_mremap(LOW, 4096, 4096, MREMAP_MAYMOVE | MREMAP_FIXED, HIGH);
        if p != LOW as i64 || m != HIGH as i64 {
            sys_exit(1);
        }
        // One page down: fine
        unsafe { core::ptr::write_volatile((HIGH - 4096) as *mut u8, 1) };
        // 512 pages below: more than its 256 pages of offset
        unsafe { core::ptr::write_volatile((HIGH - (2 << 20)) as *mut u8, 1) };
        sys_exit(2);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    if st & 0x7f == 11 {
        pass(b"MMAP_GROWSDOWN_MOVED_PGOFF");
    } else {
        fail_num(b"MMAP_GROWSDOWN_MOVED_PGOFF:FAIL status=", st as i64);
    }
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
        fail_num(b"MPROTECT_GROWSDOWN:FAIL mmap errno=", -ptr);
        return;
    }

    // mprotect upper page with PROT_GROWSDOWN - should extend to whole VMA
    let result = sys_mprotect(ptr as u64 + 4096, 4096, PROT_READ | PROT_GROWSDOWN);
    if result < 0 {
        fail_num(b"MPROTECT_GROWSDOWN:FAIL errno=", -result);
        sys_munmap(ptr as u64, 8192);
        return;
    }

    sys_munmap(ptr as u64, 8192);
    pass(b"MPROTECT_GROWSDOWN");
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
        fail_num(b"MPROTECT_GROWSUP:FAIL mmap errno=", -ptr);
        return;
    }

    // PROT_GROWSUP should fail with EINVAL (no VM_GROWSUP on x86-64/aarch64)
    let result = sys_mprotect(ptr as u64, 4096, PROT_READ | PROT_GROWSUP);
    if result != -22 {
        // EINVAL = 22
        fail_num(b"MPROTECT_GROWSUP:FAIL expected -22 got ", result);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MPROTECT_GROWSUP");
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
        fail_num(b"MPROTECT_GROWS_BOTH:FAIL mmap errno=", -ptr);
        return;
    }

    // Both flags together should fail with EINVAL
    let result = sys_mprotect(ptr as u64, 4096, PROT_READ | PROT_GROWSDOWN | PROT_GROWSUP);
    if result != -22 {
        // EINVAL
        fail_num(b"MPROTECT_GROWS_BOTH:FAIL expected -22 got ", result);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MPROTECT_GROWS_BOTH");
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
        fail_num(b"MMAP_POPULATE:FAIL errno=", -ptr);
        return;
    }

    // Page should already be mapped - write should not need to fault
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0xDEADBEEF);
    }

    let val = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    if val != 0xDEADBEEF {
        fail_num(b"MMAP_POPULATE:FAIL value mismatch got ", val as i64);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MMAP_POPULATE");
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
        fail_num(b"MMAP_POPULATE_NONBLOCK:FAIL errno=", -ptr);
        return;
    }

    // Should still work via demand paging
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0xCAFEBABE);
    }

    let val = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    if val != 0xCAFEBABE {
        fail_num(
            b"MMAP_POPULATE_NONBLOCK:FAIL value mismatch got ",
            val as i64,
        );
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MMAP_POPULATE_NONBLOCK");
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
        fail_num(b"MMAP_NONBLOCK_ALONE:FAIL errno=", -ptr);
        return;
    }

    // Verify mapping works
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0x12345678);
    }

    let val = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    if val != 0x12345678 {
        fail_num(b"MMAP_NONBLOCK_ALONE:FAIL value mismatch got ", val as i64);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MMAP_NONBLOCK_ALONE");
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
        fail_num(b"MMAP_STACK:FAIL errno=", -ptr);
        return;
    }

    // Verify mapping works normally (flag is just a hint)
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0x57ACE000);
    }

    let val = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    if val != 0x57ACE000 {
        fail_num(b"MMAP_STACK:FAIL value mismatch got ", val as i64);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MMAP_STACK");
}

// ============================================================================
// MAP_FIXED_NOREPLACE tests
// ============================================================================

/// Test: MAP_FIXED_NOREPLACE succeeds when no collision
fn test_mmap_fixed_noreplace_success() {
    // First mmap to get a valid address
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        fail_num(b"MMAP_FIXED_NOREPLACE_OK:FAIL initial mmap errno=", -ptr);
        return;
    }

    // Unmap it
    sys_munmap(ptr as u64, 4096);

    // Now use MAP_FIXED_NOREPLACE at the same address - should succeed
    let ptr2 = sys_mmap(
        ptr as u64,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
        -1,
        0,
    );

    if ptr2 < 0 {
        fail_num(b"MMAP_FIXED_NOREPLACE_OK:FAIL errno=", -ptr2);
        return;
    }

    if ptr2 as u64 != ptr as u64 {
        print(b"MMAP_FIXED_NOREPLACE_OK:FAIL addr mismatch expected ");
        print_num(ptr);
        print(b" got ");
        print_num(ptr2);
        println(b"");
        sys_munmap(ptr2 as u64, 4096);
        return;
    }

    sys_munmap(ptr2 as u64, 4096);
    pass(b"MMAP_FIXED_NOREPLACE_OK");
}

/// Test: MAP_FIXED_NOREPLACE returns EEXIST on collision
fn test_mmap_fixed_noreplace_collision() {
    // Create a mapping
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        fail_num(
            b"MMAP_FIXED_NOREPLACE_EEXIST:FAIL initial mmap errno=",
            -ptr,
        );
        return;
    }

    // Try MAP_FIXED_NOREPLACE at same address - should fail with EEXIST (-17)
    let ptr2 = sys_mmap(
        ptr as u64,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
        -1,
        0,
    );

    if ptr2 != -17 {
        // EEXIST
        fail_num(b"MMAP_FIXED_NOREPLACE_EEXIST:FAIL expected -17 got ", ptr2);
        if ptr2 >= 0 {
            sys_munmap(ptr2 as u64, 4096);
        }
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MMAP_FIXED_NOREPLACE_EEXIST");
}

/// Test: MAP_NORESERVE flag is accepted
fn test_mmap_noreserve() {
    const MAP_NORESERVE: u32 = 0x4000;

    // Create anonymous mapping with MAP_NORESERVE
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
        -1,
        0,
    );

    if ptr < 0 {
        fail_num(b"MMAP_NORESERVE:FAIL mmap errno=", -ptr);
        return;
    }

    // Verify we can read/write to it
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0x12345678);
        let val = core::ptr::read_volatile(ptr as *const u32);
        if val != 0x12345678 {
            println(b"MMAP_NORESERVE:FAIL data mismatch");
            sys_munmap(ptr as u64, 4096);
            return;
        }
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MMAP_NORESERVE");
}

// ============================================================================
// msync tests
// ============================================================================

/// Test: msync with MS_ASYNC on anonymous mapping
fn test_msync_basic() {
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        fail_num(b"MSYNC_BASIC:FAIL mmap errno=", -ptr);
        return;
    }

    // Write something
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0xDEADBEEF);
    }

    // msync with MS_ASYNC (essentially a no-op but should succeed)
    let ret = sys_msync(ptr as u64, 4096, MS_ASYNC);
    if ret != 0 {
        fail_num(b"MSYNC_BASIC:FAIL msync errno=", -ret);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MSYNC_BASIC");
}

/// Test: msync with invalid flags returns EINVAL
fn test_msync_invalid_flags() {
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        fail_num(b"MSYNC_EINVAL:FAIL mmap errno=", -ptr);
        return;
    }

    // MS_ASYNC | MS_SYNC together is invalid
    let ret = sys_msync(ptr as u64, 4096, MS_ASYNC | MS_SYNC);
    if ret != -22 {
        // EINVAL
        fail_num(b"MSYNC_EINVAL:FAIL expected -22 got ", ret);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MSYNC_EINVAL");
}

// ============================================================================
// madvise tests
// ============================================================================

/// Test: madvise with MADV_NORMAL
fn test_madvise_normal() {
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        fail_num(b"MADVISE_NORMAL:FAIL mmap errno=", -ptr);
        return;
    }

    // First set to RANDOM, then back to NORMAL
    let ret = sys_madvise(ptr as u64, 4096, MADV_RANDOM);
    if ret != 0 {
        fail_num(b"MADVISE_NORMAL:FAIL madvise RANDOM errno=", -ret);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    let ret = sys_madvise(ptr as u64, 4096, MADV_NORMAL);
    if ret != 0 {
        fail_num(b"MADVISE_NORMAL:FAIL madvise NORMAL errno=", -ret);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MADVISE_NORMAL");
}

/// Test: madvise with MADV_DONTNEED zaps pages
fn test_madvise_dontneed() {
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        fail_num(b"MADVISE_DONTNEED:FAIL mmap errno=", -ptr);
        return;
    }

    // Write something
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0xDEADBEEF);
    }

    // MADV_DONTNEED - should zap the pages
    let ret = sys_madvise(ptr as u64, 4096, MADV_DONTNEED);
    if ret != 0 {
        fail_num(b"MADVISE_DONTNEED:FAIL madvise errno=", -ret);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    // Re-read - page should be zeroed (new anonymous page)
    let val = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    if val != 0 {
        fail_num(b"MADVISE_DONTNEED:FAIL expected 0 got ", val as i64);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MADVISE_DONTNEED");
}

/// Test: madvise with MADV_WILLNEED prefaults pages
fn test_madvise_willneed() {
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        fail_num(b"MADVISE_WILLNEED:FAIL mmap errno=", -ptr);
        return;
    }

    // MADV_WILLNEED - should prefault pages
    let ret = sys_madvise(ptr as u64, 4096, MADV_WILLNEED);
    if ret != 0 {
        fail_num(b"MADVISE_WILLNEED:FAIL madvise errno=", -ret);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    // Should be able to read (page prefaulted)
    let val = unsafe { core::ptr::read_volatile(ptr as *const u32) };
    // Anonymous pages are zeroed
    if val != 0 {
        fail_num(b"MADVISE_WILLNEED:FAIL expected 0 got ", val as i64);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MADVISE_WILLNEED");
}

/// Test: madvise with invalid advice returns EINVAL
fn test_madvise_invalid() {
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        fail_num(b"MADVISE_EINVAL:FAIL mmap errno=", -ptr);
        return;
    }

    // Invalid advice (999 is not a valid MADV_* value)
    let ret = sys_madvise(ptr as u64, 4096, 999);
    if ret != -22 {
        // EINVAL
        fail_num(b"MADVISE_EINVAL:FAIL expected -22 got ", ret);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MADVISE_EINVAL");
}

// ============================================================================
// mremap tests
// ============================================================================

/// Test: mremap shrink - reduce mapping size
fn test_mremap_shrink() {
    // Create a 2-page mapping
    let ptr = sys_mmap(
        0,
        8192, // 2 pages
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        fail_num(b"MREMAP_SHRINK:FAIL mmap errno=", -ptr);
        return;
    }

    // Write to both pages to verify they're mapped
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0xAAAAAAAA);
        core::ptr::write_volatile((ptr as u64 + 4096) as *mut u32, 0xBBBBBBBB);
    }

    // Shrink to 1 page
    let new_ptr = sys_mremap(ptr as u64, 8192, 4096, 0, 0);
    if new_ptr < 0 {
        fail_num(b"MREMAP_SHRINK:FAIL mremap errno=", -new_ptr);
        sys_munmap(ptr as u64, 8192);
        return;
    }

    // Should return same address
    if new_ptr as u64 != ptr as u64 {
        print(b"MREMAP_SHRINK:FAIL addr changed from ");
        print_num(ptr);
        print(b" to ");
        print_num(new_ptr);
        println(b"");
        sys_munmap(new_ptr as u64, 4096);
        return;
    }

    // First page data should be preserved
    let val = unsafe { core::ptr::read_volatile(new_ptr as *const u32) };
    if val != 0xAAAAAAAA {
        fail_num(b"MREMAP_SHRINK:FAIL data mismatch got ", val as i64);
        sys_munmap(new_ptr as u64, 4096);
        return;
    }

    sys_munmap(new_ptr as u64, 4096);
    pass(b"MREMAP_SHRINK");
}

/// Test: mremap expand in-place
fn test_mremap_expand_inplace() {
    // Create a 1-page mapping
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        fail_num(b"MREMAP_EXPAND:FAIL mmap errno=", -ptr);
        return;
    }

    // Write test data
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0xDEADBEEF);
    }

    // Try to expand to 2 pages (may move if no room)
    let new_ptr = sys_mremap(ptr as u64, 4096, 8192, MREMAP_MAYMOVE, 0);
    if new_ptr < 0 {
        fail_num(b"MREMAP_EXPAND:FAIL mremap errno=", -new_ptr);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    // Original data should be preserved
    let val = unsafe { core::ptr::read_volatile(new_ptr as *const u32) };
    if val != 0xDEADBEEF {
        fail_num(b"MREMAP_EXPAND:FAIL data mismatch got ", val as i64);
        sys_munmap(new_ptr as u64, 8192);
        return;
    }

    // Second page should be accessible (zeroed for anonymous)
    let val2 = unsafe { core::ptr::read_volatile((new_ptr as u64 + 4096) as *const u32) };
    // Note: expanded page may or may not be zero depending on implementation
    let _ = val2; // Just verify it's accessible

    sys_munmap(new_ptr as u64, 8192);
    pass(b"MREMAP_EXPAND");
}

/// Test: mremap expand with forced move (MREMAP_MAYMOVE)
fn test_mremap_expand_maymove() {
    // Create two adjacent mappings to force a collision
    let ptr1 = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr1 < 0 {
        fail_num(b"MREMAP_MAYMOVE:FAIL mmap1 errno=", -ptr1);
        return;
    }

    // Try to create a second mapping right after the first
    // (this may or may not succeed depending on address layout)
    let ptr2 = sys_mmap(
        (ptr1 as u64 + 4096) as u64,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
        -1,
        0,
    );

    // Write test data to first mapping
    unsafe {
        core::ptr::write_volatile(ptr1 as *mut u32, 0xCAFEBABE);
    }

    // Now try to expand first mapping - if ptr2 succeeded, this should move
    let new_ptr = sys_mremap(ptr1 as u64, 4096, 8192, MREMAP_MAYMOVE, 0);
    if new_ptr < 0 {
        fail_num(b"MREMAP_MAYMOVE:FAIL mremap errno=", -new_ptr);
        sys_munmap(ptr1 as u64, 4096);
        if ptr2 >= 0 {
            sys_munmap(ptr2 as u64, 4096);
        }
        return;
    }

    // Data should be preserved regardless of whether it moved
    let val = unsafe { core::ptr::read_volatile(new_ptr as *const u32) };
    if val != 0xCAFEBABE {
        fail_num(b"MREMAP_MAYMOVE:FAIL data mismatch got ", val as i64);
        sys_munmap(new_ptr as u64, 8192);
        if ptr2 >= 0 {
            sys_munmap(ptr2 as u64, 4096);
        }
        return;
    }

    sys_munmap(new_ptr as u64, 8192);
    if ptr2 >= 0 {
        sys_munmap(ptr2 as u64, 4096);
    }
    pass(b"MREMAP_MAYMOVE");
}

// ============================================================================
// VMA merging tests (Tier 3 optimization)
// Note: VMA merging is internal; we test that behavior is correct after merge
// ============================================================================

/// Test: Adjacent anonymous mappings with same flags (triggers VMA merge)
fn test_vma_merge_adjacent_anonymous() {
    // First, allocate a page to get a base address
    let ptr1 = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr1 < 0 {
        fail_num(b"VMA_MERGE_ADJACENT:FAIL mmap1 errno=", -ptr1);
        return;
    }

    // Try to allocate adjacent page using MAP_FIXED_NOREPLACE
    // If it collides, use the hint address mechanism instead
    let adjacent_addr = ptr1 as u64 + 4096;
    let ptr2 = sys_mmap(
        adjacent_addr,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
        -1,
        0,
    );

    if ptr2 < 0 {
        // Adjacent address not available, skip test
        sys_munmap(ptr1 as u64, 4096);
        println(b"VMA_MERGE_ADJACENT:SKIP (no adjacent space)");
        return;
    }

    // Write to both pages
    unsafe {
        core::ptr::write_volatile(ptr1 as *mut u32, 0x11111111);
        core::ptr::write_volatile(ptr2 as *mut u32, 0x22222222);
    }

    // Read back - if VMA merge worked, pages should still be accessible
    let val1 = unsafe { core::ptr::read_volatile(ptr1 as *const u32) };
    let val2 = unsafe { core::ptr::read_volatile(ptr2 as *const u32) };

    if val1 != 0x11111111 || val2 != 0x22222222 {
        print(b"VMA_MERGE_ADJACENT:FAIL val1=");
        print_num(val1 as i64);
        print(b" val2=");
        print_num(val2 as i64);
        println(b"");
        sys_munmap(ptr1 as u64, 8192);
        return;
    }

    // Unmap both (may be merged into single VMA internally)
    sys_munmap(ptr1 as u64, 8192);
    pass(b"VMA_MERGE_ADJACENT");
}

/// Test: VMAs with different protection don't merge (verify isolation)
fn test_vma_no_merge_different_prot() {
    // Allocate RW page
    let ptr1 = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr1 < 0 {
        fail_num(b"VMA_NO_MERGE_PROT:FAIL mmap1 errno=", -ptr1);
        return;
    }

    // Try to allocate adjacent RO page
    let adjacent_addr = ptr1 as u64 + 4096;
    let ptr2 = sys_mmap(
        adjacent_addr,
        4096,
        PROT_READ, // Different protection - read-only
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
        -1,
        0,
    );

    if ptr2 < 0 {
        sys_munmap(ptr1 as u64, 4096);
        println(b"VMA_NO_MERGE_PROT:SKIP (no adjacent space)");
        return;
    }

    // Write to RW page
    unsafe {
        core::ptr::write_volatile(ptr1 as *mut u32, 0xAAAAAAAA);
    }

    // Read from both (RO page should be readable)
    let val1 = unsafe { core::ptr::read_volatile(ptr1 as *const u32) };
    let val2 = unsafe { core::ptr::read_volatile(ptr2 as *const u32) };

    if val1 != 0xAAAAAAAA {
        fail_num(b"VMA_NO_MERGE_PROT:FAIL val1=", val1 as i64);
        sys_munmap(ptr1 as u64, 4096);
        sys_munmap(ptr2 as u64, 4096);
        return;
    }

    // val2 should be 0 (anonymous zeroed page)
    let _ = val2;

    sys_munmap(ptr1 as u64, 4096);
    sys_munmap(ptr2 as u64, 4096);
    pass(b"VMA_NO_MERGE_PROT");
}

/// Test: mprotect followed by merge opportunity
fn test_vma_merge_after_mprotect() {
    // Create two adjacent RW pages
    let ptr1 = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr1 < 0 {
        fail_num(b"VMA_MERGE_MPROTECT:FAIL mmap1 errno=", -ptr1);
        return;
    }

    let adjacent_addr = ptr1 as u64 + 4096;
    let ptr2 = sys_mmap(
        adjacent_addr,
        4096,
        PROT_READ, // Start with different prot
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
        -1,
        0,
    );

    if ptr2 < 0 {
        sys_munmap(ptr1 as u64, 4096);
        println(b"VMA_MERGE_MPROTECT:SKIP (no adjacent space)");
        return;
    }

    // Write to first page
    unsafe {
        core::ptr::write_volatile(ptr1 as *mut u32, 0xDEADC0DE);
    }

    // Now mprotect second page to RW (same as first) - may trigger merge
    let ret = sys_mprotect(ptr2 as u64, 4096, PROT_READ | PROT_WRITE);
    if ret != 0 {
        fail_num(b"VMA_MERGE_MPROTECT:FAIL mprotect errno=", -ret);
        sys_munmap(ptr1 as u64, 4096);
        sys_munmap(ptr2 as u64, 4096);
        return;
    }

    // Both pages should now be writable
    unsafe {
        core::ptr::write_volatile(ptr2 as *mut u32, 0xBEEFCAFE);
    }

    let val1 = unsafe { core::ptr::read_volatile(ptr1 as *const u32) };
    let val2 = unsafe { core::ptr::read_volatile(ptr2 as *const u32) };

    if val1 != 0xDEADC0DE || val2 != 0xBEEFCAFE {
        print(b"VMA_MERGE_MPROTECT:FAIL val1=");
        print_num(val1 as i64);
        print(b" val2=");
        print_num(val2 as i64);
        println(b"");
        sys_munmap(ptr1 as u64, 8192);
        return;
    }

    sys_munmap(ptr1 as u64, 8192);
    pass(b"VMA_MERGE_MPROTECT");
}

/// Test: Multiple consecutive mappings (stress test for merge cascade)
fn test_vma_merge_multiple() {
    const NUM_PAGES: u64 = 4;
    let size = NUM_PAGES * 4096;

    // Allocate first page to get base
    let base = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if base < 0 {
        fail_num(b"VMA_MERGE_MULTI:FAIL mmap base errno=", -base);
        return;
    }

    // Try to allocate consecutive pages
    let mut success = true;
    for i in 1..NUM_PAGES {
        let addr = base as u64 + i * 4096;
        let ptr = sys_mmap(
            addr,
            4096,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            -1,
            0,
        );
        if ptr < 0 {
            // Couldn't allocate consecutive page
            sys_munmap(base as u64, i * 4096);
            println(b"VMA_MERGE_MULTI:SKIP (no consecutive space)");
            return;
        }
    }

    // Write pattern to all pages
    for i in 0..NUM_PAGES {
        let addr = base as u64 + i * 4096;
        unsafe {
            core::ptr::write_volatile(addr as *mut u32, 0x11111111 * (i + 1) as u32);
        }
    }

    // Verify all pages
    for i in 0..NUM_PAGES {
        let addr = base as u64 + i * 4096;
        let expected = 0x11111111 * (i + 1) as u32;
        let val = unsafe { core::ptr::read_volatile(addr as *const u32) };
        if val != expected {
            print(b"VMA_MERGE_MULTI:FAIL page ");
            print_num(i as i64);
            print(b" expected ");
            print_num(expected as i64);
            print(b" got ");
            print_num(val as i64);
            println(b"");
            success = false;
            break;
        }
    }

    sys_munmap(base as u64, size);

    if success {
        pass(b"VMA_MERGE_MULTI");
    }
}

/// Test: mremap with invalid parameters returns EINVAL
fn test_mremap_einval() {
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        fail_num(b"MREMAP_EINVAL:FAIL mmap errno=", -ptr);
        return;
    }

    // new_len = 0 should fail
    let ret = sys_mremap(ptr as u64, 4096, 0, 0, 0);
    if ret != -22 {
        // EINVAL
        fail_num(b"MREMAP_EINVAL:FAIL new_len=0 expected -22 got ", ret);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    // MREMAP_FIXED without MREMAP_MAYMOVE should fail
    let ret = sys_mremap(ptr as u64, 4096, 4096, MREMAP_FIXED, 0x100000);
    if ret != -22 {
        // EINVAL
        fail_num(
            b"MREMAP_EINVAL:FAIL FIXED w/o MAYMOVE expected -22 got ",
            ret,
        );
        sys_munmap(ptr as u64, 4096);
        return;
    }

    // unaligned old_addr should fail
    let ret = sys_mremap(ptr as u64 + 1, 4096, 4096, 0, 0);
    if ret != -22 {
        // EINVAL
        fail_num(b"MREMAP_EINVAL:FAIL unaligned expected -22 got ", ret);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MREMAP_EINVAL");
}

// ============================================================================
// mincore tests
// ============================================================================

/// Test: mincore reports resident pages correctly
fn test_mincore_basic() {
    // Map one page of anonymous memory
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        fail_num(b"MINCORE_BASIC:FAIL mmap errno=", -ptr);
        return;
    }

    // Touch the page to make it resident
    unsafe {
        core::ptr::write_volatile(ptr as *mut u32, 0xDEADBEEF);
    }

    // Call mincore to check residency
    let mut vec: [u8; 1] = [0];
    let ret = sys_mincore(ptr as u64, 4096, vec.as_mut_ptr());

    if ret != 0 {
        fail_num(b"MINCORE_BASIC:FAIL mincore errno=", -ret);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    // Check that the page is reported as resident (bit 0 set)
    if vec[0] & 1 == 0 {
        fail_num(
            b"MINCORE_BASIC:FAIL page not reported as resident, vec=",
            vec[0] as i64,
        );
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MINCORE_BASIC");
}

/// Test: mincore returns EINVAL for unaligned address
fn test_mincore_invalid_addr() {
    // Map one page
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        fail_num(b"MINCORE_INVALID:FAIL mmap errno=", -ptr);
        return;
    }

    // Try mincore with unaligned address - should return EINVAL (-22)
    let mut vec: [u8; 1] = [0];
    let ret = sys_mincore((ptr as u64) + 1, 4096, vec.as_mut_ptr());

    if ret != -22 {
        // EINVAL
        fail_num(b"MINCORE_INVALID:FAIL expected -22 got ", ret);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MINCORE_INVALID");
}

// ============================================================================
// VMA splitting tests
// ============================================================================

/// Test: mprotect on partial VMA range triggers VMA splitting
fn test_mprotect_partial_vma() {
    // Map 3 pages as a single VMA
    let size: u64 = 3 * 4096;
    let ptr = sys_mmap(
        0,
        size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        fail_num(b"MPROTECT_PARTIAL:FAIL mmap errno=", -ptr);
        return;
    }

    // Write to all 3 pages to make sure they're accessible
    unsafe {
        core::ptr::write_volatile(ptr as *mut u8, 1);
        core::ptr::write_volatile((ptr as u64 + 4096) as *mut u8, 2);
        core::ptr::write_volatile((ptr as u64 + 8192) as *mut u8, 3);
    }

    // mprotect only the middle page to read-only
    // This should split the VMA into 3 parts:
    // [ptr, ptr+4096) = RW
    // [ptr+4096, ptr+8192) = R
    // [ptr+8192, ptr+12288) = RW
    let middle = ptr as u64 + 4096;
    let ret = sys_mprotect(middle, 4096, PROT_READ);
    if ret != 0 {
        fail_num(b"MPROTECT_PARTIAL:FAIL mprotect errno=", -ret);
        sys_munmap(ptr as u64, size);
        return;
    }

    // Verify we can still write to first and third pages
    unsafe {
        core::ptr::write_volatile(ptr as *mut u8, 10);
        core::ptr::write_volatile((ptr as u64 + 8192) as *mut u8, 30);
    }

    // Verify reads work on all pages
    let v1 = unsafe { core::ptr::read_volatile(ptr as *const u8) };
    let v2 = unsafe { core::ptr::read_volatile((ptr as u64 + 4096) as *const u8) };
    let v3 = unsafe { core::ptr::read_volatile((ptr as u64 + 8192) as *const u8) };

    if v1 != 10 || v2 != 2 || v3 != 30 {
        print(b"MPROTECT_PARTIAL:FAIL read mismatch ");
        print_num(v1 as i64);
        print(b" ");
        print_num(v2 as i64);
        print(b" ");
        print_num(v3 as i64);
        println(b"");
        sys_munmap(ptr as u64, size);
        return;
    }

    // Note: We can't easily test that writing to middle page fails
    // without handling SIGSEGV, so we just verify the API works

    sys_munmap(ptr as u64, size);
    pass(b"MPROTECT_PARTIAL");
}

// ============================================================================
// Additional madvise hint tests
// ============================================================================

/// Test: MADV_COLD hint (no-op, just verify it returns 0)
fn test_madvise_cold() {
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        fail_num(b"MADVISE_COLD:FAIL mmap errno=", -ptr);
        return;
    }

    let ret = sys_madvise(ptr as u64, 4096, MADV_COLD);
    if ret == 0 {
        pass(b"MADVISE_COLD");
    } else {
        fail_num(b"MADVISE_COLD:FAIL expected 0, got ", ret);
    }

    sys_munmap(ptr as u64, 4096);
}

/// Test: MADV_PAGEOUT hint (no-op, just verify it returns 0)
fn test_madvise_pageout() {
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        fail_num(b"MADVISE_PAGEOUT:FAIL mmap errno=", -ptr);
        return;
    }

    let ret = sys_madvise(ptr as u64, 4096, MADV_PAGEOUT);
    if ret == 0 {
        pass(b"MADVISE_PAGEOUT");
    } else {
        fail_num(b"MADVISE_PAGEOUT:FAIL expected 0, got ", ret);
    }

    sys_munmap(ptr as u64, 4096);
}

/// Test: MADV_WIPEONFORK / MADV_KEEPONFORK
fn test_madvise_wipeonfork() {
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        fail_num(b"MADVISE_WIPEONFORK:FAIL mmap errno=", -ptr);
        return;
    }

    // Set WIPEONFORK
    let ret = sys_madvise(ptr as u64, 4096, MADV_WIPEONFORK);
    if ret != 0 {
        fail_num(b"MADVISE_WIPEONFORK:FAIL WIPEONFORK returned ", ret);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    // Clear with KEEPONFORK
    let ret = sys_madvise(ptr as u64, 4096, MADV_KEEPONFORK);
    if ret != 0 {
        fail_num(b"MADVISE_WIPEONFORK:FAIL KEEPONFORK returned ", ret);
        sys_munmap(ptr as u64, 4096);
        return;
    }

    sys_munmap(ptr as u64, 4096);
    pass(b"MADVISE_WIPEONFORK");
}

/// Map `pages` untouched anonymous pages; returns 0 on failure
fn mmap_untouched(pages: u64) -> u64 {
    let p = sys_mmap(
        0,
        pages * 4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if p < 0 { 0 } else { p as u64 }
}

/// Test: kernel writes into never-touched anonymous pages must demand-fault
/// them in (Linux: do_user_addr_fault for kernel-mode faults), not panic
fn test_uaccess_demand_fault() {
    let base = mmap_untouched(4);
    if base == 0 {
        println(b"UACCESS_DEMAND_FAULT:FAIL mmap");
        return;
    }
    // read() into the middle of untouched memory, spanning a page boundary
    let fd = sys_open(b"/test.txt\0".as_ptr(), 0, 0);
    if fd < 0 {
        println(b"UACCESS_DEMAND_FAULT:FAIL open");
        return;
    }
    let buf = base + 4096 - 5;
    let n = sys_read(fd as u64, buf as *mut u8, 17);
    sys_close(fd as u64);
    let got = unsafe { core::slice::from_raw_parts(buf as *const u8, 17) };
    // clock_gettime / uname into further untouched pages
    let ts = (base + 2 * 4096) as *mut Timespec;
    let r1 = sys_clock_gettime(1, ts);
    let uts = (base + 3 * 4096 - 64) as *mut UtsName; // crosses into page 3
    let r2 = sys_uname(uts);
    let sysname_ok = unsafe { (*uts).sysname[0] != 0 };
    if n == 17 && got == b"Hello from ramfs!" && r1 == 0 && r2 == 0 && sysname_ok {
        pass(b"UACCESS_DEMAND_FAULT");
    } else {
        print(b"UACCESS_DEMAND_FAULT:FAIL read=");
        print_num(n);
        print(b" clock_gettime=");
        print_num(r1);
        print(b" uname=");
        print_num(r2);
        println(b"");
    }
    sys_munmap(base, 4 * 4096);
}

/// Test: kernel access to an unmapped user address returns EFAULT, no panic
fn test_uaccess_efault() {
    let base = mmap_untouched(1);
    if base == 0 {
        println(b"UACCESS_EFAULT:FAIL mmap");
        return;
    }
    sys_munmap(base, 4096);
    let fd = sys_open(b"/test.txt\0".as_ptr(), 0, 0);
    if fd < 0 {
        println(b"UACCESS_EFAULT:FAIL open");
        return;
    }
    let r = sys_read(fd as u64, base as *mut u8, 17);
    sys_close(fd as u64);
    let w = sys_write(1, base as *const u8, 4);
    if r == -14 && w == -14 {
        pass(b"UACCESS_EFAULT");
    } else {
        print(b"UACCESS_EFAULT:FAIL read=");
        print_num(r);
        print(b" write=");
        print_num(w);
        println(b"");
    }
}

/// Test: a kernel write into a COW-shared page in the child must not leak
/// into the parent's copy (x86 needs CR0.WP for kernel writes to fault)
fn test_uaccess_cow_child() {
    let base = mmap_untouched(1);
    if base == 0 {
        println(b"UACCESS_COW:FAIL mmap");
        return;
    }
    let p = base as *mut u8;
    unsafe { core::ptr::write_bytes(p, b'A', 32) };
    let pid = sys_fork();
    if pid == 0 {
        let fd = sys_open(b"/test.txt\0".as_ptr(), 0, 0);
        let n = sys_read(fd as u64, p, 17);
        let ok = n == 17 && unsafe { *p } == b'H';
        sys_exit(if ok { 0 } else { 1 });
    }
    let mut status: i32 = 0;
    sys_wait4(pid, &mut status, 0, 0);
    let parent_ok = unsafe { *p == b'A' && *p.add(16) == b'A' };
    if pid > 0 && status == 0 && parent_ok {
        pass(b"UACCESS_COW");
    } else {
        print(b"UACCESS_COW:FAIL status=");
        print_num(status as i64);
        print(b" parent_intact=");
        print_num(parent_ok as i64);
        println(b"");
    }
    sys_munmap(base, 4096);
}

/// Files without mmap (Linux do_mmap: no f_op->mmap, ENODEV; procfs
/// proc_dir_entry files: pde_mmap, EIO). A procfs mapping would fault
/// in through readers that take the mmap_lock the fault holds.
fn test_mmap_nodev() {
    let files: [(&[u8], u32, i64); 4] = [
        (b"/proc/self/maps\0", 0, -19),
        (b"/proc/sys/vm/min_free_kbytes\0", 0, -19),
        (b"/proc/version\0", 0, -5),
        (b"/tmp\0", O_DIRECTORY, -19),
    ];
    let mut bad = 0;
    for (path, flags, want) in files {
        let fd = sys_open(path.as_ptr(), flags, 0);
        let r = sys_mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd as i32, 0);
        sys_close(fd as u64);
        if r != want {
            print(b"MMAP_NODEV: ");
            print(&path[..path.len() - 1]);
            print(b" got ");
            print_num(r);
            println(b"");
            bad += 1;
        }
    }
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    let r = sys_mmap(0, 4096, PROT_READ, MAP_PRIVATE, p[0], 0);
    sys_close(p[0] as u64);
    sys_close(p[1] as u64);
    if r != -19 {
        print(b"MMAP_NODEV: pipe got ");
        print_num(r);
        println(b"");
        bad += 1;
    }
    println(if bad == 0 {
        b"MMAP_NODEV:OK"
    } else {
        b"MMAP_NODEV:FAIL"
    });
}

/// A file mapping past the largest file offset is EOVERFLOW (Linux
/// file_mmap_ok; do_mmap checks the page offset does not wrap)
fn test_mmap_offset_overflow() {
    const EOVERFLOW: i64 = -75;
    let fd = sys_open(b"/tmp_mmap_ovf\0".as_ptr(), 0o100 | 2, 0o600) as i32; // O_CREAT|O_RDWR
    let mut step = 0;
    if fd < 0 {
        step = 1;
    } else {
        for (i, off) in [0xffff_ffff_ffff_f000u64, 0x7fff_ffff_ffff_f000]
            .into_iter()
            .enumerate()
        {
            let r = sys_mmap(0, 8192, 1, 2, fd, off); // PROT_READ, MAP_PRIVATE
            if r != EOVERFLOW {
                step = 2 + i as i64;
                if r > 0 {
                    sys_munmap(r as u64, 8192);
                }
                break;
            }
        }
        sys_close(fd as u64);
        hk_syscall::sys_unlink(b"/tmp_mmap_ovf\0".as_ptr());
    }
    print(b"MMAP_OFFSET_EOVERFLOW");
    if step == 0 {
        println(b":OK");
    } else {
        fail_num(b":FAIL step ", step);
    }
}
