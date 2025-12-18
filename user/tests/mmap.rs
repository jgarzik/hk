//! Memory mapping tests
//!
//! Tests for mmap and munmap syscalls:
//! - Anonymous mmap (MAP_ANONYMOUS | MAP_PRIVATE)
//! - Write/read to mmap'd memory
//! - munmap to release memory
//! - Large anonymous mmap with demand paging

use super::helpers::{print, println, print_num};
use crate::syscall::{
    sys_mmap, sys_munmap,
    MAP_ANONYMOUS, MAP_PRIVATE,
    PROT_READ, PROT_WRITE,
};

/// Run all mmap tests
pub fn run_tests() {
    test_anonymous_mmap();
    test_mmap_write_read();
    test_munmap();
    test_large_anonymous_mmap();
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
