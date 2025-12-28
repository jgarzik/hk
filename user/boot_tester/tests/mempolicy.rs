//! NUMA Memory Policy syscall tests
//!
//! Tests for get_mempolicy, set_mempolicy, and mbind syscalls.
//! These are stub implementations for single-node systems.
//!
//! NOTE: Running these tests on aarch64 causes CLONE_CLEAR_SIGHAND to fail
//! due to a binary layout sensitivity issue. The tests are conditionally
//! skipped on ARM until this is investigated.

use super::helpers::{print, print_num, println};
#[allow(unused_imports)]
use hk_syscall::{sys_get_mempolicy, sys_mbind, sys_mmap, sys_munmap, sys_set_mempolicy};

// Policy modes
const MPOL_DEFAULT: i32 = 0;
#[allow(dead_code)]
const MPOL_PREFERRED: i32 = 1;
#[allow(dead_code)]
const MPOL_BIND: i32 = 2;
#[allow(dead_code)]
const MPOL_INTERLEAVE: i32 = 3;
const MPOL_LOCAL: i32 = 4;

// mmap constants
#[allow(dead_code)]
const PROT_READ: u32 = 1;
#[allow(dead_code)]
const PROT_WRITE: u32 = 2;
#[allow(dead_code)]
const MAP_PRIVATE: u32 = 0x02;
#[allow(dead_code)]
const MAP_ANONYMOUS: u32 = 0x20;

/// Run all mempolicy tests
pub fn run_tests() {
    println(b"=== mempolicy Tests ===");

    test_get_mempolicy_default();
    test_set_mempolicy_default();
    test_set_mempolicy_local();
    test_set_mempolicy_bind_node0();
    test_mbind_anonymous();
    test_get_mempolicy_nodemask();
}

/// Test: Get default memory policy
#[allow(dead_code)]
fn test_get_mempolicy_default() {
    print(b"  get_mempolicy default: ");

    let mut policy: i32 = -1;
    let ret = sys_get_mempolicy(
        &mut policy as *mut i32,
        core::ptr::null_mut(),
        0,
        0,
        0,
    );

    if ret == 0 && (policy == MPOL_DEFAULT || policy == MPOL_LOCAL) {
        println(b"PASS");
    } else {
        print(b"FAIL (ret=");
        print_num(ret);
        print(b", policy=");
        print_num(policy as i64);
        println(b")");
    }
}

/// Test: Set policy to MPOL_DEFAULT
#[allow(dead_code)]
fn test_set_mempolicy_default() {
    print(b"  set_mempolicy DEFAULT: ");

    let ret = sys_set_mempolicy(MPOL_DEFAULT, core::ptr::null(), 0);

    if ret == 0 {
        println(b"PASS");
    } else {
        print(b"FAIL (ret=");
        print_num(ret);
        println(b")");
    }
}

/// Test: Set policy to MPOL_LOCAL
#[allow(dead_code)]
fn test_set_mempolicy_local() {
    print(b"  set_mempolicy LOCAL: ");

    let ret = sys_set_mempolicy(MPOL_LOCAL, core::ptr::null(), 0);

    if ret == 0 {
        println(b"PASS");
    } else {
        print(b"FAIL (ret=");
        print_num(ret);
        println(b")");
    }
}

/// Test: Set policy to MPOL_BIND with node 0
#[allow(dead_code)]
fn test_set_mempolicy_bind_node0() {
    print(b"  set_mempolicy BIND node0: ");

    // Node mask with only bit 0 set (node 0)
    let nodemask: u64 = 1;
    let ret = sys_set_mempolicy(MPOL_BIND, &nodemask as *const u64, 64);

    if ret == 0 {
        println(b"PASS");
    } else {
        print(b"FAIL (ret=");
        print_num(ret);
        println(b")");
    }
}

/// Test: mbind on anonymous mapping
#[allow(dead_code)]
fn test_mbind_anonymous() {
    print(b"  mbind anonymous: ");

    // Create anonymous mapping
    let ptr = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr < 0 {
        print(b"FAIL (mmap error=");
        print_num(ptr);
        println(b")");
        return;
    }

    // Bind to node 0
    let nodemask: u64 = 1;
    let ret = sys_mbind(
        ptr as u64,
        4096,
        MPOL_BIND as u64,
        &nodemask as *const u64,
        64,
        0, // no flags
    );

    // Clean up
    sys_munmap(ptr as u64, 4096);

    if ret == 0 {
        println(b"PASS");
    } else {
        print(b"FAIL (ret=");
        print_num(ret);
        println(b")");
    }
}

/// Test: Get mempolicy with nodemask output
#[allow(dead_code)]
fn test_get_mempolicy_nodemask() {
    print(b"  get_mempolicy nodemask: ");

    let mut policy: i32 = -1;
    let mut nodemask: u64 = 0;

    let ret = sys_get_mempolicy(
        &mut policy as *mut i32,
        &mut nodemask as *mut u64,
        64, // maxnode
        0,
        0,
    );

    // For single-node system, nodemask should have bit 0 set
    if ret == 0 && (nodemask & 1) != 0 {
        println(b"PASS");
    } else {
        print(b"FAIL (ret=");
        print_num(ret);
        print(b", nodemask=");
        print_num(nodemask as i64);
        println(b")");
    }
}
