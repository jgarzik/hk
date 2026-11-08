//! NUMA Memory Policy syscall tests
//!
//! Tests for get_mempolicy, set_mempolicy, and mbind syscalls.
//! These are stub implementations for single-node systems.
//!
//! NOTE: Running these tests on aarch64 causes CLONE_CLEAR_SIGHAND to fail
//! due to a binary layout sensitivity issue. The tests are conditionally
//! skipped on ARM until this is investigated.

use crate::helpers::{print, print_num, println};
#[allow(unused_imports)]
use hk_syscall::{
    sys_get_mempolicy, sys_mbind, sys_migrate_pages, sys_mmap, sys_move_pages, sys_munmap,
    sys_set_mempolicy,
};

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
    test_migrate_pages_self();
    test_migrate_pages_null_masks();
    test_move_pages_query();
    test_move_pages_node0();
    test_move_pages_invalid_node();
    test_migrate_pages_perm();
}

/// Test: Get default memory policy
#[allow(dead_code)]
fn test_get_mempolicy_default() {
    print(b"  get_mempolicy default: ");

    let mut policy: i32 = -1;
    let ret = sys_get_mempolicy(&mut policy as *mut i32, core::ptr::null_mut(), 0, 0, 0);

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

/// Test: migrate_pages on current process
#[allow(dead_code)]
fn test_migrate_pages_self() {
    print(b"  migrate_pages self: ");

    // Migrate current process pages from node 0 to node 0
    let old_nodes: u64 = 1; // bit 0 = node 0
    let new_nodes: u64 = 1; // bit 0 = node 0

    let ret = sys_migrate_pages(0, 64, &old_nodes as *const u64, &new_nodes as *const u64);

    if ret == 0 {
        println(b"PASS");
    } else {
        print(b"FAIL (ret=");
        print_num(ret);
        println(b")");
    }
}

/// Test: migrate_pages with NULL masks (should work)
#[allow(dead_code)]
fn test_migrate_pages_null_masks() {
    print(b"  migrate_pages null masks: ");

    let ret = sys_migrate_pages(0, 64, core::ptr::null(), core::ptr::null());

    // NULL new_nodes is an empty mask: EINVAL (Linux kernel_migrate_pages)
    if ret == -22 {
        println(b"PASS");
    } else {
        print(b"FAIL (ret=");
        print_num(ret);
        println(b")");
    }
}

/// Test: move_pages query mode (nodes=NULL)
#[allow(dead_code)]
fn test_move_pages_query() {
    print(b"  move_pages query: ");

    // Create a page to query
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

    // Populate the page: Linux reports -EFAULT status for unmapped pages
    unsafe { core::ptr::write_volatile(ptr as *mut u8, 1) };

    let pages: [u64; 1] = [ptr as u64];
    let mut status: [i32; 1] = [-1];

    let ret = sys_move_pages(
        0,
        1,
        pages.as_ptr(),
        core::ptr::null(), // Query mode
        status.as_mut_ptr(),
        0,
    );

    sys_munmap(ptr as u64, 4096);

    // Should return node 0 for single-node system
    if ret == 0 && status[0] == 0 {
        println(b"PASS");
    } else {
        print(b"FAIL (ret=");
        print_num(ret);
        print(b", status=");
        print_num(status[0] as i64);
        println(b")");
    }
}

/// Test: move_pages to node 0 (should succeed)
#[allow(dead_code)]
fn test_move_pages_node0() {
    print(b"  move_pages node0: ");

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

    // Populate the page: Linux reports -EFAULT status for unmapped pages
    unsafe { core::ptr::write_volatile(ptr as *mut u8, 1) };

    let pages: [u64; 1] = [ptr as u64];
    let nodes: [i32; 1] = [0]; // Node 0
    let mut status: [i32; 1] = [-1];

    let ret = sys_move_pages(0, 1, pages.as_ptr(), nodes.as_ptr(), status.as_mut_ptr(), 0);

    sys_munmap(ptr as u64, 4096);

    if ret == 0 && status[0] == 0 {
        println(b"PASS");
    } else {
        print(b"FAIL (ret=");
        print_num(ret);
        print(b", status=");
        print_num(status[0] as i64);
        println(b")");
    }
}

/// Test: move_pages to non-existent node (should fail per-page)
#[allow(dead_code)]
fn test_move_pages_invalid_node() {
    print(b"  move_pages invalid node: ");

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

    let pages: [u64; 1] = [ptr as u64];
    // No machine here has a node 63 (hk and Linux both number below
    // MAX_NUMNODES, so it is a valid id, just not online: ENODEV)
    let nodes: [i32; 1] = [63];
    let mut status: [i32; 1] = [0];

    let ret = sys_move_pages(0, 1, pages.as_ptr(), nodes.as_ptr(), status.as_mut_ptr(), 0);

    sys_munmap(ptr as u64, 4096);

    // An invalid target node fails the whole call with ENODEV
    // (Linux mm/migrate.c do_pages_move)
    if ret == -19 {
        println(b"PASS");
    } else {
        print(b"FAIL (ret=");
        print_num(ret);
        print(b", status=");
        print_num(status[0] as i64);
        println(b")");
    }
}

/// MIGRATE_PAGES_PERM: migrate_pages and move_pages on another process
/// as an unprivileged user (Linux kernel_migrate_pages,
/// find_mm_struct): no such pid is ESRCH before any permission check,
/// root's init is EPERM (ptrace_may_access, PTRACE_MODE_READ_REALCREDS),
/// and one's own same-uid child needs no CAP_SYS_NICE; a move_pages of
/// no page still looks the target up first
fn test_migrate_pages_perm() {
    use hk_syscall::{
        sys_exit, sys_fork, sys_kill, sys_pause, sys_prctl, sys_setresgid, sys_setresuid, sys_wait4,
    };
    const ESRCH: i64 = -3;
    const EPERM: i64 = -1;
    let prober = sys_fork();
    if prober == 0 {
        if sys_setresgid(1000, 1000, 1000) != 0 || sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(1);
        }
        // The id change made it non-dumpable (Linux commit_creds)
        sys_prctl(4, 1, 0, 0, 0); // PR_SET_DUMPABLE
        let child = sys_fork();
        if child == 0 {
            sys_pause();
            sys_exit(0);
        }
        let node0: u64 = 1;
        let mask = &node0 as *const u64;
        let word = 0u64;
        let pages: [u64; 1] = [&word as *const u64 as u64];
        let mut status: [i32; 1] = [0];
        let none = core::ptr::null();
        let mut move_query =
            |pid: i64, n: u64| sys_move_pages(pid, n, pages.as_ptr(), none, status.as_mut_ptr(), 0);
        let code = if sys_migrate_pages(99_999_999, 64, mask, mask) != ESRCH {
            2
        } else if sys_migrate_pages(1, 64, mask, mask) != EPERM {
            3
        } else if sys_migrate_pages(child, 64, mask, mask) < 0 {
            4
        } else if move_query(99_999_999, 0) != ESRCH {
            5
        } else if move_query(1, 1) != EPERM {
            6
        } else if move_query(child, 1) != 0 {
            7
        } else {
            0
        };
        sys_kill(child, 9);
        let mut st = 0i32;
        sys_wait4(child, &mut st, 0, 0);
        sys_exit(code);
    }
    let mut st = 0i32;
    sys_wait4(prober, &mut st, 0, 0);
    print(b"MIGRATE_PAGES_PERM");
    if st == 0 {
        println(b":OK");
    } else {
        print(b":FAIL wstatus=");
        print_num(i64::from(st));
        println(b"");
    }
}
