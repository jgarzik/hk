//! NUMA Memory Policy syscall tests
//!
//! Tests for get_mempolicy, set_mempolicy, and mbind syscalls.
//! Single-node machines: node 0 is the only one with memory.

use crate::harness::{R, check, report_r};
use crate::helpers::{linux_at_least, print, print_num, println};
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
    reset();

    run(b"MPOL_SET_GET", set_get);
    run(b"MPOL_MAXNODE", maxnode);
    run(b"MPOL_MODE_FLAGS", mode_flags);
    run(b"MPOL_GET_FLAGS", get_flags);
    run(b"MPOL_FORK", fork_inherits);
    run(b"MPOL_ADDR", addr_policy);
    run(b"MBIND_POLICY", mbind_policy);
    run(b"MBIND_HOLES", mbind_holes);
    run(b"MBIND_STRICT", mbind_strict);
    run(b"MBIND_FORK", mbind_fork);
}

/// Test: Get default memory policy
#[allow(dead_code)]
fn test_get_mempolicy_default() {
    print(b"  get_mempolicy default: ");

    let mut policy: i32 = -1;
    let ret = sys_get_mempolicy(&mut policy as *mut i32, core::ptr::null_mut(), 0, 0, 0);

    if ret == 0 && policy == MPOL_DEFAULT {
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

const EINVAL: i64 = -22;
const EFAULT: i64 = -14;
const MPOL_PREFERRED_MANY: i32 = 5;
const MPOL_WEIGHTED_INTERLEAVE: i32 = 6;
const MPOL_F_STATIC_NODES: i32 = 1 << 15;
const MPOL_F_RELATIVE_NODES: i32 = 1 << 14;
const MPOL_F_NUMA_BALANCING: i32 = 1 << 13;
const MPOL_F_NODE: u64 = 1;
const MPOL_F_ADDR: u64 = 2;
const MPOL_F_MEMS_ALLOWED: u64 = 4;
const PAGE: u64 = 4096;

/// Run `f` with the task policy reset after it, and report it
fn run(name: &[u8], f: fn() -> R) {
    let r = f();
    reset();
    report_r(name, r);
}

/// Back to MPOL_DEFAULT
fn reset() {
    sys_set_mempolicy(MPOL_DEFAULT, core::ptr::null(), 0);
}

/// set_mempolicy with a one-word mask, all 64 bits read
fn set1(mode: i32, mask: u64) -> i64 {
    sys_set_mempolicy(mode, &mask, 65)
}

/// (return, policy, mask) of get_mempolicy with a one-word mask
fn get1(addr: u64, flags: u64) -> (i64, i32, u64) {
    let mut p = -1;
    let mut m = !0u64;
    let r = sys_get_mempolicy(&mut p, &mut m, 64, addr, flags);
    (r, p, m)
}

/// The task policy is `want` with nodes `mask`
fn is_pol(want: i32, mask: u64) -> R {
    let (r, p, m) = get1(0, 0);
    check(b"get_mempolicy", r == 0, r)?;
    check(b"policy", p == want, i64::from(p))?;
    check(b"nodes", m == mask, m as i64)
}

/// MPOL_SET_GET: set_mempolicy stores the policy and get_mempolicy
/// reports it (Linux do_set_mempolicy, do_get_mempolicy): nodes without
/// memory are dropped, none left is EINVAL; MPOL_PREFERRED without
/// nodes is MPOL_LOCAL; MPOL_DEFAULT and MPOL_LOCAL take no nodes; a
/// refused call keeps the old policy
fn set_get() -> R {
    let cases: [(i32, u64, i32, u64); 7] = [
        (MPOL_BIND, 1, MPOL_BIND, 1),
        (MPOL_PREFERRED, 1, MPOL_PREFERRED, 1),
        (MPOL_INTERLEAVE, 1, MPOL_INTERLEAVE, 1),
        (MPOL_LOCAL, 0, MPOL_LOCAL, 0),
        (MPOL_PREFERRED, 0, MPOL_LOCAL, 0),
        (MPOL_BIND, 1 | 1 << 5, MPOL_BIND, 1),
        (MPOL_DEFAULT, 0, MPOL_DEFAULT, 0),
    ];
    for (mode, mask, want, wmask) in cases {
        let r = set1(mode, mask);
        check(b"set_mempolicy", r == 0, r)?;
        is_pol(want, wmask)?;
    }
    let r = set1(MPOL_BIND, 1 << 5);
    check(b"no node with memory", r == EINVAL, r)?;
    let r = set1(MPOL_DEFAULT, 1);
    check(b"default with nodes", r == EINVAL, r)?;
    let r = set1(MPOL_LOCAL, 1);
    check(b"local with nodes", r == EINVAL, r)?;
    let r = set1(MPOL_BIND, 0);
    check(b"bind without nodes", r == EINVAL, r)?;
    let r = sys_set_mempolicy(MPOL_INTERLEAVE, core::ptr::null(), 64);
    check(b"interleave null mask", r == EINVAL, r)?;
    let r = set1(MPOL_PREFERRED, 1);
    check(b"preferred", r == 0, r)?;
    let r = set1(MPOL_BIND, 1 << 5);
    check(b"refused", r == EINVAL, r)?;
    is_pol(MPOL_PREFERRED, 1)
}

/// MPOL_MAXNODE: the mask holds maxnode - 1 bits (Linux get_nodes):
/// maxnode 0 is EINVAL, 1 reads none; bits past the kernel's
/// MAX_NUMNODES must be zero; more than a page of bits is EINVAL
fn maxnode() -> R {
    let one = 1u64;
    let r = sys_set_mempolicy(MPOL_BIND, &one, 0);
    check(b"maxnode 0", r == EINVAL, r)?;
    let r = sys_set_mempolicy(MPOL_BIND, &one, 1);
    check(b"maxnode 1", r == EINVAL, r)?;
    let r = sys_set_mempolicy(MPOL_BIND, &one, 2);
    check(b"maxnode 2", r == 0, r)?;
    let top = 1u64 << 63;
    let r = sys_set_mempolicy(MPOL_BIND, &top, 64);
    check(b"bit 63 of 64", r == EINVAL, r)?;
    let r = sys_set_mempolicy(MPOL_BIND, &(top | 1), 64);
    check(b"bits 0 and 63 of 64", r == 0, r)?;
    // A page of bits; 1100 is past any MAX_NUMNODES (at most 1024)
    let mut page = [0u64; 512];
    page[0] = 1;
    page[1100 / 64] = 1 << (1100 % 64);
    let r = sys_set_mempolicy(MPOL_BIND, page.as_ptr(), 2048);
    check(b"node 1100", r == EINVAL, r)?;
    page[1100 / 64] = 0;
    let r = sys_set_mempolicy(MPOL_BIND, page.as_ptr(), 2048);
    check(b"2047 bits", r == 0, r)?;
    let r = sys_set_mempolicy(MPOL_BIND, page.as_ptr(), PAGE * 8 + 1);
    check(b"a page of bits", r == 0, r)?;
    let r = sys_set_mempolicy(MPOL_BIND, page.as_ptr(), PAGE * 8 + 2);
    check(b"past a page", r == EINVAL, r)
}

/// MPOL_MODE_FLAGS: mode flags (Linux sanitize_mpol_flags, mpol_new):
/// MPOL_F_STATIC_NODES and MPOL_F_RELATIVE_NODES exclude each other,
/// need nodes, and make get_mempolicy report the caller's mask;
/// MPOL_F_NUMA_BALANCING only with MPOL_BIND and MPOL_PREFERRED_MANY
/// (the latter since Linux 6.10); a mode past MPOL_MAX (MPOL_WEIGHTED_INTERLEAVE
/// since 6.9) is EINVAL
fn mode_flags() -> R {
    let both = MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES;
    let r = set1(MPOL_BIND | both, 1);
    check(b"static and relative", r == EINVAL, r)?;
    let r = set1(MPOL_INTERLEAVE | MPOL_F_NUMA_BALANCING, 1);
    check(b"balancing interleave", r == EINVAL, r)?;
    let r = set1(MPOL_BIND | MPOL_F_NUMA_BALANCING, 1);
    check(b"balancing bind", r == 0, r)?;
    is_pol(MPOL_BIND | MPOL_F_NUMA_BALANCING, 1)?;
    let r = set1(MPOL_PREFERRED_MANY | MPOL_F_NUMA_BALANCING, 1);
    // Before 6.10 EINVAL, unless backported (Ubuntu's 6.8 has it)
    let old = !linux_at_least(6, 10) && r == EINVAL;
    check(b"balancing preferred many", r == 0 || old, r)?;
    let r = set1(MPOL_BIND | MPOL_F_STATIC_NODES, 1 | 1 << 5);
    check(b"static", r == 0, r)?;
    is_pol(MPOL_BIND | MPOL_F_STATIC_NODES, 1 | 1 << 5)?;
    let r = set1(MPOL_BIND | MPOL_F_RELATIVE_NODES, 1 << 1);
    check(b"relative", r == 0, r)?;
    is_pol(MPOL_BIND | MPOL_F_RELATIVE_NODES, 1 << 1)?;
    let r = set1(MPOL_LOCAL | MPOL_F_STATIC_NODES, 0);
    check(b"static local", r == EINVAL, r)?;
    let r = set1(MPOL_PREFERRED | MPOL_F_RELATIVE_NODES, 0);
    check(b"relative preferred local", r == EINVAL, r)?;
    let r = set1(MPOL_BIND | 1 << 16, 1);
    check(b"unknown flag", r == EINVAL, r)?;
    let r = set1(7, 1);
    check(b"mode 7", r == EINVAL, r)?;
    let r = set1(MPOL_WEIGHTED_INTERLEAVE, 1);
    if !linux_at_least(6, 9) {
        return check(b"weighted interleave", r == EINVAL, r);
    }
    check(b"weighted interleave", r == 0, r)?;
    is_pol(MPOL_WEIGHTED_INTERLEAVE, 1)?;
    let (r, p, _) = get1(0, MPOL_F_NODE);
    check(b"weighted next node", r == 0 && p == 0, r)
}

/// MPOL_GET_FLAGS: get_mempolicy flags and mask sizes (Linux
/// kernel_get_mempolicy, do_get_mempolicy, copy_nodes_to_user):
/// MPOL_F_MEMS_ALLOWED alone; an address without MPOL_F_ADDR is EINVAL;
/// MPOL_F_NODE is the next interleave node, EINVAL for other policies;
/// a mask shorter than the kernel's node count is EINVAL, words past it
/// are zeroed, more than a page EINVAL
fn get_flags() -> R {
    let (r, _, _) = get1(0, 8);
    check(b"unknown flag", r == EINVAL, r)?;
    let (r, p, m) = get1(0, MPOL_F_MEMS_ALLOWED);
    check(b"mems allowed", r == 0 && p == 0 && m & 1 != 0, r)?;
    let (r, _, _) = get1(0, MPOL_F_MEMS_ALLOWED | MPOL_F_NODE);
    check(b"mems allowed node", r == EINVAL, r)?;
    let (r, _, _) = get1(0, MPOL_F_MEMS_ALLOWED | MPOL_F_ADDR);
    check(b"mems allowed addr", r == EINVAL, r)?;
    let (r, _, _) = get1(PAGE, 0);
    check(b"addr without flag", r == EINVAL, r)?;
    let (r, _, _) = get1(0, MPOL_F_NODE);
    check(b"default next node", r == EINVAL, r)?;
    set1(MPOL_BIND, 1);
    let (r, _, _) = get1(0, MPOL_F_NODE);
    check(b"bind next node", r == EINVAL, r)?;
    set1(MPOL_INTERLEAVE, 1);
    let (r, p, m) = get1(0, MPOL_F_NODE);
    check(b"interleave next node", r == 0 && p == 0 && m == 1, r)?;
    let mut p = -1;
    let mut w = [!0u64; 3];
    let r = sys_get_mempolicy(&mut p, w.as_mut_ptr(), 0, 0, 0);
    check(b"maxnode 0", r == EINVAL, r)?;
    let r = sys_get_mempolicy(&mut p, core::ptr::null_mut(), 0, 0, 0);
    check(b"no mask", r == 0 && p == MPOL_INTERLEAVE, r)?;
    let r = sys_get_mempolicy(&mut p, w.as_mut_ptr(), 129, 0, 0);
    check(b"129 bits", r == 0, r)?;
    check(b"word 0", w[0] == 1, w[0] as i64)?;
    check(b"word 1 zeroed", w[1] == 0, w[1] as i64)?;
    check(b"word 2 kept", w[2] == !0, w[2] as i64)?;
    let r = sys_get_mempolicy(&mut p, w.as_mut_ptr(), PAGE * 8 + 2, 0, 0);
    check(b"past a page", r == EINVAL, r)
}

/// MPOL_FORK: a child starts with its parent's policy (Linux
/// copy_process: mpol_dup) and changes only its own
fn fork_inherits() -> R {
    use hk_syscall::{sys_exit, sys_fork, sys_wait4};
    set1(MPOL_INTERLEAVE, 1);
    let pid = sys_fork();
    if pid == 0 {
        let (r, p, m) = get1(0, 0);
        let code = if r != 0 || p != MPOL_INTERLEAVE || m != 1 {
            1
        } else if get1(0, MPOL_F_NODE) != (0, 0, 1) {
            2
        } else if set1(MPOL_LOCAL, 0) != 0 {
            3
        } else {
            0
        };
        sys_exit(code);
    }
    check(b"fork", pid > 0, pid)?;
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    check(b"child", st == 0, i64::from(st))?;
    is_pol(MPOL_INTERLEAVE, 1)
}

/// MPOL_ADDR: MPOL_F_ADDR reports the policy of the VMA at the address,
/// MPOL_DEFAULT without one (never the task's), EFAULT outside any VMA;
/// with MPOL_F_NODE the node of its page, faulted in if missing (Linux
/// lookup_node), EFAULT if it cannot be read
fn addr_policy() -> R {
    set1(MPOL_BIND, 1);
    let len = 2 * PAGE;
    let p = sys_mmap(
        0,
        len,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    check(b"mmap", p > 0, p)?;
    let a = p as u64;
    let r = addr_checks(a);
    sys_munmap(a, len);
    r?;
    let (r, _, _) = get1(a, MPOL_F_ADDR);
    check(b"unmapped", r == EFAULT, r)?;
    let q = sys_mmap(0, PAGE, 0, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(b"mmap none", q > 0, q)?;
    let (r1, p1, _) = get1(q as u64, MPOL_F_ADDR);
    let (r2, _, _) = get1(q as u64, MPOL_F_ADDR | MPOL_F_NODE);
    sys_munmap(q as u64, PAGE);
    check(b"prot none", r1 == 0 && p1 == MPOL_DEFAULT, r1)?;
    check(b"prot none node", r2 == EFAULT, r2)
}

/// The MPOL_ADDR checks on the two fresh pages at `a`
fn addr_checks(a: u64) -> R {
    let (r, p, m) = get1(a + 8, MPOL_F_ADDR);
    check(
        b"vma policy",
        r == 0 && p == MPOL_DEFAULT && m == 0,
        i64::from(p),
    )?;
    // SAFETY: the first page is mapped writable
    unsafe { core::ptr::write_volatile(a as *mut u8, 1) };
    let (r, p, _) = get1(a, MPOL_F_ADDR | MPOL_F_NODE);
    check(b"touched node", r == 0 && p == 0, r)?;
    let (r, p, _) = get1(a + PAGE, MPOL_F_ADDR | MPOL_F_NODE);
    check(b"untouched node", r == 0 && p == 0, r)
}

const MPOL_MF_STRICT: u32 = 1;
const MPOL_MF_MOVE: u32 = 2;
const MPOL_MF_LAZY: u32 = 8;

/// mbind with a one-word mask, all 64 bits read
fn mbind1(a: u64, len: u64, mode: i32, mask: u64, flags: u32) -> i64 {
    sys_mbind(a, len, mode as u64, &mask, 65, flags)
}

/// The VMA policy at `a` is `want` with nodes `mask`
fn vma_is(a: u64, want: i32, mask: u64) -> R {
    let (r, p, m) = get1(a, MPOL_F_ADDR);
    check(b"get_mempolicy addr", r == 0, r)?;
    check(b"vma policy", p == want, i64::from(p))?;
    check(b"vma nodes", m == mask, m as i64)
}

/// `pages` fresh anonymous read-write pages
fn map_pages(pages: u64) -> Result<u64, (&'static [u8], i64)> {
    let p = sys_mmap(
        0,
        pages * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    check(b"mmap", p > 0, p)?;
    Ok(p as u64)
}

/// Run `f` on `pages` fresh pages, unmapped after it
fn with_pages(pages: u64, f: fn(u64) -> R) -> R {
    let a = map_pages(pages)?;
    let r = f(a);
    sys_munmap(a, pages * PAGE);
    r
}

/// MBIND_POLICY: mbind gives the VMAs of the range the policy, split at
/// its edges, the length rounded up to pages (Linux do_mbind,
/// mbind_range); MPOL_DEFAULT removes it; the task policy is untouched;
/// argument checks (EINVAL: flags, alignment, a wrapping range, the
/// mode's nodes)
fn mbind_policy() -> R {
    with_pages(4, |a| {
        let r = mbind1(a + PAGE, 2 * PAGE, MPOL_BIND, 1, 0);
        check(b"mbind bind", r == 0, r)?;
        vma_is(a, MPOL_DEFAULT, 0)?;
        vma_is(a + PAGE, MPOL_BIND, 1)?;
        vma_is(a + 2 * PAGE + 8, MPOL_BIND, 1)?;
        vma_is(a + 3 * PAGE, MPOL_DEFAULT, 0)?;
        is_pol(MPOL_DEFAULT, 0)?;
        let r = mbind1(a, 1, MPOL_INTERLEAVE, 1, 0);
        check(b"mbind one byte", r == 0, r)?;
        vma_is(a, MPOL_INTERLEAVE, 1)?;
        vma_is(a + PAGE, MPOL_BIND, 1)?;
        let r = mbind1(
            a + 3 * PAGE,
            PAGE,
            MPOL_PREFERRED | MPOL_F_STATIC_NODES,
            1 | 1 << 5,
            0,
        );
        check(b"mbind static", r == 0, r)?;
        vma_is(
            a + 3 * PAGE,
            MPOL_PREFERRED | MPOL_F_STATIC_NODES,
            1 | 1 << 5,
        )?;
        let r = mbind1(a + 2 * PAGE, PAGE, MPOL_PREFERRED, 0, 0);
        check(b"mbind preferred local", r == 0, r)?;
        vma_is(a + 2 * PAGE, MPOL_LOCAL, 0)?;
        let r = mbind1(a, 4 * PAGE, MPOL_DEFAULT, 0, 0);
        check(b"mbind default", r == 0, r)?;
        for i in 0..4 {
            vma_is(a + i * PAGE, MPOL_DEFAULT, 0)?;
        }
        let r = mbind1(a, 0, MPOL_BIND, 1, 0);
        check(b"length 0", r == 0, r)?;
        let r = mbind1(a + 1, PAGE, MPOL_BIND, 1, 0);
        check(b"unaligned", r == EINVAL, r)?;
        let r = mbind1(a, PAGE, MPOL_BIND, 1, MPOL_MF_LAZY);
        check(b"lazy", r == EINVAL, r)?;
        let r = mbind1(a, !(PAGE - 1), MPOL_BIND, 1, 0);
        check(b"wraps", r == EINVAL, r)?;
        let r = mbind1(a, PAGE, MPOL_BIND, 0, 0);
        check(b"bind without nodes", r == EINVAL, r)?;
        let r = mbind1(a, PAGE, MPOL_DEFAULT, 1, 0);
        check(b"default with nodes", r == EINVAL, r)?;
        let r = mbind1(a, PAGE, MPOL_BIND, 1 << 5, 0);
        check(b"no node with memory", r == EINVAL, r)?;
        vma_is(a, MPOL_DEFAULT, 0)
    })
}

/// MBIND_HOLES: a hole in the range is EFAULT and nothing changes,
/// except for MPOL_DEFAULT; a range with no VMA is EFAULT for every
/// mode (Linux queue_pages_range, queue_pages_test_walk)
fn mbind_holes() -> R {
    let a = map_pages(3)?;
    sys_munmap(a + PAGE, PAGE);
    let r = holes(a);
    sys_munmap(a, 3 * PAGE);
    r?;
    let r = mbind1(a, PAGE, MPOL_DEFAULT, 0, 0);
    check(b"unmapped", r == EFAULT, r)
}

/// The MBIND_HOLES checks: pages 0 and 2 at `a` mapped, 1 not
fn holes(a: u64) -> R {
    let r = mbind1(a, 3 * PAGE, MPOL_BIND, 1, 0);
    check(b"middle hole", r == EFAULT, r)?;
    vma_is(a, MPOL_DEFAULT, 0)?;
    let r = mbind1(a, 2 * PAGE, MPOL_BIND, 1, 0);
    check(b"tail hole", r == EFAULT, r)?;
    let r = mbind1(a + PAGE, 2 * PAGE, MPOL_BIND, 1, 0);
    check(b"head hole", r == EFAULT, r)?;
    vma_is(a + 2 * PAGE, MPOL_DEFAULT, 0)?;
    let r = mbind1(a + PAGE, PAGE, MPOL_DEFAULT, 0, 0);
    check(b"default in the hole", r == EFAULT, r)?;
    let r = mbind1(a + 2 * PAGE, PAGE, MPOL_BIND, 1, 0);
    check(b"bind", r == 0, r)?;
    let r = mbind1(a, 3 * PAGE, MPOL_DEFAULT, 0, 0);
    check(b"default over the hole", r == 0, r)?;
    vma_is(a + 2 * PAGE, MPOL_DEFAULT, 0)
}

/// MBIND_STRICT: MPOL_MF_STRICT with a page off the policy's nodes is
/// EIO and, without a move, leaves the policy unchanged; with
/// MPOL_MF_MOVE the page goes where the policy puts it (here: where it
/// is); untouched pages and MPOL_DEFAULT check nothing (Linux
/// queue_folios_pte_range, strictly_unmovable)
fn mbind_strict() -> R {
    with_pages(2, |a| {
        // SAFETY: the first page is mapped writable
        unsafe { core::ptr::write_volatile(a as *mut u8, 1) };
        let r = mbind1(a, 2 * PAGE, MPOL_BIND, 1, MPOL_MF_STRICT);
        check(b"strict on node 0", r == 0, r)?;
        vma_is(a, MPOL_BIND, 1)?;
        let r = mbind1(a, 2 * PAGE, MPOL_LOCAL, 0, MPOL_MF_STRICT);
        check(b"strict local", r == -5, r)?;
        vma_is(a, MPOL_BIND, 1)?;
        let r = mbind1(a + PAGE, PAGE, MPOL_LOCAL, 0, MPOL_MF_STRICT);
        check(b"strict untouched", r == 0, r)?;
        vma_is(a + PAGE, MPOL_LOCAL, 0)?;
        let r = mbind1(a, 2 * PAGE, MPOL_LOCAL, 0, MPOL_MF_STRICT | MPOL_MF_MOVE);
        check(b"strict move local", r == 0, r)?;
        vma_is(a, MPOL_LOCAL, 0)?;
        let r = mbind1(a, 2 * PAGE, MPOL_DEFAULT, 0, MPOL_MF_STRICT);
        check(b"strict default", r == 0, r)?;
        vma_is(a, MPOL_DEFAULT, 0)
    })
}

/// MBIND_FORK: a child's VMAs keep their policies (Linux dup_mmap:
/// vma_dup_policy)
fn mbind_fork() -> R {
    use hk_syscall::{sys_exit, sys_fork, sys_wait4};
    with_pages(2, |a| {
        let r = mbind1(a + PAGE, PAGE, MPOL_INTERLEAVE, 1, 0);
        check(b"mbind", r == 0, r)?;
        let pid = sys_fork();
        if pid == 0 {
            let ok =
                vma_is(a, MPOL_DEFAULT, 0).is_ok() && vma_is(a + PAGE, MPOL_INTERLEAVE, 1).is_ok();
            sys_exit(if ok { 0 } else { 1 });
        }
        check(b"fork", pid > 0, pid)?;
        let mut st = 0i32;
        sys_wait4(pid, &mut st, 0, 0);
        check(b"child", st == 0, i64::from(st))
    })
}
