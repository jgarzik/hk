//! Page protection and 2MB page splits (Linux mm/mprotect.c,
//! mm/huge_memory.c __split_huge_pmd)
//!
//! Tests:
//! - THP_SPLIT_MPROTECT: mprotect of one 4KB page inside a 2MB page
//!   (MADV_HUGEPAGE) splits it; every page keeps its data, before and
//!   after the protection is restored
//! - THP_SPLIT_MUNMAP: munmap of a few pages inside a 2MB page splits
//!   it; the rest keeps its data, the hole is unmapped (mincore ENOMEM)

use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_madvise, sys_mincore, sys_mmap, sys_mprotect, sys_munmap, MAP_ANONYMOUS, MAP_PRIVATE,
    PROT_READ, PROT_WRITE,
};

const PAGE: u64 = 4096;
const HUGE: u64 = 2 << 20;
const MADV_HUGEPAGE: i32 = 14;
const RW: u32 = PROT_READ | PROT_WRITE;
const ENOMEM: i64 = -12;

pub fn run_tests() {
    thp_split_mprotect();
    thp_split_munmap();
}

fn report(name: &[u8], code: i64) {
    print(name);
    if code == 0 {
        println(b":OK");
    } else {
        print(b":FAIL ");
        print_num(code);
        println(b"");
    }
}

fn get(a: u64) -> u64 {
    unsafe { core::ptr::read_volatile(a as *const u64) }
}

fn put(a: u64, v: u64) {
    unsafe { core::ptr::write_volatile(a as *mut u64, v) }
}

/// Pattern word of the page at `a`
fn pattern(a: u64) -> u64 {
    a ^ 0x6b6b_0000_0000_6b6b
}

/// Write the pattern at the start and end of each page of [a, a + len)
fn fill(a: u64, len: u64) {
    for p in (a..a + len).step_by(PAGE as usize) {
        put(p, pattern(p));
        put(p + PAGE - 8, pattern(p));
    }
}

/// [a, a + len) still holds the pattern, except the pages of [hole, hole_end)
fn intact(a: u64, len: u64, hole: u64, hole_end: u64) -> bool {
    (a..a + len)
        .step_by(PAGE as usize)
        .filter(|&p| p < hole || p >= hole_end)
        .all(|p| get(p) == pattern(p) && get(p + PAGE - 8) == pattern(p))
}

/// `n` 2MB-aligned huge-page-eligible bytes (a mapping of `n + HUGE`
/// starting at the returned `.1`), filled with the pattern; None if mmap fails
fn huge_area(n: u64) -> Option<(u64, u64)> {
    let p = sys_mmap(0, n + HUGE, RW, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if p < 0 {
        return None;
    }
    let p = p as u64;
    let base = (p + HUGE - 1) & !(HUGE - 1);
    // EINVAL without THP support (Linux): the test still holds
    sys_madvise(base, n, MADV_HUGEPAGE);
    fill(base, n);
    Some((base, p))
}

fn thp_split_mprotect() {
    const NAME: &[u8] = b"THP_SPLIT_MPROTECT";
    let Some((base, p)) = huge_area(2 * HUGE) else {
        return report(NAME, -1);
    };
    let one = base + HUGE / 2;
    let mut code = 0;
    if sys_mprotect(one, PAGE, PROT_READ) != 0 {
        code = 1;
    } else if !intact(base, 2 * HUGE, 0, 0) {
        code = 2;
    } else if sys_mprotect(one, PAGE, RW) != 0 {
        code = 3;
    } else {
        fill(base, 2 * HUGE);
        if !intact(base, 2 * HUGE, 0, 0) {
            code = 4;
        }
    }
    sys_munmap(p, 3 * HUGE);
    report(NAME, code);
}

fn thp_split_munmap() {
    const NAME: &[u8] = b"THP_SPLIT_MUNMAP";
    let Some((base, p)) = huge_area(2 * HUGE) else {
        return report(NAME, -1);
    };
    let hole = base + HUGE + 5 * PAGE;
    let hole_end = hole + 3 * PAGE;
    let mut vec = [0u8; 3];
    let mut code = 0;
    if sys_munmap(hole, hole_end - hole) != 0 {
        code = 1;
    } else if !intact(base, 2 * HUGE, hole, hole_end) {
        code = 2;
    } else if sys_mincore(hole, PAGE, vec.as_mut_ptr()) != ENOMEM {
        code = 3;
    } else {
        // The pages around the hole are still writable
        fill(base + HUGE, 5 * PAGE);
        fill(hole_end, base + 2 * HUGE - hole_end);
        if !intact(base, 2 * HUGE, hole, hole_end) {
            code = 4;
        }
    }
    sys_munmap(p, 3 * HUGE);
    report(NAME, code);
}
