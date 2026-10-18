//! vm.max_map_count (Linux mm/mmap.c sysctl_max_map_count): the
//! default, mmap refused with ENOMEM once the address space has more
//! VMAs than the limit, and a split (an munmap hole, an mprotect of a
//! VMA's middle) refused at it. Runs in an isolated child; the limit
//! is restored.

use super::helpers::{print, print_num, println, read_file};
use hk_syscall::{
    MAP_ANONYMOUS, MAP_PRIVATE, O_WRONLY, PROT_NONE, PROT_READ, sys_close, sys_mmap, sys_mprotect,
    sys_munmap, sys_open, sys_write,
};

const PAGE: u64 = 4096;
const ENOMEM: i64 = -12;
const PATH: &[u8] = b"/proc/sys/vm/max_map_count\0";

fn verdict(name: &[u8], ok: bool, got: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL got ");
        print_num(got);
        println(b"");
    }
}

fn read_limit() -> i64 {
    let mut b = [0u8; 32];
    let n = read_file(PATH, &mut b);
    if n <= 0 {
        return -1;
    }
    b[..n as usize]
        .iter()
        .take_while(|c| c.is_ascii_digit())
        .fold(0, |v, &c| v * 10 + (c - b'0') as i64)
}

fn write_limit(v: i64) -> bool {
    let mut b = [0u8; 24];
    let mut n = b.len();
    let mut x = v;
    loop {
        n -= 1;
        b[n] = b'0' + (x % 10) as u8;
        x /= 10;
        if x == 0 {
            break;
        }
    }
    let fd = sys_open(PATH.as_ptr(), O_WRONLY, 0);
    if fd < 0 {
        return false;
    }
    let w = sys_write(fd as u64, b[n..].as_ptr(), (b.len() - n) as u64);
    sys_close(fd as u64);
    w == (b.len() - n) as i64
}

/// VMAs of this address space: /proc/self/maps lines, less Linux's
/// x86 [vsyscall] (a gate area, not a VMA)
fn map_count() -> i64 {
    let mut b = [0u8; 16384];
    let n = read_file(b"/proc/self/maps\0", &mut b);
    if n <= 0 {
        return -1;
    }
    b[..n as usize]
        .split(|&c| c == b'\n')
        .filter(|l| !l.is_empty() && !l.windows(10).any(|w| w == b"[vsyscall]"))
        .count() as i64
}

fn map(prot: u32) -> i64 {
    sys_mmap(0, 3 * PAGE, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
}

pub fn run_tests() {
    let def = read_limit();
    verdict(b"MAX_MAP_COUNT_DEFAULT", def == 65530, def);
    let limit = map_count() + 8;
    if !write_limit(limit) {
        println(b"MAX_MAP_COUNT_SET:FAIL");
        return;
    }
    // Neighbours alternate protections, so no two merge
    let mut last = 0;
    let mut err = 0;
    for i in 0..64 {
        let p = map(if i % 2 == 0 { PROT_READ } else { PROT_NONE });
        if p < 0 {
            err = p;
            break;
        }
        last = p;
    }
    let count = map_count();
    // mmap refuses once the count exceeds the limit (Linux: map_count >
    // max), so it stops at limit + 1
    verdict(
        b"MAX_MAP_COUNT_MMAP",
        err == ENOMEM && count == limit + 1,
        count - limit,
    );
    // At the limit, a hole or a middle mprotect would add a VMA
    let hole = sys_munmap(last as u64 + PAGE, PAGE);
    let mid = sys_mprotect(last as u64 + PAGE, PAGE, PROT_READ | 2);
    let whole = sys_munmap(last as u64, 3 * PAGE);
    verdict(
        b"MAX_MAP_COUNT_SPLIT",
        hole == ENOMEM && mid == ENOMEM && whole == 0,
        hole * 1000 + mid,
    );
    let restored = write_limit(def);
    let again = map(PROT_READ);
    verdict(b"MAX_MAP_COUNT_RESTORE", restored && again > 0, again);
}
