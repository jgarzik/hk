//! Range arguments of the memory syscalls (Linux mm/madvise.c,
//! mm/mlock.c, mm/vma.c do_vmi_munmap, mm/mmap.c brk, mm/mprotect.c,
//! mm/msync.c, mm/mincore.c): errno for every kind of bad range, and
//! the mappings left behind (/proc/self/maps, data, fork)
//!
//! Each table runs its cases in order; a FAIL names the first case that
//! returned the wrong value. "top" is the end of the user address space
//! (TASK_SIZE), probed at run time: it differs between kernels.
//!
//! Tests:
//! - MADV_ARGS: invalid advice and unaligned starts are EINVAL (also
//!   with length 0), a length that wraps when rounded up is EINVAL,
//!   length 0 is a no-op; ranges at or past top, straddling it, or with
//!   unmapped parts are ENOMEM; the mapping is unchanged
//! - MADV_HOLES: advice over two VMAs with a hole between applies to
//!   both and returns ENOMEM: MADV_DONTNEED empties both, MADV_DONTFORK
//!   splits both at the range edges (a child misses exactly those pages)
//! - MADV_SPLIT: flag advice on part of a VMA splits it there
//!   (DONTFORK, WIPEONFORK, DONTDUMP: maps lines; a child sees each
//!   part as advised) and undoing it merges the parts again; advice
//!   that changes nothing does not split; MADV_DONTNEED of part of a
//!   VMA empties only that part
//! - MADV_LOCKED: DONTNEED, FREE, COLD, PAGEOUT and REMOVE are EINVAL on
//!   a locked VMA; over [unlocked][locked] the first is emptied before
//!   the error, over [locked][unlocked] nothing is
//! - MADV_SHARED: MADV_REMOVE over [shared][private] punches the shared
//!   page, then fails EINVAL; MADV_FREE is EINVAL on shared memory and
//!   stops there

use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_close, sys_exit, sys_fork, sys_madvise, sys_mincore, sys_mlock, sys_mmap, sys_mprotect,
    sys_munlock, sys_munmap, sys_open, sys_read, sys_wait4, MADV_COLD, MADV_DODUMP, MADV_DOFORK,
    MADV_DONTDUMP, MADV_DONTFORK, MADV_DONTNEED, MADV_FREE, MADV_KEEPONFORK, MADV_NORMAL,
    MADV_PAGEOUT, MADV_RANDOM, MADV_REMOVE, MADV_WILLNEED, MADV_WIPEONFORK, MAP_ANONYMOUS,
    MAP_FIXED, MAP_FIXED_NOREPLACE, MAP_PRIVATE, MAP_SHARED, O_RDONLY, PROT_NONE, PROT_READ,
    PROT_WRITE,
};

const P: u64 = 4096;
const RW: u32 = PROT_READ | PROT_WRITE;
const ENOMEM: i64 = -12;
const EINVAL: i64 = -22;
const EEXIST: i64 = -17;
/// The highest page-aligned address
const LAST: u64 = !(P - 1);

pub fn run_tests() {
    madv_args();
    madv_holes();
    madv_split();
    madv_locked();
    madv_shared();
}

// ============================================================================
// Helpers
// ============================================================================

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

/// Run `cases` (a, b, c, expected) through `f` in order: 0, or the
/// 1-based index of the first case returning something else (printed)
fn table(name: &[u8], cases: &[(u64, u64, i64, i64)], f: fn(u64, u64, i64) -> i64) -> i64 {
    for (i, &(a, b, c, want)) in cases.iter().enumerate() {
        let got = f(a, b, c);
        if got != want {
            print(name);
            print(b": case ");
            print_num(i as i64 + 1);
            print(b" got ");
            print_num(got);
            print(b" want ");
            print_num(want);
            println(b"");
            return i as i64 + 1;
        }
    }
    0
}

fn get(a: u64) -> u64 {
    unsafe { core::ptr::read_volatile(a as *const u64) }
}

fn put(a: u64, v: u64) {
    unsafe { core::ptr::write_volatile(a as *mut u64, v) }
}

fn pattern(a: u64) -> u64 {
    a ^ 0x5a5a_0000_0000_5a5a
}

/// Write the pattern word of each page of [a, a + len)
fn fill(a: u64, len: u64) {
    for p in (a..a + len).step_by(P as usize) {
        put(p, pattern(p));
    }
}

/// Each page of [a, a + len) holds its pattern word
fn intact(a: u64, len: u64) -> bool {
    (a..a + len).step_by(P as usize).all(|p| get(p) == pattern(p))
}

/// Each page of [a, a + len) reads zero
fn zeroed(a: u64, len: u64) -> bool {
    (a..a + len).step_by(P as usize).all(|p| get(p) == 0)
}

/// A VMA is mapped at `a` (mincore succeeds)
fn mapped(a: u64) -> bool {
    let mut v = [0u8; 1];
    sys_mincore(a, P, v.as_mut_ptr()) == 0
}

/// `n` read-write private anonymous pages, filled, with an unmapped
/// page below and above; None if mmap fails
fn area(n: u64) -> Option<u64> {
    let p = sys_mmap(0, (n + 2) * P, RW, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if p < 0 {
        return None;
    }
    let p = p as u64;
    sys_munmap(p, P);
    sys_munmap(p + (n + 1) * P, P);
    fill(p + P, n * P);
    Some(p + P)
}

/// End of the user address space: the largest candidate whose last
/// page can be mapped (or already is)
fn top() -> u64 {
    #[cfg(target_arch = "x86_64")]
    const C: [u64; 2] = [(1 << 47) - P, (1 << 56) - P];
    #[cfg(target_arch = "aarch64")]
    const C: [u64; 2] = [1 << 48, 1 << 52];
    let mut t = C[0];
    for &c in &C[1..] {
        if mappable(c - P) {
            t = c;
        }
    }
    t
}

/// The page at `a` is a user address (mapping it works or finds it taken)
fn mappable(a: u64) -> bool {
    let r = sys_mmap(a, P, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if r == a as i64 {
        sys_munmap(a, P);
        return true;
    }
    r == EEXIST
}

/// Parse a hex number at the start of `s`: (value, digits)
fn hex(s: &[u8]) -> (u64, usize) {
    let mut v = 0u64;
    let mut n = 0;
    for &c in s {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => break,
        };
        v = (v << 4) | d as u64;
        n += 1;
    }
    (v, n)
}

/// Number of /proc/self/maps lines (VMAs) meeting [lo, hi)
fn vmas(lo: u64, hi: u64) -> i64 {
    let mut buf = [0u8; 16384];
    let fd = sys_open(b"/proc/self/maps\0".as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return -1;
    }
    let mut len = 0;
    while len < buf.len() {
        let n = sys_read(fd as u64, buf[len..].as_mut_ptr(), (buf.len() - len) as u64);
        if n <= 0 {
            break;
        }
        len += n as usize;
    }
    sys_close(fd as u64);
    buf[..len]
        .split(|&b| b == b'\n')
        .filter(|l| {
            let (s, n) = hex(l);
            let (e, m) = l.get(n + 1..).map_or((0, 0), hex);
            n > 0 && m > 0 && s < hi && e > lo
        })
        .count() as i64
}

/// Run `f` in a child; its value (0..255) as exit status, or 1000 + the
/// signal that killed it
fn child(f: &dyn Fn() -> bool) -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(if f() { 0 } else { 1 });
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    if st & 0x7f != 0 {
        1000 + (st & 0x7f) as i64
    } else {
        ((st >> 8) & 0xff) as i64
    }
}

// ============================================================================
// madvise
// ============================================================================

fn madv(a: u64, len: u64, advice: i64) -> i64 {
    sys_madvise(a, len, advice as i32)
}

fn madv_args() {
    const NAME: &[u8] = b"MADV_ARGS";
    let Some(a) = area(4) else {
        return report(NAME, -1);
    };
    let t = top();
    let hi = t + (1 << 28);
    let n = MADV_NORMAL as i64;
    let cases = [
        (a + 1, P, n, EINVAL),
        (a + 1, 0, n, EINVAL),
        (a, P, 7, EINVAL),
        (a, 0, 7, EINVAL),
        (a, P, -1, EINVAL),
        (a, P, 999, EINVAL),
        (a, 0, n, 0),
        (a, u64::MAX, n, EINVAL),
        (a, u64::MAX - 2 * P, n, EINVAL),
        (a, LAST - a + P, n, EINVAL),
        (LAST, P, n, EINVAL),
        (LAST, 0, n, 0),
        (hi, P, n, ENOMEM),
        (hi, P, MADV_DONTNEED as i64, ENOMEM),
        (t, P, MADV_DONTNEED as i64, ENOMEM),
        (t - P, 2 * P, n, ENOMEM),
        (a - P, P, n, ENOMEM),
        (a - P, 2 * P, n, ENOMEM),
        (a, 5 * P, n, ENOMEM),
        (a + 4 * P, P, MADV_DONTNEED as i64, ENOMEM),
        (a, 4 * P, n, 0),
        (a, 4 * P - 1, MADV_RANDOM as i64, 0),
        (a, 4 * P, n, 0),
        (a, 4 * P, MADV_WILLNEED as i64, 0),
        (a, 4 * P, MADV_COLD as i64, 0),
        (a, 4 * P, MADV_PAGEOUT as i64, 0),
    ];
    let mut code = table(NAME, &cases, madv);
    if code == 0 && !intact(a, 4 * P) {
        code = 100;
    } else if code == 0 && (vmas(a - P, a + 5 * P) != 1 || mapped(a - P) || mapped(a + 4 * P)) {
        code = 101;
    }
    sys_munmap(a, 4 * P);
    report(NAME, code);
}

fn madv_holes() {
    const NAME: &[u8] = b"MADV_HOLES";
    let Some(b) = area(5) else {
        return report(NAME, -1);
    };
    sys_munmap(b + 2 * P, P);
    let code = madv_holes_on(b);
    sys_munmap(b, 5 * P);
    report(NAME, code);
}

/// [b, b + 2P) and [b + 3P, b + 5P) mapped and filled
fn madv_holes_on(b: u64) -> i64 {
    if madv(b, 5 * P, MADV_DONTNEED as i64) != ENOMEM {
        return 1;
    }
    if !zeroed(b, 2 * P) || !zeroed(b + 3 * P, 2 * P) || mapped(b + 2 * P) {
        return 2;
    }
    if vmas(b, b + 5 * P) != 2 {
        return 3;
    }
    fill(b, 2 * P);
    fill(b + 3 * P, 2 * P);
    if madv(b + P, 3 * P, MADV_DONTFORK as i64) != ENOMEM || vmas(b, b + 5 * P) != 4 {
        return 4;
    }
    let seen = || mapped(b) && !mapped(b + P) && !mapped(b + 3 * P) && get(b + 4 * P) == pattern(b + 4 * P);
    if child(&seen) != 0 {
        return 5;
    }
    if madv(b, 5 * P, MADV_DOFORK as i64) != ENOMEM || vmas(b, b + 5 * P) != 2 {
        return 6;
    }
    if madv(b + 2 * P, P, MADV_NORMAL as i64) != ENOMEM {
        return 7;
    }
    if madv(b + 2 * P, 2 * P, MADV_DONTNEED as i64) != ENOMEM {
        return 8;
    }
    if get(b + 3 * P) != 0 || !intact(b + 4 * P, P) || !intact(b, 2 * P) {
        return 9;
    }
    0
}

fn madv_split() {
    const NAME: &[u8] = b"MADV_SPLIT";
    let Some(a) = area(4) else {
        return report(NAME, -1);
    };
    let code = madv_split_on(a);
    sys_munmap(a, 4 * P);
    report(NAME, code);
}

/// `a`: four filled pages, one VMA
fn madv_split_on(a: u64) -> i64 {
    let lines = || vmas(a, a + 4 * P);
    if madv(a + P, P, MADV_DONTFORK as i64) != 0 || lines() != 3 {
        return 1;
    }
    if madv(a + 2 * P, P, MADV_WIPEONFORK as i64) != 0 || lines() != 4 {
        return 2;
    }
    let seen = || {
        get(a) == pattern(a) && !mapped(a + P) && get(a + 2 * P) == 0 && get(a + 3 * P) == pattern(a + 3 * P)
    };
    if child(&seen) != 0 {
        return 3;
    }
    if madv(a, 4 * P, MADV_DOFORK as i64) != 0 || lines() != 3 {
        return 4;
    }
    if madv(a, 4 * P, MADV_KEEPONFORK as i64) != 0 || lines() != 1 {
        return 5;
    }
    let whole = || intact(a, 4 * P);
    if child(&whole) != 0 || !whole() {
        return 6;
    }
    if madv(a + 3 * P, P, MADV_DONTDUMP as i64) != 0 || lines() != 2 {
        return 7;
    }
    if madv(a, 4 * P, MADV_DODUMP as i64) != 0 || lines() != 1 {
        return 8;
    }
    // Nothing changes: no split
    if madv(a + P, P, MADV_NORMAL as i64) != 0 || lines() != 1 {
        return 9;
    }
    if madv(a + P, 2 * P, MADV_DONTNEED as i64) != 0 || lines() != 1 {
        return 10;
    }
    if !intact(a, P) || !zeroed(a + P, 2 * P) || !intact(a + 3 * P, P) {
        return 11;
    }
    0
}

/// Two pages at `c`: read-write then read-only (two VMAs), filled, the
/// one at `locked` (0 or 1) locked
fn locked_pair(locked: u64) -> Option<u64> {
    let c = area(2)?;
    if sys_mprotect(c + P, P, PROT_READ) != 0 || sys_mlock(c + locked * P, P) != 0 {
        sys_munmap(c, 2 * P);
        return None;
    }
    Some(c)
}

fn madv_locked() {
    const NAME: &[u8] = b"MADV_LOCKED";
    let Some(c) = locked_pair(1) else {
        return report(NAME, -1);
    };
    let l = c + P;
    let cases = [
        (l, P, MADV_DONTNEED as i64, EINVAL),
        (l, P, MADV_FREE as i64, EINVAL),
        (l, P, MADV_COLD as i64, EINVAL),
        (l, P, MADV_PAGEOUT as i64, EINVAL),
        (l, P, MADV_REMOVE as i64, EINVAL),
        (l, P, MADV_NORMAL as i64, 0),
        (l, P, MADV_WILLNEED as i64, 0),
        (c, 2 * P, MADV_DONTNEED as i64, EINVAL),
    ];
    let mut code = table(NAME, &cases, madv);
    // The unlocked page was emptied before the walk met the locked one
    if code == 0 && (get(c) != 0 || !intact(l, P)) {
        code = 100;
    }
    if code == 0 && (sys_munlock(l, P) != 0 || madv(l, P, MADV_DONTNEED as i64) != 0 || get(l) != 0) {
        code = 101;
    }
    sys_munmap(c, 2 * P);
    if code == 0 {
        code = match locked_pair(0) {
            // Locked first: the walk stops before the second page
            Some(d) => {
                let r = if madv(d, 2 * P, MADV_DONTNEED as i64) != EINVAL || !intact(d, 2 * P) {
                    102
                } else {
                    0
                };
                sys_munmap(d, 2 * P);
                r
            }
            None => 103,
        };
    }
    report(NAME, code);
}

fn madv_shared() {
    const NAME: &[u8] = b"MADV_SHARED";
    let s = sys_mmap(0, 2 * P, RW, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if s < 0 {
        return report(NAME, -1);
    }
    let s = s as u64;
    let q = sys_mmap(s + P, P, RW, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    let code = if q != (s + P) as i64 { -2 } else { madv_shared_on(s) };
    sys_munmap(s, 2 * P);
    report(NAME, code);
}

/// [s shared][s + P private], both anonymous
fn madv_shared_on(s: u64) -> i64 {
    fill(s, 2 * P);
    if madv(s, 2 * P, MADV_REMOVE as i64) != EINVAL {
        return 1;
    }
    if get(s) != 0 || !intact(s + P, P) {
        return 2;
    }
    fill(s, P);
    if madv(s, P, MADV_FREE as i64) != EINVAL || !intact(s, P) {
        return 3;
    }
    if madv(s, 2 * P, MADV_FREE as i64) != EINVAL || !intact(s, 2 * P) {
        return 4;
    }
    if madv(s + P, P, MADV_FREE as i64) != 0 {
        return 5;
    }
    0
}
