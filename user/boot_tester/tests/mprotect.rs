//! Page protection and 2MB page splits (Linux mm/mprotect.c,
//! mm/huge_memory.c __split_huge_pmd)
//!
//! Tests:
//! - THP_SPLIT_MPROTECT: mprotect of one 4KB page inside a 2MB page
//!   (MADV_HUGEPAGE) splits it; every page keeps its data, before and
//!   after the protection is restored
//! - THP_SPLIT_MUNMAP: munmap of a few pages inside a 2MB page splits
//!   it; the rest keeps its data, the hole is unmapped (mincore ENOMEM)
//! - THP_MREMAP_MOVE: mremap moving two 2MB pages keeps every page's
//!   data at the new address; the old range is unmapped
//! - PROTNONE_PRESENT: mprotect(PROT_NONE) of a page already mapped
//!   (the middle of three): loads and stores fault with SIGSEGV
//!   SEGV_ACCERR at the address, the kernel cannot read or write it
//!   either (write()/read() through a pipe: EFAULT), its neighbours stay
//!   accessible, mincore still reports it resident; mprotect back to
//!   read-write: data intact
//! - PROTNONE_READONLY: PROT_READ on a written page: stores fault
//!   (SEGV_ACCERR), loads see the data
//! - PROTNONE_FORK: a child forked after PROT_NONE faults too; after
//!   its own mprotect it sees the data and its write stays private
//! - PROTNONE_WRITEONLY: PROT_WRITE alone on a page still shared
//!   copy-on-write with a child: loads see the data, a store copies it
//!   (write implies read; the entry never becomes protnone)
//! - PROTNONE_THP: PROT_NONE over a whole 2MB page and over one 4KB
//!   page of another: both fault, the rest stays accessible, all data
//!   intact once read-write again
//! - PROTNONE_MREMAP: a PROT_NONE range moved by mremap faults at its
//!   new address and keeps its data
//! - MAPS_MATCH_MPROTECT: after PROT_NONE and PROT_READ on two pages
//!   inside a read-write mapping, /proc/self/maps shows ---p, r--p and
//!   rw-p where loads and stores fault or work accordingly
//! - MAPS_MATCH_MREMAP: mremap shrinking or moving only the start of a
//!   mapping leaves the rest mapped with its data (maps and access
//!   agree), the moved pages answer at the new address only
//! - MREMAP_EDGES: growing a range that does not end its VMA cannot stay
//!   in place (ENOMEM without MREMAP_MAYMOVE; with it the range moves
//!   and the rest stays); a length past user space fails; a
//!   MREMAP_DONTUNMAP target overlapping the old range is EINVAL;
//!   MREMAP_DONTUNMAP alone moves the pages and leaves the old range
//!   mapped and empty; a shrink may unmap a tail crossing VMAs

use super::fault_signals::{fault_seen, install, reset, run_fault, After, MAGIC1, MAGIC2};
use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_close, sys_exit, sys_fork, sys_madvise, sys_open, sys_mincore, sys_mmap, sys_mprotect, sys_mremap, sys_munmap,
    sys_pipe, sys_read, sys_wait4, sys_write, MAP_ANONYMOUS, MAP_PRIVATE, MREMAP_DONTUNMAP, MREMAP_FIXED, MREMAP_MAYMOVE, O_RDONLY, PROT_NONE, PROT_READ,
    PROT_WRITE, SIGSEGV,
};

const PAGE: u64 = 4096;
const HUGE: u64 = 2 << 20;
const MADV_HUGEPAGE: i32 = 14;
const RW: u32 = PROT_READ | PROT_WRITE;
const ENOMEM: i64 = -12;
const EINVAL: i64 = -22;
const EFAULT: i64 = -14;
const SEGV_ACCERR: i32 = 2;
/// The word `store` writes
#[cfg(target_arch = "x86_64")]
const STORED: u64 = 0;
#[cfg(target_arch = "aarch64")]
const STORED: u64 = MAGIC1;

pub fn run_tests() {
    thp_split_mprotect();
    thp_split_munmap();
    thp_mremap_move();
    if !install(SIGSEGV) {
        return report(b"PROTNONE_SIGACTION", -1);
    }
    protnone_present();
    protnone_readonly();
    protnone_fork();
    protnone_writeonly();
    protnone_thp();
    protnone_mremap();
    maps_match_mprotect();
    maps_match_mremap();
    mremap_edges();
}

fn mremap_edges() {
    const NAME: &[u8] = b"MREMAP_EDGES";
    let p = sys_mmap(0, 8 * PAGE, RW, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if p < 0 {
        return report(NAME, -1);
    }
    let p = p as u64;
    fill(p, 8 * PAGE);
    let dfix = MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP;
    let mut code = if sys_mremap(p, 2 * PAGE, 3 * PAGE, 0, 0) != ENOMEM {
        1
    } else if !matches!(sys_mremap(p, 2 * PAGE, 1 << 62, MREMAP_MAYMOVE, 0), EINVAL | ENOMEM) {
        // EINVAL in mainline (check_mremap_params), ENOMEM before
        3
    } else if sys_mremap(p, 2 * PAGE, 2 * PAGE, dfix, p + PAGE) != EINVAL {
        4
    } else {
        0
    };
    if code == 0 {
        // Grow the first two pages: moved, the other six stay
        let q = sys_mremap(p, 2 * PAGE, 3 * PAGE, MREMAP_MAYMOVE, 0);
        if q < 0 || q as u64 == p {
            code = 5;
        } else if !moved_intact(q as u64, p, 2 * PAGE) || !intact(p + 2 * PAGE, 6 * PAGE, 0, 0) {
            code = 6;
        } else if maps_perm(p).is_some() {
            code = 7;
        }
        if q > 0 {
            sys_munmap(q as u64, 3 * PAGE);
        }
    }
    if code == 0 {
        // MREMAP_DONTUNMAP alone: the old range stays, empty
        let q = sys_mremap(p + 2 * PAGE, 2 * PAGE, 2 * PAGE, MREMAP_MAYMOVE | MREMAP_DONTUNMAP, 0);
        if q < 0 || q as u64 == p + 2 * PAGE {
            code = 8;
        } else if !moved_intact(q as u64, p + 2 * PAGE, 2 * PAGE) || get(p + 2 * PAGE) != 0 {
            code = 9;
        }
        if q > 0 {
            sys_munmap(q as u64, 2 * PAGE);
        }
    }
    sys_munmap(p, 8 * PAGE);
    if code == 0 {
        code = mremap_shrink_across();
    }
    report(NAME, code);
}

/// Shrinking may unmap a tail that crosses VMAs: four pages, the third
/// made a VMA of its own, shrunk to one page
fn mremap_shrink_across() -> i64 {
    let p = sys_mmap(0, 4 * PAGE, RW, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if p < 0 {
        return -2;
    }
    let p = p as u64;
    fill(p, 4 * PAGE);
    let code = if sys_mprotect(p + 2 * PAGE, PAGE, PROT_READ) != 0 {
        10
    } else if sys_mremap(p, 4 * PAGE, PAGE, 0, 0) != p as i64 {
        11
    } else if !intact(p, PAGE, 0, 0) || maps_perm(p + PAGE).is_some() || maps_perm(p + 3 * PAGE).is_some() {
        13
    } else {
        0
    };
    sys_munmap(p, 4 * PAGE);
    code
}

/// Parse a hex number at the start of `s`: (value, digits)
fn hex(s: &[u8]) -> (u64, usize) {
    let mut v = 0u64;
    let mut n = 0;
    while let Some(d) = s.get(n).and_then(|&c| (c as char).to_digit(16)) {
        v = v << 4 | d as u64;
        n += 1;
    }
    (v, n)
}

/// The permission field ("rw-p", ...) of the /proc/self/maps line
/// covering `addr`; None if unmapped there
fn maps_perm(addr: u64) -> Option<[u8; 4]> {
    let mut buf = [0u8; 16384];
    let fd = sys_open(b"/proc/self/maps\0".as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return None;
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
    buf[..len].split(|&b| b == b'\n').find_map(|l| {
        let (start, n) = hex(l);
        let (end, m) = hex(l.get(n + 1..)?);
        let perm = l.get(n + 1 + m + 1..n + 1 + m + 5)?;
        (start <= addr && addr < end).then(|| [perm[0], perm[1], perm[2], perm[3]])
    })
}

/// /proc/self/maps says `perm` at `addr` and loads/stores there behave
/// that way (`fill` left the page's third word zero; a store writes the
/// fourth, which no check reads)
fn agrees(addr: u64, perm: &[u8; 4]) -> bool {
    if maps_perm(addr) != Some(*perm) {
        return false;
    }
    let (r, w) = (addr + 16, addr + 24);
    let read_ok = if perm[0] == b'r' { load(r) == Ok(0) } else { load(r) == Err((SEGV_ACCERR, r)) };
    let write_ok = if perm[1] == b'w' { store(w).is_ok() } else { store(w) == Err((SEGV_ACCERR, w)) };
    read_ok && write_ok
}

fn maps_match_mprotect() {
    const NAME: &[u8] = b"MAPS_MATCH_MPROTECT";
    let p = sys_mmap(0, 4 * PAGE, RW, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if p < 0 {
        return report(NAME, -1);
    }
    let p = p as u64;
    fill(p, 4 * PAGE);
    let code = if sys_mprotect(p + PAGE, PAGE, PROT_NONE) != 0
        || sys_mprotect(p + 2 * PAGE, PAGE, PROT_READ) != 0
    {
        1
    } else if !agrees(p, b"rw-p") || !agrees(p + 3 * PAGE, b"rw-p") {
        2
    } else if !agrees(p + PAGE, b"---p") {
        3
    } else if !agrees(p + 2 * PAGE, b"r--p") {
        4
    } else if sys_mprotect(p, 4 * PAGE, RW) != 0 || !intact(p, 4 * PAGE, 0, 0) {
        5
    } else {
        0
    };
    sys_munmap(p, 4 * PAGE);
    report(NAME, code);
}

fn maps_match_mremap() {
    const NAME: &[u8] = b"MAPS_MATCH_MREMAP";
    let p = sys_mmap(0, 8 * PAGE, RW, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    let dst = free_range(2 * PAGE);
    if p < 0 || dst == 0 {
        return report(NAME, -1);
    }
    let p = p as u64;
    fill(p, 8 * PAGE);
    let flags = MREMAP_MAYMOVE | MREMAP_FIXED;
    // Shrink [p, p + 2 pages) to one page; then move [p + 4, p + 6) away
    let code = if sys_mremap(p, 2 * PAGE, PAGE, 0, 0) != p as i64 {
        1
    } else if maps_perm(p + PAGE).is_some() || load(p + PAGE) != Err((1, p + PAGE)) {
        2
    } else if !agrees(p, b"rw-p") || !intact(p + 2 * PAGE, 6 * PAGE, 0, 0) {
        3
    } else if !agrees(p + 2 * PAGE, b"rw-p") {
        4
    } else if sys_mremap(p + 4 * PAGE, 2 * PAGE, 2 * PAGE, flags, dst) != dst as i64 {
        5
    } else if !moved_intact(dst, p + 4 * PAGE, 2 * PAGE) || !agrees(dst, b"rw-p") {
        6
    } else if maps_perm(p + 4 * PAGE).is_some() || load(p + 5 * PAGE) != Err((1, p + 5 * PAGE)) {
        7
    } else if !intact(p + 6 * PAGE, 2 * PAGE, 0, 0) || !agrees(p + 7 * PAGE, b"rw-p") {
        8
    } else {
        0
    };
    sys_munmap(dst, 2 * PAGE);
    sys_munmap(p, 8 * PAGE);
    report(NAME, code);
}

/// A free range of `len` bytes: mapped, then unmapped (0 if mmap fails)
fn free_range(len: u64) -> u64 {
    let p = sys_mmap(0, len, RW, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if p < 0 {
        return 0;
    }
    sys_munmap(p as u64, len);
    p as u64
}

fn thp_mremap_move() {
    const NAME: &[u8] = b"THP_MREMAP_MOVE";
    let Some(base) = huge_area(2 * HUGE) else {
        return report(NAME, -1);
    };
    let dst = free_range(2 * HUGE);
    let mut vec = [0u8; 1];
    let flags = MREMAP_MAYMOVE | MREMAP_FIXED;
    let code = if dst == 0 {
        -1
    } else if sys_mremap(base, 2 * HUGE, 2 * HUGE, flags, dst) != dst as i64 {
        1
    } else if !moved_intact(dst, base, 2 * HUGE) {
        2
    } else if sys_mincore(base, PAGE, vec.as_mut_ptr()) != ENOMEM {
        3
    } else {
        0
    };
    sys_munmap(dst, 2 * HUGE);
    sys_munmap(base, 2 * HUGE);
    report(NAME, code);
}

/// Load the word at `addr`: its value, or the (si_code, si_addr) of the
/// SIGSEGV it raised
fn load(addr: u64) -> Result<u64, (i32, u64)> {
    reset();
    #[cfg(target_arch = "x86_64")]
    let a = run_fault!("mov rax, [rdi]", addr);
    #[cfg(target_arch = "aarch64")]
    let a = run_fault!("ldr x12, [x0]", addr);
    fault_seen().map_or(Ok(a.result), Err)
}

/// Store `STORED` at `addr`, or the (si_code, si_addr) of its SIGSEGV
fn store(addr: u64) -> Result<(), (i32, u64)> {
    reset();
    #[cfg(target_arch = "x86_64")]
    let _ = run_fault!("mov qword ptr [rdi], rdx", addr);
    #[cfg(target_arch = "aarch64")]
    let _ = run_fault!("str x10, [x0]", addr);
    fault_seen().map_or(Ok(()), Err)
}

/// Loads and stores at `addr` fault with SEGV_ACCERR at `addr`
fn denied(addr: u64) -> bool {
    load(addr) == Err((SEGV_ACCERR, addr)) && store(addr + 8) == Err((SEGV_ACCERR, addr + 8))
}

/// A kernel copy from or to `addr` fails with EFAULT: write() of it to a
/// pipe, and read() into it from the pipe (holding a word from `ok`)
fn kernel_denied(addr: u64, ok: u64) -> bool {
    let mut fds = [0i32; 2];
    if sys_pipe(fds.as_mut_ptr()) != 0 {
        return false;
    }
    let (r, w) = (fds[0] as u64, fds[1] as u64);
    let denied = sys_write(w, addr as *const u8, 8) == EFAULT
        && sys_write(w, ok as *const u8, 8) == 8
        && sys_read(r, addr as *mut u8, 8) == EFAULT;
    sys_close(r);
    sys_close(w);
    denied
}

/// [a, a + len) holds the pattern written at [from, from + len)
fn moved_intact(a: u64, from: u64, len: u64) -> bool {
    (0..len)
        .step_by(PAGE as usize)
        .all(|o| get(a + o) == pattern(from + o) && get(a + o + PAGE - 8) == pattern(from + o))
}

/// Three read-write pages, filled
fn three_pages() -> Option<u64> {
    let p = sys_mmap(0, 3 * PAGE, RW, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if p < 0 {
        return None;
    }
    fill(p as u64, 3 * PAGE);
    Some(p as u64)
}

fn protnone_present() {
    const NAME: &[u8] = b"PROTNONE_PRESENT";
    let Some(p) = three_pages() else {
        return report(NAME, -1);
    };
    let mid = p + PAGE;
    let mut vec = [0u8; 1];
    let code = if sys_mprotect(mid, PAGE, PROT_NONE) != 0 {
        1
    } else if !denied(mid + 0x40) {
        2
    } else if !kernel_denied(mid, p) {
        8
    } else if load(p) != Ok(pattern(p)) || load(p + 2 * PAGE) != Ok(pattern(p + 2 * PAGE)) {
        3
    } else if sys_mincore(mid, PAGE, vec.as_mut_ptr()) != 0 || vec[0] & 1 == 0 {
        4
    } else if sys_mprotect(mid, PAGE, RW) != 0 {
        5
    } else if !intact(p, 3 * PAGE, 0, 0) {
        6
    } else if store(mid) != Ok(()) || get(mid) != STORED {
        7
    } else {
        0
    };
    sys_munmap(p, 3 * PAGE);
    report(NAME, code);
}

fn protnone_readonly() {
    const NAME: &[u8] = b"PROTNONE_READONLY";
    let Some(p) = three_pages() else {
        return report(NAME, -1);
    };
    let code = if sys_mprotect(p, 3 * PAGE, PROT_READ) != 0 {
        1
    } else if store(p + PAGE) != Err((SEGV_ACCERR, p + PAGE)) {
        2
    } else if load(p + PAGE) != Ok(pattern(p + PAGE)) || !intact(p, 3 * PAGE, 0, 0) {
        3
    } else if sys_mprotect(p, 3 * PAGE, RW) != 0 || store(p + PAGE) != Ok(()) {
        4
    } else {
        0
    };
    sys_munmap(p, 3 * PAGE);
    report(NAME, code);
}

/// The forked child of PROTNONE_FORK: exit status 0 if right
fn protnone_child(p: u64) -> u64 {
    if !denied(p) {
        return 1;
    }
    if sys_mprotect(p, 3 * PAGE, RW) != 0 || !intact(p, 3 * PAGE, 0, 0) {
        return 2;
    }
    put(p, 0x0c0c);
    if get(p) != 0x0c0c { 3 } else { 0 }
}

fn protnone_fork() {
    const NAME: &[u8] = b"PROTNONE_FORK";
    let Some(p) = three_pages() else {
        return report(NAME, -1);
    };
    let mut code = 0;
    if sys_mprotect(p, 3 * PAGE, PROT_NONE) != 0 {
        code = 1;
    } else {
        let pid = sys_fork();
        if pid == 0 {
            sys_exit(protnone_child(p));
        }
        let mut st = 0i32;
        if pid < 0 || sys_wait4(pid, &mut st, 0, 0) != pid || st != 0 {
            code = 10 + ((st >> 8) & 0xff) as i64;
        } else if !denied(p + PAGE) {
            code = 2;
        } else if sys_mprotect(p, 3 * PAGE, RW) != 0 || !intact(p, 3 * PAGE, 0, 0) {
            code = 3;
        }
    }
    sys_munmap(p, 3 * PAGE);
    report(NAME, code);
}

fn protnone_writeonly() {
    const NAME: &[u8] = b"PROTNONE_WRITEONLY";
    let Some(p) = three_pages() else {
        return report(NAME, -1);
    };
    let mut fds = [0i32; 2];
    if sys_pipe(fds.as_mut_ptr()) != 0 {
        return report(NAME, -2);
    }
    let (r, w) = (fds[0] as u64, fds[1] as u64);
    let pid = sys_fork();
    if pid == 0 {
        // Keeps the pages shared until the parent is done
        let mut b = [0u8; 1];
        sys_read(r, b.as_mut_ptr(), 1);
        sys_exit(if intact(p, 3 * PAGE, 0, 0) { 0 } else { 1 });
    }
    let code = if pid < 0 {
        -3
    } else if sys_mprotect(p, 3 * PAGE, PROT_WRITE) != 0 {
        1
    } else if load(p + PAGE) != Ok(pattern(p + PAGE)) {
        2
    } else if store(p + PAGE + 8) != Ok(()) || get(p + PAGE) != pattern(p + PAGE) {
        3
    } else {
        0
    };
    sys_write(w, b"x".as_ptr(), 1);
    let mut st = 0i32;
    let code = if pid > 0 && (sys_wait4(pid, &mut st, 0, 0) != pid || st != 0) && code == 0 {
        4
    } else {
        code
    };
    sys_close(r);
    sys_close(w);
    sys_munmap(p, 3 * PAGE);
    report(NAME, code);
}

fn protnone_thp() {
    const NAME: &[u8] = b"PROTNONE_THP";
    let Some(base) = huge_area(2 * HUGE) else {
        return report(NAME, -1);
    };
    let one = base + HUGE + 3 * PAGE;
    let code = if sys_mprotect(base, HUGE, PROT_NONE) != 0 {
        1
    } else if sys_mprotect(one, PAGE, PROT_NONE) != 0 {
        2
    } else if !denied(base) || !denied(base + HUGE / 2) || !denied(one + 0x80) {
        3
    } else if load(base + HUGE) != Ok(pattern(base + HUGE)) || load(one + PAGE) != Ok(pattern(one + PAGE)) {
        4
    } else if sys_mprotect(base, 2 * HUGE, RW) != 0 {
        5
    } else if !intact(base, 2 * HUGE, 0, 0) {
        6
    } else {
        0
    };
    sys_munmap(base, 2 * HUGE);
    report(NAME, code);
}

fn protnone_mremap() {
    const NAME: &[u8] = b"PROTNONE_MREMAP";
    const LEN: u64 = 8 * PAGE;
    let p = sys_mmap(0, LEN, RW, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    let dst = free_range(LEN);
    if p < 0 || dst == 0 {
        return report(NAME, -1);
    }
    let p = p as u64;
    fill(p, LEN);
    let flags = MREMAP_MAYMOVE | MREMAP_FIXED;
    let code = if sys_mprotect(p, LEN, PROT_NONE) != 0 {
        1
    } else if sys_mremap(p, LEN, LEN, flags, dst) != dst as i64 {
        2
    } else if !denied(dst + 3 * PAGE) {
        3
    } else if sys_mprotect(dst, LEN, RW) != 0 {
        4
    } else if !moved_intact(dst, p, LEN) {
        5
    } else {
        0
    };
    sys_munmap(dst, LEN);
    report(NAME, code);
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

/// A mapping of `n` huge-page-eligible bytes at a 2MB-aligned address
/// (the slack of a larger mapping unmapped), filled with the pattern;
/// None if mmap fails
fn huge_area(n: u64) -> Option<u64> {
    let p = sys_mmap(0, n + HUGE, RW, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if p < 0 {
        return None;
    }
    let p = p as u64;
    let base = (p + HUGE - 1) & !(HUGE - 1);
    if base > p {
        sys_munmap(p, base - p);
    }
    if p + HUGE > base {
        sys_munmap(base + n, p + HUGE - base);
    }
    // EINVAL without THP support (Linux): the test still holds
    sys_madvise(base, n, MADV_HUGEPAGE);
    fill(base, n);
    Some(base)
}

fn thp_split_mprotect() {
    const NAME: &[u8] = b"THP_SPLIT_MPROTECT";
    let Some(base) = huge_area(2 * HUGE) else {
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
    sys_munmap(base, 2 * HUGE);
    report(NAME, code);
}

fn thp_split_munmap() {
    const NAME: &[u8] = b"THP_SPLIT_MUNMAP";
    let Some(base) = huge_area(2 * HUGE) else {
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
    sys_munmap(base, 2 * HUGE);
    report(NAME, code);
}
