//! TLB maintenance seen from user space: a mapping removed or made
//! read-only must fault at once (no stale TLB entry), copy-on-write
//! pages stay private under fork churn, and code the kernel copied
//! into a page (a file mapping, a CoW copy, mprotect to executable)
//! runs as written (instruction caches synced, arm64). Each case runs
//! in a child whose fate is checked.

use super::helpers::{print, print_num, println};
use hk_syscall::{
    MAP_ANONYMOUS, MAP_PRIVATE, O_CREAT, O_RDWR, O_TRUNC, PROT_EXEC, PROT_READ, PROT_WRITE,
    sys_close, sys_exit, sys_fork, sys_madvise, sys_mmap, sys_mprotect, sys_munmap, sys_open,
    sys_unlink, sys_wait4, sys_write,
};

const PAGE: u64 = 4096;
const RW: u32 = PROT_READ | PROT_WRITE;
const SIGSEGV: i64 = 11;

/// `return 42` (x86-64: mov eax, 42; ret)
#[cfg(target_arch = "x86_64")]
const CODE: [u8; 8] = [0xb8, 42, 0, 0, 0, 0xc3, 0x90, 0x90];
/// `return 42` (arm64: movz w0, #42; ret)
#[cfg(target_arch = "aarch64")]
const CODE: [u8; 8] = [0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6];

pub fn run_tests() {
    expect(b"TLB_MUNMAP_SEGV", munmap_access, SIGSEGV);
    expect(b"TLB_MUNMAP_LARGE_SEGV", munmap_large, SIGSEGV);
    expect(b"TLB_MPROTECT_RO_SEGV", mprotect_ro_write, SIGSEGV);
    expect(b"TLB_COW_CHURN", cow_churn, 0);
    expect(b"TLB_EXEC_MPROTECT", exec_mprotect, 42);
    expect(b"TLB_EXEC_FILE", exec_file, 42);
    expect(b"TLB_EXEC_COW", exec_cow, 42);
    expect(b"TLB_EXEC_MUNMAP_SEGV", exec_munmap, SIGSEGV);
    expect(b"TLB_EXEC_HUGE_REWRITE", exec_huge_rewrite, 0);
    #[cfg(target_arch = "aarch64")]
    expect(b"TLB_EL0_DC_ZVA", dc_zva, 0);
}

/// Run `f` in a child: it must exit with `want`, or die of signal
/// SIGSEGV when `want` is SIGSEGV
fn expect(name: &[u8], f: fn() -> i64, want: i64) {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(f() as u64 & 0xff);
    }
    let mut st = 0i32;
    let ok = pid > 0 && sys_wait4(pid, &mut st, 0, 0) == pid && {
        let sig = (st & 0x7f) as i64;
        if want == SIGSEGV {
            sig == SIGSEGV
        } else {
            sig == 0 && ((st >> 8) & 0xff) as i64 == want
        }
    };
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL wstatus=");
        print_num(st as i64);
        println(b"");
    }
}

fn map(len: u64, prot: u32) -> u64 {
    let p = sys_mmap(0, len, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if p < 0 {
        sys_exit(100);
    }
    p as u64
}

fn get(a: u64) -> u64 {
    unsafe { core::ptr::read_volatile(a as *const u64) }
}

fn put(a: u64, v: u64) {
    unsafe { core::ptr::write_volatile(a as *mut u64, v) }
}

/// Write then read every page of [a, a + n pages): their translations
/// are in the TLB
fn touch(a: u64, n: u64) {
    for i in 0..n {
        put(a + i * PAGE, i);
    }
    for i in 0..n {
        if get(a + i * PAGE) != i {
            sys_exit(101);
        }
    }
}

/// Unmap a page just used, then read it: SIGSEGV
fn munmap_access() -> i64 {
    let a = map(4 * PAGE, RW);
    touch(a, 4);
    sys_munmap(a + PAGE, PAGE);
    get(a + PAGE) as i64
}

/// Unmap more pages than one ranged flush covers (a full flush), then
/// read one in the middle: SIGSEGV
fn munmap_large() -> i64 {
    let n = 64;
    let a = map(n * PAGE, RW);
    touch(a, n);
    sys_munmap(a, n * PAGE);
    get(a + 40 * PAGE) as i64
}

/// Write a page, make it read-only, write it again: SIGSEGV
fn mprotect_ro_write() -> i64 {
    let a = map(2 * PAGE, RW);
    touch(a, 2);
    sys_mprotect(a, PAGE, PROT_READ);
    if get(a) != 0 {
        return 102;
    }
    put(a, 7);
    0
}

/// Rounds of fork: the parent writes its pages right after each fork
/// (copy-on-write break while the child reads), the child must still
/// see the values from before the fork and its own writes stay its own
fn cow_churn() -> i64 {
    let n = 16;
    let a = map(n * PAGE, RW);
    for round in 1..=12u64 {
        for i in 0..n {
            put(a + i * PAGE, round * 1000 + i);
        }
        let pid = sys_fork();
        if pid == 0 {
            for _ in 0..50 {
                for i in 0..n {
                    if get(a + i * PAGE) != round * 1000 + i {
                        sys_exit(1);
                    }
                }
            }
            for i in 0..n {
                put(a + i * PAGE, 7);
            }
            sys_exit(0);
        }
        for i in 0..n {
            put(a + i * PAGE, round);
        }
        let mut st = 0i32;
        if sys_wait4(pid, &mut st, 0, 0) != pid || st != 0 {
            return 2;
        }
        for i in 0..n {
            if get(a + i * PAGE) != round {
                return 3;
            }
        }
    }
    0
}

/// Call the code at `a`
fn call(a: u64) -> i64 {
    let f: extern "C" fn() -> i32 = unsafe { core::mem::transmute(a as usize) };
    f() as i64
}

fn copy_code(a: u64) {
    for (i, b) in CODE.iter().enumerate() {
        unsafe { core::ptr::write_volatile((a + i as u64) as *mut u8, *b) };
    }
}

/// Code written to a fresh page, then mprotect'ed executable: the
/// kernel syncs the instruction caches when the page becomes executable
fn exec_mprotect() -> i64 {
    let a = map(PAGE, RW);
    copy_code(a);
    if sys_mprotect(a, PAGE, PROT_READ | PROT_EXEC) != 0 {
        return 103;
    }
    call(a)
}

const FILE: &[u8] = b"/tlb_code\0";

/// Code in a file, mapped private and executable: the fault copies it
/// into the page and must sync the instruction caches
fn exec_file() -> i64 {
    let Some(fd) = code_file() else {
        return 104;
    };
    let p = sys_mmap(0, PAGE, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd as i32, 0);
    sys_close(fd);
    sys_unlink(FILE.as_ptr());
    if p < 0 {
        return 105;
    }
    call(p as u64)
}

/// The code file (one page)
fn code_file() -> Option<u64> {
    let fd = sys_open(FILE.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o755);
    if fd < 0 {
        return None;
    }
    let mut page = [0u8; PAGE as usize];
    page[..CODE.len()].copy_from_slice(&CODE);
    (sys_write(fd as u64, page.as_ptr(), PAGE) == PAGE as i64).then_some(fd as u64)
}

/// A private writable executable file mapping, copied on write after
/// fork: the copy the child runs was made by the kernel
fn exec_cow() -> i64 {
    let Some(fd) = code_file() else {
        return 106;
    };
    let p = sys_mmap(0, PAGE, RW | PROT_EXEC, MAP_PRIVATE, fd as i32, 0);
    sys_close(fd);
    sys_unlink(FILE.as_ptr());
    if p < 0 {
        return 107;
    }
    let a = p as u64;
    if call(a) != 42 {
        return 108;
    }
    let pid = sys_fork();
    if pid == 0 {
        // Break the copy-on-write share (past the code), then run it
        put(a + 64, 1);
        sys_exit(call(a) as u64);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    if st & 0x7f != 0 {
        return 109;
    }
    ((st >> 8) & 0xff) as i64
}

/// Run code, unmap it, run it again: SIGSEGV
fn exec_munmap() -> i64 {
    let a = map(PAGE, RW);
    copy_code(a);
    sys_mprotect(a, PAGE, PROT_READ | PROT_EXEC);
    if call(a) != 42 {
        return 110;
    }
    sys_munmap(a, PAGE);
    call(a)
}

/// `return v` at `a`
#[cfg(target_arch = "x86_64")]
fn put_ret(a: u64, v: u8) {
    let code = [0xb8, v, 0, 0, 0, 0xc3];
    for (i, b) in code.iter().enumerate() {
        unsafe { core::ptr::write_volatile((a + i as u64) as *mut u8, *b) };
    }
}

/// `return v` at `a` (movz w0, #v; ret)
#[cfg(target_arch = "aarch64")]
fn put_ret(a: u64, v: u8) {
    let movz = 0x5280_0000u32 | ((v as u32) << 5);
    for (i, w) in [movz, 0xd65f_03c0].iter().enumerate() {
        unsafe { core::ptr::write_volatile((a + 4 * i as u64) as *mut u32, *w) };
    }
    clear_cache(a, 8);
}

/// Make code this process wrote visible to instruction fetch, as a JIT
/// must (__clear_cache): Linux only syncs pages the kernel fills, so on
/// real hardware a user rewrite of code needs this on both kernels
#[cfg(target_arch = "aarch64")]
fn clear_cache(a: u64, len: u64) {
    let ctr: u64;
    unsafe { core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack)) };
    let (dline, iline) = (4u64 << ((ctr >> 16) & 0xf), 4u64 << (ctr & 0xf));
    for va in ((a & !(dline - 1))..a + len).step_by(dline as usize) {
        unsafe { core::arch::asm!("dc cvau, {}", in(reg) va, options(nostack)) };
    }
    unsafe { core::arch::asm!("dsb ish", options(nostack)) };
    for va in ((a & !(iline - 1))..a + len).step_by(iline as usize) {
        unsafe { core::arch::asm!("ic ivau, {}", in(reg) va, options(nostack)) };
    }
    unsafe { core::arch::asm!("dsb ish", "isb", options(nostack)) };
}

/// DC ZVA from EL0 zeroes one block (glibc memset uses it; Linux sets
/// SCTLR_EL1.DZE): 0 if it did, or if DCZID_EL0 forbids it
#[cfg(target_arch = "aarch64")]
fn dc_zva() -> i64 {
    let id: u64;
    unsafe { core::arch::asm!("mrs {}, dczid_el0", out(reg) id, options(nomem, nostack)) };
    if id & 0x10 != 0 {
        return 0;
    }
    let bs = 4u64 << (id & 0xf);
    let a = map(4096, RW);
    for off in (0..4096).step_by(8) {
        put(a + off, u64::MAX);
    }
    unsafe { core::arch::asm!("dc zva, {}", in(reg) a, options(nostack)) };
    let zeroed = (0..bs).step_by(8).all(|off| get(a + off) == 0);
    if zeroed && get(a + bs) == u64::MAX {
        0
    } else {
        1
    }
}

/// Code written at the start, middle and end of a 2MB-aligned region
/// (a 2MB page on hk with MADV_HUGEPAGE) while it is not executable,
/// then mprotect'ed executable and run; rewritten with other values
/// (writable again), made executable again, run again: every function
/// returns what it was last written to return (protection changes and
/// TLB flushes cover all 2MB; user writes are synced by `clear_cache`)
fn exec_huge_rewrite() -> i64 {
    const HUGE: u64 = 2 << 20;
    const MADV_HUGEPAGE: i32 = 14;
    let raw = map(2 * HUGE, RW);
    let a = (raw + HUGE - 1) & !(HUGE - 1);
    sys_madvise(a, HUGE, MADV_HUGEPAGE);
    let offs = [0, HUGE / 2 + 0x340, HUGE - 16];
    for round in 0..2u8 {
        if sys_mprotect(a, HUGE, RW) != 0 {
            return 111;
        }
        for (i, &o) in offs.iter().enumerate() {
            put_ret(a + o, 10 * (round + 1) + i as u8);
        }
        if sys_mprotect(a, HUGE, PROT_READ | PROT_EXEC) != 0 {
            return 112;
        }
        for (i, &o) in offs.iter().enumerate() {
            if call(a + o) != (10 * (round + 1) + i as u8) as i64 {
                return 113 + round as i64;
            }
        }
    }
    0
}
