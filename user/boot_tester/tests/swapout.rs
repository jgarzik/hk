//! Swap-out and swap-in through vda2 (the 64 MiB mkswap partition of
//! the test disk, tools/mkdisk.sh): MADV_PAGEOUT writes anonymous pages
//! out (SwapFree and VmSwap drop, Linux reclaim_pages), faults read them
//! back intact, fork and mremap carry swapped pages, munmap gives the
//! slots back, swapoff reads everything in (Linux try_to_unuse).
//! Expectations from Linux 6.8; both kernels run it.

use super::helpers::{
    find_blkdev, freeswap_within, host_mode, print, print_num, println, proc_kb, swap_off, swap_on,
};
use hk_syscall::{
    MADV_COLD, MADV_PAGEOUT, MAP_ANONYMOUS, MAP_PRIVATE, MREMAP_FIXED, MREMAP_MAYMOVE, PROT_READ,
    PROT_WRITE, sys_exit, sys_fork, sys_madvise, sys_mmap, sys_mremap, sys_munmap, sys_wait4,
};

const MIB: u64 = 1024 * 1024;
/// Pages out per test (16 MiB)
const LEN: u64 = 16 * MIB;
/// Slack in kB for SwapFree/VmSwap comparisons (a few pages)
const TOL: i64 = 256;

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

/// The word stored at word `i` of a mapping filled with `seed`
fn word(seed: u64, i: u64) -> u64 {
    (i ^ seed).wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

fn map(len: u64) -> u64 {
    let p = sys_mmap(
        0,
        len,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if p < 0 { 0 } else { p as u64 }
}

/// Fill [p, p + len) with the pattern of `seed`, one word per 512 bytes
fn fill(p: u64, len: u64, seed: u64) {
    for i in (0..len / 8).step_by(64) {
        unsafe { core::ptr::write_volatile((p + i * 8) as *mut u64, word(seed, i)) };
    }
}

/// The first word index of [p, p + len) not holding the pattern
fn check(p: u64, len: u64, seed: u64) -> Option<u64> {
    (0..len / 8)
        .step_by(64)
        .find(|&i| unsafe { core::ptr::read_volatile((p + i * 8) as *const u64) } != word(seed, i))
}

/// `check` of bytes [from, to) of a mapping filled at `p`
fn check_from(p: u64, from: u64, to: u64, seed: u64) -> Option<u64> {
    (from / 8..to / 8)
        .step_by(64)
        .find(|&i| unsafe { core::ptr::read_volatile((p + i * 8) as *const u64) } != word(seed, i))
}

fn vmswap() -> i64 {
    proc_kb(b"/proc/self/status\0", b"VmSwap:")
}

fn swapfree() -> i64 {
    proc_kb(b"/proc/meminfo\0", b"SwapFree:")
}

pub fn run_tests() {
    let Some(p2) = find_blkdev(b"vd", 65536) else {
        println(b"SWAPOUT_FIND:FAIL no 64 MiB swap partition");
        return;
    };
    let mut buf = [0u8; 48];
    let path = p2.path(&mut buf);
    let on = swap_on(path);
    // mkswap of 64 MiB: 16383 usable pages
    let total = proc_kb(b"/proc/meminfo\0", b"SwapTotal:");
    verdict(
        b"SWAPOUT_SWAPON",
        on == 0 && total == 65532,
        on * 1_000_000 + total,
    );
    if on != 0 {
        return;
    }
    let base = swapfree();
    pageout_cycle(base);
    direct_reclaim();
    swapoff_swapped(path);
}

/// Page out 16 MiB, read it back through fork and mremap, then unmap
fn pageout_cycle(base: i64) {
    let p = map(LEN);
    if p == 0 {
        println(b"SWAPOUT_MMAP:FAIL");
        return;
    }
    fill(p, LEN, 1);
    let cold = sys_madvise(p, LEN, MADV_COLD);
    let r = sys_madvise(p, LEN, MADV_PAGEOUT);
    let want = base - (LEN / 1024) as i64;
    let free = freeswap_within(want, TOL);
    verdict(
        b"SWAPOUT_PAGEOUT",
        cold == 0 && r == 0 && free.is_ok(),
        free.unwrap_or_else(|g| g) - want,
    );
    let vs = vmswap();
    verdict(
        b"SWAPOUT_VMSWAP",
        (vs - (LEN / 1024) as i64).abs() <= TOL,
        vs,
    );
    fork_reads(p);
    let q = moved(p);
    if q != 0 {
        let bad = check(q, LEN, 1);
        verdict(b"SWAPOUT_DATA", bad.is_none(), bad.map_or(0, |i| i as i64));
        // Partly out again (swap PTEs and swap-cache pages), then gone:
        // every slot comes back
        sys_madvise(q, MIB, MADV_PAGEOUT);
        sys_munmap(q, LEN);
    }
    // Linux keeps up to 64 slots per CPU reserved in its swap slot
    // caches (mm/swap_slots.c); hk gives every slot back
    let tol = if host_mode() { 64 * 4 * 4 + TOL } else { TOL };
    let free = freeswap_within(base, tol);
    verdict(
        b"SWAPOUT_MUNMAP_FREES",
        free.is_ok(),
        free.unwrap_or_else(|g| g) - base,
    );
}

/// A fork child sees the swapped-out data and its writes stay its own
fn fork_reads(p: u64) {
    let pid = sys_fork();
    if pid == 0 {
        // Its first 4 MiB (each read is a swap I/O; slow under TCG)
        let ok = check(p, 4 * MIB, 1).is_none();
        fill(p, MIB, 2);
        sys_exit(if ok && check(p, MIB, 2).is_none() {
            0
        } else {
            1
        });
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    // The part the child wrote (the rest stays swapped out for mremap)
    let bad = check(p, MIB, 1);
    verdict(b"SWAPOUT_FORK", st == 0 && bad.is_none(), st as i64);
}

/// mremap the swapped-out range elsewhere: its pages follow; the new
/// address (0 on failure)
fn moved(p: u64) -> u64 {
    // A free range twice the size, the mapping moved to its upper half
    let r = map(2 * LEN);
    if r == 0 {
        return 0;
    }
    sys_munmap(r, 2 * LEN);
    // Mostly still out: the fork test read back only its first MiB
    let q = sys_mremap(p, LEN, LEN, MREMAP_MAYMOVE | MREMAP_FIXED, r + LEN);
    verdict(b"SWAPOUT_MREMAP", q == (r + LEN) as i64, q);
    if q < 0 { 0 } else { q as u64 }
}

/// More anonymous memory than is free: faults reclaim (swap out) the
/// oldest pages instead of failing, and every page reads back intact
fn direct_reclaim() {
    let free = proc_kb(b"/proc/meminfo\0", b"MemFree:");
    let len = ((free as u64 * 1024) + 4 * MIB) & !(MIB - 1);
    let p = map(len);
    if free <= 0 || p == 0 {
        verdict(b"SWAPOUT_DIRECT_RECLAIM", false, free);
        return;
    }
    // Touched in a child: running out of memory kills it, not init
    let pid = sys_fork();
    if pid == 0 {
        fill(p, len, 4);
        // hk had to swap; Linux may have found the room in its caches
        let swapped = host_mode() || vmswap() > 0;
        // The oldest pages went out; read them back (all of it would
        // cycle every page through swap, oldest first)
        let head = 8 * MIB;
        let tail = check_from(p, len - MIB, len, 4);
        let ok = check(p, head, 4).is_none() && tail.is_none() && swapped;
        sys_exit(if ok { 0 } else { 1 });
    }
    let st = wait_bounded(pid, 300);
    sys_munmap(p, len);
    verdict(b"SWAPOUT_DIRECT_RECLAIM", st == 0, st as i64);
}

/// wait4 for `pid`, SIGKILLing it after `secs` seconds (a stuck test
/// must not hang the boot): its status, -1 after a kill
fn wait_bounded(pid: i64, secs: u64) -> i32 {
    let ts = hk_syscall::Timespec {
        tv_sec: 0,
        tv_nsec: 100_000_000,
    };
    let mut st = 0i32;
    for _ in 0..secs * 10 {
        if sys_wait4(pid, &mut st, 1, 0) == pid {
            return st;
        }
        hk_syscall::sys_nanosleep(&ts, core::ptr::null_mut());
    }
    hk_syscall::sys_kill(pid, hk_syscall::SIGKILL);
    sys_wait4(pid, &mut st, 0, 0);
    -1
}

/// swapoff with pages out reads them all back
fn swapoff_swapped(path: &[u8]) {
    let len = 4 * MIB;
    let p = map(len);
    if p == 0 {
        swap_off(path);
        return;
    }
    fill(p, len, 3);
    sys_madvise(p, len, MADV_PAGEOUT);
    let out = vmswap();
    let off = swap_off(path);
    let total = proc_kb(b"/proc/meminfo\0", b"SwapTotal:");
    let bad = check(p, len, 3);
    let ok = out >= (len / 1024) as i64 - TOL
        && off == 0
        && total == 0
        && bad.is_none()
        && vmswap() == 0;
    verdict(b"SWAPOUT_SWAPOFF", ok, off * 1000 + out);
    sys_munmap(p, len);
}
