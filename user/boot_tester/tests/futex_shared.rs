//! Futex keys (Linux get_futex_key): a shared futex is the backing
//! object and offset, a private one the mm and address.
//!
//! - FUTEX_SHARED_ALIAS: one file page mapped at two addresses; a waiter
//!   on the first is woken through the second.
//! - FUTEX_SHARED_MOVED: a shared anonymous page mremap'd to another
//!   address in a child; a wake at the parent's address finds it.
//! - FUTEX_PRIVATE_SPLIT: after fork, the same address in private memory
//!   is a different futex in each process.
//! - FUTEX_CTID_SHARED: clear_child_tid wakes a shared (non-PRIVATE)
//!   waiter on the tid word.
//! - FUTEX_ROBUST_PENDING: a thread exiting with a robust pending op on
//!   a free futex word wakes a waiter there (Linux handle_futex_death).
//! - ROBUST_DEATH_WAKE: likewise for a word with waiters but no owner
//!   (FUTEX_WAITERS alone): Linux wakes on the owner bits being 0.
//! - ROBUST_DEATH_OTHER_OWNER: likewise for a word another thread
//!   owns without FUTEX_WAITERS (Linux 7.2+; skipped on older hosts).
//! - ROBUST_DEATH_WAITERS: a thread dies holding a robust lock while a
//!   waiter sets FUTEX_WAITERS and sleeps: the death's update is a
//!   cmpxchg, so the bit is never lost and the waiter always wakes
//!   (200 rounds).

use core::sync::atomic::{AtomicU32, Ordering};

use super::fork_mm::spawn_thread;
use super::helpers::{print, print_num, println};
use hk_syscall::{
    FUTEX_WAIT, FUTEX_WAKE, MAP_ANONYMOUS, MAP_PRIVATE, MAP_SHARED, MREMAP_FIXED, MREMAP_MAYMOVE,
    O_CREAT, O_RDWR, PROT_READ, PROT_WRITE, RobustListHead, Timespec, sys_close, sys_exit,
    sys_fork, sys_ftruncate, sys_futex, sys_mmap, sys_mremap, sys_munmap, sys_nanosleep, sys_open,
    sys_set_robust_list, sys_unlink, sys_wait4,
};

const PAGE: u64 = 4096;
const EAGAIN: i64 = -11;
const ETIMEDOUT: i64 = -110;

pub fn run_tests() {
    shared_alias();
    shared_moved();
    private_split();
    ctid_shared();
    robust_pending();
    robust_death_wake();
    robust_death_other_owner();
    robust_death_waiters();
}

fn report(name: &[u8], ok: bool, got: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL: got ");
        print_num(got);
        println(b"");
    }
}

fn sleep_ms(ms: i64) {
    let ts = Timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * 1_000_000,
    };
    sys_nanosleep(&ts, core::ptr::null_mut());
}

/// Shared FUTEX_WAIT on `w` while it is 0, for at most `ms`
fn wait_shared(w: *mut u32, ms: i64) -> i64 {
    let ts = Timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * 1_000_000,
    };
    sys_futex(w, FUTEX_WAIT, 0, &ts, core::ptr::null_mut(), 0)
}

/// Shared FUTEX_WAKE of one waiter on `w`, retried for up to 2 s while
/// the waiter may not be asleep yet; the last result
fn wake_shared(w: *mut u32) -> i64 {
    let mut r = 0;
    for _ in 0..200 {
        r = sys_futex(
            w,
            FUTEX_WAKE,
            1,
            core::ptr::null(),
            core::ptr::null_mut(),
            0,
        );
        if r != 0 {
            break;
        }
        sleep_ms(10);
    }
    r
}

fn map(len: u64, flags: u32, fd: i32) -> i64 {
    sys_mmap(0, len, PROT_READ | PROT_WRITE, flags, fd, 0)
}

static ALIAS_RES: AtomicU32 = AtomicU32::new(u32::MAX);

#[repr(C, align(16))]
struct Stack([u8; 16384]);
static mut STACK: Stack = Stack([0; 16384]);
static mut CTID: u32 = 0;

extern "C" fn alias_waiter(addr: u64) -> ! {
    let r = wait_shared(addr as *mut u32, 3000);
    ALIAS_RES.store(r as u32, Ordering::SeqCst);
    sys_exit(0)
}

/// Wait (up to 3 s) for the helper thread to have exited
fn join() -> bool {
    for _ in 0..300 {
        if unsafe { core::ptr::read_volatile(&raw const CTID) } == 0 {
            return true;
        }
        sleep_ms(10);
    }
    false
}

fn spawn(f: extern "C" fn(u64) -> !, arg: u64) -> bool {
    unsafe {
        core::ptr::write_volatile(&raw mut CTID, 1);
        let top = (&raw mut STACK as *mut u8).add(16384) as u64;
        spawn_thread(top, f, arg, &raw mut CTID) > 0
    }
}

fn shared_alias() {
    const NAME: &[u8] = b"FUTEX_SHARED_ALIAS";
    let path = b"/tmp/futex_alias\0";
    let fd = sys_open(path.as_ptr(), O_CREAT | O_RDWR, 0o600);
    if fd < 0 || sys_ftruncate(fd as i32, PAGE as i64) != 0 {
        return report(NAME, false, fd);
    }
    let a = map(PAGE, MAP_SHARED, fd as i32);
    let b = map(PAGE, MAP_SHARED, fd as i32);
    sys_close(fd as u64);
    sys_unlink(path.as_ptr());
    if a < 0 || b < 0 || a == b {
        return report(NAME, false, if a < 0 { a } else { b });
    }
    ALIAS_RES.store(u32::MAX, Ordering::SeqCst);
    if !spawn(alias_waiter, a as u64) {
        return report(NAME, false, -1);
    }
    let woke = wake_shared(b as *mut u32);
    let joined = join();
    let res = ALIAS_RES.load(Ordering::SeqCst) as i32 as i64;
    sys_munmap(a as u64, PAGE);
    sys_munmap(b as u64, PAGE);
    report(
        NAME,
        woke == 1 && joined && res == 0,
        if woke != 1 { woke } else { res },
    );
}

fn shared_moved() {
    const NAME: &[u8] = b"FUTEX_SHARED_MOVED";
    let w = map(PAGE, MAP_SHARED | MAP_ANONYMOUS, -1);
    // Destination for the child's move, unmapped again (free range)
    let dst = map(PAGE, MAP_PRIVATE | MAP_ANONYMOUS, -1);
    if w < 0 || dst < 0 {
        return report(NAME, false, if w < 0 { w } else { dst });
    }
    sys_munmap(dst as u64, PAGE);
    let pid = sys_fork();
    if pid == 0 {
        let moved = sys_mremap(
            w as u64,
            PAGE,
            PAGE,
            MREMAP_MAYMOVE | MREMAP_FIXED,
            dst as u64,
        );
        if moved != dst {
            sys_exit(2)
        }
        let r = wait_shared(dst as *mut u32, 3000);
        sys_exit(if r == 0 { 0 } else { 1 })
    }
    if pid < 0 {
        return report(NAME, false, pid);
    }
    let woke = wake_shared(w as *mut u32);
    let mut st = 0i32;
    let waited = sys_wait4(pid, &mut st, 0, 0);
    sys_munmap(w as u64, PAGE);
    let code = (st >> 8) & 0xff;
    report(
        NAME,
        woke == 1 && waited == pid && st & 0x7f == 0 && code == 0,
        if woke != 1 { woke } else { code as i64 },
    );
}

fn private_split() {
    const NAME: &[u8] = b"FUTEX_PRIVATE_SPLIT";
    let w = map(PAGE, MAP_PRIVATE | MAP_ANONYMOUS, -1);
    if w < 0 {
        return report(NAME, false, w);
    }
    let word = w as *mut u32;
    // The child waits on its copy; a wake at the same address in the
    // parent must not reach it (it times out)
    let pid = sys_fork();
    if pid == 0 {
        let r = wait_shared(word, 500);
        sys_exit(if r == ETIMEDOUT { 0 } else { 1 })
    }
    if pid < 0 {
        return report(NAME, false, pid);
    }
    let mut woke = 0;
    for _ in 0..20 {
        woke = sys_futex(
            word,
            FUTEX_WAKE,
            1,
            core::ptr::null(),
            core::ptr::null_mut(),
            0,
        );
        if woke != 0 {
            break;
        }
        sleep_ms(10);
    }
    let mut st = 0i32;
    let waited = sys_wait4(pid, &mut st, 0, 0);
    sys_munmap(w as u64, PAGE);
    let code = (st >> 8) & 0xff;
    report(
        NAME,
        woke == 0 && waited == pid && st & 0x7f == 0 && code == 0,
        if woke != 0 { woke } else { code as i64 },
    );
}

extern "C" fn ctid_sleeper(_: u64) -> ! {
    sleep_ms(100);
    sys_exit(0)
}

fn ctid_shared() {
    const NAME: &[u8] = b"FUTEX_CTID_SHARED";
    if !spawn(ctid_sleeper, 0) {
        return report(NAME, false, -1);
    }
    // The tid word is non-zero until the thread exits; wait on it shared
    let mut r = 0;
    for _ in 0..10 {
        let tid = unsafe { core::ptr::read_volatile(&raw const CTID) };
        if tid == 0 {
            break;
        }
        let ts = Timespec {
            tv_sec: 2,
            tv_nsec: 0,
        };
        r = sys_futex(
            &raw mut CTID,
            FUTEX_WAIT,
            tid,
            &ts,
            core::ptr::null_mut(),
            0,
        );
        if r != EAGAIN {
            break;
        }
    }
    let cleared = unsafe { core::ptr::read_volatile(&raw const CTID) } == 0;
    report(NAME, r != ETIMEDOUT && cleared, r);
}

/// A robust list entry: the link, then the futex word
#[repr(C)]
struct Robust {
    next: u64,
    word: u32,
}

static mut ROBUST_HEAD: RobustListHead = RobustListHead {
    list: 0,
    futex_offset: 8,
    list_op_pending: 0,
};
static mut ROBUST_ENTRY: Robust = Robust { next: 0, word: 0 };

extern "C" fn robust_dier(_: u64) -> ! {
    unsafe {
        let head = &raw mut ROBUST_HEAD;
        (*head).list = head as u64;
        (*head).list_op_pending = &raw mut ROBUST_ENTRY as u64;
        sys_set_robust_list(head, core::mem::size_of::<RobustListHead>());
    }
    sleep_ms(100);
    sys_exit(0)
}

fn robust_pending() {
    const NAME: &[u8] = b"FUTEX_ROBUST_PENDING";
    unsafe { core::ptr::write_volatile(&raw mut ROBUST_ENTRY.word, 0) };
    if !spawn(robust_dier, 0) {
        return report(NAME, false, -1);
    }
    let r = wait_shared(unsafe { &raw mut ROBUST_ENTRY.word }, 3000);
    let joined = join();
    report(NAME, r == 0 && joined, r);
}

const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK: u32 = 0x3fff_ffff;

fn robust_death_wake() {
    const NAME: &[u8] = b"ROBUST_DEATH_WAKE";
    let w = unsafe { &raw mut ROBUST_ENTRY.word };
    unsafe { core::ptr::write_volatile(w, FUTEX_WAITERS) };
    if !spawn(robust_dier, 0) {
        return report(NAME, false, -1);
    }
    let ts = Timespec {
        tv_sec: 3,
        tv_nsec: 0,
    };
    let r = sys_futex(w, FUTEX_WAIT, FUTEX_WAITERS, &ts, core::ptr::null_mut(), 0);
    let joined = join();
    let left = unsafe { core::ptr::read_volatile(w) };
    // Woken, the word untouched
    report(NAME, r == 0 && joined && left == FUTEX_WAITERS, r);
}

fn robust_death_other_owner() {
    const NAME: &[u8] = b"ROBUST_DEATH_OTHER_OWNER";
    if !super::helpers::linux_at_least(7, 2) {
        return super::helpers::skip(NAME, b"Linux 7.2 wake rule");
    }
    // Owned by this thread (never the dying one), no waiters marked
    let other = hk_syscall::sys_gettid() as u32;
    let w = unsafe { &raw mut ROBUST_ENTRY.word };
    unsafe { core::ptr::write_volatile(w, other) };
    if !spawn(robust_dier, 0) {
        return report(NAME, false, -1);
    }
    let ts = Timespec {
        tv_sec: 3,
        tv_nsec: 0,
    };
    let r = sys_futex(w, FUTEX_WAIT, other, &ts, core::ptr::null_mut(), 0);
    let joined = join();
    let left = unsafe { core::ptr::read_volatile(w) };
    report(NAME, r == 0 && joined && left == other, r);
}

/// The holder is ready: its TID is in the word
static HOLDER_READY: AtomicU32 = AtomicU32::new(0);

/// Takes `ROBUST_ENTRY` (its TID in the word, the entry on its robust
/// list), then exits after `spins` yields
extern "C" fn robust_holder(spins: u64) -> ! {
    unsafe {
        let head = &raw mut ROBUST_HEAD;
        let e = &raw mut ROBUST_ENTRY;
        (*e).next = head as u64;
        (*head).list = e as u64;
        (*head).list_op_pending = 0;
        core::ptr::write_volatile(&raw mut (*e).word, hk_syscall::sys_gettid() as u32);
        sys_set_robust_list(head, core::mem::size_of::<RobustListHead>());
    }
    HOLDER_READY.store(1, Ordering::Release);
    for _ in 0..spins {
        hk_syscall::sys_sched_yield();
    }
    sys_exit(0)
}

/// Compare-and-swap on a futex word: the value found (no atomic RMW
/// from core: on arm64 it needs a libc helper boot_tester lacks)
fn cas(p: *mut u32, old: u32, new: u32) -> u32 {
    let found: u32;
    // SAFETY: `p` is a live, aligned u32 shared only through atomics
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "lock cmpxchg dword ptr [{p}], {new:e}",
            p = in(reg) p,
            new = in(reg) new,
            inout("eax") old => found,
            options(nostack),
        );
    }
    // SAFETY: as above
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "1: ldaxr {f:w}, [{p}]",
            "   cmp {f:w}, {old:w}",
            "   b.ne 2f",
            "   stlxr {t:w}, {new:w}, [{p}]",
            "   cbnz {t:w}, 1b",
            "2: clrex",
            p = in(reg) p,
            old = in(reg) old,
            new = in(reg) new,
            f = out(reg) found,
            t = out(reg) _,
            options(nostack),
        );
    }
    found
}

/// One round: 0, or ETIMEDOUT if the waiter was never woken
fn robust_round(spins: u64) -> i64 {
    let w = unsafe { &raw mut ROBUST_ENTRY.word };
    HOLDER_READY.store(0, Ordering::Relaxed);
    if !spawn(robust_holder, spins) {
        return -1;
    }
    while HOLDER_READY.load(Ordering::Acquire) == 0 {
        hk_syscall::sys_sched_yield();
    }
    let mut r = 0;
    loop {
        let v = unsafe { core::ptr::read_volatile(w) };
        if v & FUTEX_OWNER_DIED != 0 || v & FUTEX_TID_MASK == 0 {
            break;
        }
        let want = v | FUTEX_WAITERS;
        if v != want && cas(w, v, want) != v {
            continue;
        }
        let ts = Timespec {
            tv_sec: 2,
            tv_nsec: 0,
        };
        r = sys_futex(w, FUTEX_WAIT, want, &ts, core::ptr::null_mut(), 0);
        if r == ETIMEDOUT {
            break;
        }
    }
    if !join() {
        return -2;
    }
    if r == ETIMEDOUT { r } else { 0 }
}

fn robust_death_waiters() {
    const NAME: &[u8] = b"ROBUST_DEATH_WAITERS";
    for round in 0..200u64 {
        let r = robust_round(round % 8);
        if r != 0 {
            return report(NAME, false, r);
        }
    }
    report(NAME, true, 0);
}
