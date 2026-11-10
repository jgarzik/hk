//! Sleeping-lock fairness (run on hk and real Linux)
//!
//! Progress-based: lockers count their iterations; each measured call
//! must finish before they complete `K` more (a fair lock lets it in
//! after a few). They stop at `2 * K` past the call's start, so a starved
//! call ends there and fails instead of hanging.
//!
//! - MUTEX_HANDOFF: children share a regular file's open file with the
//!   parent and relock its position lock (Linux f_pos_lock) back to back,
//!   with a rewind and a 1 MiB read, while the parent's lseeks sleep on
//!   that mutex. Without a handoff to the sleeping waiter, a relocker
//!   wins every race after each unlock and the parent starves.
//! - RWSEM_FAIR: through the mmap_lock (a rw_semaphore), mincore (read)
//!   calls while three threads loop mprotect (write) back to back, and
//!   mprotect calls while three threads loop mincore: queued readers are
//!   granted the lock at a writer's release and new readers queue behind
//!   a waiting writer, so neither side starves the other.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::harness::T;
use crate::mm::fork_mm::{join, spawn_thread};
use hk_syscall::{
    MAP_ANONYMOUS, MAP_PRIVATE, MAP_SHARED, O_CREAT, O_RDWR, O_TRUNC, PROT_READ, PROT_WRITE,
    sys_close, sys_exit, sys_fork, sys_kill, sys_lseek, sys_mincore, sys_mmap, sys_mprotect,
    sys_munmap, sys_open, sys_read, sys_sched_yield, sys_unlink, sys_wait4, sys_write,
};

const SIGKILL: u32 = 9;
const SEEK_SET: i32 = 0;
const SEEK_CUR: i32 = 1;

pub fn run_tests() {
    test_mutex_handoff();
    test_rwsem_fair();
}

/// Lockers' iterations, shared with the measuring task (a counter per
/// locker: load and store, as RMW atomics on aarch64 need libc)
#[repr(C)]
struct Progress {
    iters: [AtomicU64; LOCKERS],
    /// Lockers idle at this count
    limit: AtomicU64,
    stop: AtomicU64,
}

impl Progress {
    const fn new() -> Self {
        Self {
            iters: [const { AtomicU64::new(0) }; LOCKERS],
            limit: AtomicU64::new(u64::MAX),
            stop: AtomicU64::new(0),
        }
    }

    /// Iterations of all lockers so far
    fn total(&self) -> u64 {
        self.iters.iter().map(|c| c.load(Ordering::Relaxed)).sum()
    }

    /// Locker `i` runs `f` and counts it, or idles at the limit; false
    /// once stopped
    fn step(&self, i: usize, f: impl FnOnce()) -> bool {
        if self.stop.load(Ordering::Relaxed) != 0 {
            return false;
        }
        if self.total() < self.limit.load(Ordering::Relaxed) {
            f();
            let c = &self.iters[i];
            c.store(c.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
        } else {
            sys_sched_yield();
        }
        true
    }

    /// The most locker iterations any of `OPS` runs of `op` spanned,
    /// after the lockers have started; stops at the first starved one
    fn worst(&self, k: u64, mut op: impl FnMut()) -> u64 {
        while self.total() < 2 * LOCKERS as u64 {
            sys_sched_yield();
        }
        let mut worst = 0;
        for _ in 0..OPS {
            let s = self.total();
            self.limit.store(s + 2 * k, Ordering::Relaxed);
            op();
            let d = self.total() - s;
            worst = worst.max(d);
            if d >= k {
                break;
            }
        }
        worst
    }
}

/// Lockers (processes or threads) contending with the measured calls
const LOCKERS: usize = 3;
/// Measured calls per test
const OPS: usize = 200;

/// Each relocker read holds the position lock this long
const CHUNK: u64 = 1 << 20;
/// Relocker iterations an lseek may span (fair: a few dozen at most)
const MUTEX_K: u64 = 2000;

/// Rewind and read the file back to back until killed
fn relocker(p: &Progress, i: usize, fd: u64, buf: u64) -> ! {
    loop {
        p.step(i, || {
            sys_lseek(fd as i32, 0, SEEK_SET);
            sys_read(fd, buf as *mut u8, CHUNK);
        });
    }
}

fn test_mutex_handoff() {
    let mut t = T::new(b"MUTEX_HANDOFF");
    let path = b"/tmp/mutex_handoff\0";
    let fd = sys_open(path.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o600);
    let buf = sys_mmap(
        0,
        CHUNK,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    let shared = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0,
    );
    if !t.ok(b"open", fd >= 0, fd)
        || !t.ok(b"mmap", buf > 0, buf)
        || !t.ok(b"mmap shared", shared > 0, shared)
    {
        return t.done();
    }
    // SAFETY: a fresh zeroed shared page, aligned, never unmapped while
    // the relockers live; a zero Progress is valid (limit set below)
    let p = unsafe { &*(shared as *const Progress) };
    p.limit.store(u64::MAX, Ordering::Relaxed);
    let (fd, buf) = (fd as u64, buf as u64);
    let w = sys_write(fd, buf as *const u8, CHUNK);
    t.eq(b"fill", w, CHUNK as i64);
    let mut pids = [0i64; LOCKERS];
    for (i, pid) in pids.iter_mut().enumerate() {
        *pid = sys_fork();
        if *pid == 0 {
            relocker(p, i, fd, buf);
        }
    }
    let forked = pids.iter().all(|&p| p > 0);
    let worst = if forked {
        p.worst(MUTEX_K, || {
            sys_lseek(fd as i32, 0, SEEK_CUR);
        })
    } else {
        0
    };
    for &pid in pids.iter() {
        if pid > 0 {
            sys_kill(pid, SIGKILL);
            let mut st = 0i32;
            sys_wait4(pid, &mut st, 0, 0);
        }
    }
    sys_close(fd);
    sys_unlink(path.as_ptr());
    sys_munmap(buf, CHUNK);
    sys_munmap(shared as u64, 4096);
    t.ok(b"forks", forked, 0);
    t.ok(
        b"relocker iterations in an lseek",
        worst < MUTEX_K,
        worst as i64,
    );
    t.done();
}

const PAGE: u64 = 4096;
const PAGES: u64 = 16;
/// Locker iterations a call may span: a front waiter may be passed over
/// until its handoff timeout (Linux RWSEM_WAIT_TIMEOUT, a tick or 4 ms),
/// tens of thousands of fast mprotects or mincores
const RWSEM_K: u64 = 500_000;
static BASE: AtomicU64 = AtomicU64::new(0);
static PROGRESS: Progress = Progress::new();

/// One thread's stack
#[repr(C, align(16))]
struct Stack([u8; 16384]);
static mut STACKS: [Stack; LOCKERS] = [const { Stack([0; 16384]) }; LOCKERS];
static mut CTIDS: [u32; LOCKERS] = [0; LOCKERS];

/// Flip page `i`'s protection (the mmap_lock for writing; its VMA
/// splits and merges)
fn protect(i: u64) {
    let prot = if i % 2 == 0 {
        PROT_READ
    } else {
        PROT_READ | PROT_WRITE
    };
    sys_mprotect(
        BASE.load(Ordering::Relaxed) + (i % PAGES) * PAGE,
        PAGE,
        prot,
    );
}

/// Residency of the region (the mmap_lock for reading)
fn residency() {
    let mut v = [0u8; PAGES as usize];
    sys_mincore(BASE.load(Ordering::Relaxed), PAGES * PAGE, v.as_mut_ptr());
}

extern "C" fn protector(me: u64) -> ! {
    let mut i = me * 5;
    while PROGRESS.step(me as usize, || protect(i)) {
        i += 1;
    }
    sys_exit(0)
}

extern "C" fn prober(me: u64) -> ! {
    while PROGRESS.step(me as usize, residency) {}
    sys_exit(0)
}

/// The most locker iterations an `op` spanned while `LOCKERS` threads
/// run `f`; false if a thread failed to start or stop
fn against(f: extern "C" fn(u64) -> !, op: impl FnMut()) -> (bool, u64) {
    for c in &PROGRESS.iters {
        c.store(0, Ordering::Relaxed);
    }
    PROGRESS.limit.store(u64::MAX, Ordering::Relaxed);
    PROGRESS.stop.store(0, Ordering::Relaxed);
    let mut started = [false; LOCKERS];
    for (i, s) in started.iter_mut().enumerate() {
        // SAFETY: stack and tid word `i` belong to this thread alone
        // until its exit clears the word (joined below)
        *s = unsafe {
            let top = (&raw mut STACKS[i] as *mut u8).add(16384) as u64;
            let ctid = &raw mut CTIDS[i];
            core::ptr::write_volatile(ctid, 1);
            spawn_thread(top, f, i as u64, ctid) > 0
        };
    }
    let all = started.iter().all(|&s| s);
    let worst = if all { PROGRESS.worst(RWSEM_K, op) } else { 0 };
    PROGRESS.stop.store(1, Ordering::Relaxed);
    let mut ok = all;
    for (i, &s) in started.iter().enumerate() {
        // SAFETY: the word of a started thread (see above)
        ok &= s && join(unsafe { &raw mut CTIDS[i] });
    }
    (ok, worst)
}

fn test_rwsem_fair() {
    let mut t = T::new(b"RWSEM_FAIR");
    let base = sys_mmap(
        0,
        PAGES * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if !t.ok(b"mmap", base > 0, base) {
        return t.done();
    }
    BASE.store(base as u64, Ordering::Relaxed);
    let (ok, worst) = against(protector, residency);
    t.ok(b"protector threads", ok, 0);
    t.ok(
        b"protector iterations in a mincore",
        worst < RWSEM_K,
        worst as i64,
    );
    let mut i = 0;
    let (ok, worst) = against(prober, || {
        protect(i);
        i += 1;
    });
    t.ok(b"prober threads", ok, 0);
    t.ok(
        b"prober iterations in an mprotect",
        worst < RWSEM_K,
        worst as i64,
    );
    sys_munmap(base as u64, PAGES * PAGE);
    t.done();
}
