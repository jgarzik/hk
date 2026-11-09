//! Sleeping-lock fairness (run on hk and real Linux)
//!
//! - MUTEX_HANDOFF: children share a regular file's open file with the
//!   parent and relock its position lock (Linux f_pos_lock) back to back,
//!   with a rewind and a 1 MiB read; the parent's lseeks, which sleep on
//!   that mutex, each finish within a bound. Without a handoff to the
//!   sleeping waiter, a relocker wins every race after each unlock and
//!   the parent starves.
//! - RWSEM_FAIR: through the mmap_lock (a rw_semaphore), mincore (read)
//!   calls each finish within a bound while three threads loop mprotect
//!   (write) back to back, and mprotect calls while three threads loop
//!   mincore: queued readers are granted the lock at a writer's release
//!   and new readers queue behind a waiting writer, so neither side
//!   starves the other.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::harness::T;
use crate::mm::fork_mm::{join, spawn_thread};
use hk_syscall::{
    CLOCK_MONOTONIC, MAP_ANONYMOUS, MAP_PRIVATE, O_CREAT, O_RDWR, O_TRUNC, PROT_READ, PROT_WRITE,
    Timespec, sys_clock_gettime, sys_close, sys_exit, sys_fork, sys_kill, sys_lseek, sys_mincore,
    sys_mmap, sys_mprotect, sys_munmap, sys_nanosleep, sys_open, sys_read, sys_unlink, sys_wait4,
    sys_write,
};

const SIGKILL: u32 = 9;
const SEEK_SET: i32 = 0;
const SEEK_CUR: i32 = 1;

pub fn run_tests() {
    test_mutex_handoff();
    test_rwsem_fair();
}

fn now_us() -> i64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(CLOCK_MONOTONIC, &mut ts);
    ts.tv_sec * 1_000_000 + ts.tv_nsec / 1000
}

fn sleep_ms(ms: i64) {
    let ts = Timespec {
        tv_sec: 0,
        tv_nsec: ms * 1_000_000,
    };
    sys_nanosleep(&ts, core::ptr::null_mut());
}

/// Each relocker read holds the position lock this long
const CHUNK: u64 = 1 << 20;
const RELOCKERS: usize = 3;
/// The parent's locked operations
const OPS: usize = 200;
/// Longest any one may wait (a starved one waits for seconds)
const MAX_OP_US: i64 = 200_000;

/// Rewind and read the file back to back until killed
fn relocker(fd: u64, buf: u64) -> ! {
    loop {
        sys_lseek(fd as i32, 0, SEEK_SET);
        sys_read(fd, buf as *mut u8, CHUNK);
    }
}

/// The slowest of `OPS` runs of `op` (us), giving up after a few times
/// the bound
fn slowest(mut op: impl FnMut()) -> i64 {
    let (mut worst, start) = (0, now_us());
    for _ in 0..OPS {
        let t0 = now_us();
        op();
        worst = worst.max(now_us() - t0);
        if now_us() - start > MAX_OP_US * 5 {
            break;
        }
    }
    worst
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
    if !t.ok(b"open", fd >= 0, fd) || !t.ok(b"mmap", buf > 0, buf) {
        return t.done();
    }
    let (fd, buf) = (fd as u64, buf as u64);
    let w = sys_write(fd, buf as *const u8, CHUNK);
    t.eq(b"fill", w, CHUNK as i64);
    let mut pids = [0i64; RELOCKERS];
    for pid in pids.iter_mut() {
        *pid = sys_fork();
        if *pid == 0 {
            relocker(fd, buf);
        }
    }
    sleep_ms(20);
    let worst = slowest(|| {
        sys_lseek(fd as i32, 0, SEEK_CUR);
    });
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
    t.ok(b"forks", pids.iter().all(|&p| p > 0), 0);
    t.ok(b"slowest lseek (us)", worst < MAX_OP_US, worst);
    t.done();
}

const PAGE: u64 = 4096;
const PAGES: u64 = 16;
/// Threads looping on the mmap_lock
const LOCKERS: usize = 3;
static BASE: AtomicU64 = AtomicU64::new(0);
static STOP: AtomicU64 = AtomicU64::new(0);
/// Lockers stop by then (us) anyway, so a starved caller fails, not hangs
static DEADLINE: AtomicU64 = AtomicU64::new(0);

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

/// Keep locking: not stopped, not past the deadline
fn going() -> bool {
    STOP.load(Ordering::Relaxed) == 0 && (now_us() as u64) < DEADLINE.load(Ordering::Relaxed)
}

extern "C" fn protector(seed: u64) -> ! {
    let mut i = seed;
    while going() {
        protect(i);
        i += 1;
    }
    sys_exit(0)
}

extern "C" fn prober(_: u64) -> ! {
    while going() {
        residency();
    }
    sys_exit(0)
}

/// The slowest `op` while `LOCKERS` threads run `f`; false if a thread
/// failed to start or stop
fn against(f: extern "C" fn(u64) -> !, op: impl FnMut()) -> (bool, i64) {
    STOP.store(0, Ordering::Relaxed);
    DEADLINE.store((now_us() + MAX_OP_US * 15) as u64, Ordering::Relaxed);
    let mut started = [false; LOCKERS];
    for (i, s) in started.iter_mut().enumerate() {
        // SAFETY: stack and tid word `i` belong to this thread alone
        // until its exit clears the word (joined below)
        *s = unsafe {
            let top = (&raw mut STACKS[i] as *mut u8).add(16384) as u64;
            let ctid = &raw mut CTIDS[i];
            core::ptr::write_volatile(ctid, 1);
            spawn_thread(top, f, i as u64 * 5, ctid) > 0
        };
    }
    sleep_ms(20);
    let worst = slowest(op);
    STOP.store(1, Ordering::Relaxed);
    let mut ok = true;
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
    t.ok(b"slowest mincore (us)", worst < MAX_OP_US, worst);
    let mut i = 0;
    let (ok, worst) = against(prober, || {
        protect(i);
        i += 1;
    });
    t.ok(b"prober threads", ok, 0);
    t.ok(b"slowest mprotect (us)", worst < MAX_OP_US, worst);
    sys_munmap(base as u64, PAGES * PAGE);
    t.done();
}
