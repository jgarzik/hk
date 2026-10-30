//! FUTEX_CMP_REQUEUE (Linux futex_requeue): a waiter moved from futex A
//! to futex B keeps sleeping on B. FUTEX_REQUEUE_SLEEP: requeued
//! waiters are not woken by the requeue nor by a wake of A, only by a
//! wake of B. FUTEX_REQUEUE_EXIT: requeued waiters that time out leave
//! B (ETIMEDOUT) and exit; a wake of B then finds nobody.

use core::sync::atomic::{AtomicI64, AtomicU32, Ordering};

use super::fork_mm::spawn_thread;
use super::helpers::{print, print_num, println};
use hk_syscall::{
    FUTEX_CMP_REQUEUE, FUTEX_PRIVATE_FLAG, FUTEX_WAIT, FUTEX_WAKE, Timespec, sys_exit, sys_futex,
    sys_nanosleep,
};

const N: usize = 4;

static A: AtomicU32 = AtomicU32::new(0);
static B: AtomicU32 = AtomicU32::new(0);
/// Each waiter is about to wait on A (plain stores: no atomic RMW,
/// which needs getauxval on arm64)
static READY: [AtomicU32; N] = [const { AtomicU32::new(0) }; N];
/// Each waiter's FUTEX_WAIT result (1: not returned)
static RES: [AtomicI64; N] = [const { AtomicI64::new(1) }; N];
/// Relative timeout of the waiters (0 = none), ms
static TIMEOUT_MS: AtomicI64 = AtomicI64::new(0);

#[repr(C, align(16))]
struct Stack([u8; 16384]);
static mut STACKS: [Stack; N] = [const { Stack([0; 16384]) }; N];
static mut CTIDS: [u32; N] = [0; N];

pub fn run_tests() {
    requeue_sleep();
    requeue_exit();
}

fn futex(
    word: &AtomicU32,
    op: u32,
    val: u32,
    ts: *const Timespec,
    word2: &AtomicU32,
    val3: u32,
) -> i64 {
    sys_futex(
        word.as_ptr(),
        op | FUTEX_PRIVATE_FLAG,
        val,
        ts,
        word2.as_ptr(),
        val3,
    )
}

fn sleep_ms(ms: i64) {
    let ts = Timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * 1_000_000,
    };
    sys_nanosleep(&ts, core::ptr::null_mut());
}

extern "C" fn waiter(i: u64) -> ! {
    let ms = TIMEOUT_MS.load(Ordering::Relaxed);
    let ts = Timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * 1_000_000,
    };
    let tsp = if ms > 0 {
        &ts as *const Timespec
    } else {
        core::ptr::null()
    };
    READY[i as usize].store(1, Ordering::SeqCst);
    let r = futex(&A, FUTEX_WAIT, 0, tsp, &A, 0);
    RES[i as usize].store(r, Ordering::SeqCst);
    sys_exit(0)
}

/// Start the N waiters on A; false if a clone failed
fn start(timeout_ms: i64) -> bool {
    A.store(0, Ordering::SeqCst);
    B.store(0, Ordering::SeqCst);
    TIMEOUT_MS.store(timeout_ms, Ordering::SeqCst);
    for (i, r) in RES.iter().enumerate() {
        r.store(1, Ordering::SeqCst);
        READY[i].store(0, Ordering::SeqCst);
        unsafe {
            core::ptr::write_volatile(&raw mut CTIDS[i], 1);
            let top = (&raw mut STACKS[i] as *mut u8).add(16384) as u64;
            if spawn_thread(top, waiter, i as u64, &raw mut CTIDS[i]) <= 0 {
                return false;
            }
        }
    }
    for _ in 0..1000 {
        if READY.iter().all(|r| r.load(Ordering::SeqCst) == 1) {
            return true;
        }
        sleep_ms(1);
    }
    false
}

/// Move every waiter from A to B (a late one blocks on A first);
/// the number moved
fn requeue_all() -> i64 {
    let mut moved = 0i64;
    for _ in 0..100 {
        sleep_ms(10);
        let r = futex(
            &A,
            FUTEX_CMP_REQUEUE,
            0,
            (N as i64 - moved) as usize as *const Timespec,
            &B,
            0,
        );
        if r < 0 {
            return r;
        }
        moved += r;
        if moved >= N as i64 {
            break;
        }
    }
    moved
}

/// Waiters whose FUTEX_WAIT returned
fn done() -> i64 {
    RES.iter().filter(|r| r.load(Ordering::SeqCst) != 1).count() as i64
}

/// Wait (up to 3 s) for every waiter to have exited
fn join_all() -> bool {
    for _ in 0..300 {
        if (0..N).all(|i| unsafe { core::ptr::read_volatile(&raw const CTIDS[i]) } == 0) {
            return true;
        }
        sleep_ms(10);
    }
    false
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

fn requeue_sleep() {
    const NAME: &[u8] = b"FUTEX_REQUEUE_SLEEP";
    if !start(0) {
        return report(NAME, -1);
    }
    let moved = requeue_all();
    if moved != N as i64 {
        report(NAME, -100 - moved);
        futex(&B, FUTEX_WAKE, N as u32, core::ptr::null(), &B, 0);
        futex(&A, FUTEX_WAKE, N as u32, core::ptr::null(), &A, 0);
        join_all();
        return;
    }
    sleep_ms(50);
    let early = done();
    let on_a = futex(&A, FUTEX_WAKE, N as u32, core::ptr::null(), &A, 0);
    sleep_ms(50);
    let after_a = done();
    let on_b = futex(&B, FUTEX_WAKE, N as u32, core::ptr::null(), &B, 0);
    let joined = join_all();
    let all_zero = RES.iter().all(|r| r.load(Ordering::SeqCst) == 0);
    let code = if early != 0 {
        -200 - early
    } else if on_a != 0 || after_a != 0 {
        -300 - on_a
    } else if on_b != N as i64 {
        -400 - on_b
    } else if !joined || !all_zero {
        -500
    } else {
        0
    };
    report(NAME, code);
}

fn requeue_exit() {
    const NAME: &[u8] = b"FUTEX_REQUEUE_EXIT";
    if !start(300) {
        return report(NAME, -1);
    }
    let moved = requeue_all();
    let joined = join_all();
    // The waiters timed out on B and left it: nobody to wake
    let on_b = futex(&B, FUTEX_WAKE, N as u32, core::ptr::null(), &B, 0);
    let timed_out = RES.iter().all(|r| r.load(Ordering::SeqCst) == -110);
    let code = if moved != N as i64 {
        -100 - moved
    } else if !joined {
        -200
    } else if !timed_out {
        -300
    } else if on_b != 0 {
        -400 - on_b
    } else {
        0
    };
    report(NAME, code);
}
