//! io_uring_enter with IORING_ENTER_GETEVENTS (Linux io_uring/wait.c
//! io_cqring_wait, io_uring.c io_get_ext_arg):
//! - IO_URING_WAIT_WAKE: it sleeps until another task's submission on
//!   the same ring (a fork child's) posts the CQE it waits for
//! - IO_URING_WAIT_TIMEOUT: an empty CQ with IORING_ENTER_EXT_ARG's
//!   timeout is ETIME, not before the timeout
//! - IO_URING_WAIT_ARGSZ: an io_uring_getevents_arg of the wrong size is
//!   EINVAL
//! - IO_URING_WAIT_SIGNAL: a caught signal (SIGALRM of a timer) ends
//!   the wait with EINTR
//! - IO_URING_WAIT_SIGMASK: the arg's sigmask holds during the wait (the
//!   signal it blocks waits for the return, then is delivered)

use core::sync::atomic::{AtomicU32, Ordering};

use super::{Ring, sqe};
use crate::harness::{R, check, report_r};
use crate::helpers::msleep;
use crate::signal::signals::restorer_addr;
use hk_syscall::{
    CLOCK_MONOTONIC, IORING_ENTER_EXT_ARG, IORING_ENTER_GETEVENTS, IORING_OP_NOP, ITIMER_REAL,
    ITimerVal, SA_RESTORER, SA_SIGINFO, SIG_DFL, SIGALRM, Timespec, Timeval, sys_clock_gettime,
    sys_exit, sys_fork, sys_io_uring_enter, sys_rt_sigaction, sys_setitimer, sys_wait4,
};

const EINTR: i64 = -4;
const EINVAL: i64 = -22;
const ETIME: i64 = -62;

pub fn run_tests() {
    let cases: [(&[u8], fn() -> R); 5] = [
        (b"IO_URING_WAIT_WAKE", wake),
        (b"IO_URING_WAIT_TIMEOUT", timeout),
        (b"IO_URING_WAIT_ARGSZ", argsz),
        (b"IO_URING_WAIT_SIGNAL", signal),
        (b"IO_URING_WAIT_SIGMASK", sigmask),
    ];
    for (name, t) in cases {
        report_r(name, t());
    }
}

/// struct io_uring_getevents_arg
#[repr(C)]
struct GeteventsArg {
    sigmask: u64,
    sigmask_sz: u32,
    pad: u32,
    ts: u64,
}

fn now_ms() -> i64 {
    let mut t = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(CLOCK_MONOTONIC, &mut t);
    t.tv_sec * 1000 + t.tv_nsec / 1_000_000
}

/// GETEVENTS for `min` with an EXT_ARG of `ms` ms (none for 0) and
/// sigmask `mask` (none for 0)
fn wait_ext(r: &Ring, min: u32, ms: i64, mask: u64) -> i64 {
    let ts = Timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * 1_000_000,
    };
    let arg = GeteventsArg {
        sigmask: if mask != 0 {
            &mask as *const u64 as u64
        } else {
            0
        },
        sigmask_sz: 8,
        pad: 0,
        ts: if ms != 0 {
            &ts as *const Timespec as u64
        } else {
            0
        },
    };
    sys_io_uring_enter(
        r.fd as u32,
        0,
        min,
        IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG,
        &arg as *const GeteventsArg as u64,
        core::mem::size_of::<GeteventsArg>(),
    )
}

fn ring() -> Result<Ring, (&'static [u8], i64)> {
    Ring::simple(4).map_err(|e| (&b"ring setup/mmap"[..], e))
}

fn reap(pid: i64) {
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
}

fn wake() -> R {
    let mut r = ring()?;
    let pid = sys_fork();
    if pid == 0 {
        // The child's copy of the ring maps the same pages
        msleep(50);
        r.push(sqe(IORING_OP_NOP, -1, 0, 0, 0, 42));
        r.enter(1, 0, 0);
        sys_exit(0);
    }
    check(b"fork", pid > 0, pid)?;
    let n = r.enter(0, 1, IORING_ENTER_GETEVENTS);
    let got = r.pop();
    reap(pid);
    check(b"enter", n == 0, n)?;
    let c = got.ok_or((&b"returned with no cqe"[..], 0))?;
    check(b"user_data", c.user_data == 42, c.user_data as i64)
}

fn timeout() -> R {
    let r = ring()?;
    let t0 = now_ms();
    let n = wait_ext(&r, 1, 50, 0);
    let dt = now_ms() - t0;
    check(b"result", n == ETIME, n)?;
    check(b"elapsed ms", dt >= 50, dt)
}

fn argsz() -> R {
    let r = ring()?;
    let arg = GeteventsArg {
        sigmask: 0,
        sigmask_sz: 0,
        pad: 0,
        ts: 0,
    };
    let n = sys_io_uring_enter(
        r.fd as u32,
        0,
        1,
        IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG,
        &arg as *const GeteventsArg as u64,
        16,
    );
    check(b"result", n == EINVAL, n)
}

/// SIGALRM handler runs
static CAUGHT: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_alrm(_s: i32, _i: *const u8, _u: *const u8) {
    // load+store, not fetch_add: RMW atomics on aarch64 need libc's getauxval
    CAUGHT.store(CAUGHT.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
}

#[repr(C)]
struct SigAct {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

/// Catch SIGALRM (`on`) or back to SIG_DFL
fn catch(on: bool) {
    CAUGHT.store(0, Ordering::Relaxed);
    let act = SigAct {
        handler: if on {
            on_alrm as *const () as u64
        } else {
            SIG_DFL
        },
        flags: SA_SIGINFO | SA_RESTORER,
        restorer: restorer_addr(),
        mask: 0,
    };
    sys_rt_sigaction(SIGALRM, &act as *const SigAct as u64, 0, 8);
}

/// Wait `ms` (0: none) with `mask` while a timer sends SIGALRM after
/// 50 ms: the result and the handler runs seen right after
fn signalled(ms: i64, mask: u64) -> Result<(i64, u32), (&'static [u8], i64)> {
    let r = ring()?;
    catch(true);
    let it = ITimerVal {
        it_interval: Timeval::default(),
        it_value: Timeval {
            tv_sec: 0,
            tv_usec: 50_000,
        },
    };
    let t = sys_setitimer(ITIMER_REAL, &it, core::ptr::null_mut());
    let n = wait_ext(&r, 1, ms, mask);
    let caught = CAUGHT.load(Ordering::Relaxed);
    catch(false);
    check(b"setitimer", t == 0, t)?;
    Ok((n, caught))
}

fn signal() -> R {
    let (n, caught) = signalled(5000, 0)?;
    check(b"result", n == EINTR, n)?;
    check(b"handler", caught == 1, i64::from(caught))
}

fn sigmask() -> R {
    let (n, caught) = signalled(300, 1 << (SIGALRM - 1))?;
    check(b"result", n == ETIME, n)?;
    check(b"handler after", caught == 1, i64::from(caught))
}
