//! Waiting for CQEs (Linux io_uring/wait.c io_cqring_wait, io_uring.c
//! io_get_ext_arg)
//!
//! io_uring_enter with IORING_ENTER_GETEVENTS sleeps on the ring's
//! `cq_wait` until the CQ holds `min_complete` entries user space has
//! not consumed, interruptibly: a deliverable signal ends it with EINTR,
//! a timeout (IORING_ENTER_EXT_ARG's timespec, relative, CLOCK_MONOTONIC)
//! with ETIME; with CQEs ready either way it returns 0. A sigmask
//! (argp itself without EXT_ARG, else the arg's) is the mask during the
//! wait, as pselect's.

use core::pin::pin;
use core::sync::atomic::Ordering;

use super::IoRing;
use super::abi::IORING_ENTER_EXT_ARG;
use crate::sync::waitqueue::WaitEntry;
use crate::task::percpu::{SleepState, current, set_current_state};
use crate::task::task_work::task_work_run;
use crate::time::hrtimer::{HrClock, schedule_hrtimeout};
use crate::uaccess::copy_val_from_user;
use crate::util::error::{KernelError, KernelResult};

/// struct io_uring_getevents_arg
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct GeteventsArg {
    sigmask: u64,
    sigmask_sz: u32,
    min_wait_usec: u32,
    ts: u64,
}
crate::pod!(GeteventsArg {
    sigmask,
    sigmask_sz,
    min_wait_usec,
    ts
});

/// What a GETEVENTS wait takes besides the count (Linux struct ext_arg)
pub struct ExtArg {
    /// The sigset_t to wait under (0: none) and its size
    sig: u64,
    sigsz: u64,
    /// Relative timeout in ns
    ts: Option<u64>,
}

/// The wait's arguments from `argp`/`argsz` (Linux io_get_ext_arg):
/// without IORING_ENTER_EXT_ARG `argp` is the sigmask; with it an
/// io_uring_getevents_arg of exactly its size (EINVAL) holding the
/// sigmask and a timespec pointer; EFAULT
pub fn get_ext_arg(flags: u32, argp: u64, argsz: usize) -> KernelResult<ExtArg> {
    if flags & IORING_ENTER_EXT_ARG == 0 {
        return Ok(ExtArg {
            sig: argp,
            sigsz: argsz as u64,
            ts: None,
        });
    }
    if argsz != size_of::<GeteventsArg>() {
        return Err(KernelError::InvalidArgument);
    }
    let a: GeteventsArg = copy_val_from_user(argp)?;
    let ts = match a.ts {
        0 => None,
        p => Some(timespec_ns(copy_val_from_user::<[i64; 2]>(p)?)),
    };
    Ok(ExtArg {
        sig: a.sigmask,
        sigsz: u64::from(a.sigmask_sz),
        ts,
    })
}

/// A __kernel_timespec as ns, unvalidated as Linux's
/// timespec64_to_ktime: negative is 0 (already due), huge saturates
fn timespec_ns([sec, nsec]: [i64; 2]) -> u64 {
    let ns = i128::from(sec) * 1_000_000_000 + i128::from(nsec);
    ns.clamp(0, i128::from(u64::MAX)) as u64
}

impl IoRing {
    /// CQEs published and not yet consumed (Linux
    /// __io_cqring_events_user)
    fn cq_events(&self) -> u32 {
        self.rings.cq_tail().wrapping_sub(self.rings.cq_head())
    }

    /// Wait for `min` CQEs (Linux io_cqring_wait)
    pub fn cq_wait(&self, min: u32, ext: &ExtArg) -> KernelResult<()> {
        let min = min.min(self.rings.cq_entries());
        task_work_run();
        self.flush_overflow();
        if self.cq_events() >= min {
            return Ok(());
        }
        let deadline = ext
            .ts
            .map(|ns| crate::time::deadline_after(crate::time::monotonic_ns(), ns));
        crate::signal::set_user_sigmask(ext.sig, ext.sigsz)?;
        let target = self.rings.cq_head().wrapping_add(min);
        let r = self.wait_loop(target, deadline);
        crate::signal::restore_saved_sigmask_unless(r == Err(KernelError::Interrupted));
        if self.cq_events() != 0 { Ok(()) } else { r }
    }

    /// Sleep until the CQ tail reaches `target`, a signal (EINTR) or
    /// `deadline` (ETIME)
    fn wait_loop(&self, target: u32, deadline: Option<u64>) -> KernelResult<()> {
        let w = pin!(WaitEntry::new());
        let r = loop {
            self.cq_wait
                .prepare_to_wait(w.as_ref(), SleepState::Interruptible);
            // Requests ended for this task post their CQEs here (Linux
            // io_run_task_work in the wait loop)
            if current().has_tif(crate::task::tif::NOTIFY_SIGNAL) {
                set_current_state(SleepState::Running);
                task_work_run();
                continue;
            }
            self.flush_overflow();
            if self.cq_reached(target) {
                break Ok(());
            }
            // A lost CQE is reported once (Linux IO_CHECK_CQ_DROPPED_BIT)
            if self.dropped.load(Ordering::Acquire) {
                break Err(KernelError::BadRequest);
            }
            // Only a real signal ends it (Linux task_sigpending)
            if current().sigpending() {
                break Err(KernelError::Interrupted);
            }
            if schedule_hrtimeout(deadline, HrClock::Monotonic) && !self.cq_reached(target) {
                break Err(KernelError::TimerExpired);
            }
        };
        self.cq_wait.finish_wait(w.as_ref());
        r
    }

    /// The CQ tail is at or past `target` (Linux io_should_wake)
    fn cq_reached(&self, target: u32) -> bool {
        // Wrapping distance, signed: at or past
        self.rings.cq_tail().wrapping_sub(target) as i32 >= 0
    }
}
