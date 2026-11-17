//! Task and thread group CPU time (Linux kernel/sched/cputime.c)
//!
//! Tick-based accounting (Linux CONFIG_TICK_CPU_ACCOUNTING): nothing
//! happens at a syscall's entry or exit. Each tick samples the running
//! task: a tick that interrupted user mode adds a tick to its utime,
//! one that interrupted the kernel to its stime, unless it hit the idle
//! task (`account_process_tick`). Each task's runtime
//! (`SchedEntity::sum_exec_runtime`) is advanced by the scheduler
//! whenever it charges the running task (`update_curr`: the tick, a
//! switch away, a reader of a running task's clock).
//! times(2), getrusage(2), wait's rusage and /proc/<pid>/stat report
//! utime/stime scaled to that runtime (`cputime_adjust`), never going
//! backwards.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use super::Task;
use super::percpu::{GlobalTaskTable, current, task_sched_runtime};
use crate::signal::SignalStruct;
use crate::sync::{IrqSpinlock, Sole};
use crate::task::Pid;

/// A task's or thread group's CPU time, ns (Linux struct task_cputime)
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct TaskCputime {
    pub utime: u64,
    pub stime: u64,
    pub sum_exec_runtime: u64,
}

impl core::ops::Add for TaskCputime {
    type Output = Self;

    fn add(self, o: Self) -> Self {
        Self {
            utime: self.utime.saturating_add(o.utime),
            stime: self.stime.saturating_add(o.stime),
            sum_exec_runtime: self.sum_exec_runtime.saturating_add(o.sum_exec_runtime),
        }
    }
}

/// Task `t`'s CPU time: its samples and its runtime as of its last
/// charge (Linux task_cputime, task_sample_cputime)
pub fn task_cputime(t: &Task) -> TaskCputime {
    TaskCputime {
        utime: t.utime.load(Ordering::Relaxed),
        stime: t.stime.load(Ordering::Relaxed),
        sum_exec_runtime: t.se.sum_exec_runtime(),
    }
}

/// The tick's sample of the task `p` it interrupted (Linux
/// account_process_tick; interrupt context, on `p`'s CPU, its only
/// writer): a tick of user time if it came from user mode, else of
/// system time, unless `p` is the idle task and the tick interrupted
/// nothing but it (idle time is nobody's)
pub fn account_process_tick(p: &Task, user_tick: bool) {
    use crate::arch::{CurrentArch, PerCpuOps};
    let cputime = super::percpu::TICK_NS;
    if user_tick {
        account_user_time(p, cputime);
    } else if p.tid() != 0 || CurrentArch::interrupt_depth() != 1 {
        account_system_time(p, cputime);
    }
}

/// Linux account_user_time: the task's and its group's running totals
fn account_user_time(p: &Task, cputime: u64) {
    p.utime.sole_add(cputime);
    if let Some(g) = p.cpu_group() {
        g.cputimer.account_user_time(cputime);
    }
}

/// Linux account_system_index_time
fn account_system_time(p: &Task, cputime: u64) {
    p.stime.sole_add(cputime);
    if let Some(g) = p.cpu_group() {
        g.cputimer.account_system_time(cputime);
    }
}

/// Thread group `pid`'s CPU time, TASKLIST held (Linux
/// thread_group_cputime): its threads released (their SignalStruct
/// sums) plus those still listed. Only the caller's own running slice
/// is charged first: other threads' runtime is as of their last tick
/// or switch. A thread gives its time to the struct in the section
/// that takes it off the thread list (Linux __exit_signal), so none
/// counts twice.
pub fn thread_group_cputime(table: &GlobalTaskTable, pid: Pid) -> TaskCputime {
    group_cputime(table, pid).0
}

/// `thread_group_cputime` and the group's SignalStruct
fn group_cputime(table: &GlobalTaskTable, pid: Pid) -> (TaskCputime, Option<Arc<SignalStruct>>) {
    let me = current();
    if me.pid == pid {
        task_sched_runtime(&me);
    }
    let mut sig = None;
    let mut sum = TaskCputime::default();
    for t in table.threads(pid) {
        let Some(s) = t.signal() else {
            continue;
        };
        sig.get_or_insert_with(|| s.clone());
        sum = sum + task_cputime(t.task);
    }
    match sig {
        Some(s) => (sum + s.dead_times(), Some(s)),
        None => (sum, None),
    }
}

/// The utime/stime last reported for a task or thread group (Linux
/// struct prev_cputime): an IrqSpinlock leaf (Linux prev->lock, a raw
/// spinlock taken irqsave) serializing `cputime_adjust`'s callers
pub struct PrevCputime(IrqSpinlock<(u64, u64)>);

impl PrevCputime {
    /// Nothing reported yet (Linux prev_cputime_init)
    pub const fn new() -> Self {
        Self(IrqSpinlock::new((0, 0)))
    }
}

impl Default for PrevCputime {
    fn default() -> Self {
        Self::new()
    }
}

/// `curr`'s tick-sampled utime and stime scaled to its exact runtime,
/// as (utime, stime), each never below what `prev` last reported
/// (Linux cputime_adjust): stime + utime == rtime, and both are
/// monotonic while rtime is
pub fn cputime_adjust(curr: &TaskCputime, prev: &PrevCputime) -> (u64, u64) {
    let mut p = prev.0.lock();
    let rtime = curr.sum_exec_runtime;
    // rtime behind what was reported (callers reordered by the lock):
    // report that again
    if p.0.saturating_add(p.1) >= rtime {
        return *p;
    }
    let (utime, stime) = (curr.utime, curr.stime);
    // No samples of one kind yet: all of it is the other's (all user
    // when there are none); the monotonic step below converges on the
    // observed ratio once both have ticks
    let mut stime = if stime == 0 {
        0
    } else if utime == 0 {
        rtime
    } else {
        // Linux mul_u64_u64_div_u64, capped at rtime (a*b/(b+c) <= a)
        let s = u128::from(stime) * u128::from(rtime) / (u128::from(stime) + u128::from(utime));
        u64::try_from(s).unwrap_or(rtime).min(rtime)
    };
    // stime never goes backwards, so neither does utime = rtime - stime
    stime = stime.max(p.1);
    let mut utime = rtime - stime;
    // utime never goes backwards (stime still does not)
    if utime < p.0 {
        utime = p.0;
        stime = rtime - utime;
    }
    *p = (utime, stime);
    *p
}

/// Task `t`'s (utime, stime), adjusted (Linux task_cputime_adjusted:
/// its runtime as of its last charge)
pub fn task_cputime_adjusted(t: &Task) -> (u64, u64) {
    cputime_adjust(&task_cputime(t), &t.prev_cputime)
}

/// Thread group `pid`'s (utime, stime), adjusted, TASKLIST held (Linux
/// thread_group_cputime_adjusted)
pub fn thread_group_cputime_adjusted(table: &GlobalTaskTable, pid: Pid) -> (u64, u64) {
    group_adjusted(table, pid).0
}

/// [`thread_group_cputime_adjusted`], with the group's SignalStruct
/// found on the way
pub fn group_adjusted(
    table: &GlobalTaskTable,
    pid: Pid,
) -> ((u64, u64), Option<Arc<SignalStruct>>) {
    match group_cputime(table, pid) {
        (c, Some(s)) => (cputime_adjust(&c, &s.prev_cputime), Some(s)),
        (c, None) => ((c.utime, c.stime), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(utime: u64, stime: u64, rtime: u64) -> TaskCputime {
        TaskCputime {
            utime,
            stime,
            sum_exec_runtime: rtime,
        }
    }

    #[test]
    fn scales_to_runtime() {
        let p = PrevCputime::new();
        assert_eq!(cputime_adjust(&c(30, 10, 100), &p), (75, 25));
    }

    #[test]
    fn no_samples_is_user() {
        let p = PrevCputime::new();
        assert_eq!(cputime_adjust(&c(0, 0, 7), &p), (7, 0));
        assert_eq!(cputime_adjust(&c(0, 5, 9), &p), (7, 2));
    }

    #[test]
    fn monotonic() {
        let p = PrevCputime::new();
        assert_eq!(cputime_adjust(&c(10, 10, 100), &p), (50, 50));
        // The ratio swings to user: stime stays, utime takes the rest
        assert_eq!(cputime_adjust(&c(100, 10, 120), &p), (70, 50));
        // rtime behind what was reported: the same again
        assert_eq!(cputime_adjust(&c(100, 10, 110), &p), (70, 50));
        // The ratio swings to system: utime stays
        assert_eq!(cputime_adjust(&c(1, 100, 130), &p), (70, 60));
    }
}
