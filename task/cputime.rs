//! Task and thread group CPU time (Linux kernel/sched/cputime.c)
//!
//! Each task's runtime (`SchedEntity::sum_exec_runtime`) is advanced by
//! the scheduler whenever it charges the running task (`update_curr`:
//! the tick, a switch away, a reader of a running task's clock).

use super::Task;
use super::percpu::{GlobalTaskTable, current, task_sched_runtime};
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

/// Task `t`'s CPU time, its runtime as of its last charge (Linux
/// task_sample_cputime)
pub fn task_cputime(t: &Task) -> TaskCputime {
    let (utime, stime) = t.cputime(crate::time::monotonic_ns());
    TaskCputime {
        utime,
        stime,
        sum_exec_runtime: t.se.sum_exec_runtime(),
    }
}

/// Thread group `pid`'s CPU time, TASKLIST held (Linux
/// thread_group_cputime): its threads gone (their SignalStruct sums)
/// plus those still holding the SignalStruct. Only the caller's own
/// running slice is charged first: other threads' runtime is as of
/// their last tick or switch. A thread that left gave its time to the
/// struct when it lost it, so none counts twice.
pub fn thread_group_cputime(table: &GlobalTaskTable, pid: Pid) -> TaskCputime {
    let me = current();
    if me.pid == pid {
        task_sched_runtime(&me);
    }
    let mut sig = None;
    let mut sum = TaskCputime::default();
    for t in table.threads(pid) {
        let Some(s) = &t.signal else {
            continue;
        };
        sig.get_or_insert_with(|| s.clone());
        sum = sum + task_cputime(t.task);
    }
    match sig {
        Some(s) => sum + s.dead_times(),
        None => sum,
    }
}
