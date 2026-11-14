//! Job control: group stop and continue (Linux kernel/signal.c
//! do_signal_stop, task_participate_group_stop, prepare_signal,
//! do_jobctl_trap)
//!
//! A stop signal's default action stops every thread of the group: the
//! first thread to act on it sets JOBCTL_STOP_PENDING on the others and
//! counts them (`GroupStop::count`); each stops when it next runs its
//! signal work, the last one completes the stop (SIGNAL_STOP_STOPPED)
//! and tells the parent (CLD_STOPPED). SIGCONT, at generation, ends it:
//! stopped threads go on and the first of them tells the parent
//! (CLD_CONTINUED). A traced thread joins a group stop through a ptrace
//! trap instead (JOBCTL_TRAP_STOP).
//!
//! Locking (doc/LOCKING.md 3.7): the group state is under
//! `SignalStruct.jobctl` (Linux siglock's group part), taken after
//! TASKLIST and before any thread's `Task.sig`, which holds the
//! thread's own bits (`TaskSignalState::jobctl`); a stop bit of a
//! thread is changed with both held.

use super::jobctl::*;
use super::{SIGCONT, SIGSTOP, SIGTRAP, SigPending, SigSet, Signal, SignalStruct, TaskSignalState};
use crate::sync::spin::MutexGuard;
use crate::task::Task;
use crate::task::percpu::{GlobalTaskTable, WakeMode};

/// SignalStruct.flags' stop bits (Linux SIGNAL_STOP_*, SIGNAL_CLD_*)
pub mod flags {
    /// The group stop is complete (Linux SIGNAL_STOP_STOPPED)
    pub const STOP_STOPPED: u32 = 1 << 0;
    /// SIGCONT ended a stop: WCONTINUED reports it once (Linux
    /// SIGNAL_STOP_CONTINUED)
    pub const STOP_CONTINUED: u32 = 1 << 1;
    /// The parent is still to be told CLD_STOPPED (Linux
    /// SIGNAL_CLD_STOPPED)
    pub const CLD_STOPPED: u32 = 1 << 2;
    /// The parent is still to be told CLD_CONTINUED (Linux
    /// SIGNAL_CLD_CONTINUED)
    pub const CLD_CONTINUED: u32 = 1 << 3;
    /// Linux SIGNAL_CLD_MASK
    pub const CLD_MASK: u32 = CLD_STOPPED | CLD_CONTINUED;
    /// Linux SIGNAL_STOP_MASK
    pub const STOP_MASK: u32 = CLD_MASK | STOP_STOPPED | STOP_CONTINUED;
}

/// A thread group's job-control state (Linux signal->flags' stop bits,
/// group_stop_count, group_exit_code as the stop's signal), under
/// `SignalStruct.jobctl`
pub struct GroupStop {
    pub flags: u32,
    /// Threads still to stop for the group stop in progress
    pub count: u32,
    /// The stop's signal, until a wait reports it (then 0)
    pub code: u32,
}

impl GroupStop {
    pub const fn new() -> Self {
        Self {
            flags: 0,
            count: 0,
            code: 0,
        }
    }

    /// Linux signal_set_stop_flags
    fn set_stop_flags(&mut self, f: u32) {
        self.flags = (self.flags & !flags::STOP_MASK) | f;
    }
}

impl Default for GroupStop {
    fn default() -> Self {
        Self::new()
    }
}

/// CLD_* codes of a stop notice (Linux do_notify_parent_cldstop's why)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    Stopped,
    Continued,
    Trapped,
}

impl Why {
    pub fn code(self) -> i32 {
        use super::si_code::{CLD_CONTINUED, CLD_STOPPED, CLD_TRAPPED};
        match self {
            Self::Stopped => CLD_STOPPED,
            Self::Continued => CLD_CONTINUED,
            Self::Trapped => CLD_TRAPPED,
        }
    }
}

type Group<'a> = MutexGuard<'a, GroupStop>;

/// Set `mask` in `t`'s jobctl (Linux task_set_jobctl_pending): not for
/// a thread with SIGKILL pending or exiting; a stop signal in `mask`
/// replaces the recorded one
pub fn set_pending(t: &Task, s: &mut TaskSignalState, mask: u32) -> bool {
    if s.pending.signal.contains(super::SIGKILL) || t.has_flag(crate::task::pf::EXITING) {
        return false;
    }
    if mask & STOP_SIGMASK != 0 {
        s.jobctl &= !STOP_SIGMASK;
    }
    s.jobctl |= mask;
    true
}

/// Clear `mask` of the pending bits (Linux task_clear_jobctl_pending):
/// STOP_PENDING takes CONSUME and DEQUEUED with it; with nothing left
/// pending, TRAPPING ends
pub fn clear_pending(s: &mut TaskSignalState, mask: u32) {
    let mut mask = mask;
    if mask & STOP_PENDING != 0 {
        mask |= STOP_CONSUME | STOP_DEQUEUED;
    }
    s.jobctl &= !mask;
    if s.jobctl & PENDING_MASK == 0 {
        clear_trapping(s);
    }
}

/// End JOBCTL_TRAPPING, waking an attach waiting for it (Linux
/// task_clear_jobctl_trapping: wake_up_bit; the attach waits on
/// CHILD_EXIT_WQ)
pub fn clear_trapping(s: &mut TaskSignalState) {
    if s.jobctl & TRAPPING != 0 {
        s.jobctl &= !TRAPPING;
        crate::task::proc::CHILD_EXIT_WQ.wake_all();
    }
}

/// `t` takes its part in the group stop (Linux
/// task_participate_group_stop): true if it completed a fresh one, to
/// be told to the parent
fn participate(g: &mut Group<'_>, s: &mut TaskSignalState) -> bool {
    let consume = s.jobctl & STOP_CONSUME != 0;
    clear_pending(s, STOP_PENDING);
    if !consume {
        return false;
    }
    g.count = g.count.saturating_sub(1);
    if g.count == 0 && g.flags & flags::STOP_STOPPED == 0 {
        g.set_stop_flags(flags::STOP_STOPPED);
        return true;
    }
    false
}

/// A signal for `t` to act on (Linux signal_wake_up(t, fatal)), its
/// Task.sig held: TIF_SIGPENDING set and `t` woken from an
/// interruptible sleep; a fatal one also ends a job-control or ptrace
/// stop (unless its tracer's request holds that) and wakes a killable
/// sleep
pub fn signal_wake_up(t: &Task, s: &mut TaskSignalState, fatal: bool) {
    t.set_sigpending(true);
    let mode = if fatal && !s.frozen() {
        s.jobctl &= !STOPPED;
        s.end_trace_stop();
        WakeMode::Fatal
    } else {
        WakeMode::Interruptible
    };
    super::signal_wake_task(t, mode);
}

/// A seized tracee is to report a job-control change in a trap (Linux
/// ptrace_trap_notify; no PTRACE_LISTEN, so a ptrace stop it is in is
/// left alone), its Task.sig held
fn trap_notify(t: &Task, s: &mut TaskSignalState) {
    set_pending(t, s, TRAP_NOTIFY);
    t.set_sigpending(true);
    super::signal_wake_task(t, WakeMode::Interruptible);
}

/// `t` (TASKLIST held: the view) is traced with PTRACE_SEIZE
fn seized(v: &crate::task::percpu::TaskView<'_>) -> bool {
    v.ptrace() & crate::task::ptrace::PT_SEIZED != 0
}

/// The process-wide effects of a stop signal or SIGCONT sent to the
/// group `tgid` whose state `g` is (Linux prepare_signal), TASKLIST
/// held: a stop signal drops every pending SIGCONT; SIGCONT drops every
/// pending stop signal, ends the group stop, continues stopped threads
/// and leaves the parent's notice to the first of them. The signal
/// itself is then queued (or ignored) as any other.
pub fn prepare(
    table: &GlobalTaskTable,
    sig_struct: &SignalStruct,
    g: &mut Group<'_>,
    tgid: crate::task::Pid,
    sig: Signal,
    gone: &mut SigPending,
) {
    let stop = sig.kernel_stop();
    let flush = if stop {
        SigSet::of(SIGCONT)
    } else {
        super::STOP_SIGNALS
    };
    for v in table.threads(tgid) {
        let mut s = v.task.sig.lock();
        s.pending.flush_mask_into(&flush, gone);
        if !stop {
            clear_pending(&mut s, STOP_PENDING);
            if !seized(&v) {
                if s.jobctl & STOPPED != 0 {
                    s.jobctl &= !STOPPED;
                    crate::task::percpu::try_to_wake_up(v.task, WakeMode::Any);
                }
            } else {
                trap_notify(v.task, &mut s);
            }
        }
        v.task.set_sigpending(s.has_deliverable_signals());
    }
    sig_struct.shared.lock().flush_mask_into(&flush, gone);
    if !stop {
        // Stopped: CLD_CONTINUED; in the middle of a stop: as if it had
        // completed and the continue's notice were lost (Linux)
        let why = if g.flags & flags::STOP_STOPPED != 0 {
            flags::CLD_CONTINUED
        } else if g.count != 0 {
            flags::CLD_STOPPED
        } else {
            0
        };
        if why != 0 {
            g.set_stop_flags(why | flags::STOP_CONTINUED);
            g.count = 0;
            g.code = 0;
        }
    }
}

/// A dying group's stop ends (Linux zap_other_threads, complete_signal's
/// group kill): no thread is left to stop, under the group lock
pub fn end_for_kill(g: &mut Group<'_>) {
    g.count = 0;
}

/// The current thread stops for its group (Linux do_signal_stop),
/// `signr` the stop signal it dequeued (None: joining a stop in
/// progress). True if it stopped (and was continued or killed since);
/// false if no stop happened, or it is traced and will report the stop
/// in a ptrace trap (JOBCTL_TRAP_STOP set).
pub fn do_signal_stop(signr: Option<Signal>) -> bool {
    use crate::task::percpu::{SleepState, set_current_state};
    let me = crate::task::percpu::current();
    let Some(sig_struct) = me.cpu_group().cloned() else {
        return false;
    };
    let table = crate::task::percpu::TASKLIST.read();
    let Some(mv) = table.view(&me) else {
        return false;
    };
    let traced = mv.ptrace() != 0;
    let mut g = sig_struct.jobctl.lock();
    let mut s = me.sig.lock();
    if s.jobctl & STOP_PENDING == 0 {
        let Some(signr) = signr else {
            return false;
        };
        let gstop = STOP_PENDING | STOP_CONSUME;
        if s.jobctl & STOP_DEQUEUED == 0 || sig_struct.group_exit() != super::GroupExit::None {
            return false;
        }
        // A traced thread resumed in a completed stop may start another:
        // its code stays the first's (Linux)
        if g.flags & flags::STOP_STOPPED == 0 {
            g.code = signr.nr();
        }
        g.count = 0;
        if set_pending(&me, &mut s, signr.nr() | gstop) {
            g.count += 1;
        }
        drop(s);
        for v in table.threads(me.pid) {
            if me.is(v.task) {
                continue;
            }
            let mut ts = v.task.sig.lock();
            if ts.jobctl & STOPPED == 0 && set_pending(v.task, &mut ts, signr.nr() | gstop) {
                g.count += 1;
                if !seized(&v) {
                    signal_wake_up(v.task, &mut ts, false);
                } else {
                    trap_notify(v.task, &mut ts);
                }
            }
        }
        s = me.sig.lock();
    }
    if traced {
        // Traced: the stop is reported in a ptrace trap
        set_pending(&me, &mut s, TRAP_STOP);
        me.set_sigpending(true);
        return false;
    }
    let notify = participate(&mut g, &mut s);
    s.jobctl |= STOPPED;
    set_current_state(SleepState::Killable);
    drop(s);
    drop(g);
    if notify {
        super::notify::notify_parent_cldstop(&table, &me, false, Why::Stopped);
    }
    drop(table);
    drop(sig_struct);
    // Until SIGCONT, SIGKILL or a tracer's attach clears STOPPED
    loop {
        set_current_state(SleepState::Killable);
        if me.sig.lock().jobctl & STOPPED == 0 {
            break;
        }
        crate::task::percpu::schedule();
    }
    set_current_state(SleepState::Running);
    true
}

/// A ptrace trap for a job-control event (Linux do_jobctl_trap): a
/// seized tracee stops with PTRACE_EVENT_STOP (SIGTRAP once the stop is
/// over), another as for the stop signal
pub fn do_jobctl_trap() {
    use crate::task::ptrace::{PT_SEIZED, PTRACE_EVENT_STOP};
    let me = crate::task::percpu::current();
    let Some(sig_struct) = me.cpu_group().cloned() else {
        return;
    };
    let seized = {
        let table = crate::task::percpu::TASKLIST.read();
        table.view(&me).is_some_and(|v| v.ptrace() & PT_SEIZED != 0)
    };
    let mut signr = me.sig.lock().jobctl & STOP_SIGMASK;
    if seized {
        let g = sig_struct.jobctl.lock();
        if g.count == 0 && g.flags & flags::STOP_STOPPED == 0 {
            signr = SIGTRAP.nr();
        }
        drop(g);
        crate::task::ptrace::ptrace_do_notify(
            signr,
            signr | (PTRACE_EVENT_STOP << 8),
            Why::Stopped,
        );
    } else {
        crate::task::ptrace::ptrace_stop_why(signr, Why::Stopped, None);
    }
}

/// [`crate::task::ptrace::ptrace_stop`]'s group part, TASKLIST held and
/// the group lock `g`: a group-stop trap (`why` Stopped) takes its part
/// in the stop; any trap clears a pending STOP trap, a
/// PTRACE_EVENT_STOP one a NOTIFY too, and TRAPPING. True if it
/// completed the group stop.
pub fn trap_locked(g: &mut Group<'_>, s: &mut TaskSignalState, why: Why, event_stop: bool) -> bool {
    let done = why == Why::Stopped && s.jobctl & STOP_PENDING != 0 && participate(g, s);
    clear_pending(s, TRAP_STOP);
    if event_stop {
        clear_pending(s, TRAP_NOTIFY);
    }
    clear_trapping(s);
    done
}

/// The parent's notice SIGCONT or a stop left to the first thread out
/// (Linux get_signal's SIGNAL_CLD_MASK check), each pass of the signal
/// work: CLD_CONTINUED (or CLD_STOPPED for a stop it cut short) to the
/// real parent, and to the leader's tracer if it is another process
pub fn notify_cld() {
    let me = crate::task::percpu::current();
    let Some(sig_struct) = me.cpu_group().cloned() else {
        return;
    };
    let why = {
        let mut g = sig_struct.jobctl.lock();
        if g.flags & flags::CLD_MASK == 0 {
            return;
        }
        let why = if g.flags & flags::CLD_CONTINUED != 0 {
            Why::Continued
        } else {
            Why::Stopped
        };
        g.flags &= !flags::CLD_MASK;
        why
    };
    let table = crate::task::percpu::TASKLIST.read();
    super::notify::notify_parent_cldstop(&table, &me, false, why);
    if let Some(l) = table.get(me.pid)
        && l.ptrace() != 0
        && l.tracer().is_some_and(|tr| tr.pid != l.task.ppid())
    {
        let leader = crate::task::percpu::task_ref(l.task);
        super::notify::notify_parent_cldstop(&table, &leader, true, why);
    }
}

/// The current thread starts its exit with PF_EXITING (Linux
/// exit_signals) under its group lock and Task.sig: a group stop it was
/// to join counts it as stopped, and one it completes is told to the
/// parent
pub fn exit_participate() {
    let me = crate::task::percpu::current();
    let Some(sig_struct) = me.cpu_group().cloned() else {
        me.set_flag(crate::task::pf::EXITING);
        return;
    };
    let table = crate::task::percpu::TASKLIST.read();
    let notify = {
        let mut g = sig_struct.jobctl.lock();
        let mut s = me.sig.lock();
        me.set_flag(crate::task::pf::EXITING);
        s.jobctl & STOP_PENDING != 0 && participate(&mut g, &mut s)
    };
    if notify {
        super::notify::notify_parent_cldstop(&table, &me, false, Why::Stopped);
    }
}

/// The wait report of group `s`'s completed stop (Linux
/// wait_task_stopped without ptrace): its signal, taken unless
/// `wnowait`; None if there is none to report
pub fn take_stopped(s: &SignalStruct, wnowait: bool) -> Option<u32> {
    let mut g = s.jobctl.lock();
    if g.flags & flags::STOP_STOPPED == 0 || g.code == 0 {
        return None;
    }
    let code = g.code;
    if !wnowait {
        g.code = 0;
    }
    Some(code)
}

/// Group `s` was continued since a wait last said so (Linux
/// wait_task_continued): taken unless `wnowait`
pub fn take_continued(s: &SignalStruct, wnowait: bool) -> bool {
    let mut g = s.jobctl.lock();
    if g.flags & flags::STOP_CONTINUED == 0 {
        return false;
    }
    if !wnowait {
        g.flags &= !flags::STOP_CONTINUED;
    }
    true
}

/// The group's stop signal, for a CLD_STOPPED notice
pub fn stop_code(s: &SignalStruct) -> u32 {
    s.jobctl.lock().code
}

/// A tracer attaches to `t` (Linux ptrace_attach), TASKLIST held for
/// writing: if it is in a group stop it leaves it for a STOP trap
/// (TRAPPING until the trap is entered, which the attach waits for)
pub fn attach_stopped(t: &Task) {
    let Some(sig_struct) = t.cpu_group() else {
        return;
    };
    let _g = sig_struct.jobctl.lock();
    let mut s = t.sig.lock();
    if s.jobctl & STOPPED != 0 && set_pending(t, &mut s, TRAP_STOP | TRAPPING) {
        s.jobctl &= !STOPPED;
        t.set_sigpending(true);
        crate::task::percpu::try_to_wake_up(t, WakeMode::Any);
    }
}

/// `t` is in the middle of an attach's re-trap (JOBCTL_TRAPPING)
pub fn trapping(t: &Task) -> bool {
    t.sig.lock().jobctl & TRAPPING != 0
}

/// `t` loses its tracer (Linux __ptrace_unlink), TASKLIST held for
/// writing: pending traps go, a group stop in effect is pending again
/// for it unless it is exiting, and it is woken out of a ptrace stop or
/// to stop for the group, its stop's code left alone
pub fn unlink(t: &Task) {
    let sig_struct = t.cpu_group().cloned();
    let g = sig_struct.as_ref().map(|s| s.jobctl.lock());
    let mut s = t.sig.lock();
    s.jobctl &= !PTRACE_FROZEN;
    clear_pending(&mut s, TRAP_MASK);
    clear_trapping(&mut s);
    let in_stop = g
        .as_ref()
        .is_some_and(|g| g.flags & flags::STOP_STOPPED != 0 || g.count != 0);
    if !t.has_flag(crate::task::pf::EXITING) && in_stop {
        s.jobctl |= STOP_PENDING;
    }
    if s.jobctl & STOP_PENDING != 0 || s.traced() {
        // Linux ptrace_signal_wake_up(child, true)
        t.set_sigpending(true);
        let mode = if s.traced() {
            s.jobctl &= !TRACED;
            WakeMode::Any
        } else {
            WakeMode::Interruptible
        };
        super::signal_wake_task(t, mode);
    }
}

/// The current thread has a job-control step to take before dequeuing
/// (Linux get_signal: JOBCTL_STOP_PENDING, then JOBCTL_TRAP_MASK): done
/// here; true if the signal work is to look again
pub fn pending_step() -> bool {
    let me = crate::task::percpu::current();
    let (j, killed) = {
        let s = me.sig.lock();
        (s.jobctl, s.pending.signal.contains(super::SIGKILL))
    };
    // A fatal signal comes first (its dequeue ends the task)
    if killed {
        return false;
    }
    if j & STOP_PENDING != 0 && do_signal_stop(None) {
        return true;
    }
    if me.sig.lock().jobctl & TRAP_MASK != 0 {
        do_jobctl_trap();
        return true;
    }
    false
}

/// Whether a stop signal's default action applies (Linux get_signal):
/// SIGTSTP, SIGTTIN and SIGTTOU do nothing in an orphaned process group
pub fn stop_applies(sig: Signal) -> bool {
    if sig == SIGSTOP {
        return true;
    }
    let me = crate::task::percpu::current();
    let pg = crate::task::percpu::TASKLIST
        .read()
        .view(&me)
        .and_then(|v| v.pgrp().cloned());
    pg.is_none_or(|pg| !crate::task::percpu::pgrp_orphaned(&pg))
}

/// New thread `child` of `parent`'s group joins its group stop, in
/// progress (counted) or completed (Linux task_join_group_stop), under
/// TASKLIST's write lock (the clone's insert)
pub fn join_group_stop(parent: &Task, child: &Task) {
    let Some(sig_struct) = parent.cpu_group() else {
        return;
    };
    let mut g = sig_struct.jobctl.lock();
    let mut mask = parent.sig.lock().jobctl & STOP_SIGMASK;
    if g.count != 0 {
        g.count += 1;
        mask |= STOP_CONSUME;
    } else if g.flags & flags::STOP_STOPPED == 0 {
        return;
    }
    let mut s = child.sig.lock();
    set_pending(child, &mut s, mask | STOP_PENDING);
    child.set_sigpending(s.has_deliverable_signals());
}
