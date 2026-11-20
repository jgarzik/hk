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
//! trap instead (JOBCTL_TRAP_STOP); a seized one reports a later change
//! in another trap (JOBCTL_TRAP_NOTIFY), at once if its tracer listens
//! (PTRACE_LISTEN, JOBCTL_LISTENING), else once it is resumed.
//!
//! Locking (doc/LOCKING.md 3.7): the group state is under
//! `SignalStruct.jobctl` (Linux siglock's group part), taken after
//! TASKLIST and the group's siglock (when held: a send, do_signal_stop,
//! which walk the thread list under it) and before any thread's
//! `Task.sig`, which holds the thread's own bits
//! (`TaskSignalState::jobctl`); a stop bit of a thread is changed with
//! both held.

use super::jobctl::*;
use super::{
    SIGCONT, SIGSTOP, SIGTRAP, SigGuard, SigPending, SigSet, Signal, SignalStruct, TaskSignalState,
    sig_of,
};
use crate::task::Task;
use crate::task::percpu::WakeMode;

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

type Group<'a> = crate::sync::InstanceRefMut<'a, GroupStop>;

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
/// task_clear_jobctl_trapping: wake_up_bit)
pub fn clear_trapping(s: &mut TaskSignalState) {
    if s.jobctl & TRAPPING != 0 {
        s.jobctl &= !TRAPPING;
        trapping_wq(s).wake_all();
    }
}

/// The queue an attach waits on for `s`'s TRAPPING to clear (Linux
/// bit_waitqueue(&task->jobctl, JOBCTL_TRAPPING_BIT)): the shared
/// variable queue its jobctl word hashes to
pub fn trapping_wq(s: &TaskSignalState) -> &'static crate::sync::waitqueue::WaitQueue {
    crate::sync::waitqueue::var_waitqueue(core::ptr::addr_of!(s.jobctl) as usize)
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

/// A tracee has a trap or the end of its tracer to act on (Linux
/// ptrace_signal_wake_up), its Task.sig held: TIF_SIGPENDING set and
/// `t` woken from an interruptible sleep; `resume` also ends a ptrace
/// stop it is in, woken there, its code left alone
pub fn ptrace_signal_wake_up(t: &Task, s: &mut TaskSignalState, resume: bool) {
    t.set_sigpending(true);
    let mode = if resume && s.traced() {
        s.jobctl &= !TRACED;
        WakeMode::Any
    } else {
        WakeMode::Interruptible
    };
    super::signal_wake_task(t, mode);
}

/// A seized tracee is to report a job-control change in a trap (Linux
/// ptrace_trap_notify), its Task.sig held: a PTRACE_EVENT_STOP trap its
/// tracer listens in (PTRACE_LISTEN) ends for it, any other ptrace stop
/// is left alone and the trap waits for its resume
fn trap_notify(t: &Task, s: &mut TaskSignalState) {
    set_pending(t, s, TRAP_NOTIFY);
    let listening = s.jobctl & LISTENING != 0;
    ptrace_signal_wake_up(t, s, listening);
}

/// `t`'s jobctl bits, read under its siglock (0 once released)
fn jobctl_of(t: &Task) -> u32 {
    let rcu = crate::sync::rcu::read_lock();
    super::lock_task_sighand(t, &rcu).map_or(0, |g| sig_of(t, &g).jobctl)
}

/// `t` is traced with PTRACE_SEIZE (a racy read, Linux t->ptrace &
/// PT_SEIZED under siglock)
fn seized(t: &Task) -> bool {
    t.ptrace() & crate::task::ptrace::PT_SEIZED != 0
}

/// The process-wide effects of a stop signal or SIGCONT sent to the
/// group `sig_struct` whose state `j` is (Linux prepare_signal), its
/// threads walked under its table's siglock `g`: a stop signal drops
/// every pending SIGCONT;
/// SIGCONT drops every pending stop signal, ends the group stop,
/// continues stopped threads and leaves the parent's notice to the
/// first of them. The signal itself is then queued (or ignored) as any
/// other.
pub fn prepare(
    g: &SigGuard<'_>,
    sig_struct: &SignalStruct,
    j: &mut Group<'_>,
    sig: Signal,
    gone: &mut SigPending,
) {
    let stop = sig.kernel_stop();
    let flush = if stop {
        SigSet::of(SIGCONT)
    } else {
        super::STOP_SIGNALS
    };
    for t in sig_struct.threads(g) {
        let mut s = sig_of(t, g);
        s.pending.flush_mask_into(&flush, gone);
        if !stop {
            clear_pending(&mut s, STOP_PENDING);
            if !seized(t) {
                if s.jobctl & STOPPED != 0 {
                    s.jobctl &= !STOPPED;
                    crate::task::percpu::try_to_wake_up(t, WakeMode::Any);
                }
            } else {
                trap_notify(t, &mut s);
            }
        }
        super::recalc_sigpending_tsk(g, t, &s);
    }
    sig_struct.shared(g).flush_mask_into(&flush, gone);
    if !stop {
        // Stopped: CLD_CONTINUED; in the middle of a stop: as if it had
        // completed and the continue's notice were lost (Linux)
        let why = if j.flags & flags::STOP_STOPPED != 0 {
            flags::CLD_CONTINUED
        } else if j.count != 0 {
            flags::CLD_STOPPED
        } else {
            0
        };
        if why != 0 {
            j.set_stop_flags(why | flags::STOP_CONTINUED);
            j.count = 0;
            j.code = 0;
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
    let table = crate::task::tasklist::TASKLIST.read();
    let Some(mv) = table.view(&me) else {
        return false;
    };
    let traced = mv.ptrace() != 0;
    // The thread walk under the group's siglock (Linux do_signal_stop
    // under siglock), TASKLIST read for the ptrace flags
    let Some(h) = me.sighand.protected(&table) else {
        return false;
    };
    let sg = SigGuard::lock(h);
    let mut g = sig_struct.jobctl(&sg);
    let mut s = sig_of(&me, &sg);
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
        for t in sig_struct.threads(&sg) {
            if me.is(t) {
                continue;
            }
            let mut ts = sig_of(t, &sg);
            if ts.jobctl & STOPPED == 0 && set_pending(t, &mut ts, signr.nr() | gstop) {
                g.count += 1;
                if !seized(t) {
                    signal_wake_up(t, &mut ts, false);
                } else {
                    trap_notify(t, &mut ts);
                }
            }
        }
        s = sig_of(&me, &sg);
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
    // Dropped before the parent's notice, which takes its siglock
    drop(sg);
    if notify {
        super::notify::notify_parent_cldstop(&table, &me, false, Why::Stopped);
    }
    drop(table);
    drop(sig_struct);
    // Until SIGCONT, SIGKILL or a tracer's attach clears STOPPED
    loop {
        set_current_state(SleepState::Killable);
        if jobctl_of(&me) & STOPPED == 0 {
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
        let table = crate::task::tasklist::TASKLIST.read();
        table.view(&me).is_some_and(|v| v.ptrace() & PT_SEIZED != 0)
    };
    let rcu = crate::sync::rcu::read_lock();
    let Some(sg) = super::lock_task_sighand(&me, &rcu) else {
        return;
    };
    let mut signr = sig_of(&me, &sg).jobctl & STOP_SIGMASK;
    if seized {
        let g = sig_struct.jobctl(&sg);
        if g.count == 0 && g.flags & flags::STOP_STOPPED == 0 {
            signr = SIGTRAP.nr();
        }
    }
    drop(sg);
    drop(rcu);
    if seized {
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
    // The task's own reference: nothing is cloned on the common pass
    // with no notice due (Linux tests signal->flags under the siglock
    // get_signal holds)
    let Some(sig_struct) = me.cpu_group() else {
        return;
    };
    let why = {
        let rcu = crate::sync::rcu::read_lock();
        let Some(sg) = super::lock_task_sighand(&me, &rcu) else {
            return;
        };
        let mut g = sig_struct.jobctl(&sg);
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
    let table = crate::task::tasklist::TASKLIST.read();
    super::notify::notify_parent_cldstop(&table, &me, false, why);
    if let Some(l) = table.get(me.pid)
        && l.ptrace() != 0
        && l.tracer().is_some_and(|tr| tr.pid != l.ppid())
    {
        let leader = crate::task::tasklist::task_ref(l.task);
        super::notify::notify_parent_cldstop(&table, &leader, true, why);
    }
}

/// The current thread starts its exit with PF_EXITING (Linux
/// exit_signals) under its group lock and Task.sig: its private pending
/// signals go (sigqueue_dequeue_pending: nothing is queued for it once
/// PF_EXITING is set, `drops`), freed after the locks; a group stop it
/// was to join counts it as stopped, and one it completes is told to
/// the parent
pub fn exit_participate() {
    let me = crate::task::percpu::current();
    let table = crate::task::tasklist::TASKLIST.read();
    let Some(sg) = super::lock_sighand_in(&me, &table) else {
        me.set_flag(crate::task::pf::EXITING);
        return;
    };
    let (notify, gone) = {
        let mut g = me.cpu_group().map(|s| s.jobctl(&sg));
        let mut s = sig_of(&me, &sg);
        me.set_flag(crate::task::pf::EXITING);
        let gone = core::mem::take(&mut s.pending);
        let notify =
            s.jobctl & STOP_PENDING != 0 && g.as_mut().is_some_and(|g| participate(g, &mut s));
        (notify, gone)
    };
    // Dropped before the parent's notice, which takes its siglock
    drop(sg);
    if notify {
        super::notify::notify_parent_cldstop(&table, &me, false, Why::Stopped);
    }
    drop(table);
    drop(gone);
}

/// The wait report of group `s`'s completed stop (Linux
/// wait_task_stopped without ptrace), under its table's siglock `sg`:
/// its signal, taken unless `wnowait`; None if there is none to report
pub fn take_stopped(sg: &SigGuard<'_>, s: &SignalStruct, wnowait: bool) -> Option<u32> {
    let mut g = s.jobctl(sg);
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
/// wait_task_continued), under its table's siglock `sg`: taken unless
/// `wnowait`
pub fn take_continued(sg: &SigGuard<'_>, s: &SignalStruct, wnowait: bool) -> bool {
    let mut g = s.jobctl(sg);
    if g.flags & flags::STOP_CONTINUED == 0 {
        return false;
    }
    if !wnowait {
        g.flags &= !flags::STOP_CONTINUED;
    }
    true
}

/// The group's stop signal, for a CLD_STOPPED notice, under its
/// table's siglock `sg`
pub fn stop_code(sg: &SigGuard<'_>, s: &SignalStruct) -> u32 {
    s.jobctl(sg).code
}

/// A tracer attaches to `t` (Linux ptrace_attach), TASKLIST held for
/// writing: if it is in a group stop it leaves it for a STOP trap
/// (TRAPPING until the trap is entered, which the attach waits for)
pub fn attach_stopped(t: &Task) {
    let Some(sig_struct) = t.cpu_group() else {
        return;
    };
    let rcu = crate::sync::rcu::read_lock();
    let Some(sg) = super::lock_task_sighand(t, &rcu) else {
        return;
    };
    let _g = sig_struct.jobctl(&sg);
    let mut s = sig_of(t, &sg);
    if s.jobctl & STOPPED != 0 && set_pending(t, &mut s, TRAP_STOP | TRAPPING) {
        s.jobctl &= !STOPPED;
        t.set_sigpending(true);
        crate::task::percpu::try_to_wake_up(t, WakeMode::Any);
    }
}

/// A new child traced from its fork (Linux ptrace_init_task, under
/// tasklist_lock, before it first runs): a seized tracer's gets a STOP
/// trap pending, an attached one's SIGSTOP pending, so it stops before
/// its first instruction
pub fn ptrace_init_child(t: &Task, seized: bool) {
    let Some(sig_struct) = t.cpu_group() else {
        return;
    };
    let rcu = crate::sync::rcu::read_lock();
    let Some(sg) = super::lock_task_sighand(t, &rcu) else {
        return;
    };
    let _g = sig_struct.jobctl(&sg);
    let mut s = sig_of(t, &sg);
    if seized {
        set_pending(t, &mut s, TRAP_STOP);
    } else {
        s.pending.signal.add(super::SIGSTOP);
    }
    t.set_sigpending(true);
}

/// `t` is in the middle of an attach's re-trap (JOBCTL_TRAPPING)
pub fn trapping(t: &Task) -> bool {
    jobctl_of(t) & TRAPPING != 0
}

/// `t` loses its tracer (Linux __ptrace_unlink), TASKLIST held for
/// writing: pending traps go, a group stop in effect is pending again
/// for it unless it is exiting, and it is woken out of a ptrace stop or
/// to stop for the group, its stop's code left alone
pub fn unlink(t: &Task) {
    let rcu = crate::sync::rcu::read_lock();
    let Some(sg) = super::lock_task_sighand(t, &rcu) else {
        return;
    };
    let sig_struct = t.cpu_group().cloned();
    let g = sig_struct.as_ref().map(|s| s.jobctl(&sg));
    let mut s = sig_of(t, &sg);
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
        ptrace_signal_wake_up(t, &mut s, true);
    }
}

/// The current thread has a job-control step to take before dequeuing
/// (Linux get_signal: JOBCTL_STOP_PENDING, then JOBCTL_TRAP_MASK): done
/// here; true if the signal work is to look again
pub fn pending_step() -> bool {
    let me = crate::task::percpu::current();
    let rcu = crate::sync::rcu::read_lock();
    let Some((j, killed)) = super::lock_task_sighand(&me, &rcu).map(|g| {
        let s = sig_of(&me, &g);
        (s.jobctl, s.pending.signal.contains(super::SIGKILL))
    }) else {
        return false;
    };
    drop(rcu);
    // A fatal signal comes first (its dequeue ends the task)
    if killed {
        return false;
    }
    if j & STOP_PENDING != 0 && do_signal_stop(None) {
        return true;
    }
    if jobctl_of(&me) & TRAP_MASK != 0 {
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
    let pg = me
        .cpu_group()
        .and_then(|s| s.pgrp.get(&crate::sync::rcu::read_lock()));
    pg.is_none_or(|pg| !crate::task::pgrp::pgrp_orphaned(&pg))
}

/// New thread `child` of `parent`'s group joins its group stop, in
/// progress (counted) or completed (Linux task_join_group_stop), under
/// TASKLIST's write lock (the clone's insert)
pub fn join_group_stop(parent: &Task, child: &Task) {
    let Some(sig_struct) = parent.cpu_group() else {
        return;
    };
    // One table: CLONE_THREAD shares it
    let rcu = crate::sync::rcu::read_lock();
    let Some(sg) = super::lock_task_sighand(parent, &rcu) else {
        return;
    };
    let mut g = sig_struct.jobctl(&sg);
    let mut mask = sig_of(parent, &sg).jobctl & STOP_SIGMASK;
    if g.count != 0 {
        g.count += 1;
        mask |= STOP_CONSUME;
    } else if g.flags & flags::STOP_STOPPED == 0 {
        return;
    }
    let mut s = sig_of(child, &sg);
    set_pending(child, &mut s, mask | STOP_PENDING);
    super::recalc_sigpending_tsk(&sg, child, &s);
}
