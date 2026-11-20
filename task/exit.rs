//! Process exit and wait (Linux kernel/exit.c): exit_current and the
//! reparenting, notification and release of a dying task, and the
//! wait family's zombie, stop and continue reports.

use super::fork::{do_clear_child_tid, signal_vfork_done};
use super::percpu::{
    Times, current, current_pgid, current_pid, current_pid_ns, current_tid, do_task_dead,
    rusage_both,
};
use super::tasklist::{GlobalTaskTable, TASKLIST, TaskRef, TaskView, task_ref};
use crate::signal::notify::{Told, Zombie, notify};
use crate::task::{Pid, Task, TaskState, Tid};
use alloc::sync::Arc;
use alloc::vec::Vec;

/// A thread of group `tgid` other than those in `but` will still
/// report its leader when it leaves (Linux thread_group_empty is
/// false): any listed thread, a traced zombie too until its tracer
/// releases it
pub fn group_pending(table: &GlobalTaskTable, tgid: Pid, but: &[Tid]) -> bool {
    table.threads(tgid).any(|u| !but.contains(&u.task.tid()))
}

/// Reap a zombie child of the given parent
///
/// # Arguments
/// * `parent_pid` - PID of the parent process
/// * `target_pid` - Which child to wait for:
///   - > 0: wait for specific child PID
///   - -1: wait for any child
///   - 0: wait for any child in same process group (not implemented)
///
/// # Returns
/// * Some((child_pid, exit_status)) if a zombie child was found and reaped
/// * None if no zombie child matches
pub fn reap_zombie_child(parent_pid: Pid, target_pid: i64, wflags: i32) -> Option<(Pid, i32)> {
    reap_zombie_child_times(parent_pid, target_pid, wflags).map(|(pid, status, _, _)| (pid, status))
}

/// Whether `child`'s exit_signal makes it eligible under `wflags`
/// (Linux kernel/exit.c eligible_child): __WALL waits for all children;
/// otherwise "clone" children (exit_signal != SIGCHLD) are waited for only
/// with __WCLONE, and normal children only without it.
fn wait_eligible(exit_signal: crate::signal::ExitSignal, wflags: i32) -> bool {
    use super::wait_options::{__WALL, __WCLONE};
    if wflags & __WALL != 0 {
        return true;
    }
    let is_clone = exit_signal != crate::signal::ExitSignal::SIGCHLD;
    is_clone == (wflags & __WCLONE != 0)
}

/// Like [`reap_zombie_child`], but also returns the reaped child's CPU times
/// as `(pid, exit_status, utime_ns, stime_ns)` (for wait rusage reporting).
pub fn reap_zombie_child_times(
    parent_pid: Pid,
    target_pid: i64,
    wflags: i32,
) -> Option<(Pid, i32, u64, u64)> {
    let (report, done) = {
        let mut table = TASKLIST.write();
        let w = Wait {
            parent_pid,
            target_pid,
            wflags,
            pgid: current_pgid(),
            ns: crate::task::pid::current_pid_ns(),
        };
        wait_zombie(&mut table, &w)?
    };
    done.finish();
    Some(report)
}

/// A reaped zombie's tid (a leader's: its pid; reported in the
/// waiter's namespace), wait status, user and system time
type WaitReport = (Pid, i32, u64, u64);

/// What a wait4/waitid asks for: the waiting process, wait4's pid,
/// the flags, the caller's process group
struct Wait {
    parent_pid: Pid,
    target_pid: i64,
    wflags: i32,
    pgid: Pid,
    /// The waiter's pid namespace, which numbers the report
    ns: &'static crate::ns::PidNamespace,
}

/// Zombie `t` is one `w` reaps (Linux wait_consider_task): never a
/// leader with threads left (delay_group_leader); its tracer any task
/// it traces, __WCLONE or not (eligible_child: traced by us); its real
/// parent an untraced leader by the __WALL/__WCLONE rule (a zombie
/// ptracee is visible only to its ptracer)
fn reapable(table: &GlobalTaskTable, t: &TaskView<'_>, w: &Wait) -> bool {
    if !matches!(t.state, TaskState::Zombie(_)) || !wait_match(t, w.target_pid, w.pgid) {
        return false;
    }
    if t.leader && group_pending(table, t.task.pid, &[t.task.tid()]) {
        return false;
    }
    if tracee_of(t, w.parent_pid) {
        return true;
    }
    t.leader
        && t.task.ptrace() == 0
        && t.ppid() == w.parent_pid
        && wait_eligible(t.exit_signal, w.wflags)
}

/// How [`wait_zombie`] releases the zombie it reaps
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reap {
    /// A traced thread (Linux EXIT_DEAD, release_task)
    Thread,
    /// A leader traced from outside its real parent's process: its
    /// tracer is done, its real parent told (Linux EXIT_TRACE)
    Traced,
    /// A leader its real parent's process reaps (Linux EXIT_DEAD)
    Child,
}

/// [`Reap`] of zombie `z`
fn reap_kind(z: &TaskView<'_>) -> Reap {
    if !z.leader {
        Reap::Thread
    } else if ptrace_reparented(z) {
        Reap::Traced
    } else {
        Reap::Child
    }
}

/// `t` is traced by a task outside its real parent's process (Linux
/// ptrace_reparented)
fn ptrace_reparented(t: &TaskView<'_>) -> bool {
    t.tracer().is_some_and(|tr| tr.pid != t.ppid())
}

/// [`reap_zombie_child_times`]'s TASKLIST write section: the zombie
/// `w` finds is reported and, unless WNOWAIT, released, a traced
/// thread as by [`unhash_thread`]
fn wait_zombie(table: &mut GlobalTaskTable, w: &Wait) -> Option<(WaitReport, Unhashed)> {
    let found = {
        let tb: &GlobalTaskTable = table;
        tb.find(|t| reapable(tb, t, w))
            .map(|z| (zombie_report(tb, &z), reap_kind(&z)))
    };
    let (report, kind) = found?;
    // Numbered for the waiter while the zombie is still listed (Linux
    // wait_task_zombie: task_pid_vnr)
    let tid = report.0;
    let report = (
        Pid::from(crate::task::pid::nr_ns(tid, w.ns)),
        report.1,
        report.2,
        report.3,
    );
    // WNOWAIT (waitid): report the zombie, leave it waitable
    if w.wflags & super::wait_options::WNOWAIT != 0 {
        return Some((report, Unhashed::default()));
    }
    if kind == Reap::Traced {
        // Its real parent is told now, as if it had never been traced
        // (Linux wait_task_zombie: EXIT_TRACE, ptrace_unlink,
        // do_notify_parent); the tracer's process gets no child times
        let z = Zombie::Detached(tid);
        if let Some(mut v) = table.get_mut(tid) {
            crate::task::ptrace::ptrace_unlink(&mut v);
        }
        let (told, gone) = tell(table, Some(z));
        let done = Unhashed {
            thread: None,
            told,
            gone,
        };
        return Some((report, done));
    }
    if kind == Reap::Thread {
        // A traced thread: its tracer releases it (Linux
        // wait_task_zombie: EXIT_DEAD, then release_task)
        let z = table
            .get(tid)
            .and_then(|t| thread_teller(table, t.task.pid, tid));
        return Some((report, unhash_thread(table, tid, z)));
    }
    // The reaper's cutime/cstime
    if let Some(s) = current().cpu_group().cloned() {
        s.add_child_times((report.2, report.3));
    }
    let gone = reap_locked(table, tid);
    Some((
        report,
        Unhashed {
            gone,
            ..Unhashed::default()
        },
    ))
}

/// Zombie `z`'s wait report `(tid, status, utime, stime)`: a leader's
/// time is its group's (every thread gone) and its children's (wait's
/// rusage, Linux RUSAGE_BOTH); a thread's its own
fn zombie_report(table: &GlobalTaskTable, z: &TaskView<'_>) -> WaitReport {
    let own = match z.state {
        TaskState::Zombie(s) => s,
        _ => 0,
    };
    // Linux wait_task_zombie: thread_group_cputime_adjusted
    let (mut utime, mut stime) = if z.leader {
        crate::task::cputime::thread_group_cputime_adjusted(table, z.task.pid)
    } else {
        crate::task::cputime::task_cputime_adjusted(z.task)
    };
    if z.leader
        && let Some(s) = z.signal()
    {
        let (cu, cs) = s.child_times();
        utime = utime.saturating_add(cu);
        stime = stime.saturating_add(cs);
    }
    (z.task.tid(), group_status(z, own), utime, stime)
}

/// The wait status a zombie leader reports (Linux wait_task_zombie):
/// the group's exit status after a group exit, else its own
fn group_status(t: &TaskView<'_>, own: i32) -> i32 {
    match t.signal().map(|s| s.group_exit()) {
        Some(crate::signal::GroupExit::Exit(code)) => code,
        _ => own,
    }
}

/// A ptrace stop of a task traced by the group `tracer_pid`, matching
/// `target_pid` (wait4's pid: > 0 that tid, -1 any, 0 the caller's
/// process group, < -1 that group), not yet reported: its tid (as the
/// caller numbers it) and the stop's code. Reported once unless
/// `wnowait` (Linux wait_task_stopped with ptrace: exit_code cleared
/// under siglock), with its process's CPU time ([`rusage_both`]). The
/// tracees are walked under the read lock, each stop read and its code
/// taken under the tracee's siglock.
pub fn wait_traced(tracer_pid: Pid, target_pid: i64, wnowait: bool) -> Option<(Tid, u32, Times)> {
    let table = TASKLIST.read();
    let pgid = current_pgid();
    let (tid, pid, code) = table.iter().find_map(|t| {
        if !(tracee_of(&t, tracer_pid) && wait_match(&t, target_pid, pgid)) {
            return None;
        }
        let g = crate::signal::lock_sighand_in(t.task, &table)?;
        let mut s = crate::signal::sig_of(t.task, &g);
        // Not one its tracer listens in (Linux task_stopped_code:
        // JOBCTL_LISTENING)
        if !s.traced() || s.jobctl & crate::signal::jobctl::LISTENING != 0 || s.ptrace_code == 0 {
            return None;
        }
        let code = s.ptrace_code;
        if !wnowait {
            s.ptrace_code = 0;
        }
        Some((t.task.tid(), t.task.pid, code))
    })?;
    let times = rusage_both(&table, pid);
    // The tracee as the tracer numbers it (Linux wait_task_stopped:
    // task_pid_vnr)
    Some((
        Tid::from(crate::task::pid::nr_ns(tid, current_pid_ns())),
        code,
        times,
    ))
}

/// A job-control change a wait reports (Linux wait_task_stopped
/// without ptrace, wait_task_continued)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobReport {
    /// The group stop completed, with this signal
    Stopped(u32),
    /// SIGCONT continued it
    Continued,
}

/// A child of the group `parent_pid` (or a task it traces, for
/// WCONTINUED) matching `target_pid`, stopped (WUNTRACED/WSTOPPED in
/// `wflags`) or continued (WCONTINUED) since a wait last reported it:
/// its tid as the caller numbers it, the report and its real uid; the
/// report taken unless WNOWAIT (Linux wait_consider_task: a child its
/// own process traces shows its ptrace stops instead of the group's; a
/// reapable zombie none), with its process's CPU time
/// ([`rusage_both`]). The tasks are walked under TASKLIST's read lock,
/// each group's state read under its `SignalStruct.jobctl`.
pub fn wait_jobctl(
    parent_pid: Pid,
    target_pid: i64,
    wflags: i32,
) -> Option<(Tid, JobReport, u32, Times)> {
    use super::wait_options::{WCONTINUED, WNOWAIT, WUNTRACED};
    if wflags & (WUNTRACED | WCONTINUED) == 0 {
        return None;
    }
    let wnowait = wflags & WNOWAIT != 0;
    let table = TASKLIST.read();
    let pgid = current_pgid();
    let (tid, pid, r, uid) = table.iter().find_map(|t| {
        let child = t.leader && t.ppid() == parent_pid && wait_eligible(t.exit_signal, wflags);
        let traced = tracee_of(&t, parent_pid);
        if !(child || traced) || !wait_match(&t, target_pid, pgid) {
            return None;
        }
        if matches!(t.state, TaskState::Zombie(_))
            && !group_pending(&table, t.task.pid, &[t.task.tid()])
        {
            return None;
        }
        let s = t.signal()?;
        let uid = t.cred_arc().uid;
        // Under its siglock (Linux wait_task_stopped/continued)
        let g = crate::signal::lock_sighand_in(t.task, &table)?;
        if child
            && !traced
            && wflags & WUNTRACED != 0
            && let Some(code) = crate::signal::stop::take_stopped(&g, s, wnowait)
        {
            return Some((t.task.tid(), t.task.pid, JobReport::Stopped(code), uid));
        }
        (wflags & WCONTINUED != 0 && crate::signal::stop::take_continued(&g, s, wnowait))
            .then(|| (t.task.tid(), t.task.pid, JobReport::Continued, uid))
    })?;
    let times = rusage_both(&table, pid);
    Some((
        Tid::from(crate::task::pid::nr_ns(tid, current_pid_ns())),
        r,
        uid,
        times,
    ))
}

/// `t` is what wait4's `target_pid` names (`pgid`: the caller's group)
fn wait_match(t: &TaskView<'_>, target_pid: i64, pgid: Pid) -> bool {
    match target_pid {
        -1 => true,
        0 => t.pgid() == pgid,
        p if p < -1 => t.pgid() == p.unsigned_abs(),
        p => t.task.tid() == p as u64,
    }
}

/// `t` is traced by a thread of group `tracer_pid`
fn tracee_of(t: &TaskView<'_>, tracer_pid: Pid) -> bool {
    t.task.ptrace() != 0 && t.tracer().is_some_and(|tr| tr.pid == tracer_pid)
}

/// The group `tracer_pid` traces a task matching `target_pid` (so a
/// wait for it is not ECHILD)
pub fn has_tracees(tracer_pid: Pid, target_pid: i64) -> bool {
    let table = TASKLIST.read();
    let pgid = current_pgid();
    table
        .iter()
        .any(|t| tracee_of(&t, tracer_pid) && wait_match(&t, target_pid, pgid))
}

/// Check if a process has any children matching the criteria
///
/// # Arguments
/// * `parent_pid` - PID of the parent process
/// * `target_pid` - Which children to check for:
///   - > 0: check for specific child PID
///   - -1: check for any child
///   - 0: check for any child in same process group
pub fn has_children(parent_pid: Pid, target_pid: i64, wflags: i32) -> bool {
    let table = TASKLIST.read();
    let pgid = current_pgid();

    table.iter().any(|t| {
        // Must be a child of the parent (a thread-group leader)
        if t.ppid() != parent_pid || !t.leader {
            return false;
        }

        if !wait_eligible(t.exit_signal, wflags) {
            return false;
        }

        wait_match(&t, target_pid, pgid)
    })
}

/// The current task is exiting (Linux current->flags & PF_EXITING)
pub fn current_exiting() -> bool {
    current().has_flag(crate::task::pf::EXITING)
}

/// Hand the current task's children to a new parent before it dies
/// (Linux forget_original_parent): another live thread of its group,
/// else a live thread of the nearest PR_SET_CHILD_SUBREAPER ancestor
/// process in its pid namespace, else that namespace's init. Its
/// tracees are detached first (exit_ptrace), while it is still the
/// real parent of those that are its children: a zombie one is then
/// released or told to it as Linux __ptrace_detach does, before any
/// is handed on. A dying namespace init then kills and reaps the rest
/// of its namespace (find_child_reaper).
#[inline(never)]
fn forget_original_parent() {
    crate::task::ptrace::exit_ptrace();
    let me = task_ref(&current());
    crate::task::pidns::find_child_reaper(&me);
    // Room for every child first: the moved list grows outside TASKLIST
    // (only a notice's queue entry is made under it, GFP_ATOMIC)
    let mut moved = Vec::new();
    loop {
        let n = TASKLIST.read().view(&me).map_or(0, |t| t.children.len());
        moved.reserve(n + 1);
        match reparent_children(&me, &mut moved) {
            Moved::All => break,
            Moved::Full => {}
            Moved::Told(told, gone) => {
                told.finish();
                release(gone);
            }
        }
    }
    // Then, with TASKLIST dropped (Linux forget_original_parent): each
    // moved child's threads get their pdeath_signal, from this task
    for c in &moved {
        let deaths = GlobalTaskTable::collect_threads(c.pid, |_, t| {
            let sig = t.pdeath_signal?;
            Some((task_ref(t.task), sig))
        });
        for (t, sig) in deaths {
            let _ = crate::signal::send_group_signal(&t, sig, crate::signal::SendInfo::User);
        }
    }
}

/// How far [`reparent_children`] got
enum Moved {
    /// Every child moved
    All,
    /// `moved` has no room for the next
    Full,
    /// A zombie moved and its new parent told (it may be released)
    Told(Told, Option<Reaped>),
}

/// Hand `me`'s children to their new parent ([`find_reaper`]). A
/// zombie whose group is gone moving to another process tells its new
/// parent in the same TASKLIST write section (Linux reparent_leader);
/// one such move ends the pass.
fn reparent_children(me: &TaskRef, moved: &mut Vec<TaskRef>) -> Moved {
    let mut table = TASKLIST.write();
    if table.view(me).is_none_or(|t| t.children.is_empty()) {
        return Moved::All;
    }
    let Some(reaper) = find_reaper(&table, me) else {
        return Moved::All;
    };
    if Arc::ptr_eq(&reaper, me) {
        return Moved::All;
    }
    let other = reaper.pid != me.pid;
    loop {
        if moved.len() == moved.capacity() {
            return Moved::Full;
        }
        let Some(c) = table
            .view(me)
            .and_then(|t| t.children.front().map(task_ref))
        else {
            return Moved::All;
        };
        let tells = other && leader_waits(&table, c.pid);
        table.adopt(&c, &reaper, other);
        moved.push(c.clone());
        if tells {
            let told = notify(&table, Zombie::Leader(c.pid));
            let gone = if told.autoreap {
                reap_locked(&mut table, c.pid)
            } else {
                None
            };
            return Moved::Told(told, gone);
        }
    }
}

/// `me`'s children's new parent (Linux find_new_reaper): another live
/// thread of its group, else a live thread of the nearest ancestor
/// process in its pid namespace that is a child subreaper, else that
/// namespace's init (its child reaper).
/// Unlike Linux, every ancestor is checked, with no has_child_subreaper
/// shortcut: that flag is set on every descendant of a subreaper (fork,
/// walk_process_tree), and an orphan only moves up, so the walk finds
/// the same reaper.
fn find_reaper(table: &GlobalTaskTable, me: &TaskRef) -> Option<TaskRef> {
    if let Some(t) = live_thread(table, me.pid) {
        return Some(t);
    }
    let v = table.view(me)?;
    let level = v.thread_pid_ref().map(|p| p.level);
    let mut p = v.real_parent();
    while let Some(t) = p {
        // An ancestor gone from the list, or in another pid namespace,
        // ends the walk: the namespace's init adopts (Linux
        // find_new_reaper ends at the child_reaper, by
        // task_pid(reaper)->level)
        let Some(v) = table.view(t) else { break };
        if v.thread_pid_ref().map(|p| p.level) != level {
            break;
        }
        if v.signal().is_some_and(|s| s.subreaper(table))
            && let Some(r) = live_thread(table, t.pid)
        {
            return Some(r);
        }
        p = v.real_parent();
    }
    crate::task::pidns::child_reaper(table, me.pid_ns())
}

/// A thread of process `pid` that has not started exiting (Linux
/// find_alive_thread: !PF_EXITING)
pub(crate) fn live_thread(table: &GlobalTaskTable, pid: Pid) -> Option<TaskRef> {
    table
        .threads(pid)
        .find(crate::signal::task_live)
        .map(|t| task_ref(t.task))
}

/// The exiting task becomes a zombie with wait status `status` and
/// tells its parent or tracer in the same TASKLIST write section (Linux
/// exit_notify: EXIT_ZOMBIE and do_notify_parent under tasklist_lock),
/// so a wait never reaps it before its signal is pending: a traced task
/// its tracer; a leader with no other thread left to report it
/// (thread_group_empty) its parent. An untraced non-leader thread
/// leaves the task list in that section (Linux autoreaps it), and if it
/// was the last of a group whose leader is a zombie, the leader tells
/// there. A child the parent does not wait for is released at once
/// (autoreap).
// Not inlined: its send path's stack is used only for the call, not
// added to exit_current's frame for the rest of the exit
#[inline(never)]
fn exit_notify(tid: Tid, status: i32) {
    let done = exit_locked(&mut TASKLIST.write(), tid, status);
    if let Some(done) = done {
        done.finish();
    }
    // An exec in its group waits for it to leave or, as the leader, to
    // be a zombie (Linux exit_notify: notify_count < 0 ->
    // wake_up_process(group_exec_task))
    if let Some(s) = current().cpu_group() {
        wake_exec(s);
    }
}

/// The thread of `sig`'s group whose exec waits for the others
/// (de_thread) rechecks (Linux wake_up_process(sig->group_exec_task)
/// from __exit_signal and exit_notify). TASKLIST not held.
fn wake_exec(sig: &crate::signal::SignalStruct) {
    if let crate::signal::GroupExit::Exec(tid) = sig.group_exit()
        && let Some(t) = TASKLIST.read().task(tid)
    {
        crate::task::percpu::try_to_wake_up(&t, crate::task::percpu::WakeMode::Any);
    }
}

/// [`exit_notify`]'s TASKLIST write section for task `tid`
fn exit_locked(table: &mut GlobalTaskTable, tid: Tid, status: i32) -> Option<Unhashed> {
    let t = table.get(tid)?;
    let (pid, traced, leader) = (t.task.pid, t.task.ptrace() != 0, t.leader);
    // A traced task stays for its tracer, a leader for its parent; an
    // untraced thread goes now
    let stays = traced || leader;
    let teller = if stays {
        (traced || !group_pending(table, pid, &[tid])).then_some(Zombie::Exiting(tid))
    } else {
        thread_teller(table, pid, tid)
    };
    if let Some(mut t) = table.get_mut(tid) {
        t.exit_code = status;
        t.state = TaskState::Zombie(status);
    }
    if !stays {
        // An untraced thread's pidfd pollers (Linux exit_notify:
        // do_notify_pidfd for an untraced sub-thread); its removal
        // wakes them again
        notify_pidfd(table, tid);
        return Some(unhash_thread(table, tid, teller));
    }
    let (told, gone) = tell(table, teller);
    Some(Unhashed {
        thread: None,
        told,
        gone,
    })
}

/// What a TASKLIST write section that released zombies leaves for
/// after the lock (Linux release_task's work past tasklist_lock): the
/// thread it took out of the list, its leader's notice, the leader it
/// autoreaped
#[derive(Default)]
struct Unhashed {
    /// The thread and its struct pid, pinned before the release cleared
    /// it (Linux release_task: get_pid(task_pid(p)) for proc_flush_pid)
    thread: Option<(TaskRef, Option<Arc<crate::task::pid::Pid>>)>,
    told: Option<Told>,
    gone: Option<Reaped>,
}

impl Unhashed {
    /// Release what the section took and wake whoever waits (TASKLIST
    /// not held): an exec (de_thread) waiting for the thread
    fn finish(self) {
        if let Some((t, pid)) = self.thread {
            crate::fs::proc::proc_flush_pid(&t, pid);
            if let Some(s) = t.cpu_group() {
                wake_exec(s);
            }
            drop(t);
        }
        if let Some(t) = self.told {
            t.finish();
        }
        release(self.gone);
    }
}

/// Zombie `z`'s notice, if any, its queue entry made in this section
/// (GFP_ATOMIC, Linux do_notify_parent); a zombie its parent does not
/// wait for is taken out of the list (autoreap)
fn tell(table: &mut GlobalTaskTable, z: Option<Zombie>) -> (Option<Told>, Option<Reaped>) {
    let Some(z) = z else {
        return (None, None);
    };
    let told = notify(table, z);
    let gone = if told.autoreap {
        reap_locked(table, z.tid())
    } else {
        None
    };
    (Some(told), gone)
}

/// Thread `tid` (not a leader) leaves the task list (Linux
/// release_task); `z`, from [`thread_teller`] in this section, is its
/// zombie leader's notice if it was the last thread
fn unhash_thread(table: &mut GlobalTaskTable, tid: Tid, z: Option<Zombie>) -> Unhashed {
    let pid = table.get(tid).and_then(|v| v.thread_pid());
    let thread = table.remove(tid).map(|t| (t, pid));
    let (told, gone) = tell(table, z);
    Unhashed { thread, told, gone }
}

/// The notice thread `tid` of process `pid` leaving the list sends:
/// its zombie leader's, if it is the last thread but the leader
fn thread_teller(table: &GlobalTaskTable, pid: Pid, tid: Tid) -> Option<Zombie> {
    last_thread(table, pid, tid).then_some(Zombie::Leader(pid))
}

/// The exiting tracer `me`'s zombie tracees are detached, one per
/// TASKLIST write section, leaders first (Linux exit_ptrace ->
/// __ptrace_detach, its dead list released after the lock): a thread
/// is released, the last of its group telling its zombie leader's
/// parent (release_task); a leader with no thread left tells its real
/// parent as if never traced, or, if that is `me`'s own process, is
/// released if that process does not wait for children
pub fn detach_zombies(me: &Task) {
    loop {
        let done = detach_zombie(&mut TASKLIST.write(), me);
        let Some(done) = done else {
            break;
        };
        done.finish();
    }
}

/// [`detach_zombies`]'s TASKLIST write section for one zombie `me`
/// traces
fn detach_zombie(table: &mut GlobalTaskTable, me: &Task) -> Option<Unhashed> {
    let (tid, pid, leader, ppid) = traced_zombie(table, me)?;
    let (z, dead) = if !leader {
        (thread_teller(table, pid, tid), true)
    } else if group_pending(table, pid, &[pid]) {
        (None, false)
    } else if ppid != me.pid {
        (Some(Zombie::Detached(tid)), false)
    } else {
        (None, crate::signal::notify::ignoring_children(table, me))
    };
    if let Some(mut v) = table.get_mut(tid) {
        crate::task::ptrace::ptrace_unlink(&mut v);
    }
    if !leader {
        return Some(unhash_thread(table, tid, z));
    }
    let (told, mut gone) = tell(table, z);
    if dead {
        gone = reap_locked(table, tid);
    }
    Some(Unhashed {
        thread: None,
        told,
        gone,
    })
}

/// A zombie `me` traces, a leader first: its tid, pid, whether it
/// leads, its real parent's pid
fn traced_zombie(table: &GlobalTaskTable, me: &Task) -> Option<(Tid, Pid, bool, Pid)> {
    let mine = |t: &TaskView<'_>| {
        t.task.ptrace() != 0 && t.traced_by(me) && matches!(t.state, TaskState::Zombie(_))
    };
    table
        .find(|t| mine(t) && t.leader)
        .or_else(|| table.find(|t| mine(t)))
        .map(|t| (t.task.tid(), t.task.pid, t.leader, t.ppid()))
}

/// Wake the pidfd pollers of zombie `tid` (Linux do_notify_pidfd,
/// under tasklist_lock): it exited, so a poll may now see it readable
/// ([`pidfd_exited`])
pub fn notify_pidfd(table: &GlobalTaskTable, tid: Tid) {
    if let Some(p) = table.get(tid).and_then(|t| t.thread_pid()) {
        p.wait_pidfd.wake_poll(u32::from(
            crate::io::poll::POLLIN | crate::io::poll::POLLRDNORM,
        ));
    }
}

/// What a pidfd poll sees of the task `pid` names (Linux pidfd_poll,
/// with TASKLIST's read lock for its RCU read side): None once it is
/// released; Some(true) once it is a zombie, unless it leads a group
/// with another thread still listed (delay_group_leader: a thread
/// still running or exiting, or a traced zombie its tracer has not
/// reaped)
pub fn pidfd_exited(pid: &crate::task::pid::Pid) -> Option<bool> {
    let table = TASKLIST.read();
    let tid = table.pid_tid(pid)?;
    let t = table.get(tid)?;
    let delayed = t.leader && group_pending(&table, t.task.pid, &[tid]);
    Some(matches!(t.state, TaskState::Zombie(_)) && !delayed)
}

/// Thread `tid` of process `pid` is the last but its zombie leader:
/// its removal leaves the leader with no thread to wait for (Linux
/// release_task: thread_group_empty and the leader's EXIT_ZOMBIE)
fn last_thread(table: &GlobalTaskTable, pid: Pid, tid: Tid) -> bool {
    table.get(pid).is_some_and(|l| {
        l.leader
            && matches!(l.state, TaskState::Zombie(_))
            && !group_pending(table, pid, &[pid, tid])
    })
}

/// Process `pid`'s leader is an untraced zombie with no other thread
/// left: a new parent is told of it (Linux reparent_leader: !ptrace,
/// EXIT_ZOMBIE, thread_group_empty); a traced one is its tracer's
fn leader_waits(table: &GlobalTaskTable, pid: Pid) -> bool {
    table.get(pid).is_some_and(|l| {
        l.leader
            && l.task.ptrace() == 0
            && matches!(l.state, TaskState::Zombie(_))
            && !group_pending(table, pid, &[pid])
    })
}

/// A zombie leader no one will wait for, taken out of the task list
/// under TASKLIST (Linux EXIT_DEAD, then release_task after the lock)
struct Reaped {
    t: TaskRef,
    /// Its parent, which rechecks once it is gone
    parent: Option<TaskRef>,
    /// Its struct pid, pinned for proc_flush_pid
    pid: Option<Arc<crate::task::pid::Pid>>,
    ucounts: crate::task::UcountsRef,
}

/// Take zombie `tid` out of the task list for [`release`]
fn reap_locked(table: &mut GlobalTaskTable, tid: Tid) -> Option<Reaped> {
    let (ucounts, pid, parent) = match table.get(tid) {
        Some(t) if matches!(t.state, TaskState::Zombie(_)) => {
            (t.ucounts(), t.thread_pid(), t.real_parent().map(task_ref))
        }
        _ => return None,
    };
    table.remove(tid).map(|t| Reaped {
        t,
        parent,
        pid,
        ucounts,
    })
}

/// Release a zombie leader [`reap_locked`] took (Linux release_task of
/// an autoreaped child): its RLIMIT_NPROC charge dropped, its parent's
/// waiters recheck (it was their child until now: Linux marks it
/// EXIT_DEAD, which wait skips, in the section that notified them); its
/// run queue keeps it if it still runs. TASKLIST not held.
fn release(gone: Option<Reaped>) {
    let Some(Reaped {
        t,
        parent,
        pid,
        ucounts,
    }) = gone
    else {
        return;
    };
    crate::fs::proc::proc_flush_pid(&t, pid);
    ucounts.dec(crate::task::Ucount::Nproc, 1);
    drop(t);
    if let Some(p) = parent {
        crate::signal::notify::wake_up_parent(&p);
    }
}

/// Exit the current task and switch to another
///
/// This function never returns. The current task is removed from the
/// run queue (but kept in TASKLIST as zombie), and execution switches
/// to the next available task (typically idle if no others).
///
/// With a `status`, the task becomes a zombie carrying it once everything
/// it owned is released (Linux exit_notify after exit_mm/exit_files): a
/// parent's wait never sees it, and never removes it, while it still
/// runs on its resources.
pub fn exit_current(status: Option<i32>) -> ! {
    let tid = current_tid();

    // Release the task's resources first, without the rq lock: these paths
    // take sleeping-context locks and may wake other tasks (futex CLEARTID,
    // robust futexes), which needs this CPU's rq lock.
    if tid != 0 {
        // Its io_uring requests end first, so none outlives the task
        // (Linux do_exit: io_uring_files_cancel, which runs the task's
        // callbacks as it waits)
        crate::io::io_uring::task_cancel(false);
        crate::task::task_work::task_work_run();
        // PF_EXITING, set under the group lock and Task.sig, then the
        // group signals this thread would have taken go to another
        // (Linux exit_signals)
        crate::signal::exit_signals();

        // Exactly one thread, the one taking the group's live count to
        // zero, does the group-level exit work (Linux do_exit:
        // group_dead = atomic_dec_and_test(&signal->live))
        let group_dead = crate::signal::get_task_signal_struct(&current())
            .is_none_or(|s| s.thread_exiting(&current(), status));

        // Nothing reaps orphans or keeps userspace going without the
        // global init: its death is fatal, and loud (Linux do_exit:
        // is_global_init when group_dead), not a silent idle machine
        if group_dead
            && current_pid() == 1
            && let Some(st) = status
        {
            panic!("Attempted to kill init! exitcode={:#010x}", st);
        }

        // The group's last thread writes the accounting record while the
        // task still has its mm, files and identity (Linux acct_process
        // when group_dead, before exit_mm/exit_files)
        if let Some(st) = status
            && group_dead
        {
            crate::task::acct::write_acct_record(st);
        }

        // A non-leader thread is released at exit (Linux autoreaps it):
        // its RLIMIT_NPROC charge goes now; a process's when it is reaped
        {
            let me = current();
            let table = TASKLIST.read();
            if let Some(task) = table.view(&me)
                && task.task.tid() != task.task.pid
            {
                task.ucounts().dec(crate::task::Ucount::Nproc, 1);
            }
        }

        // Clean up filesystem context for exiting task
        crate::fs::exit_task_fs(&current());

        // Clean up FD table for exiting task
        crate::task::fdtable::exit_task_fd(&current());
        // POSIX locks went as the last user of the descriptor table
        // closed its descriptors (exit_task_fd; Linux close_files ->
        // filp_flush -> locks_remove_posix)
        if group_dead {
            // A session leader's session loses its controlling tty
            // (Linux do_exit -> disassociate_ctty(1))
            crate::tty::jobctrl::disassociate_ctty(true);
        }

        // Clean up SysV semaphore undo list for exiting task
        // This may apply undo operations if this is the last holder
        // MUST be done BEFORE exit_task_ns() since exit_sem needs IPC namespace
        crate::ipc::sem::exit_sem(&current());

        // Clean up I/O context for exiting task
        crate::task::remove_task_io_context(&current());

        // Clean up namespace context for exiting task
        crate::ns::exit_task_ns(&current());

        // Clean up seccomp state for exiting task
        crate::seccomp::exit_seccomp(&current());

        // The group's last thread deletes its timers (Linux exit_itimers
        // when group_dead)
        if group_dead && let Some(sig) = crate::signal::get_task_signal_struct(&current()) {
            crate::time::posix_timer::exit_itimers(&sig);
        }

        // Clean up robust futex list for exiting task
        crate::task::futex::exit_robust_list(&current());

        // Handle CLONE_CHILD_CLEARTID: write 0 and wake futex waiters
        // This must be done before switching away since we need to be in
        // the task's address space to write to user memory
        do_clear_child_tid(&current());

        // Signal vfork completion if parent is waiting
        // This must be done after CLEARTID but before we switch away
        signal_vfork_done();
    }

    // Leave the address space (Linux exit_mm, after mm_release above has
    // used it for the robust list and CLEARTID): the last user tears it
    // down; its top-level table stays loaded here until we switched away
    let dead_mm = if tid != 0 {
        crate::mm::exit_task_mm(&current())
    } else {
        None
    };
    if tid != 0 {
        // The files its descriptors, address space and the rest held
        // are released now, before a parent can see it exited; then no
        // callback can be queued on it any more, and a file it still
        // drops goes to the delayed list (Linux do_exit: exit_mm,
        // exit_files, exit_fs, exit_task_namespaces, then
        // exit_task_work)
        crate::task::task_work::exit_task_work();
        forget_original_parent();
        // Out of its cgroup while still running, before it is a zombie
        // a waiting parent may reap at once (Linux do_exit: cgroup_exit
        // before exit_notify); TASKLIST is not held
        crate::cgroup::detach_task(&current());
    }
    if let Some(st) = status {
        exit_notify(tid, st);
    }

    do_task_dead(dead_mm)
}
