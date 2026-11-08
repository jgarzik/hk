//! A pid namespace's init (Linux kernel/pid_namespace.c, kernel/exit.c
//! find_child_reaper): the first task numbered 1 in a namespace is its
//! child reaper, which adopts its orphans; when the last thread of its
//! group exits, every other task of the namespace is killed and reaped
//! before it dies (zap_pid_ns_processes).
//!
//! Locking (doc/LOCKING.md, "A pid namespace's init"):
//! `PidNamespace.reaper` and `reboot` are TASKLIST's;
//! `PidNamespace.alloc` (pid count, adding, init) is PIDMAP_LOCK's
//! (`task::pid`).

use crate::ns::PidNamespace;
use crate::task::Task;
use crate::task::percpu::{GlobalTaskTable, TASKLIST, TaskRef, task_ref};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

/// `ns`'s child reaper, if listed (Linux pid_ns->child_reaper)
pub fn child_reaper(table: &GlobalTaskTable, ns: &PidNamespace) -> Option<TaskRef> {
    let t = ns.reaper.access(table).as_ref()?.upgrade()?;
    table.task(t.tid()).filter(|l| Arc::ptr_eq(l, &t))
}

/// `t` is `ns`'s child reaper (TASKLIST held)
fn is_reaper(table: &GlobalTaskTable, ns: &PidNamespace, t: &TaskRef) -> bool {
    ns.reaper
        .access(table)
        .as_ref()
        .is_some_and(|r| core::ptr::eq(r.as_ptr(), Arc::as_ptr(t)))
}

/// `t` becomes `ns`'s child reaper (TASKLIST held for writing): its
/// init as it joins the task list, or another live thread of init's
/// group as init's thread exits. The reference it replaces is the
/// caller's to drop after unlocking.
#[must_use]
pub fn set_reaper(
    table: &mut GlobalTaskTable,
    ns: &PidNamespace,
    t: &TaskRef,
) -> Option<Weak<Task>> {
    ns.reaper.access_mut(table).replace(Arc::downgrade(t))
}

/// The init `t` (a new process numbered 1 in its namespace) joins the
/// task list (TASKLIST held for writing): it is the namespace's child
/// reaper, and other numbers may now be made there (Linux copy_process:
/// is_child_reaper)
pub fn attach_init(table: &mut GlobalTaskTable, t: &TaskRef) {
    let ns = t.pid_ns();
    let old = set_reaper(table, ns, t);
    debug_assert!(old.is_none(), "pidns: a second init");
    crate::task::pid::set_ns_init(ns);
}

/// Linux find_child_reaper, as `me` exits (before its children are
/// handed on): if it is its namespace's child reaper, another live
/// thread of its group takes over; with none left the namespace dies
/// with it (zap_pid_ns_processes). The global init's death panics
/// before this.
pub fn find_child_reaper(me: &TaskRef) {
    let ns = me.pid_ns();
    // Most exits are no reaper's: the read lock tells. A thread cannot
    // become the reaper after this, as it is exiting (PF_EXITING, set
    // before) and a handover takes only a live thread.
    if !is_reaper(&TASKLIST.read(), ns, me) {
        return;
    }
    let (zap, _old) = {
        let mut table = TASKLIST.write();
        if !is_reaper(&table, ns, me) {
            return;
        }
        match crate::task::percpu::live_thread(&table, me.pid) {
            Some(t) => (false, set_reaper(&mut table, ns, &t)),
            None => (ns.level != 0, None),
        }
    };
    if zap {
        zap_pid_ns_processes(me, ns);
    }
}

/// The init `me` is dying (Linux zap_pid_ns_processes): no new pid in
/// `ns`, SIGKILL to every other task in it, then reap its children
/// (orphans of the namespace come to it meanwhile) and wait until the
/// only pids left there are its group's, so its parent sees it exit
/// only once the namespace is empty. Called with no lock held.
fn zap_pid_ns_processes(me: &TaskRef, ns: &PidNamespace) {
    crate::task::pid::disable_pid_allocation(ns);
    for t in ns_tasks(ns, me.pid) {
        let _ = crate::signal::send_group_signal(
            &t,
            crate::signal::SIGKILL,
            crate::signal::SendInfo::Kernel,
        );
    }
    // Its own pid, and its zombie leader's if it is not the leader
    let init_pids = if me.tid() == me.pid { 1 } else { 2 };
    reap_ns(me, ns, init_pids);
    // A reboot(2) inside sets what its parent sees
    let code = *ns.reboot.access(&TASKLIST.read());
    if code != 0
        && let Some(s) = crate::signal::get_task_signal_struct(me)
    {
        s.set_exit_code(code);
    }
    crate::task::acct::exit_ns(ns);
}

/// reboot(2) `cmd` from inside a child pid namespace ends that
/// namespace, never the machine (Linux reboot_pid_ns): its init is
/// killed and its parent sees it killed by SIGHUP (restart) or SIGINT
/// (power off, halt), and the caller exits; another command is EINVAL.
/// None in the root namespace.
pub fn reboot_pid_ns(cmd: u32) -> Option<crate::util::error::KernelError> {
    use crate::power::cmd::{HALT, POWER_OFF, RESTART, RESTART2};
    use crate::signal::{SIGHUP, SIGINT, SIGKILL, SendInfo};
    let ns = crate::task::pid::current_pid_ns();
    if ns.level == 0 {
        return None;
    }
    let sig = match cmd {
        RESTART | RESTART2 => SIGHUP,
        POWER_OFF | HALT => SIGINT,
        _ => return Some(crate::util::error::KernelError::InvalidArgument),
    };
    let reaper = {
        let mut table = TASKLIST.write();
        *ns.reboot.access_mut(&mut table) = sig as i32;
        child_reaper(&table, ns)
    };
    if let Some(r) = reaper {
        let _ = crate::signal::send_sig_info(&r, SIGKILL, SendInfo::Kernel);
    }
    crate::task::proc::do_exit(0)
}

/// The live tasks numbered in `ns` but those of process `pid` (Linux:
/// the namespace's idr from 2); collected under TASKLIST's read lock
/// with room made before it (nothing allocates under it)
fn ns_tasks(ns: &PidNamespace, pid: crate::task::Pid) -> Vec<TaskRef> {
    let mine = |t: &crate::task::percpu::TaskView<'_>| {
        t.task.pid != pid
            && crate::signal::task_live(t)
            && t.thread_pid.as_ref().is_some_and(|p| p.nr_in(ns).is_some())
    };
    let mut v = Vec::new();
    loop {
        let n = TASKLIST.read().iter().filter(|t| mine(t)).count();
        v.reserve(n);
        let full = {
            let table = TASKLIST.read();
            let mut full = false;
            for t in table.iter().filter(|t| mine(t)) {
                if v.len() == v.capacity() {
                    full = true;
                    break;
                }
                v.push(task_ref(t.task));
            }
            full
        };
        if !full {
            return v;
        }
        v.clear();
    }
}

/// Reap `me`'s children until it has none and `ns` holds only
/// `init_pids` pids (Linux zap_pid_ns_processes: kernel_wait4 until
/// ECHILD, then pid_allocated == init_pids). Linux sets init's SIGCHLD
/// to SIG_IGN so late zombies autoreap; an exiting hk task has no
/// handlers left, so it reaps them here (each exit and the namespace's
/// last pids wake CHILD_EXIT_WQ).
fn reap_ns(me: &TaskRef, ns: &PidNamespace, init_pids: u32) {
    use crate::sync::waitqueue::WaitEntry;
    use crate::task::percpu::{SleepState, has_children, reap_zombie_child_times, schedule};
    use crate::task::proc::CHILD_EXIT_WQ;
    use crate::task::wait_options::__WALL;
    let w = core::pin::pin!(WaitEntry::new());
    loop {
        CHILD_EXIT_WQ.prepare_to_wait(w.as_ref(), SleepState::Uninterruptible);
        if reap_zombie_child_times(me.pid, -1, __WALL).is_some() {
            continue;
        }
        if !has_children(me.pid, -1, __WALL) && crate::task::pid::ns_pids(ns) <= init_pids {
            break;
        }
        schedule();
    }
    CHILD_EXIT_WQ.finish_wait(w.as_ref());
}
