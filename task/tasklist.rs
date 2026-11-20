//! The task list and pid lookups (Linux tasklist_lock, init_task.tasks
//! and kernel/pid.c's task lookups): `TASKLIST` over every task, the
//! locked views of a task's `TaskInner`, and find_task_by_vpid and
//! friends.
#![expect(clippy::undocumented_unsafe_blocks)] // TODO(unsafe): SAFETY comments (doc/UNSAFE.md)

use super::percpu::INIT_TASK;
use crate::ns::Namespace;
use crate::sync::spin::RwLock;
use crate::task::{Cred, Pid, Task, TaskInner, Tid};
use ::core::sync::atomic::Ordering;
use alloc::sync::Arc;
use alloc::vec::Vec;

/// A reference to a task (Linux struct task_struct *, pinned by a
/// reference count)
pub type TaskRef = Arc<Task>;

/// Every task (Linux tasklist: the list of all tasks, init_task.tasks,
/// plus the pid hash for lookups), under TASKLIST
///
/// fork/exit/reap change it (write lock); lookups and walks read it. A
/// task's locked fields ([`crate::task::TaskInner`]) are reached through
/// the views below, which borrow the locked list: `get`/`iter` read them
/// (shared lock), `get_mut`/`iter_mut` write them (exclusive lock).
pub struct GlobalTaskTable {
    /// Its list is [`TASKS`], reached without TASKLIST by RCU walkers
    _list: (),
}

/// Every task in the table, holding a reference each (Linux
/// init_task.tasks): changed only under TASKLIST's write lock (the
/// table's `&mut self` methods: `insert`, `unhash`), walked under
/// TASKLIST (`GlobalTaskTable::iter`) or an RCU read guard
/// ([`for_each_task_rcu`], Linux for_each_process_thread under
/// rcu_read_lock; list_add_tail_rcu, list_del_rcu); a task leaves it a
/// grace period before its list reference goes (`RcuUnlinked::defer`)
static TASKS: crate::util::rculist::RcuList<TasksAdapter> = crate::util::rculist::RcuList::new();

/// Every task in the task list, under RCU (`g`; Linux
/// for_each_process_thread under rcu_read_lock): one listed or
/// unlisted meanwhile may or may not be seen; each stays allocated for
/// the guard's life
pub fn for_each_task_rcu<'a>(
    g: &'a crate::sync::rcu::RcuReadGuard,
) -> impl Iterator<Item = &'a Task> + 'a {
    TASKS.iter(g)
}

crate::adapter!(TasksAdapter, Task, tasks_link);
crate::hadapter!(pub PgrpLink, Task, pgrp_link);
crate::hadapter!(pub SessionLink, Task, session_link);

/// A new reference to a task that lives in an `Arc` (every task but the
/// boot task does: the table and run queues hold `TaskRef`s); one
/// reached under RCU through a pid or a parent link still has the
/// list's reference, dropped a grace period after it is unlisted
/// (Linux get_task_struct under rcu_read_lock)
pub fn task_ref(t: &Task) -> TaskRef {
    let p = core::ptr::from_ref::<Task>(t);
    // The static boot task is in no Arc: one pointer compare keeps this
    // safe fn from corrupting the memory before it
    assert!(
        !core::ptr::eq(p, &raw const INIT_TASK),
        "task_ref of the boot task"
    );
    // SAFETY: `t` is the data of a live `Arc<Task>` (see above)
    unsafe {
        Arc::increment_strong_count(p);
        Arc::from_raw(p)
    }
}

/// A task with its locked fields readable (the table is locked)
#[derive(Clone, Copy)]
pub struct TaskView<'a> {
    pub task: &'a Task,
    inner: &'a TaskInner,
    table: &'a GlobalTaskTable,
}

impl<'a> TaskView<'a> {
    /// The locked fields, for the whole borrow of the table
    pub fn fields(&self) -> &'a TaskInner {
        self.inner
    }
}

impl core::ops::Deref for TaskView<'_> {
    type Target = TaskInner;
    fn deref(&self) -> &TaskInner {
        self.inner
    }
}

/// A task with its locked fields writable (the table is locked and
/// borrowed mutably)
pub struct TaskViewMut<'a> {
    pub task: &'a Task,
    inner: &'a mut TaskInner,
    table: &'a GlobalTaskTable,
}

impl core::ops::Deref for TaskViewMut<'_> {
    type Target = TaskInner;
    fn deref(&self) -> &TaskInner {
        self.inner
    }
}

impl core::ops::DerefMut for TaskViewMut<'_> {
    fn deref_mut(&mut self) -> &mut TaskInner {
        self.inner
    }
}

fn view<'a>(table: &'a GlobalTaskTable, task: &'a Task) -> TaskView<'a> {
    let inner = task.inner().access(table);
    let inner = inner.as_ref().expect("task table: boot task");
    TaskView { task, inner, table }
}

/// # Safety
/// `table` comes from a mutable borrow of the locked table, and no
/// other view of `task` is live for 'a.
unsafe fn view_mut<'a>(table: &'a GlobalTaskTable, task: &'a Task) -> TaskViewMut<'a> {
    // SAFETY: see above
    let inner = unsafe { task.inner().access_mut_unchecked(table) };
    let inner = inner.as_mut().expect("task table: boot task");
    TaskViewMut { task, inner, table }
}

/// Credentials of a listed task (read under RCU: `Task::cred`)
macro_rules! owner_reads {
    ($t:ident) => {
        impl<'a> $t<'a> {
            /// Its credentials, copied
            pub fn cred(&self) -> Cred {
                self.task.cred()
            }

            /// A reference to its credentials
            pub fn cred_arc(&self) -> Arc<Cred> {
                self.task.cred_arc()
            }

            /// A reference to its real uid's counters (Linux
            /// task_ucounts)
            pub fn ucounts(&self) -> crate::task::UcountsRef {
                self.task.ucounts()
            }
        }
    };
}
owner_reads!(TaskView);
owner_reads!(TaskViewMut);

/// Tracer links of a task, read under TASKLIST (the views borrow it;
/// Linux task->parent of a ptraced task under tasklist_lock)
macro_rules! tracer_reads {
    ($t:ident) => {
        impl<'a> $t<'a> {
            /// Its tracer, if it is traced (no reference taken: listed
            /// while the table is borrowed)
            pub fn tracer(&self) -> Option<&'a Task> {
                self.task.tracer_locked(self.table)
            }

            /// Traced by `t` (pointer identity: never a recycled number)
            pub fn traced_by(&self, t: &Task) -> bool {
                core::ptr::eq(self.task.tracer_ptr(), t)
            }
        }
    };
}
tracer_reads!(TaskView);
tracer_reads!(TaskViewMut);

/// Parent, group and session links of a task, read under TASKLIST (the
/// views borrow it; Linux rcu_dereference_protected under
/// tasklist_lock)
macro_rules! relation_reads {
    ($t:ident) => {
        impl<'a> $t<'a> {
            /// Its ptrace flags (`Task::ptrace`)
            pub fn ptrace(&self) -> u32 {
                self.task.ptrace()
            }

            /// Its struct pid (Linux task_pid), a counted reference;
            /// none for an idle task
            pub fn thread_pid(&self) -> Option<Arc<crate::task::pid::Pid>> {
                self.task.thread_pid.get_protected(self.table)
            }

            /// Its struct pid, borrowed while the table is
            pub fn thread_pid_ref(&self) -> Option<&'a crate::task::pid::Pid> {
                self.task.thread_pid.protected(self.table)
            }

            /// Its thread group's signal struct (Linux task->signal;
            /// none for a kernel thread)
            pub fn signal(&self) -> Option<&'a Arc<crate::signal::SignalStruct>> {
                self.task.cpu_group()
            }

            /// A reference to its signal handlers (none before fork
            /// attaches them or once it is released)
            pub fn sighand(&self) -> Option<Arc<crate::signal::SigHand>> {
                self.task.sighand.get_protected(self.table)
            }

            /// Its real parent (no reference taken: listed while the
            /// table is borrowed)
            pub fn real_parent(&self) -> Option<&'a Task> {
                self.task.parent_locked(self.table)
            }

            /// Its real parent's process (root number), 0 for none
            /// (Linux task_tgid_nr(real_parent)); read through the
            /// parent link, no reference taken
            pub fn ppid(&self) -> Pid {
                self.real_parent().map_or(0, |p| p.pid)
            }

            /// Its process group
            pub fn pgrp(&self) -> Option<&'a crate::task::pid::Pid> {
                self.task.cpu_group()?.pgrp.protected(self.table)
            }

            /// Its session
            pub fn session(&self) -> Option<&'a crate::task::pid::Pid> {
                self.task.cpu_group()?.session.protected(self.table)
            }

            /// Its process group (root number), 0 for none (Linux
            /// pid_nr(task_pgrp))
            pub fn pgid(&self) -> Pid {
                self.pgrp().map_or(0, |p| Pid::from(p.nr()))
            }

            /// Its session (root number), 0 for none (Linux
            /// pid_nr(task_session))
            pub fn sid(&self) -> Pid {
                self.session().map_or(0, |p| Pid::from(p.nr()))
            }
        }
    };
}
relation_reads!(TaskView);
relation_reads!(TaskViewMut);

impl TaskViewMut<'_> {
    /// Set its ptrace flags, TASKLIST held for writing (this view)
    pub fn set_ptrace(&mut self, v: u32) {
        self.task.ptrace.store(v, Ordering::Relaxed);
    }

    /// Its tracer becomes `p` (Linux __ptrace_link, __ptrace_unlink:
    /// under tasklist_lock's write lock, which the view holds); `p` is
    /// listed and not exiting, and the task is listed or joins the list
    /// in this write section (the `Task` invariant)
    pub fn set_tracer(&mut self, p: Option<&Task>) {
        debug_assert!(p.is_none_or(|p| p.tasks_link.is_listed()));
        // INVARIANT: the callers', under the write lock
        self.task
            .ptracer
            .set(p.map_or(core::ptr::null(), core::ptr::from_ref));
    }
}

// SAFETY: `new` is private to this module and called once, for TASKLIST
unsafe impl crate::sync::UniqueOwner for GlobalTaskTable {}

impl GlobalTaskTable {
    const fn new() -> Self {
        Self { _list: () }
    }

    /// Task `tid`, found through the pid hash (root namespace); the
    /// hash walked under RCU, the task listed for the table's borrow
    fn lookup(&self, tid: Tid) -> Option<&Task> {
        let nr = u32::try_from(tid).ok()?;
        let g = crate::sync::rcu::read_lock();
        crate::task::pid::find_pid_ns(&crate::ns::INIT_PID_NS, nr, &g)?.task_locked(self)
    }

    /// The task `pid` names (Linux pid_task under tasklist_lock)
    fn pid_task(&self, pid: &crate::task::pid::Pid) -> Option<&Task> {
        pid.task_locked(self)
    }

    /// The tid of the task `pid` names: that struct pid's, not its
    /// number's, which a reaped process frees for reuse
    pub fn pid_tid(&self, pid: &crate::task::pid::Pid) -> Option<Tid> {
        self.pid_task(pid).map(Task::tid)
    }

    /// Task `tid`
    pub fn get(&self, tid: Tid) -> Option<TaskView<'_>> {
        self.lookup(tid).map(|t| view(self, t))
    }

    /// Task `tid`, writable
    pub fn get_mut(&mut self, tid: Tid) -> Option<TaskViewMut<'_>> {
        let me = &*self;
        // SAFETY: `me` comes from `&mut self`; one view is handed out
        me.lookup(tid).map(|t| unsafe { view_mut(me, t) })
    }

    /// Task `t`, None once it is reaped (never a task reusing its tid)
    pub fn view<'a>(&'a self, t: &'a Task) -> Option<TaskView<'a>> {
        // `tasks_link` is on this list only, linked and unlinked under
        // the write lock (`insert`, `remove_task`): read under the lock
        // the borrow of `self` holds
        t.tasks_link.is_listed().then(|| view(self, t))
    }

    /// Task `t`, writable; None once it is reaped
    pub fn view_mut<'a>(&'a mut self, t: &'a Task) -> Option<TaskViewMut<'a>> {
        let me = &*self;
        // SAFETY: `me` comes from `&mut self`; one view is handed out
        t.tasks_link.is_listed().then(|| unsafe { view_mut(me, t) })
    }

    /// A reference to task `tid`
    pub fn task(&self, tid: Tid) -> Option<TaskRef> {
        self.lookup(tid).map(task_ref)
    }

    /// What `f` picks of each thread of process `pid`, gathered with no
    /// allocation under TASKLIST: the vector is sized under one read
    /// hold and filled under another, again if the group grew between
    pub fn collect_threads<T>(
        pid: Pid,
        f: impl Fn(&GlobalTaskTable, &TaskView<'_>) -> Option<T>,
    ) -> Vec<T> {
        Self::collect(
            |table, visit| {
                for t in table.threads(pid) {
                    if !visit(&t) {
                        break;
                    }
                }
            },
            f,
        )
    }

    /// What `f` picks of each thread of every process of group `pg`,
    /// gathered as `collect_threads` does
    pub fn collect_pgrp_threads<T>(
        pg: &crate::task::pid::Pid,
        f: impl Fn(&GlobalTaskTable, &TaskView<'_>) -> Option<T>,
    ) -> Vec<T> {
        Self::collect(
            |table, visit| {
                for t in table.pgrp_threads(pg) {
                    if !visit(&t) {
                        break;
                    }
                }
            },
            f,
        )
    }

    /// What `f` picks of each thread of task `t`'s process, gathered as
    /// `collect_threads` does, nothing once `t` is no longer listed (its
    /// group is found from `t` under each read hold, never by a number
    /// taken earlier)
    pub fn collect_group<T>(
        t: &Task,
        f: impl Fn(&GlobalTaskTable, &TaskView<'_>) -> Option<T>,
    ) -> Vec<T> {
        Self::collect(
            |table, visit| {
                if table.view(t).is_none() {
                    return;
                }
                for x in table.threads(t.pid) {
                    if !visit(&x) {
                        break;
                    }
                }
            },
            f,
        )
    }

    /// What `f` picks of every task, gathered as `collect_threads` does
    pub fn collect_tasks<T>(f: impl Fn(&GlobalTaskTable, &TaskView<'_>) -> Option<T>) -> Vec<T> {
        Self::collect(
            |table, visit| {
                for t in table.iter() {
                    if !visit(&t) {
                        break;
                    }
                }
            },
            f,
        )
    }

    /// What `f` picks of the tasks `walk` visits (until a visit returns
    /// false), with no allocation under TASKLIST: sized under one read
    /// hold, filled under another, again if the set grew between
    fn collect<T>(
        walk: impl Fn(&GlobalTaskTable, &mut dyn FnMut(&TaskView<'_>) -> bool),
        f: impl Fn(&GlobalTaskTable, &TaskView<'_>) -> Option<T>,
    ) -> Vec<T> {
        let mut cap = 1;
        walk(&TASKLIST.read(), &mut |_| {
            cap += 1;
            true
        });
        loop {
            let mut v = Vec::with_capacity(cap);
            let mut full = false;
            {
                let table = TASKLIST.read();
                walk(&table, &mut |t| {
                    if v.len() == v.capacity() {
                        full = true;
                        return false;
                    }
                    if let Some(x) = f(&table, t) {
                        v.push(x);
                    }
                    true
                });
            }
            if !full {
                return v;
            }
            cap *= 2;
        }
    }

    /// Every task
    pub fn iter(&self) -> impl Iterator<Item = TaskView<'_>> {
        // SAFETY: TASKLIST is held (`&self`), and every remover of TASKS
        // holds its write lock
        unsafe { TASKS.iter_locked() }.map(|t| view(self, t))
    }

    /// Every task, writable
    pub fn iter_mut(&mut self) -> impl Iterator<Item = TaskViewMut<'_>> {
        let me = &*self;
        // SAFETY: as in `iter`
        let all = unsafe { TASKS.iter_locked() };
        // SAFETY: `me` comes from `&mut self`; the list holds each task
        // once, so each view is handed out once
        all.map(|t| unsafe { view_mut(me, t) })
    }

    /// The first task `f` accepts
    pub fn find(&self, f: impl Fn(&TaskView<'_>) -> bool) -> Option<TaskView<'_>> {
        self.iter().find(|t| f(t))
    }

    /// The first task `f` accepts, writable
    pub fn find_mut(&mut self, f: impl Fn(&TaskViewMut<'_>) -> bool) -> Option<TaskViewMut<'_>> {
        self.iter_mut().find(|t| f(t))
    }

    /// The locked fields of a task, writable
    pub(super) fn inner_mut_of<'a>(&'a mut self, t: &'a Task) -> &'a mut TaskInner {
        t.inner()
            .access_mut(self)
            .as_mut()
            .expect("task table: boot task")
    }

    /// Put `child` (a group leader in this list) on its real parent's
    /// `children` (Linux list_add_tail(&p->sibling, &parent->children))
    pub fn link_child(&mut self, child: &TaskRef) {
        let Some(parent) = child.parent_locked(self).map(task_ref) else {
            return;
        };
        let ci = self.inner_mut_of(child);
        if ci.in_children {
            return;
        }
        ci.in_children = true;
        let pi = self.inner_mut_of(&parent);
        pi.children.push_back(child.clone());
    }

    /// Take `child` off its real parent's `children`
    fn unlink_child(&mut self, child: &Task) {
        let ci = self.inner_mut_of(child);
        if !core::mem::take(&mut ci.in_children) {
            return;
        }
        let Some(parent) = child.parent_locked(self).map(task_ref) else {
            return;
        };
        let pi = self.inner_mut_of(&parent);
        drop(unsafe { pi.children.remove(child) });
    }

    /// Move `child` to `reaper`'s children, every thread of its
    /// process with it (Linux forget_original_parent, reparent_leader);
    /// `other_group`: the reaper is not a thread of its old parent's
    /// process
    pub fn adopt(&mut self, child: &TaskRef, reaper: &TaskRef, other_group: bool) {
        self.unlink_child(child);
        let ci = self.inner_mut_of(child);
        // Linux reparent_leader: no custom exit signal to a new
        // parent process ("we don't want people slaying init")
        if other_group {
            ci.exit_signal = crate::signal::ExitSignal::SIGCHLD;
        }
        self.set_parents(child, reaper);
        self.link_child(child);
    }

    /// Every thread of leader `l`'s process gets real parent `p`
    /// (Linux forget_original_parent: for_each_thread, t->real_parent)
    fn set_parents(&mut self, l: &Task, p: &Task) {
        l.set_parent(Some(p), self);
        let mut cur = self.first_thread(l.pid);
        while let Some(t) = cur {
            t.set_parent(Some(p), self);
            cur = self.next_thread(l.pid, &t);
        }
    }

    /// Add a task (fork, kernel thread creation); it has a pid. It joins
    /// its group's thread list where it gets its group
    /// (`install_fork_signal`, `init_task_signal`).
    pub fn insert(&mut self, task: TaskRef) {
        let thread_pid = task.inner().access(self).as_ref().and_then(|i| {
            // Its credentials' user namespace is active while it is
            // listed (Linux copy_creds: get_cred_namespaces)
            if let Some(u) = &i.user_ns {
                u.active_get();
            }
            task.thread_pid.get_protected(self)
        });
        // The pid hash names it (Linux attach_pid PIDTYPE_PID), joining
        // the list in this section
        if let Some(p) = &thread_pid {
            p.set_task(Some(&task), self);
        }
        TASKS.push_back(task.clone());
    }

    /// Process `pid`'s thread list (Linux signal->thread_head, read under
    /// tasklist_lock); None for a task with no group (a kernel thread,
    /// the global init before it gets one), its own only thread
    fn thread_list(
        &self,
        pid: Pid,
    ) -> Option<&crate::util::list::OwnedList<crate::task::ThreadNode>> {
        Some(self.get(pid)?.signal()?.threads.access_a(self))
    }

    /// The threads of process `pid` (Linux for_each_thread under
    /// tasklist_lock)
    pub fn threads(&self, pid: Pid) -> impl Iterator<Item = TaskView<'_>> {
        let list = self.thread_list(pid);
        let mut cur = match list {
            Some(l) => l.first(),
            None => self.get(pid).map(|v| v.task),
        };
        core::iter::from_fn(move || {
            let t = cur?;
            cur = list.and_then(|l| l.next_ref(t));
            Some(view(self, t))
        })
    }

    /// The first thread of process `pid`
    pub fn first_thread(&self, pid: Pid) -> Option<TaskRef> {
        match self.thread_list(pid) {
            Some(l) => l.front(),
            None => self.task(pid),
        }
    }

    /// The thread after `t` in process `pid`'s list (Linux next_thread);
    /// None at the end or if `t` is not on it
    pub fn next_thread(&self, pid: Pid, t: &Task) -> Option<TaskRef> {
        self.thread_list(pid)?.next(t)
    }

    /// Take `t` off its group's thread list, under TASKLIST's write lock
    /// and its table's siglock `g` (Linux __unhash_process:
    /// list_del_rcu(&p->thread_node))
    fn unlink_thread(&mut self, t: &Task, g: &mut crate::signal::SigGuard<'_>) {
        if let Some(s) = t.cpu_group() {
            drop(s.threads.access_mut(self, g).remove(t));
        }
    }

    /// Remove task `tid`; the caller drops it after unlocking (nothing
    /// is released under TASKLIST)
    pub fn remove(&mut self, tid: Tid) -> Option<TaskRef> {
        self.remove_task(tid, true)
    }

    /// [`remove`](Self::remove); `release`: its numbers no task uses go
    /// back (not for an old leader whose pid an exec takes over)
    fn remove_task(&mut self, tid: Tid, release: bool) -> Option<TaskRef> {
        let t = task_ref(self.lookup(tid)?);
        self.unhash(&t, release);
        Some(t)
    }

    /// Listed task `t` leaves the list (Linux __unhash_process); see
    /// [`remove_task`](Self::remove_task)
    pub(super) fn unhash(&mut self, t: &TaskRef, release: bool) {
        let t = t.clone();
        self.unlink_child(&t);
        self.orphan_children(&t);
        self.detach_pids(&t);
        let thread_pid = t.thread_pid.get_protected(self);
        if let Some(p) = &thread_pid {
            // Before the list's reference goes (below): an RCU reader
            // of the pid finds the task only while that reference keeps
            // it (Linux detach_pid PIDTYPE_PID)
            p.set_task(None, self);
            // Its pidfd pollers see it gone (Linux __unhash_process:
            // wake_up_all under tasklist_lock)
            p.wait_pidfd.wake_all();
        }
        if release {
            self.release_pids(&t);
            if t.inner().access(self).as_ref().is_some_and(|i| i.leader) {
                self.detach_group_pids(&t);
            }
        }
        // It names no struct pid any more (Linux detach_pid PIDTYPE_PID:
        // task_pid_nr_ns then reads 0); RCU readers may still be on it.
        // de_thread's removed threads give theirs up once their numbers
        // are dealt with (`detach_thread_pid`)
        if release {
            self.detach_thread_pid(&t);
        }
        // Linux release_task: exit_cred_namespaces (atomics only; the
        // namespace itself goes with the task, after the unlock)
        if let Some(u) = t
            .inner()
            .access(self)
            .as_ref()
            .and_then(|i| i.user_ns.as_ref())
        {
            u.active_put();
        }
        // Off its group's thread list, its CPU time given to the group,
        // and its handlers gone, under its table's siglock (Linux
        // __exit_signal from release_task): a zombie keeps them until
        // here. The reference taken to do it is not the last (the
        // cell's goes through put_rcu)
        if let Some(h) = t.sighand.get_protected(self) {
            let mut g = crate::signal::SigGuard::lock(&h);
            self.unlink_thread(&t, &mut g);
            if let Some(s) = t.cpu_group() {
                s.add_dead_times(crate::task::cputime::task_cputime(&t));
            }
            h.leave(&t, None, self, &g);
        }
        // SAFETY: listed (the caller's)
        let listed = unsafe { TASKS.remove(&t) };
        // The list's reference goes a grace period later (Linux
        // list_del_rcu, release_task -> put_task_struct_rcu_user): an RCU
        // reader that reached it through the list, a pid or a parent
        // link may still read it
        listed.defer();
    }

    /// A task leaves the list with no children (Linux: exit hands them
    /// on first, forget_original_parent, so release_task has no such
    /// step). Any left is a bug, reported once as TASK:FAIL (Linux
    /// WARN_ON_ONCE); they are then made to name no parent, so a parent
    /// link never outlives its target's listing (the `Task` invariant
    /// `Task::parent`'s RCU read rests on)
    fn orphan_children(&mut self, t: &Task) {
        if self.inner_mut_of(t).children.is_empty() {
            return;
        }
        static REPORTED: core::sync::atomic::AtomicBool =
            core::sync::atomic::AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            crate::printkln!("TASK:FAIL tid {} left the task list with children", t.tid());
        }
        while let Some(c) = self.inner_mut_of(t).children.front().map(task_ref) {
            // SAFETY: on `t`'s children list
            drop(unsafe { self.inner_mut_of(t).children.remove(&c) });
            self.inner_mut_of(&c).in_children = false;
            c.set_parent(None, self);
            let mut cur = self.first_thread(c.pid);
            while let Some(th) = cur {
                th.set_parent(None, self);
                cur = self.next_thread(c.pid, &th);
            }
        }
    }

    /// Released leader `t`'s group is gone (Linux __unhash_process with
    /// group_dead: detach_pid PIDTYPE_TGID, PGID, SID): its group's pid
    /// and its group and session links clear, the references dropped a
    /// grace period later (an RCU reader may be on them)
    fn detach_group_pids(&mut self, t: &Task) {
        if let Some(s) = t.cpu_group() {
            s.leader_pid.replace(None, self).defer_put();
            s.pgrp.replace(None, self).defer_put();
            s.session.replace(None, self).defer_put();
        }
    }

    /// Removed task `t` names no struct pid (Linux detach_pid
    /// PIDTYPE_PID), the reference dropped a grace period later
    pub(super) fn detach_thread_pid(&mut self, t: &Task) {
        t.thread_pid.replace(None, self).defer_put();
    }

    /// The numbers of removed task `t` that no task uses any more go
    /// back (Linux free_pid)
    pub(super) fn release_pids(&self, t: &Task) {
        if t.inner().access(self).is_some() {
            let s = t.cpu_group();
            let pids = [
                t.thread_pid.protected(self),
                s.and_then(|s| s.pgrp.protected(self)),
                s.and_then(|s| s.session.protected(self)),
            ];
            for p in pids.into_iter().flatten() {
                self.release_unused(p);
            }
        }
    }

    /// The group leaders in process group `pg` (Linux
    /// do_each_pid_task(pg, PIDTYPE_PGID))
    pub fn pgrp<'a>(
        &'a self,
        pg: &'a crate::task::pid::Pid,
    ) -> impl Iterator<Item = TaskView<'a>> + 'a {
        pg.pgrp.iter_locked(self).map(move |t| view(self, t))
    }

    /// The group leaders in session `s` (Linux do_each_pid_task(s,
    /// PIDTYPE_SID))
    pub fn session<'a>(
        &'a self,
        s: &'a crate::task::pid::Pid,
    ) -> impl Iterator<Item = TaskView<'a>> + 'a {
        s.session.iter_locked(self).map(move |t| view(self, t))
    }

    /// The threads of every process in group `pg` (Linux
    /// do_each_pid_thread(pg, PIDTYPE_PGID))
    pub fn pgrp_threads<'a>(
        &'a self,
        pg: &'a crate::task::pid::Pid,
    ) -> impl Iterator<Item = TaskView<'a>> + 'a {
        self.pgrp(pg).flat_map(move |l| self.threads(l.task.pid))
    }

    /// A new process `s` joins its creator's process group and session
    /// (Linux copy_process init_task_pid: under the write lock, so the
    /// creator's concurrent setpgid or setsid is not missed)
    pub fn inherit_pids(&mut self, s: &crate::signal::SignalStruct, parent: &Task) {
        let Some(ps) = parent.cpu_group() else {
            return;
        };
        let (pg, ses) = (ps.pgrp.get_protected(self), ps.session.get_protected(self));
        // The group had none (new: nothing to retire)
        s.pgrp.replace(pg, self).defer_put();
        s.session.replace(ses, self).defer_put();
    }

    /// The process group and session of `t`'s group, counted
    fn group_pids(
        &self,
        t: &Task,
    ) -> (
        Option<Arc<crate::task::pid::Pid>>,
        Option<Arc<crate::task::pid::Pid>>,
    ) {
        t.cpu_group().map_or((None, None), |s| {
            (s.pgrp.get_protected(self), s.session.get_protected(self))
        })
    }

    /// Put group leader `t` on its process group's and session's lists
    /// (Linux attach_pid PIDTYPE_PGID, PIDTYPE_SID)
    pub(crate) fn attach_pids(&mut self, t: &Task) {
        let ti = self.inner_mut_of(t);
        if ti.pids_linked || !ti.leader {
            return;
        }
        let (Some(pg), Some(s)) = self.group_pids(t) else {
            return;
        };
        self.inner_mut_of(t).pids_linked = true;
        // No reference (Linux hlist_add_head_rcu of the task's bare
        // pid_links)
        // SAFETY: `t` is listed (`inner_mut_of` found it) and is unlinked
        // by `detach_pids` in `unhash`, before it leaves the task list,
        // whose reference goes a grace period after that (`kfree_rcu`)
        unsafe {
            pg.pgrp.add_head(t, self);
            s.session.add_head(t, self);
        }
    }

    /// Take `t` off its process group's and session's lists (Linux
    /// detach_pid)
    fn detach_pids(&mut self, t: &Task) {
        let ti = self.inner_mut_of(t);
        if !core::mem::take(&mut ti.pids_linked) {
            return;
        }
        if let (Some(pg), Some(s)) = self.group_pids(t) {
            // RCU readers may stand on it: the task outlives them by its
            // own rule (Linux hlist_del_rcu; freed a grace period after
            // it leaves the task list)
            let (p, q) = (pg.pgrp.del_init(t, self), s.session.del_init(t, self));
            debug_assert!(p && q, "linked: on both lists");
        }
    }

    /// `p`'s numbers go back once no task uses it: none has it as its
    /// pid, none heads or belongs to the group or session it names
    /// (Linux detach_pid -> free_pid when every pid type's list is empty)
    fn release_unused(&self, p: &crate::task::pid::Pid) {
        if !p.has_task() && p.pgrp.is_empty() && p.session.is_empty() {
            p.release_numbers();
        }
    }

    /// Move process `pid` (its leader on the lists) to group `pg` and,
    /// if given, session `s` (Linux change_pid on signal->pids); the
    /// group and session it left come back, for the caller to drop
    /// after TASKLIST (Linux ksys_setsid's pids[] and free_pids).
    /// Nothing is allocated; the replaced references are dropped a
    /// grace period later (`put_rcu`: an RCU reader may still be on
    /// them).
    #[must_use]
    pub(super) fn change_pids(
        &mut self,
        pid: Pid,
        pg: &Arc<crate::task::pid::Pid>,
        s: Option<&Arc<crate::task::pid::Pid>>,
    ) -> [Option<Arc<crate::task::pid::Pid>>; 2] {
        let Some(l) = self.task(pid) else {
            return [None, None];
        };
        let Some(sig) = l.cpu_group().cloned() else {
            return [None, None];
        };
        let (before, before_s) = self.group_pids(&l);
        self.detach_pids(&l);
        // RCU readers of the old link may still hold it: dropped a
        // grace period later (Linux free_pid -> delayed_put_pid)
        sig.pgrp.replace(Some(pg.clone()), self).defer_put();
        if let Some(s) = s {
            sig.session.replace(Some(s.clone()), self).defer_put();
        }
        self.attach_pids(&l);
        // The group or session it left may be gone (setpgid, setsid)
        for p in [&before, &before_s].into_iter().flatten() {
            self.release_unused(p);
        }
        [before, before_s]
    }

    /// Number of tasks, zombies included
    pub fn len(&self) -> usize {
        TASKS.count()
    }

    pub fn is_empty(&self) -> bool {
        TASKS.is_empty()
    }
}

/// Every task (Linux tasklist_lock and the task list): spin RwLock,
/// thread context only (Linux write_lock_irq: hk never takes it in an
/// interrupt handler, so interrupts stay on)
pub static TASKLIST: RwLock<GlobalTaskTable> = RwLock::new(GlobalTaskTable::new());

/// A reference to task `tid` (a root number), found under RCU
pub fn find_task(tid: Tid) -> Option<TaskRef> {
    find_task_by_pid_ns(tid, &crate::ns::INIT_PID_NS)
}

/// The task `ns` numbers `nr`, no reference taken (Linux
/// find_task_by_pid_ns under rcu_read_lock): it stays allocated while
/// `g` is held, and may be leaving the list
pub fn pid_ns_task<'a>(
    nr: u64,
    ns: &crate::ns::PidNamespace,
    g: &'a crate::sync::rcu::RcuReadGuard,
) -> Option<&'a Task> {
    crate::task::pid::find_pid_ns(ns, u32::try_from(nr).ok()?, g)?.task(g)
}

/// The task the caller numbers `nr`, no reference taken (Linux
/// find_task_by_vpid under rcu_read_lock)
pub fn vpid_task(nr: u64, g: &crate::sync::rcu::RcuReadGuard) -> Option<&Task> {
    pid_ns_task(nr, crate::task::pid::current_pid_ns(), g)
}

/// A reference to the task `ns` numbers `nr` (Linux rcu_read_lock;
/// find_task_by_pid_ns; get_task_struct): no TASKLIST
pub fn find_task_by_pid_ns(nr: u64, ns: &crate::ns::PidNamespace) -> Option<TaskRef> {
    let g = crate::sync::rcu::read_lock();
    pid_ns_task(nr, ns, &g).map(task_ref)
}

/// A reference to the task the caller numbers `nr` (Linux
/// find_get_task_by_vpid): what a pid argument names, None (ESRCH) if
/// not visible in its namespace
pub fn find_task_by_vpid(nr: u64) -> Option<TaskRef> {
    find_task_by_pid_ns(nr, crate::task::pid::current_pid_ns())
}

/// A reference to the task struct pid `pid` names (Linux get_pid_task
/// with PIDTYPE_PID): under RCU, no TASKLIST
pub fn get_pid_task(pid: &crate::task::pid::Pid) -> Option<TaskRef> {
    let g = crate::sync::rcu::read_lock();
    pid.task(&g).map(task_ref)
}
