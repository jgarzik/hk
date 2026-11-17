# hk siglock: Linux sighand->siglock and lock_task_sighand

To-do tracker for the series that closes BUGS.md "Another task's signal
state is read under TASKLIST". Delete this file in the series' last
commit.

## 1. Linux (reference tree ~/tmp/repo/linux)

### What siglock protects

`sighand->siglock` (spinlock_t, in the `sighand_struct`, shared by every
task with CLONE_SIGHAND; all threads of a group share one) is the lock of
all signal state:

- The handler table `sighand->action[]`: do_sigaction, get_signal
  (reads the action under it), force_sig_info_to_task (resets it).
- Per thread: `blocked`, `real_blocked`, `saved_sigmask`
  (__set_current_blocked, sigprocmask paths, set_current_blocked),
  `pending` (__send_signal_locked, dequeue_signal, flush_signals,
  flush_sigqueue_mask), `jobctl` (task_set_jobctl_pending,
  task_clear_jobctl_pending, task_clear_jobctl_trapping),
  `exit_code` and `last_siginfo` while ptrace-stopped (ptrace_stop,
  ptrace_resume), TIF_SIGPENDING recalc (recalc_sigpending under it,
  signal_wake_up / signal_wake_up_state must be called with it held),
  the sigaltstack lock (sigaltstack_lock).
- Per group (signal_struct): `shared_pending`, `curr_target`
  (complete_signal, __exit_signal), `flags` (SIGNAL_STOP_*,
  SIGNAL_CLD_*, SIGNAL_GROUP_EXIT, SIGNAL_UNKILLABLE cleared by
  force_sig_info_to_task), `group_stop_count`, `group_exit_code`,
  `group_exec_task`, `notify_count` (de_thread, zap_other_threads,
  do_signal_stop, task_join_group_stop), `tty` (tty_jobctrl:
  proc_clear_tty, __proc_set_tty), itimer state (itimer.c), the
  posix-cpu-timers lists (lock_task_sighand in posix-cpu-timers.c).
- The thread list `signal->thread_head`: copy_process adds a thread
  (list_add_tail_rcu) under `tasklist_lock` (write) + siglock;
  __exit_signal -> __unhash_process removes it (list_del_rcu) under
  both. Readers: either lock, or RCU (for_each_thread).
- The `task->sighand` pointer: set NULL by __exit_signal
  (smp_store_release, under tasklist write + siglock, from
  release_task); swapped by unshare_sighand (exec: tasklist write +
  old siglock, rcu_assign_pointer). A zombie keeps it until released.
- Not under siglock: `task->signal` (fixed for the task's life, freed
  with the task), `task->ptrace` (written under tasklist write, read
  racily under siglock: sig_ignored, ptrace_signal), credentials (RCU).

### lock_task_sighand

`__lock_task_sighand`: rcu_read_lock; loop { sighand =
rcu_dereference(tsk->sighand); NULL -> fail (released, ESRCH);
spin_lock_irqsave(&sighand->siglock); if it is still tsk->sighand,
done; else unlock and retry (raced de_thread/unshare or __exit_signal) };
rcu_read_unlock. Linux relies on SLAB_TYPESAFE_BY_RCU for a freed
sighand; hk frees a sighand a grace period late instead.

Users: do_send_sig_info (kill_pid_info_type, group_send_sig_info,
do_send_specific: tkill/tgkill/rt_sigqueueinfo all RCU-found, no
tasklist_lock), posixtimer_send_sigqueue, posix-cpu-timers, /proc
(task_sig, do_task_stat), tty, getrusage, wait_task_* take siglock
directly under tasklist read.

### IRQ class and order

spin_lock_irqsave / spin_lock_irq: signals are sent from hardirq
(it_real_fn, posix-timer hrtimer callbacks). Order:

    cred_guard_mutex -> tasklist_lock -> siglock -> tty ctrl.lock
    it_lock (posix timer) -> siglock (posixtimer_send_sigqueue)
    siglock -> pi_lock -> rq lock (signal_wake_up -> try_to_wake_up)
    siglock -> posix-cpu-timer it_lock (posix_cpu_timers_exit)

tasklist_lock stays only where a group or parent link is walked:
__kill_pgrp_info, kill(-1), send_sigio to a group, do_notify_parent*,
setpgid, wait, ptrace attach/detach, release_task, de_thread.

### Step 5's two open points

(a) Per-task state across a table swap. `task->blocked`,
`real_blocked`, `saved_sigmask`, `pending`, `jobctl`, `exit_code`,
`last_siginfo` live in task_struct and have no lock of their own: they
are under the siglock of whatever table `task->sighand` names at the
time (`signal->shared_pending`, `flags`, `group_stop_count`,
`curr_target`, `ignored_posix_timers` likewise, through the group's
threads, which share one table: CLONE_THREAD needs CLONE_SIGHAND). The
table changes in two places only, both under tasklist write and the old
table's siglock: unshare_sighand (exec, after de_thread left the task
alone in its group: copies `action[]` under the old siglock,
rcu_assign_pointer(me->sighand, new), unlock) and __exit_signal
(release: smp_store_release(&tsk->sighand, NULL) under the old siglock,
after posix_cpu_timers_exit and __unhash_process). copy_process sets a
child's table before the child is listed (fork's attach under tasklist
write + the parent's siglock; the child's own state initialised before,
unseen). Readers reach another task's state only through
lock_task_sighand's retry (lock the table read under RCU, recheck it is
still `tsk->sighand`): a hand-off under the old siglock is seen by the
retry, so a holder of either table never touches state the other
table's holder owns. de_thread changes no table (the exec'ing thread and
the leader share it); exchange_tids/transfer_pid move pids, not signal
state. hk: the per-task and per-group cells name their owner table and
move with `Task.sighand` in the same section (TASKLIST write + old
siglock), as `SignalStruct.threads` already does (`set_owner`); after
release (no table) the state is unreachable, as Linux's
(lock_task_sighand fails).

(b) sigaction's lock. do_sigaction takes spin_lock_irq(&siglock) only:
SA_IMMUTABLE check, old action copied, new installed, then, still under
siglock, an action that now ignores the signal flushes it from
`shared_pending` and every thread's `pending` (flush_sigqueue_mask,
for_each_thread; entries freed in place) and one that stopped ignoring
it requeues ignored periodic POSIX timers (posixtimer_sig_unignore).
There is no sleeping lock. The requeue does not take a timer's it_lock
(order it_lock -> siglock, posixtimer_send_sigqueue): the timers whose
signal was ignored are on `signal->ignored_posix_timers`, an hlist
under siglock, put there by posixtimer_sig_ignore (from
posixtimer_send_sigqueue on an ignored periodic signal, and from
sigqueue_free_ignored when a flush drops a timer's queued entry), taken
off by unignore (sigq requeued under siglock, the rearm left to the
dequeue: it_sigqueue_seq/it_sig_periodic are siglock-written) and by
timer deletion (posix_timer_cleanup_ignored under siglock). hk: rt_sigaction
runs under `lock_task_sighand(current)` alone; the flush walks the thread
list under it; the timer requeue walks a siglock-owned ignored list in
`SignalStruct` (Linux's), not the registry under `posix_timers`;
`SigHand.update` goes. hk frees flushed entries after the siglock (rule
5: freed outside, a timer entry back to its timer), the one difference
from Linux's in-place free; the decision to list a timer as ignored is
made under siglock as Linux's.

## 2. hk state -> Linux owner -> change

| hk state | today | Linux owner | change |
|---|---|---|---|
| `TaskInner.sighand` | TASKLIST, cleared at exit (`exit_task_signal`) | `task->sighand` `__rcu`, siglock + tasklist write | `Task.sighand: RcuLockedArc<SigHand, GlobalTaskTable>`, cleared at release under TASKLIST write + its siglock; `lock_task_sighand` |
| `SigHand.users` | TASKLIST | `sighand->count` refcount | unchanged (TASKLIST write is held by every writer) |
| `TaskInner.signal` | gone (2b) | `task->signal`, fixed | `Task.cpu_group` is it (fixed) |
| leader `TaskInner.threads` | `SignalStruct.threads` (3) | `signal->thread_head`: tasklist write + siglock | done |
| `TaskInner.ptrace` | `Task.ptrace` atomic (4) | tasklist write; racy read under siglock | done |
| `Task.sig` (blocked, pending, altstack, ptrace jobctl, last_siginfo) | per-task spin Mutex | siglock | nested under siglock first; folded into siglock-owned state last |
| `SignalStruct.jobctl` (group stop) | spin Mutex after TASKLIST | siglock | as above |
| `SignalStruct.shared` (shared_pending, curr_target, forks) | spin Mutex | siglock | as above |
| `SigHand.action` | IrqSpinlock leaf | siglock | as above |
| `SigHand.update` | sleeping, rt_sigaction | siglock across do_sigaction | becomes siglock once the flush runs under it |
| thread choice, group kill, stop prepare | TASKLIST read (rule 6) | siglock (complete_signal, zap_other_threads, prepare_signal) | under siglock |

## 3. Rust design

- `SigHand.siglock`: thread-context spin `Mutex<()>`, lockdep-tracked,
  as Linux PREEMPT_RT (posix-timer/itimer expiry in thread context,
  siglock never taken from hardirq): hk sends no signal from interrupt
  context (LOCKING 3.7 rule 1), guarded by `check_send_context`; a
  hardirq sender would make it an IrqSpinlock (Linux irqsave).
  Position: TASKLIST -> siglock -> SignalStruct.jobctl -> Task.sig ->
  SignalStruct.shared -> SigHand.action; SigHand.update before
  TASKLIST.
- `Task.sighand` is an `RcuLockedArc<SigHand, GlobalTaskTable>`: written
  only under TASKLIST's write lock (Linux holds it at every write) and
  the old table's siglock; read under RCU or TASKLIST. A replaced or
  cleared table goes through `put_rcu` (`SigHand.puts`), so the retry
  loop may lock a stale table safely.
- `lock_task_sighand(&Task, &RcuReadGuard) -> Option<SigGuard<'_>>`:
  Linux's loop over `Task.sighand.read(g)`, `as_ptr` recheck. `SigGuard`
  holds the mutex guard and `&SigHand`.
- Siglock-owned state uses a per-instance cell, `SigCell<T>`, checked
  against the guard's table at run time (Rust-for-Linux `LockedBy`
  with its owner check), since `SigHand` instances are many (sync's
  `LockedBy` needs a unique owner). The thread list's cell needs a
  `&mut GlobalTaskTable` and a `SigGuard` to change, either to walk.
  One new unsafe wrapper (per doc/UNSAFE.md), in sync/.

## 4. Commit sequence (each passes the gate alone)

1. [x] siglock exists; `Task.sighand` RCU pointer out of TaskInner; exec
   unshare and the exit clear take TASKLIST write + old siglock;
   `get_task_sighand` under RCU.
   `lock_task_sighand` is added with its first caller.
2. [x] sighand set in the section that lists the child and cleared at
   release (`unhash`, Linux __exit_signal), not at exit: a zombie keeps
   its handlers.
2b. [x] `Task.sig` no longer swapped at exit: only the private queue
   goes, in exit_signals under PF_EXITING (the reference tree's
   sigqueue_dequeue_pending); a zombie keeps its mask, its group's
   set stays. `TaskInner.signal` dropped (`Task.cpu_group` is
   task->signal); group pending reached through it; dead CPU time
   added at release (`unhash`). `group_task` gone: a group signal goes
   to the task found (a zombie leader included), a child's notice to
   the parent thread (Linux __group_send_sig_info(tsk->parent)).
3. [x] thread list into `SignalStruct.threads` (`sync::LockedByBoth`:
   TASKLIST write + the owner table's siglock to change, either to
   walk; `SigGuard` = `InstanceGuard<SigHand>`); a send holds the
   receiver's siglock; complete_signal, zap_threads, stop::prepare,
   do_signal_stop walk under it (TASKLIST still held for ptrace flags
   until step 4). CLONE_THREAD/CLONE_SIGHAND flag checks first.
4. [x] `Task.ptrace` atomic (Relaxed loads, written under TASKLIST
   write); sender numbering under RCU (`Task.thread_pid`, fixed
   first); the send under `lock_task_sighand`: kill, tkill, tgkill,
   rt_sigqueueinfo, pidfd_send_signal, POSIX/itimer timer signals off
   TASKLIST; TASKLIST callers (pgrp walk, kill(-1), notify parent,
   exit_ptrace, send_sigio) take siglock inside it. exit_group and
   de_thread's zap take only siglock. BUGS.md bullet deleted.
5. [ ] fold Task.sig, SignalStruct.jobctl/shared, SigHand.action/update
   into siglock-owned `SigCell`s (Linux: one lock). Delete this file.

Also in this series:

- [x] `Task.thread_pid` an RCU pointer (TASKLIST write: creation,
  exchange_tids, release); `Task::pid_nr_ns` reads it directly.
- [ ] `Pid.pgrp`/`session` (`task/pid.rs`, `util/rcuhlist.rs`) hold a
  reference to each listed leader; Linux holds none (pid_links are
  bare hlist nodes; a task is freed a grace period after release,
  after detach_pid). Needs a non-owning RCU chain (writers under
  TASKLIST, readers' validity from task lifetime, as `RcuPtr`).
- [ ] PRIO_USER (`task/schedsys.rs` `tasks_of_user`) walks every task
  under TASKLIST into a vector; Linux walks for_each_process_thread
  under rcu_read_lock alone. Needs the task list
  (`GlobalTaskTable.tasks`) RCU-readable (Linux list_add_tail_rcu /
  list_del_rcu of task->tasks).
