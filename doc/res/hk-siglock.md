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

## 2. hk state -> Linux owner -> change

| hk state | today | Linux owner | change |
|---|---|---|---|
| `TaskInner.sighand` | TASKLIST, cleared at exit (`exit_task_signal`) | `task->sighand` `__rcu`, siglock + tasklist write | `Task.sighand: RcuLockedArc<SigHand, GlobalTaskTable>`, cleared at release under TASKLIST write + its siglock; `lock_task_sighand` |
| `SigHand.users` | TASKLIST | `sighand->count` refcount | unchanged (TASKLIST write is held by every writer) |
| `TaskInner.signal` | TASKLIST, cleared at exit for threads | `task->signal`, fixed | `Task.cpu_group` is it (fixed); drop the TaskInner copy |
| leader `TaskInner.threads` | TASKLIST | `signal->thread_head`: tasklist write + siglock | moves into `SignalStruct`, a cell needing both proofs to change, either to walk |
| `TaskInner.ptrace` | TASKLIST | tasklist write; racy read under siglock | atomic (Relaxed load = Linux's racy read) |
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
   Left for 2: fork names the child's table after the child is
   listed (Linux: before it is visible), so `lock_task_sighand` (added
   with its first caller) would see none in that gap.
2. [ ] sighand cleared at release (`remove`, Linux __exit_signal), not
   at exit; the zombie leader keeps handlers; `group_task` goes (Linux
   takes the leader); group pending reached through `Task.cpu_group`.
3. [ ] thread list into `SignalStruct` (`SigCell` + TASKLIST); walks in
   signal/ move from TASKLIST to siglock (complete_signal, zap_threads,
   stop::prepare, do_signal_stop).
4. [ ] `TaskInner.ptrace` atomic; sender numbering under RCU; the send
   (`send_task`) under `lock_task_sighand`: kill, tkill, tgkill,
   rt_sigqueueinfo, pidfd_send_signal, POSIX timer signals off
   TASKLIST; TASKLIST callers (pgrp walk, notify parent, exit_ptrace)
   take siglock inside it. Delete the BUGS.md bullet.
5. [ ] fold Task.sig, SignalStruct.jobctl/shared, SigHand.action/update
   into siglock-owned `SigCell`s (Linux: one lock). Delete this file.
