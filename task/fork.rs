//! Process creation (Linux kernel/fork.c): clone and its copy_process
//! steps, io threads, and the child-tid and vfork completion a child
//! signals when it releases its mm.

use super::percpu::{Cur, current, current_pt_regs, current_tid, policy_class, wake_up_new_task};
use super::tasklist::{TASKLIST, TaskRef, task_ref};
use crate::arch::{ArchPageTable, ContextOps, CpuOps, CurrentArch, FrameAlloc, SchedArch};
use crate::printkln;
use crate::task::sched;
use crate::task::{Task, TaskKind, TaskState, Tid};
use crate::util::error::{KernelError, KernelResult};
use ::core::sync::atomic::Ordering;
use alloc::sync::Arc;

/// Clear the child TID and wake futex waiters
///
/// Called when a task exits if CLONE_CHILD_CLEARTID was set during clone.
/// This:
/// 1. Gets and clears the clear_child_tid address from the Task struct
/// 2. Writes 0 to that address
/// 3. Calls futex_wake on that address to wake pthread_join waiters
pub(super) fn do_clear_child_tid(me: &Task) {
    // Get and clear the address from the Task struct directly
    let addr = {
        let mut table = TASKLIST.write();
        if let Some(mut task) = table.view_mut(me) {
            let addr = task.clear_child_tid;
            task.clear_child_tid = 0;
            (addr != 0).then_some(addr)
        } else {
            None
        }
    };

    if let Some(addr) = addr {
        use crate::uaccess::put_user;

        // Write 0 to the address
        if put_user::<i32>(addr, 0).is_ok() {
            // Wake one waiter, shared (Linux mm_release)
            let _ = crate::task::futex::futex_wake(
                addr,
                1,
                crate::task::futex::futex_op::FUTEX_BITSET_MATCH_ANY,
                false,
            );
        }
    }
}

/// Signal vfork completion (Linux complete_vfork_done; the child, on
/// exec or exit): wakes the parent sleeping in `do_clone` on the
/// completion on its stack. The pointer is taken once, so the parent's
/// completion is touched at most once and only while it waits.
pub fn signal_vfork_done() {
    let p = current()
        .vfork_done
        .swap(core::ptr::null_mut(), Ordering::AcqRel);
    // SAFETY: set by the vforking parent, which waits (uninterruptibly)
    // until this completes it; `Completion` does not touch itself once
    // the waiter can return
    if let Some(c) = unsafe { p.as_ref() } {
        c.complete();
    }
}

/// Clone configuration for do_clone
pub struct CloneConfig {
    /// Clone flags (CLONE_VM, CLONE_THREAD, etc.)
    pub flags: u64,
    /// Child's user stack top (required for CLONE_VM, 0: the parent's)
    pub child_stack: u64,
    /// User address to store parent TID (CLONE_PARENT_SETTID)
    pub parent_tidptr: u64,
    /// User address to store child TID (CLONE_CHILD_SETTID/CLEARTID)
    pub child_tidptr: u64,
    /// TLS pointer for child (CLONE_SETTLS)
    pub tls: u64,
    /// User address to store pidfd (CLONE_PIDFD)
    pub pidfd_ptr: u64,
    /// Exit signal for child (SIGCHLD for fork; a thread's is
    /// ExitSignal::THREAD whatever this says)
    pub exit_signal: crate::signal::ExitSignal,
    /// Cgroup file descriptor (CLONE_INTO_CGROUP, clone3 only)
    pub cgroup_fd: i32,
    /// clone3 set_tid: the child's number in the innermost
    /// `set_tid_size` levels of its pid namespace, its own first
    pub set_tid: [u32; crate::ns::pid::MAX_PID_NS_LEVEL as usize],
    pub set_tid_size: usize,
    /// An io thread (`create_io_thread`): the child runs this in the
    /// kernel instead of returning to user mode
    pub io_thread: Option<crate::task::IoThreadFn>,
}

impl CloneConfig {
    /// No set_tid
    pub const NO_SET_TID: [u32; crate::ns::pid::MAX_PID_NS_LEVEL as usize] =
        [0; crate::ns::pid::MAX_PID_NS_LEVEL as usize];
}

/// clone3's set_tid numbers for a child in `ns` (Linux alloc_pid): no
/// more than its levels and each a valid number (EINVAL), and the
/// right to choose them (EPERM: CAP_CHECKPOINT_RESTORE or
/// CAP_SYS_ADMIN, checkpoint_restore_ns_capable); a level with no init
/// yet takes only 1 (EINVAL)
fn check_set_tid(ns: &crate::ns::PidNamespace, set_tid: &[u32]) -> KernelResult<()> {
    if set_tid.len() > ns.level as usize + 1 {
        return Err(KernelError::InvalidArgument);
    }
    let mut level = Some(ns);
    for &nr in set_tid {
        if !(1..crate::task::pid::PID_MAX_LIMIT).contains(&nr) {
            return Err(KernelError::InvalidArgument);
        }
        let l = level.ok_or(KernelError::InvalidArgument)?;
        if nr != 1 && !crate::task::pid::ns_has_init(l) {
            return Err(KernelError::InvalidArgument);
        }
        level = l.parent.as_deref();
        if !crate::task::capable(crate::task::CAP_CHECKPOINT_RESTORE)
            && !crate::task::capable(crate::task::CAP_SYS_ADMIN)
        {
            return Err(KernelError::NotPermitted);
        }
    }
    Ok(())
}

/// Create a new thread/process via clone() (Linux kernel_clone): the
/// child made by [`copy_process`], its number stored for
/// CLONE_PARENT_SETTID, then woken; with CLONE_VFORK the caller waits
/// until the child execs or exits
///
/// # Returns
/// * Ok(child's pid as the caller numbers it) on success (the child
///   returns 0 when scheduled)
/// * Err(e) on failure
pub fn do_clone<FA: FrameAlloc<PhysAddr = u64>>(
    config: CloneConfig,
    frame_alloc: &mut FA,
) -> KernelResult<Tid> {
    use crate::task::clone_flags::*;

    let (child_task, child_tid) = copy_process(&config, frame_alloc)?;

    // The child's number as the caller sees it, for the return value
    // and CLONE_PARENT_SETTID, taken before it can run and be reaped
    // (Linux kernel_clone: pid_vnr before wake_up_new_task)
    let child_vnr = crate::task::pid::vnr(child_tid);
    if config.flags & CLONE_PARENT_SETTID != 0 && config.parent_tidptr != 0 {
        use crate::uaccess::put_user;
        if put_user::<i32>(config.parent_tidptr, child_vnr as i32).is_err() {
            // Continue even if write fails - Linux does the same
            printkln!("CLONE: CLONE_PARENT_SETTID write failed");
        }
    }

    // CLONE_VFORK: the completion must be in place before the child can
    // run (it may exec or exit at once on another CPU; Linux
    // p->vfork_done)
    let vfork = crate::sync::completion::Completion::new();
    if config.flags & CLONE_VFORK != 0 {
        child_task
            .vfork_done
            .store((&raw const vfork).cast_mut(), Ordering::Release);
    }

    // Only a fully set up child becomes runnable (Linux: wake_up_new_task
    // at the end of kernel_clone)
    wake_up_new_task(&child_task);

    // CLONE_VFORK: parent sleeps until the child exec()s or _exit()s
    // (Linux wait_for_vfork_done; uninterruptible here, so the
    // completion on this stack outlives the child's use of it)
    if config.flags & CLONE_VFORK != 0 {
        vfork.wait();
    }

    // The child's pid (a new process's pid is its tid), as the caller
    // numbers it
    Ok(Tid::from(child_vnr))
}

/// The flag combinations clone refuses before any work (Linux
/// copy_process's opening checks): EINVAL
fn clone_flags_ok(config: &CloneConfig, me: &Cur) -> KernelResult<()> {
    use crate::task::clone_flags::*;
    let flags = config.flags;
    // A new mount or user namespace with a shared fs context: its root
    // and cwd would cross namespaces
    if flags & CLONE_FS != 0 && flags & (CLONE_NEWNS | CLONE_NEWUSER) != 0 {
        return Err(KernelError::InvalidArgument);
    }
    // CLONE_VM requires a child stack unless CLONE_VFORK (vfork shares
    // the parent's stack)
    if flags & CLONE_VM != 0
        && config.child_stack == 0
        && flags & CLONE_VFORK == 0
        && config.io_thread.is_none()
    {
        return Err(KernelError::InvalidArgument);
    }
    // A thread group shares its handlers, and handlers are shared only
    // with the memory: every thread of a group names its group's table,
    // whose siglock its thread list is under
    if flags & CLONE_THREAD != 0 && flags & CLONE_SIGHAND == 0 {
        return Err(KernelError::InvalidArgument);
    }
    if flags & CLONE_SIGHAND != 0 && flags & CLONE_VM == 0 {
        return Err(KernelError::InvalidArgument);
    }
    // Handlers shared and reset at once
    if flags & CLONE_SIGHAND != 0 && flags & CLONE_CLEAR_SIGHAND != 0 {
        return Err(KernelError::InvalidArgument);
    }
    // A pid namespace's init cannot make a sibling (CLONE_PARENT with
    // SIGNAL_UNKILLABLE)
    if flags & CLONE_PARENT != 0
        && crate::signal::get_task_signal_struct(me).is_some_and(|s| s.unkillable())
    {
        return Err(KernelError::InvalidArgument);
    }
    // A thread stays in its group's pid namespace: CLONE_THREAD with
    // CLONE_NEWPID or CLONE_NEWUSER, or after an unshare(CLONE_NEWPID)
    if flags & CLONE_THREAD != 0 {
        let for_children = me.nsproxy().map(|ns| Arc::as_ptr(&ns.pid_ns));
        let own: *const crate::ns::PidNamespace = me.pid_ns();
        if flags & (CLONE_NEWPID | CLONE_NEWUSER) != 0 || for_children.is_some_and(|p| p != own) {
            return Err(KernelError::InvalidArgument);
        }
    }
    // CLONE_DETACHED is refused with CLONE_PIDFD
    if flags & CLONE_PIDFD != 0 && flags & CLONE_DETACHED != 0 {
        return Err(KernelError::InvalidArgument);
    }
    Ok(())
}

/// Linux dup_task_struct: the child task, built in its block from the
/// caller's settings (a copy of the caller, as Linux copies its task
/// struct), with its kernel stack. The copy_* steps of `copy_process`
/// then replace what the child does not share. Unshared: the caller
/// fills it in place through `Arc::get_mut` until it is listed.
#[inline(never)]
fn dup_task_struct(me: &Cur, config: &CloneConfig) -> KernelResult<TaskRef> {
    use crate::task::clone_flags::*;
    // The caller's settings, under TASKLIST
    let (pid, cpus, pgd, cred, prctl, personality, seccomp, filter, exec_id, leader_exit, iopl) = {
        let table = TASKLIST.read();
        let parent = table.view(me).ok_or(KernelError::NoProcess)?;
        let leader_exit = table
            .get(parent.task.pid)
            .map_or(crate::signal::ExitSignal::NONE, |l| l.exit_signal);
        (
            parent.task.pid,
            parent.task.cpus_mask.snapshot(),
            parent.pgd,
            parent.cred_arc(),
            parent.prctl.clone(),
            parent.personality,
            parent.task.seccomp_mode(),
            parent.seccomp_filter.clone(),
            parent.parent_exec_id,
            leader_exit,
            parent.iopl_emul,
        )
    };
    // Its own alloc_lock fields (lock-free but the memory policy)
    let alloc = crate::task::TaskAlloc {
        comm: me.comm(),
        mempolicy: me.task_lock().mempolicy(),
    };
    // pgrp/session are set from the creator's under TASKLIST
    // (`inherit_pids`); pdeath_signal is never inherited; untraced until
    // listed: CLONE_PTRACE links it in the write section that lists it
    let inner = crate::task::TaskInner {
        // Linux copy_process: a thread -1, a CLONE_PARENT child the
        // group leader's; their parent_exec_id the caller's, else the
        // caller's exec count
        exit_signal: if config.flags & CLONE_THREAD != 0 {
            crate::signal::ExitSignal::THREAD
        } else if config.flags & CLONE_PARENT != 0 {
            leader_exit
        } else {
            config.exit_signal
        },
        parent_exec_id: if config.flags & (CLONE_PARENT | CLONE_THREAD) != 0 {
            exec_id
        } else {
            crate::task::self_exec_id(me)
        },
        // prctl state: the name is inherited (dumpability lives in the
        // mm: shared with CLONE_VM, copied by dup_mm)
        prctl: crate::task::PrctlState {
            no_new_privs: prctl.no_new_privs,     // Inherited (irreversible)
            timer_slack_ns: prctl.timer_slack_ns, // Inherited
            keep_caps: false,                     // Reset on fork
            tsc_mode: prctl.tsc_mode,             // Inherited
            thp_disable: prctl.thp_disable,       // Inherited
        },
        personality,
        // Seccomp filters are reference-counted, so this is cheap
        seccomp_filter: filter,
        // I/O port permissions (x86-64 only)
        iopl_emul: iopl,
        // Copied like the rest of task->flags
        leader: config.flags & CLONE_THREAD == 0,
        ..crate::task::TaskInner::new(TaskState::Ready, pgd)
    };
    let group_pid = if config.flags & CLONE_THREAD != 0 {
        pid
    } else {
        0
    };
    // Built in its block (Linux dup_task_struct fills the slab object):
    // a task on fork's frames would cost its size under every call
    let mut child = crate::util::kalloc::try_arc_with(|| {
        Task::new(
            0,
            crate::task::TaskIds {
                pid: group_pid,
                seccomp_mode: seccomp,
                thread_pid: None,
            },
            TaskKind::UserProcess,
            0,
            crate::cpu::this_id(),
            &cpus,
            cred,
            None,
            // The name and memory policy are inherited
            alloc,
            crate::signal::TaskSignalState::new(),
            inner,
        )
    })?;
    // Its kernel stack (zeroed, guard gap below; Linux
    // alloc_thread_stack_node): it goes with the task on failure
    let stack = crate::mm::vmstack::alloc().ok_or(KernelError::OutOfMemory)?;
    Arc::get_mut(&mut child)
        .expect("dup_task_struct: a new task is unshared")
        .kstack_top = stack.top();
    child.se.stack.set(stack);
    // The parent's thread state (Linux arch_dup_task_struct): arm64 its
    // user FP/SIMD state, the child's marked not loaded on any CPU
    // (copy_thread: fpsimd_flush_task_state)
    // SAFETY: our child, not yet on a run queue
    unsafe { crate::arch::dup_thread(&child) };
    // Linux dup_task_struct copies the parent's flags: the I/O flusher
    // mark (PR_SET_IO_FLUSHER) is inherited, and PF_NPROC_EXCEEDED
    if me.has_flag(crate::task::pf::NPROC_EXCEEDED) {
        child.set_flag(crate::task::pf::NPROC_EXCEEDED);
    }
    child.set_flag(me.flags() & crate::task::pf::IO_FLUSHER);
    Ok(child)
}

/// Linux copy_creds: the child's credentials (shared by a thread, else
/// a copy) and keyrings; its RLIMIT_NPROC charge, EAGAIN over the limit
/// unless root or CAP_SYS_RESOURCE/CAP_SYS_ADMIN (Linux copy_process).
/// The charge goes back on any error until `keep`.
fn fork_creds(t: &mut Task, me: &Cur, flags: u64) -> KernelResult<crate::task::NprocCharge> {
    use crate::task::clone_flags::*;
    let parent_cred = me.cred_arc();
    let cred = crate::task::copy_creds(flags, &parent_cred)?;
    // Its keyrings, made before it is visible
    let parent_keys = me.keyrings.lock().clone();
    let keys = crate::keys::keyring::fork_keyrings(
        &parent_keys,
        flags & CLONE_THREAD != 0,
        parent_cred.fsuid,
        parent_cred.fsgid,
    );
    *t.keyrings.get_mut() = keys;
    // Every task, threads included, is charged to its real uid until
    // it is released
    let nproc = crate::task::NprocCharge::new(cred.ucounts.clone());
    t.cred = crate::task::TaskCred::new(cred);
    if crate::task::nproc_over(&nproc.ucounts) {
        return Err(KernelError::WouldBlock);
    }
    Ok(nproc)
}

/// Linux sched_fork: the child inherits the policy and priorities;
/// with SCHED_RESET_ON_FORK an rt parent's child is SCHED_NORMAL nice
/// 0, and a negative nice becomes 0
fn sched_fork(t: &Task, me: &Cur) {
    // One setting of the parameters (one load)
    let p = me.se.params();
    let (mut policy, mut prio, mut rt) = (p.policy(), p.static_prio(), p.rt_priority());
    if me.se.reset_on_fork() {
        if crate::task::is_rt_policy(policy) {
            (policy, prio, rt) = (crate::task::SCHED_NORMAL, sched::DEFAULT_PRIO, 0);
        } else if prio < sched::DEFAULT_PRIO {
            prio = sched::DEFAULT_PRIO;
        }
    }
    t.se.set_params(policy_class(policy), policy, prio, rt);
}

/// Linux copy_mm: the child's address space, shared for CLONE_VM, else
/// a copy (dup_mm), and the page table it runs on
fn copy_mm<FA: FrameAlloc<PhysAddr = u64>>(
    t: &mut Task,
    me: &Cur,
    flags: u64,
    frame_alloc: &mut FA,
) -> KernelResult<()> {
    let mm = match me.mm_ref() {
        None => return Ok(()),
        Some(pm) if flags & crate::task::clone_flags::CLONE_VM != 0 => pm,
        Some(pm) => {
            let mut pt = ArchPageTable::new_user(frame_alloc).ok_or(KernelError::OutOfMemory)?;
            pt.copy_kernel_mappings();
            crate::mm::dup_mm(&pm, pt.root_table_phys())?
        }
    };
    if let Some(inner) = t.inner.get_mut() {
        inner.pgd = mm.pgd();
    }
    *t.mm.get_mut() = Some(mm);
    Ok(())
}

/// Linux copy_thread: the child's user registers, those of the
/// caller's syscall returning 0 on its own stack unless it shares the
/// caller's (fork: child_stack 0), its inherited FP/SIMD state, the
/// context its first switch starts from, and its TLS and GS bases
fn copy_thread(t: &Task, config: &CloneConfig) -> KernelResult<()> {
    use crate::arch::Arch;
    use crate::task::clone_flags::CLONE_SETTLS;
    // A TLS base the register cannot take (Linux set_new_tls ->
    // do_arch_prctl_64)
    if config.flags & CLONE_SETTLS != 0 && !crate::arch::user_tls_ok(config.tls) {
        return Err(KernelError::NotPermitted);
    }
    // The TrapFrame at the top of the child's kernel stack (its
    // pt_regs), the inherited FP/SIMD state below it if the arch keeps
    // that apart (loaded by clone_child_entry before it returns to user
    // mode)
    let trapframe_size = core::mem::size_of::<<CurrentArch as Arch>::TrapFrame>() as u64;
    let trapframe_ptr = t.kstack_top - trapframe_size;
    // Every user register (Linux *childregs = *current_pt_regs()),
    // copied straight onto the child's kernel stack: through this frame
    // it would cost the whole frame, FP/SIMD state included, of stack
    let tf_ptr = trapframe_ptr as *mut <CurrentArch as Arch>::TrapFrame;
    // SAFETY: the parent's frame (ours, running) into the TrapFrame slot
    // at the top of the child's new kernel stack, which nothing else
    // reaches before the child runs; plain registers, no drop
    unsafe { core::ptr::copy_nonoverlapping(current_pt_regs().as_ptr(), tf_ptr, 1) };
    // SAFETY: the child's frame, written just above, reached only here
    // until the child runs
    let child_regs = unsafe { crate::arch::UserFrame::from_ptr(tf_ptr) };
    child_regs.set_ret(0);
    if config.child_stack != 0 {
        child_regs.set_sp(config.child_stack);
    }
    // The context its first switch starts from: clone_child_entry, its
    // frame below the TrapFrame and the saved FP state
    // SAFETY: the child's TrapFrame, on its new kernel stack (not run)
    let frame_top = unsafe { CurrentArch::clone_child_fpu(trapframe_ptr) };
    // An io thread starts in the kernel, at its function (Linux
    // copy_thread with args->fn); a user one returns to user mode
    let context = if config.io_thread.is_some() {
        CurrentArch::new_kernel_thread_context(io_thread_entry as *const () as usize, t.kstack_top)
    } else {
        CurrentArch::new_clone_child_context(frame_top)
    };
    // SAFETY: not on a run queue yet
    unsafe { *t.se.ctx() = context };
    // CLONE_SETTLS: its TLS pointer, loaded by clone_child_entry into
    // the arch's register (FS base on x86_64, TPIDR_EL0 on aarch64);
    // else the parent's, as every other user register (Linux
    // copy_thread: fsbase / tpidr_el0) ...
    let tls = if config.flags & CLONE_SETTLS != 0 {
        config.tls
    } else {
        crate::arch::read_user_tls()
    };
    t.tls.store(tls, Ordering::Relaxed);
    // ... and its user GS base (Linux copy_thread: gsbase)
    t.gsbase
        .store(crate::arch::read_user_gsbase(), Ordering::Relaxed);
    Ok(())
}

/// Linux alloc_pid for the child: its struct pid, numbered in each
/// level of its pid namespace (the one its creator makes children in,
/// a new one with CLONE_NEWPID: Linux p->nsproxy->pid_ns_for_children);
/// EAGAIN with no number left, ENOMEM. A new process's pid is its tid
/// (leader pid == tid), a thread keeps its group's.
fn fork_pid(
    t: &mut Task,
    ns: &crate::ns::NsProxy,
    config: &CloneConfig,
) -> KernelResult<Arc<crate::task::pid::Pid>> {
    let set_tid = &config.set_tid[..config.set_tid_size];
    check_set_tid(&ns.pid_ns, set_tid)?;
    let pid = crate::task::pid::alloc_pid_nr(&ns.pid_ns, set_tid)?;
    let tid = Tid::from(pid.nr());
    *t.tid.get_mut() = tid;
    if config.flags & crate::task::clone_flags::CLONE_THREAD == 0 {
        t.pid = tid;
    }
    t.pid_ns = Some(pid.ns().clone());
    t.thread_pid = crate::sync::rcu::RcuLockedArc::new(Some(pid.clone()));
    Ok(pid)
}

/// Linux copy_process: the child, a copy of the caller (dup_task_struct)
/// given its own or shared credentials, files, fs context, signal
/// state, memory, namespaces, I/O context, registers and pid, in
/// Linux's order, then listed. An error drops what was made so far:
/// the unlisted task with its parts, and the guards (pid numbers,
/// RLIMIT_NPROC charge, cgroup charge, pidfd reservation) give theirs
/// back (Linux's bad_fork_* labels). Returns the task, not yet running,
/// and its tid.
fn copy_process<FA: FrameAlloc<PhysAddr = u64>>(
    config: &CloneConfig,
    frame_alloc: &mut FA,
) -> KernelResult<(TaskRef, Tid)> {
    use crate::task::clone_flags::*;

    let me = current();
    let current_tid = current_tid();
    clone_flags_ok(config, &me)?;

    // Signals that came before this point are handled before the fork
    // (ERESTARTNOINTR: it restarts after them); multiprocess ones sent
    // from now on are delayed for the child
    let delay = crate::signal::fork_signals_begin(&me, config.flags & CLONE_THREAD != 0)?;

    let mut child_task = dup_task_struct(&me, config)?;
    let t = Arc::get_mut(&mut child_task).expect("copy_process: an unlisted task is unshared");
    let nproc = fork_creds(t, &me, config.flags)?;
    sched_fork(t, &me);
    // CLONE_SYSVSEM shares the parent's undo list, made now if it has
    // none (Linux copy_semundo's get_undo_list): SEM_UNDO from either
    // side then lands in the one list
    if config.flags & CLONE_SYSVSEM != 0 {
        crate::ipc::sem::get_or_create_undo_list(&me)?;
    }
    // Its files and fs context, installed once it is listed
    let child_files = crate::task::fdtable::fork_task_fd(config.flags & CLONE_FILES != 0)?;
    let child_fs = crate::fs::fsstruct::fork_fs(config.flags & CLONE_FS != 0)?;
    // copy_sighand, copy_signal
    let (child_sig, child_signal) = crate::signal::fork_signal(
        &me,
        config.flags & CLONE_SIGHAND != 0,
        config.flags & CLONE_THREAD != 0,
        config.flags & CLONE_CLEAR_SIGHAND != 0,
        config.flags & (CLONE_VM | CLONE_VFORK) == CLONE_VM,
    )?;
    *t.sig.get_mut() = child_sig;
    copy_mm(t, &me, config.flags, frame_alloc)?;
    // Its namespaces (a new mount namespace moves its fs context),
    // installed once it is listed; its credentials' user namespace: a
    // new one with CLONE_NEWUSER (Linux copy_creds -> create_user_ns)
    let child_ns = crate::ns::fork_nsproxy(config.flags, child_fs.as_deref())?;
    if let Some(inner) = t.inner.get_mut() {
        inner.user_ns = Some(child_ns.user_ns.clone());
    }
    // copy_io
    let child_io = if config.flags & CLONE_IO != 0 {
        Some(crate::task::fork_io(true)?)
    } else {
        None
    };
    copy_thread(t, config)?;
    let child_thread_pid = fork_pid(t, &child_ns, config)?;
    // Its numbers go back if the fork fails (Linux bad_fork_free_pid)
    let new_pid = crate::task::pid::NewPid::new(&child_thread_pid);
    let child_tid = Tid::from(child_thread_pid.nr());
    // A new process numbered 1 is its namespace's init (Linux
    // copy_process: is_child_reaper)
    let child_init = config.flags & CLONE_THREAD == 0 && child_thread_pid.is_child_reaper();
    if child_init {
        child_signal.set_unkillable();
    }

    // CLONE_PIDFD: the child's pidfd descriptor is reserved in the
    // caller's table and its number stored before the child exists; the
    // file is installed past the point of no return, so a failure
    // releases the reservation and leaves no descriptor (Linux
    // copy_process: pidfd_prepare and put_user, bad_fork_put_pidfd,
    // fd_install at the end)
    let pidfd = if config.flags & CLONE_PIDFD != 0 {
        Some(clone_pidfd(
            child_thread_pid,
            config.flags & CLONE_THREAD != 0,
            config.pidfd_ptr,
        )?)
    } else {
        None
    };
    // Admitted into the target cgroup now (Linux cgroup_can_fork: a bad
    // fd is EBADF, the pids limit is charged here, EAGAIN past it); an
    // error below gives the charge back when `fork_cg` drops
    let into_cgroup = if config.flags & CLONE_INTO_CGROUP != 0 {
        Some(crate::task::cgroup_from_fd(config.cgroup_fd)?)
    } else {
        None
    };
    let fork_cg = crate::cgroup::can_fork(into_cgroup)?;

    crate::signal::fork_cpu_watch(&child_task, &child_signal);
    // Add to global task table
    {
        let mut table = TASKLIST.write();
        // Not into a namespace whose init died meanwhile (Linux
        // copy_process: PIDNS_ADDING under tasklist_lock, ENOMEM): its
        // zap walks the list after disabling allocation, so it sees
        // this child or this sees the namespace dying
        if !crate::task::pid::ns_adding(child_task.pid_ns()) {
            drop(table);
            // The reservation goes with `pidfd` (put_unused_fd)
            return Err(KernelError::OutOfMemory);
        }
        // A fatal signal ends the fork here: the caller dies, and its
        // child must not slip out of the kill (Linux copy_process:
        // fatal_signal_pending under siglock, EINTR)
        if crate::signal::task_fatal_pending(&me) {
            drop(table);
            return Err(KernelError::Interrupted);
        }
        if child_init {
            crate::task::pidns::attach_init(&mut table, &child_task);
        }
        // CLONE_PARENT/CLONE_THREAD: the caller's real parent and its
        // exec id as they are now, under the write lock (Linux
        // copy_process): a reparent since the snapshot above moved the
        // caller to its reaper, never to a gone parent
        if config.flags & (CLONE_PARENT | CLONE_THREAD) != 0 {
            let cur = table
                .view(&me)
                .map(|v| (v.real_parent().map(task_ref), v.parent_exec_id));
            if let Some((rp, eid)) = cur {
                child_task.set_parent(rp.as_deref(), &mut table);
                table.inner_mut_of(&child_task).parent_exec_id = eid;
            }
        } else if table.view(&me).is_some() {
            // Else the caller (Linux copy_process: p->real_parent =
            // current), listed
            child_task.set_parent(Some(&*me), &mut table);
        }
        table.inherit_pids(&child_task, &current());
        table.insert(child_task.clone());
        new_pid.attached();
        // Its handlers and group state, in the section that lists it
        // (Linux copy_process: visible with its sighand and signal)
        crate::signal::install_fork_signal(&mut table, &child_task, child_signal, delay);
        // CLONE_PTRACE: traced as the caller is now, by its tracer
        // (Linux ptrace_init_task under tasklist_lock: never a tracer
        // that has detached its tracees on its way out)
        if config.flags & (CLONE_PTRACE | CLONE_UNTRACED) == CLONE_PTRACE {
            let cur = table
                .view(&me)
                .filter(|v| v.task.ptrace() != 0)
                .and_then(|v| Some((v.task.ptrace(), task_ref(v.tracer()?))));
            if let Some((pt, tr)) = cur
                && let Some(mut c) = table.view_mut(&child_task)
            {
                c.set_ptrace(pt);
                c.set_tracer(Some(&tr));
            }
        }
        // A new thread joins a group stop in progress or in effect
        // (Linux copy_process: task_join_group_stop under siglock)
        if config.flags & CLONE_THREAD != 0 {
            crate::signal::stop::join_group_stop(&me, &child_task);
        }
        // A new process joins its real parent's children (Linux: only
        // group leaders are on children lists)
        if config.flags & CLONE_THREAD == 0 {
            table.link_child(&child_task);
        }
    }

    // Its fs context (CLONE_FS: the parent's, cwd changes affect both;
    // else a copy)
    if let Some(fs) = child_fs {
        crate::fs::fsstruct::install_fork_fs(&child_task, fs, config.flags & CLONE_FS != 0);
    }

    // Handle FD table (CLONE_FILES)
    // If CLONE_FILES is set, child shares parent's FD table
    // Otherwise, child gets an independent deep copy
    crate::task::fdtable::init_task_fd(&child_task, child_files);

    // Its namespaces (CLONE_NEW* flags), built above
    crate::ns::init_task_ns(&child_task, child_ns);

    // Its cgroup: the CLONE_INTO_CGROUP target, else the parent's,
    // charged above (Linux cgroup_post_fork)
    if let Some(fc) = fork_cg {
        fc.post_fork(&child_task);
    }

    // A thread cloned into a dying group dies too (its signal state was
    // attached in the listing section)
    if config.flags & CLONE_THREAD != 0 {
        crate::signal::zap_new_thread(&me, &child_task);
    }

    // Handle I/O context (CLONE_IO)
    // If CLONE_IO is set, child shares parent's I/O context (ioprio changes affect both)
    // Otherwise, child gets an independent copy with inherited ioprio value
    // NOTE: Only run when explicitly requested or basic fork
    if let Some(io) = child_io {
        crate::task::set_task_io_context(&child_task, io);
    }

    // Handle SysV semaphore undo list (CLONE_SYSVSEM)
    // If CLONE_SYSVSEM is set, child shares parent's semaphore undo list
    // Otherwise, child starts with no undo list (allocated on first SEM_UNDO operation)
    if config.flags & CLONE_SYSVSEM != 0 {
        crate::ipc::sem::clone_task_semundo(&me, &child_task, true);
    }

    // Handle CLONE_CHILD_SETTID: write child TID to child's address space
    // For threads (CLONE_VM set), parent and child share address space, so we can write now.
    // For fork (CLONE_VM not set), store for clone_child_entry to write in child's context.
    if config.flags & CLONE_CHILD_SETTID != 0 && config.child_tidptr != 0 {
        if config.flags & CLONE_VM != 0 {
            // Shared address space - write directly, the child's own
            // number in its namespace (Linux schedule_tail writes it)

            use crate::uaccess::put_user;
            let own = crate::task::pid::nr_ns(child_tid, child_task.pid_ns()) as i32;
            if put_user::<i32>(config.child_tidptr, own).is_err() {
                printkln!("CLONE: CLONE_CHILD_SETTID write failed");
            }
        } else {
            // Separate address space (fork) - store for clone_child_entry to write
            crate::task::set_set_child_tid(&child_task, config.child_tidptr);
        }
    }

    // Handle CLONE_CHILD_CLEARTID: store address to clear and wake on exit
    // This enables pthread_join to work by waking when thread exits
    if config.flags & CLONE_CHILD_CLEARTID != 0 && config.child_tidptr != 0 {
        crate::task::set_clear_child_tid(&child_task, config.child_tidptr);
    }

    // Nothing fails from here: the pidfd goes in its descriptor (Linux
    // copy_process: fd_install(pidfd, pidfile))
    if let Some((fd, file)) = pidfd {
        fd.install(file);
    }

    // The child exists now: its charge is released with it; the parent
    // forked within its limit (Linux clears PF_NPROC_EXCEEDED)
    nproc.keep();
    {
        if let Some(t) = TASKLIST.read().get(current_tid) {
            t.task.clear_flag(crate::task::pf::NPROC_EXCEEDED);
        }
    }

    // An io thread: its function, PF_IO_WORKER, every signal but
    // SIGKILL and SIGSTOP blocked (Linux copy_process with io_thread)
    if let Some(f) = config.io_thread.clone() {
        child_task.io_thread.call_once(|| f);
        child_task.set_flag(crate::task::pf::IO_WORKER);
        let mut keep = crate::signal::SigSet::new();
        keep.add(crate::signal::SIGKILL);
        keep.add(crate::signal::SIGSTOP);
        crate::signal::with_task_signal_state(&child_task, |s| {
            s.blocked = crate::signal::SigSet::from_bits(!keep.bits());
        });
        let mut name = [0u8; 16];
        io_thread_name(&mut name, current_tid);
        child_task.task_lock().set_comm(name);
    }
    Ok((child_task, child_tid))
}

/// CLONE_PIDFD: a close-on-exec descriptor reserved in the caller's
/// table and a pidfd of the child `pid` for it (a thread pidfd for a
/// new thread: Linux PIDFD_THREAD), the number stored at `ptr` (Linux
/// pidfd_prepare, put_user): EMFILE, ENOMEM, EFAULT. Installed once the
/// clone cannot fail; dropped before, the reservation is released.
fn clone_pidfd(
    pid: Arc<crate::task::pid::Pid>,
    thread: bool,
    ptr: u64,
) -> KernelResult<(crate::task::fdtable::UnusedFd, crate::fs::FileRef)> {
    use crate::task::pidfd::pidfd_flags::PIDFD_THREAD;
    let flags = if thread { PIDFD_THREAD } else { 0 };
    let fd = crate::fs::io::get_unused_fd_flags(crate::task::FD_CLOEXEC)?;
    let file = crate::task::pidfd::pidfd_file(pid, flags)?;
    crate::uaccess::put_user::<i32>(ptr, fd.fd()).map_err(|_| KernelError::BadAddress)?;
    Ok((fd, file))
}

/// Start a thread of the current task's process that runs `f(arg)` in
/// the kernel and never returns to user mode (Linux create_io_thread):
/// it shares the mm, files, fs context, signal handlers and I/O context
/// (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
/// CLONE_IO, untraced), is PF_IO_WORKER (no ptrace attach), blocks every
/// signal but SIGKILL and SIGSTOP, shows as `iou-wrk-<creator tid>` in
/// /proc, and exits when `f` returns
pub fn create_io_thread(
    f: fn(Arc<dyn core::any::Any + Send + Sync>),
    arg: Arc<dyn core::any::Any + Send + Sync>,
) -> KernelResult<Tid> {
    use crate::task::clone_flags::*;
    let config = CloneConfig {
        flags: CLONE_VM
            | CLONE_FS
            | CLONE_FILES
            | CLONE_SIGHAND
            | CLONE_THREAD
            | CLONE_IO
            | CLONE_UNTRACED,
        child_stack: 0,
        parent_tidptr: 0,
        child_tidptr: 0,
        tls: 0,
        pidfd_ptr: 0,
        exit_signal: crate::signal::ExitSignal::NONE,
        cgroup_fd: -1,
        set_tid: CloneConfig::NO_SET_TID,
        set_tid_size: 0,
        io_thread: Some((f, arg)),
    };
    let mut fa = crate::mm::frame_alloc::FrameAllocRef(&crate::FRAME_ALLOCATOR);
    do_clone(config, &mut fa)
}

/// First code an io thread runs: its function, then a thread exit
extern "C" fn io_thread_entry() -> ! {
    // The switch that started it left interrupts disabled
    CurrentArch::enable_interrupts();
    let work = current().io_thread.get().cloned();
    if let Some((f, arg)) = work {
        f(arg);
    }
    crate::task::proc::do_exit(0)
}

/// "iou-wrk-<tid>" (Linux io_wq_worker: "iou-wrk-%d"), cut to 15 bytes
fn io_thread_name(out: &mut [u8; 16], tid: Tid) {
    let mut n = 0;
    for &c in b"iou-wrk-" {
        out[n] = c;
        n += 1;
    }
    let mut digits = [0u8; 20];
    let (mut v, mut k) = (tid, 0);
    loop {
        digits[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    while k > 0 && n < 15 {
        k -= 1;
        out[n] = digits[k];
        n += 1;
    }
}
