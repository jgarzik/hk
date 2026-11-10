//! Ptrace syscall implementation
//!
//! Ptrace (process trace) allows one process to observe and control the execution
//! of another process, and to examine and change the tracee's memory and registers.
//! This is the foundation for debuggers (gdb), system call tracers (strace), etc.
//!
//! # Linux compatibility
//!
//! This implementation follows the Linux ptrace ABI for both x86-64 and aarch64.
//! Not all ptrace operations are implemented; this focuses on the core subset
//! needed for basic debugging and tracing.

use crate::signal::{self, SIGKILL, SIGSTOP, SIGTRAP, Signal};
use crate::task::percpu::TaskRef;
use crate::task::percpu::{self, TASKLIST};
use crate::task::{CAP_SYS_PTRACE, Pid, Task, TaskState, capable};
use crate::uaccess::{UserPtr, copy_to_user};
use crate::util::error::{KernelError, KernelResult};

// =============================================================================
// Ptrace request codes (from Linux include/uapi/linux/ptrace.h)
// =============================================================================

/// Indicate that this process is to be traced by its parent
pub const PTRACE_TRACEME: i64 = 0;
/// Read word at addr in tracee's memory
pub const PTRACE_PEEKTEXT: i64 = 1;
/// Read word at addr in tracee's memory (same as PEEKTEXT on Linux)
pub const PTRACE_PEEKDATA: i64 = 2;
/// Read word at addr in tracee's USER area
pub const PTRACE_PEEKUSER: i64 = 3;
/// Write word at addr in tracee's memory
pub const PTRACE_POKETEXT: i64 = 4;
/// Write word at addr in tracee's memory (same as POKETEXT on Linux)
pub const PTRACE_POKEDATA: i64 = 5;
/// Write word at addr in tracee's USER area
pub const PTRACE_POKEUSER: i64 = 6;
/// Continue the tracee
pub const PTRACE_CONT: i64 = 7;
/// Kill the tracee
pub const PTRACE_KILL: i64 = 8;
/// Single-step the tracee
pub const PTRACE_SINGLESTEP: i64 = 9;
/// Get all general-purpose registers (x86-64)
pub const PTRACE_GETREGS: i64 = 12;
/// Set all general-purpose registers (x86-64)
pub const PTRACE_SETREGS: i64 = 13;
/// Get floating-point registers (x86-64)
pub const PTRACE_GETFPREGS: i64 = 14;
/// Set floating-point registers (x86-64)
pub const PTRACE_SETFPREGS: i64 = 15;
/// Attach to a process
pub const PTRACE_ATTACH: i64 = 16;
/// Detach from a process
pub const PTRACE_DETACH: i64 = 17;
/// Continue but stop at next syscall entry/exit
pub const PTRACE_SYSCALL: i64 = 24;
/// Set ptrace options
pub const PTRACE_SETOPTIONS: i64 = 0x4200;
/// Get last event message
pub const PTRACE_GETEVENTMSG: i64 = 0x4201;
/// Get siginfo for last signal
pub const PTRACE_GETSIGINFO: i64 = 0x4202;
/// Set siginfo for next signal
pub const PTRACE_SETSIGINFO: i64 = 0x4203;
/// Get register set
pub const PTRACE_GETREGSET: i64 = 0x4204;
/// Set register set
pub const PTRACE_SETREGSET: i64 = 0x4205;
/// Attach without stopping the tracee
pub const PTRACE_SEIZE: i64 = 0x4206;
/// Interrupt tracee
pub const PTRACE_INTERRUPT: i64 = 0x4207;
/// Listen for events (after PTRACE_SEIZE)
pub const PTRACE_LISTEN: i64 = 0x4208;
/// Peek at siginfo
pub const PTRACE_PEEKSIGINFO: i64 = 0x4209;
/// Get seccomp filter metadata
pub const PTRACE_SECCOMP_GET_FILTER: i64 = 0x420c;
/// Get seccomp filter metadata
pub const PTRACE_SECCOMP_GET_METADATA: i64 = 0x420d;
/// Get syscall info
pub const PTRACE_GET_SYSCALL_INFO: i64 = 0x420e;
/// Get RSeq configuration
pub const PTRACE_GET_RSEQ_CONFIGURATION: i64 = 0x420f;
/// Set/clear syscall user dispatch config
pub const PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG: i64 = 0x4210;
/// Get syscall user dispatch config
pub const PTRACE_GET_SYSCALL_USER_DISPATCH_CONFIG: i64 = 0x4211;

// =============================================================================
// Ptrace flags (stored in task->ptrace)
// =============================================================================

/// Task is being ptraced
pub const PT_PTRACED: u32 = 1 << 0;
/// Task was seized (PTRACE_SEIZE vs PTRACE_ATTACH)
pub const PT_SEIZED: u32 = 1 << 1;
/// Syscall tracing active (PTRACE_SYSCALL)
pub const PT_SYSCALL_TRACE: u32 = 1 << 2;
/// Single-step mode active
pub const PT_SINGLESTEP: u32 = 1 << 3;

// =============================================================================
// Ptrace options (set via PTRACE_SETOPTIONS)
// =============================================================================

/// Add 0x80 to signal number on syscall stop
pub const PTRACE_O_TRACESYSGOOD: u32 = 1 << 0;
/// Stop on fork
pub const PTRACE_O_TRACEFORK: u32 = 1 << 1;
/// Stop on vfork
pub const PTRACE_O_TRACEVFORK: u32 = 1 << 2;
/// Stop on clone
pub const PTRACE_O_TRACECLONE: u32 = 1 << 3;
/// Stop on exec
pub const PTRACE_O_TRACEEXEC: u32 = 1 << 4;
/// Stop on vfork done
pub const PTRACE_O_TRACEVFORKDONE: u32 = 1 << 5;
/// Stop on exit
pub const PTRACE_O_TRACEEXIT: u32 = 1 << 6;
/// Stop on seccomp event
pub const PTRACE_O_TRACESECCOMP: u32 = 1 << 7;
/// Don't stop when tracee exits
pub const PTRACE_O_EXITKILL: u32 = 1 << 20;
/// Send SIGKILL to tracee if tracer exits
pub const PTRACE_O_SUSPEND_SECCOMP: u32 = 1 << 21;

/// All supported ptrace options
pub const PTRACE_O_MASK: u32 = PTRACE_O_TRACESYSGOOD
    | PTRACE_O_TRACEFORK
    | PTRACE_O_TRACEVFORK
    | PTRACE_O_TRACECLONE
    | PTRACE_O_TRACEEXEC
    | PTRACE_O_TRACEVFORKDONE
    | PTRACE_O_TRACEEXIT
    | PTRACE_O_TRACESECCOMP
    | PTRACE_O_EXITKILL
    | PTRACE_O_SUSPEND_SECCOMP;

// =============================================================================
// Ptrace events (reported via wait status)
// =============================================================================

/// Fork event
pub const PTRACE_EVENT_FORK: u32 = 1;
/// Vfork event
pub const PTRACE_EVENT_VFORK: u32 = 2;
/// Clone event
pub const PTRACE_EVENT_CLONE: u32 = 3;
/// Exec event
pub const PTRACE_EVENT_EXEC: u32 = 4;
/// Vfork done event
pub const PTRACE_EVENT_VFORK_DONE: u32 = 5;
/// Exit event
pub const PTRACE_EVENT_EXIT: u32 = 6;
/// Seccomp event
pub const PTRACE_EVENT_SECCOMP: u32 = 7;
/// Stop event (for PTRACE_INTERRUPT)
pub const PTRACE_EVENT_STOP: u32 = 128;

// =============================================================================
// Helper functions
// =============================================================================

/// May the caller attach to the target (Linux ptrace_attach ->
/// __ptrace_may_access, PTRACE_MODE_ATTACH_REALCREDS): [`may_access`]
/// with the caller's real ids
fn ptrace_may_access(t: &Task) -> bool {
    may_access_view(t, false)
}

/// Linux ptrace_attach's first refusals (EPERM): a kernel thread, or a
/// thread of the caller's own thread group
fn attach_refused(t: &Task) -> bool {
    let table = TASKLIST.read();
    table.view(t).is_none_or(|v| {
        // Not a kernel thread nor an io thread (Linux ptrace_attach:
        // PF_KTHREAD, PF_IO_WORKER)
        v.task.has_flag(crate::task::pf::KTHREAD)
            || v.task.has_flag(crate::task::pf::IO_WORKER)
            || v.task.pid == percpu::current_pid()
    })
}

/// The thread `pid` names in the caller's pid namespace (Linux
/// find_task_by_vpid): ESRCH if none
fn tracee(pid: Pid) -> KernelResult<TaskRef> {
    percpu::find_task_by_vpid(pid).ok_or(KernelError::NoProcess)
}

/// Check if tracee is stopped and caller is its tracer.
///
/// Most ptrace operations require the tracee to be in a ptrace-stop,
/// and switched out: its CPU may still be on its way out of it, with
/// its TLS and GS base not yet saved (Linux wait_task_inactive)
fn ptrace_check_attach(task: &TaskRef) -> KernelResult<Frozen> {
    {
        let mut table = TASKLIST.write();
        let mut target = table.view_mut(task).ok_or(KernelError::NoProcess)?;

        // Check if we are the tracer
        if !target.traced_by(&percpu::current()) {
            return Err(KernelError::NoProcess);
        }

        // In a ptrace stop, and not killed (Linux ptrace_freeze_traced):
        // the stop then stays until the request ends
        if !matches!(target.state, TaskState::Traced(_)) || signal::task_fatal_pending(task) {
            return Err(KernelError::NoProcess);
        }
        target.ptrace_frozen = true;
    }
    let frozen = Frozen(task.clone());
    if !percpu::wait_task_inactive(&frozen.0) {
        return Err(KernelError::NoProcess);
    }
    Ok(frozen)
}

/// A tracee its tracer's request holds in its ptrace stop (Linux
/// JOBCTL_PTRACE_FROZEN, set by ptrace_check_attach); dropped at the
/// end of the request, it lets go (Linux ptrace_unfreeze_traced): a
/// SIGKILL that came meanwhile ends the stop and wakes it
struct Frozen(TaskRef);

impl Drop for Frozen {
    fn drop(&mut self) {
        let killed = {
            let mut table = TASKLIST.write();
            let Some(mut t) = table.view_mut(&self.0) else {
                return;
            };
            t.ptrace_frozen = false;
            let killed = signal::task_fatal_pending(&self.0);
            if killed {
                t.end_trace_stop();
            }
            killed
        };
        // Also ends a sleep a SIGKILL could not (ptrace_stop sleeps
        // uninterruptibly while frozen with one pending)
        if killed {
            percpu::try_to_wake_up(&self.0, percpu::WakeMode::Any);
        }
    }
}

/// Task `t` is being traced
pub fn is_traced(t: &Task) -> bool {
    TASKLIST.read().view(t).is_some_and(|v| v.ptrace != 0)
}

// =============================================================================
// PTRACE_TRACEME implementation
// =============================================================================

/// PTRACE_TRACEME - indicate that this process is to be traced by its parent.
///
/// This must be called before exec() to allow the parent to trace the child.
fn ptrace_traceme() -> KernelResult<i64> {
    let me = percpu::current();

    let mut table = TASKLIST.write();
    let mut task = table.view_mut(&me).ok_or(KernelError::NoProcess)?;

    // Already being traced?
    if task.ptrace != 0 {
        return Err(KernelError::NotPermitted);
    }

    // Set up tracing - parent becomes tracer
    task.ptrace = PT_PTRACED;
    task.ptracer = task.real_parent.clone();

    Ok(0)
}

// =============================================================================
// PTRACE_ATTACH implementation
// =============================================================================

/// PTRACE_ATTACH - attach to a process for tracing.
///
/// This sends SIGSTOP to the target and makes the caller the tracer.
fn ptrace_attach(target_pid: Pid) -> KernelResult<i64> {
    let task = tracee(target_pid)?;

    if attach_refused(&task) {
        return Err(KernelError::NotPermitted);
    }

    // Check permissions and attach under the target's cred_guard_mutex
    // (Linux ptrace_attach): no exec of it changes its dumpability between
    let _guard = crate::signal::CredGuard::lock(&task)?;
    if !ptrace_may_access(&task) {
        return Err(KernelError::NotPermitted);
    }

    {
        let mut table = TASKLIST.write();
        let mut target = table.view_mut(&task).ok_or(KernelError::NoProcess)?;

        // Already being traced?
        if target.ptrace != 0 {
            return Err(KernelError::NotPermitted);
        }

        // Set up tracing
        target.ptrace = PT_PTRACED;
        target.ptracer = Some(alloc::sync::Arc::downgrade(&percpu::task_ref(
            &percpu::current(),
        )));
    }

    // Send SIGSTOP to the target to stop it (Linux ptrace_attach:
    // SEND_SIG_PRIV)
    let _ = signal::send_sig_info(&task, SIGSTOP, signal::SendInfo::Kernel);

    Ok(0)
}

// =============================================================================
// PTRACE_SEIZE implementation
// =============================================================================

/// PTRACE_SEIZE - attach to a process without stopping it.
///
/// Similar to PTRACE_ATTACH but doesn't send SIGSTOP. The tracee continues
/// running until it hits a stop event or the tracer uses PTRACE_INTERRUPT.
fn ptrace_seize(target_pid: Pid, options: u32) -> KernelResult<i64> {
    // Validate options
    if options & !PTRACE_O_MASK != 0 {
        return Err(KernelError::InvalidArgument);
    }

    let task = tracee(target_pid)?;

    if attach_refused(&task) {
        return Err(KernelError::NotPermitted);
    }

    // Check permissions and attach under the target's cred_guard_mutex
    // (Linux ptrace_attach): no exec of it changes its dumpability between
    let _guard = crate::signal::CredGuard::lock(&task)?;
    if !ptrace_may_access(&task) {
        return Err(KernelError::NotPermitted);
    }

    {
        let mut table = TASKLIST.write();
        let mut target = table.view_mut(&task).ok_or(KernelError::NoProcess)?;

        // Already being traced?
        if target.ptrace != 0 {
            return Err(KernelError::NotPermitted);
        }

        // Set up tracing with SEIZED flag
        target.ptrace = PT_PTRACED | PT_SEIZED;
        target.ptracer = Some(alloc::sync::Arc::downgrade(&percpu::task_ref(
            &percpu::current(),
        )));
        target.ptrace_options = options;
    }

    // Don't send SIGSTOP - tracee continues running

    Ok(0)
}

// =============================================================================
// PTRACE_DETACH implementation
// =============================================================================

/// PTRACE_DETACH - detach from a traced process.
///
/// The tracee is continued with an optional signal (its low 32 bits,
/// Linux ptrace_detach's unsigned int): EIO past NSIG.
fn ptrace_detach(target_pid: Pid, signal: u32) -> KernelResult<i64> {
    let task = tracee(target_pid)?;

    // Verify we are the tracer
    let _frozen = ptrace_check_attach(&task)?;
    let sig = resume_sig(u64::from(signal))?;

    {
        let mut table = TASKLIST.write();
        let mut t = table.view_mut(&task).ok_or(KernelError::NoProcess)?;
        ptrace_unlink(&mut t);
    }
    crate::arch::ptrace::disable_single_step(&task);

    // Resume it, delivering `signal` (Linux ptrace_detach: exit_code)
    ptrace_wake(&task, sig);
    Ok(0)
}

/// A resume's signal argument (Linux valid_signal): None for 0, EIO
/// past NSIG
fn resume_sig(data: u64) -> KernelResult<Option<Signal>> {
    signal::valid_signal(data).ok_or(KernelError::Io)
}

/// Let a stopped tracee go on with `sig` to deliver (Linux
/// ptrace_resume: exit_code, wake_up_state(__TASK_TRACED))
fn ptrace_wake(task: &TaskRef, sig: Option<Signal>) {
    {
        let mut table = TASKLIST.write();
        let Some(mut t) = table.view_mut(task) else {
            return;
        };
        if !matches!(t.state, TaskState::Traced(_)) {
            return;
        }
        t.state = TaskState::Ready;
        t.ptrace_frozen = false;
        t.ptrace_code = sig.map_or(0, Signal::nr);
    }
    percpu::try_to_wake_up(task, percpu::WakeMode::Any);
}

// =============================================================================
// PTRACE_CONT / PTRACE_SYSCALL / PTRACE_SINGLESTEP implementation
// =============================================================================

/// Resume execution of a traced process.
///
/// # Arguments
/// * `target_pid` - PID of the tracee
/// * `request` - PTRACE_CONT, PTRACE_SYSCALL, or PTRACE_SINGLESTEP
/// * `signal` - Signal to inject (0 for none; EIO past NSIG, the whole
///   word: Linux ptrace_resume)
fn ptrace_resume(target_pid: Pid, request: i64, signal: u64) -> KernelResult<i64> {
    let task = tracee(target_pid)?;

    // Verify we are the tracer and tracee is stopped
    let _frozen = ptrace_check_attach(&task)?;
    let sig = resume_sig(signal)?;

    {
        let mut table = TASKLIST.write();
        let mut target = table.view_mut(&task).ok_or(KernelError::NoProcess)?;

        // Update ptrace flags based on request
        use crate::task::tif::SYSCALL_TRACE;
        match request {
            PTRACE_CONT => {
                target.ptrace &= !(PT_SYSCALL_TRACE | PT_SINGLESTEP);
                target.task.clear_tif(SYSCALL_TRACE);
            }
            PTRACE_SYSCALL => {
                target.ptrace |= PT_SYSCALL_TRACE;
                target.ptrace &= !PT_SINGLESTEP;
                target.task.set_tif(SYSCALL_TRACE);
            }
            PTRACE_SINGLESTEP => {
                target.ptrace |= PT_SINGLESTEP;
                target.ptrace &= !PT_SYSCALL_TRACE;
                target.task.clear_tif(SYSCALL_TRACE);
            }
            _ => return Err(KernelError::InvalidArgument),
        }
    }

    // The trap flag (these take TASKLIST themselves)
    if request == PTRACE_SINGLESTEP {
        crate::arch::ptrace::enable_single_step(&task);
    } else {
        crate::arch::ptrace::disable_single_step(&task);
    }

    ptrace_wake(&task, sig);
    Ok(0)
}

// =============================================================================
// PTRACE_KILL implementation
// =============================================================================

/// PTRACE_KILL - kill a traced process (deprecated, use PTRACE_CONT with SIGKILL).
fn ptrace_kill(target_pid: Pid) -> KernelResult<i64> {
    let task = tracee(target_pid)?;

    // Verify we are the tracer
    {
        let table = TASKLIST.read();
        let target = table.view(&task).ok_or(KernelError::NoProcess)?;

        if !target.traced_by(&percpu::current()) {
            return Err(KernelError::NoProcess);
        }
    }

    // Send SIGKILL
    let _ = signal::send_signal(&task, SIGKILL);

    Ok(0)
}

// =============================================================================
// PTRACE_PEEKDATA / PTRACE_POKEDATA implementation
// =============================================================================

/// The tracer may read and write the tracee's memory (Linux
/// ptrace_access_vm): its mm is dumpable, or the tracer has
/// CAP_SYS_PTRACE. A tracee that became non-dumpable after the attach
/// (setuid, PR_SET_DUMPABLE) keeps its memory.
fn may_access_vm(mm: &crate::mm::MmRef) -> bool {
    use crate::task::dumpable::SUID_DUMP_USER;
    mm.dumpable() == SUID_DUMP_USER || capable(CAP_SYS_PTRACE)
}

/// Read a word from tracee's memory.
fn ptrace_peek_data(target_pid: Pid, addr: u64, data: u64) -> KernelResult<i64> {
    let task = tracee(target_pid)?;

    // Verify we are the tracer
    let _frozen = ptrace_check_attach(&task)?;

    // A user reference: the address space cannot be torn down while we
    // access it (Linux get_task_mm)
    let Some(target_mm) = crate::mm::get_task_mm_users(&task) else {
        return Err(KernelError::NoProcess);
    };
    if !may_access_vm(&target_mm) {
        return Err(KernelError::Io);
    }

    // Forced, as Linux ptrace_access_vm (FOLL_FORCE): any mapping reads
    let mut buf = [0u8; 8];
    match crate::mm::remote::access_remote_vm_read(&target_mm, addr, &mut buf, true) {
        // The raw syscall stores the word at `data` and returns 0
        // (Linux generic_ptrace_peekdata; libc returns the word)
        Ok(8) => {
            UserPtr::<u64>::new(data).write(&u64::from_ne_bytes(buf))?;
            Ok(0)
        }
        _ => Err(KernelError::Io),
    }
}

/// Write a word to tracee's memory.
fn ptrace_poke_data(target_pid: Pid, addr: u64, data: u64) -> KernelResult<i64> {
    let task = tracee(target_pid)?;

    // Verify we are the tracer
    let _frozen = ptrace_check_attach(&task)?;

    // A user reference: the address space cannot be torn down while we
    // access it (Linux get_task_mm)
    let Some(target_mm) = crate::mm::get_task_mm_users(&task) else {
        return Err(KernelError::NoProcess);
    };
    if !may_access_vm(&target_mm) {
        return Err(KernelError::Io);
    }

    // Forced (FOLL_FORCE): a private read-only mapping, program text
    // for a breakpoint, gets its own read-only copy
    let buf = data.to_ne_bytes();
    match crate::mm::remote::access_remote_vm_write(&target_mm, addr, &buf, true) {
        Ok(8) => Ok(0),
        _ => Err(KernelError::Io),
    }
}

// =============================================================================
// PTRACE_SETOPTIONS implementation
// =============================================================================

/// Set ptrace options for a tracee.
fn ptrace_setoptions(target_pid: Pid, options: u32) -> KernelResult<i64> {
    // Validate options
    if options & !PTRACE_O_MASK != 0 {
        return Err(KernelError::InvalidArgument);
    }

    let task = tracee(target_pid)?;

    // Verify we are the tracer
    let _frozen = ptrace_check_attach(&task)?;

    {
        let mut table = TASKLIST.write();
        let mut target = table.view_mut(&task).ok_or(KernelError::NoProcess)?;

        target.ptrace_options = options;
    }

    Ok(0)
}

// =============================================================================
// PTRACE_GETEVENTMSG implementation
// =============================================================================

/// Get the event message for the last ptrace event.
/// PTRACE_GETSIGINFO: the stopped tracee's stop siginfo to `data`
/// (Linux ptrace_getsiginfo): EINVAL if the stop has none
fn ptrace_getsiginfo(target_pid: Pid, data: u64) -> KernelResult<i64> {
    let task = tracee(target_pid)?;
    let _frozen = ptrace_check_attach(&task)?;
    let info = TASKLIST.read().view(&task).and_then(|t| t.last_siginfo);
    info.ok_or(KernelError::InvalidArgument)?
        .copy_to_user(data)?;
    Ok(0)
}

/// PTRACE_SETSIGINFO: replace the stopped tracee's stop siginfo with
/// the one at `data` (Linux ptrace_setsiginfo): what it delivers if the
/// tracer resumes it with that signal; EINVAL if the stop has none
fn ptrace_setsiginfo(target_pid: Pid, data: u64) -> KernelResult<i64> {
    let task = tracee(target_pid)?;
    let _frozen = ptrace_check_attach(&task)?;
    let info = crate::signal::SigInfo::copy_from_user(data)?;
    let mut table = TASKLIST.write();
    match table.view_mut(&task) {
        Some(mut t) if t.last_siginfo.is_some() => {
            t.last_siginfo = Some(info);
            Ok(0)
        }
        _ => Err(KernelError::InvalidArgument),
    }
}

/// PTRACE_PEEKSIGINFO: copy up to `nr` siginfo of the stopped tracee's
/// queued signals, from the `off`th, its own or (PTRACE_PEEKSIGINFO_SHARED)
/// its group's, to `data` (Linux ptrace_peek_siginfo): how many
fn ptrace_peeksiginfo(target_pid: Pid, addr: u64, data: u64) -> KernelResult<i64> {
    const PTRACE_PEEKSIGINFO_SHARED: u32 = 1;
    let task = tracee(target_pid)?;
    let _frozen = ptrace_check_attach(&task)?;
    // struct ptrace_peeksiginfo_args { u64 off; u32 flags; s32 nr; }
    let mut args = [0u8; 16];
    crate::uaccess::copy_from_user(&mut args, addr, 16)?;
    let off = u64::from_ne_bytes(args[..8].try_into().unwrap_or([0; 8]));
    let flags = u32::from_ne_bytes(args[8..12].try_into().unwrap_or([0; 4]));
    let nr = i32::from_ne_bytes(args[12..].try_into().unwrap_or([0; 4]));
    if flags & !PTRACE_PEEKSIGINFO_SHARED != 0 || nr < 0 {
        return Err(KernelError::InvalidArgument);
    }
    let shared = flags & PTRACE_PEEKSIGINFO_SHARED != 0;
    let mut copied = 0i64;
    for i in 0..u64::from(nr.unsigned_abs()) {
        let Some(n) = off.checked_add(i) else {
            break;
        };
        let info = signal::with_task_signal_state(&task, |s| {
            if shared {
                s.shared_pending.lock().nth(n)
            } else {
                s.pending.nth(n)
            }
        })
        .flatten();
        let Some(info) = info else {
            break;
        };
        let to = data.wrapping_add(i * 128);
        if info.copy_to_user(to).is_err() {
            return if copied > 0 {
                Ok(copied)
            } else {
                Err(KernelError::BadAddress)
            };
        }
        copied += 1;
        if crate::sync::waitqueue::signal_pending() {
            break;
        }
    }
    Ok(copied)
}

fn ptrace_geteventmsg(target_pid: Pid, data: u64) -> KernelResult<i64> {
    let task = tracee(target_pid)?;

    // Verify we are the tracer
    let _frozen = ptrace_check_attach(&task)?;

    let message = {
        let table = TASKLIST.read();
        table.view(&task).map(|t| t.ptrace_message).unwrap_or(0)
    };

    // Write message to user space
    let buf = message.to_ne_bytes();
    copy_to_user(data, &buf)?;

    Ok(0)
}

// =============================================================================
// PTRACE_GETREGS / PTRACE_SETREGS implementation
// =============================================================================

/// Get all general-purpose registers from tracee.
fn ptrace_getregs(target_pid: Pid, data: u64) -> KernelResult<i64> {
    let task = tracee(target_pid)?;

    // Verify we are the tracer
    let _frozen = ptrace_check_attach(&task)?;

    // Architecture-specific implementation
    let regs = crate::arch::ptrace::get_user_regs(&task)?;
    UserPtr::new(data).write(&regs)?;
    Ok(0)
}

/// Set all general-purpose registers for tracee.
fn ptrace_setregs(target_pid: Pid, data: u64) -> KernelResult<i64> {
    let task = tracee(target_pid)?;

    // Verify we are the tracer
    let _frozen = ptrace_check_attach(&task)?;

    let regs = UserPtr::<crate::arch::ptrace::UserRegs>::new(data).read()?;
    crate::arch::ptrace::set_user_regs(&task, &regs)?;
    Ok(0)
}

// =============================================================================
// Ptrace stop handling
// =============================================================================

/// Stop for the tracer (Linux ptrace_stop): the stop is reported to its
/// wait with `code`, and the task sleeps until the tracer resumes it,
/// detaches or exits, or SIGKILL. Returns the signal the tracer left to
/// deliver (none when killed); untraced, `code` read as one.
pub fn ptrace_stop(
    code: u32,
    info: Option<crate::signal::SigInfo>,
) -> (Option<Signal>, Option<crate::signal::SigInfo>) {
    use percpu::{SleepState, schedule, set_current_state};
    let me = percpu::current();
    let tracer = {
        let mut table = TASKLIST.write();
        let Some(mut t) = table.view_mut(&me) else {
            return (None, info);
        };
        if t.ptrace == 0 {
            return (Signal::new(code), info);
        }
        t.state = TaskState::Traced(code as i32);
        t.ptrace_frozen = false;
        t.ptrace_code = code;
        t.last_siginfo = info;
        // Asleep before the tracer can see the stop (Linux
        // set_special_state(TASK_TRACED) before notifying it): a tracer
        // on another CPU waits for us to switch out
        // (wait_task_inactive), and gives up on a Running tracee
        set_current_state(SleepState::Killable);
        t.tracer()
    };
    // The tracer's wait finds the stop; SIGCHLD tells it (Linux
    // do_notify_parent_cldstop, CLD_TRAPPED)
    super::proc::CHILD_EXIT_WQ.wake_all();
    if let Some(tr) = tracer {
        signal::notify::notify_tracer_trapped(&me, &tr, code);
    }
    loop {
        set_current_state(SleepState::Killable);
        let (st, frozen) = stop_state(&me);
        if !st {
            break;
        }
        if signal::fatal_signal_pending() {
            if !frozen {
                break;
            }
            // Killed inside a tracer's request: the stop stays until
            // the request ends, which wakes us (Linux: SIGKILL does not
            // wake a JOBCTL_PTRACE_FROZEN tracee); asleep first, then
            // checked, so that wakeup is never lost
            set_current_state(SleepState::Uninterruptible);
            if stop_state(&me) != (true, true) {
                continue;
            }
        }
        schedule();
    }
    set_current_state(SleepState::Running);
    let mut table = TASKLIST.write();
    let Some(mut t) = table.view_mut(&me) else {
        return (None, None);
    };
    // The stop's siginfo, as the tracer left it (Linux: last_siginfo
    // cleared after the stop)
    let info = t.last_siginfo.take();
    // Out of the stop: nothing holds it (Linux clears
    // JOBCTL_PTRACE_FROZEN with the stop)
    t.ptrace_frozen = false;
    // Killed while stopped: no longer reported, nothing delivered
    if matches!(t.state, TaskState::Traced(_)) {
        t.state = TaskState::Ready;
        t.ptrace_code = 0;
        return (None, info);
    }
    // A resume's signal (ptrace_wake)
    (Signal::new(core::mem::take(&mut t.ptrace_code)), info)
}

/// The current task is in a ptrace stop, and its tracer inside a
/// request on it (frozen)
fn stop_state(me: &Task) -> (bool, bool) {
    let table = TASKLIST.read();
    table.view(me).map_or((false, false), |t| {
        (matches!(t.state, TaskState::Traced(_)), t.ptrace_frozen)
    })
}

/// A PTRACE_SYSCALL stop at syscall entry or exit (Linux
/// ptrace_report_syscall): SIGTRAP, | 0x80 with PTRACE_O_TRACESYSGOOD; a
/// signal the tracer leaves is sent to the task
pub fn ptrace_report_syscall(entry: bool) {
    let me = percpu::current();
    let options = {
        let mut table = TASKLIST.write();
        let Some(mut t) = table.view_mut(&me) else {
            return;
        };
        if t.ptrace & PT_SYSCALL_TRACE == 0 {
            return;
        }
        t.ptrace_message = if entry { 1 } else { 2 };
        t.ptrace_options
    };
    let code = if options & PTRACE_O_TRACESYSGOOD != 0 {
        SIGTRAP.nr() | 0x80
    } else {
        SIGTRAP.nr()
    };
    // The stop's siginfo (Linux ptrace_do_notify): SIGTRAP, si_code the
    // stop code, from this thread
    let info = crate::signal::SigInfo::kill(
        SIGTRAP,
        code as i32,
        crate::task::pid::vnr(me.tid()) as i32,
        crate::task::current_cred().uid,
    );
    // Linux send_sig(exit_code, current, 1): SEND_SIG_PRIV
    if let (Some(sig), _) = ptrace_stop(code, Some(info)) {
        let _ = signal::send_sig_info(&me, sig, signal::SendInfo::Kernel);
    }
}

/// A traced task dequeued `sig` with `info` (not SIGKILL): the tracer
/// sees it first (Linux ptrace_signal) and may cancel it (None) or
/// change it
pub fn ptrace_signal(info: &mut crate::signal::SigInfo, sig: Signal) -> Option<Signal> {
    if !is_traced(&percpu::current()) {
        return Some(sig);
    }
    let (new, left) = ptrace_stop(sig.nr(), Some(*info));
    if let Some(i) = left {
        *info = i;
    }
    new
}

/// Task `t` is no longer traced (Linux __ptrace_unlink), under
/// TASKLIST's write lock (the view borrows it)
pub(crate) fn ptrace_unlink(t: &mut percpu::TaskViewMut<'_>) {
    t.ptrace = 0;
    t.ptrace_frozen = false;
    t.ptracer = None;
    t.ptrace_options = 0;
    t.task.clear_tif(crate::task::tif::SYSCALL_TRACE);
}

/// The exiting task's tracees are detached (Linux exit_ptrace), one per
/// TASKLIST write section: stopped ones go on, and PTRACE_O_EXITKILL
/// ones are killed; then the zombies ([`percpu::detach_zombies`])
pub fn exit_ptrace() {
    let me = percpu::current();
    // Most tasks trace nothing: look under the read lock first
    let traces = TASKLIST
        .read()
        .iter()
        .any(|t| t.ptrace != 0 && t.traced_by(&me));
    if !traces {
        return;
    }
    while let Some((t, kill)) = detach_live(&me) {
        if let Some(k) = kill {
            k.finish();
        }
        percpu::try_to_wake_up(&t, percpu::WakeMode::Any);
    }
    percpu::detach_zombies(&me);
}

/// [`exit_ptrace`]'s write section for one live tracee of `me`: an
/// EXITKILL one gets SIGKILL before it is detached and resumed (Linux
/// exit_ptrace: send_sig_info under tasklist_lock, then
/// __ptrace_detach), so it never runs untraced code first; the tracee
/// and the kill's wakeups, for after the lock
fn detach_live(me: &crate::task::Task) -> Option<(percpu::TaskRef, Option<signal::Posted>)> {
    let mut table = TASKLIST.write();
    let v = table
        .find(|t| t.ptrace != 0 && t.traced_by(me) && !matches!(t.state, TaskState::Zombie(_)))?;
    let exitkill = v.ptrace_options & PTRACE_O_EXITKILL != 0;
    let t = percpu::task_ref(v.task);
    let kill = if exitkill {
        signal::sigkill_held(&table, &t)
    } else {
        None
    };
    let mut v = table.view_mut(&t)?;
    ptrace_unlink(&mut v);
    v.end_trace_stop();
    Some((t, kill))
}

// =============================================================================
// Main ptrace syscall dispatcher
// =============================================================================

/// Main ptrace syscall entry point.
///
/// # Arguments
/// * `request` - Ptrace operation to perform
/// * `pid` - Target process ID (or 0 for TRACEME)
/// * `addr` - Address argument (operation-specific)
/// * `data` - Data argument (operation-specific)
///
/// # Returns
/// 0 on success, or negative error code.
/// For PEEKDATA/PEEKTEXT, the word goes to `data` (the raw syscall ABI).
pub fn sys_ptrace(request: i64, pid: i64, addr: u64, data: u64) -> KernelResult<i64> {
    match request {
        PTRACE_TRACEME => ptrace_traceme(),
        PTRACE_ATTACH => ptrace_attach(pid as Pid),
        PTRACE_SEIZE => ptrace_seize(pid as Pid, data as u32),
        PTRACE_DETACH => ptrace_detach(pid as Pid, data as u32),

        PTRACE_PEEKTEXT | PTRACE_PEEKDATA => ptrace_peek_data(pid as Pid, addr, data),
        PTRACE_POKETEXT | PTRACE_POKEDATA => ptrace_poke_data(pid as Pid, addr, data),

        PTRACE_CONT | PTRACE_SYSCALL | PTRACE_SINGLESTEP => {
            ptrace_resume(pid as Pid, request, data)
        }

        PTRACE_KILL => ptrace_kill(pid as Pid),

        PTRACE_SETOPTIONS => ptrace_setoptions(pid as Pid, data as u32),
        PTRACE_GETEVENTMSG => ptrace_geteventmsg(pid as Pid, data),

        PTRACE_GETSIGINFO => ptrace_getsiginfo(pid as Pid, data),
        PTRACE_SETSIGINFO => ptrace_setsiginfo(pid as Pid, data),
        PTRACE_PEEKSIGINFO => ptrace_peeksiginfo(pid as Pid, addr, data),

        PTRACE_GETREGS => ptrace_getregs(pid as Pid, data),
        PTRACE_SETREGS => ptrace_setregs(pid as Pid, data),

        // Not yet implemented
        PTRACE_PEEKUSER | PTRACE_POKEUSER | PTRACE_GETFPREGS | PTRACE_SETFPREGS
        | PTRACE_GETREGSET | PTRACE_SETREGSET | PTRACE_INTERRUPT | PTRACE_LISTEN => {
            Err(KernelError::InvalidArgument)
        }

        _ => ptrace_unknown(pid as Pid),
    }
}

/// A request ptrace does not know (Linux sys_ptrace: ptrace_check_attach,
/// then ptrace_request's default): ESRCH unless the caller traces `pid`
/// and it is stopped, else EIO; nothing is logged, a user can send any
/// number
fn ptrace_unknown(pid: Pid) -> KernelResult<i64> {
    let task = tracee(pid)?;
    let _frozen = ptrace_check_attach(&task)?;
    Err(KernelError::Io)
}

/// May the current task read process `pid`'s private state through
/// /proc (Linux __ptrace_may_access with PTRACE_MODE_READ_FSCREDS): its
/// own thread group always, else [`may_access`] with the caller's
/// fsuid/fsgid
pub fn may_read_proc(pid: crate::task::Pid) -> bool {
    if pid == percpu::current_pid() {
        return true;
    }
    may_access(|t| t.task.pid == pid, true)
}

/// Linux ptrace_may_access for task `t`: the caller's own thread
/// group always (Linux __ptrace_may_access: same_thread_group, even
/// once `t` is reaped), else [`may_access`] with its fsuid/fsgid
/// (`fscreds`, PTRACE_MODE_*_FSCREDS) or its real ids
/// (PTRACE_MODE_*_REALCREDS)
pub fn may_access_task(t: &Task, fscreds: bool) -> bool {
    same_thread_group(t) || may_access_view(t, fscreds)
}

/// Is `t` a thread of the caller's process (Linux same_thread_group:
/// the same signal_struct, which a task keeps until it is freed)
fn same_thread_group(t: &Task) -> bool {
    let me = percpu::current();
    match (t.cpu_group(), me.cpu_group()) {
        (Some(a), Some(b)) => alloc::sync::Arc::ptr_eq(a, b),
        _ => me.is(t),
    }
}

/// [`may_access`] for task `t` itself: false once it is reaped
fn may_access_view(t: &Task, fscreds: bool) -> bool {
    let target = TASKLIST.read().view(t).map(|v| access_ids(&v));
    access_ok(target, fscreds)
}

/// Linux __ptrace_may_access for the first task `pick` selects: the
/// caller's ids (fsuid/fsgid with `fscreds`, else the real ones) must
/// equal all of the target's real, effective and saved ids, or the
/// caller has CAP_SYS_PTRACE; and a non-dumpable target with an address
/// space needs CAP_SYS_PTRACE too (get_dumpable(mm) != SUID_DUMP_USER)
pub fn may_access(pick: impl Fn(&percpu::TaskView<'_>) -> bool, fscreds: bool) -> bool {
    let target = TASKLIST.read().find(|t| pick(t)).map(|v| access_ids(&v));
    access_ok(target, fscreds)
}

/// What the access check reads of a target (TASKLIST held): its
/// credentials and its address space's dumpability, if it has one
fn access_ids(v: &percpu::TaskView<'_>) -> (crate::task::Cred, Option<u8>) {
    (v.cred(), v.task.task_lock().mm().map(|m| m.dumpable()))
}

/// [`may_access`]'s decision on `target` ([`access_ids`]; None: no task)
fn access_ok(target: Option<(crate::task::Cred, Option<u8>)>, fscreds: bool) -> bool {
    use crate::task::dumpable::SUID_DUMP_USER;
    let me = percpu::current_cred();
    let Some((c, dumpable)) = target else {
        return false;
    };
    let cap = capable(CAP_SYS_PTRACE);
    let (u, g) = if fscreds {
        (me.fsuid, me.fsgid)
    } else {
        (me.uid, me.gid)
    };
    let ids = u == c.uid && u == c.euid && u == c.suid && g == c.gid && g == c.egid && g == c.sgid;
    if !ids && !cap {
        return false;
    }
    dumpable.is_none_or(|d| d == SUID_DUMP_USER) || cap
}
