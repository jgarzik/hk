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

use crate::signal::{self, SIGKILL, SIGSTOP, SIGTRAP};
use crate::task::percpu::{self, TASKLIST};
use crate::task::{CAP_SYS_PTRACE, Pid, TaskState, Tid, capable};
use crate::uaccess::{copy_from_user, copy_to_user};

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
// Error codes
// =============================================================================

const EPERM: i64 = 1;
const ESRCH: i64 = 3;
const EIO: i64 = 5;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;

// =============================================================================
// Helper functions
// =============================================================================

/// May the caller attach to the target (Linux ptrace_attach ->
/// __ptrace_may_access, PTRACE_MODE_ATTACH_REALCREDS): [`may_access`]
/// with the caller's real ids
fn ptrace_may_access(target_tid: Tid) -> bool {
    may_access(|t| t.task.tid() == target_tid, false)
}

/// Linux ptrace_attach's first refusals (EPERM): a kernel thread, or a
/// thread of the caller's own thread group
fn attach_refused(target_tid: Tid) -> bool {
    let table = TASKLIST.read();
    table.get(target_tid).is_none_or(|t| {
        t.task.has_flag(crate::task::pf::KTHREAD) || t.task.pid == percpu::current_pid()
    })
}

/// Check if tracee is stopped and caller is its tracer.
///
/// Most ptrace operations require the tracee to be in a ptrace-stop,
/// and switched out: its CPU may still be on its way out of it, with
/// its TLS and GS base not yet saved (Linux wait_task_inactive)
fn ptrace_check_attach(target_tid: Tid) -> Result<(), i64> {
    let task = {
        let table = TASKLIST.read();
        let target = table.get(target_tid).ok_or(-ESRCH)?;

        // Check if we are the tracer
        if !target.traced_by(&percpu::current()) {
            return Err(-ESRCH);
        }

        // Check if target is in ptrace stop
        if !matches!(target.state, TaskState::Traced(_)) {
            return Err(-ESRCH);
        }
        table.task(target_tid).ok_or(-ESRCH)?
    };
    if !percpu::wait_task_inactive(&task) {
        return Err(-ESRCH);
    }
    Ok(())
}

/// Find a task by PID (thread group leader)
fn find_task_by_pid(pid: Pid) -> Option<Tid> {
    let table = TASKLIST.read();
    table.get(pid).map(|t| t.task.tid())
}

/// Check if a task is being traced
pub fn is_traced(tid: Tid) -> bool {
    let table = TASKLIST.read();
    table.get(tid).map(|t| t.ptrace != 0).unwrap_or(false)
}

/// Check if syscall tracing is active for a task
pub fn has_syscall_trace(tid: Tid) -> bool {
    let table = TASKLIST.read();
    table
        .get(tid)
        .map(|t| t.ptrace & PT_SYSCALL_TRACE != 0)
        .unwrap_or(false)
}

/// Check if single-step is active for a task
pub fn has_singlestep(tid: Tid) -> bool {
    let table = TASKLIST.read();
    table
        .get(tid)
        .map(|t| t.ptrace & PT_SINGLESTEP != 0)
        .unwrap_or(false)
}

// =============================================================================
// PTRACE_TRACEME implementation
// =============================================================================

/// PTRACE_TRACEME - indicate that this process is to be traced by its parent.
///
/// This must be called before exec() to allow the parent to trace the child.
fn ptrace_traceme() -> i64 {
    let tid = percpu::current_tid();

    let mut table = TASKLIST.write();
    let mut task = match table.get_mut(tid) {
        Some(t) => t,
        None => return -ESRCH,
    };

    // Already being traced?
    if task.ptrace != 0 {
        return -EPERM;
    }

    // Set up tracing - parent becomes tracer
    task.ptrace = PT_PTRACED;
    task.ptracer = task.real_parent.clone();

    0
}

// =============================================================================
// PTRACE_ATTACH implementation
// =============================================================================

/// PTRACE_ATTACH - attach to a process for tracing.
///
/// This sends SIGSTOP to the target and makes the caller the tracer.
fn ptrace_attach(target_pid: Pid) -> i64 {
    let target_tid = match find_task_by_pid(target_pid) {
        Some(tid) => tid,
        None => return -ESRCH,
    };

    if attach_refused(target_tid) {
        return -EPERM;
    }

    // Check permissions and attach under the target's cred_guard_mutex
    // (Linux ptrace_attach): no exec of it changes its dumpability between
    let _guard = match crate::signal::CredGuard::lock(target_tid) {
        Ok(g) => g,
        Err(e) => return e.sysret(),
    };
    if !ptrace_may_access(target_tid) {
        return -EPERM;
    }

    {
        let mut table = TASKLIST.write();
        let mut target = match table.get_mut(target_tid) {
            Some(t) => t,
            None => return -ESRCH,
        };

        // Already being traced?
        if target.ptrace != 0 {
            return -EPERM;
        }

        // Set up tracing
        target.ptrace = PT_PTRACED;
        target.ptracer = Some(alloc::sync::Arc::downgrade(&percpu::task_ref(
            &percpu::current(),
        )));
    }

    // Send SIGSTOP to the target to stop it
    signal::send_signal(target_tid, SIGSTOP);

    0
}

// =============================================================================
// PTRACE_SEIZE implementation
// =============================================================================

/// PTRACE_SEIZE - attach to a process without stopping it.
///
/// Similar to PTRACE_ATTACH but doesn't send SIGSTOP. The tracee continues
/// running until it hits a stop event or the tracer uses PTRACE_INTERRUPT.
fn ptrace_seize(target_pid: Pid, options: u32) -> i64 {
    // Validate options
    if options & !PTRACE_O_MASK != 0 {
        return -EINVAL;
    }

    let target_tid = match find_task_by_pid(target_pid) {
        Some(tid) => tid,
        None => return -ESRCH,
    };

    if attach_refused(target_tid) {
        return -EPERM;
    }

    // Check permissions and attach under the target's cred_guard_mutex
    // (Linux ptrace_attach): no exec of it changes its dumpability between
    let _guard = match crate::signal::CredGuard::lock(target_tid) {
        Ok(g) => g,
        Err(e) => return e.sysret(),
    };
    if !ptrace_may_access(target_tid) {
        return -EPERM;
    }

    {
        let mut table = TASKLIST.write();
        let mut target = match table.get_mut(target_tid) {
            Some(t) => t,
            None => return -ESRCH,
        };

        // Already being traced?
        if target.ptrace != 0 {
            return -EPERM;
        }

        // Set up tracing with SEIZED flag
        target.ptrace = PT_PTRACED | PT_SEIZED;
        target.ptracer = Some(alloc::sync::Arc::downgrade(&percpu::task_ref(
            &percpu::current(),
        )));
        target.ptrace_options = options;
    }

    // Don't send SIGSTOP - tracee continues running

    0
}

// =============================================================================
// PTRACE_DETACH implementation
// =============================================================================

/// PTRACE_DETACH - detach from a traced process.
///
/// The tracee is continued with an optional signal.
fn ptrace_detach(target_pid: Pid, signal: u32) -> i64 {
    let target_tid = match find_task_by_pid(target_pid) {
        Some(tid) => tid,
        None => return -ESRCH,
    };

    // Verify we are the tracer
    if let Err(e) = ptrace_check_attach(target_tid) {
        return e;
    }

    {
        let mut table = TASKLIST.write();
        let mut target = match table.get_mut(target_tid) {
            Some(t) => t,
            None => return -ESRCH,
        };

        // Clear tracing state
        target.ptrace = 0;
        target.ptracer = None;
        target.ptrace_options = 0;
        target.task.clear_tif(crate::task::tif::SYSCALL_TRACE);
    }
    crate::arch::ptrace::disable_single_step(target_tid);

    // Resume it, delivering `signal` (Linux ptrace_detach: exit_code)
    ptrace_wake(target_tid, resume_sig(signal));
    0
}

/// A resume's signal argument: the signal to deliver, 0 for none
fn resume_sig(sig: u32) -> u32 {
    if sig < 65 { sig } else { 0 }
}

/// Let a stopped tracee go on with `sig` to deliver (Linux
/// ptrace_resume: exit_code, wake_up_state(__TASK_TRACED))
fn ptrace_wake(tid: Tid, sig: u32) {
    let task = {
        let mut table = TASKLIST.write();
        let Some(mut t) = table.get_mut(tid) else {
            return;
        };
        if !matches!(t.state, TaskState::Traced(_)) {
            return;
        }
        t.state = TaskState::Ready;
        t.ptrace_code = sig;
        table.task(tid)
    };
    if let Some(t) = task {
        percpu::try_to_wake_up(&t, percpu::WakeMode::Any);
    }
}

// =============================================================================
// PTRACE_CONT / PTRACE_SYSCALL / PTRACE_SINGLESTEP implementation
// =============================================================================

/// Resume execution of a traced process.
///
/// # Arguments
/// * `target_pid` - PID of the tracee
/// * `request` - PTRACE_CONT, PTRACE_SYSCALL, or PTRACE_SINGLESTEP
/// * `signal` - Signal to inject (0 for none)
fn ptrace_resume(target_pid: Pid, request: i64, signal: u32) -> i64 {
    let target_tid = match find_task_by_pid(target_pid) {
        Some(tid) => tid,
        None => return -ESRCH,
    };

    // Verify we are the tracer and tracee is stopped
    if let Err(e) = ptrace_check_attach(target_tid) {
        return e;
    }

    {
        let mut table = TASKLIST.write();
        let mut target = match table.get_mut(target_tid) {
            Some(t) => t,
            None => return -ESRCH,
        };

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
            _ => return -EINVAL,
        }
    }

    // The trap flag (these take TASKLIST themselves)
    if request == PTRACE_SINGLESTEP {
        crate::arch::ptrace::enable_single_step(target_tid);
    } else {
        crate::arch::ptrace::disable_single_step(target_tid);
    }

    ptrace_wake(target_tid, resume_sig(signal));
    0
}

// =============================================================================
// PTRACE_KILL implementation
// =============================================================================

/// PTRACE_KILL - kill a traced process (deprecated, use PTRACE_CONT with SIGKILL).
fn ptrace_kill(target_pid: Pid) -> i64 {
    let target_tid = match find_task_by_pid(target_pid) {
        Some(tid) => tid,
        None => return -ESRCH,
    };

    // Verify we are the tracer
    {
        let table = TASKLIST.read();
        let target = match table.get(target_tid) {
            Some(t) => t,
            None => return -ESRCH,
        };

        if !target.traced_by(&percpu::current()) {
            return -ESRCH;
        }
    }

    // Send SIGKILL
    signal::send_signal(target_tid, SIGKILL);

    0
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

/// Get target's memory descriptor and page table root
fn get_target_mm_and_pt(target_tid: Tid) -> Option<(crate::mm::MmRef, u64)> {
    // A user reference: the address space cannot be torn down while we
    // access it (Linux get_task_mm)
    let mm = crate::mm::get_task_mm_users(target_tid)?;
    let pgd = mm.pgd();
    Some((mm, pgd))
}

/// Read a word from tracee's memory.
fn ptrace_peek_data(target_pid: Pid, addr: u64, data: u64) -> i64 {
    let target_tid = match find_task_by_pid(target_pid) {
        Some(tid) => tid,
        None => return -ESRCH,
    };

    // Verify we are the tracer
    if let Err(e) = ptrace_check_attach(target_tid) {
        return e;
    }

    // Get target's mm and page table
    let (target_mm, _) = match get_target_mm_and_pt(target_tid) {
        Some(x) => x,
        None => return -ESRCH,
    };
    if !may_access_vm(&target_mm) {
        return -EIO;
    }

    // Lock mm and read from tracee
    let mm_guard = target_mm.mmap_read();
    let mut buf = [0u8; 8];
    match crate::mm::remote::access_remote_vm_read(&target_mm, &mm_guard, addr, &mut buf) {
        // The raw syscall stores the word at `data` and returns 0
        // (Linux generic_ptrace_peekdata; libc returns the word)
        Ok(8) => {
            drop(mm_guard);
            match crate::uaccess::put_user::<crate::arch::Uaccess, u64>(
                data,
                u64::from_ne_bytes(buf),
            ) {
                Ok(()) => 0,
                Err(_) => -EFAULT,
            }
        }
        _ => -EIO,
    }
}

/// Write a word to tracee's memory.
fn ptrace_poke_data(target_pid: Pid, addr: u64, data: u64) -> i64 {
    let target_tid = match find_task_by_pid(target_pid) {
        Some(tid) => tid,
        None => return -ESRCH,
    };

    // Verify we are the tracer
    if let Err(e) = ptrace_check_attach(target_tid) {
        return e;
    }

    // Get target's mm and page table
    let (target_mm, _) = match get_target_mm_and_pt(target_tid) {
        Some(x) => x,
        None => return -ESRCH,
    };
    if !may_access_vm(&target_mm) {
        return -EIO;
    }

    // Lock mm and write to tracee
    let mm_guard = target_mm.mmap_read();
    let buf = data.to_ne_bytes();
    match crate::mm::remote::access_remote_vm_write(&target_mm, &mm_guard, addr, &buf) {
        Ok(8) => 0,
        _ => -EIO,
    }
}

// =============================================================================
// PTRACE_SETOPTIONS implementation
// =============================================================================

/// Set ptrace options for a tracee.
fn ptrace_setoptions(target_pid: Pid, options: u32) -> i64 {
    // Validate options
    if options & !PTRACE_O_MASK != 0 {
        return -EINVAL;
    }

    let target_tid = match find_task_by_pid(target_pid) {
        Some(tid) => tid,
        None => return -ESRCH,
    };

    // Verify we are the tracer
    if let Err(e) = ptrace_check_attach(target_tid) {
        return e;
    }

    {
        let mut table = TASKLIST.write();
        let mut target = match table.get_mut(target_tid) {
            Some(t) => t,
            None => return -ESRCH,
        };

        target.ptrace_options = options;
    }

    0
}

// =============================================================================
// PTRACE_GETEVENTMSG implementation
// =============================================================================

/// Get the event message for the last ptrace event.
fn ptrace_geteventmsg(target_pid: Pid, data: u64) -> i64 {
    let target_tid = match find_task_by_pid(target_pid) {
        Some(tid) => tid,
        None => return -ESRCH,
    };

    // Verify we are the tracer
    if let Err(e) = ptrace_check_attach(target_tid) {
        return e;
    }

    let message = {
        let table = TASKLIST.read();
        table.get(target_tid).map(|t| t.ptrace_message).unwrap_or(0)
    };

    // Write message to user space
    let buf = message.to_ne_bytes();
    if copy_to_user::<crate::arch::Uaccess>(data, &buf).is_err() {
        return -EFAULT;
    }

    0
}

// =============================================================================
// PTRACE_GETREGS / PTRACE_SETREGS implementation
// =============================================================================

/// Get all general-purpose registers from tracee.
fn ptrace_getregs(target_pid: Pid, data: u64) -> i64 {
    let target_tid = match find_task_by_pid(target_pid) {
        Some(tid) => tid,
        None => return -ESRCH,
    };

    // Verify we are the tracer
    if let Err(e) = ptrace_check_attach(target_tid) {
        return e;
    }

    // Architecture-specific implementation
    match crate::arch::ptrace::get_user_regs(target_tid) {
        Ok(regs) => {
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    &regs as *const _ as *const u8,
                    core::mem::size_of_val(&regs),
                )
            };
            if copy_to_user::<crate::arch::Uaccess>(data, bytes).is_err() {
                return -EFAULT;
            }
            0
        }
        Err(e) => e as i64,
    }
}

/// Set all general-purpose registers for tracee.
fn ptrace_setregs(target_pid: Pid, data: u64) -> i64 {
    let target_tid = match find_task_by_pid(target_pid) {
        Some(tid) => tid,
        None => return -ESRCH,
    };

    // Verify we are the tracer
    if let Err(e) = ptrace_check_attach(target_tid) {
        return e;
    }

    // Architecture-specific implementation
    #[cfg(target_arch = "x86_64")]
    {
        let mut regs = crate::arch::ptrace::UserRegsStruct::default();
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                &mut regs as *mut _ as *mut u8,
                core::mem::size_of_val(&regs),
            )
        };
        if copy_from_user::<crate::arch::Uaccess>(bytes, data, bytes.len()).is_err() {
            return -EFAULT;
        }
        match crate::arch::ptrace::set_user_regs(target_tid, &regs) {
            Ok(()) => 0,
            Err(e) => e as i64,
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let mut regs = crate::arch::ptrace::UserPtRegs::default();
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                &mut regs as *mut _ as *mut u8,
                core::mem::size_of_val(&regs),
            )
        };
        if copy_from_user::<crate::arch::Uaccess>(bytes, data, bytes.len()).is_err() {
            return -EFAULT;
        }
        match crate::arch::ptrace::set_user_regs(target_tid, &regs) {
            Ok(()) => 0,
            Err(e) => e as i64,
        }
    }
}

// =============================================================================
// Ptrace stop handling
// =============================================================================

/// Stop for the tracer (Linux ptrace_stop): the stop is reported to its
/// wait with `code`, and the task sleeps until the tracer resumes it,
/// detaches or exits, or SIGKILL. Returns the signal the tracer left to
/// deliver (0: none; always 0 when killed).
pub fn ptrace_stop(code: u32) -> u32 {
    use percpu::{SleepState, schedule, set_current_state};
    let tid = percpu::current_tid();
    let tracer = {
        let mut table = TASKLIST.write();
        let Some(mut t) = table.get_mut(tid) else {
            return 0;
        };
        if t.ptrace == 0 {
            return code;
        }
        t.state = TaskState::Traced(code as i32);
        t.ptrace_code = code;
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
        signal::send_signal_to_process(tr.pid, signal::SIGCHLD);
    }
    loop {
        set_current_state(SleepState::Killable);
        if !stopped(tid) || signal::fatal_signal_pending() {
            break;
        }
        schedule();
    }
    set_current_state(SleepState::Running);
    let mut table = TASKLIST.write();
    let Some(mut t) = table.get_mut(tid) else {
        return 0;
    };
    // Killed while stopped: no longer reported, nothing delivered
    if matches!(t.state, TaskState::Traced(_)) {
        t.state = TaskState::Ready;
        t.ptrace_code = 0;
        return 0;
    }
    core::mem::take(&mut t.ptrace_code)
}

/// The current task is in a ptrace stop
fn stopped(tid: Tid) -> bool {
    let table = TASKLIST.read();
    table
        .get(tid)
        .is_some_and(|t| matches!(t.state, TaskState::Traced(_)))
}

/// A PTRACE_SYSCALL stop at syscall entry or exit (Linux
/// ptrace_report_syscall): SIGTRAP, | 0x80 with PTRACE_O_TRACESYSGOOD; a
/// signal the tracer leaves is sent to the task
pub fn ptrace_report_syscall(entry: bool) {
    let tid = percpu::current_tid();
    let options = {
        let mut table = TASKLIST.write();
        let Some(mut t) = table.get_mut(tid) else {
            return;
        };
        if t.ptrace & PT_SYSCALL_TRACE == 0 {
            return;
        }
        t.ptrace_message = if entry { 1 } else { 2 };
        t.ptrace_options
    };
    let code = if options & PTRACE_O_TRACESYSGOOD != 0 {
        SIGTRAP | 0x80
    } else {
        SIGTRAP
    };
    let sig = ptrace_stop(code);
    if sig != 0 {
        signal::send_signal(tid, sig);
    }
}

/// A traced task dequeued `sig` (not SIGKILL): the tracer sees it first
/// (Linux ptrace_signal) and may cancel it (0) or change it
pub fn ptrace_signal(sig: u32) -> u32 {
    if !is_traced(percpu::current_tid()) {
        return sig;
    }
    ptrace_stop(sig)
}

/// The exiting task's tracees are detached (Linux exit_ptrace): stopped
/// ones go on, and PTRACE_O_EXITKILL ones are killed
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
    let mut gone = alloc::vec::Vec::new();
    {
        let mut table = TASKLIST.write();
        let tids: alloc::vec::Vec<Tid> = table
            .iter()
            .filter(|t| t.ptrace != 0 && t.traced_by(&me))
            .map(|t| t.task.tid())
            .collect();
        for tid in tids {
            let Some(mut t) = table.get_mut(tid) else {
                continue;
            };
            let kill = t.ptrace_options & PTRACE_O_EXITKILL != 0;
            t.ptrace = 0;
            t.ptracer = None;
            t.ptrace_options = 0;
            t.task.clear_tif(crate::task::tif::SYSCALL_TRACE);
            if matches!(t.state, TaskState::Traced(_)) {
                t.state = TaskState::Ready;
                t.ptrace_code = 0;
            }
            if let Some(task) = table.task(tid) {
                gone.push((task, kill));
            }
        }
    }
    for (t, kill) in gone {
        if kill {
            signal::send_signal(t.tid(), SIGKILL);
        }
        percpu::try_to_wake_up(&t, percpu::WakeMode::Any);
    }
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
pub fn sys_ptrace(request: i64, pid: i64, addr: u64, data: u64) -> i64 {
    match request {
        PTRACE_TRACEME => ptrace_traceme(),
        PTRACE_ATTACH => ptrace_attach(pid as Pid),
        PTRACE_SEIZE => ptrace_seize(pid as Pid, data as u32),
        PTRACE_DETACH => ptrace_detach(pid as Pid, data as u32),

        PTRACE_PEEKTEXT | PTRACE_PEEKDATA => ptrace_peek_data(pid as Pid, addr, data),
        PTRACE_POKETEXT | PTRACE_POKEDATA => ptrace_poke_data(pid as Pid, addr, data),

        PTRACE_CONT | PTRACE_SYSCALL | PTRACE_SINGLESTEP => {
            ptrace_resume(pid as Pid, request, data as u32)
        }

        PTRACE_KILL => ptrace_kill(pid as Pid),

        PTRACE_SETOPTIONS => ptrace_setoptions(pid as Pid, data as u32),
        PTRACE_GETEVENTMSG => ptrace_geteventmsg(pid as Pid, data),

        PTRACE_GETREGS => ptrace_getregs(pid as Pid, data),
        PTRACE_SETREGS => ptrace_setregs(pid as Pid, data),

        // Not yet implemented
        PTRACE_PEEKUSER | PTRACE_POKEUSER | PTRACE_GETFPREGS | PTRACE_SETFPREGS
        | PTRACE_GETREGSET | PTRACE_SETREGSET | PTRACE_GETSIGINFO | PTRACE_SETSIGINFO
        | PTRACE_INTERRUPT | PTRACE_LISTEN => {
            crate::printkln!("ptrace: unimplemented request {}", request);
            -EINVAL
        }

        _ => {
            crate::printkln!("ptrace: unknown request {}", request);
            -EINVAL
        }
    }
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

/// [`may_read_proc`] for task `tid` itself (tids are never reused): a
/// caller that resolved a pid once checks the very task it then uses
pub fn may_read_task(tid: Tid) -> bool {
    let me = percpu::current_pid();
    let own = TASKLIST
        .read()
        .iter()
        .any(|t| t.task.tid() == tid && t.task.pid == me);
    own || may_access(|t| t.task.tid() == tid, true)
}

/// Linux __ptrace_may_access for the first task `pick` selects: the
/// caller's ids (fsuid/fsgid with `fscreds`, else the real ones) must
/// equal all of the target's real, effective and saved ids, or the
/// caller has CAP_SYS_PTRACE; and a non-dumpable target with an address
/// space needs CAP_SYS_PTRACE too (get_dumpable(mm) != SUID_DUMP_USER)
pub fn may_access(pick: impl Fn(&percpu::TaskView<'_>) -> bool, fscreds: bool) -> bool {
    use crate::task::dumpable::SUID_DUMP_USER;
    let me = percpu::current_cred();
    let target = {
        let table = TASKLIST.read();
        table
            .find(|t| pick(t))
            .map(|t| (t.cred(), t.task.task_lock().mm().map(|m| m.dumpable())))
    };
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
