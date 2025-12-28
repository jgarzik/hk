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
use crate::task::percpu::{self, TASK_TABLE};
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

/// Check if caller has permission to ptrace the target process.
///
/// A process can be ptraced if:
/// 1. Caller has CAP_SYS_PTRACE, OR
/// 2. Caller is the real parent of the target (for TRACEME), OR
/// 3. Caller has same effective UID as target
///
/// Additionally, the target must not be:
/// - A kernel thread
/// - The init process (TID 1)
fn ptrace_may_access(target_tid: Tid) -> bool {
    // CAP_SYS_PTRACE bypasses all checks
    if capable(CAP_SYS_PTRACE) {
        return true;
    }

    // Cannot trace init or kernel threads
    if target_tid == 1 {
        return false;
    }

    // Get caller and target credentials
    let caller_cred = percpu::current_cred();

    let target_cred = {
        let table = TASK_TABLE.lock();
        table
            .tasks
            .iter()
            .find(|t| t.tid == target_tid)
            .map(|t| *t.cred)
    };

    match target_cred {
        Some(cred) => {
            // Same effective UID check
            caller_cred.euid == cred.euid
        }
        None => false, // Target doesn't exist
    }
}

/// Check if tracee is stopped and caller is its tracer.
///
/// Most ptrace operations require the tracee to be in a ptrace-stop.
fn ptrace_check_attach(target_tid: Tid) -> Result<(), i64> {
    let caller_tid = percpu::current_tid();

    let table = TASK_TABLE.lock();
    let target = table
        .tasks
        .iter()
        .find(|t| t.tid == target_tid)
        .ok_or(-ESRCH)?;

    // Check if we are the tracer
    if target.ptracer_tid != Some(caller_tid) {
        return Err(-ESRCH);
    }

    // Check if target is in ptrace stop
    if !matches!(target.state, TaskState::Traced(_)) {
        return Err(-ESRCH);
    }

    Ok(())
}

/// Find a task by PID (thread group leader)
fn find_task_by_pid(pid: Pid) -> Option<Tid> {
    let table = TASK_TABLE.lock();
    table.tasks.iter().find(|t| t.pid == pid).map(|t| t.tid)
}

/// Check if a task is being traced
pub fn is_traced(tid: Tid) -> bool {
    let table = TASK_TABLE.lock();
    table
        .tasks
        .iter()
        .find(|t| t.tid == tid)
        .map(|t| t.ptrace != 0)
        .unwrap_or(false)
}

/// Check if syscall tracing is active for a task
pub fn has_syscall_trace(tid: Tid) -> bool {
    let table = TASK_TABLE.lock();
    table
        .tasks
        .iter()
        .find(|t| t.tid == tid)
        .map(|t| t.ptrace & PT_SYSCALL_TRACE != 0)
        .unwrap_or(false)
}

/// Check if single-step is active for a task
pub fn has_singlestep(tid: Tid) -> bool {
    let table = TASK_TABLE.lock();
    table
        .tasks
        .iter()
        .find(|t| t.tid == tid)
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

    let mut table = TASK_TABLE.lock();
    let task = match table.tasks.iter_mut().find(|t| t.tid == tid) {
        Some(t) => t,
        None => return -ESRCH,
    };

    // Already being traced?
    if task.ptrace != 0 {
        return -EPERM;
    }

    // Set up tracing - parent becomes tracer
    let ppid = task.ppid;
    task.ptrace = PT_PTRACED;
    task.ptracer_tid = Some(ppid);
    task.real_parent_tid = ppid;

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

    let caller_tid = percpu::current_tid();

    // Cannot attach to self
    if target_tid == caller_tid {
        return -EPERM;
    }

    // Check permissions
    if !ptrace_may_access(target_tid) {
        return -EPERM;
    }

    {
        let mut table = TASK_TABLE.lock();
        let target = match table.tasks.iter_mut().find(|t| t.tid == target_tid) {
            Some(t) => t,
            None => return -ESRCH,
        };

        // Already being traced?
        if target.ptrace != 0 {
            return -EPERM;
        }

        // Set up tracing
        target.ptrace = PT_PTRACED;
        target.ptracer_tid = Some(caller_tid);
        // real_parent_tid is already set correctly
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

    let caller_tid = percpu::current_tid();

    // Cannot attach to self
    if target_tid == caller_tid {
        return -EPERM;
    }

    // Check permissions
    if !ptrace_may_access(target_tid) {
        return -EPERM;
    }

    {
        let mut table = TASK_TABLE.lock();
        let target = match table.tasks.iter_mut().find(|t| t.tid == target_tid) {
            Some(t) => t,
            None => return -ESRCH,
        };

        // Already being traced?
        if target.ptrace != 0 {
            return -EPERM;
        }

        // Set up tracing with SEIZED flag
        target.ptrace = PT_PTRACED | PT_SEIZED;
        target.ptracer_tid = Some(caller_tid);
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
        let mut table = TASK_TABLE.lock();
        let target = match table.tasks.iter_mut().find(|t| t.tid == target_tid) {
            Some(t) => t,
            None => return -ESRCH,
        };

        // Clear tracing state
        target.ptrace = 0;
        target.ptracer_tid = None;
        target.ptrace_options = 0;

        // Change state from Traced to Ready (this wakes the task)
        if matches!(target.state, TaskState::Traced(_)) {
            target.state = TaskState::Ready;
        }
    }

    // Inject signal if requested
    if signal > 0 && signal < 64 {
        signal::send_signal(target_tid, signal);
    }

    0
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
        let mut table = TASK_TABLE.lock();
        let target = match table.tasks.iter_mut().find(|t| t.tid == target_tid) {
            Some(t) => t,
            None => return -ESRCH,
        };

        // Update ptrace flags based on request
        match request {
            PTRACE_CONT => {
                target.ptrace &= !(PT_SYSCALL_TRACE | PT_SINGLESTEP);
            }
            PTRACE_SYSCALL => {
                target.ptrace |= PT_SYSCALL_TRACE;
                target.ptrace &= !PT_SINGLESTEP;
            }
            PTRACE_SINGLESTEP => {
                target.ptrace |= PT_SINGLESTEP;
                target.ptrace &= !PT_SYSCALL_TRACE;
                // Architecture-specific single-step setup
                crate::arch::ptrace::enable_single_step(target_tid);
            }
            _ => return -EINVAL,
        }

        // Clear singlestep if not single-stepping
        if request != PTRACE_SINGLESTEP {
            crate::arch::ptrace::disable_single_step(target_tid);
        }

        // Change state from Traced to Ready (this wakes the task)
        target.state = TaskState::Ready;
    }

    // Inject signal if requested
    if signal > 0 && signal < 64 {
        signal::send_signal(target_tid, signal);
    }

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
    let caller_tid = percpu::current_tid();
    {
        let table = TASK_TABLE.lock();
        let target = match table.tasks.iter().find(|t| t.tid == target_tid) {
            Some(t) => t,
            None => return -ESRCH,
        };

        if target.ptracer_tid != Some(caller_tid) {
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

/// Get target's memory descriptor and page table root
fn get_target_mm_and_pt(
    target_tid: Tid,
) -> Option<(alloc::sync::Arc<spin::Mutex<crate::mm::MmStruct>>, u64)> {
    let table = TASK_TABLE.lock();
    let task = table.tasks.iter().find(|t| t.tid == target_tid)?;

    let mm = task.mm.clone()?;
    let pt_root = task.page_table.root_table_phys();

    Some((mm, pt_root))
}

/// Read a word from tracee's memory.
fn ptrace_peek_data(target_pid: Pid, addr: u64) -> i64 {
    let target_tid = match find_task_by_pid(target_pid) {
        Some(tid) => tid,
        None => return -ESRCH,
    };

    // Verify we are the tracer
    if let Err(e) = ptrace_check_attach(target_tid) {
        return e;
    }

    // Get target's mm and page table
    let (target_mm, page_table_root) = match get_target_mm_and_pt(target_tid) {
        Some(x) => x,
        None => return -ESRCH,
    };

    // Lock mm and read from tracee
    let mm_guard = target_mm.lock();
    let mut buf = [0u8; 8];
    match crate::mm::remote::access_remote_vm_read(&mm_guard, page_table_root, addr, &mut buf) {
        Ok(8) => {
            // Return the word value
            i64::from_ne_bytes(buf)
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
    let (target_mm, page_table_root) = match get_target_mm_and_pt(target_tid) {
        Some(x) => x,
        None => return -ESRCH,
    };

    // Lock mm and write to tracee
    let mm_guard = target_mm.lock();
    let buf = data.to_ne_bytes();
    match crate::mm::remote::access_remote_vm_write(&mm_guard, page_table_root, addr, &buf) {
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
        let mut table = TASK_TABLE.lock();
        let target = match table.tasks.iter_mut().find(|t| t.tid == target_tid) {
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
        let table = TASK_TABLE.lock();
        table
            .tasks
            .iter()
            .find(|t| t.tid == target_tid)
            .map(|t| t.ptrace_message)
            .unwrap_or(0)
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

/// Enter ptrace stop state.
///
/// Called when a traced task should stop (signal delivery, syscall trap, etc.).
/// This puts the task in Traced state and wakes the tracer.
pub fn ptrace_stop(sig: u32) {
    let tid = percpu::current_tid();

    // Set task state to Traced and wake tracer
    {
        let mut table = TASK_TABLE.lock();
        let tracer_tid = if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
            task.state = TaskState::Traced(sig as i32);
            task.ptracer_tid
        } else {
            None
        };

        // Wake up the tracer (if any) so it can collect the stop via wait()
        if let Some(tracer_tid) = tracer_tid
            && let Some(tracer) = table.tasks.iter_mut().find(|t| t.tid == tracer_tid)
            && matches!(tracer.state, TaskState::Sleeping)
        {
            tracer.state = TaskState::Ready;
        }
    }

    // Yield CPU - we're now stopped
    percpu::yield_now();
}

/// Report a syscall entry/exit to tracer.
///
/// Called at syscall entry (if PTRACE_SYSCALL is active) to stop and let
/// the tracer inspect/modify the syscall.
pub fn ptrace_report_syscall(entry: bool) {
    let tid = percpu::current_tid();

    // Check if syscall tracing is active
    if !has_syscall_trace(tid) {
        return;
    }

    // Get options to check for TRACESYSGOOD
    let options = {
        let table = TASK_TABLE.lock();
        table
            .tasks
            .iter()
            .find(|t| t.tid == tid)
            .map(|t| t.ptrace_options)
            .unwrap_or(0)
    };

    // Signal number is SIGTRAP, optionally with 0x80 bit for TRACESYSGOOD
    let sig = if options & PTRACE_O_TRACESYSGOOD != 0 {
        SIGTRAP | 0x80
    } else {
        SIGTRAP
    };

    // Store whether this is entry or exit in ptrace_message
    {
        let mut table = TASK_TABLE.lock();
        if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
            task.ptrace_message = if entry { 1 } else { 2 };
        }
    }

    ptrace_stop(sig);
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
/// For PEEKDATA/PEEKTEXT, returns the read value on success.
pub fn sys_ptrace(request: i64, pid: i64, addr: u64, data: u64) -> i64 {
    match request {
        PTRACE_TRACEME => ptrace_traceme(),
        PTRACE_ATTACH => ptrace_attach(pid as Pid),
        PTRACE_SEIZE => ptrace_seize(pid as Pid, data as u32),
        PTRACE_DETACH => ptrace_detach(pid as Pid, data as u32),

        PTRACE_PEEKTEXT | PTRACE_PEEKDATA => ptrace_peek_data(pid as Pid, addr),
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
