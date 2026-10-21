//! Context switching for kernel threads
//!
//! This module provides the low-level context switch mechanism for
//! switching between kernel threads. It saves and restores only the
//! callee-saved registers (per the System V AMD64 ABI).
//!
//! The actual context switch is implemented in switch_to.S (pure assembly)
//! to avoid Rust inline assembly ABI issues, following the Linux kernel's
//! __switch_to_asm pattern.
//!
//! TLS (Thread Local Storage) handling follows the Linux kernel pattern:
//! save/restore FS base in Rust before calling the pure-asm switch.

use super::fpu::{self, FpuArea};
use super::percpu::{write_fs_base, write_user_gsbase};

// External assembly functions from switch_to.S
unsafe extern "C" {
    /// Switch from current task context to new task context
    ///
    /// Arguments:
    ///   prev_sp_ptr - Pointer to prev task's saved RSP location
    ///   next_sp - next task's saved RSP value
    ///   new_kstack - new kernel stack top (for TSS.RSP0)
    fn __switch_to_asm(prev_sp_ptr: *mut u64, next_sp: u64, new_kstack: u64);

    /// Switch to a new task without saving current context
    ///
    /// Arguments:
    ///   next_sp - next task's saved RSP value
    ///   new_kstack - new kernel stack top (for TSS.RSP0 and SYSCALL_KERNEL_STACK)
    fn __switch_to_asm_first(next_sp: u64, new_kstack: u64);
}

/// Kernel thread context (callee-saved registers only)
///
/// This is a minimal context structure for kernel thread switching.
/// We only need to save callee-saved registers because the caller-saved
/// registers are already saved by the calling code.
///
/// Per System V AMD64 ABI, callee-saved registers are:
/// - rbx, rbp, r12, r13, r14, r15
///
/// Plus we save rsp and rip for the actual switch.
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct TaskContext {
    /// R15 register
    pub r15: u64,
    /// R14 register
    pub r14: u64,
    /// R13 register
    pub r13: u64,
    /// R12 register
    pub r12: u64,
    /// RBX register
    pub rbx: u64,
    /// RBP register (frame pointer)
    pub rbp: u64,
    /// RSP register (stack pointer)
    pub rsp: u64,
    /// RIP register (return address / instruction pointer)
    pub rip: u64,
}

impl TaskContext {
    /// Create a new context for a kernel thread
    ///
    /// # Arguments
    /// * `entry` - Entry point function address
    /// * `stack_top` - Top of the kernel stack (highest address)
    ///
    /// The stack is set up so that when context_switch restores this context,
    /// it will "return" to kernel_thread_start, which will then call the
    /// actual entry function.
    ///
    /// Stack layout after setup (growing down):
    ///   [stack_top - 8]  = return address (kernel_thread_start)
    ///   [stack_top - 16] = rbp (0)
    ///   [stack_top - 24] = rbx (0)
    ///   [stack_top - 32] = r12 (entry function)
    ///   [stack_top - 40] = r13 (0)
    ///   [stack_top - 48] = r14 (0)
    ///   [stack_top - 56] = r15 (0)  <-- RSP points here
    pub fn new_kernel_thread(entry: usize, stack_top: u64) -> Self {
        // Build the stack frame that __switch_to_asm expects
        unsafe {
            let stack = stack_top as *mut u64;
            // Write return address (popped last by `ret`)
            *stack.sub(1) = kernel_thread_start as *const () as u64;
            // Write callee-saved registers in pop order: rbp, rbx, r12, r13, r14, r15
            *stack.sub(2) = 0; // rbp
            *stack.sub(3) = 0; // rbx
            *stack.sub(4) = entry as u64; // r12 (entry function)
            *stack.sub(5) = 0; // r13
            *stack.sub(6) = 0; // r14
            *stack.sub(7) = 0; // r15
        }

        Self {
            // RSP points to r15 (top of pushed values)
            rsp: stack_top - 56,
            // These fields are unused when using stack-based context switch
            rip: 0,
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbx: 0,
            rbp: 0,
        }
    }
}

/// Entry point wrapper for new kernel threads
///
/// This function is the initial "return" target when switching to a new
/// kernel thread. It calls the actual thread entry function stored in R12.
#[unsafe(naked)]
extern "C" fn kernel_thread_start() {
    core::arch::naked_asm!(
            // First, release the scheduler lock that was held during context switch
            // The guard is on the old task's stack and will never drop on this stack.
            "call {finish_switch}",
            // The actual entry function pointer is in R12 (set by new_kernel_thread)
            // Call it (it should never return, but if it does we'll handle it)
            "call r12",
            // If the thread returns, call the exit handler
            "mov rdi, rax",  // Pass return value as argument
            "call {exit_handler}",
            // Should never get here, but halt just in case
        "2:",
        "hlt",
        "jmp 2b",
        finish_switch = sym finish_context_switch,
        exit_handler = sym kernel_thread_exit,
    );
}

/// Called after context switch to a new kernel thread to release scheduler lock
extern "C" fn finish_context_switch() {
    // Release the scheduler lock that was held during context switch
    // The guard is on the old task's stack.
    crate::task::percpu::finish_context_switch();
}

/// Called when a kernel thread returns (should not normally happen)
///
/// Kernel threads are expected to run indefinitely or call exit explicitly.
/// If a kernel thread function returns, we halt the CPU as a safety measure.
extern "C" fn kernel_thread_exit(_status: i64) {
    // Kernel threads should never return - halt if they do
    loop {
        unsafe {
            ::core::arch::asm!("hlt");
        }
    }
}

/// Entry point for cloned threads/processes (Linux ret_from_fork)
///
/// The initial "return" target of a clone/fork child's first switch. Its
/// pt_regs (the parent's syscall frame, RAX = 0) are at the top of its
/// kernel stack, the FP/SIMD state the parent saved just below them; the
/// switch frame ended at that state, so RSP points to it. The switch
/// already loaded the child's address space, TLS and GS base.
#[unsafe(naked)]
pub extern "C" fn clone_child_entry() -> ! {
    core::arch::naked_asm!(
        "mov rdi, rsp",
        "call {tail}",
        // RAX = the child's pt_regs: leave through IRET
        "mov rsp, rax",
        "jmp {ret}",
        tail = sym ret_from_fork,
        ret = sym super::entry::irq_return,
    );
}

/// The C part of `clone_child_entry` (Linux schedule_tail, then
/// syscall_exit_to_user_mode): release the rq lock held across the
/// switch, load the inherited FP state at `fpu`, write the child TID
/// (CLONE_CHILD_SETTID, may fault and sleep: interrupts on, as in any
/// syscall), the work of a syscall's return; returns the child's
/// pt_regs, with interrupts off
extern "C" fn ret_from_fork(fpu: *const FpuArea) -> *mut super::PtRegs {
    crate::task::percpu::finish_context_switch();
    // SAFETY: the area the parent saved (fpu::save_for_clone_child)
    unsafe { fpu::restore_raw(fpu) };
    super::interrupts::enable();
    crate::task::percpu::write_child_tid_if_needed();
    let regs = crate::task::percpu::current_pt_regs();
    crate::entry::syscall_exit_to_user_mode(regs);
    regs
}

impl TaskContext {
    /// Create a new context for a clone/fork child
    ///
    /// # Arguments
    /// * `kstack_with_trapframe` - Where the child's first switch frame
    ///   ends: its saved FP state (below its pt_regs)
    ///
    /// When context_switch restores this context, it will jump to clone_child_entry
    /// which returns to user mode through the child's pt_regs.
    ///
    /// Stack layout after setup (growing down):
    ///   [kstack_with_trapframe]      = FP state (already saved by caller)
    ///   [kstack_with_trapframe - 8]  = clone_child_entry (return address)
    ///   [kstack_with_trapframe - 16] = rbp (0)
    ///   [kstack_with_trapframe - 24] = rbx (0)
    ///   [kstack_with_trapframe - 32] = r12 (0)
    ///   [kstack_with_trapframe - 40] = r13 (0)
    ///   [kstack_with_trapframe - 48] = r14 (0)
    ///   [kstack_with_trapframe - 56] = r15 (0)  <-- RSP points here
    ///
    /// After context switch pops 6 registers and `ret`:
    /// RSP will point to kstack_with_trapframe (the FP state)
    pub fn new_clone_child(kstack_with_trapframe: u64) -> Self {
        // Build the stack frame that __switch_to_asm expects
        unsafe {
            let frame_base = kstack_with_trapframe as *mut u64;
            // Write return address (popped last by `ret`)
            *frame_base.sub(1) = clone_child_entry as *const () as u64;
            // Write callee-saved registers in pop order: rbp, rbx, r12, r13, r14, r15
            *frame_base.sub(2) = 0; // rbp
            *frame_base.sub(3) = 0; // rbx
            *frame_base.sub(4) = 0; // r12
            *frame_base.sub(5) = 0; // r13
            *frame_base.sub(6) = 0; // r14
            *frame_base.sub(7) = 0; // r15
        }

        Self {
            // RSP points to r15 (top of pushed values)
            rsp: kstack_with_trapframe - 56,
            // These fields are unused when using stack-based context switch
            rip: 0,
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbx: 0,
            rbp: 0,
        }
    }
}

/// Switch from the current task context to a new task context
///
/// Follows Linux kernel pattern: handle TLS in Rust wrapper, then call pure-asm switch.
///
/// # Safety
/// - `old_ctx` must point to valid, writable memory for storing the current context
/// - `new_ctx` must point to a valid, previously saved context
/// - `new_kstack` must be a valid kernel stack top address
/// - the next task's address space is loaded (`mm::tlb::switch_mm`)
/// - Interrupts should be disabled during the switch
///
/// # Arguments
/// * `old_ctx` - Where to save the current task's context
/// * `new_ctx` - The context to restore
/// * `new_kstack` - New kernel stack top (for TSS.RSP0)
/// * `next_tls` - its user TLS register value
/// * `next_gs` - its user GS base (swapped in on its return to user)
pub unsafe fn context_switch(
    old_ctx: *mut TaskContext,
    new_ctx: *const TaskContext,
    new_kstack: u64,
    next_tls: u64,
    next_gs: u64,
) {
    // Load next task's user TLS register (FS base) and GS base
    write_fs_base(next_tls);
    write_user_gsbase(next_gs);

    // The external assembly function uses a stack-based context.
    // It saves/restores callee-saved registers via push/pop on the stack,
    // with RSP stored in TaskContext.rsp.
    //
    // The assembly expects:
    //   prev_sp_ptr - pointer to where to save current RSP
    //   next_sp - the RSP value to switch to
    //   new_kstack - kernel stack top for TSS.RSP0
    //
    // The outgoing task's user FP/SIMD registers (the kernel itself never
    // touches them: soft-float) are kept in `fpu_area` on its own kernel
    // stack and reloaded when it is switched back in.
    let mut fpu_area = core::mem::MaybeUninit::<FpuArea>::uninit();
    unsafe {
        fpu::save_raw(fpu_area.as_mut_ptr());
        let prev_sp_ptr = &raw mut (*old_ctx).rsp;
        let next_sp = (*new_ctx).rsp;
        __switch_to_asm(prev_sp_ptr, next_sp, new_kstack);
        // Back on this task: its FP state is in `fpu_area`
        fpu::restore_raw(fpu_area.as_ptr());
    }
}

/// Switch to a new task without saving the old context
///
/// Used for the initial switch to the first task or when exiting.
/// Follows Linux kernel pattern: load TLS for new task, then call pure-asm switch.
///
/// # Safety
/// Same requirements as context_switch, except old_ctx is not used.
pub unsafe fn context_switch_first(
    new_ctx: *const TaskContext,
    new_kstack: u64,
    next_tls: u64,
    next_gs: u64,
) {
    // Load next task's user TLS register (FS base) and GS base
    write_fs_base(next_tls);
    write_user_gsbase(next_gs);

    // The external assembly function handles:
    // - Loading next task's RSP
    // - Setting the kernel stack of entries from user mode
    // - Restoring callee-saved registers from the new stack
    unsafe {
        let next_sp = (*new_ctx).rsp;
        __switch_to_asm_first(next_sp, new_kstack);
    }
}

// ============================================================================
// ContextOps trait implementation
// ============================================================================

use crate::arch::ContextOps;

use super::X86_64Arch;

impl ContextOps for X86_64Arch {
    type TaskContext = TaskContext;

    #[inline]
    fn new_kernel_thread_context(entry: usize, stack_top: u64) -> Self::TaskContext {
        TaskContext::new_kernel_thread(entry, stack_top)
    }

    #[inline]
    fn new_clone_child_context(kstack_with_trapframe: u64) -> Self::TaskContext {
        TaskContext::new_clone_child(kstack_with_trapframe)
    }

    #[inline]
    unsafe fn context_switch(
        old_ctx: *mut Self::TaskContext,
        new_ctx: *const Self::TaskContext,
        new_kstack: u64,
        next_tls: u64,
        next_gs: u64,
    ) {
        unsafe {
            context_switch(old_ctx, new_ctx, new_kstack, next_tls, next_gs);
        }
    }

    unsafe fn context_switch_first(
        new_ctx: *const Self::TaskContext,
        new_kstack: u64,
        next_tls: u64,
        next_gs: u64,
    ) -> ! {
        unsafe {
            context_switch_first(new_ctx, new_kstack, next_tls, next_gs);
            // The above never returns, but we need to satisfy the type system
            core::hint::unreachable_unchecked()
        }
    }
}
