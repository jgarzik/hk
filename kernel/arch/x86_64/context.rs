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

use super::percpu::{read_fs_base, write_fs_base};
use crate::task::percpu::current_tid;
use crate::task::{Tid, get_task_tls, set_task_tls};

// External assembly functions from switch_to.S
unsafe extern "C" {
    /// Switch from current task context to new task context
    ///
    /// Arguments:
    ///   prev_sp_ptr - Pointer to prev task's saved RSP location
    ///   next_sp - next task's saved RSP value
    ///   new_kstack - new kernel stack top (for TSS.RSP0)
    ///   new_cr3 - new task's CR3 (page table physical address)
    fn __switch_to_asm(prev_sp_ptr: *mut u64, next_sp: u64, new_kstack: u64, new_cr3: u64);

    /// Switch to a new task without saving current context
    ///
    /// Arguments:
    ///   next_sp - next task's saved RSP value
    ///   new_kstack - new kernel stack top (for TSS.RSP0 and SYSCALL_KERNEL_STACK)
    ///   new_cr3 - new task's CR3 (page table physical address)
    fn __switch_to_asm_first(next_sp: u64, new_kstack: u64, new_cr3: u64);
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

/// Entry point for cloned threads/processes
///
/// This function is the initial "return" target when switching to a new
/// clone/fork child. The child's kernel stack has a TrapFrame at the top.
/// We restore the trap frame and iretq to user mode.
///
/// When we arrive here via context_switch:
/// - RSP points to a location where we placed a TrapFrame
/// - We need to release the scheduler lock
/// - Load the child's page table (CR3)
/// - Load the child's TLS (FS base) if CLONE_SETTLS was used
/// - Restore all registers from TrapFrame
/// - IRETQ to user mode with RAX=0 (child return value)
#[unsafe(naked)]
pub extern "C" fn clone_child_entry() -> ! {
    core::arch::naked_asm!(
        // First, release the scheduler lock that was held during context switch
        "call {finish_switch}",

        // Get the child's CR3 (page table root physical address)
        // This is crucial for fork() - the child has its own address space
        "call {get_cr3}",
        // RAX now contains the child's CR3
        // Load it into CR3 NOW, before restoring registers
        // This is safe because we're still in kernel mode with kernel stack
        "mov cr3, rax",

        // Write child TID if CLONE_CHILD_SETTID was used (for fork)
        // Must be after CR3 switch since we're writing to child's address space
        "call {write_child_tid}",

        // Get and load the child's TLS (FS base)
        // This handles CLONE_SETTLS - if no TLS was set, get_tls returns 0
        "call {get_tls}",
        // RAX now contains the TLS value (or 0 if not set)
        "test rax, rax",
        "jz 1f",                  // Skip wrmsr if TLS is 0
        // Write to MSR_FS_BASE (0xC0000100)
        // wrmsr expects: ECX = MSR number, EDX:EAX = value
        "mov rdx, rax",
        "shr rdx, 32",            // High 32 bits in EDX
        "mov ecx, 0xC0000100",    // MSR_FS_BASE
        "wrmsr",
        "1:",

        // RSP points to the TrapFrame we prepared on the child's kernel stack
        // TrapFrame layout:
        //   r15, r14, r13, r12, r11, r10, r9, r8, rbp, rdi, rsi, rdx, rcx, rbx, rax,
        //   error_code, rip, cs, rflags, rsp, ss

        // Restore general purpose registers from TrapFrame
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rbp",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rbx",
        "pop rax",     // Will be 0 (child return value)

        // Skip error_code
        "add rsp, 8",

        // IRETQ will pop: rip, cs, rflags, rsp, ss
        "iretq",

        finish_switch = sym finish_context_switch,
        get_cr3 = sym crate::task::percpu::get_current_task_cr3,
        write_child_tid = sym crate::task::percpu::write_child_tid_if_needed,
        get_tls = sym crate::task::percpu::get_current_task_tls,
    );
}

impl TaskContext {
    /// Create a new context for a clone/fork child
    ///
    /// # Arguments
    /// * `kstack_with_trapframe` - Kernel stack pointer where TrapFrame is stored
    ///
    /// When context_switch restores this context, it will jump to clone_child_entry
    /// which will restore the TrapFrame and iretq to user mode.
    ///
    /// Stack layout after setup (growing down):
    ///   [kstack_with_trapframe]      = TrapFrame (already placed by caller)
    ///   [kstack_with_trapframe - 8]  = clone_child_entry (return address)
    ///   [kstack_with_trapframe - 16] = rbp (0)
    ///   [kstack_with_trapframe - 24] = rbx (0)
    ///   [kstack_with_trapframe - 32] = r12 (0)
    ///   [kstack_with_trapframe - 40] = r13 (0)
    ///   [kstack_with_trapframe - 48] = r14 (0)
    ///   [kstack_with_trapframe - 56] = r15 (0)  <-- RSP points here
    ///
    /// After context switch pops 6 registers and `ret`:
    /// RSP will point to kstack_with_trapframe (the TrapFrame)
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
/// - `new_cr3` must be a valid page table physical address
/// - Interrupts should be disabled during the switch
///
/// # Arguments
/// * `old_ctx` - Where to save the current task's context
/// * `new_ctx` - The context to restore
/// * `new_kstack` - New kernel stack top (for TSS.RSP0)
/// * `new_cr3` - New task's page table physical address
/// * `next_tid` - TID of the task we're switching to (for TLS lookup)
pub unsafe fn context_switch(
    old_ctx: *mut TaskContext,
    new_ctx: *const TaskContext,
    new_kstack: u64,
    new_cr3: u64,
    next_tid: Tid,
) {
    // Save current task's TLS (FS base) before switching
    let prev_tid = current_tid();
    if prev_tid != 0 {
        let fs_base = read_fs_base();
        if fs_base != 0 {
            set_task_tls(prev_tid, fs_base);
        }
    }

    // Load next task's TLS (FS base) before switching
    if next_tid != 0 {
        let tls = get_task_tls(next_tid).unwrap_or(0);
        write_fs_base(tls);
    }

    // The external assembly function uses a stack-based context.
    // It saves/restores callee-saved registers via push/pop on the stack,
    // with RSP stored in TaskContext.rsp.
    //
    // The assembly expects:
    //   prev_sp_ptr - pointer to where to save current RSP
    //   next_sp - the RSP value to switch to
    //   new_kstack - kernel stack top for TSS.RSP0
    //   new_cr3 - new task's page table physical address
    unsafe {
        let prev_sp_ptr = &raw mut (*old_ctx).rsp;
        let next_sp = (*new_ctx).rsp;
        __switch_to_asm(prev_sp_ptr, next_sp, new_kstack, new_cr3);
    }
    // When we return here, we're a different task that was switched back to us
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
    new_cr3: u64,
    next_tid: Tid,
) {
    // Load next task's TLS (FS base) - no prev task to save
    if next_tid != 0 {
        let tls = get_task_tls(next_tid).unwrap_or(0);
        write_fs_base(tls);
    }

    // The external assembly function handles:
    // - Loading next task's RSP
    // - Updating TSS.RSP0
    // - Updating SYSCALL_KERNEL_STACK
    // - Loading new task's CR3
    // - Restoring callee-saved registers from the new stack
    unsafe {
        let next_sp = (*new_ctx).rsp;
        __switch_to_asm_first(next_sp, new_kstack, new_cr3);
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
        new_page_table_root: u64,
        next_tid: Tid,
    ) {
        unsafe {
            context_switch(old_ctx, new_ctx, new_kstack, new_page_table_root, next_tid);
        }
    }

    unsafe fn context_switch_first(
        new_ctx: *const Self::TaskContext,
        new_kstack: u64,
        new_page_table_root: u64,
        next_tid: Tid,
    ) -> ! {
        unsafe {
            context_switch_first(new_ctx, new_kstack, new_page_table_root, next_tid);
            // The above never returns, but we need to satisfy the type system
            core::hint::unreachable_unchecked()
        }
    }
}
