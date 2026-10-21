//! Context switching for kernel threads (aarch64)
//!
//! This module provides the low-level context switch mechanism for
//! switching between kernel threads on aarch64. It saves and restores
//! callee-saved registers per AAPCS64 (ARM ABI).
//!
//! The actual context switch is implemented in switch_to.S (pure assembly).
//!
//! TLS (Thread Local Storage) handling follows the Linux kernel pattern:
//! save/restore TPIDR_EL0 in Rust before calling the pure-asm switch.

use super::percpu::write_tpidr_el0;

// External assembly functions from switch_to.S
unsafe extern "C" {
    /// Switch from current task context to new task context
    ///
    /// Arguments:
    ///   prev_ctx - Pointer to prev task's TaskContext (to save into)
    ///   next_ctx - Pointer to next task's TaskContext (to restore from)
    ///   new_kstack - new kernel stack top (unused on aarch64)
    fn __switch_to_asm(
        prev_ctx: *mut Aarch64TaskContext,
        next_ctx: *const Aarch64TaskContext,
        new_kstack: u64,
    );

    /// Switch to a new task without saving current context
    ///
    /// Arguments:
    ///   next_ctx - Pointer to next task's TaskContext (to restore from)
    ///   new_kstack - new kernel stack top (unused on aarch64)
    fn __switch_to_asm_first(next_ctx: *const Aarch64TaskContext, new_kstack: u64);
}

/// AArch64 task context for context switching
///
/// Contains callee-saved registers that must be preserved across function calls.
/// Layout must match what switch_to.S expects.
#[repr(C)]
#[derive(Clone, Default)]
pub struct Aarch64TaskContext {
    /// Callee-saved registers x19-x28
    pub x19_x28: [u64; 10],
    /// Frame pointer (x29)
    pub fp: u64,
    /// Link register (x30) - return address
    pub lr: u64,
    /// Stack pointer
    pub sp: u64,
    /// Callee-saved FP registers d8-d15 (AAPCS64; the kernel uses FP/SIMD)
    pub d8_d15: [u64; 8],
}

impl Aarch64TaskContext {
    /// Create a new context for a kernel thread
    ///
    /// # Arguments
    /// * `entry` - Entry point function address
    /// * `stack_top` - Top of the kernel stack (highest address)
    ///
    /// When context_switch restores this context, it will "return" to
    /// kernel_thread_start, which will then call the actual entry function.
    pub fn new_kernel_thread(entry: usize, stack_top: u64) -> Self {
        Self {
            x19_x28: [entry as u64, 0, 0, 0, 0, 0, 0, 0, 0, 0], // x19 = entry
            fp: 0,
            lr: kernel_thread_start as *const () as u64, // Return address
            sp: stack_top,
            d8_d15: [0; 8],
        }
    }

    /// Create a new context for a clone/fork child
    ///
    /// # Arguments
    /// * `kstack_with_trapframe` - Kernel stack pointer where TrapFrame is stored
    ///
    /// When context_switch restores this context, it will jump to clone_child_entry
    /// which will restore the TrapFrame and ERET to user mode.
    pub fn new_clone_child(kstack_with_trapframe: u64) -> Self {
        Self {
            x19_x28: [0; 10],
            fp: 0,
            lr: clone_child_entry as *const () as u64, // Return address
            sp: kstack_with_trapframe,
            d8_d15: [0; 8],
        }
    }
}

/// Entry point wrapper for new kernel threads
///
/// This function is the initial "return" target when switching to a new
/// kernel thread. It calls the actual thread entry function stored in X19.
#[unsafe(naked)]
extern "C" fn kernel_thread_start() {
    core::arch::naked_asm!(
        // First, release the scheduler lock that was held during context switch
        "bl {finish_switch}",
        // The actual entry function pointer is in X19 (set by new_kernel_thread)
        // Call it (it should never return, but if it does we'll handle it)
        "blr x19",
        // If the thread returns, call the exit handler
        "mov x0, x0",  // Return value already in x0
        "bl {exit_handler}",
        // Should never get here, but halt just in case
        "1:",
        "wfi",
        "b 1b",
        finish_switch = sym finish_context_switch,
        exit_handler = sym kernel_thread_exit,
    );
}

/// Called after context switch to a new kernel thread to release scheduler lock
extern "C" fn finish_context_switch() {
    crate::task::percpu::finish_context_switch();
}

/// Called when a kernel thread returns (should not normally happen)
extern "C" fn kernel_thread_exit(_status: i64) {
    loop {
        unsafe {
            ::core::arch::asm!("wfi");
        }
    }
}

/// Entry point for cloned threads/processes (Linux ret_from_fork)
///
/// The initial "return" target of a clone/fork child's first switch: SP
/// is its pt_regs (a copy of the parent's syscall frame, x0 = 0, the
/// FP/SIMD state included) at the top of its kernel stack. The switch
/// loaded its address space and TLS register.
#[unsafe(naked)]
pub extern "C" fn clone_child_entry() -> ! {
    core::arch::naked_asm!(
        // Release the scheduler lock held across the switch
        "bl {finish_switch}",
        // IRQs on, as in any syscall (Linux ret_from_fork): the
        // child-TID write may fault and sleep
        "msr daifclr, #2",
        "bl {write_child_tid}",
        // The work of a syscall's return, on the child's pt_regs (SP)
        "mov x0, sp",
        "bl {exit_work}",
        // Out through the child's pt_regs (ret_to_user masks DAIF)
        "b ret_to_user",
        finish_switch = sym finish_context_switch,
        write_child_tid = sym crate::task::percpu::write_child_tid_if_needed,
        exit_work = sym ret_from_fork,
    );
}

/// A fork child's first return to user mode: the work of a syscall's
/// return (Linux ret_from_fork -> syscall_exit_to_user_mode)
extern "C" fn ret_from_fork(regs: &mut super::Aarch64TrapFrame) {
    crate::entry::syscall_exit_to_user_mode(regs);
}

/// Switch from the current task context to a new task context
///
/// Follows Linux kernel pattern: handle TLS in Rust wrapper, then call pure-asm switch.
///
/// # Safety
/// - `old_ctx` must point to valid, writable memory for storing the current context
/// - `new_ctx` must point to a valid, previously saved context
/// - `new_kstack` should be the new kernel stack top (informational on aarch64)
/// - the next task's TTBR0 is loaded (`mm::tlb::switch_mm`)
/// - Interrupts should be disabled during the switch
/// - `next_tls` is the next task's user TLS register value
pub unsafe fn context_switch(
    old_ctx: *mut Aarch64TaskContext,
    new_ctx: *const Aarch64TaskContext,
    new_kstack: u64,
    next_tls: u64,
) {
    // Load next task's user TLS register (TPIDR_EL0)
    write_tpidr_el0(next_tls);

    unsafe {
        __switch_to_asm(old_ctx, new_ctx, new_kstack);
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
    new_ctx: *const Aarch64TaskContext,
    new_kstack: u64,
    next_tls: u64,
) -> ! {
    // Load next task's user TLS register (TPIDR_EL0)
    write_tpidr_el0(next_tls);

    unsafe {
        __switch_to_asm_first(new_ctx, new_kstack);
        // The above never returns
        core::hint::unreachable_unchecked()
    }
}
