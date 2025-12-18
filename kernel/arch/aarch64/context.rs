//! Context switching for kernel threads (aarch64)
//!
//! This module provides the low-level context switch mechanism for
//! switching between kernel threads on aarch64. It saves and restores
//! callee-saved registers per AAPCS64 (ARM ABI).
//!
//! The actual context switch is implemented in switch_to.S (pure assembly).

// External assembly functions from switch_to.S
unsafe extern "C" {
    /// Switch from current task context to new task context
    ///
    /// Arguments:
    ///   prev_ctx - Pointer to prev task's TaskContext (to save into)
    ///   next_ctx - Pointer to next task's TaskContext (to restore from)
    ///   new_kstack - new kernel stack top (unused on aarch64)
    ///   new_ttbr0 - new task's TTBR0_EL1 (user page table physical address)
    fn __switch_to_asm(
        prev_ctx: *mut Aarch64TaskContext,
        next_ctx: *const Aarch64TaskContext,
        new_kstack: u64,
        new_ttbr0: u64,
    );

    /// Switch to a new task without saving current context
    ///
    /// Arguments:
    ///   next_ctx - Pointer to next task's TaskContext (to restore from)
    ///   new_kstack - new kernel stack top (unused on aarch64)
    ///   new_ttbr0 - new task's TTBR0_EL1 (user page table physical address)
    fn __switch_to_asm_first(next_ctx: *const Aarch64TaskContext, new_kstack: u64, new_ttbr0: u64);
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

/// Entry point for cloned threads/processes
///
/// This function is the initial "return" target when switching to a new
/// clone/fork child. The child's kernel stack has a TrapFrame at the top.
/// We restore the trap frame and ERET to user mode.
#[unsafe(naked)]
pub extern "C" fn clone_child_entry() -> ! {
    core::arch::naked_asm!(
        // First, release the scheduler lock that was held during context switch
        "bl {finish_switch}",

        // Get the child's TTBR0 (page table root physical address)
        "bl {get_ttbr0}",
        // X0 now contains the child's TTBR0
        // Load it into TTBR0_EL1 NOW, before restoring registers
        "msr ttbr0_el1, x0",
        "tlbi vmalle1is",
        "dsb ish",
        "isb",

        // SP points to the TrapFrame we prepared on the child's kernel stack
        // TrapFrame layout (272 bytes):
        //   sp+0x000: x0-x30 (31 * 8 = 248 bytes)
        //   sp+0x0f8: sp
        //   sp+0x100: elr
        //   sp+0x108: spsr

        // Restore SPSR_EL1
        "ldr x0, [sp, #0x108]",
        "msr spsr_el1, x0",

        // Restore ELR_EL1
        "ldr x0, [sp, #0x100]",
        "msr elr_el1, x0",

        // Restore SP_EL0 (user stack - not the kernel stack!)
        // Note: TrapFrame.sp is SP_EL0 for user exceptions
        "ldr x0, [sp, #0xf8]",
        "msr sp_el0, x0",

        // Restore x30 (LR)
        "ldr x30, [sp, #0xf0]",

        // Restore x1-x29 (x0 last since we're using it as scratch)
        "ldp x28, x29, [sp, #0xe0]",
        "ldp x26, x27, [sp, #0xd0]",
        "ldp x24, x25, [sp, #0xc0]",
        "ldp x22, x23, [sp, #0xb0]",
        "ldp x20, x21, [sp, #0xa0]",
        "ldp x18, x19, [sp, #0x90]",
        "ldp x16, x17, [sp, #0x80]",
        "ldp x14, x15, [sp, #0x70]",
        "ldp x12, x13, [sp, #0x60]",
        "ldp x10, x11, [sp, #0x50]",
        "ldp x8, x9, [sp, #0x40]",
        "ldp x6, x7, [sp, #0x30]",
        "ldp x4, x5, [sp, #0x20]",
        "ldp x2, x3, [sp, #0x10]",
        // x0 will be 0 (child return value from fork/clone)
        // x1 is restored here too
        "ldp x0, x1, [sp, #0x00]",

        // Deallocate frame (but we won't return to kernel, so this just cleans up)
        "add sp, sp, #272",

        // Return to user mode
        "eret",

        finish_switch = sym finish_context_switch,
        get_ttbr0 = sym crate::task::percpu::get_current_task_cr3,
    );
}

/// Switch from the current task context to a new task context
///
/// # Safety
/// - `old_ctx` must point to valid, writable memory for storing the current context
/// - `new_ctx` must point to a valid, previously saved context
/// - `new_kstack` should be the new kernel stack top (informational on aarch64)
/// - `new_ttbr0` must be a valid page table physical address for TTBR0_EL1
/// - Interrupts should be disabled during the switch
pub unsafe fn context_switch(
    old_ctx: *mut Aarch64TaskContext,
    new_ctx: *const Aarch64TaskContext,
    new_kstack: u64,
    new_ttbr0: u64,
) {
    unsafe {
        __switch_to_asm(old_ctx, new_ctx, new_kstack, new_ttbr0);
    }
}

/// Switch to a new task without saving the old context
///
/// Used for the initial switch to the first task, when there's no
/// previous context to save.
///
/// # Safety
/// Same requirements as context_switch, except old_ctx is not used.
pub unsafe fn context_switch_first(
    new_ctx: *const Aarch64TaskContext,
    new_kstack: u64,
    new_ttbr0: u64,
) -> ! {
    unsafe {
        __switch_to_asm_first(new_ctx, new_kstack, new_ttbr0);
        // The above never returns
        core::hint::unreachable_unchecked()
    }
}
