/* x86-64 Context Switch Assembly
 *
 * Follows Linux kernel's __switch_to_asm pattern.
 * Pure assembly avoids Rust inline asm ABI issues.
 *
 * This file implements the core task switching mechanism,
 * saving/restoring only callee-saved registers per System V AMD64 ABI.
 *
 * TLS (FS base) handling is done in Rust before calling these functions,
 * following the Linux kernel pattern (tls_thread_switch before cpu_switch_to).
 */

.section .text

.global __switch_to_asm
.global __switch_to_asm_first

/* __switch_to_asm(prev_sp_ptr: *mut u64, next_sp: u64, new_kstack: u64)
 *
 * Arguments (System V AMD64 ABI):
 *   %rdi - Pointer to prev task's saved RSP location
 *   %rsi - next task's saved RSP value
 *   %rdx - new kernel stack top (for TSS.RSP0 and SYSCALL_KERNEL_STACK)
 *
 * The scheduler has already loaded the next task's address space
 * (mm::tlb::switch_mm). This function:
 *   1. Saves callee-saved registers on current stack
 *   2. Saves current RSP to *prev_sp_ptr
 *   3. Loads next task's RSP
 *   4. Updates TSS.RSP0 for interrupt handling
 *   5. Updates SYSCALL_KERNEL_STACK for syscall entry
 *   6. Restores callee-saved registers from new stack
 *   7. Returns (to the new task's saved return address)
 */
__switch_to_asm:
    /* Save callee-saved registers on current stack */
    pushq   %rbp
    pushq   %rbx
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

    /* Save current RSP to prev task */
    movq    %rsp, (%rdi)

    /* Load next task's RSP */
    movq    %rsi, %rsp

    /* Save new_kstack in a callee-saved register for use across calls */
    movq    %rdx, %r12

    /* Update TSS.RSP0 for interrupt handling */
    movq    %r12, %rdi
    call    set_kernel_stack

    /* Update SYSCALL_KERNEL_STACK for syscall entry */
    movq    %r12, %rdi
    call    set_syscall_kernel_stack

    /* Restore callee-saved registers from new stack */
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp

    ret

/* __switch_to_asm_first(next_sp: u64, new_kstack: u64)
 *
 * Arguments:
 *   %rdi - next task's saved RSP value
 *   %rsi - new kernel stack top (for TSS.RSP0 and SYSCALL_KERNEL_STACK)
 *
 * Used for initial switch to first task or when switching from exiting task.
 * Does NOT save current context (no prev task to save).
 *
 * IMPORTANT: We must NOT push to the stack after loading next_sp, as that
 * would corrupt the saved register frame. Use a callee-saved register (r12)
 * to preserve new_kstack across calls.
 */
__switch_to_asm_first:
    /* Load next task's RSP */
    movq    %rdi, %rsp

    /* Save new_kstack in a callee-saved register (restored later anyway) */
    movq    %rsi, %r12

    /* Update TSS.RSP0 */
    movq    %r12, %rdi
    call    set_kernel_stack

    /* Update SYSCALL_KERNEL_STACK (for syscall entry) */
    movq    %r12, %rdi
    call    set_syscall_kernel_stack

    /* Restore callee-saved registers from new stack */
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp

    ret
