/* x86-64 Context Switch Assembly
 *
 * Follows Linux kernel's __switch_to_asm pattern.
 * Pure assembly avoids Rust inline asm ABI issues.
 *
 * This file implements the core task switching mechanism,
 * saving/restoring only callee-saved registers per System V AMD64 ABI.
 */

.section .text

.global __switch_to_asm
.global __switch_to_asm_first

/* __switch_to_asm(prev_sp_ptr: *mut u64, next_sp: u64, new_kstack: u64, new_cr3: u64)
 *
 * Arguments (System V AMD64 ABI):
 *   %rdi - Pointer to prev task's saved RSP location
 *   %rsi - next task's saved RSP value
 *   %rdx - new kernel stack top (for TSS.RSP0 and SYSCALL_KERNEL_STACK)
 *   %rcx - new task's CR3 (page table physical address)
 *
 * This function:
 *   1. Saves callee-saved registers on current stack
 *   2. Saves current RSP to *prev_sp_ptr
 *   3. Loads next task's RSP
 *   4. Updates TSS.RSP0 for interrupt handling
 *   5. Updates SYSCALL_KERNEL_STACK for syscall entry
 *   6. Loads new task's CR3 (page table)
 *   7. Restores callee-saved registers from new stack
 *   8. Returns (to the new task's saved return address)
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

    /* Save new_kstack and new_cr3 in callee-saved registers for use across calls */
    movq    %rdx, %r12
    movq    %rcx, %r13

    /* Update TSS.RSP0 for interrupt handling */
    movq    %r12, %rdi
    call    set_kernel_stack

    /* Update SYSCALL_KERNEL_STACK for syscall entry */
    movq    %r12, %rdi
    call    set_syscall_kernel_stack

    /* Switch to new task's page table (CR3) */
    /* This automatically flushes the TLB */
    movq    %r13, %cr3

    /* Restore callee-saved registers from new stack */
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp

    ret

/* __switch_to_asm_first(next_sp: u64, new_kstack: u64, new_cr3: u64)
 *
 * Arguments:
 *   %rdi - next task's saved RSP value
 *   %rsi - new kernel stack top (for TSS.RSP0 and SYSCALL_KERNEL_STACK)
 *   %rdx - new task's CR3 (page table physical address)
 *
 * Used for initial switch to first task or when switching from exiting task.
 * Does NOT save current context (no prev task to save).
 *
 * IMPORTANT: We must NOT push to the stack after loading next_sp, as that
 * would corrupt the saved register frame. Use callee-saved registers (r12, r13)
 * to preserve new_kstack and new_cr3 across calls.
 */
__switch_to_asm_first:
    /* Load next task's RSP */
    movq    %rdi, %rsp

    /* Save new_kstack and new_cr3 in callee-saved registers (will be restored later anyway) */
    movq    %rsi, %r12
    movq    %rdx, %r13

    /* Update TSS.RSP0 */
    movq    %r12, %rdi
    call    set_kernel_stack

    /* Update SYSCALL_KERNEL_STACK (for syscall entry) */
    movq    %r12, %rdi
    call    set_syscall_kernel_stack

    /* Switch to new task's page table (CR3) */
    /* This automatically flushes the TLB */
    movq    %r13, %cr3

    /* Restore callee-saved registers from new stack */
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp

    ret
