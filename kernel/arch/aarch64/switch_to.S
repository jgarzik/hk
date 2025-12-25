/*
 * AArch64 Context Switch Assembly
 *
 * This implements the core task switching mechanism for aarch64.
 * Saves/restores callee-saved registers per AAPCS64 (ARM ABI).
 *
 * Callee-saved registers: x19-x28, x29 (FP), x30 (LR)
 * The stack pointer (SP) is also saved/restored.
 *
 * TLS (TPIDR_EL0) handling is done in Rust before calling these functions,
 * following the Linux kernel pattern (tls_thread_switch before cpu_switch_to).
 */

.section .text

.global __switch_to_asm
.global __switch_to_asm_first

/*
 * __switch_to_asm(prev_ctx: *mut TaskContext, next_ctx: *const TaskContext,
 *                 new_kstack: u64, new_ttbr0: u64)
 *
 * Arguments (AAPCS64):
 *   x0 - Pointer to prev task's TaskContext (to save into)
 *   x1 - Pointer to next task's TaskContext (to restore from)
 *   x2 - new kernel stack top (unused on aarch64 - SP managed by context)
 *   x3 - new task's TTBR0_EL1 (user page table physical address)
 *
 * TaskContext layout (must match Rust struct Aarch64TaskContext):
 *   offset 0x00: x19-x28 (10 registers, 80 bytes)
 *   offset 0x50: fp (x29)
 *   offset 0x58: lr (x30)
 *   offset 0x60: sp
 */
__switch_to_asm:
    /* Save callee-saved registers to prev context */
    stp     x19, x20, [x0, #0x00]
    stp     x21, x22, [x0, #0x10]
    stp     x23, x24, [x0, #0x20]
    stp     x25, x26, [x0, #0x30]
    stp     x27, x28, [x0, #0x40]
    stp     x29, x30, [x0, #0x50]   // FP, LR
    mov     x9, sp
    str     x9, [x0, #0x60]         // SP

    /* Switch to new user page table */
    msr     ttbr0_el1, x3
    tlbi    vmalle1is               // Invalidate TLB for EL1
    ic      iallu                   // Invalidate instruction cache
    dsb     sy                      // Full system barrier (stronger than ish)
    isb                             // Synchronize context

    /* Restore callee-saved registers from next context */
    ldp     x19, x20, [x1, #0x00]
    ldp     x21, x22, [x1, #0x10]
    ldp     x23, x24, [x1, #0x20]
    ldp     x25, x26, [x1, #0x30]
    ldp     x27, x28, [x1, #0x40]
    ldp     x29, x30, [x1, #0x50]   // FP, LR
    ldr     x9, [x1, #0x60]
    mov     sp, x9                  // SP

    ret                             // Return to new task's LR

/*
 * __switch_to_asm_first(next_ctx: *const TaskContext, new_kstack: u64, new_ttbr0: u64) -> !
 *
 * Arguments:
 *   x0 - Pointer to next task's TaskContext (to restore from)
 *   x1 - new kernel stack top (unused on aarch64)
 *   x2 - new task's TTBR0_EL1 (user page table physical address)
 *
 * Used for initial switch to first task.
 * Does NOT save current context (no prev task to save).
 * Never returns - enters the first task.
 */
__switch_to_asm_first:
    /* Switch to new user page table */
    msr     ttbr0_el1, x2
    tlbi    vmalle1is               // Invalidate TLB
    ic      iallu                   // Invalidate instruction cache
    dsb     sy                      // Full system barrier
    isb

    /* Restore callee-saved registers from next context */
    ldp     x19, x20, [x0, #0x00]
    ldp     x21, x22, [x0, #0x10]
    ldp     x23, x24, [x0, #0x20]
    ldp     x25, x26, [x0, #0x30]
    ldp     x27, x28, [x0, #0x40]
    ldp     x29, x30, [x0, #0x50]   // FP, LR
    ldr     x9, [x0, #0x60]
    mov     sp, x9                  // SP

    ret                             // Jump to task's entry (via LR)
