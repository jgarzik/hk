/*
 * AArch64 Exception Vector Table
 *
 * The vector table must be 2KB (0x800) aligned.
 * Each entry is 128 bytes (0x80), with 16 entries total.
 *
 * Layout:
 *   +0x000: EL1t Synchronous (EL1, SP_EL0)
 *   +0x080: EL1t IRQ
 *   +0x100: EL1t FIQ
 *   +0x180: EL1t SError
 *   +0x200: EL1h Synchronous (EL1, SP_EL1) - kernel exceptions
 *   +0x280: EL1h IRQ - kernel IRQ
 *   +0x300: EL1h FIQ
 *   +0x380: EL1h SError
 *   +0x400: EL0 64-bit Synchronous - syscalls
 *   +0x480: EL0 64-bit IRQ
 *   +0x500: EL0 64-bit FIQ
 *   +0x580: EL0 64-bit SError
 *   +0x600: EL0 32-bit Synchronous (unused)
 *   +0x680: EL0 32-bit IRQ (unused)
 *   +0x700: EL0 32-bit FIQ (unused)
 *   +0x780: EL0 32-bit SError (unused)
 */

.section .text.vectors
.balign 0x800

.global exception_vectors
exception_vectors:

// ============================================================================
// EL1t: Exception from EL1 while using SP_EL0 (unusual, treat as error)
// ============================================================================
.balign 0x80
el1t_sync:
    b       el1_sync_handler

.balign 0x80
el1t_irq:
    b       el1_irq_handler

.balign 0x80
el1t_fiq:
    b       unhandled_exception

.balign 0x80
el1t_serror:
    b       unhandled_exception

// ============================================================================
// EL1h: Exception from EL1 while using SP_EL1 (normal kernel exceptions)
// ============================================================================
.balign 0x80
el1h_sync:
    b       el1_sync_handler

.balign 0x80
el1h_irq:
    b       el1_irq_handler

.balign 0x80
el1h_fiq:
    b       unhandled_exception

.balign 0x80
el1h_serror:
    b       unhandled_exception

// ============================================================================
// EL0 64-bit: Exception from user mode (syscalls, IRQs)
// ============================================================================
.balign 0x80
el0_64_sync:
    b       el0_sync_handler

.balign 0x80
el0_64_irq:
    b       el0_irq_handler

.balign 0x80
el0_64_fiq:
    b       unhandled_exception

.balign 0x80
el0_64_serror:
    b       unhandled_exception

// ============================================================================
// EL0 32-bit: Not supported - just hang
// ============================================================================
.balign 0x80
el0_32_sync:
    b       unhandled_exception

.balign 0x80
el0_32_irq:
    b       unhandled_exception

.balign 0x80
el0_32_fiq:
    b       unhandled_exception

.balign 0x80
el0_32_serror:
    b       unhandled_exception


// ============================================================================
// Exception Handlers
// ============================================================================

/*
 * Macro to save all general-purpose registers to the stack.
 * Creates an Aarch64TrapFrame on the stack.
 *
 * Stack layout (grows down):
 *   sp+0x110: spsr
 *   sp+0x108: elr
 *   sp+0x100: sp (saved SP)
 *   sp+0x0F8: x30
 *   sp+0x0F0: x29
 *   ...
 *   sp+0x008: x1
 *   sp+0x000: x0
 *
 * Parameter: use_sp_el0 - if 1, save SP_EL0 (user stack), else save SP_EL1 (kernel stack)
 */
.macro SAVE_CONTEXT use_sp_el0=0
    // Allocate space for trap frame (31 regs + sp + elr + spsr = 34 * 8 = 272 bytes)
    sub     sp, sp, #272

    // Save x0-x29 (30 registers)
    stp     x0, x1, [sp, #0x00]
    stp     x2, x3, [sp, #0x10]
    stp     x4, x5, [sp, #0x20]
    stp     x6, x7, [sp, #0x30]
    stp     x8, x9, [sp, #0x40]
    stp     x10, x11, [sp, #0x50]
    stp     x12, x13, [sp, #0x60]
    stp     x14, x15, [sp, #0x70]
    stp     x16, x17, [sp, #0x80]
    stp     x18, x19, [sp, #0x90]
    stp     x20, x21, [sp, #0xa0]
    stp     x22, x23, [sp, #0xb0]
    stp     x24, x25, [sp, #0xc0]
    stp     x26, x27, [sp, #0xd0]
    stp     x28, x29, [sp, #0xe0]

    // Save x30 (LR)
    str     x30, [sp, #0xf0]

    // Save SP - either SP_EL0 (user) or SP_EL1 (kernel) depending on exception source
.if \use_sp_el0
    mrs     x0, sp_el0
.else
    add     x0, sp, #272
.endif
    str     x0, [sp, #0xf8]

    // Save ELR_EL1 (return address)
    mrs     x0, elr_el1
    str     x0, [sp, #0x100]

    // Save SPSR_EL1 (saved program status)
    mrs     x0, spsr_el1
    str     x0, [sp, #0x108]
.endm

/*
 * Macro to restore all general-purpose registers from the stack.
 *
 * Parameter: use_sp_el0 - if 1, restore SP_EL0 from trap frame (for return to user mode)
 */
.macro RESTORE_CONTEXT use_sp_el0=0
    // Restore SPSR_EL1
    ldr     x0, [sp, #0x108]
    msr     spsr_el1, x0

    // Restore ELR_EL1
    ldr     x0, [sp, #0x100]
    msr     elr_el1, x0

    // Restore SP_EL0 from trap frame if returning to user mode
.if \use_sp_el0
    ldr     x0, [sp, #0xf8]
    msr     sp_el0, x0
.endif

    // Restore x30
    ldr     x30, [sp, #0xf0]

    // Restore x0-x29
    ldp     x28, x29, [sp, #0xe0]
    ldp     x26, x27, [sp, #0xd0]
    ldp     x24, x25, [sp, #0xc0]
    ldp     x22, x23, [sp, #0xb0]
    ldp     x20, x21, [sp, #0xa0]
    ldp     x18, x19, [sp, #0x90]
    ldp     x16, x17, [sp, #0x80]
    ldp     x14, x15, [sp, #0x70]
    ldp     x12, x13, [sp, #0x60]
    ldp     x10, x11, [sp, #0x50]
    ldp     x8, x9, [sp, #0x40]
    ldp     x6, x7, [sp, #0x30]
    ldp     x4, x5, [sp, #0x20]
    ldp     x2, x3, [sp, #0x10]
    ldp     x0, x1, [sp, #0x00]

    // Deallocate frame
    add     sp, sp, #272
.endm


/*
 * EL1 Synchronous exception handler (kernel mode)
 * Called for data aborts, instruction aborts, etc. while in kernel.
 */
el1_sync_handler:
    SAVE_CONTEXT

    // x0 = pointer to trap frame
    mov     x0, sp
    // x1 = ESR_EL1 (exception syndrome)
    mrs     x1, esr_el1

    // Call Rust handler: handle_el1_sync(frame: *mut TrapFrame, esr: u64)
    bl      handle_el1_sync

    RESTORE_CONTEXT
    eret

/*
 * EL1 IRQ handler (kernel mode)
 */
el1_irq_handler:
    SAVE_CONTEXT

    // x0 = pointer to trap frame
    mov     x0, sp

    // Call Rust handler: handle_el1_irq(frame: *mut TrapFrame)
    bl      handle_el1_irq

    RESTORE_CONTEXT
    eret

/*
 * EL0 Synchronous exception handler (user mode - syscalls)
 */
el0_sync_handler:
    SAVE_CONTEXT 1      // use_sp_el0=1: save user stack pointer

    // Memory barrier to ensure all user memory accesses are visible
    // This is critical for correct user memory access during syscalls
    // DSB ISH: ensure all prior memory accesses complete
    // ISB: ensure pipeline is flushed and subsequent instructions see
    //      the effects of any page table updates
    dsb     ish
    isb

    // x0 = pointer to trap frame
    mov     x0, sp
    // x1 = ESR_EL1 (exception syndrome)
    mrs     x1, esr_el1

    // Call Rust handler: handle_el0_sync(frame: *mut TrapFrame, esr: u64)
    bl      handle_el0_sync

    // Memory barrier before returning to user mode to ensure all
    // kernel memory updates are visible.
    // This is critical for ARM memory ordering correctness.
    dsb     ish

    // TLB invalidate for address 0 to act as a stronger barrier.
    // Linux does this for ARM64_WORKAROUND_SPECULATIVE_UNPRIV_LOAD.
    // This ensures any speculative loads from user space see correct data.
    tlbi    vale1, xzr
    dsb     nsh
    isb

    RESTORE_CONTEXT 1   // use_sp_el0=1: restore user stack pointer
    eret

/*
 * EL0 IRQ handler (user mode)
 */
el0_irq_handler:
    SAVE_CONTEXT 1      // use_sp_el0=1: save user stack pointer

    // x0 = pointer to trap frame
    mov     x0, sp

    // Call Rust handler: handle_el0_irq(frame: *mut TrapFrame)
    bl      handle_el0_irq

    RESTORE_CONTEXT 1   // use_sp_el0=1: restore user stack pointer
    eret

/*
 * Unhandled exception - just hang
 */
unhandled_exception:
    wfi
    b       unhandled_exception
