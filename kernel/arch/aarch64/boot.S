/*
 * AArch64 boot entry point
 *
 * When loaded by QEMU with -kernel flag, we receive:
 *   x0 = DTB pointer (physical address of device tree blob)
 *   x1-x3 = 0 (reserved)
 *   PC = entry point (_start)
 *
 * CPU state:
 *   - Running at EL1 (kernel mode)
 *   - MMU disabled
 *   - Caches may be enabled
 *   - Interrupts disabled (DAIF.IF set)
 */

.section .text.boot
.global _start

/*
 * ARM64 Image header (64 bytes)
 * This makes QEMU use Linux boot protocol and pass DTB in x0
 */
_start:
    /* code0: Branch to real entry point (skip header) */
    b       real_start

    /* code1: Reserved */
    .word   0

    /* text_offset: Offset from start of RAM to load image (2MB alignment) */
    .quad   0x100000    /* Load at RAM + 1MB */

    /* image_size: Effective size of kernel image */
    .quad   0           /* 0 = unknown, let bootloader figure it out */

    /* flags: Kernel flags */
    .quad   0           /* LE kernel, 4K pages, anywhere placement */

    /* res2, res3, res4: Reserved */
    .quad   0
    .quad   0
    .quad   0

    /* magic: ARM64 magic number "ARM\x64" */
    .ascii  "ARM\x64"

    /* res5: PE header offset (0 for non-EFI) */
    .word   0

real_start:
    /* Save DTB pointer FIRST - before anything else */
    mov     x19, x0

    /* Early debug: Print "X0=" and the DTB pointer value to UART */
    /* UART base address for QEMU virt is 0x09000000 */
    mov     x10, #0x09000000

    /* Print "X0=" */
    mov     w11, #'X'
    str     w11, [x10]
    mov     w11, #'0'
    str     w11, [x10]
    mov     w11, #'='
    str     w11, [x10]

    /* Print x19 (saved DTB pointer) as hex */
    mov     x12, x19
    mov     x13, #60        /* Start from high bits */
1:
    lsr     x14, x12, x13
    and     x14, x14, #0xF
    cmp     x14, #10
    blt     2f
    add     x14, x14, #('A' - 10)
    b       3f
2:
    add     x14, x14, #'0'
3:
    str     w14, [x10]
    sub     x13, x13, #4
    cmp     x13, #0
    bge     1b

    /* Print newline */
    mov     w11, #'\r'
    str     w11, [x10]
    mov     w11, #'\n'
    str     w11, [x10]

    /* Get CPU ID from MPIDR_EL1 */
    mrs     x1, mpidr_el1
    and     x1, x1, #0xFF       /* Aff0 = CPU ID within cluster */

    /* Only CPU 0 (BSP) continues, others wait */
    cbnz    x1, .Lspin_secondary

    /* Set up stack for BSP */
    adrp    x0, __stack_top
    add     sp, x0, :lo12:__stack_top

    /* Clear BSS */
    adrp    x0, __bss_start
    add     x0, x0, :lo12:__bss_start
    adrp    x1, __bss_end
    add     x1, x1, :lo12:__bss_end
.Lclear_bss:
    cmp     x0, x1
    b.ge    .Lbss_done
    str     xzr, [x0], #8
    b       .Lclear_bss
.Lbss_done:

    /* Pass DTB pointer to Rust entry */
    mov     x0, x19

    /* Jump to Rust entry point */
    bl      _start_rust

    /* Should never return, but halt if it does */
.Lhalt:
    wfi
    b       .Lhalt

/* Secondary CPUs spin here until SMP startup */
.Lspin_secondary:
    wfe                         /* Wait for event */
    b       .Lspin_secondary    /* Loop forever for now */

/*
 * AP (Application Processor) entry point
 *
 * Called by PSCI CPU_ON with:
 *   x0 = context_id (pointer to ApBootData structure)
 *   MMU disabled, EL1, caches off
 *
 * ApBootData layout:
 *   +0x00: stack_top (u64)
 *   +0x08: ttbr0 (u64)
 *   +0x10: entry_point (u64)
 *   +0x18: mpidr (u64)
 *   +0x20: cpu_id (u32)
 */
.section .text.boot
.global ap_entry_point
.balign 4
ap_entry_point:
    /* x0 = context_id = pointer to ApBootData - save FIRST before clobbering */
    mov     x19, x0

    /* Load stack pointer from ApBootData */
    ldr     x1, [x19, #0]           /* stack_top */
    mov     sp, x1

    /* Load page table base from ApBootData */
    ldr     x20, [x19, #8]          /* ttbr0 - save for later */

    /* Invalidate TLB */
    tlbi    vmalle1
    dsb     ish
    isb

    /* Set MAIR_EL1 (Memory Attribute Indirection Register) */
    /* Attr0 = Normal (0xFF), Attr1 = Device-nGnRnE (0x00) */
    mov     x1, #0xFF00
    msr     mair_el1, x1
    isb

    /* Set TCR_EL1 (Translation Control Register) */
    /* 48-bit VA, 4KB granule, inner/outer write-back cacheable */
    /* Value = 0x00000025B5103510 */
    movz    x1, #0x3510
    movk    x1, #0xB510, lsl #16
    movk    x1, #0x0025, lsl #32
    msr     tcr_el1, x1
    isb

    /* Set TTBR0_EL1 and TTBR1_EL1 */
    msr     ttbr0_el1, x20
    msr     ttbr1_el1, x20
    isb

    /* Ensure writes complete before enabling MMU */
    dsb     ish
    isb

    /* Enable MMU, caches via SCTLR_EL1 */
    mrs     x1, sctlr_el1
    orr     x1, x1, #(1 << 0)       /* M: MMU enable */
    orr     x1, x1, #(1 << 2)       /* C: Data cache enable */
    orr     x1, x1, #(1 << 12)      /* I: Instruction cache enable */
    msr     sctlr_el1, x1
    isb

    /* Load Rust entry point from ApBootData */
    ldr     x1, [x19, #16]          /* entry_point */

    /* x0 = boot data pointer - pass to Rust */
    mov     x0, x19

    /* Jump to Rust AP entry */
    br      x1

/*
 * BSS section symbols (defined by linker script)
 */
.section .bss
.align 16
__stack_bottom:
    .skip 32768                 /* 32KB stack for BSP */
.global __stack_top
__stack_top:
