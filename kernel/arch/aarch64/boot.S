/*
 * AArch64 boot entry point
 *
 * When loaded by QEMU with -kernel flag, we receive:
 *   x0 = DTB pointer (physical address of device tree blob)
 *   PC = entry point (_start, physical)
 *
 * CPU state: EL1, MMU off, interrupts masked.
 *
 * The image is linked in the TTBR1 half (kernel.ld) but entered at its
 * physical address: everything up to the MMU switch is position
 * independent (adr/adrp). The boot tables (1GB blocks) map:
 *   TTBR0: identity map of the RAM gigabyte at 0x40000000 (this code)
 *   TTBR1: linear map of that gigabyte (PAGE_OFFSET), the kernel image
 *          (KIMAGE_OFFSET + phys) and the device window (IO_BASE: phys
 *          0-1GB, Device-nGnRnE)
 * then the code jumps to its linked (high) address. kmap::init later
 * replaces them. Linux: arch/arm64/kernel/head.S.
 */

/* Block/table descriptors: normal = AF | inner shareable | AttrIdx 0;
 * device = AF | AttrIdx 1 | PXN | UXN */
.equ BLOCK_NORMAL, 0x701
.equ BLOCK_DEVICE, 0x0060000000000405
.equ DESC_TABLE, 0x3
.equ RAM_GB, 0x40000000
/* L1 indices in the 0xffff8000... L0 slot (256): image GB and devices */
.equ L1_IMAGE, 1
.equ L1_IO, 8
/* MAIR: Attr0 normal WB (0xff), Attr1 device-nGnRnE (0x00) */
.equ MAIR_VALUE, 0xff00
/* TCR: T0SZ=T1SZ=16 (48-bit), 4KB granules, inner-shareable WB walks,
 * IPS 40-bit */
.equ TCR_VALUE, 0x2B5103510

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

    /* Early debug (MMU off): "X0=" and the DTB pointer to the PL011 */
    mov     x10, #0x09000000
    mov     w11, #'X'
    str     w11, [x10]
    mov     w11, #'0'
    str     w11, [x10]
    mov     w11, #'='
    str     w11, [x10]
    mov     x12, x19
    mov     x13, #60
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
    mov     w11, #'\r'
    str     w11, [x10]
    mov     w11, #'\n'
    str     w11, [x10]

    /* Only CPU 0 (BSP) continues, others wait */
    mrs     x1, mpidr_el1
    and     x1, x1, #0xFF
    cbnz    x1, .Lspin_secondary

    /* Clear BSS (physical addresses: PC-relative) */
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

    bl      create_boot_tables
    adrp    x0, boot_l0
    bl      enable_mmu

    /* Continue at the linked (high) address */
    ldr     x0, =.Lhigh
    br      x0
.Lhigh:
    ldr     x0, =__stack_top
    mov     sp, x0
    mov     x0, x19
    bl      _start_rust

.Lhalt:
    wfi
    b       .Lhalt

/* Secondary CPUs spin here until PSCI CPU_ON */
.Lspin_secondary:
    wfe
    b       .Lspin_secondary

/*
 * Fill the (zeroed) boot tables; MMU off, so adrp yields physical
 * addresses
 */
create_boot_tables:
    ldr     x3, =BLOCK_NORMAL
    mov     x4, #RAM_GB
    orr     x5, x4, x3                  /* 1GB normal block at RAM_GB */

    /* TTBR0 identity: L0[0] -> L1; L1[1] = RAM gigabyte */
    adrp    x0, boot_idmap_l0
    adrp    x1, boot_idmap_l1
    orr     x2, x1, #DESC_TABLE
    str     x2, [x0]
    str     x5, [x1, #8]

    /* TTBR1: L0[0] -> linear L1 (L1[1] = RAM gigabyte) */
    adrp    x0, boot_l0
    adrp    x1, boot_lin_l1
    orr     x2, x1, #DESC_TABLE
    str     x2, [x0]
    str     x5, [x1, #8]

    /* TTBR1: L0[256] -> kernel L1 (image gigabyte, device window) */
    adrp    x1, boot_k_l1
    orr     x2, x1, #DESC_TABLE
    str     x2, [x0, #256 * 8]
    str     x5, [x1, #L1_IMAGE * 8]
    ldr     x3, =BLOCK_DEVICE
    str     x3, [x1, #L1_IO * 8]
    dsb     sy
    ret

/*
 * Enable the MMU: TTBR1 = x0 (physical), TTBR0 = boot identity map.
 * Called with the MMU off (BSP and APs); clobbers x1.
 */
enable_mmu:
    /* FP/SIMD at EL1 (the kernel is built with NEON) */
    mrs     x1, cpacr_el1
    orr     x1, x1, #(3 << 20)
    msr     cpacr_el1, x1

    ldr     x1, =MAIR_VALUE
    msr     mair_el1, x1
    ldr     x1, =TCR_VALUE
    msr     tcr_el1, x1
    msr     ttbr1_el1, x0
    adrp    x1, boot_idmap_l0
    msr     ttbr0_el1, x1
    isb
    tlbi    vmalle1
    dsb     nsh
    isb

    mrs     x1, sctlr_el1
    orr     x1, x1, #(1 << 0)           /* M: MMU */
    orr     x1, x1, #(1 << 2)           /* C: data cache */
    orr     x1, x1, #(1 << 12)          /* I: instruction cache */
    /* EL0 cache ops like Linux INIT_SCTLR_EL1_MMU_ON (__clear_cache, memset) */
    orr     x1, x1, #(1 << 14)          /* DZE: DC ZVA */
    orr     x1, x1, #(1 << 15)          /* UCT: CTR_EL0 reads */
    orr     x1, x1, #(1 << 26)          /* UCI: DC CVAU/CIVAC/CVAC, IC IVAU */
    msr     sctlr_el1, x1
    isb
    ret

/*
 * __replace_ttbr1(ttbr1: u64, reserved: u64): switch TTBR1 tables.
 * Called through its identity-mapped (physical) address, so no TTBR1
 * translation is in use while TTBR1 goes through the empty table
 * (Linux: idmap_cpu_replace_ttbr1). Touches no memory.
 */
.global __replace_ttbr1
__replace_ttbr1:
    msr     ttbr1_el1, x1
    isb
    tlbi    vmalle1
    dsb     nsh
    isb
    msr     ttbr1_el1, x0
    isb
    tlbi    vmalle1
    dsb     nsh
    isb
    ret

/*
 * AP (Application Processor) entry point
 *
 * Called by PSCI CPU_ON (physical address) with:
 *   x0 = context_id (physical pointer to ApBootData), MMU off, EL1
 *
 * ApBootData layout:
 *   +0x00: stack_top (u64, virtual)
 *   +0x08: ttbr1 (u64, kernel table, physical)
 *   +0x10: entry_point (u64, virtual)
 *   +0x18: mpidr (u64)
 *   +0x20: cpu_id (u32)
 */
.global ap_entry_point
.balign 4
ap_entry_point:
    mov     x19, x0
    ldr     x0, [x19, #8]
    bl      enable_mmu
    ldr     x0, =.Lap_high
    br      x0
.Lap_high:
    /* x19 is still the physical pointer: valid through the identity map */
    ldr     x1, [x19, #0]
    mov     sp, x1
    ldr     x1, [x19, #16]
    mov     x0, x19
    br      x1

.ltorg

/*
 * Boot page tables and BSP stack (zeroed with BSS)
 */
.section .bss
.balign 4096
boot_idmap_l0:
    .skip 4096
boot_idmap_l1:
    .skip 4096
boot_l0:
    .skip 4096
boot_lin_l1:
    .skip 4096
boot_k_l1:
    .skip 4096

/* 64KB-aligned like every EL1 stack (vectors.S KERNEL_ENTRY: SP has
 * bit 15 clear while on a stack); .align N is 2^N on arm */
.balign 65536
__stack_bottom:
    .skip 32768                 /* 32KB stack for BSP */
.global __stack_top
__stack_top:
