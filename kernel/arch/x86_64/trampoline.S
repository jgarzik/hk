/* AP (Application Processor) startup trampoline for SMP
 *
 * This code is copied to low memory (0x8000) and executed by each AP
 * after receiving a SIPI (Startup IPI) from the BSP.
 *
 * The AP starts in 16-bit real mode and must transition through:
 *   16-bit real mode -> 32-bit protected mode -> 64-bit long mode
 *
 * Data layout (at end of trampoline):
 *   ap_data_pml4:       u64 - Page table root (physical)
 *   ap_data_entry:      u64 - Entry point (virtual)
 *   ap_data_stack:      u64 - Stack top (virtual)
 *   ap_data_cpu_id:     u32 - Logical CPU ID
 *   ap_data_apic_id:    u32 - Hardware APIC ID
 */

.section .trampoline, "ax"
.code16

/* These symbols are used by the Rust code to find the trampoline and data */
.global __trampoline_start
.global __trampoline_end
.global __ap_data_pml4
.global __ap_data_entry
.global __ap_data_stack
.global __ap_data_cpu_id
.global __ap_data_apic_id

__trampoline_start:
    /* Entry point - we start here in 16-bit real mode after SIPI */
    cli                             /* Disable interrupts */
    cld                             /* Clear direction flag */

    /* Set up segments for real mode */
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw $0x7000, %sp               /* Temporary stack in low memory */

    /* Load our temporary GDT for protected mode transition */
    lgdt (ap_gdt_desc - __trampoline_start + 0x8000)

    /* Enable protected mode (CR0.PE = bit 0) */
    movl %cr0, %eax
    orl $0x1, %eax
    movl %eax, %cr0

    /* Far jump to 32-bit protected mode code (selector 0x08 = code segment) */
    ljmpl $0x08, $(ap_pm32 - __trampoline_start + 0x8000)

/* ---------------------------------------------------------------------- */
/* 32-bit protected mode                                                  */
/* ---------------------------------------------------------------------- */
.align 16
.code32
ap_pm32:
    /* Set up data segments */
    movw $0x10, %ax                 /* Data segment selector */
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    /* Load CR3 with PML4 physical address */
    movl (__ap_data_pml4 - __trampoline_start + 0x8000), %eax
    movl %eax, %cr3

    /* Enable PAE (CR4.PAE = bit 5) */
    movl %cr4, %eax
    orl $(1 << 5), %eax
    movl %eax, %cr4

    /* Enable long mode (EFER.LME = bit 8) and NX (EFER.NXE = bit 11) */
    movl $0xC0000080, %ecx          /* EFER MSR */
    rdmsr
    orl $((1 << 8) | (1 << 11)), %eax  /* Set LME and NXE bits */
    wrmsr

    /* Enable paging (CR0.PG = bit 31) - this activates long mode */
    movl %cr0, %eax
    orl $(1 << 31), %eax
    movl %eax, %cr0

    /* Far jump to 64-bit long mode code (selector 0x18 = 64-bit code segment) */
    ljmpl $0x18, $(ap_lm64 - __trampoline_start + 0x8000)

/* ---------------------------------------------------------------------- */
/* 64-bit long mode                                                       */
/* ---------------------------------------------------------------------- */
.align 16
.code64
ap_lm64:
    /* Load stack from data area */
    movq (__ap_data_stack - __trampoline_start + 0x8000), %rsp

    /* Load cpu_id into edi (first arg), apic_id into esi (second arg) */
    movl (__ap_data_cpu_id - __trampoline_start + 0x8000), %edi
    movl (__ap_data_apic_id - __trampoline_start + 0x8000), %esi

    /* Jump to entry point */
    movq (__ap_data_entry - __trampoline_start + 0x8000), %rax
    jmp *%rax

/* Should never reach here */
ap_halt:
    cli
    hlt
    jmp ap_halt

/* ---------------------------------------------------------------------- */
/* GDT (must live in low memory with trampoline)                          */
/* ---------------------------------------------------------------------- */
.align 16
ap_gdt:
    .quad 0x0000000000000000        /* 0x00: Null descriptor */
    /* 0x08: 32-bit code segment - base=0, limit=4GB, code, exec/read */
    .word 0xFFFF                    /* limit 0:15 */
    .word 0x0000                    /* base 0:15 */
    .byte 0x00                      /* base 16:23 */
    .byte 0x9A                      /* present, ring0, code, exec/read */
    .byte 0xCF                      /* granularity=4K, 32-bit, limit 16:19 */
    .byte 0x00                      /* base 24:31 */
    /* 0x10: 32-bit data segment - base=0, limit=4GB, data, read/write */
    .word 0xFFFF
    .word 0x0000
    .byte 0x00
    .byte 0x92                      /* present, ring0, data, read/write */
    .byte 0xCF
    .byte 0x00
    /* 0x18: 64-bit code segment - L=1, D=0 */
    .word 0x0000                    /* limit (ignored in 64-bit) */
    .word 0x0000                    /* base (ignored in 64-bit) */
    .byte 0x00
    .byte 0x9A                      /* present, ring0, code, exec/read */
    .byte 0xA0                      /* L=1 (64-bit), D=0, granularity=0 */
    .byte 0x00
ap_gdt_end:

/* GDT descriptor for lgdt instruction */
.align 4
ap_gdt_desc:
    .word ap_gdt_end - ap_gdt - 1   /* Limit */
    .long ap_gdt - __trampoline_start + 0x8000  /* Base (runtime address) */

/* ---------------------------------------------------------------------- */
/* Data area - BSP patches these before sending SIPI                      */
/* ---------------------------------------------------------------------- */
.align 8
__ap_data_pml4:
    .quad 0                         /* Page table root (physical address) */
__ap_data_entry:
    .quad 0                         /* Entry point function (virtual address) */
__ap_data_stack:
    .quad 0                         /* Stack top (virtual address) */
__ap_data_cpu_id:
    .long 0                         /* Logical CPU ID */
__ap_data_apic_id:
    .long 0                         /* Hardware APIC ID */

__trampoline_end:
