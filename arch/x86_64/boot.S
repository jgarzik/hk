/* 32-bit to 64-bit boot stub for multiboot2
 *
 * GRUB enters _start32 in 32-bit protected mode, paging off, at the
 * physical load address. The stub builds the boot page tables, enables
 * long mode and jumps to the kernel's high-half entry (_start). Linux:
 * arch/x86/kernel/head_64.S (early_top_pgt).
 *
 * Boot page tables (2MB pages):
 *   PML4[0]   -> identity map of 0-4GB (this stub, later the AP trampoline)
 *   PML4[273] -> same: early direct map at PAGE_OFFSET (0xffff888000000000)
 *   PML4[511] -> PDPT[510..511]: kernel image at __START_KERNEL_map
 *                (0xffffffff80000000 -> physical 0-2GB)
 * paging::init replaces them with the kernel page table (swapper), which
 * has no low mapping; boot_pml4 then serves as the AP trampoline table.
 */

.equ PML4_DIRECT, 273                  /* PAGE_OFFSET >> 39 & 511 */
.equ PTE_TABLE, 0x03                    /* present + writable */
.equ PTE_LARGE, 0x83                    /* present + writable + 2MB */

.section .multiboot, "a"
.align 8

/* Multiboot2 header */
multiboot_header:
    .long 0xE85250D6                    /* magic */
    .long 0                             /* architecture: i386 */
    .long multiboot_header_end - multiboot_header  /* header length */
    .long -(0xE85250D6 + 0 + (multiboot_header_end - multiboot_header))  /* checksum */

    /* End tag */
    .short 0                            /* type */
    .short 0                            /* flags */
    .long 8                             /* size */
multiboot_header_end:

.section .boot_bss, "aw", @nobits
.align 4096

.global boot_pml4
boot_pml4:
    .skip 4096
boot_pdpt_low:                          /* 0-4GB: 4 PDs */
    .skip 4096
boot_pdpt_high:                         /* -2GB: PDPT[510..511] */
    .skip 4096
boot_pd:                                /* 4 x 512 x 2MB = 4GB */
    .skip 4 * 4096
boot_tables_end:

.section .boot, "ax"
.code32
.global _start32

_start32:
    cli

    /* Save multiboot info pointer (in EBX) for later */
    movl %ebx, (multiboot_info_ptr)

    /* Clear the boot page tables */
    movl $boot_pml4, %edi
    xorl %eax, %eax
    movl $((boot_tables_end - boot_pml4) / 4), %ecx
    rep stosl

    /* PML4[0] and PML4[273] -> boot_pdpt_low; PML4[511] -> boot_pdpt_high */
    movl $boot_pdpt_low + PTE_TABLE, %eax
    movl %eax, boot_pml4
    movl %eax, boot_pml4 + PML4_DIRECT * 8
    movl $boot_pdpt_high + PTE_TABLE, %eax
    movl %eax, boot_pml4 + 511 * 8

    /* boot_pdpt_low[0..3] -> boot_pd[0..3] */
    movl $boot_pdpt_low, %edi
    movl $boot_pd + PTE_TABLE, %eax
    movl $4, %ecx
1:
    movl %eax, (%edi)
    addl $4096, %eax
    addl $8, %edi
    decl %ecx
    jnz 1b

    /* boot_pdpt_high[510..511] -> boot_pd[0..1] (image: physical 0-2GB) */
    movl $boot_pd + PTE_TABLE, %eax
    movl %eax, boot_pdpt_high + 510 * 8
    addl $4096, %eax
    movl %eax, boot_pdpt_high + 511 * 8

    /* boot_pd: 2048 x 2MB pages, physical 0-4GB */
    movl $boot_pd, %edi
    movl $PTE_LARGE, %eax
    movl $2048, %ecx
2:
    movl %eax, (%edi)
    movl $0, 4(%edi)
    addl $0x200000, %eax
    addl $8, %edi
    decl %ecx
    jnz 2b

    movl $boot_pml4, %eax
    movl %eax, %cr3

    /* PAE */
    movl %cr4, %eax
    orl $0x20, %eax
    movl %eax, %cr4

    /* EFER: long mode + NX (the kernel tables use NX) */
    movl $0xC0000080, %ecx
    rdmsr
    orl $0x900, %eax
    wrmsr

    /* PG + WP (kernel writes honor R/O user PTEs, for COW) */
    movl %cr0, %eax
    orl $0x80010000, %eax
    movl %eax, %cr0

    lgdt gdt64_ptr
    ljmp $0x08, $long_mode_start

.code64
long_mode_start:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    /* High-half stack, then the high-half entry */
    movabsq $boot_stack_top, %rsp
    movl multiboot_info_ptr, %edi
    movabsq $_start, %rax
    call *%rax

3:
    hlt
    jmp 3b

.section .boot_data, "a"
.align 8

multiboot_info_ptr:
    .long 0

gdt64:
    .quad 0                             /* Null descriptor */
    .quad 0x00AF9A000000FFFF            /* Code: 64-bit, present, executable */
    .quad 0x00AF92000000FFFF            /* Data: 64-bit, present, writable */
gdt64_end:

.align 4
gdt64_ptr:
    .word gdt64_end - gdt64 - 1         /* Limit */
    .long gdt64                         /* Base (physical, low) */
    .long 0

/* BSP boot stack (high half; the Rust entry runs on it) */
.section .bss.boot_stack, "aw", @nobits
.align 16
boot_stack_bottom:
    .skip 32768
boot_stack_top:
