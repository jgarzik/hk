/* 32-bit to 64-bit boot stub for multiboot2 */
/* This code runs in 32-bit protected mode after GRUB loads us */
/* It sets up long mode and jumps to the 64-bit Rust kernel */

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

/* Page tables - identity map first 512MB */
pml4:
    .skip 4096
pdpt:
    .skip 4096
pd:
    .skip 4096

/* Stack */
.align 16
stack_bottom:
    .skip 16384                         /* 16KB stack */
stack_top:

.section .boot, "ax"
.code32
.global _start32

_start32:
    /* Disable interrupts */
    cli

    /* Save multiboot info pointer (in EBX) for later */
    movl %ebx, (multiboot_info_ptr)

    /* Set up stack - use absolute address */
    movl $stack_top, %esp

    /* Clear page tables - use absolute addresses */
    movl $pml4, %edi
    xorl %eax, %eax
    movl $3072, %ecx                    /* 3 * 4096 / 4 = 3072 dwords */
    rep stosl

    /* Set up PML4[0] -> PDPT */
    movl $pdpt, %eax
    orl $0x03, %eax                     /* Present + Writable */
    movl %eax, pml4

    /* Set up PDPT[0] -> PD */
    movl $pd, %eax
    orl $0x03, %eax
    movl %eax, pdpt

    /* Map 512MB using 2MB pages (256 entries in PD) */
    movl $pd, %edi
    movl $0x83, %eax                    /* Present + Writable + Huge (2MB) */
    movl $256, %ecx                     /* 256 * 2MB = 512MB */
1:
    movl %eax, (%edi)
    movl $0, 4(%edi)                    /* High 32 bits = 0 */
    addl $0x200000, %eax                /* Next 2MB */
    addl $8, %edi
    decl %ecx
    jnz 1b

    /* Load PML4 into CR3 */
    movl $pml4, %eax
    movl %eax, %cr3

    /* Enable PAE in CR4 */
    movl %cr4, %eax
    orl $0x20, %eax                     /* PAE bit */
    movl %eax, %cr4

    /* Enable long mode in EFER MSR */
    movl $0xC0000080, %ecx              /* EFER MSR */
    rdmsr
    orl $0x100, %eax                    /* LME bit */
    wrmsr

    /* Enable paging in CR0 */
    movl %cr0, %eax
    orl $0x80000000, %eax               /* PG bit */
    movl %eax, %cr0

    /* Load 64-bit GDT */
    lgdt gdt64_ptr

    /* Jump to 64-bit code - use far jump with absolute address */
    ljmp $0x08, $long_mode_start

.code64
long_mode_start:
    /* Set up segment registers */
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    /* Set up 64-bit stack */
    movabsq $stack_top, %rsp

    /* Pass multiboot2 info pointer in RDI */
    /* Zero-extend 32-bit pointer to 64-bit (pointer is in low memory) */
    movl multiboot_info_ptr, %edi

    /* Jump to Rust kernel entry point */
    movabsq $_start, %rax
    call *%rax

    /* Should never return, but halt if it does */
2:
    hlt
    jmp 2b

.section .boot_data, "a"
.align 8

/* Storage for multiboot info pointer */
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
    .long gdt64                         /* Base (32-bit, sufficient for low memory) */
    .long 0                             /* Padding for 64-bit alignment */
