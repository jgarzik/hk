/*
 * Kernel linker script for AArch64
 *
 * QEMU virt machine places DTB at 0x40000000 (start of RAM) for ELF kernels.
 * We load at 0x40100000 to leave 1MB for the DTB.
 */

OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_start)

/* DTB is placed at start of RAM by QEMU for bare-metal ELF boots */
DTB_ADDRESS = 0x40000000;

SECTIONS
{
    /* Kernel loads at 1GB + 1MB, leaving room for DTB at 0x40000000 */
    . = 0x40100000;

    /* Boot code must be first */
    .text.boot ALIGN(4K) : {
        KEEP(*(.text.boot))
    }

    /* Code section */
    .text ALIGN(4K) : {
        *(.text .text.*)
    }

    /* Read-only data */
    .rodata ALIGN(4K) : {
        *(.rodata .rodata.*)
    }

    /* Read-write data */
    .data ALIGN(4K) : {
        *(.data .data.*)
    }

    /* BSS (zero-initialized data) */
    .bss ALIGN(4K) : {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    /* Kernel end marker */
    . = ALIGN(4K);
    __kernel_end = .;

    /* Discard unwanted sections */
    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
