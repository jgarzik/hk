/* Kernel linker script for x86-64 */
/* Loads at 1MB, standard location for x86 kernels */

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start32)

SECTIONS
{
    /* Kernel loads at 1MB (after real mode memory) */
    . = 1M;

    /* Multiboot header must be in first 8KB of the file */
    .multiboot ALIGN(4K) : {
        KEEP(*(.multiboot))
    }

    /* Boot stub (32-bit code and data) */
    .boot ALIGN(4K) : {
        *(.boot)
    }

    .boot_data ALIGN(4K) : {
        *(.boot_data)
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

    /* Boot BSS (page tables and stack) */
    .boot_bss ALIGN(4K) : {
        *(.boot_bss)
    }

    /* AP trampoline code (will be copied to low memory at runtime) */
    /* Symbols __trampoline_start and __trampoline_end are defined in trampoline.S */
    .trampoline ALIGN(4K) : {
        *(.trampoline)
    }

    /* Kernel end marker */
    __kernel_end = .;

    /* Discard unwanted sections */
    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
