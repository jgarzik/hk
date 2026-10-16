/* Kernel linker script for x86-64
 *
 * GRUB loads the image at physical 1MB. The 32-bit boot stub and its
 * page tables are linked there (virtual == physical, they run before
 * paging and from the boot identity map); everything else is linked
 * at __START_KERNEL_map + physical (-2GB, the kernel code model) and
 * loaded at the physical address (AT). Linux: arch/x86/kernel/vmlinux.lds.S
 */

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start32)

KERNEL_PHYS = 1M;
KERNEL_MAP = 0xffffffff80000000;

SECTIONS
{
    . = KERNEL_PHYS;

    /* Multiboot header must be in the first 32KB of the file */
    .multiboot : {
        KEEP(*(.multiboot))
    }

    /* Boot stub: 32-bit code, its data and the boot page tables */
    .boot ALIGN(4K) : {
        *(.boot)
    }

    .boot_data ALIGN(4K) : {
        *(.boot_data)
    }

    .boot_bss ALIGN(4K) (NOLOAD) : {
        *(.boot_bss)
    }

    /* High half: virtual = KERNEL_MAP + physical */
    . = ALIGN(4K);
    . += KERNEL_MAP;
    __kernel_start = KERNEL_MAP + KERNEL_PHYS;

    /* Code (read-only, executable) */
    .text ALIGN(4K) : AT(ADDR(.text) - KERNEL_MAP) {
        _text = .;
        *(.text .text.*)
    }

    /* AP trampoline code (copied to low memory at runtime) */
    .trampoline ALIGN(16) : AT(ADDR(.trampoline) - KERNEL_MAP) {
        *(.trampoline)
    }
    . = ALIGN(4K);
    _etext = .;

    /* Read-only data (read-only, no-execute) */
    .rodata ALIGN(4K) : AT(ADDR(.rodata) - KERNEL_MAP) {
        *(.rodata .rodata.*)
        *(.got .got.*)
    }
    . = ALIGN(4K);
    __end_rodata = .;

    /* Read-write data (no-execute) */
    .data ALIGN(4K) : AT(ADDR(.data) - KERNEL_MAP) {
        _sdata = .;
        *(.data .data.*)
    }

    .bss ALIGN(4K) : AT(ADDR(.bss) - KERNEL_MAP) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    . = ALIGN(4K);
    __kernel_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
