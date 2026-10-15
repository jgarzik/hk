/*
 * Kernel linker script for AArch64
 *
 * QEMU virt loads the ELF at its physical addresses (AT) and enters at
 * the physical entry point with the MMU off; the DTB sits at the start
 * of RAM (0x40000000), so the image is loaded at 0x40100000. The image
 * is linked in the TTBR1 half at KIMAGE_OFFSET + physical; boot.S runs
 * position-independent until the MMU is on. Linux: arch/arm64/kernel/vmlinux.lds.S
 */

OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)

KIMAGE_OFFSET = 0xffff800000000000;
KERNEL_PHYS = 0x40100000;

/* QEMU enters the ELF entry point as a physical address */
_start_phys = _start - KIMAGE_OFFSET;
ENTRY(_start_phys)

SECTIONS
{
    . = KERNEL_PHYS + KIMAGE_OFFSET;
    __kernel_start = .;

    /* Boot code must be first; code is read-only and executable */
    .text.boot ALIGN(4K) : AT(ADDR(.text.boot) - KIMAGE_OFFSET) {
        _text = .;
        KEEP(*(.text.boot))
    }

    .text ALIGN(4K) : AT(ADDR(.text) - KIMAGE_OFFSET) {
        *(.text .text.*)
    }
    . = ALIGN(4K);
    _etext = .;

    /* Read-only data (read-only, no-execute) */
    .rodata ALIGN(4K) : AT(ADDR(.rodata) - KIMAGE_OFFSET) {
        *(.rodata .rodata.*)
        *(.got .got.*)
    }
    . = ALIGN(4K);
    __end_rodata = .;

    /* Read-write data (no-execute) */
    .data ALIGN(4K) : AT(ADDR(.data) - KIMAGE_OFFSET) {
        _sdata = .;
        *(.data .data.*)
    }

    .bss ALIGN(4K) : AT(ADDR(.bss) - KIMAGE_OFFSET) {
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
