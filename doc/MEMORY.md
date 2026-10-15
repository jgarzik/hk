# hk Memory Layout

hk uses Linux's virtual memory layout: the lower half of every address
space belongs to user space, the kernel lives in the upper half. Kernel
code reaches RAM through the direct map (`phys_to_virt` / `virt_to_phys`,
Linux `__va` / `__pa`); physical addresses are never dereferenced.

## x86-64 (4-level paging, 48-bit virtual)

Linux: `Documentation/arch/x86/x86_64/mm.rst`.

| Virtual range | Size | Contents |
|---|---|---|
| `0000000000000000 - 00007fffffffefff` | 128 TB | user space (`TASK_SIZE`) |
| `ffff888000000000 - ...` | RAM | direct map of all RAM (`PAGE_OFFSET`) |
| `ffffc90000000000 - ffffc9003fffffff` | 1 GB | vmalloc/ioremap window (`VMALLOC_START`) |
| `ffffffff80000000 - ...` | image | kernel image (`__START_KERNEL_map`, -2 GB) |

- **Kernel image**: GRUB loads it at physical 1 MB; it is linked at
  `0xffffffff80000000 + physical` (the kernel code model). Text is
  read-only and executable, rodata read-only, data and bss writable;
  nothing is both writable and executable (`kmap.rs::map_image`).
- **Direct map**: every 2 MB chunk holding RAM (multiboot memory map
  types available, ACPI, NVS) plus the first 1 MB; 1 GB pages where a
  whole gigabyte is RAM and the CPU has them, otherwise 2 MB pages. All
  RAM is mapped, so all RAM can be handed out by the frame allocator.
- **Kernel half sharing**: PML4 entries 256-511 are built once
  (`kmap::init`) and copied into each new address space; the lower
  tables are shared, so kernel mappings added later (ioremap) are seen
  everywhere (see `doc/LOCKING.md`, Kernel Page Tables).
- **Boot**: `boot.S` runs at the physical load address with temporary
  tables that identity-map 0-4 GB and map the image high; it jumps to
  the high-half `_start`, whose first act is `kmap::init`, switching to
  the kernel table (no low mappings). The AP trampoline (copied to
  physical 0x8000) enables paging on the boot table (identity map plus
  the kernel half) and `ap_entry` switches to the kernel table.
- **Kernel memory**: the heap is a fixed physical range after the boot
  modules, used through the direct map; kernel stacks and DMA buffers
  are physically contiguous frame runs, also through the direct map.
