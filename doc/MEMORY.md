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

## arm64 (4KB granule, 48-bit virtual)

Linux: `Documentation/arch/arm64/memory.rst`.

| Virtual range | Size | Contents |
|---|---|---|
| `0000000000000000 - 0000ffffffffffff` | 256 TB | user space (TTBR0, `TASK_SIZE`) |
| `ffff000000000000 - ...` | RAM | linear map of RAM (`PAGE_OFFSET` + phys) |
| `ffff800040100000 - ...` | image | kernel image (`KIMAGE_OFFSET` + phys) |
| `ffff800100000000 - ffff80013fffffff` | 1 GB | vmalloc/ioremap window |
| `ffff800200000000 - ffff80023fffffff` | 1 GB | device window: physical 0-1 GB as Device-nGnRnE (`io_va`) |

- **TTBR0** holds only user mappings; kernel threads run with an empty
  table (Linux `reserved_pg_dir`). **TTBR1** is the kernel table, built
  once by `kmap::init` and never switched per process.
- **Kernel image**: QEMU loads the ELF at physical 0x40100000 and
  enters at the physical entry point with the MMU off. `boot.S` is
  position independent until it enables the MMU on boot tables (1 GB
  blocks: an identity map of the kernel's RAM gigabyte in TTBR0; in
  TTBR1 the first RAM gigabyte, the image and the device window), then
  jumps to the linked address. W^X as on x86.
- **Linear map**: the DTB `/memory` range, 1 GB blocks where possible,
  2 MB otherwise; built after the heap exists (the DTB parser needs
  it), then TTBR1 is switched from the identity map
  (`__replace_ttbr1`, Linux `cpu_replace_ttbr1`).
- **Device window**: an early fixmap for QEMU virt's fixed devices
  (GIC, PL011, PL031) and PCI MMIO below 1 GB; `ioremap` returns
  window addresses for that range and maps anything else (PCI ECAM)
  into the ioremap window.
- **APs**: PSCI `CPU_ON` enters `ap_entry_point` (physical) with the
  boot data's physical address; it enables the MMU with the kernel
  TTBR1 and the identity map, jumps high, and `ap_rust_entry` drops the
  identity map.

## User address space (both arches)

- `mmap_min_addr` is 65536 (Linux vm.mmap_min_addr default): below it a
  fixed mapping fails with EPERM unless the task has CAP_SYS_RAWIO, and
  no mapping is ever placed there.
- Executables load at their linked address (non-PIE `ET_EXEC`, e.g.
  busybox at 0x400000) or, for PIE, at `ELF_ET_DYN_BASE`
  (0x555555554000 on x86-64, 0xaaaaaaaa0000 on arm64; no ASLR). Each
  PT_LOAD segment and the stack are VMAs (`/proc/<pid>/maps`).
- `brk` starts at the page after the last segment.
- The stack ends at `STACK_TOP` (0x7ffffffff000 on x86-64, 2^48 on
  arm64) and grows down up to RLIMIT_STACK; the initial stack holds
  argc/argv/envp and the Linux auxiliary vector (AT_PHDR, AT_RANDOM,
  AT_EXECFN, AT_HWCAP, ...).
- `mmap` without a hint allocates top-down from below the stack gap
  (STACK_TOP less RLIMIT_STACK, at least 128 MB); hints are used when
  the whole range is free and mappable.
- `access_ok` accepts a range only if it ends at or below `TASK_SIZE`;
  SMAP (x86) and PAN (arm64) catch stray kernel accesses to user memory.


## Address space lifetime (both arches)

An address space is an `Mm` (Linux mm_struct, `kernel/mm/mod.rs`): its
top-level table (x86 PML4, arm64 TTBR0 L0) and its VMAs. Locking and the
reference rules are in `doc/LOCKING.md` (Address Spaces).

- **Two counts, as in Linux.** `users` (mm_users): the tasks running in
  it (threads and a vfork parent share one) and short-lived pinned users
  (ptrace, process_vm_*, a /proc/<pid>/maps read). The `Arc` count
  (mm_count) keeps the struct and the top-level table.
- **Frame references.** Every present user PTE holds one reference on its
  frame: a fault allocates with count 1, fork increfs each copy-on-write
  frame, a SysV shm attachment takes one per page (the segment holds its
  own), splitting a 2MB page gives each 4KB frame the head's count.
  Unmapping drops the reference and the last one frees the frame. Frames
  outside the allocator (MMIO) have no count and are never freed.
- **Teardown (Linux exit_mmap).** When `users` drops to zero (last task
  exits, or the old image at exec), the VMAs and their rmap chains go,
  the user half is detached from the top-level table and the TLB
  flushed, then every user leaf is released (4KB pages, 2MB pages, swap
  slots) and every lower table frame (all levels) freed. The kernel half
  (x86 PML4 256-511, shared) and TTBR1 are never touched.
- **Top-level table (Linux __mmdrop).** Freed with the last `Arc`: an
  exiting task keeps one until its CPU has switched to another task
  (the next task frees it with the dead task's kernel stack).
- **exec** builds the new image in a fresh `Mm` (an error frees it),
  switches the task to it, then drops its user reference on the old one,
  which is torn down only if no vfork parent or other thread uses it.
- **munmap / MAP_FIXED / brk shrink / shmdt** release the pages in the
  range under the mm lock; empty page-table pages are kept until exit
  (reused by later mappings at the same addresses).
- `/proc/meminfo` reports MemTotal and MemFree from the frame allocator
  (exact free count).
