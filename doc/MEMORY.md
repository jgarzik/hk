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
- Page faults on user addresses (user mode, or a kernel uaccess) go to
  the generic `mm::fault::handle_mm_fault` on both arches: the VMA must
  allow the access (Linux access_error: a read needs any of
  PROT_READ/WRITE/EXEC, a write PROT_WRITE, an instruction fetch
  PROT_EXEC), then a missing page is mapped (zeroed, a 2MB page for a
  MADV_HUGEPAGE area, or a copy of the file data), a swap entry read
  back, or a write-protected page made writable (copied first if still
  shared copy-on-write). Unresolved: SIGSEGV or SIGBUS for a user
  access, EFAULT for a kernel uaccess.
- Out of memory: pages for user data and user page tables stop at the
  reserve kept for the kernel (1/32 of RAM, at least 4MB; Linux min
  watermark). mlock that cannot fault its range in fails with EAGAIN. A user fault that finds no memory kills its process
  with SIGKILL, logged as `Out of memory: Killed process <pid> (<comm>)`
  (Linux pagefault_out_of_memory; hk has no OOM killer choosing another
  victim, and never retries the fault in a loop); a kernel uaccess that
  finds none fails with EFAULT (Linux kernelmode_fixup_or_oops). Past
  RLIMIT_AS, mmap/mremap fail with ENOMEM and brk keeps the break.
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
  frame: a fault allocates with count 1, fork increfs each frame it
  shares, a shared object (shared anonymous memory, a SysV shm segment)
  holds its own on each of its pages, splitting a 2MB page gives each 4KB frame the head's count.
  Unmapping drops the reference and the last one frees the frame. Frames
  outside the allocator (MMIO) have no count and are never freed.
- **Shared anonymous memory.** A MAP_SHARED|MAP_ANONYMOUS mapping gets a
  `Shmem` object (Linux shmem_zero_setup) holding its pages by index:
  every VMA mapping it (fork's copies, split pieces, mremap) faults the
  same page in, so pages first touched after fork are shared too, and
  MADV_DONTNEED keeps the data (MADV_REMOVE clears it for every
  mapping: a page mapped elsewhere is zeroed in place, others freed).
  Its size is fixed at mmap (a page past it, after mremap grew the
  mapping, is SIGBUS, as on Linux); its pages and its index (a 4-level
  radix tree of 512-entry nodes, like a page table) are user memory
  from frames, none from the kernel heap (they stop at the kernel's
  reserve; a fault out of memory kills the process). The object holds
  a reference on each page; it goes with its last VMA. A SysV shm
  segment is such an object too: shmat maps it lazily, and each attach
  VMA holds a `ShmAttach` counted in shm_nattch (Linux shm_open /
  shm_close), so fork, split, munmap, shmdt, exit and exec keep the
  count, and the last detach of a removed segment destroys it.
- **File mappings.** A MAP_SHARED mapping of a ramfs file maps the
  file's page-cache pages (`InodeOps::map_page`, Linux filemap_fault):
  every mapping, fork's copies and read()/write() see the same data, and
  a page past the one holding the end of the file is SIGBUS. Other
  filesystems, and MAP_PRIVATE mappings, get a private copy of the data
  at fault time.
- **fork (Linux dup_mmap / copy_page_range).** Each VMA is copied with its
  PTEs: a MAP_SHARED mapping keeps sharing its pages (writes stay
  visible both ways); a private one shares them copy-on-write (both
  PTEs read-only and marked COW, also for pages read-only at fork, so a
  later mprotect(PROT_WRITE) cannot make the shared page writable). A
  2MB page is split into 4KB PTEs in the parent first; a swap PTE fails
  the fork (ENOMEM; unreachable while swap-out is inert). MADV_DONTFORK VMAs are left out of the
  child, MADV_WIPEONFORK ones start empty there, and memory locks
  (VM_LOCKED, locked_vm, MCL_FUTURE) are not inherited.
- **Page-table updates (break-before-make).** An entry that maps a
  page is changed in place only for its permissions. To map another
  page (a copy-on-write break) or another size (a 2MB page split into
  512 4KB PTEs; its table allocated first, so a failed split changes
  nothing), it is cleared and its TLB entry flushed first, then the new
  entry written (ARM ARM break-before-make; Linux ptep_clear_flush,
  pmdp_invalidate).
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
- **munmap / MAP_FIXED / brk shrink / shmdt** split VMAs at the range
  edges and release the pages inside; empty page-table pages are kept
  until exit (reused by later mappings at the same addresses).
- **mremap move (Linux move_page_tables)** allocates first: the old
  range's 2MB pages are split and the new range's page tables
  allocated before any VMA or entry changes (ENOMEM then leaves the
  old mapping intact); then, under the same mm lock hold, the old VMA
  (split at the old range's edges) is retired, the new one inserted,
  the entries (pages, swap) moved into it with their frame references,
  and the old range's TLB flushed. Shrinking unmaps the tail like
  munmap.
- `/proc/meminfo` reports MemTotal and MemFree from the frame allocator
  (exact free count).
