# Memory Mapping (mmap) Implementation

This document describes the Linux-compatible mmap/munmap syscall implementation in hk kernel.

## Overview

The `mmap()` syscall creates virtual memory mappings. It is the fundamental building block for:
- **Heap allocation** - glibc malloc uses mmap for large allocations
- **File-backed mappings** - Map files into memory for efficient I/O
- **Shared memory** - IPC between processes via shared mappings
- **Anonymous mappings** - Zero-filled private memory regions

## Syscall Interface

### mmap

```c
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
```

| Argument | Description |
|----------|-------------|
| addr | Hint address (0 = kernel chooses) |
| length | Mapping size in bytes |
| prot | Protection flags (PROT_*) |
| flags | Mapping flags (MAP_*) |
| fd | File descriptor (-1 for anonymous) |
| offset | File offset (page-aligned) |

**Returns**: Mapped address on success, -errno on failure

### munmap

```c
int munmap(void *addr, size_t length);
```

| Argument | Description |
|----------|-------------|
| addr | Start address (page-aligned) |
| length | Size to unmap |

**Returns**: 0 on success, -errno on failure

## Protection Flags (PROT_*)

| Flag | Value | Description | Status |
|------|-------|-------------|--------|
| PROT_NONE | 0x0 | No access | Implemented |
| PROT_READ | 0x1 | Read permission | Implemented |
| PROT_WRITE | 0x2 | Write permission | Implemented |
| PROT_EXEC | 0x4 | Execute permission | Implemented |
| PROT_SEM | 0x8 | Atomic ops support | Not implemented |
| PROT_GROWSDOWN | 0x01000000 | mprotect: extend to growsdown VMA start | Implemented |
| PROT_GROWSUP | 0x02000000 | mprotect: extend to growsup VMA end | Implemented (always EINVAL on x86-64/aarch64) |

## Mapping Flags (MAP_*)

| Flag | Value | Description | Status |
|------|-------|-------------|--------|
| MAP_SHARED | 0x01 | Share with other processes | Implemented |
| MAP_PRIVATE | 0x02 | Private copy-on-write | Implemented |
| MAP_FIXED | 0x10 | Use exact address | Implemented |
| MAP_ANONYMOUS | 0x20 | No file backing | Implemented |
| MAP_GROWSDOWN | 0x100 | Stack-like segment growth | Implemented |
| MAP_DENYWRITE | 0x0800 | ETXTBSY (deprecated) | Implemented (ignored per Linux) |
| MAP_EXECUTABLE | 0x1000 | Mark executable (deprecated) | Implemented (ignored per Linux) |
| MAP_LOCKED | 0x2000 | Lock pages in memory | Implemented |
| MAP_NORESERVE | 0x4000 | Don't reserve swap | Not implemented |
| MAP_POPULATE | 0x8000 | Prefault pages | Implemented |
| MAP_NONBLOCK | 0x10000 | Non-blocking with MAP_POPULATE | Implemented |
| MAP_STACK | 0x20000 | Stack allocation hint | Implemented (no-op, no THP) |
| MAP_HUGETLB | 0x40000 | Use huge pages | Not implemented |
| MAP_SYNC | 0x80000 | Synchronous page faults (DAX) | Not implemented |
| MAP_FIXED_NOREPLACE | 0x100000 | MAP_FIXED without unmapping | Implemented |
| MAP_UNINITIALIZED | 0x4000000 | Skip zero-fill (embedded only) | Not implemented |

## Implementation Architecture

### Data Structures

#### VMA (Virtual Memory Area)
```rust
pub struct Vma {
    pub start: u64,              // Page-aligned start address
    pub end: u64,                // Page-aligned end (exclusive)
    pub prot: u32,               // PROT_* flags
    pub flags: u32,              // MAP_* flags
    pub file: Option<Arc<File>>, // File backing (None for anonymous)
    pub offset: u64,             // File offset
}
```

#### MmStruct (Per-Task Memory Descriptor)
```rust
pub struct MmStruct {
    vmas: Vec<Vma>,      // Sorted by start address
    mmap_base: u64,      // Base for free area search
    mmap_end: u64,       // End of mmap region
    start_brk: u64,      // Initial program break (heap start)
    brk: u64,            // Current program break
    locked_vm: u64,      // Count of locked pages
    total_vm: u64,       // Total virtual memory (for RLIMIT_AS)
    def_flags: u32,      // Default VMA flags (for mlockall MCL_FUTURE)
}
```

### Address Space Layout

| Architecture | mmap_base | mmap_end |
|--------------|-----------|----------|
| x86-64 | 0x7F00_0000_0000 | 0x8000_0000_0000 |
| aarch64 | 0x0000_7F00_0000_0000 | 0x0000_8000_0000_0000 |

### Demand Paging

Pages are **not** allocated at mmap time. Instead:

1. mmap creates a VMA entry describing the mapping
2. First access triggers a page fault
3. Page fault handler checks if address is in a VMA
4. If yes: allocate frame, zero-fill (anonymous) or read from file, map page
5. If no: deliver SIGSEGV

#### x86-64 Page Fault Flow
```
Page Fault (error_code)
    ↓
Check !present && user mode
    ↓
handle_mmap_fault(fault_addr, is_write)
    ↓
Find VMA containing fault_addr
    ↓
Check write permission if is_write
    ↓
Allocate frame (FRAME_ALLOCATOR.alloc())
    ↓
Zero-fill (anonymous) or read from file (file-backed)
    ↓
Map page with appropriate permissions
    ↓
Flush TLB
```

#### aarch64 Page Fault Flow
```
Data Abort (EC_DABORT_LOWER)
    ↓
Check DFSC 0x04-0x07 (translation fault)
    ↓
handle_mmap_fault(FAR_EL1, is_write)
    ↓
(same as x86-64 from here)
```

### Task Lifecycle Integration

| Event | Action |
|-------|--------|
| Task creation | `init_task_mm()` - Create default MmStruct |
| clone/fork | `clone_task_mm()` - Share (CLONE_VM) or copy VMAs |
| Task exit | `exit_task_mm()` - Remove MmStruct from table |

## Common Usage Patterns

### Anonymous Private Mapping (heap)
```c
void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
```
Used by malloc for large allocations.

### File-Backed Private Mapping
```c
int fd = open("file.txt", O_RDONLY);
void *ptr = mmap(NULL, size, PROT_READ,
                 MAP_PRIVATE, fd, 0);
```
Private copy-on-write mapping of file contents.

### Fixed Address Mapping
```c
void *ptr = mmap((void*)0x10000000, size,
                 PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
```
Map at exact address (removes any existing mappings).

## Memory Locking (mlock)

The mlock family of syscalls lock virtual memory pages into physical RAM, preventing them from being paged out. Since hk currently has no swap, these primarily provide ABI compatibility and set the VM_LOCKED flag on VMAs for future-proofing.

### mlock/mlock2

```c
int mlock(const void *addr, size_t len);
int mlock2(const void *addr, size_t len, unsigned int flags);
```

| Flag | Value | Description |
|------|-------|-------------|
| MLOCK_ONFAULT | 0x01 | Lock pages on first fault (don't populate immediately) |

**Returns**: 0 on success, -errno on failure

### munlock

```c
int munlock(const void *addr, size_t len);
```

Unlocks pages in the specified range, allowing them to be paged out (when swap is implemented).

### mlockall/munlockall

```c
int mlockall(int flags);
int munlockall(void);
```

| Flag | Value | Description |
|------|-------|-------------|
| MCL_CURRENT | 1 | Lock all current mappings |
| MCL_FUTURE | 2 | Lock all future mappings |
| MCL_ONFAULT | 4 | Lock on fault (combine with MCL_CURRENT or MCL_FUTURE) |

### VMA Flags

| Flag | Value | Description |
|------|-------|-------------|
| VM_LOCKED | 0x2000 | Pages are locked in memory |
| VM_LOCKONFAULT | 0x10000 | Lock pages on first fault |
| VM_SHM | 0x20000 | System V shared memory segment |
| VM_SHARED | 0x40000 | Shared mapping (MAP_SHARED) |

## Error Codes

| Error | Value | Condition |
|-------|-------|-----------|
| EINVAL | -22 | Invalid argument (length=0, bad alignment, etc.) |
| ENOMEM | -12 | No memory for VMA or page tables |
| EACCES | -13 | Permission denied (file not readable) |
| EBADF | -9 | Bad file descriptor |
| ENODEV | -19 | File doesn't support mmap |

### mprotect

```c
int mprotect(void *addr, size_t len, int prot);
```

| Argument | Description |
|----------|-------------|
| addr | Start address (page-aligned) |
| len | Length in bytes (0 = no-op) |
| prot | New protection flags (PROT_*) |

**Returns**: 0 on success, -errno on failure

Changes the protection flags for pages in the specified range. The range must be fully covered by existing VMAs (returns ENOMEM for unmapped regions).

### msync

```c
int msync(void *addr, size_t length, int flags);
```

| Argument | Description |
|----------|-------------|
| addr | Start address (page-aligned) |
| length | Length in bytes |
| flags | Combination of MS_ASYNC, MS_SYNC, MS_INVALIDATE |

| Flag | Value | Description |
|------|-------|-------------|
| MS_ASYNC | 1 | Schedule write but don't wait (no-op in modern kernels) |
| MS_INVALIDATE | 2 | Invalidate cached pages |
| MS_SYNC | 4 | Synchronously write dirty pages to disk |

**Returns**: 0 on success, -errno on failure

Flushes changes made to file-backed mappings back to the filesystem. MS_ASYNC and MS_SYNC are mutually exclusive.

### madvise

```c
int madvise(void *addr, size_t length, int advice);
```

| Argument | Description |
|----------|-------------|
| addr | Start address (page-aligned) |
| length | Length in bytes |
| advice | Type of advice (MADV_*) |

| Flag | Value | Description | Status |
|------|-------|-------------|--------|
| MADV_NORMAL | 0 | No special treatment (default) | Implemented |
| MADV_RANDOM | 1 | Expect random page references | Implemented |
| MADV_SEQUENTIAL | 2 | Expect sequential page references | Implemented |
| MADV_WILLNEED | 3 | Will need these pages soon (prefault) | Implemented |
| MADV_DONTNEED | 4 | Don't need these pages (zap and free) | Implemented |
| MADV_FREE | 8 | Mark pages as lazily freeable | Implemented (treated as DONTNEED) |
| MADV_DONTFORK | 10 | Don't copy this VMA on fork | Implemented |
| MADV_DOFORK | 11 | Do copy this VMA on fork | Implemented |
| MADV_DONTDUMP | 16 | Don't include in core dumps | Implemented |
| MADV_DODUMP | 17 | Include in core dumps | Implemented |

**Returns**: 0 on success, -errno on failure

Advises the kernel about how to handle paging I/O in the specified address range. MADV_DONTNEED is particularly important as it's widely used by allocators to release memory.

### mremap

```c
void *mremap(void *old_addr, size_t old_len, size_t new_len,
             int flags, ... /* void *new_addr */);
```

| Argument | Description |
|----------|-------------|
| old_addr | Start address of existing mapping (page-aligned) |
| old_len | Old length of mapping in bytes |
| new_len | New length of mapping in bytes |
| flags | MREMAP_* flags |
| new_addr | New address (only used with MREMAP_FIXED) |

**Returns**: New address on success, -errno on failure

| Flag | Value | Description | Status |
|------|-------|-------------|--------|
| MREMAP_MAYMOVE | 0x01 | Allow kernel to move mapping if can't resize in-place | Implemented |
| MREMAP_FIXED | 0x02 | Move to exact new_addr (implies MAYMOVE) | Implemented |
| MREMAP_DONTUNMAP | 0x04 | Keep original mapping after move | Implemented |

## Missing Syscalls

| Syscall | Priority | Description |
|---------|----------|-------------|
| mincore | Low | Query page residency status |

## Implementation Notes

Current limitations in the implementation:

1. **No VMA merging** - Adjacent VMAs with compatible flags are not merged. Linux has sophisticated merge logic (`vma_merge()`) for efficiency.

2. **No VMA splitting** - mprotect on a partial VMA region updates the entire VMA's protection; a full implementation would split the VMA.

## Future Work

### Tier 1: Core Functionality (DONE)
- ~~**mprotect()** - Change protection on existing mappings~~ ✓
- ~~**MAP_SHARED** - Shared memory between processes~~ ✓
- ~~**File-backed mapping I/O** - Read file contents on demand fault~~ ✓
- ~~**MAP_GROWSDOWN** - Stack-like growth for guard pages~~ ✓
- ~~**PROT_GROWSDOWN/PROT_GROWSUP** - mprotect growth extensions~~ ✓
- ~~**MAP_POPULATE** - Prefault pages to avoid later faults~~ ✓
- ~~**MAP_NONBLOCK** - Skip populate when combined with MAP_POPULATE~~ ✓
- ~~**MAP_STACK** - Stack allocation hint (no-op, no THP)~~ ✓

### Tier 2: Common Features (DONE)
- ~~**madvise()** - Memory hints (MADV_DONTNEED for memory release)~~ ✓
- ~~**mremap()** - Resize/move mappings (used by realloc)~~ ✓
- ~~**msync()** - Sync file-backed mappings to disk~~ ✓
- ~~**MAP_FIXED_NOREPLACE** - Safer MAP_FIXED that fails on overlap~~ ✓

### Tier 3: Optimization
- **VMA merging** - Merge adjacent compatible VMAs

### Tier 4: Advanced Features
- **MAP_HUGETLB** - Huge page support (requires arch TLB support)
- **mincore()** - Query which pages are resident

## File Locations

| File | Purpose |
|------|---------|
| kernel/mm/vma.rs | VMA struct, PROT_*, MAP_*, VM_LOCKED* constants |
| kernel/mm/mod.rs | MmStruct, TASK_MM table, lifecycle functions |
| kernel/mm/syscall.rs | sys_mmap, sys_munmap, mlock syscalls |
| kernel/mm/page_cache.rs | Page cache infrastructure for file-backed mappings |
| kernel/mm/writeback.rs | Dirty page writeback for file-backed mappings |
| kernel/arch/x86_64/interrupts.rs | x86-64 demand paging handler |
| kernel/arch/aarch64/exceptions.rs | aarch64 demand paging handler |
| user/tests/mmap.rs | Boot tester mmap tests |

## References

- Linux mmap(2) man page
- Linux munmap(2) man page
- Understanding the Linux Virtual Memory Manager (Mel Gorman)
