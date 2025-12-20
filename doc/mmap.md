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

## Mapping Flags (MAP_*)

| Flag | Value | Description | Status |
|------|-------|-------------|--------|
| MAP_SHARED | 0x01 | Share with other processes | Not implemented |
| MAP_PRIVATE | 0x02 | Private copy-on-write | Implemented |
| MAP_FIXED | 0x10 | Use exact address | Implemented |
| MAP_ANONYMOUS | 0x20 | No file backing | Implemented |
| MAP_GROWSDOWN | 0x100 | Stack-like growth | Not implemented |
| MAP_LOCKED | 0x2000 | Lock pages in memory | Via mlock syscalls |
| MAP_NORESERVE | 0x4000 | Don't reserve swap | Not implemented |
| MAP_POPULATE | 0x8000 | Prefault pages | Not implemented |
| MAP_HUGETLB | 0x40000 | Use huge pages | Not implemented |

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
    locked_vm: u64,      // Count of locked pages
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
Zero-fill for anonymous mapping
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

### VMA Lock Flags

| Flag | Value | Description |
|------|-------|-------------|
| VM_LOCKED | 0x2000 | Pages are locked in memory |
| VM_LOCKONFAULT | 0x10000 | Lock pages on first fault |

## Error Codes

| Error | Value | Condition |
|-------|-------|-----------|
| EINVAL | -22 | Invalid argument (length=0, bad alignment, etc.) |
| ENOMEM | -12 | No memory for VMA or page tables |
| EACCES | -13 | Permission denied (file not readable) |
| EBADF | -9 | Bad file descriptor |
| ENODEV | -19 | File doesn't support mmap |

## Future Work

### Tier 1: File-Backed Mappings
- Read file contents on demand fault
- Handle truncated files (SIGBUS)
- mmap() with actual file descriptors

### Tier 2: Shared Mappings (MAP_SHARED)
- Multiple processes share same physical pages
- Write visibility between processes
- msync() for file writeback

### Tier 3: Memory Protection
- mprotect() syscall
- Change protection on existing mappings

### Tier 4: Advanced Features
- mremap() - Resize/move mappings
- madvise() - Memory usage hints
- MAP_POPULATE - Prefault pages
- MAP_HUGETLB - Huge page support

## File Locations

| File | Purpose |
|------|---------|
| kernel/mm/vma.rs | VMA struct, PROT_*, MAP_*, VM_LOCKED* constants |
| kernel/mm/mod.rs | MmStruct, TASK_MM table, lifecycle functions |
| kernel/mm/syscall.rs | sys_mmap, sys_munmap, mlock syscalls |
| kernel/arch/x86_64/interrupts.rs | x86-64 demand paging handler |
| kernel/arch/aarch64/exceptions.rs | aarch64 demand paging handler |
| user/syscall/{x86_64,aarch64}.rs | Userspace syscall wrappers |
| user/tests/mmap.rs | Boot tester mmap tests |

## References

- Linux mmap(2) man page
- Linux munmap(2) man page
- Understanding the Linux Virtual Memory Manager (Mel Gorman)
