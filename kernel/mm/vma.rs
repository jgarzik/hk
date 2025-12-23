//! Virtual Memory Area (VMA) implementation
//!
//! Describes contiguous regions of virtual memory in a process's address space.

use alloc::sync::Arc;

use crate::fs::File;

/// Protection flags - Linux PROT_* values
pub const PROT_NONE: u32 = 0;
pub const PROT_READ: u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC: u32 = 4;
/// PROT_GROWSDOWN - mprotect: extend change to start of growsdown VMA
pub const PROT_GROWSDOWN: u32 = 0x0100_0000;
/// PROT_GROWSUP - mprotect: extend change to end of growsup VMA
/// Note: Always fails with EINVAL on x86-64/aarch64 (no VM_GROWSUP VMAs)
pub const PROT_GROWSUP: u32 = 0x0200_0000;

/// Map flags - Linux MAP_* values
pub const MAP_SHARED: u32 = 0x01;
pub const MAP_PRIVATE: u32 = 0x02;
pub const MAP_FIXED: u32 = 0x10;
pub const MAP_ANONYMOUS: u32 = 0x20;
/// MAP_GROWSDOWN - stack-like segment that grows downward on page faults
pub const MAP_GROWSDOWN: u32 = 0x0100;
/// MAP_DENYWRITE - ignored for Linux ABI compatibility (deprecated)
/// Linux kernel explicitly ignores this flag (see include/linux/mman.h)
pub const MAP_DENYWRITE: u32 = 0x0800;
/// MAP_EXECUTABLE - ignored for Linux ABI compatibility (deprecated)
/// Linux kernel explicitly ignores this flag (see include/linux/mman.h)
pub const MAP_EXECUTABLE: u32 = 0x1000;
/// MAP_LOCKED - lock pages in memory (Linux mman.h value)
/// Note: Same value as VM_LOCKED (0x2000) - Linux uses calc_vm_flag_bits() for identity mapping
pub const MAP_LOCKED: u32 = 0x2000;
/// MAP_POPULATE - prefault page tables (populate pages immediately after mmap)
pub const MAP_POPULATE: u32 = 0x8000;
/// MAP_NONBLOCK - don't block on I/O when used with MAP_POPULATE
/// When combined with MAP_POPULATE, the populate step is skipped
pub const MAP_NONBLOCK: u32 = 0x10000;
/// MAP_STACK - hint for stack allocation (no-op in hk, no THP support)
/// Linux uses this to set VM_NOHUGEPAGE when transparent huge pages are enabled
pub const MAP_STACK: u32 = 0x20000;

/// Return value for failed mmap
pub const MAP_FAILED: i64 = -1;

// ============================================================================
// VMA flags (internal kernel flags, stored in Vma.flags alongside MAP_*)
// These use higher bits to avoid conflict with MAP_* flags
// ============================================================================

/// Pages in this VMA are memory-locked (cannot be swapped out)
/// Matches Linux VM_LOCKED bit position
pub const VM_LOCKED: u32 = 0x2000;

/// Pages will be locked on fault (deferred locking for mlock2/MCL_ONFAULT)
/// Matches Linux VM_LOCKONFAULT bit position
pub const VM_LOCKONFAULT: u32 = 0x0001_0000;

/// Combined mask for all lock-related VMA flags
pub const VM_LOCKED_MASK: u32 = VM_LOCKED | VM_LOCKONFAULT;

/// VMA is backed by System V shared memory segment
/// Uses a high bit to avoid conflicts with standard flags
pub const VM_SHM: u32 = 0x0002_0000;

/// VMA is a shared mapping (MAP_SHARED)
/// This affects how page faults are handled - shared mappings
/// share the same physical pages and writes are visible to all
pub const VM_SHARED: u32 = 0x0004_0000;

/// VMA can expand downward on page faults (stack-like growth)
/// Set when MAP_GROWSDOWN is used during mmap
pub const VM_GROWSDOWN: u32 = 0x0008_0000;

/// Page size (4KB)
pub const PAGE_SIZE: u64 = 4096;

/// Virtual Memory Area - describes a contiguous region of virtual memory
#[derive(Clone)]
pub struct Vma {
    /// Start address (page-aligned, inclusive)
    pub start: u64,
    /// End address (page-aligned, exclusive)
    pub end: u64,
    /// Protection flags (PROT_READ | PROT_WRITE | PROT_EXEC)
    pub prot: u32,
    /// Map flags (MAP_SHARED, MAP_PRIVATE, MAP_ANONYMOUS, etc.)
    pub flags: u32,
    /// File backing (None for anonymous mappings)
    pub file: Option<Arc<File>>,
    /// Offset within file (in bytes, page-aligned)
    pub offset: u64,
}

impl Vma {
    /// Create a new VMA
    pub fn new(start: u64, end: u64, prot: u32, flags: u32) -> Self {
        Self {
            start,
            end,
            prot,
            flags,
            file: None,
            offset: 0,
        }
    }

    /// Create a new file-backed VMA
    pub fn new_file(
        start: u64,
        end: u64,
        prot: u32,
        flags: u32,
        file: Arc<File>,
        offset: u64,
    ) -> Self {
        Self {
            start,
            end,
            prot,
            flags,
            file: Some(file),
            offset,
        }
    }

    /// Check if address falls within this VMA
    #[inline]
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Size of mapping in bytes
    #[inline]
    pub fn size(&self) -> u64 {
        self.end - self.start
    }

    /// Check if this is an anonymous mapping
    #[inline]
    pub fn is_anonymous(&self) -> bool {
        self.flags & MAP_ANONYMOUS != 0
    }

    /// Check if this is a private mapping
    #[inline]
    pub fn is_private(&self) -> bool {
        self.flags & MAP_PRIVATE != 0
    }

    /// Check if this is a shared mapping
    #[inline]
    pub fn is_shared(&self) -> bool {
        self.flags & MAP_SHARED != 0
    }

    /// Check if this VMA is writable
    #[inline]
    pub fn is_writable(&self) -> bool {
        self.prot & PROT_WRITE != 0
    }

    /// Check if this VMA is readable
    #[inline]
    pub fn is_readable(&self) -> bool {
        self.prot & PROT_READ != 0
    }

    /// Check if this VMA is executable
    #[inline]
    pub fn is_executable(&self) -> bool {
        self.prot & PROT_EXEC != 0
    }

    /// Check if this VMA is memory-locked
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.flags & VM_LOCKED != 0
    }

    /// Check if this VMA has lock-on-fault enabled
    #[inline]
    pub fn is_lockonfault(&self) -> bool {
        self.flags & VM_LOCKONFAULT != 0
    }

    /// Check if this VMA can grow downward (stack-like)
    #[inline]
    pub fn is_growsdown(&self) -> bool {
        self.flags & VM_GROWSDOWN != 0
    }
}
