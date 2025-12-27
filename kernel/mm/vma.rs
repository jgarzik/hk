//! Virtual Memory Area (VMA) implementation
//!
//! Describes contiguous regions of virtual memory in a process's address space.

use alloc::sync::Arc;

use crate::fs::File;
use crate::mm::anon_vma::AnonVma;

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
/// MAP_FIXED_NOREPLACE - like MAP_FIXED but fails with EEXIST instead of unmapping
/// Safer alternative to MAP_FIXED that doesn't silently replace existing mappings
pub const MAP_FIXED_NOREPLACE: u32 = 0x100000;

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

/// VMA has random access pattern (madvise MADV_RANDOM)
pub const VM_RAND_READ: u32 = 0x0010_0000;

/// VMA has sequential access pattern (madvise MADV_SEQUENTIAL)
pub const VM_SEQ_READ: u32 = 0x0020_0000;

/// VMA should not be copied on fork (madvise MADV_DONTFORK)
pub const VM_DONTCOPY: u32 = 0x0040_0000;

/// VMA should not be included in core dumps (madvise MADV_DONTDUMP)
pub const VM_DONTDUMP: u32 = 0x0080_0000;

/// VMA explicitly allows transparent huge pages (madvise MADV_HUGEPAGE)
/// When set, the kernel will try to use 2MB pages for this VMA
pub const VM_HUGEPAGE: u32 = 0x0100_0000;

/// VMA explicitly prohibits transparent huge pages (madvise MADV_NOHUGEPAGE)
/// When set, the kernel will never use huge pages for this VMA
pub const VM_NOHUGEPAGE: u32 = 0x0200_0000;

// ============================================================================
// msync flags (MS_*)
// ============================================================================

/// MS_ASYNC - Schedule write but don't wait (no-op in modern Linux)
pub const MS_ASYNC: i32 = 1;

/// MS_INVALIDATE - Invalidate cached pages
pub const MS_INVALIDATE: i32 = 2;

/// MS_SYNC - Synchronously write dirty pages to disk
pub const MS_SYNC: i32 = 4;

// ============================================================================
// madvise flags (MADV_*)
// ============================================================================

/// MADV_NORMAL - No special treatment (default)
pub const MADV_NORMAL: i32 = 0;

/// MADV_RANDOM - Expect random page references
pub const MADV_RANDOM: i32 = 1;

/// MADV_SEQUENTIAL - Expect sequential page references
pub const MADV_SEQUENTIAL: i32 = 2;

/// MADV_WILLNEED - Will need these pages soon (prefault)
pub const MADV_WILLNEED: i32 = 3;

/// MADV_DONTNEED - Don't need these pages (zap and free)
pub const MADV_DONTNEED: i32 = 4;

/// MADV_FREE - Mark pages as lazily freeable (kernel may free them if needed)
pub const MADV_FREE: i32 = 8;

/// MADV_DONTFORK - Don't copy this VMA on fork
pub const MADV_DONTFORK: i32 = 10;

/// MADV_DOFORK - Do copy this VMA on fork (undo MADV_DONTFORK)
pub const MADV_DOFORK: i32 = 11;

/// MADV_DONTDUMP - Don't include in core dumps
pub const MADV_DONTDUMP: i32 = 16;

/// MADV_DODUMP - Include in core dumps (undo MADV_DONTDUMP)
pub const MADV_DODUMP: i32 = 17;

/// MADV_HUGEPAGE - Mark region as suitable for transparent huge pages
/// Linux value from include/uapi/asm-generic/mman-common.h
pub const MADV_HUGEPAGE: i32 = 14;

/// MADV_NOHUGEPAGE - Mark region as unsuitable for transparent huge pages
/// Linux value from include/uapi/asm-generic/mman-common.h
pub const MADV_NOHUGEPAGE: i32 = 15;

// ============================================================================
// mremap flags (MREMAP_*)
// ============================================================================

/// MREMAP_MAYMOVE - Allow kernel to move mapping if can't resize in-place
pub const MREMAP_MAYMOVE: u32 = 1;

/// MREMAP_FIXED - Move to exact new_addr (implies MREMAP_MAYMOVE)
pub const MREMAP_FIXED: u32 = 2;

/// MREMAP_DONTUNMAP - Keep original mapping after move (requires old_len == new_len)
pub const MREMAP_DONTUNMAP: u32 = 4;

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
    /// Anonymous VMA tracking for reverse mapping
    ///
    /// Set for private anonymous mappings (MAP_ANONYMOUS | MAP_PRIVATE).
    /// Shared between parent and child on fork for COW pages.
    pub anon_vma: Option<Arc<AnonVma>>,
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
            anon_vma: None,
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
            anon_vma: None,
        }
    }

    /// Create a new anonymous VMA with anon_vma tracking
    ///
    /// Used for MAP_ANONYMOUS | MAP_PRIVATE mappings that need
    /// reverse mapping support for swap-out.
    pub fn new_anon(start: u64, end: u64, prot: u32, flags: u32, anon_vma: Arc<AnonVma>) -> Self {
        Self {
            start,
            end,
            prot,
            flags,
            file: None,
            offset: 0,
            anon_vma: Some(anon_vma),
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

    /// Check if this VMA can merge with another adjacent VMA
    ///
    /// Two VMAs can merge if they are adjacent and have identical:
    /// - Protection flags (prot)
    /// - VMA flags (flags)
    /// - File backing (both anonymous or same file with contiguous offsets)
    /// - anon_vma (must be same Arc for anonymous mappings)
    pub fn can_merge_with(&self, other: &Vma) -> bool {
        // Must be adjacent (this VMA ends where other begins)
        if self.end != other.start {
            return false;
        }
        // Must have same protection
        if self.prot != other.prot {
            return false;
        }
        // Must have same flags
        if self.flags != other.flags {
            return false;
        }
        // Must have same anon_vma (or both None)
        match (&self.anon_vma, &other.anon_vma) {
            (None, None) => {}
            (Some(av1), Some(av2)) => {
                if !Arc::ptr_eq(av1, av2) {
                    return false;
                }
            }
            _ => return false, // One has anon_vma, other doesn't
        }
        // Must have same file backing with contiguous offsets
        match (&self.file, &other.file) {
            (None, None) => true, // Both anonymous
            (Some(f1), Some(f2)) => {
                // Same file and contiguous offset
                Arc::ptr_eq(f1, f2) && self.offset + self.size() == other.offset
            }
            _ => false, // One has file, other doesn't
        }
    }

    /// Check if this VMA is a private anonymous mapping
    ///
    /// These are the mappings that can be swapped out and need
    /// reverse mapping support.
    #[inline]
    pub fn is_anon_private(&self) -> bool {
        self.is_anonymous() && self.is_private()
    }

    /// Get the anon_vma for this VMA, if any
    #[inline]
    pub fn get_anon_vma(&self) -> Option<&Arc<AnonVma>> {
        self.anon_vma.as_ref()
    }

    /// Set the anon_vma for this VMA
    pub fn set_anon_vma(&mut self, anon_vma: Arc<AnonVma>) {
        self.anon_vma = Some(anon_vma);
    }

    // =========================================================================
    // Transparent Huge Page (THP) support
    // =========================================================================

    /// Check if this VMA is eligible for transparent huge pages
    ///
    /// A VMA is THP-eligible if:
    /// - It is anonymous and private (not file-backed, not shared)
    /// - VM_NOHUGEPAGE is not set
    /// - VM_HUGEPAGE is set (we currently require explicit opt-in)
    ///
    /// For now we require MADV_HUGEPAGE to enable THP (madvise mode).
    /// This is safer than always-on THP and matches typical Linux deployments.
    #[inline]
    pub fn is_thp_eligible(&self) -> bool {
        self.is_anon_private() && !self.prohibits_hugepage() && self.wants_hugepage()
    }

    /// Check if this VMA explicitly wants transparent huge pages
    ///
    /// Returns true if MADV_HUGEPAGE was called on this VMA.
    #[inline]
    pub fn wants_hugepage(&self) -> bool {
        self.flags & VM_HUGEPAGE != 0
    }

    /// Check if this VMA explicitly prohibits transparent huge pages
    ///
    /// Returns true if MADV_NOHUGEPAGE was called on this VMA.
    #[inline]
    pub fn prohibits_hugepage(&self) -> bool {
        self.flags & VM_NOHUGEPAGE != 0
    }
}
