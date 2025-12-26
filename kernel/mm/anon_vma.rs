//! Anonymous VMA tracking for reverse mapping
//!
//! When a process forks, both parent and child map the same anonymous pages
//! (with copy-on-write semantics). The anon_vma structure tracks all VMAs
//! that share these pages, enabling efficient reverse mapping lookups when
//! we need to swap out a page.
//!
//! ## Design (following Linux's anon_vma)
//!
//! - Each private anonymous VMA gets an associated `AnonVma` when created
//! - On fork, the child's VMA links to the parent's `AnonVma`
//! - The `AnonVma` maintains a list of all VMAs that may contain mappings
//!   to pages from the original allocation
//! - When swapping out a page, we use the page's `AnonVma` to find all VMAs
//!   that might map it, then walk each VMA's page table to find the PTE
//!
//! ## Differences from Linux
//!
//! Linux uses a more complex anon_vma_chain system with interval trees for
//! scalability with many forks. We use a simpler linear list which is
//! sufficient for our use case and easier to understand.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use spin::Mutex;

use crate::task::Tid;

// ============================================================================
// AnonVma
// ============================================================================

/// Anonymous VMA container
///
/// Links all VMAs that may share anonymous pages from a common ancestor.
/// Used for reverse mapping during swap-out.
pub struct AnonVma {
    /// Lock protecting the VMA list
    inner: Mutex<AnonVmaInner>,
}

struct AnonVmaInner {
    /// List of VMAs sharing this anon_vma
    /// Each entry identifies a VMA by (tid, vma_start, vma_end)
    vmas: Vec<AnonVmaChain>,
}

/// Links a VMA to its anon_vma
///
/// We store task ID and VMA address range rather than pointers to avoid
/// lifetime issues. During rmap_walk, we look up the actual VMA.
#[derive(Clone, Debug, PartialEq)]
pub struct AnonVmaChain {
    /// Task ID owning the VMA
    pub tid: Tid,
    /// VMA start address (used to locate VMA in task's mm)
    pub vma_start: u64,
    /// VMA end address
    pub vma_end: u64,
}

impl AnonVma {
    /// Create a new empty anon_vma
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(AnonVmaInner { vmas: Vec::new() }),
        })
    }

    /// Register a VMA with this anon_vma
    ///
    /// Called when:
    /// - A new anonymous VMA is created (mmap with MAP_ANONYMOUS|MAP_PRIVATE)
    /// - A VMA is inherited during fork
    ///
    /// # Arguments
    /// * `tid` - Task ID owning the VMA
    /// * `vma_start` - Start address of the VMA
    /// * `vma_end` - End address of the VMA
    pub fn add_vma(&self, tid: Tid, vma_start: u64, vma_end: u64) {
        let mut inner = self.inner.lock();

        // Don't add duplicates
        let chain = AnonVmaChain {
            tid,
            vma_start,
            vma_end,
        };
        if !inner.vmas.contains(&chain) {
            inner.vmas.push(chain);
        }
    }

    /// Unregister a VMA from this anon_vma
    ///
    /// Called when:
    /// - VMA is unmapped (munmap)
    /// - Task exits
    /// - VMA is replaced (mremap with MREMAP_FIXED)
    ///
    /// # Arguments
    /// * `tid` - Task ID of the VMA
    /// * `vma_start` - Start address of the VMA
    pub fn remove_vma(&self, tid: Tid, vma_start: u64) {
        let mut inner = self.inner.lock();
        inner
            .vmas
            .retain(|c| !(c.tid == tid && c.vma_start == vma_start));
    }

    /// Update VMA bounds (e.g., after mremap resize)
    ///
    /// # Arguments
    /// * `tid` - Task ID of the VMA
    /// * `old_start` - Original start address
    /// * `new_start` - New start address
    /// * `new_end` - New end address
    pub fn update_vma(&self, tid: Tid, old_start: u64, new_start: u64, new_end: u64) {
        let mut inner = self.inner.lock();
        for chain in inner.vmas.iter_mut() {
            if chain.tid == tid && chain.vma_start == old_start {
                chain.vma_start = new_start;
                chain.vma_end = new_end;
                break;
            }
        }
    }

    /// Get all VMAs registered with this anon_vma
    ///
    /// Returns a clone of the VMA list for iteration during rmap_walk.
    /// The clone allows releasing the lock during the potentially slow
    /// page table walks.
    pub fn get_vmas(&self) -> Vec<AnonVmaChain> {
        self.inner.lock().vmas.clone()
    }

    /// Check if any VMAs remain
    ///
    /// Returns true if no VMAs are registered (anon_vma can be dropped).
    pub fn is_empty(&self) -> bool {
        self.inner.lock().vmas.is_empty()
    }

    /// Get the number of VMAs registered
    pub fn vma_count(&self) -> usize {
        self.inner.lock().vmas.len()
    }

    /// Check if a specific VMA is registered
    pub fn contains_vma(&self, tid: Tid, vma_start: u64) -> bool {
        let inner = self.inner.lock();
        inner
            .vmas
            .iter()
            .any(|c| c.tid == tid && c.vma_start == vma_start)
    }
}

impl Default for AnonVma {
    fn default() -> Self {
        Self {
            inner: Mutex::new(AnonVmaInner { vmas: Vec::new() }),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anon_vma_new() {
        let av = AnonVma::new();
        assert!(av.is_empty());
        assert_eq!(av.vma_count(), 0);
    }

    #[test]
    fn test_anon_vma_add_remove() {
        let av = AnonVma::new();

        // Add a VMA
        av.add_vma(1, 0x1000, 0x2000);
        assert!(!av.is_empty());
        assert_eq!(av.vma_count(), 1);
        assert!(av.contains_vma(1, 0x1000));

        // Add another
        av.add_vma(2, 0x3000, 0x4000);
        assert_eq!(av.vma_count(), 2);

        // Remove first
        av.remove_vma(1, 0x1000);
        assert_eq!(av.vma_count(), 1);
        assert!(!av.contains_vma(1, 0x1000));
        assert!(av.contains_vma(2, 0x3000));

        // Remove second
        av.remove_vma(2, 0x3000);
        assert!(av.is_empty());
    }

    #[test]
    fn test_anon_vma_no_duplicates() {
        let av = AnonVma::new();

        av.add_vma(1, 0x1000, 0x2000);
        av.add_vma(1, 0x1000, 0x2000); // Duplicate
        av.add_vma(1, 0x1000, 0x2000); // Duplicate

        assert_eq!(av.vma_count(), 1);
    }

    #[test]
    fn test_anon_vma_get_vmas() {
        let av = AnonVma::new();

        av.add_vma(1, 0x1000, 0x2000);
        av.add_vma(2, 0x3000, 0x4000);

        let vmas = av.get_vmas();
        assert_eq!(vmas.len(), 2);

        assert!(vmas.iter().any(|c| c.tid == 1 && c.vma_start == 0x1000));
        assert!(vmas.iter().any(|c| c.tid == 2 && c.vma_start == 0x3000));
    }

    #[test]
    fn test_anon_vma_update() {
        let av = AnonVma::new();

        av.add_vma(1, 0x1000, 0x2000);

        // Simulate mremap that moves the VMA
        av.update_vma(1, 0x1000, 0x5000, 0x6000);

        assert!(!av.contains_vma(1, 0x1000));
        assert!(av.contains_vma(1, 0x5000));

        let vmas = av.get_vmas();
        assert_eq!(vmas[0].vma_start, 0x5000);
        assert_eq!(vmas[0].vma_end, 0x6000);
    }
}
