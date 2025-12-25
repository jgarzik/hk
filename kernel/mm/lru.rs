//! LRU page lists for page reclaim
//!
//! Maintains separate lists for active and inactive pages following Linux's
//! two-list LRU design:
//!
//! - **Inactive list**: Pages that haven't been accessed recently. These are
//!   candidates for eviction during memory pressure.
//!
//! - **Active list**: Pages that have been accessed at least twice recently.
//!   These are protected from immediate eviction.
//!
//! Pages start on the inactive list when first allocated. On a second access
//! (when already on inactive), they are promoted to the active list. When
//! the active list grows too large or we need victims, pages are demoted
//! from active back to inactive.
//!
//! This implements a "second chance" algorithm: a page must be accessed
//! twice before being protected from eviction.

extern crate alloc;

use alloc::collections::VecDeque;

use spin::Mutex;

use crate::mm::page::{PG_ACTIVE, PG_LRU, page_descriptor};

// ============================================================================
// LRU Lists
// ============================================================================

/// LRU lists for page reclaim
///
/// Uses VecDeque for O(1) push/pop at both ends.
/// We store physical frame addresses (page-aligned).
pub struct LruLists {
    /// Recently accessed pages (second chance protection)
    active: VecDeque<u64>,
    /// Candidates for eviction
    inactive: VecDeque<u64>,
}

impl LruLists {
    /// Create empty LRU lists
    const fn new() -> Self {
        Self {
            active: VecDeque::new(),
            inactive: VecDeque::new(),
        }
    }

    /// Add a new page to the inactive list (at the back)
    ///
    /// Called when a page is first allocated for user space.
    /// The page starts on inactive and can be promoted on second access.
    pub fn add_new(&mut self, frame: u64) {
        // Update page descriptor flags
        if let Some(page) = page_descriptor(frame) {
            page.set_flag(PG_LRU);
            page.clear_flag(PG_ACTIVE);
        }
        self.inactive.push_back(frame);
    }

    /// Mark a page as accessed
    ///
    /// If on inactive list: promote to active list (second access)
    /// If on active list: move to back (refresh position)
    /// If not on any list: do nothing
    pub fn mark_accessed(&mut self, frame: u64) {
        // Check if on inactive list - if so, promote to active
        if let Some(pos) = self.inactive.iter().position(|&f| f == frame) {
            self.inactive.remove(pos);
            self.active.push_back(frame);

            // Update page descriptor
            if let Some(page) = page_descriptor(frame) {
                page.set_flag(PG_ACTIVE);
            }
            return;
        }

        // Check if on active list - if so, refresh position
        if let Some(pos) = self.active.iter().position(|&f| f == frame) {
            self.active.remove(pos);
            self.active.push_back(frame);
        }
    }

    /// Remove a page from LRU lists
    ///
    /// Called when a page is freed or swapped out.
    pub fn remove(&mut self, frame: u64) {
        // Update page descriptor
        if let Some(page) = page_descriptor(frame) {
            page.clear_flag(PG_LRU | PG_ACTIVE);
        }

        // Remove from whichever list it's on
        self.inactive.retain(|&f| f != frame);
        self.active.retain(|&f| f != frame);
    }

    /// Get the next victim for eviction
    ///
    /// Returns the frame at the front of the inactive list.
    /// If inactive is empty, demotes pages from active to inactive first.
    /// Returns None if both lists are empty.
    pub fn get_victim(&mut self) -> Option<u64> {
        // If inactive is empty, try to demote from active
        if self.inactive.is_empty() && !self.active.is_empty() {
            self.demote_active();
        }
        self.inactive.front().copied()
    }

    /// Remove and return the front of inactive list
    ///
    /// Called after successfully swapping out a victim.
    pub fn pop_victim(&mut self) -> Option<u64> {
        let frame = self.inactive.pop_front()?;

        // Update page descriptor
        if let Some(page) = page_descriptor(frame) {
            page.clear_flag(PG_LRU | PG_ACTIVE);
        }

        Some(frame)
    }

    /// Demote pages from active to inactive list
    ///
    /// Moves pages from the front of active to the back of inactive.
    /// This is called when we need more victims but inactive is empty.
    fn demote_active(&mut self) {
        // Demote up to 1/4 of active list or at least 1 page
        let demote_count = (self.active.len() / 4).max(1);

        for _ in 0..demote_count {
            if let Some(frame) = self.active.pop_front() {
                // Update page descriptor
                if let Some(page) = page_descriptor(frame) {
                    page.clear_flag(PG_ACTIVE);
                }
                self.inactive.push_back(frame);
            }
        }
    }

    /// Get count of pages on active list
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Get count of pages on inactive list
    pub fn inactive_count(&self) -> usize {
        self.inactive.len()
    }

    /// Get total count of pages on LRU lists
    pub fn total_count(&self) -> usize {
        self.active.len() + self.inactive.len()
    }

    /// Check if a frame is on the LRU lists
    pub fn contains(&self, frame: u64) -> bool {
        self.inactive.contains(&frame) || self.active.contains(&frame)
    }

    /// Rebalance lists if active is too large
    ///
    /// Linux tries to keep active list around half the size of inactive.
    /// This helps ensure we always have enough eviction candidates.
    pub fn rebalance(&mut self) {
        // If active is more than 2x inactive, demote some
        if self.active.len() > self.inactive.len() * 2 && !self.active.is_empty() {
            self.demote_active();
        }
    }
}

// ============================================================================
// Global LRU
// ============================================================================

/// Global LRU lists for anonymous page reclaim
///
/// Protected by a mutex. Lock ordering: LRU lock should be acquired
/// before page descriptor locks and frame allocator lock.
pub static LRU: Mutex<LruLists> = Mutex::new(LruLists::new());

// ============================================================================
// Convenience functions
// ============================================================================

/// Add a new page to LRU (convenience wrapper)
#[inline]
pub fn lru_add_new(frame: u64) {
    LRU.lock().add_new(frame);
}

/// Mark page as accessed (convenience wrapper)
#[inline]
pub fn lru_mark_accessed(frame: u64) {
    LRU.lock().mark_accessed(frame);
}

/// Remove page from LRU (convenience wrapper)
#[inline]
pub fn lru_remove(frame: u64) {
    LRU.lock().remove(frame);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lru_add_and_get_victim() {
        let mut lru = LruLists::new();

        // Add some pages
        lru.inactive.push_back(0x1000);
        lru.inactive.push_back(0x2000);
        lru.inactive.push_back(0x3000);

        // First victim should be first added
        assert_eq!(lru.get_victim(), Some(0x1000));

        // Pop it
        assert_eq!(lru.pop_victim(), Some(0x1000));

        // Next victim
        assert_eq!(lru.get_victim(), Some(0x2000));
    }

    #[test]
    fn test_lru_promote_on_access() {
        let mut lru = LruLists::new();

        // Add page to inactive
        lru.inactive.push_back(0x1000);
        assert_eq!(lru.inactive.len(), 1);
        assert_eq!(lru.active.len(), 0);

        // Mark accessed - should promote
        lru.mark_accessed(0x1000);
        assert_eq!(lru.inactive.len(), 0);
        assert_eq!(lru.active.len(), 1);
    }

    #[test]
    fn test_lru_demote_when_inactive_empty() {
        let mut lru = LruLists::new();

        // Add pages directly to active
        lru.active.push_back(0x1000);
        lru.active.push_back(0x2000);
        lru.active.push_back(0x3000);
        lru.active.push_back(0x4000);

        assert!(lru.inactive.is_empty());

        // Get victim should demote from active
        let victim = lru.get_victim();
        assert!(victim.is_some());
        assert!(!lru.inactive.is_empty());
    }

    #[test]
    fn test_lru_remove() {
        let mut lru = LruLists::new();

        lru.inactive.push_back(0x1000);
        lru.active.push_back(0x2000);

        lru.remove(0x1000);
        assert!(!lru.inactive.contains(&0x1000));

        lru.remove(0x2000);
        assert!(!lru.active.contains(&0x2000));
    }

    #[test]
    fn test_lru_counts() {
        let mut lru = LruLists::new();

        lru.inactive.push_back(0x1000);
        lru.inactive.push_back(0x2000);
        lru.active.push_back(0x3000);

        assert_eq!(lru.inactive_count(), 2);
        assert_eq!(lru.active_count(), 1);
        assert_eq!(lru.total_count(), 3);
    }
}
