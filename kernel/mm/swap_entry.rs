//! Swap entry representation and PTE encoding
//!
//! A swap entry encodes two pieces of information:
//! - swap_type: Which swap device (0-31, 5 bits)
//! - offset: Which slot within the swap device
//!
//! Swap entries are stored in page table entries (PTEs) when a page
//! has been swapped out. The PTE has Present=0 to indicate not present,
//! with the swap entry encoded in the remaining bits.
//!
//! ## PTE Format for Swap Entries (x86-64 and aarch64)
//!
//! ```text
//! Bit 0:     0 (not present / not valid)
//! Bits 1-5:  swap type (0-31)
//! Bits 6-58: swap offset
//! Bits 59-63: reserved (must be 0 for swap detection)
//! ```
//!
//! This allows up to 32 swap devices with up to 2^53 pages each.

use core::fmt;

/// Maximum number of swap devices supported
pub const MAX_SWAPFILES: usize = 32;

/// Swap entry - encodes swap device type and slot offset
///
/// This is a logical reference to a swap slot, analogous to Linux's `swp_entry_t`.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct SwapEntry(u64);

impl SwapEntry {
    /// Number of bits for swap type (5 bits = 32 devices)
    const TYPE_BITS: u32 = 5;

    /// Mask for swap type field
    const TYPE_MASK: u64 = (1 << Self::TYPE_BITS) - 1; // 0x1F

    /// Shift for offset field (after type bits)
    const OFFSET_SHIFT: u32 = Self::TYPE_BITS;

    /// Marker bits to identify a swap PTE (bits 59-63 = 0, bit 0 = 0)
    /// We use bits 59-62 as a "swap marker" to distinguish from other non-present PTEs
    /// Value 0b0001 in bits 59-62 indicates swap entry
    const SWAP_MARKER: u64 = 0x1 << 59;
    const SWAP_MARKER_MASK: u64 = 0xF << 59;

    /// Create a new swap entry
    ///
    /// # Arguments
    /// - `swap_type`: Swap device index (0-31)
    /// - `offset`: Slot offset within the swap device
    ///
    /// # Panics
    /// Panics if swap_type >= MAX_SWAPFILES
    #[inline]
    pub fn new(swap_type: u8, offset: u64) -> Self {
        debug_assert!((swap_type as usize) < MAX_SWAPFILES);
        let entry = (offset << Self::OFFSET_SHIFT) | (swap_type as u64 & Self::TYPE_MASK);
        Self(entry)
    }

    /// Create a null/invalid swap entry
    #[inline]
    pub const fn null() -> Self {
        Self(0)
    }

    /// Check if this is a valid (non-null) swap entry
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.0 != 0
    }

    /// Get the swap type (device index)
    #[inline]
    pub fn swap_type(&self) -> u8 {
        (self.0 & Self::TYPE_MASK) as u8
    }

    /// Get the slot offset within the swap device
    #[inline]
    pub fn offset(&self) -> u64 {
        self.0 >> Self::OFFSET_SHIFT
    }

    /// Get the raw value
    #[inline]
    pub fn raw(&self) -> u64 {
        self.0
    }

    /// Create from raw value
    #[inline]
    pub fn from_raw(val: u64) -> Self {
        Self(val)
    }

    // ========================================================================
    // PTE encoding/decoding
    // ========================================================================

    /// Convert swap entry to a PTE value
    ///
    /// The PTE format:
    /// - Bit 0 = 0 (not present)
    /// - Bits 1-58: swap entry data (shifted by 1)
    /// - Bits 59-62: swap marker (0b0001)
    /// - Bit 63: 0
    ///
    /// This ensures:
    /// 1. Page is not present (bit 0 = 0)
    /// 2. We can distinguish swap PTEs from other non-present PTEs
    #[inline]
    pub fn to_pte(&self) -> u64 {
        // Shift entry left by 1 to leave room for present bit (0)
        // Add swap marker in high bits
        (self.0 << 1) | Self::SWAP_MARKER
    }

    /// Create a swap entry from a PTE value
    ///
    /// # Safety
    /// Caller must ensure the PTE is actually a swap entry (use `is_swap_pte()` first)
    #[inline]
    pub fn from_pte(pte: u64) -> Self {
        // Remove swap marker and shift right to get original entry
        Self((pte & !Self::SWAP_MARKER_MASK) >> 1)
    }

    /// Check if a PTE value contains a swap entry
    ///
    /// A swap PTE has:
    /// - Bit 0 = 0 (not present)
    /// - Bits 59-62 = swap marker (0b0001)
    /// - Non-zero swap data
    #[inline]
    pub fn is_swap_pte(pte: u64) -> bool {
        // Must not be present
        if pte & 1 != 0 {
            return false;
        }
        // Must have swap marker
        if pte & Self::SWAP_MARKER_MASK != Self::SWAP_MARKER {
            return false;
        }
        // Must have non-zero swap data
        let entry_data = (pte & !Self::SWAP_MARKER_MASK) >> 1;
        entry_data != 0
    }
}

impl fmt::Debug for SwapEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_valid() {
            write!(
                f,
                "SwapEntry(type={}, offset={})",
                self.swap_type(),
                self.offset()
            )
        } else {
            write!(f, "SwapEntry(null)")
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
    fn test_swap_entry_roundtrip() {
        let entry = SwapEntry::new(3, 12345);
        assert_eq!(entry.swap_type(), 3);
        assert_eq!(entry.offset(), 12345);
    }

    #[test]
    fn test_pte_roundtrip() {
        let entry = SwapEntry::new(7, 0xABCDEF);
        let pte = entry.to_pte();

        // PTE should not be present
        assert_eq!(pte & 1, 0);

        // Should be detected as swap PTE
        assert!(SwapEntry::is_swap_pte(pte));

        // Should roundtrip
        let recovered = SwapEntry::from_pte(pte);
        assert_eq!(recovered.swap_type(), 7);
        assert_eq!(recovered.offset(), 0xABCDEF);
    }

    #[test]
    fn test_null_entry() {
        let null = SwapEntry::null();
        assert!(!null.is_valid());

        // Null entry's PTE should not be detected as swap
        // (it has the marker but zero data)
        let pte = SwapEntry::SWAP_MARKER; // Just marker, no data
        assert!(!SwapEntry::is_swap_pte(pte));
    }

    #[test]
    fn test_non_swap_pte() {
        // Present page
        assert!(!SwapEntry::is_swap_pte(0x1000 | 1));

        // Non-present but no swap marker
        assert!(!SwapEntry::is_swap_pte(0x1000));

        // Zero PTE
        assert!(!SwapEntry::is_swap_pte(0));
    }
}
