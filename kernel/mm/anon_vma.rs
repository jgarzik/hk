//! Anonymous VMA chains for the reverse map (Linux mm/rmap.c anon_vma)
//!
//! Every private anonymous VMA has an [`AnonVma`]; fork's copies of it
//! and the pieces of a split share it. Its chain lists each VMA that
//! may map its pages ([`Avc`], Linux anon_vma_chain): the address space,
//! the VMA's range and its page offset `pgoff` (Linux vm_pgoff). An
//! anonymous page records its AnonVma (`Page.mapping`, holding a
//! reference until the page is freed) and its linear index
//! (`Page.index` = pgoff + (address - start) / 4KB at fault time,
//! Linux linear_page_index); a VMA that maps it has it at
//! `start + (index - pgoff) * 4KB`, so the reverse map finds each
//! mapping without searching (Linux vma_address). mremap moves a VMA
//! with its pgoff, so its pages keep their index.
//!
//! Locking (Linux anon_vma->rwsem): the chain is a sleeping `RwSem`.
//! Every change of a VMA that has one (insert, split, merge, grow,
//! shrink, removal, an mlock change) updates its entry under the
//! write lock, from `MmStruct` with the mmap_lock held for writing
//! (mmap_lock -> anon_vma lock). The reverse map reads it, holding it
//! across its page-table accesses: unmapping a VMA, and exit, unlink
//! it (write lock) before freeing its page tables, so a walk never
//! reaches a freed table. Order: mmap_lock -> anon_vma lock -> PTE lock.
//!
//! Deviation from Linux: one AnonVma per family of VMAs (fork shares
//! the parent's instead of chaining a child one under it), and the chain
//! is a vector, not an interval tree.

extern crate alloc;

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use super::Mm;

/// The chain's lock: a sleeping RwSem; host tests, which cannot
/// schedule, use a spinning one with the same interface
#[cfg(not(test))]
type ChainLock = crate::sync::RwSem<Vec<Avc>>;
#[cfg(test)]
type ChainLock = crate::sync::spin::RwLock<Vec<Avc>>;

/// One VMA that may map pages of an AnonVma (Linux anon_vma_chain)
#[derive(Clone, Debug)]
pub struct Avc {
    /// The address space (an mm_count reference only when upgraded: a
    /// chain never keeps an address space alive)
    pub mm: Weak<Mm>,
    /// Its top-level table: names the address space in the chain
    pub pgd: u64,
    /// The VMA's range
    pub start: u64,
    pub end: u64,
    /// Page index of `start` (Linux vm_pgoff)
    pub pgoff: u64,
    /// The VMA is memory-locked (VM_LOCKED): its pages are not reclaimed
    pub locked: bool,
}

impl Avc {
    /// The address of page `index` in this VMA, if it lies there
    pub fn address(&self, index: u64) -> Option<u64> {
        let off = index.checked_sub(self.pgoff)?;
        let addr = self.start.checked_add(off.checked_mul(4096)?)?;
        (addr < self.end).then_some(addr)
    }
}

/// The reverse map of a family of anonymous VMAs (Linux struct anon_vma)
pub struct AnonVma {
    chain: ChainLock,
}

impl AnonVma {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Add a VMA's entry (Linux anon_vma_chain_link)
    pub fn link(&self, avc: Avc) {
        self.chain.write().push(avc);
    }

    /// Drop the entry of the VMA at `start` of the address space `pgd`
    /// (Linux unlink_anon_vmas)
    pub fn unlink(&self, pgd: u64, start: u64) {
        self.chain
            .write()
            .retain(|c| !(c.pgd == pgd && c.start == start));
    }

    /// Change the entry of the VMA at `start` of `pgd` (a VMA split,
    /// merged, grown or relocked)
    pub fn update(&self, pgd: u64, start: u64, f: impl FnOnce(&mut Avc)) {
        let mut chain = self.chain.write();
        if let Some(c) = chain.iter_mut().find(|c| c.pgd == pgd && c.start == start) {
            f(c);
        }
    }

    /// The chain, for a reverse-map walk (Linux anon_vma_lock_read)
    pub fn read(&self) -> impl core::ops::Deref<Target = Vec<Avc>> + '_ {
        self.chain.read()
    }

    /// Entries in the chain
    pub fn len(&self) -> usize {
        self.chain.read().len()
    }

    /// No VMA left
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for AnonVma {
    #[track_caller]
    fn default() -> Self {
        Self {
            chain: ChainLock::new(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn avc(pgd: u64, start: u64, end: u64, pgoff: u64) -> Avc {
        Avc {
            mm: Weak::new(),
            pgd,
            start,
            end,
            pgoff,
            locked: false,
        }
    }

    #[test]
    fn address_of_an_index() {
        // A VMA moved by mremap from 0x10000 to 0x50000 keeps pgoff 0x10
        let c = avc(1, 0x50000, 0x52000, 0x10);
        assert_eq!(c.address(0x10), Some(0x50000));
        assert_eq!(c.address(0x11), Some(0x51000));
        assert_eq!(c.address(0x12), None);
        assert_eq!(c.address(0xf), None);
        assert_eq!(c.address(u64::MAX), None);
    }

    #[test]
    fn link_update_unlink() {
        let av = AnonVma::new();
        av.link(avc(1, 0x10000, 0x20000, 0x10));
        av.link(avc(2, 0x10000, 0x20000, 0x10));
        // Split at 0x18000
        av.update(1, 0x10000, |c| c.end = 0x18000);
        av.link(avc(1, 0x18000, 0x20000, 0x18));
        assert_eq!(av.len(), 3);
        assert!(av.read().iter().any(|c| c.pgd == 1 && c.end == 0x18000));
        av.unlink(1, 0x10000);
        av.unlink(1, 0x18000);
        assert_eq!(av.len(), 1);
        assert_eq!(av.read()[0].pgd, 2);
        av.unlink(2, 0x10000);
        assert!(av.is_empty());
    }
}
