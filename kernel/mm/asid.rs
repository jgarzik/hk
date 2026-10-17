//! Address-space identifiers (ASIDs) allocated by generation (Linux
//! arch/arm64/mm/context.c)
//!
//! An address space's `id` (an `AtomicU64` in its arch TLB context) holds
//! `generation | asid`, 0 before it first runs. The ASID of a CPU's
//! running address space is in `active[cpu]`. When the ASID space runs
//! out, the generation is bumped (rollover): the bitmap restarts with
//! only the ASIDs still in use on some CPU (`active`, or `reserved` for a
//! CPU that has not switched since an earlier rollover), every CPU must
//! flush its TLB before its next switch (`flush_pending`), and an
//! address space from an older generation gets a new ASID at its next
//! switch, keeping its old number if it is free or reserved.
//!
//! Fast path (no lock): the address space's generation is current and
//! this CPU's `active` entry is swapped from non-zero to its ASID; a
//! rollover in progress zeroes `active` entries first (`flush_context`),
//! so the swap fails and the slow path takes the lock. The lock
//! (`ASID lock`, an IrqSpinlock: the switch runs with interrupts off) is
//! one global, like Linux cpu_asid_lock: ASIDs are a machine-wide
//! namespace and the slow path runs once per generation per address
//! space.
//!
//! Generic so that the host unit tests can run it with a small ASID
//! space; arm64 is its only user.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::IrqSpinlock;
use crate::cpumask::NR_CPUS;

/// Largest supported ASID space (16-bit ASIDs)
const MAX_ASIDS: usize = 1 << 16;

struct Inner {
    /// ASIDs handed out in the current generation (bit 0 never: the
    /// kernel's ASID)
    map: [u64; MAX_ASIDS / 64],
    /// Where the next search starts
    cur_idx: usize,
    /// Per CPU: the ASID kept for a CPU that did not switch since the
    /// last rollover (its `active` entry was 0)
    reserved: [u64; NR_CPUS],
}

/// An ASID allocator (one per machine)
pub struct AsidAlloc {
    /// log2 of the number of ASIDs
    bits: AtomicU64,
    /// Current generation (multiples of the ASID count)
    generation: AtomicU64,
    /// Per CPU: `generation | asid` running there, 0 during a rollover
    active: [AtomicU64; NR_CPUS],
    /// Per CPU: flush the TLB before the next switch (rollover)
    flush_pending: [AtomicBool; NR_CPUS],
    inner: IrqSpinlock<Inner>,
}

impl AsidAlloc {
    /// An allocator of 2^`bits` ASIDs
    pub const fn new(bits: u32) -> Self {
        Self {
            bits: AtomicU64::new(bits as u64),
            generation: AtomicU64::new(1 << bits),
            active: [const { AtomicU64::new(0) }; NR_CPUS],
            flush_pending: [const { AtomicBool::new(false) }; NR_CPUS],
            inner: IrqSpinlock::new(Inner {
                map: [0; MAX_ASIDS / 64],
                cur_idx: 1,
                reserved: [0; NR_CPUS],
            }),
        }
    }

    /// Set the ASID width (boot, before any address space runs). A
    /// rollover keeps one ASID per CPU, so there must be more ASIDs
    /// than CPUs (plus ASID 0)
    pub fn set_bits(&self, bits: u32) {
        assert!(1usize << bits > NR_CPUS + 1, "too few ASIDs for the CPUs");
        self.bits.store(bits as u64, Ordering::Relaxed);
        self.generation.store(1 << bits, Ordering::Relaxed);
    }

    fn bits(&self) -> u32 {
        self.bits.load(Ordering::Relaxed) as u32
    }

    fn count(&self) -> usize {
        1 << self.bits()
    }

    /// The ASID number of `id`
    pub fn asid(&self, id: u64) -> u64 {
        id & (self.count() as u64 - 1)
    }

    /// `id` belongs to the current generation
    fn gen_match(&self, id: u64) -> bool {
        (id ^ self.generation.load(Ordering::Relaxed)) >> self.bits() == 0
    }

    /// The ASID for the address space with context `id` about to run on
    /// `cpu` (Linux check_and_switch_context), interrupts off; true if
    /// this CPU must flush its whole TLB first (a rollover happened).
    pub fn switch(&self, cpu: u32, id: &AtomicU64) -> (u64, bool) {
        let c = cpu as usize;
        let cur = id.load(Ordering::Relaxed);
        let old_active = self.active[c].load(Ordering::Relaxed);
        if old_active != 0
            && self.gen_match(cur)
            && self.active[c]
                .compare_exchange(old_active, cur, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            return (self.asid(cur), false);
        }
        let mut inner = self.inner.lock();
        let mut cur = id.load(Ordering::Relaxed);
        if !self.gen_match(cur) {
            cur = self.new_context(&mut inner, cur);
            id.store(cur, Ordering::Relaxed);
        }
        let flush = self.flush_pending[c].swap(false, Ordering::Relaxed);
        self.active[c].store(cur, Ordering::Relaxed);
        (self.asid(cur), flush)
    }

    /// A current-generation id for an address space whose id is `old`
    /// (Linux new_context): its old ASID again if a CPU still holds it
    /// reserved or it is free, else the next free one, rolling over if
    /// none is left
    fn new_context(&self, inner: &mut Inner, old: u64) -> u64 {
        let mut generation = self.generation.load(Ordering::Relaxed);
        if old != 0 {
            let new = generation | self.asid(old);
            if self.update_reserved(inner, old, new) {
                return new;
            }
            if !test_and_set(&mut inner.map, self.asid(old) as usize) {
                return new;
            }
        }
        let asid = match find_zero(&inner.map, inner.cur_idx, self.count()) {
            Some(a) => a,
            None => {
                generation = self
                    .generation
                    .fetch_add(self.count() as u64, Ordering::Relaxed)
                    + self.count() as u64;
                self.flush_context(inner);
                find_zero(&inner.map, 1, self.count()).expect("no ASID after rollover")
            }
        };
        test_and_set(&mut inner.map, asid);
        inner.cur_idx = asid;
        generation | asid as u64
    }

    /// Rollover (Linux flush_context): restart the bitmap with the ASIDs
    /// each CPU runs (or kept reserved), and have every CPU flush
    fn flush_context(&self, inner: &mut Inner) {
        inner.map.fill(0);
        for c in 0..NR_CPUS {
            let mut asid = self.active[c].swap(0, Ordering::Relaxed);
            // A CPU that did not switch since the last rollover runs
            // the address space it reserved then
            if asid == 0 {
                asid = inner.reserved[c];
            }
            test_and_set(&mut inner.map, self.asid(asid) as usize);
            inner.reserved[c] = asid;
        }
        // Bit 0 (the kernel's ASID) may be marked by an idle CPU: harmless
        for f in &self.flush_pending {
            f.store(true, Ordering::Relaxed);
        }
    }

    /// A CPU holding `old` reserved now holds `new` (same ASID, current
    /// generation); true if any did (Linux check_update_reserved_asid)
    fn update_reserved(&self, inner: &mut Inner, old: u64, new: u64) -> bool {
        let mut hit = false;
        for r in inner.reserved.iter_mut() {
            if *r == old {
                *r = new;
                hit = true;
            }
        }
        hit
    }
}

/// Set bit `n`; whether it was set
fn test_and_set(map: &mut [u64], n: usize) -> bool {
    let (w, b) = (n / 64, 1u64 << (n % 64));
    let was = map[w] & b != 0;
    map[w] |= b;
    was
}

/// The first clear bit at or after `from`, below `count`
fn find_zero(map: &[u64], from: usize, count: usize) -> Option<usize> {
    (from..count).find(|&n| map[n / 64] & (1 << (n % 64)) == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::boxed::Box;

    /// A fresh allocator of 2^`bits` ASIDs (boxed: it is large)
    fn alloc(bits: u32) -> Box<AsidAlloc> {
        Box::new(AsidAlloc::new(bits))
    }

    #[test]
    fn distinct_asids_in_one_generation() {
        let a = alloc(4);
        let ids: std::vec::Vec<AtomicU64> = (0..15).map(|_| AtomicU64::new(0)).collect();
        let mut seen = std::collections::BTreeSet::new();
        for id in &ids {
            let (asid, flush) = a.switch(0, id);
            assert!(!flush);
            assert_ne!(asid, 0, "ASID 0 is the kernel's");
            assert!(seen.insert(asid), "ASID {asid} handed out twice");
        }
    }

    #[test]
    fn asid_zero_never_handed_out() {
        let a = alloc(3); // ASIDs 1..7 for 4 CPUs: a rollover every few switches
        let ids: std::vec::Vec<AtomicU64> = (0..11).map(|_| AtomicU64::new(0)).collect();
        for round in 0..50 {
            for (i, id) in ids.iter().enumerate() {
                let (asid, _) = a.switch(((i + round) % 4) as u32 % NR_CPUS as u32, id);
                assert_ne!(asid, 0, "ASID 0 is the kernel threads'");
            }
        }
    }

    #[test]
    fn fast_path_keeps_asid() {
        let a = alloc(4);
        let id = AtomicU64::new(0);
        let (first, _) = a.switch(1, &id);
        let (again, flush) = a.switch(1, &id);
        assert_eq!(first, again);
        assert!(!flush);
    }

    #[test]
    fn rollover_flushes_every_cpu_once() {
        let a = alloc(3); // ASIDs 1..7
        let ids: std::vec::Vec<AtomicU64> = (0..8).map(|_| AtomicU64::new(0)).collect();
        for id in &ids[..7] {
            a.switch(0, id);
        }
        // The eighth address space rolls the generation over
        let (_, flush) = a.switch(0, &ids[7]);
        assert!(
            flush,
            "the rolling CPU flushes before using the new generation"
        );
        let (_, flush) = a.switch(2, &ids[0]);
        assert!(flush, "another CPU flushes at its next switch");
        let (_, flush) = a.switch(2, &ids[1]);
        assert!(!flush, "once");
    }

    #[test]
    fn rollover_keeps_running_asids() {
        let a = alloc(3);
        let ids: std::vec::Vec<AtomicU64> = (0..9).map(|_| AtomicU64::new(0)).collect();
        // CPU 1 runs ids[0]; CPU 0 then exhausts the space
        let (on_cpu1, _) = a.switch(1, &ids[0]);
        for id in &ids[1..8] {
            a.switch(0, id);
        }
        // ids[0] is still running on CPU 1 (reserved across the
        // rollover): it keeps its ASID, and nobody else gets it
        let (kept, _) = a.switch(1, &ids[0]);
        assert_eq!(kept, on_cpu1);
        let mut others = std::vec::Vec::new();
        for id in &ids[1..9] {
            let (x, _) = a.switch(3, id);
            others.push(x);
        }
        assert!(
            others.iter().all(|&x| x != kept),
            "ASID {kept} running on CPU 1 handed to another address space"
        );
    }

    #[test]
    fn reserved_asid_survives_two_rollovers() {
        let a = alloc(2); // ASIDs 1..3
        let ids: std::vec::Vec<AtomicU64> = (0..6).map(|_| AtomicU64::new(0)).collect();
        let (mine, _) = a.switch(1, &ids[0]); // CPU 1 never switches again
        for id in &ids[1..] {
            a.switch(0, id);
        }
        for id in &ids[1..] {
            a.switch(0, id);
        }
        // CPU 1 still runs ids[0]: it must still own its ASID
        let (now, _) = a.switch(1, &ids[0]);
        assert_eq!(now, mine);
        for id in &ids[1..] {
            let (x, _) = a.switch(0, id);
            if x == mine {
                panic!("ASID {mine} reserved by CPU 1 handed to another address space");
            }
            a.switch(0, &ids[1]);
        }
    }
}
