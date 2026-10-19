//! Boot memory map (Linux mm/memblock.c)
//!
//! Before the page allocator exists, the kernel knows physical memory as
//! two sets of ranges: `memory`, every RAM range the firmware reports
//! (multiboot2 memory map, DTB /memory nodes), and `reserved`, what is
//! in use already (kernel image, boot modules, DTB, initrd, early
//! allocations such as the memory map itself). The page allocator is
//! built from them: every free range (memory minus reserved) is handed
//! to it once at boot (Linux memblock_free_all), and memblock is not used
//! afterwards.
//!
//! Locking: `MEMBLOCK` is a `spin::Mutex` leaf, taken only on the boot
//! CPU before SMP (thread context, never in IRQ context).

use crate::sync::spin::Mutex;

/// Ranges per set (Linux INIT_MEMBLOCK_REGIONS)
pub const MAX_REGIONS: usize = 128;

const PAGE: u64 = 4096;

/// A physical range [base, end)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Range {
    pub base: u64,
    pub end: u64,
}

impl Range {
    pub fn size(&self) -> u64 {
        self.end - self.base
    }
}

/// Sorted, non-overlapping, non-adjacent ranges
pub struct RangeSet {
    r: [Range; MAX_REGIONS],
    n: usize,
}

impl RangeSet {
    pub const fn new() -> Self {
        Self {
            r: [Range { base: 0, end: 0 }; MAX_REGIONS],
            n: 0,
        }
    }

    pub fn ranges(&self) -> &[Range] {
        &self.r[..self.n]
    }

    /// Add [base, end), merging with overlapping or adjacent ranges.
    /// False if the set is full (the range is dropped).
    pub fn add(&mut self, mut base: u64, mut end: u64) -> bool {
        if base >= end {
            return true;
        }
        // First range ending at or after `base`
        let lo = self.r[..self.n].partition_point(|x| x.end < base);
        // First range starting after `end`
        let hi = self.r[..self.n].partition_point(|x| x.base <= end);
        if lo < hi {
            base = base.min(self.r[lo].base);
            end = end.max(self.r[hi - 1].end);
        } else if self.n == MAX_REGIONS {
            return false;
        }
        // Replace r[lo..hi] with the merged range
        let tail = self.n - hi;
        self.r.copy_within(hi..self.n, lo + 1);
        self.r[lo] = Range { base, end };
        self.n = lo + 1 + tail;
        true
    }

    /// Remove [base, end) (splitting a range that straddles it). False
    /// if a split found the set full (the set is then unchanged).
    pub fn remove(&mut self, base: u64, end: u64) -> bool {
        if base >= end {
            return true;
        }
        let mut out = RangeSet::new();
        for x in self.ranges() {
            for (b, e) in [(x.base, x.end.min(base)), (x.base.max(end), x.end)] {
                if b < e && !out.add(b, e) {
                    return false;
                }
            }
        }
        *self = out;
        true
    }

    /// Bytes covered
    pub fn total(&self) -> u64 {
        self.ranges().iter().map(Range::size).sum()
    }
}

impl Default for RangeSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Highest physical address memblock tracks (52 bits: x86-64 and arm64
/// LPA maximum); firmware values past it are clipped
pub const PHYS_LIMIT: u64 = 1 << 52;

/// [base, base + size) shrunk to whole pages, clipped to PHYS_LIMIT
/// (empty when nothing is left)
fn inner(base: u64, size: u64) -> (u64, u64) {
    let end = base.saturating_add(size).min(PHYS_LIMIT) & !(PAGE - 1);
    let base = base.min(PHYS_LIMIT).next_multiple_of(PAGE);
    (base, end.max(base))
}

/// [base, base + size) widened to whole pages, clipped to PHYS_LIMIT
fn outer(base: u64, size: u64) -> (u64, u64) {
    let end = base
        .saturating_add(size)
        .min(PHYS_LIMIT)
        .next_multiple_of(PAGE);
    (base.min(PHYS_LIMIT) & !(PAGE - 1), end)
}

/// RAM and reserved ranges, plus the highest address early allocations
/// may use (Linux memblock.current_limit)
pub struct Memblock {
    pub memory: RangeSet,
    pub reserved: RangeSet,
    limit: u64,
}

impl Memblock {
    pub const fn new() -> Self {
        Self {
            memory: RangeSet::new(),
            reserved: RangeSet::new(),
            limit: u64::MAX,
        }
    }

    /// RAM at [base, base + size), trimmed to whole pages; firmware
    /// ranges past the physical address limit or wrapping are clipped
    pub fn add(&mut self, base: u64, size: u64) {
        let (b, e) = inner(base, size);
        assert!(self.memory.add(b, e), "memblock: too many memory ranges");
    }

    /// Forget RAM at [base, base + size) (e.g. past the direct map)
    pub fn remove(&mut self, base: u64, size: u64) {
        let (b, e) = outer(base, size);
        assert!(self.memory.remove(b, e), "memblock: too many memory ranges");
    }

    /// Mark [base, base + size) in use, widened to whole pages
    pub fn reserve(&mut self, base: u64, size: u64) {
        let (b, e) = outer(base, size);
        assert!(
            self.reserved.add(b, e),
            "memblock: too many reserved ranges"
        );
    }

    /// Early allocations stay below `limit` (what the direct map covers)
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    /// Call `f(base, end)` for every free range (memory minus reserved),
    /// in address order (Linux for_each_free_mem_range)
    pub fn for_each_free(&self, mut f: impl FnMut(u64, u64)) {
        let res = self.reserved.ranges();
        for m in self.memory.ranges() {
            let mut cur = m.base;
            let first = res.partition_point(|r| r.end <= m.base);
            for r in &res[first..] {
                if r.base >= m.end {
                    break;
                }
                if r.base > cur {
                    f(cur, r.base);
                }
                cur = cur.max(r.end);
            }
            if cur < m.end {
                f(cur, m.end);
            }
        }
    }

    /// Allocate `size` bytes aligned to `align` (a power of two), top
    /// down below the limit, and reserve them (Linux memblock_phys_alloc)
    pub fn alloc(&mut self, size: u64, align: u64) -> Option<u64> {
        let mut free = [Range::default(); 2 * MAX_REGIONS];
        let mut n = 0;
        self.for_each_free(|base, end| {
            if n < free.len() {
                free[n] = Range { base, end };
                n += 1;
            }
        });
        let found = free[..n].iter().rev().find_map(|r| {
            let top = r.end.min(self.limit).checked_sub(size)? & !(align - 1);
            (top >= r.base).then_some(top)
        })?;
        self.reserve(found, size);
        Some(found)
    }

    /// Lowest and highest RAM addresses
    pub fn span(&self) -> (u64, u64) {
        let m = self.memory.ranges();
        match (m.first(), m.last()) {
            (Some(a), Some(b)) => (a.base, b.end),
            _ => (0, 0),
        }
    }
}

impl Default for Memblock {
    fn default() -> Self {
        Self::new()
    }
}

/// The boot memory map
pub static MEMBLOCK: Mutex<Memblock> = Mutex::new(Memblock::new());

/// Report RAM at [base, base + size)
pub fn add(base: u64, size: u64) {
    MEMBLOCK.lock().add(base, size);
}

/// Mark [base, base + size) in use
pub fn reserve(base: u64, size: u64) {
    MEMBLOCK.lock().reserve(base, size);
}

/// Allocate and reserve `size` bytes (zeroed by the caller if needed);
/// panics when boot memory is exhausted, like Linux memblock_alloc
/// callers that cannot run without it
pub fn alloc(size: u64, align: u64) -> u64 {
    MEMBLOCK
        .lock()
        .alloc(size, align)
        .unwrap_or_else(|| panic!("memblock: no {size:#x} bytes for boot allocation"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(rs: &[(u64, u64)]) -> RangeSet {
        let mut s = RangeSet::new();
        for &(b, e) in rs {
            assert!(s.add(b, e));
        }
        s
    }

    fn pairs(s: &RangeSet) -> Vec<(u64, u64)> {
        s.ranges().iter().map(|r| (r.base, r.end)).collect()
    }

    #[test]
    fn add_merges_overlap_and_adjacent() {
        let s = set(&[(10, 20), (30, 40), (20, 25), (35, 50), (0, 5)]);
        assert_eq!(pairs(&s), [(0, 5), (10, 25), (30, 50)]);
        let s = set(&[(10, 20), (30, 40), (5, 45)]);
        assert_eq!(pairs(&s), [(5, 45)]);
    }

    #[test]
    fn remove_splits() {
        let mut s = set(&[(0, 100)]);
        assert!(s.remove(40, 60));
        assert_eq!(pairs(&s), [(0, 40), (60, 100)]);
        assert!(s.remove(90, 200));
        assert_eq!(pairs(&s), [(0, 40), (60, 90)]);
        assert_eq!(s.total(), 70);
    }

    #[test]
    fn full_set_refuses() {
        let mut s = RangeSet::new();
        for i in 0..MAX_REGIONS as u64 {
            assert!(s.add(i * 10, i * 10 + 5));
        }
        assert!(!s.add(10_000, 10_005));
        // Merging needs no new slot
        assert!(s.add(5, 10));
        assert!(s.add(10_000, 10_005));
    }

    #[test]
    fn free_ranges_skip_reserved() {
        let mut m = Memblock::new();
        m.add(0x1000, 0x9000);
        m.add(0x20000, 0x10000);
        m.reserve(0x0, 0x2000);
        m.reserve(0x4000, 0x1000);
        m.reserve(0x9000, 0x18000);
        let mut got = Vec::new();
        m.for_each_free(|b, e| got.push((b, e)));
        assert_eq!(
            got,
            [(0x2000, 0x4000), (0x5000, 0x9000), (0x21000, 0x30000)]
        );
    }

    #[test]
    fn alloc_top_down_below_limit() {
        let mut m = Memblock::new();
        m.add(0x100000, 0x400000);
        m.set_limit(0x300000);
        let a = m.alloc(0x2000, 0x1000).unwrap();
        assert_eq!(a, 0x2fe000);
        let b = m.alloc(0x1000, 0x10000).unwrap();
        assert_eq!(b, 0x2f0000);
        assert!(m.alloc(0x300000, 0x1000).is_none());
        let mut free = 0;
        m.for_each_free(|b, e| free += e - b);
        assert_eq!(free, 0x400000 - 0x3000);
    }

    #[test]
    fn hostile_ranges_are_clipped() {
        let mut m = Memblock::new();
        m.add(u64::MAX - 10, 100);
        m.add(PHYS_LIMIT - 0x1000, u64::MAX);
        m.add(0x5000, 0x10);
        assert_eq!(pairs(&m.memory), [(PHYS_LIMIT - 0x1000, PHYS_LIMIT)]);
        m.reserve(u64::MAX, u64::MAX);
        m.remove(u64::MAX - 1, 5);
        assert_eq!(m.memory.total(), 0x1000);
    }

    #[test]
    fn add_trims_to_pages() {
        let mut m = Memblock::new();
        m.add(0xc01, 0x9f000);
        assert_eq!(pairs(&m.memory), [(0x1000, 0x9f000)]);
        m.reserve(0x1800, 0x10);
        assert_eq!(pairs(&m.reserved), [(0x1000, 0x2000)]);
    }
}
