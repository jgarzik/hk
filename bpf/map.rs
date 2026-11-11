//! BPF map implementations
//!
//! This module provides the BPF map types used by the bpf() syscall.
//! Maps are key-value stores that can be accessed from both userspace
//! (via syscall) and BPF programs.
//!
//! ## Supported Map Types
//!
//! - `BPF_MAP_TYPE_HASH`: Hash table with arbitrary keys
//! - `BPF_MAP_TYPE_ARRAY`: Fixed-size array indexed by u32

use crate::util::kalloc::try_arc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::sync::IrqSpinlock;
use crate::util::error::KernelError;

// =============================================================================
// Map Type Constants (Linux ABI)
// =============================================================================

/// Hash table map
pub const BPF_MAP_TYPE_HASH: u32 = 1;
/// Array map (indexed by u32)
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;

// =============================================================================
// Map Update Flags (Linux ABI)
// =============================================================================

/// Create new element or update existing
#[cfg(test)]
pub const BPF_ANY: u64 = 0;
/// Create new element only if it doesn't exist
pub const BPF_NOEXIST: u64 = 1;
/// Update existing element only
pub const BPF_EXIST: u64 = 2;
/// Update under the value's bpf_spin_lock
pub const BPF_F_LOCK: u64 = 4;
/// Percpu maps: the CPU in the upper 32 bits / every CPU
pub const BPF_F_CPU: u64 = 8;
pub const BPF_F_ALL_CPUS: u64 = 16;

/// Flags no map op knows (Linux htab/array_map_update_elem: anything
/// but BPF_F_LOCK above BPF_EXIST) are EINVAL
fn update_flags_ok(flags: u64) -> Result<(), KernelError> {
    if flags & !BPF_F_LOCK > BPF_EXIST {
        return Err(KernelError::InvalidArgument);
    }
    Ok(())
}

// =============================================================================
// Map Limits
// =============================================================================

/// Maximum key size in bytes
pub const BPF_MAX_KEY_SIZE: u32 = 256;
/// Maximum value size in bytes
pub const BPF_MAX_VALUE_SIZE: u32 = 65536;
/// Maximum number of entries
pub const BPF_MAX_ENTRIES: u32 = 1 << 20; // 1M entries

// =============================================================================
// Map Operations Trait
// =============================================================================

/// Trait for BPF map operations
///
/// Each map type implements this trait to provide its specific behavior.
pub trait BpfMapOps: Send + Sync {
    /// Look up an element by key, copying its value into `out` (the
    /// value size, allocated by the caller before the map is locked:
    /// Linux bpf_map_copy_value); false if absent
    fn lookup(&self, key: &[u8], out: &mut [u8]) -> bool;

    /// Update or insert an element
    ///
    /// Flags:
    /// - `BPF_ANY`: Create or update
    /// - `BPF_NOEXIST`: Create only if key doesn't exist
    /// - `BPF_EXIST`: Update only if key exists
    fn update(&self, key: &[u8], value: &[u8], flags: u64) -> Result<(), KernelError>;

    /// Delete an element by key
    fn delete(&self, key: &[u8]) -> Result<(), KernelError>;

    /// Copy the key after `key` (the first for None) into `out` (the key
    /// size, allocated by the caller); false when iteration is complete
    fn get_next_key(&self, key: Option<&[u8]>, out: &mut [u8]) -> bool;

    /// Get the map type
    fn map_type(&self) -> u32;

    /// Get the key size in bytes
    fn key_size(&self) -> u32;

    /// Get the value size in bytes
    fn value_size(&self) -> u32;

    /// Get the maximum number of entries
    fn max_entries(&self) -> u32;

    /// Get the current number of entries
    fn len(&self) -> usize;

    /// Check if map is empty
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// =============================================================================
// BPF Hash Map
// =============================================================================

/// Hash map implementation using BTreeMap
///
/// Keys and values are stored as byte vectors. BTreeMap is used instead
/// of HashMap because HashMap isn't available in alloc.
pub struct BpfHashMap {
    /// The table, every element preallocated at create (Linux htab
    /// prealloc_init): an update takes one from the free list and copies
    /// in, so nothing allocates under the lock
    data: IrqSpinlock<Htab>,
    /// Key size in bytes
    key_size: u32,
    /// Value size in bytes
    value_size: u32,
    /// Maximum number of entries
    max_entries: u32,
}

/// No element (an index's end of chain)
const NIL: u32 = u32::MAX;

/// A preallocated hash table (Linux struct bpf_htab with its freelist):
/// elements by index, each `key_size + value_size` bytes of `kv`, chained
/// per bucket through `next` (newest first, as hlist_nulls_add_head)
struct Htab {
    /// Each bucket's first element
    buckets: Vec<u32>,
    /// Each element's successor in its bucket, or on the free list
    next: Vec<u32>,
    /// Each element's key hash
    hash: Vec<u32>,
    /// Keys and values, element by element
    kv: Vec<u8>,
    /// Head of the free elements
    free: u32,
    len: usize,
    /// Random per-map hash seed (Linux htab->hashrnd): user space cannot
    /// pick keys that crowd one bucket
    seed: u32,
}

impl Htab {
    /// A key's hash: FNV-1a from the map's seed, then a full avalanche
    /// (murmur3 fmix32), so the seed reaches every bit of the bucket
    /// index (Linux jhash(key, key_size, hashrnd))
    fn key_hash(&self, key: &[u8]) -> u32 {
        let mut h = key.iter().fold(0x811c_9dc5u32 ^ self.seed, |h, &b| {
            (h ^ u32::from(b)).wrapping_mul(0x0100_0193)
        });
        h ^= self.seed;
        h ^= h >> 16;
        h = h.wrapping_mul(0x85eb_ca6b);
        h ^= h >> 13;
        h = h.wrapping_mul(0xc2b2_ae35);
        h ^ (h >> 16)
    }
}

impl Htab {
    /// Every element on the free list
    fn new(kv_size: usize, max_entries: u32) -> Result<Self, KernelError> {
        use crate::util::kmem::try_vec;
        let n = max_entries as usize;
        let nbuckets = n.next_power_of_two();
        let mut next = try_vec(n, NIL)?;
        for (i, x) in next.iter_mut().enumerate().take(n - 1) {
            *x = i as u32 + 1;
        }
        Ok(Self {
            buckets: try_vec(nbuckets, NIL)?,
            next,
            hash: try_vec(n, 0)?,
            kv: try_vec(n * kv_size, 0)?,
            free: 0,
            len: 0,
            seed: crate::random::get_random_u32(),
        })
    }

    fn bucket(&self, h: u32) -> usize {
        h as usize & (self.buckets.len() - 1)
    }
}

impl BpfHashMap {
    /// Create a new hash map
    pub fn new(key_size: u32, value_size: u32, max_entries: u32) -> Result<Arc<Self>, KernelError> {
        if key_size == 0 || key_size > BPF_MAX_KEY_SIZE {
            return Err(KernelError::InvalidArgument);
        }
        if value_size == 0 || value_size > BPF_MAX_VALUE_SIZE {
            return Err(KernelError::InvalidArgument);
        }
        if max_entries == 0 || max_entries > BPF_MAX_ENTRIES {
            return Err(KernelError::InvalidArgument);
        }
        // Every element is allocated now (Linux htab_map_alloc with
        // prealloc): ENOMEM at create, within the budget the array map
        // preallocates against. Each element: its key and value, its
        // chain, hash and bucket words
        let entry = u64::from(key_size) + u64::from(value_size) + 4 * 4;
        if u64::from(max_entries) * entry > prealloc_budget() {
            return Err(KernelError::OutOfMemory);
        }
        let kv = (key_size + value_size) as usize;
        try_arc(Self {
            data: IrqSpinlock::new(Htab::new(kv, max_entries)?),
            key_size,
            value_size,
            max_entries,
        })
    }

    fn kv_size(&self) -> usize {
        (self.key_size + self.value_size) as usize
    }

    /// Element `e`'s key and value
    fn key_of<'a>(&self, t: &'a Htab, e: u32) -> &'a [u8] {
        let at = e as usize * self.kv_size();
        &t.kv[at..at + self.key_size as usize]
    }

    fn value_of<'a>(&self, t: &'a mut Htab, e: u32) -> &'a mut [u8] {
        let at = e as usize * self.kv_size() + self.key_size as usize;
        &mut t.kv[at..at + self.value_size as usize]
    }

    /// The element holding `key` (Linux lookup_elem_raw)
    fn find(&self, t: &Htab, key: &[u8], h: u32) -> Option<u32> {
        let mut e = t.buckets[t.bucket(h)];
        while e != NIL {
            if t.hash[e as usize] == h && self.key_of(t, e) == key {
                return Some(e);
            }
            e = t.next[e as usize];
        }
        None
    }
}

impl BpfMapOps for BpfHashMap {
    fn lookup(&self, key: &[u8], out: &mut [u8]) -> bool {
        if key.len() != self.key_size as usize || out.len() != self.value_size as usize {
            return false;
        }
        let mut t = self.data.lock();
        let h = t.key_hash(key);
        let Some(e) = self.find(&t, key, h) else {
            return false;
        };
        out.copy_from_slice(self.value_of(&mut t, e));
        true
    }

    fn update(&self, key: &[u8], value: &[u8], flags: u64) -> Result<(), KernelError> {
        update_flags_ok(flags)?;
        if key.len() != self.key_size as usize {
            return Err(KernelError::InvalidArgument);
        }
        if value.len() != self.value_size as usize {
            return Err(KernelError::InvalidArgument);
        }
        let mut t = self.data.lock();
        let h = t.key_hash(key);
        // Linux htab check_flags
        if let Some(e) = self.find(&t, key, h) {
            if flags & !BPF_F_LOCK == BPF_NOEXIST {
                return Err(KernelError::AlreadyExists);
            }
            self.value_of(&mut t, e).copy_from_slice(value);
            return Ok(());
        }
        if flags & !BPF_F_LOCK == BPF_EXIST {
            return Err(KernelError::NotFound);
        }
        // Full (Linux htab: E2BIG): the free list is empty
        let e = t.free;
        if e == NIL {
            return Err(KernelError::ArgListTooLong);
        }
        t.free = t.next[e as usize];
        let at = e as usize * self.kv_size();
        t.kv[at..at + key.len()].copy_from_slice(key);
        self.value_of(&mut t, e).copy_from_slice(value);
        t.hash[e as usize] = h;
        let b = t.bucket(h);
        t.next[e as usize] = t.buckets[b];
        t.buckets[b] = e;
        t.len += 1;
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<(), KernelError> {
        if key.len() != self.key_size as usize {
            return Err(KernelError::InvalidArgument);
        }
        let mut t = self.data.lock();
        let h = t.key_hash(key);
        let b = t.bucket(h);
        // Unlink from the bucket's chain, onto the free list
        let mut prev = NIL;
        let mut e = t.buckets[b];
        while e != NIL {
            if t.hash[e as usize] == h && self.key_of(&t, e) == key {
                let n = t.next[e as usize];
                match prev {
                    NIL => t.buckets[b] = n,
                    p => t.next[p as usize] = n,
                }
                t.next[e as usize] = t.free;
                t.free = e;
                t.len -= 1;
                return Ok(());
            }
            prev = e;
            e = t.next[e as usize];
        }
        Err(KernelError::NotFound)
    }

    /// Linux htab_map_get_next_key: the element after `key` in its
    /// bucket, else the first of the next non-empty bucket; a key not in
    /// the map (or none) starts from the first bucket
    fn get_next_key(&self, key: Option<&[u8]>, out: &mut [u8]) -> bool {
        if out.len() != self.key_size as usize {
            return false;
        }
        let t = self.data.lock();
        let found = key
            .filter(|k| k.len() == self.key_size as usize)
            .and_then(|k| {
                let h = t.key_hash(k);
                Some((self.find(&t, k, h)?, t.bucket(h)))
            });
        let next = match found {
            Some((e, _)) if t.next[e as usize] != NIL => Some(t.next[e as usize]),
            Some((_, b)) => t.buckets[b + 1..].iter().copied().find(|&e| e != NIL),
            None => t.buckets.iter().copied().find(|&e| e != NIL),
        };
        let Some(e) = next else {
            return false;
        };
        out.copy_from_slice(self.key_of(&t, e));
        true
    }

    fn map_type(&self) -> u32 {
        BPF_MAP_TYPE_HASH
    }

    fn key_size(&self) -> u32 {
        self.key_size
    }

    fn value_size(&self) -> u32 {
        self.value_size
    }

    fn max_entries(&self) -> u32 {
        self.max_entries
    }

    fn len(&self) -> usize {
        self.data.lock().len
    }
}

// =============================================================================
// BPF Array Map
// =============================================================================

/// Most bytes a map may preallocate: half of free memory (host tests:
/// no limit)
fn prealloc_budget() -> u64 {
    #[cfg(not(test))]
    {
        crate::FRAME_ALLOCATOR.stats().free_bytes / 2
    }
    #[cfg(test)]
    u64::MAX
}

/// Array map implementation
///
/// Entries are accessed by u32 index (stored in key). The array is
/// pre-allocated to max_entries size, with each entry zero-initialized.
pub struct BpfArrayMap {
    /// The array data - each entry is protected by its own lock
    data: Vec<IrqSpinlock<Vec<u8>>>,
    /// Value size in bytes
    value_size: u32,
    /// Number of entries (key is always u32)
    max_entries: u32,
}

impl BpfArrayMap {
    /// Create a new array map
    ///
    /// Array maps always have key_size = 4 (u32 index).
    pub fn new(value_size: u32, max_entries: u32) -> Result<Arc<Self>, KernelError> {
        if value_size == 0 || value_size > BPF_MAX_VALUE_SIZE {
            return Err(KernelError::InvalidArgument);
        }
        if max_entries == 0 || max_entries > BPF_MAX_ENTRIES {
            return Err(KernelError::InvalidArgument);
        }

        // Pre-allocate all entries with zero values: ENOMEM rather than
        // exhaust memory (Linux bpf_map_area_alloc fails; no memcg here,
        // so at most half of free memory)
        // Each entry: its lock and Vec header, and the value's kmalloc
        // class (powers of two from 16 bytes)
        let entry = core::mem::size_of::<IrqSpinlock<Vec<u8>>>() as u64
            + u64::from(value_size).next_power_of_two().max(16);
        let bytes = u64::from(max_entries) * entry;
        if bytes > prealloc_budget() {
            return Err(KernelError::OutOfMemory);
        }
        let mut data = Vec::new();
        data.try_reserve_exact(max_entries as usize)
            .map_err(|_| KernelError::OutOfMemory)?;
        for _ in 0..max_entries {
            data.push(IrqSpinlock::new(crate::util::kmem::try_vec(
                value_size as usize,
                0u8,
            )?));
        }

        try_arc(Self {
            data,
            value_size,
            max_entries,
        })
    }

    /// Convert key bytes to index
    fn key_to_index(&self, key: &[u8]) -> Option<u32> {
        if key.len() != 4 {
            return None;
        }
        let index = u32::from_ne_bytes([key[0], key[1], key[2], key[3]]);
        (index < self.max_entries).then_some(index)
    }
}

impl BpfMapOps for BpfArrayMap {
    fn lookup(&self, key: &[u8], out: &mut [u8]) -> bool {
        let Some(index) = self.key_to_index(key) else {
            return false;
        };
        let v = self.data[index as usize].lock();
        if out.len() != v.len() {
            return false;
        }
        out.copy_from_slice(&v);
        true
    }

    fn update(&self, key: &[u8], value: &[u8], flags: u64) -> Result<(), KernelError> {
        update_flags_ok(flags)?;
        if value.len() != self.value_size as usize {
            return Err(KernelError::InvalidArgument);
        }

        // Every element is preallocated: no new index (Linux
        // array_map_update_elem: E2BIG), none missing (EEXIST)
        let index = self.key_to_index(key).ok_or(KernelError::ArgListTooLong)?;
        if flags & BPF_NOEXIST != 0 {
            return Err(KernelError::AlreadyExists);
        }

        let mut entry = self.data[index as usize].lock();
        entry.copy_from_slice(value);
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<(), KernelError> {
        // Array entries can't be deleted, only zeroed
        let index = self.key_to_index(key).ok_or(KernelError::NotFound)?;
        let mut entry = self.data[index as usize].lock();
        entry.fill(0);
        Ok(())
    }

    fn get_next_key(&self, key: Option<&[u8]>, out: &mut [u8]) -> bool {
        // Linux array_map_get_next_key: a missing or out-of-range key
        // starts from 0
        let next_index = match key.and_then(|k| self.key_to_index(k)) {
            None => 0u32,
            Some(i) => i + 1,
        };
        if next_index >= self.max_entries || out.len() != 4 {
            return false;
        }
        out.copy_from_slice(&next_index.to_ne_bytes());
        true
    }

    fn map_type(&self) -> u32 {
        BPF_MAP_TYPE_ARRAY
    }

    fn key_size(&self) -> u32 {
        4 // Always u32 for array maps
    }

    fn value_size(&self) -> u32 {
        self.value_size
    }

    fn max_entries(&self) -> u32 {
        self.max_entries
    }

    fn len(&self) -> usize {
        self.max_entries as usize
    }
}

// =============================================================================
// BPF Map Container
// =============================================================================

/// Global map ID counter
static NEXT_MAP_ID: AtomicU32 = AtomicU32::new(1);

/// Container for a BPF map with metadata
pub struct BpfMap {
    /// Unique map ID
    pub id: u32,
    /// The underlying map operations
    ops: Arc<dyn BpfMapOps>,
    /// Map flags from creation
    pub flags: u32,
}

impl BpfMap {
    /// Create a new map container
    pub fn new(ops: Arc<dyn BpfMapOps>, flags: u32) -> Result<Arc<Self>, KernelError> {
        let id = NEXT_MAP_ID.fetch_add(1, Ordering::Relaxed);
        try_arc(Self { id, ops, flags })
    }

    /// Get the underlying map operations
    pub fn ops(&self) -> &dyn BpfMapOps {
        &*self.ops
    }
}

// Implement BpfMapOps by delegation
impl BpfMapOps for BpfMap {
    fn lookup(&self, key: &[u8], out: &mut [u8]) -> bool {
        self.ops.lookup(key, out)
    }

    fn update(&self, key: &[u8], value: &[u8], flags: u64) -> Result<(), KernelError> {
        self.ops.update(key, value, flags)
    }

    fn delete(&self, key: &[u8]) -> Result<(), KernelError> {
        self.ops.delete(key)
    }

    fn get_next_key(&self, key: Option<&[u8]>, out: &mut [u8]) -> bool {
        self.ops.get_next_key(key, out)
    }

    fn map_type(&self) -> u32 {
        self.ops.map_type()
    }

    fn key_size(&self) -> u32 {
        self.ops.key_size()
    }

    fn value_size(&self) -> u32 {
        self.ops.value_size()
    }

    fn max_entries(&self) -> u32 {
        self.ops.max_entries()
    }

    fn len(&self) -> usize {
        self.ops.len()
    }
}

/// Create a new BPF map based on type
pub fn create_map(
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    flags: u32,
) -> Result<Arc<BpfMap>, KernelError> {
    let ops: Arc<dyn BpfMapOps> = match map_type {
        BPF_MAP_TYPE_HASH => BpfHashMap::new(key_size, value_size, max_entries)?,
        BPF_MAP_TYPE_ARRAY => {
            // Array maps must have key_size = 4
            if key_size != 4 {
                return Err(KernelError::InvalidArgument);
            }
            BpfArrayMap::new(value_size, max_entries)?
        }
        _ => return Err(KernelError::InvalidArgument),
    };

    BpfMap::new(ops, flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_map_basic() {
        let map = BpfHashMap::new(4, 8, 10).unwrap();

        let key = [1u8, 2, 3, 4];
        let value = [0u8, 1, 2, 3, 4, 5, 6, 7];

        // Insert
        assert!(map.update(&key, &value, BPF_ANY).is_ok());

        // Lookup
        let mut out = [0u8; 8];
        assert!(map.lookup(&key, &mut out));
        assert_eq!(out, value);

        // Delete
        assert!(map.delete(&key).is_ok());
        assert!(!map.lookup(&key, &mut out));
    }

    /// Full at max_entries (E2BIG), a deleted element is reused, and
    /// get_next_key visits every key once
    #[test]
    fn test_hash_map_prealloc_and_iteration() {
        let map = BpfHashMap::new(4, 4, 8).unwrap();
        for i in 0u32..8 {
            assert!(
                map.update(&i.to_ne_bytes(), &i.to_ne_bytes(), BPF_NOEXIST)
                    .is_ok()
            );
        }
        assert!(matches!(
            map.update(&9u32.to_ne_bytes(), &[0; 4], BPF_ANY),
            Err(KernelError::ArgListTooLong)
        ));
        assert!(map.delete(&3u32.to_ne_bytes()).is_ok());
        assert!(map.update(&9u32.to_ne_bytes(), &[9; 4], BPF_ANY).is_ok());
        let mut seen = alloc::vec::Vec::new();
        let mut k = [0u8; 4];
        let mut cur: Option<[u8; 4]> = None;
        while map.get_next_key(cur.as_ref().map(|c| &c[..]), &mut k) {
            seen.push(u32::from_ne_bytes(k));
            cur = Some(k);
        }
        seen.sort_unstable();
        assert_eq!(seen, [0, 1, 2, 4, 5, 6, 7, 9]);
        // A key not in the map starts from the first
        assert!(map.get_next_key(Some(&77u32.to_ne_bytes()), &mut k));
    }

    #[test]
    fn test_array_map_basic() {
        let map = BpfArrayMap::new(8, 10).unwrap();

        let key = 5u32.to_ne_bytes();
        let value = [0u8, 1, 2, 3, 4, 5, 6, 7];

        // Update
        assert!(map.update(&key, &value, BPF_ANY).is_ok());

        // Lookup
        let mut out = [0u8; 8];
        assert!(map.lookup(&key, &mut out));
        assert_eq!(out, value);
    }
}
