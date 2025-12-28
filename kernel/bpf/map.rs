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

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::arch::IrqSpinlock;
use crate::error::KernelError;

// =============================================================================
// Map Type Constants (Linux ABI)
// =============================================================================

/// Unspecified map type
#[allow(dead_code)]
pub const BPF_MAP_TYPE_UNSPEC: u32 = 0;
/// Hash table map
pub const BPF_MAP_TYPE_HASH: u32 = 1;
/// Array map (indexed by u32)
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;

// =============================================================================
// Map Update Flags (Linux ABI)
// =============================================================================

/// Create new element or update existing
#[allow(dead_code)]
pub const BPF_ANY: u64 = 0;
/// Create new element only if it doesn't exist
pub const BPF_NOEXIST: u64 = 1;
/// Update existing element only
pub const BPF_EXIST: u64 = 2;
/// Update with spin_lock held
#[allow(dead_code)]
pub const BPF_F_LOCK: u64 = 4;

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
    /// Look up an element by key
    ///
    /// Returns the value if found, None otherwise.
    fn lookup(&self, key: &[u8]) -> Option<Vec<u8>>;

    /// Update or insert an element
    ///
    /// Flags:
    /// - `BPF_ANY`: Create or update
    /// - `BPF_NOEXIST`: Create only if key doesn't exist
    /// - `BPF_EXIST`: Update only if key exists
    fn update(&self, key: &[u8], value: &[u8], flags: u64) -> Result<(), KernelError>;

    /// Delete an element by key
    fn delete(&self, key: &[u8]) -> Result<(), KernelError>;

    /// Get the next key after the given key
    ///
    /// If key is None, returns the first key.
    /// Returns None when iteration is complete.
    fn get_next_key(&self, key: Option<&[u8]>) -> Option<Vec<u8>>;

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
    /// The actual key-value store
    data: IrqSpinlock<BTreeMap<Vec<u8>, Vec<u8>>>,
    /// Key size in bytes
    key_size: u32,
    /// Value size in bytes
    value_size: u32,
    /// Maximum number of entries
    max_entries: u32,
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

        Ok(Arc::new(Self {
            data: IrqSpinlock::new(BTreeMap::new()),
            key_size,
            value_size,
            max_entries,
        }))
    }
}

impl BpfMapOps for BpfHashMap {
    fn lookup(&self, key: &[u8]) -> Option<Vec<u8>> {
        if key.len() != self.key_size as usize {
            return None;
        }
        let data = self.data.lock();
        data.get(key).cloned()
    }

    fn update(&self, key: &[u8], value: &[u8], flags: u64) -> Result<(), KernelError> {
        if key.len() != self.key_size as usize {
            return Err(KernelError::InvalidArgument);
        }
        if value.len() != self.value_size as usize {
            return Err(KernelError::InvalidArgument);
        }

        let mut data = self.data.lock();
        let exists = data.contains_key(key);

        match flags {
            BPF_NOEXIST if exists => return Err(KernelError::AlreadyExists),
            BPF_EXIST if !exists => return Err(KernelError::NotFound),
            _ => {}
        }

        // Check max entries only for new insertions
        if !exists && data.len() >= self.max_entries as usize {
            return Err(KernelError::ArgListTooLong);
        }

        data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<(), KernelError> {
        if key.len() != self.key_size as usize {
            return Err(KernelError::InvalidArgument);
        }
        let mut data = self.data.lock();
        if data.remove(key).is_some() {
            Ok(())
        } else {
            Err(KernelError::NotFound)
        }
    }

    fn get_next_key(&self, key: Option<&[u8]>) -> Option<Vec<u8>> {
        let data = self.data.lock();

        match key {
            None => {
                // Return first key
                data.keys().next().cloned()
            }
            Some(k) => {
                // Return key after this one
                // Use range to find keys greater than k
                data.range::<[u8], _>((core::ops::Bound::Excluded(k), core::ops::Bound::Unbounded))
                    .next()
                    .map(|(key, _)| key.clone())
            }
        }
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
        self.data.lock().len()
    }
}

// =============================================================================
// BPF Array Map
// =============================================================================

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

        // Pre-allocate all entries with zero values
        let zero_value = vec![0u8; value_size as usize];
        let mut data = Vec::with_capacity(max_entries as usize);
        for _ in 0..max_entries {
            data.push(IrqSpinlock::new(zero_value.clone()));
        }

        Ok(Arc::new(Self {
            data,
            value_size,
            max_entries,
        }))
    }

    /// Convert key bytes to index
    fn key_to_index(&self, key: &[u8]) -> Option<u32> {
        if key.len() != 4 {
            return None;
        }
        let index = u32::from_ne_bytes([key[0], key[1], key[2], key[3]]);
        if index < self.max_entries {
            Some(index)
        } else {
            None
        }
    }
}

impl BpfMapOps for BpfArrayMap {
    fn lookup(&self, key: &[u8]) -> Option<Vec<u8>> {
        let index = self.key_to_index(key)?;
        Some(self.data[index as usize].lock().clone())
    }

    fn update(&self, key: &[u8], value: &[u8], flags: u64) -> Result<(), KernelError> {
        if value.len() != self.value_size as usize {
            return Err(KernelError::InvalidArgument);
        }

        let index = self.key_to_index(key).ok_or(KernelError::NotFound)?;

        // Array entries always exist (pre-allocated)
        if flags == BPF_NOEXIST {
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

    fn get_next_key(&self, key: Option<&[u8]>) -> Option<Vec<u8>> {
        let next_index = match key {
            None => 0u32,
            Some(k) => {
                let current = self.key_to_index(k)?;
                current.checked_add(1)?
            }
        };

        if next_index < self.max_entries {
            Some(next_index.to_ne_bytes().to_vec())
        } else {
            None
        }
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
    pub fn new(ops: Arc<dyn BpfMapOps>, flags: u32) -> Arc<Self> {
        let id = NEXT_MAP_ID.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self { id, ops, flags })
    }

    /// Get the underlying map operations
    pub fn ops(&self) -> &dyn BpfMapOps {
        &*self.ops
    }
}

// Implement BpfMapOps by delegation
impl BpfMapOps for BpfMap {
    fn lookup(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.ops.lookup(key)
    }

    fn update(&self, key: &[u8], value: &[u8], flags: u64) -> Result<(), KernelError> {
        self.ops.update(key, value, flags)
    }

    fn delete(&self, key: &[u8]) -> Result<(), KernelError> {
        self.ops.delete(key)
    }

    fn get_next_key(&self, key: Option<&[u8]>) -> Option<Vec<u8>> {
        self.ops.get_next_key(key)
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

    Ok(BpfMap::new(ops, flags))
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
        let result = map.lookup(&key).unwrap();
        assert_eq!(result, value);

        // Delete
        assert!(map.delete(&key).is_ok());
        assert!(map.lookup(&key).is_none());
    }

    #[test]
    fn test_array_map_basic() {
        let map = BpfArrayMap::new(8, 10).unwrap();

        let key = 5u32.to_ne_bytes();
        let value = [0u8, 1, 2, 3, 4, 5, 6, 7];

        // Update
        assert!(map.update(&key, &value, BPF_ANY).is_ok());

        // Lookup
        let result = map.lookup(&key).unwrap();
        assert_eq!(result, value);
    }
}
