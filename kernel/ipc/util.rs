//! IPC Utilities - ID allocation, permission checking, common infrastructure
//!
//! This module provides:
//! - ID allocation with sequence numbers (prevents ABA problems)
//! - Permission checking following Linux semantics
//! - Common traits and structures for IPC objects

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::{Mutex, RwLock};

use crate::error::KernelError;
use crate::ipc::{IPC_CREAT, IPC_EXCL, IPC_PRIVATE};

// ============================================================================
// ID Allocation Constants
// ============================================================================

/// Maximum index value (15 bits for 32k entries)
const IPCMNI: u32 = 32768;

/// Shift for sequence number in ID
const IPCMNI_SEQ_SHIFT: u32 = 16;

/// Maximum sequence value
const IPCMNI_SEQ_MAX: u32 = 0x8000;

// ============================================================================
// IPC Permission Structure (kernel-internal)
// ============================================================================

/// Mutable fields of KernIpcPerm, protected by the lock
///
/// These fields are wrapped in UnsafeCell and protected by `KernIpcPerm::lock`.
/// Following Linux's pattern where ipcperms() must be called with lock held.
#[repr(C)]
pub struct KernIpcPermMutable {
    /// IPC identifier (composite: seq << 16 | idx) - set once during allocation
    pub id: i32,
    /// Current owner UID - can be changed via IPC_SET
    pub uid: u32,
    /// Current owner GID - can be changed via IPC_SET
    pub gid: u32,
    /// Permission mode bits (rwxrwxrwx) - can be changed via IPC_SET
    pub mode: u16,
    /// Sequence number for ID validation - set once during allocation
    pub seq: u32,
}

/// Kernel IPC permission structure
///
/// This is the kernel-internal version, NOT the user-space ABI structure.
/// Each IPC object embeds this for common permission/ID tracking.
///
/// # Locking
/// Mutable fields in `mutable` are protected by `lock`. Callers must hold
/// the lock when reading or writing these fields. This follows Linux's
/// locking scheme where ipcperms() is called with the object lock held.
pub struct KernIpcPerm {
    /// Lock protecting mutable fields
    pub lock: Mutex<()>,
    /// Mutable fields (protected by lock)
    mutable: UnsafeCell<KernIpcPermMutable>,
    /// Deletion marker (lock-free, checked under RCU-like patterns)
    pub deleted: AtomicBool,
    /// User-supplied key (immutable after creation)
    pub key: i32,
    /// Creator UID (immutable after creation)
    pub cuid: u32,
    /// Creator GID (immutable after creation)
    pub cgid: u32,
    /// Reference count (lock-free)
    pub refcount: AtomicU32,
}

// SAFETY: KernIpcPerm is safe to share between threads because:
// - Mutable fields are protected by the lock
// - deleted and refcount use atomics
// - key, cuid, cgid are immutable after creation
unsafe impl Sync for KernIpcPerm {}

impl KernIpcPerm {
    /// Create new permission structure
    pub fn new(key: i32, mode: u16) -> Self {
        let cred = crate::task::percpu::current_cred();
        let uid = cred.euid;
        let gid = cred.egid;
        Self {
            lock: Mutex::new(()),
            mutable: UnsafeCell::new(KernIpcPermMutable {
                id: -1,
                uid,
                gid,
                mode: mode & 0o777,
                seq: 0,
            }),
            deleted: AtomicBool::new(false),
            key,
            cuid: uid,
            cgid: gid,
            refcount: AtomicU32::new(1),
        }
    }

    /// Get mutable reference to inner fields
    ///
    /// # Safety
    /// Caller must hold `self.lock`.
    #[inline]
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn mutable(&self) -> &mut KernIpcPermMutable {
        // SAFETY: Caller guarantees they hold the lock.
        // This is the standard UnsafeCell pattern for interior mutability
        // protected by a lock.
        unsafe { &mut *self.mutable.get() }
    }

    /// Get immutable reference to inner fields
    ///
    /// # Safety
    /// Caller must hold `self.lock`.
    #[inline]
    pub unsafe fn mutable_ref(&self) -> &KernIpcPermMutable {
        // SAFETY: Caller guarantees they hold the lock
        unsafe { &*self.mutable.get() }
    }

    /// Increment reference count
    ///
    /// Returns false if object is being deleted (refcount was 0)
    pub fn get_ref(&self) -> bool {
        loop {
            let current = self.refcount.load(Ordering::Acquire);
            if current == 0 {
                return false;
            }
            if self
                .refcount
                .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Decrement reference count
    ///
    /// Returns true if this was the last reference
    pub fn put_ref(&self) -> bool {
        let prev = self.refcount.fetch_sub(1, Ordering::AcqRel);
        prev == 1
    }

    /// Mark as deleted
    pub fn mark_deleted(&self) {
        self.deleted.store(true, Ordering::Release);
    }

    /// Check if deleted
    pub fn is_deleted(&self) -> bool {
        self.deleted.load(Ordering::Acquire)
    }

    /// Fill user-space ipc64_perm structure
    ///
    /// Acquires the lock internally.
    pub fn fill_ipc64_perm(&self, out: &mut crate::ipc::Ipc64Perm) {
        let _lock = self.lock.lock();
        // SAFETY: We hold the lock
        let inner = unsafe { self.mutable_ref() };
        out.key = self.key;
        out.uid = inner.uid;
        out.gid = inner.gid;
        out.cuid = self.cuid;
        out.cgid = self.cgid;
        out.mode = inner.mode;
        out.seq = inner.seq as u16;
        out.__pad1 = [0; 2];
        out.__pad2 = 0;
        out.__unused1 = 0;
        out.__unused2 = 0;
    }
}

// ============================================================================
// IPC Object Type Tag
// ============================================================================

/// IPC object type discriminant for safe downcasting
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcType {
    /// Shared memory segment
    Shm,
    /// Semaphore array
    Sem,
    /// Message queue
    Msg,
}

// ============================================================================
// IPC Object Trait
// ============================================================================

/// Trait for all IPC objects (shm segments, sem arrays, msg queues)
pub trait IpcObject: Send + Sync {
    /// Get the permission structure
    fn perm(&self) -> &KernIpcPerm;

    /// Get the IPC object type for safe downcasting
    fn ipc_type(&self) -> IpcType;

    /// Called when object should be freed
    fn destroy(&self);
}

// ============================================================================
// IPC IDs Table
// ============================================================================

/// Inner state of IPC IDs table (protected by RwLock)
pub struct IpcIdsInner {
    /// Number of allocated IDs
    pub in_use: u32,
    /// Global sequence number
    pub seq: u32,
    /// Last allocated index (for cyclic allocation)
    pub last_idx: u32,
    /// ID -> Object mapping
    pub entries: BTreeMap<u32, Arc<dyn IpcObject>>,
    /// Key -> Index mapping (for non-private keys)
    pub key_map: BTreeMap<i32, u32>,
}

impl IpcIdsInner {
    fn new() -> Self {
        Self {
            in_use: 0,
            seq: 0,
            last_idx: 0,
            entries: BTreeMap::new(),
            key_map: BTreeMap::new(),
        }
    }
}

/// IPC IDs table - manages IPC object IDs for a namespace
pub struct IpcIds {
    pub inner: RwLock<IpcIdsInner>,
}

impl IpcIds {
    /// Create new empty IDs table
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(IpcIdsInner::new()),
        }
    }

    /// Allocate a new ID for an object
    ///
    /// Returns the allocated ID on success
    pub fn alloc_id(&self, obj: Arc<dyn IpcObject>, max_ids: u32) -> Result<i32, i32> {
        let mut inner = self.inner.write();

        if inner.in_use >= max_ids || inner.in_use >= IPCMNI {
            return Err(KernelError::NoSpace.errno());
        }

        // Find free index (cyclic allocation)
        let start_idx = inner.last_idx;
        let mut idx = start_idx;

        loop {
            idx = (idx + 1) % IPCMNI;
            if !inner.entries.contains_key(&idx) {
                break;
            }
            if idx == start_idx {
                return Err(KernelError::NoSpace.errno());
            }
        }

        // Update sequence number on wrap
        if idx <= inner.last_idx && inner.in_use > 0 {
            inner.seq = inner.seq.wrapping_add(1);
            if inner.seq >= IPCMNI_SEQ_MAX {
                inner.seq = 0;
            }
        }

        inner.last_idx = idx;

        // Calculate composite ID
        let id = ((inner.seq << IPCMNI_SEQ_SHIFT) | idx) as i32;

        // Update object's perm (lock protected)
        {
            let perm = obj.perm();
            let _lock = perm.lock.lock();
            // SAFETY: We hold the lock
            let perm_mutable = unsafe { perm.mutable() };
            perm_mutable.id = id;
            perm_mutable.seq = inner.seq;
        }

        // Insert into maps
        let key = obj.perm().key;
        inner.entries.insert(idx, obj);
        if key != IPC_PRIVATE {
            inner.key_map.insert(key, idx);
        }
        inner.in_use += 1;

        Ok(id)
    }

    /// Look up object by ID
    pub fn find_by_id(&self, id: i32) -> Option<Arc<dyn IpcObject>> {
        let inner = self.inner.read();
        let idx = (id as u32) & (IPCMNI - 1);
        let seq = ((id as u32) >> IPCMNI_SEQ_SHIFT) & (IPCMNI_SEQ_MAX - 1);

        if let Some(obj) = inner.entries.get(&idx) {
            let perm = obj.perm();
            let _lock = perm.lock.lock();
            // SAFETY: We hold the lock
            let perm_mutable = unsafe { perm.mutable_ref() };
            if perm_mutable.seq == seq && !perm.is_deleted() && perm.get_ref() {
                return Some(obj.clone());
            }
        }
        None
    }

    /// Look up object by key
    pub fn find_by_key(&self, key: i32) -> Option<Arc<dyn IpcObject>> {
        if key == IPC_PRIVATE {
            return None;
        }

        let inner = self.inner.read();
        if let Some(&idx) = inner.key_map.get(&key)
            && let Some(obj) = inner.entries.get(&idx)
            && !obj.perm().is_deleted()
            && obj.perm().get_ref()
        {
            return Some(obj.clone());
        }
        None
    }

    /// Remove object by ID
    pub fn remove(&self, id: i32) -> Option<Arc<dyn IpcObject>> {
        let mut inner = self.inner.write();
        let idx = (id as u32) & (IPCMNI - 1);

        if let Some(obj) = inner.entries.remove(&idx) {
            let key = obj.perm().key;
            if key != IPC_PRIVATE {
                inner.key_map.remove(&key);
            }
            inner.in_use -= 1;
            obj.perm().mark_deleted();
            Some(obj)
        } else {
            None
        }
    }
}

impl Default for IpcIds {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Permission Checking
// ============================================================================

/// Permission flags for ipc_checkperm
pub const IPC_PERM_READ: u16 = 0o444;
pub const IPC_PERM_WRITE: u16 = 0o222;

/// Check IPC permissions
///
/// Follows Linux's ipcperms() logic: uses bitwise checking to ensure all
/// requested permission bits are present in the granted bits.
///
/// Acquires the lock internally, following Linux's pattern.
/// Returns Ok(()) on success, Err(-EACCES) on failure
pub fn ipc_checkperm(perm: &KernIpcPerm, flag: u16) -> Result<(), i32> {
    let cred = crate::task::percpu::current_cred();
    let euid = cred.euid;
    let gid = cred.egid;

    // Extract requested permission bits (collapse to lowest 3 bits like Linux)
    // Linux: requested_mode = (flag >> 6) | (flag >> 3) | flag
    let requested = ((flag >> 6) | (flag >> 3) | flag) & 0o7;

    let _lock = perm.lock.lock();
    // SAFETY: We hold the lock
    let inner = unsafe { perm.mutable_ref() };

    // Determine which permission bits apply based on user/group matching
    // Linux shifts granted_mode based on owner/group/other
    let granted = if euid == perm.cuid || euid == inner.uid {
        // Owner permissions
        (inner.mode >> 6) & 0o7
    } else if gid == perm.cgid || gid == inner.gid {
        // Group permissions
        (inner.mode >> 3) & 0o7
    } else {
        // Other permissions
        inner.mode & 0o7
    };

    // Check if all requested bits are present in granted bits
    // Linux: (requested_mode & ~granted_mode & 0007) means "any bit requested but not granted"
    // We invert: (granted & requested) == requested means "all requested bits are granted"
    if (granted & requested) == requested {
        return Ok(());
    }

    // TODO: CAP_IPC_OWNER capability check

    Err(KernelError::PermissionDenied.errno())
}

/// Generic IPC get operation
///
/// Handles IPC_CREAT, IPC_EXCL, IPC_PRIVATE logic
pub fn ipcget<T: IpcObject + 'static>(
    ids: &IpcIds,
    key: i32,
    flags: i32,
    max_ids: u32,
    create_fn: impl FnOnce(i32, u16) -> Result<Arc<T>, i32>,
) -> Result<i32, i32> {
    let mode = (flags as u16) & 0o777;

    // IPC_PRIVATE always creates new
    if key == IPC_PRIVATE {
        let obj = create_fn(key, mode)?;
        return ids.alloc_id(obj, max_ids);
    }

    // Try to find existing
    if let Some(existing) = ids.find_by_key(key) {
        // Found existing - check flags
        if flags & IPC_CREAT != 0 && flags & IPC_EXCL != 0 {
            existing.perm().put_ref();
            return Err(KernelError::AlreadyExists.errno());
        }

        // Check permissions for access
        let access_flag = if flags & 0o4 != 0 {
            IPC_PERM_READ
        } else if flags & 0o2 != 0 {
            IPC_PERM_WRITE
        } else {
            0
        };

        let perm = existing.perm();

        if access_flag != 0
            && let Err(e) = ipc_checkperm(perm, access_flag)
        {
            perm.put_ref();
            return Err(e);
        }

        let _lock = perm.lock.lock();
        // SAFETY: We hold the lock
        let id = unsafe { perm.mutable_ref() }.id;
        drop(_lock);
        perm.put_ref();
        return Ok(id);
    }

    // Not found - create if IPC_CREAT
    if flags & IPC_CREAT != 0 {
        let obj = create_fn(key, mode)?;
        return ids.alloc_id(obj, max_ids);
    }

    Err(KernelError::NotFound.errno())
}
