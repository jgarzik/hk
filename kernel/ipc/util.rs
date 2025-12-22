//! IPC Utilities - ID allocation, permission checking, common infrastructure
//!
//! This module provides:
//! - ID allocation with sequence numbers (prevents ABA problems)
//! - Permission checking following Linux semantics
//! - Common traits and structures for IPC objects

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::{Mutex, RwLock};

use crate::ipc::{IPC_CREAT, IPC_EXCL, IPC_PRIVATE};

// Error codes
const EACCES: i32 = 13;
const EEXIST: i32 = 17;
const ENOENT: i32 = 2;

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

/// Kernel IPC permission structure
///
/// This is the kernel-internal version, NOT the user-space ABI structure.
/// Each IPC object embeds this for common permission/ID tracking.
pub struct KernIpcPerm {
    /// Per-object lock for state modifications
    pub lock: Mutex<()>,
    /// Deletion marker (checked under RCU-like patterns)
    pub deleted: AtomicBool,
    /// IPC identifier (composite: seq << 16 | idx)
    pub id: i32,
    /// User-supplied key
    pub key: i32,
    /// Current owner UID
    pub uid: u32,
    /// Current owner GID
    pub gid: u32,
    /// Creator UID
    pub cuid: u32,
    /// Creator GID
    pub cgid: u32,
    /// Permission mode bits (rwxrwxrwx)
    pub mode: u16,
    /// Sequence number for ID validation
    pub seq: u32,
    /// Reference count
    pub refcount: AtomicU32,
}

impl KernIpcPerm {
    /// Create new permission structure
    pub fn new(key: i32, mode: u16) -> Self {
        let cred = crate::task::percpu::current_cred();
        let uid = cred.euid;
        let gid = cred.egid;
        Self {
            lock: Mutex::new(()),
            deleted: AtomicBool::new(false),
            id: -1,
            key,
            uid,
            gid,
            cuid: uid,
            cgid: gid,
            mode: mode & 0o777,
            seq: 0,
            refcount: AtomicU32::new(1),
        }
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
    pub fn fill_ipc64_perm(&self, perm: &mut crate::ipc::Ipc64Perm) {
        perm.key = self.key;
        perm.uid = self.uid;
        perm.gid = self.gid;
        perm.cuid = self.cuid;
        perm.cgid = self.cgid;
        perm.mode = self.mode;
        perm.seq = self.seq as u16;
        perm.__pad1 = [0; 2];
        perm.__pad2 = 0;
        perm.__unused1 = 0;
        perm.__unused2 = 0;
    }
}

// ============================================================================
// IPC Object Trait
// ============================================================================

/// Trait for all IPC objects (shm segments, sem arrays, msg queues)
pub trait IpcObject: Send + Sync {
    /// Get the permission structure
    fn perm(&self) -> &KernIpcPerm;

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
            return Err(ENOSPC);
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
                return Err(ENOSPC);
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

        // Update object's perm
        {
            let perm = obj.perm();
            // Safety: we have exclusive access via write lock
            let perm_ptr = perm as *const KernIpcPerm as *mut KernIpcPerm;
            unsafe {
                (*perm_ptr).id = id;
                (*perm_ptr).seq = inner.seq;
            }
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

        if let Some(obj) = inner.entries.get(&idx)
            && obj.perm().seq == seq
            && !obj.perm().is_deleted()
            && obj.perm().get_ref()
        {
            return Some(obj.clone());
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

// ENOSPC is not in our errno module, define locally
const ENOSPC: i32 = 28;

// ============================================================================
// Permission Checking
// ============================================================================

/// Permission flags for ipc_checkperm
pub const IPC_PERM_READ: u16 = 0o444;
pub const IPC_PERM_WRITE: u16 = 0o222;

/// Check IPC permissions
///
/// Returns 0 on success, -EACCES on failure
pub fn ipc_checkperm(perm: &KernIpcPerm, flag: u16) -> Result<(), i32> {
    let cred = crate::task::percpu::current_cred();
    let euid = cred.euid;
    let gid = cred.egid;

    // Extract requested permission bits
    let requested = flag & 0o7;

    // Check owner permissions
    if (euid == perm.cuid || euid == perm.uid) && (perm.mode >> 6) & 0o7 >= requested {
        return Ok(());
    }

    // Check group permissions
    if (gid == perm.cgid || gid == perm.gid) && (perm.mode >> 3) & 0o7 >= requested {
        return Ok(());
    }

    // Check other permissions
    if perm.mode & 0o7 >= requested {
        return Ok(());
    }

    // TODO: CAP_IPC_OWNER capability check

    Err(EACCES)
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
            return Err(EEXIST);
        }

        // Check permissions for access
        let access_flag = if flags & 0o4 != 0 {
            IPC_PERM_READ
        } else if flags & 0o2 != 0 {
            IPC_PERM_WRITE
        } else {
            0
        };

        if access_flag != 0
            && let Err(e) = ipc_checkperm(existing.perm(), access_flag)
        {
            existing.perm().put_ref();
            return Err(e);
        }

        let id = existing.perm().id;
        existing.perm().put_ref();
        return Ok(id);
    }

    // Not found - create if IPC_CREAT
    if flags & IPC_CREAT != 0 {
        let obj = create_fn(key, mode)?;
        return ids.alloc_id(obj, max_ids);
    }

    Err(ENOENT)
}
