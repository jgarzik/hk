//! IPC Utilities - ID allocation, permission checking, common infrastructure
//!
//! This module provides:
//! - ID allocation with sequence numbers (prevents ABA problems)
//! - Permission checking following Linux semantics
//! - Common traits and structures for IPC objects

use crate::sync::spin::{Mutex, RwLock};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::ops::Deref;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::ipc::{IPC_CREAT, IPC_EXCL, IPC_PRIVATE};
use crate::util::error::KernelError;

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

/// Mutable fields of KernIpcPerm, inside its lock (Linux: ipcperms() is
/// called with the object lock held)
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
/// The mutable fields are inside `lock` (spin leaf).
pub struct KernIpcPerm {
    /// The mutable fields (Linux kern_ipc_perm.lock)
    pub lock: Mutex<KernIpcPermMutable>,
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

impl KernIpcPerm {
    /// Create new permission structure
    pub fn new(key: i32, mode: u16) -> Self {
        let cred = crate::task::percpu::current_cred();
        let uid = cred.euid;
        let gid = cred.egid;
        Self {
            lock: Mutex::new(KernIpcPermMutable {
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

    /// The owner may change the object (IPC_SET, IPC_RMID): its uid, its
    /// creator, or CAP_SYS_ADMIN (Linux ipcctl_obtain_check)
    pub fn is_owner(inner: &KernIpcPermMutable, perm_cuid: u32, uid: u32) -> bool {
        uid == inner.uid || uid == perm_cuid || crate::task::capable(crate::task::CAP_SYS_ADMIN)
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
        let inner = self.lock.lock();
        out.key = self.key;
        out.uid = inner.uid;
        out.gid = inner.gid;
        out.cuid = self.cuid;
        out.cgid = self.cgid;
        out.mode = inner.mode;
        out.seq = inner.seq as u16;
        out.__pad1 = [0; 2];
        out.__pad2 = 0;
        out.__pad3 = 0;
        out.__unused1 = 0;
        out.__unused2 = 0;
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

/// Counted reference to an IPC object, returned by `IpcIds` lookups
///
/// Holds one `perm.get_ref()` reference, released by `put_ref()` on drop,
/// so every exit path (including `?`) balances the refcount.
pub struct IpcRef<T: IpcObject>(Arc<T>);

impl<T: IpcObject> Deref for IpcRef<T> {
    type Target = Arc<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: IpcObject> Drop for IpcRef<T> {
    fn drop(&mut self) {
        self.0.perm().put_ref();
    }
}

// ============================================================================
// IPC IDs Table
// ============================================================================

/// Inner state of IPC IDs table (protected by RwLock)
pub struct IpcIdsInner<T> {
    /// Number of allocated IDs
    pub in_use: u32,
    /// Global sequence number
    pub seq: u32,
    /// Last allocated index (for cyclic allocation)
    pub last_idx: u32,
    /// ID -> Object mapping
    pub entries: BTreeMap<u32, Arc<T>>,
    /// Key -> Index mapping (for non-private keys)
    pub key_map: BTreeMap<i32, u32>,
}

impl<T> IpcIdsInner<T> {
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

/// IPC IDs table - manages IPC object IDs for a namespace (one per
/// object type, Linux ipc_ids)
pub struct IpcIds<T> {
    /// Serializes creation and removal (Linux ids->rwsem, held for write
    /// by ipcget, IPC_RMID and IPC_SET): a key's lookup, the limit
    /// checks and the insert are one step, so IPC_CREAT|IPC_EXCL creates
    /// one object and the namespace totals never overshoot. Sleeping;
    /// `inner` (the lookup table, Linux's idr) is taken under it.
    pub rwsem: crate::sync::RwSem<()>,
    pub inner: RwLock<IpcIdsInner<T>>,
}

impl<T: IpcObject> IpcIds<T> {
    /// Create new empty IDs table
    pub fn new() -> Self {
        Self {
            rwsem: crate::sync::RwSem::new(()),
            inner: RwLock::new(IpcIdsInner::new()),
        }
    }

    /// Allocate a new ID for an object
    ///
    /// Returns the allocated ID on success
    pub fn alloc_id(&self, obj: Arc<T>, max_ids: u32) -> Result<i32, i32> {
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
            let mut perm = obj.perm().lock.lock();
            perm.id = id;
            perm.seq = inner.seq;
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
    pub fn find_by_id(&self, id: i32) -> Option<IpcRef<T>> {
        let inner = self.inner.read();
        let idx = (id as u32) & (IPCMNI - 1);
        let seq = ((id as u32) >> IPCMNI_SEQ_SHIFT) & (IPCMNI_SEQ_MAX - 1);

        if let Some(obj) = inner.entries.get(&idx) {
            let perm = obj.perm();
            let cur = perm.lock.lock().seq;
            if cur == seq && !perm.is_deleted() && perm.get_ref() {
                return Some(IpcRef(obj.clone()));
            }
        }
        None
    }

    /// Look up object by key
    pub fn find_by_key(&self, key: i32) -> Option<IpcRef<T>> {
        if key == IPC_PRIVATE {
            return None;
        }

        let inner = self.inner.read();
        if let Some(&idx) = inner.key_map.get(&key)
            && let Some(obj) = inner.entries.get(&idx)
            && !obj.perm().is_deleted()
            && obj.perm().get_ref()
        {
            return Some(IpcRef(obj.clone()));
        }
        None
    }

    /// Remove object by ID
    pub fn remove(&self, id: i32) -> Option<Arc<T>> {
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

    // Extract requested permission bits (collapse to lowest 3 bits like Linux)
    // Linux: requested_mode = (flag >> 6) | (flag >> 3) | flag
    let requested = ((flag >> 6) | (flag >> 3) | flag) & 0o7;

    let inner = perm.lock.lock();

    // Determine which permission bits apply based on user/group matching
    // Linux shifts granted_mode based on owner/group/other
    let granted = if euid == perm.cuid || euid == inner.uid {
        // Owner permissions
        (inner.mode >> 6) & 0o7
    } else if crate::fs::dac::in_group(&cred, perm.cgid)
        || crate::fs::dac::in_group(&cred, inner.gid)
    {
        // Group permissions (Linux in_group_p: fsgid or a supplementary
        // group)
        (inner.mode >> 3) & 0o7
    } else {
        // Other permissions
        inner.mode & 0o7
    };

    // Check if all requested bits are present in granted bits
    // Linux: (requested_mode & ~granted_mode & 0007) means "any bit requested but not granted"
    // We invert: (granted & requested) == requested means "all requested bits are granted"
    if (granted & requested) == requested || crate::task::capable(crate::task::CAP_IPC_OWNER) {
        return Ok(());
    }

    Err(KernelError::PermissionDenied.errno())
}

/// What ipcget needs from each IPC type (Linux struct ipc_ops)
pub struct IpcOps<T, N, C, A>
where
    N: FnOnce(i32, u16) -> Result<Arc<T>, i32>,
    C: FnOnce(&T) -> Result<(), i32>,
    A: FnOnce(&T),
{
    /// Build a new object (Linux newary/newseg/newque up to ipc_addid):
    /// the namespace limits are checked here, under `ids.rwsem`
    pub new: N,
    /// Extra checks on an existing object (Linux more_checks: semget's
    /// nsems, shmget's size)
    pub more_checks: C,
    /// After the insert succeeded: charge the namespace totals (Linux
    /// newary/newseg add used_sems/shm_tot after ipc_addid), so a failed
    /// insert leaves nothing to undo
    pub added: A,
}

/// Generic IPC get operation (Linux ipcget, ipcget_new, ipcget_public):
/// under `ids.rwsem` (write) across the key lookup, the permission and
/// type checks, and the creation and insert
pub fn ipcget<T: IpcObject + 'static, N, C, A>(
    ids: &IpcIds<T>,
    key: i32,
    flags: i32,
    max_ids: u32,
    ops: IpcOps<T, N, C, A>,
) -> Result<i32, i32>
where
    N: FnOnce(i32, u16) -> Result<Arc<T>, i32>,
    C: FnOnce(&T) -> Result<(), i32>,
    A: FnOnce(&T),
{
    let mode = (flags as u16) & 0o777;
    let _w = ids.rwsem.write();

    if key != IPC_PRIVATE
        && let Some(existing) = ids.find_by_key(key)
    {
        if flags & IPC_CREAT != 0 && flags & IPC_EXCL != 0 {
            return Err(KernelError::AlreadyExists.errno());
        }
        // Linux ipc_check_perms: ipcperms on the caller's mode bits
        // (EACCES), then the type's own checks
        let perm = existing.perm();
        ipc_checkperm(perm, mode)?;
        (ops.more_checks)(&existing)?;
        return Ok(perm.lock.lock().id);
    }
    if key != IPC_PRIVATE && flags & IPC_CREAT == 0 {
        return Err(KernelError::NotFound.errno());
    }
    let obj = (ops.new)(key, mode)?;
    let id = ids.alloc_id(obj.clone(), max_ids)?;
    (ops.added)(&obj);
    Ok(id)
}
