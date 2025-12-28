//! POSIX advisory byte-range locking (fcntl F_GETLK/F_SETLK/F_SETLKW)
//!
//! This module implements POSIX.1 advisory record locking as specified
//! in fcntl(2). Unlike BSD flock() which locks entire files, POSIX locks
//! apply to byte ranges within files.
//!
//! ## Key Semantics
//!
//! - Locks are associated with (inode, owning-PID) pairs
//! - Read locks (F_RDLCK) allow multiple readers
//! - Write locks (F_WRLCK) are exclusive
//! - Closing ANY fd to a file releases ALL POSIX locks held by that process
//! - Locks are NOT inherited across fork() but ARE released on exec()
//! - Length 0 means "to end of file" (EOF lock)

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::error::KernelError;
use crate::fs::file::seek;
use crate::fs::{File, Inode};
use crate::task::percpu::current_pid;
use spin::Mutex;

// =============================================================================
// Lock type constants (Linux ABI)
// =============================================================================

/// Read (shared) lock
pub const F_RDLCK: i16 = 0;
/// Write (exclusive) lock
pub const F_WRLCK: i16 = 1;
/// Unlock
pub const F_UNLCK: i16 = 2;

// =============================================================================
// Flock structure (Linux ABI)
// =============================================================================

/// struct flock for POSIX advisory byte-range locks
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Flock {
    /// Lock type: F_RDLCK, F_WRLCK, or F_UNLCK
    pub l_type: i16,
    /// How to interpret l_start: SEEK_SET, SEEK_CUR, or SEEK_END
    pub l_whence: i16,
    /// Starting offset of the lock
    pub l_start: i64,
    /// Length of the lock (0 = to EOF)
    pub l_len: i64,
    /// PID of lock owner (filled in by F_GETLK)
    pub l_pid: i32,
}

// =============================================================================
// Lock Types
// =============================================================================

/// Lock type for a byte range
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosixLockType {
    /// Read (shared) lock - multiple holders allowed
    Read,
    /// Write (exclusive) lock - single holder only
    Write,
}

impl PosixLockType {
    /// Convert from flock l_type field
    pub fn from_flock(l_type: i16) -> Option<Self> {
        match l_type {
            F_RDLCK => Some(PosixLockType::Read),
            F_WRLCK => Some(PosixLockType::Write),
            _ => None,
        }
    }

    /// Convert to flock l_type field
    pub fn to_flock(self) -> i16 {
        match self {
            PosixLockType::Read => F_RDLCK,
            PosixLockType::Write => F_WRLCK,
        }
    }
}

/// A single byte-range lock
#[derive(Debug, Clone)]
pub struct PosixLock {
    /// Owning process ID
    pub owner: u64,
    /// Start offset (inclusive)
    pub start: u64,
    /// End offset (exclusive), u64::MAX means EOF
    pub end: u64,
    /// Lock type
    pub lock_type: PosixLockType,
}

impl PosixLock {
    /// Check if this lock overlaps with a given range
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.start < end && start < self.end
    }

    /// Check if this lock conflicts with another lock request
    ///
    /// Same owner can always modify their own locks.
    /// Read locks don't conflict with read locks.
    /// All other combinations conflict.
    pub fn conflicts_with(&self, other_type: PosixLockType, other_owner: u64) -> bool {
        // Same owner can always modify their own locks
        if self.owner == other_owner {
            return false;
        }
        // Read locks don't conflict with read locks
        if self.lock_type == PosixLockType::Read && other_type == PosixLockType::Read {
            return false;
        }
        // All other combinations conflict
        true
    }
}

// =============================================================================
// Per-Inode Lock Table
// =============================================================================

/// Locks held on a single inode
#[derive(Default)]
struct InodeLocks {
    locks: Vec<PosixLock>,
}

impl InodeLocks {
    /// Find a conflicting lock for F_GETLK
    fn find_conflict(
        &self,
        start: u64,
        end: u64,
        lock_type: PosixLockType,
        pid: u64,
    ) -> Option<&PosixLock> {
        self.locks
            .iter()
            .find(|lock| lock.overlaps(start, end) && lock.conflicts_with(lock_type, pid))
    }

    /// Try to set a lock (F_SETLK)
    fn try_lock(
        &mut self,
        pid: u64,
        start: u64,
        end: u64,
        lock_type: PosixLockType,
    ) -> Result<(), KernelError> {
        // Check for conflicts
        if self.find_conflict(start, end, lock_type, pid).is_some() {
            return Err(KernelError::WouldBlock);
        }

        // Remove overlapping locks from same owner (they'll be replaced/merged)
        self.unlock_range(pid, start, end);

        // Add new lock
        self.locks.push(PosixLock {
            owner: pid,
            start,
            end,
            lock_type,
        });

        // Coalesce adjacent locks of same type from same owner
        self.coalesce_locks(pid);

        Ok(())
    }

    /// Unlock a range - may split existing locks
    fn unlock_range(&mut self, pid: u64, start: u64, end: u64) {
        let mut new_locks = Vec::new();

        for lock in self.locks.drain(..) {
            if lock.owner != pid {
                // Not our lock, keep it
                new_locks.push(lock);
                continue;
            }

            if !lock.overlaps(start, end) {
                // No overlap, keep it
                new_locks.push(lock);
                continue;
            }

            // Lock overlaps with unlock range - may need to split

            // Case 1: Lock completely within unlock range - remove entirely
            if lock.start >= start && lock.end <= end {
                continue;
            }

            // Case 2: Unlock range splits the lock into two parts
            if lock.start < start && lock.end > end {
                // Left part
                new_locks.push(PosixLock {
                    owner: lock.owner,
                    start: lock.start,
                    end: start,
                    lock_type: lock.lock_type,
                });
                // Right part
                new_locks.push(PosixLock {
                    owner: lock.owner,
                    start: end,
                    end: lock.end,
                    lock_type: lock.lock_type,
                });
                continue;
            }

            // Case 3: Partial overlap at start of lock
            if lock.start >= start && lock.start < end && lock.end > end {
                new_locks.push(PosixLock {
                    owner: lock.owner,
                    start: end,
                    end: lock.end,
                    lock_type: lock.lock_type,
                });
                continue;
            }

            // Case 4: Partial overlap at end of lock
            if lock.start < start && lock.end > start && lock.end <= end {
                new_locks.push(PosixLock {
                    owner: lock.owner,
                    start: lock.start,
                    end: start,
                    lock_type: lock.lock_type,
                });
            }
        }

        self.locks = new_locks;
    }

    /// Remove all locks held by a PID
    fn remove_all_for_pid(&mut self, pid: u64) {
        self.locks.retain(|l| l.owner != pid);
    }

    /// Coalesce adjacent locks of same type from same owner
    fn coalesce_locks(&mut self, _pid: u64) {
        // Sort by (owner, type, start)
        self.locks.sort_by(|a, b| {
            a.owner
                .cmp(&b.owner)
                .then_with(|| (a.lock_type as u8).cmp(&(b.lock_type as u8)))
                .then_with(|| a.start.cmp(&b.start))
        });

        // Merge adjacent/overlapping locks
        let mut merged: Vec<PosixLock> = Vec::new();
        for lock in self.locks.drain(..) {
            if let Some(last) = merged.last_mut()
                && last.owner == lock.owner
                && last.lock_type == lock.lock_type
                && last.end >= lock.start
            {
                // Merge: extend last to cover this lock
                last.end = last.end.max(lock.end);
                continue;
            }
            merged.push(lock);
        }
        self.locks = merged;
    }

    fn is_empty(&self) -> bool {
        self.locks.is_empty()
    }
}

// =============================================================================
// Global Lock Registry
// =============================================================================

/// Key for the global lock table - uses inode pointer for uniqueness
type InodeKey = u64;

/// Global POSIX lock registry
static POSIX_LOCKS: Mutex<BTreeMap<InodeKey, InodeLocks>> = Mutex::new(BTreeMap::new());

fn inode_key(inode: &Arc<Inode>) -> InodeKey {
    Arc::as_ptr(inode) as u64
}

// =============================================================================
// Range Resolution
// =============================================================================

/// Resolve flock start/len to absolute byte range
///
/// Returns (start, end) where end is exclusive. EOF is represented as u64::MAX.
fn resolve_range(flock: &Flock, file: &File) -> Result<(u64, u64), KernelError> {
    let inode = file.get_inode().ok_or(KernelError::BadFd)?;
    let file_size = inode.get_size();

    let base = match flock.l_whence as i32 {
        seek::SEEK_SET => 0i64,
        seek::SEEK_CUR => file.get_pos() as i64,
        seek::SEEK_END => file_size as i64,
        _ => return Err(KernelError::InvalidArgument),
    };

    let start = base
        .checked_add(flock.l_start)
        .ok_or(KernelError::InvalidArgument)?;

    if start < 0 {
        return Err(KernelError::InvalidArgument);
    }

    let start = start as u64;
    let end = if flock.l_len == 0 {
        u64::MAX // To EOF
    } else if flock.l_len > 0 {
        start
            .checked_add(flock.l_len as u64)
            .ok_or(KernelError::InvalidArgument)?
    } else {
        // Negative length: lock bytes before start
        let len = (-flock.l_len) as u64;
        let new_start = start.checked_sub(len).ok_or(KernelError::InvalidArgument)?;
        return Ok((new_start, start));
    };

    Ok((start, end))
}

// =============================================================================
// Public API
// =============================================================================

/// F_GETLK - test if lock would block
///
/// If the lock described by flock would be blocked, fills in flock with
/// information about the conflicting lock. Otherwise, sets l_type to F_UNLCK.
pub fn posix_getlk(file: &File, flock: &mut Flock) -> Result<(), KernelError> {
    let inode = file.get_inode().ok_or(KernelError::BadFd)?;
    let (start, end) = resolve_range(flock, file)?;
    let lock_type = PosixLockType::from_flock(flock.l_type).ok_or(KernelError::InvalidArgument)?;
    let pid = current_pid();

    let locks = POSIX_LOCKS.lock();
    let key = inode_key(&inode);

    if let Some(inode_locks) = locks.get(&key)
        && let Some(conflict) = inode_locks.find_conflict(start, end, lock_type, pid)
    {
        // Return info about conflicting lock
        flock.l_type = conflict.lock_type.to_flock();
        flock.l_whence = 0; // SEEK_SET
        flock.l_start = conflict.start as i64;
        flock.l_len = if conflict.end == u64::MAX {
            0
        } else {
            (conflict.end - conflict.start) as i64
        };
        flock.l_pid = conflict.owner as i32;
        return Ok(());
    }

    // No conflict - lock would succeed
    flock.l_type = F_UNLCK;
    Ok(())
}

/// F_SETLK - set/clear lock (non-blocking)
///
/// Attempts to acquire or release a lock. Returns EAGAIN if the lock
/// cannot be acquired due to a conflict.
pub fn posix_setlk(file: &File, flock: &Flock) -> Result<(), KernelError> {
    let inode = file.get_inode().ok_or(KernelError::BadFd)?;
    let (start, end) = resolve_range(flock, file)?;
    let pid = current_pid();
    let key = inode_key(&inode);

    let mut locks = POSIX_LOCKS.lock();

    if flock.l_type == F_UNLCK {
        // Unlock
        if let Some(inode_locks) = locks.get_mut(&key) {
            inode_locks.unlock_range(pid, start, end);
            if inode_locks.is_empty() {
                locks.remove(&key);
            }
        }
        Ok(())
    } else {
        // Lock
        let lock_type =
            PosixLockType::from_flock(flock.l_type).ok_or(KernelError::InvalidArgument)?;

        let inode_locks = locks.entry(key).or_default();
        inode_locks.try_lock(pid, start, end, lock_type)
    }
}

/// F_SETLKW - set/clear lock (blocking)
///
/// Like F_SETLK, but waits for the lock to become available.
/// Note: We don't implement actual blocking - returns EAGAIN like flock() does.
pub fn posix_setlkw(file: &File, flock: &Flock) -> Result<(), KernelError> {
    // For now, just call setlk - we don't implement actual blocking
    // A real implementation would sleep and retry
    posix_setlk(file, flock)
}

/// Release all POSIX locks held by current process on a file
///
/// Called when any fd to file is closed. POSIX semantics require
/// releasing ALL locks when ANY fd to the file is closed.
pub fn release_posix_locks_on_close(file: &File) {
    let inode = match file.get_inode() {
        Some(i) => i,
        None => return,
    };

    let pid = current_pid();
    let key = inode_key(&inode);

    let mut locks = POSIX_LOCKS.lock();
    if let Some(inode_locks) = locks.get_mut(&key) {
        inode_locks.remove_all_for_pid(pid);
        if inode_locks.is_empty() {
            locks.remove(&key);
        }
    }
}

/// Release all POSIX locks held by a process
///
/// Called during execve to release all locks (POSIX semantics).
pub fn release_all_posix_locks_for_pid(pid: u64) {
    let mut locks = POSIX_LOCKS.lock();
    locks.retain(|_, inode_locks| {
        inode_locks.remove_all_for_pid(pid);
        !inode_locks.is_empty()
    });
}
