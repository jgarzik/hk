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

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fs::file::seek;
use crate::fs::{File, Inode};
use crate::task::percpu::current_pid;
use crate::util::error::KernelError;

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
    /// Explicit padding (always zero; avoids leaking kernel bytes)
    pub _pad0: u32,
    /// Starting offset of the lock
    pub l_start: i64,
    /// Length of the lock (0 = to EOF)
    pub l_len: i64,
    /// PID of lock owner (filled in by F_GETLK)
    pub l_pid: i32,
    /// Explicit tail padding (always zero)
    pub _pad1: u32,
}

const _: () = assert!(core::mem::size_of::<Flock>() == 32);

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
    /// Owner: the holder's descriptor table (Linux fl_owner, the
    /// files_struct; see `current_owner`)
    pub owner: u64,
    /// Process that set it (Linux fl_pid: F_GETLK's l_pid)
    pub pid: u64,
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
pub struct InodeLocks {
    locks: Vec<PosixLock>,
}

impl InodeLocks {
    /// Find a conflicting lock for F_GETLK
    fn find_conflict(
        &self,
        start: u64,
        end: u64,
        lock_type: PosixLockType,
        owner: u64,
    ) -> Option<&PosixLock> {
        self.locks
            .iter()
            .find(|lock| lock.overlaps(start, end) && lock.conflicts_with(lock_type, owner))
    }

    /// Try to set a lock (F_SETLK)
    fn try_lock(
        &mut self,
        (owner, pid): (u64, u64),
        start: u64,
        end: u64,
        lock_type: PosixLockType,
    ) -> Result<(), KernelError> {
        // Check for conflicts
        if self.find_conflict(start, end, lock_type, owner).is_some() {
            return Err(KernelError::WouldBlock);
        }
        // Already held as asked: nothing changes, the lock keeps its
        // pid (Linux posix_lock_inode)
        if self.locks.iter().any(|l| {
            l.owner == owner && l.lock_type == lock_type && l.start <= start && l.end >= end
        }) {
            return Ok(());
        }

        // Remove overlapping locks from same owner (they'll be replaced/merged)
        self.unlock_range(owner, start, end);

        // Add new lock
        self.locks.push(PosixLock {
            owner,
            pid,
            start,
            end,
            lock_type,
        });

        // Coalesce adjacent locks of same type from same owner
        self.coalesce_locks(owner);

        Ok(())
    }

    /// Unlock a range - may split existing locks
    fn unlock_range(&mut self, owner: u64, start: u64, end: u64) {
        let mut new_locks = Vec::new();

        for lock in self.locks.drain(..) {
            if lock.owner != owner {
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
                    pid: lock.pid,
                    start: lock.start,
                    end: start,
                    lock_type: lock.lock_type,
                });
                // Right part
                new_locks.push(PosixLock {
                    owner: lock.owner,
                    pid: lock.pid,
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
                    pid: lock.pid,
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
                    pid: lock.pid,
                    start: lock.start,
                    end: start,
                    lock_type: lock.lock_type,
                });
            }
        }

        self.locks = new_locks;
    }

    /// Drop every lock of `owner`: whether it had any
    fn remove_all_for_owner(&mut self, pid: u64) -> bool {
        let n = self.locks.len();
        self.locks.retain(|l| l.owner != pid);
        self.locks.len() != n
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
}

// =============================================================================
// Global Lock Registry
// =============================================================================

// =============================================================================
// Range Resolution
// =============================================================================

/// Resolve flock start/len to absolute byte range
///
/// Returns (start, end) where end is exclusive. EOF is represented as u64::MAX.
fn resolve_range(flock: &Flock, file: &File) -> Result<(u64, u64), KernelError> {
    let inode = file.get_inode().ok_or(KernelError::BadFd)?;
    let base = match i32::from(flock.l_whence) {
        seek::SEEK_SET => 0i64,
        seek::SEEK_CUR => file.get_pos() as i64,
        seek::SEEK_END => inode.get_size() as i64,
        _ => return Err(KernelError::InvalidArgument),
    };
    lock_range(base, flock.l_start, flock.l_len)
}

/// The byte range [start, end) of a lock at `base + l_start` of
/// `l_len` bytes (Linux flock64_to_posix_lock, whose end is inclusive
/// and OFFSET_MAX = LLONG_MAX means "to EOF"; here end is exclusive and
/// u64::MAX means EOF): past OFFSET_MAX is EOVERFLOW, below 0 EINVAL
fn lock_range(base: i64, l_start: i64, l_len: i64) -> Result<(u64, u64), KernelError> {
    const OFFSET_MAX: i64 = i64::MAX;
    if l_start > OFFSET_MAX - base {
        return Err(KernelError::Overflow);
    }
    // base >= 0: no overflow below
    let start = base + l_start;
    if start < 0 {
        return Err(KernelError::InvalidArgument);
    }
    match l_len {
        0 => Ok((start as u64, u64::MAX)),
        len if len > 0 => {
            if len - 1 > OFFSET_MAX - start {
                return Err(KernelError::Overflow);
            }
            // Last byte start + len - 1; ending at OFFSET_MAX is "to EOF"
            let last = start + (len - 1);
            let end = if last == OFFSET_MAX {
                u64::MAX
            } else {
                last as u64 + 1
            };
            Ok((start as u64, end))
        }
        len => {
            // Bytes before start (start >= 0 and len < 0: no overflow)
            if start + len < 0 {
                return Err(KernelError::InvalidArgument);
            }
            Ok(((start + len) as u64, start as u64))
        }
    }
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
    let owner = current_owner();
    let conflict = inode.i_flctx.with(|l| {
        let c = l.posix.find_conflict(start, end, lock_type, owner).cloned();
        (c, false)
    });
    match conflict {
        Some(c) => {
            flock.l_type = c.lock_type.to_flock();
            flock.l_whence = 0; // SEEK_SET
            flock.l_start = c.start as i64;
            flock.l_len = if c.end == u64::MAX {
                0
            } else {
                (c.end - c.start) as i64
            };
            flock.l_pid = c.pid as i32;
        }
        None => flock.l_type = F_UNLCK,
    }
    Ok(())
}

/// Set (or with F_UNLCK clear) the caller's lock on [start, end) of
/// `inode`: Err(WouldBlock) on a conflict, with its owner
fn set(
    inode: &Arc<Inode>,
    (start, end): (u64, u64),
    l_type: i16,
) -> Result<(), (KernelError, Option<u64>)> {
    let owner = current_owner();
    if l_type == F_UNLCK {
        inode.i_flctx.with(|l| {
            l.posix.unlock_range(owner, start, end);
            ((), true)
        });
        return Ok(());
    }
    let lock_type =
        PosixLockType::from_flock(l_type).ok_or((KernelError::InvalidArgument, None))?;
    let pid = current_pid();
    inode.i_flctx.with(|l| {
        let r = l
            .posix
            .try_lock((owner, pid), start, end, lock_type)
            .map_err(|e| {
                let blocker = l
                    .posix
                    .find_conflict(start, end, lock_type, owner)
                    .map(|c| c.owner);
                (e, blocker)
            });
        // A lock set may replace or split one of ours, releasing a
        // range; a refused one changed nothing (counting it would wake
        // the other waiters into a retry loop)
        let changed = r.is_ok();
        (r, changed)
    })
}

/// F_SETLK - set/clear lock (non-blocking): the absolute range it
/// covered
///
/// Attempts to acquire or release a lock. Returns EAGAIN if the lock
/// cannot be acquired due to a conflict.
pub fn posix_setlk(file: &File, flock: &Flock) -> Result<(u64, u64), KernelError> {
    let inode = file.get_inode().ok_or(KernelError::BadFd)?;
    let range = resolve_range(flock, file)?;
    set(&inode, range, flock.l_type).map_err(|(e, _)| e)?;
    Ok(range)
}

/// Unlock the current process's locks on `file` over `[start, end)`,
/// a range already resolved (Linux fcntl_setlk's F_UNLCK retry reuses
/// the resolved file_lock: offset or size changes don't move it)
pub fn posix_unlock(file: &File, range: (u64, u64)) {
    if let Some(inode) = file.get_inode() {
        let _ = set(&inode, range, F_UNLCK);
    }
}

/// F_SETLKW - set/clear lock, waiting while it conflicts (Linux
/// fcntl_setlk with F_SETLKW: locks_insert_block, posix_locks_deadlock):
/// EDEADLK if the owner it would wait on waits, through a chain, on the
/// caller; EINTR if a signal ends the wait
pub fn posix_setlkw(file: &File, flock: &Flock) -> Result<(u64, u64), KernelError> {
    let inode = file.get_inode().ok_or(KernelError::BadFd)?;
    let range = resolve_range(flock, file)?;
    let me = current_owner();
    loop {
        let g = inode.i_flctx.generation();
        match set(&inode, range, flock.l_type) {
            Ok(()) => return Ok(range),
            Err((KernelError::WouldBlock, Some(blocker))) => {
                super::locks::block_on(me, blocker)?;
                let r = inode.i_flctx.wait_change(g);
                super::locks::unblock(me);
                r?;
            }
            Err((e, _)) => return Err(e),
        }
    }
}

/// The lock owner of the current task: its descriptor table (Linux
/// fl_owner = current->files), shared by CLONE_FILES; a task without
/// one (kernel threads) is owned by its pid, kept apart by the top bit
pub fn current_owner() -> u64 {
    match crate::task::percpu::current().files() {
        Some(f) => f.id(),
        None => current_pid() | 1 << 63,
    }
}

/// A descriptor of `file` in the table `owner` was closed: every POSIX
/// lock `owner` holds on the inode goes (Linux locks_remove_posix with
/// the closer's files_struct), whichever descriptor took it
pub fn release_posix_locks_on_close(file: &File, owner: u64) {
    if let Some(inode) = file.get_inode() {
        inode
            .i_flctx
            .with(|l| ((), l.posix.remove_all_for_owner(owner)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_ranges() {
        let r = lock_range;
        assert_eq!(r(0, 10, 5), Ok((10, 15)));
        assert_eq!(r(0, 10, 0), Ok((10, u64::MAX)));
        assert_eq!(r(0, 10, -4), Ok((6, 10)));
        // Negative lengths and starts below 0
        assert_eq!(r(0, 3, -4), Err(KernelError::InvalidArgument));
        assert_eq!(r(0, 3, i64::MIN), Err(KernelError::InvalidArgument));
        assert_eq!(r(0, -1, 1), Err(KernelError::InvalidArgument));
        assert_eq!(r(100, -50, 0), Ok((50, u64::MAX)));
        // Past OFFSET_MAX
        assert_eq!(r(1, i64::MAX, 1), Err(KernelError::Overflow));
        assert_eq!(r(0, i64::MAX, 2), Err(KernelError::Overflow));
        assert_eq!(r(0, 2, i64::MAX), Err(KernelError::Overflow));
        assert_eq!(r(0, 1, i64::MAX), Ok((1, u64::MAX)));
        // Ending exactly at OFFSET_MAX is the same as "to EOF"
        assert_eq!(r(0, i64::MAX, 1), Ok((i64::MAX as u64, u64::MAX)));
    }
}
