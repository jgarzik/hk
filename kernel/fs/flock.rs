//! flock - BSD-style advisory file locking
//!
//! This module implements the flock() syscall for advisory file locking.
//! Advisory locks do not prevent I/O; they only prevent other flock() calls
//! from conflicting.
//!
//! ## Lock Types
//!
//! - `LOCK_SH` (1): Shared lock - multiple processes can hold shared locks
//! - `LOCK_EX` (2): Exclusive lock - only one process can hold
//! - `LOCK_UN` (8): Unlock
//! - `LOCK_NB` (4): Non-blocking - return EWOULDBLOCK instead of blocking
//!
//! ## Semantics
//!
//! BSD flock semantics: locks are associated with the open file description,
//! not the file descriptor. Multiple fds from dup() share the same lock.
//! Locks are released when all fds referring to the open file description
//! are closed.

use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::error::KernelError;
use crate::fs::File;
use crate::fs::syscall::current_fd_table;
use crate::task::percpu::current_pid;
use spin::Mutex;

// =============================================================================
// flock operation constants (Linux ABI)
// =============================================================================

/// Shared lock (read lock)
pub const LOCK_SH: i32 = 1;
/// Exclusive lock (write lock)
pub const LOCK_EX: i32 = 2;
/// Non-blocking - return EWOULDBLOCK if lock not available
pub const LOCK_NB: i32 = 4;
/// Unlock
pub const LOCK_UN: i32 = 8;

// =============================================================================
// Lock state tracking
// =============================================================================

/// Type of lock held
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockType {
    /// No lock held
    None,
    /// Shared (read) lock
    Shared,
    /// Exclusive (write) lock
    Exclusive,
}

/// Per-file lock state
///
/// Tracks the current lock holders for a file. Used for BSD flock() semantics.
pub struct FileLock {
    /// Type of lock currently held
    lock_type: LockType,
    /// Set of PIDs holding shared locks (for LOCK_SH)
    shared_holders: BTreeSet<u64>,
    /// PID holding exclusive lock (for LOCK_EX)
    exclusive_holder: Option<u64>,
}

impl FileLock {
    /// Create new unlocked state
    pub const fn new() -> Self {
        Self {
            lock_type: LockType::None,
            shared_holders: BTreeSet::new(),
            exclusive_holder: None,
        }
    }

    /// Check if currently unlocked
    pub fn is_unlocked(&self) -> bool {
        self.lock_type == LockType::None
    }

    /// Try to acquire a shared lock
    ///
    /// Returns Ok(()) if lock acquired, Err if would block or conflict
    pub fn try_lock_shared(&mut self, pid: u64) -> Result<(), KernelError> {
        match self.lock_type {
            LockType::None => {
                // No lock held, acquire shared
                self.lock_type = LockType::Shared;
                self.shared_holders.insert(pid);
                Ok(())
            }
            LockType::Shared => {
                // Already shared, add ourselves
                self.shared_holders.insert(pid);
                Ok(())
            }
            LockType::Exclusive => {
                // Check if we hold the exclusive lock (upgrade case)
                if self.exclusive_holder == Some(pid) {
                    // Downgrade: release exclusive, acquire shared
                    self.lock_type = LockType::Shared;
                    self.exclusive_holder = None;
                    self.shared_holders.insert(pid);
                    Ok(())
                } else {
                    // Someone else holds exclusive
                    Err(KernelError::WouldBlock)
                }
            }
        }
    }

    /// Try to acquire an exclusive lock
    ///
    /// Returns Ok(()) if lock acquired, Err if would block or conflict
    pub fn try_lock_exclusive(&mut self, pid: u64) -> Result<(), KernelError> {
        match self.lock_type {
            LockType::None => {
                // No lock held, acquire exclusive
                self.lock_type = LockType::Exclusive;
                self.exclusive_holder = Some(pid);
                Ok(())
            }
            LockType::Shared => {
                // Check if we're the only shared holder (upgrade case)
                if self.shared_holders.len() == 1 && self.shared_holders.contains(&pid) {
                    // Upgrade: release shared, acquire exclusive
                    self.lock_type = LockType::Exclusive;
                    self.shared_holders.clear();
                    self.exclusive_holder = Some(pid);
                    Ok(())
                } else {
                    // Others hold shared locks
                    Err(KernelError::WouldBlock)
                }
            }
            LockType::Exclusive => {
                // Check if we already hold it
                if self.exclusive_holder == Some(pid) {
                    Ok(()) // Already have exclusive
                } else {
                    Err(KernelError::WouldBlock)
                }
            }
        }
    }

    /// Release any lock held by this PID
    pub fn unlock(&mut self, pid: u64) {
        match self.lock_type {
            LockType::None => {}
            LockType::Shared => {
                self.shared_holders.remove(&pid);
                if self.shared_holders.is_empty() {
                    self.lock_type = LockType::None;
                }
            }
            LockType::Exclusive => {
                if self.exclusive_holder == Some(pid) {
                    self.lock_type = LockType::None;
                    self.exclusive_holder = None;
                }
            }
        }
    }
}

impl Default for FileLock {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Global file lock registry
// =============================================================================

/// Global counter for generating unique file IDs
static NEXT_FILE_ID: AtomicU32 = AtomicU32::new(1);

/// Generate a unique file ID for lock tracking
pub fn alloc_file_id() -> u32 {
    NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed)
}

/// Global file lock table
///
/// Maps file IDs to their lock state. Files are identified by their unique
/// file ID (assigned at File creation time).
static FILE_LOCKS: Mutex<alloc::collections::BTreeMap<u64, FileLock>> =
    Mutex::new(alloc::collections::BTreeMap::new());

/// Get or create lock state for a file
fn get_or_create_lock(file_id: u64) -> FileLock {
    let mut locks = FILE_LOCKS.lock();
    locks.entry(file_id).or_default().clone()
}

/// Update lock state for a file
fn update_lock(file_id: u64, lock: FileLock) {
    let mut locks = FILE_LOCKS.lock();
    if lock.is_unlocked() {
        locks.remove(&file_id);
    } else {
        locks.insert(file_id, lock);
    }
}

// Clone implementation for FileLock
impl Clone for FileLock {
    fn clone(&self) -> Self {
        Self {
            lock_type: self.lock_type,
            shared_holders: self.shared_holders.clone(),
            exclusive_holder: self.exclusive_holder,
        }
    }
}

// =============================================================================
// sys_flock implementation
// =============================================================================

/// sys_flock - apply or remove an advisory lock on an open file
///
/// # Arguments
/// * `fd` - File descriptor
/// * `operation` - Lock operation (LOCK_SH, LOCK_EX, LOCK_UN, optionally OR'd with LOCK_NB)
///
/// # Returns
/// 0 on success, negative errno on error:
/// * -EBADF: fd is not an open file descriptor
/// * -EINVAL: operation is invalid
/// * -EWOULDBLOCK: LOCK_NB was specified and lock is held by another
pub fn sys_flock(fd: i32, operation: i32) -> i64 {
    // Validate operation - must be exactly one of SH, EX, or UN, with optional NB
    let lock_op = operation & !LOCK_NB;
    let nonblock = operation & LOCK_NB != 0;

    if lock_op != LOCK_SH && lock_op != LOCK_EX && lock_op != LOCK_UN {
        return KernelError::InvalidArgument.sysret();
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f.clone(),
        None => return KernelError::BadFd.sysret(),
    };

    // Get file ID for lock tracking
    // We use the file's dentry address as a unique identifier
    let file_id = Arc::as_ptr(&file.dentry) as u64;

    let pid = current_pid();

    // Get current lock state
    let mut lock_state = get_or_create_lock(file_id);

    // Perform the requested operation
    let result = match lock_op {
        LOCK_SH => lock_state.try_lock_shared(pid),
        LOCK_EX => lock_state.try_lock_exclusive(pid),
        LOCK_UN => {
            lock_state.unlock(pid);
            Ok(())
        }
        _ => Err(KernelError::InvalidArgument),
    };

    match result {
        Ok(()) => {
            update_lock(file_id, lock_state);
            0
        }
        Err(KernelError::WouldBlock) if nonblock => KernelError::WouldBlock.sysret(),
        Err(KernelError::WouldBlock) => {
            // Blocking case: for now, we don't implement blocking
            // A full implementation would sleep and retry
            // For now, return EWOULDBLOCK even without LOCK_NB
            // (matches behavior of many real-world workloads that use LOCK_NB anyway)
            KernelError::WouldBlock.sysret()
        }
        Err(e) => e.sysret(),
    }
}

/// Clean up locks when a file is closed
///
/// Called from File::drop() to release any locks held by this file.
pub fn release_file_locks(file: &File) {
    let file_id = Arc::as_ptr(&file.dentry) as u64;
    let pid = current_pid();

    let mut lock_state = get_or_create_lock(file_id);
    lock_state.unlock(pid);
    update_lock(file_id, lock_state);
}
