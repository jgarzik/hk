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

use crate::error::KernelError;
use crate::fs::File;
use crate::fs::syscall::current_fd_table;

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

    /// Release any lock held by this owner: whether it held one
    pub fn unlock(&mut self, pid: u64) -> bool {
        match self.lock_type {
            LockType::None => false,
            LockType::Shared => {
                let held = self.shared_holders.remove(&pid);
                if self.shared_holders.is_empty() {
                    self.lock_type = LockType::None;
                }
                held
            }
            LockType::Exclusive => {
                if self.exclusive_holder == Some(pid) {
                    self.lock_type = LockType::None;
                    self.exclusive_holder = None;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// The lock this owner holds
    pub fn held(&self, pid: u64) -> LockType {
        match self.lock_type {
            LockType::Shared if self.shared_holders.contains(&pid) => LockType::Shared,
            LockType::Exclusive if self.exclusive_holder == Some(pid) => LockType::Exclusive,
            _ => LockType::None,
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

/// Run `f` on the flock state of `file`'s inode (Linux i_flctx
/// flc_flock), so every name and every open of a file share it; `f`
/// says whether it released a lock (waking blocked lockers). A file
/// with no inode has nothing to lock.
fn with_lock<R>(
    file: &File,
    f: impl FnOnce(&mut FileLock) -> (Result<R, KernelError>, bool),
) -> Result<R, KernelError> {
    let Some(inode) = file.get_inode() else {
        return f(&mut FileLock::new()).0;
    };
    inode.i_flctx.with(|l| f(&mut l.flock))
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

    // flock locks belong to the open file description (Linux fl_file):
    // every descriptor of it, in any process, holds the same lock
    let owner = Arc::as_ptr(&file) as u64;
    let ctx = file.get_inode();

    // Linux flock_lock_inode: a lock of the other type the owner holds
    // goes first (a conversion is not atomic, even with LOCK_NB: two
    // upgraders never wait on each other's shared locks, and a
    // downgrade wakes the shared waiters); then retried after each
    // change of the inode's locks while it conflicts, unless LOCK_NB.
    // A signal ends the wait (ERESTARTSYS: restarted under SA_RESTART).
    let want = match lock_op {
        LOCK_SH => LockType::Shared,
        LOCK_EX => LockType::Exclusive,
        _ => LockType::None,
    };
    loop {
        let g = ctx.as_ref().map_or(0, |i| i.i_flctx.generation());
        let result = with_lock(&file, |l| {
            let held = l.held(owner);
            if held == want && want != LockType::None {
                return (Ok(()), false);
            }
            let dropped = held != LockType::None && l.unlock(owner);
            let r = match want {
                LockType::Shared => l.try_lock_shared(owner),
                LockType::Exclusive => l.try_lock_exclusive(owner),
                LockType::None => Ok(()),
            };
            (r, dropped)
        });
        match (result, &ctx) {
            (Ok(()), _) => return 0,
            (Err(KernelError::WouldBlock), Some(i)) if !nonblock => {
                if let Err(e) = i.i_flctx.wait_change(g) {
                    return e.sysret();
                }
            }
            (Err(e), _) => return e.sysret(),
        }
    }
}

/// The open file description `file` is gone (File::drop, its last
/// reference): its flock locks go (Linux locks_remove_file)
pub fn release_file_locks(file: &File) {
    let owner = file as *const File as u64;
    let _ = with_lock(file, |l| {
        let held = l.unlock(owner);
        (Ok(()), held)
    });
}
