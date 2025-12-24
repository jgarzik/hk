//! Per-task file descriptor table management
//!
//! This module manages per-task FD tables following the same pattern as
//! `fs/fsstruct.rs` for filesystem context. Each task has its own FD table,
//! which can be shared (CLONE_FILES) or copied (fork without CLONE_FILES).
//!
//! ## Design
//!
//! - `TASK_FD`: Global BTreeMap mapping TID to Arc<Mutex<FdTable>>
//! - Multiple tasks can share the same Arc when CLONE_FILES is used
//! - Fork without CLONE_FILES creates a deep copy of the FD table
//!
//! ## Locking
//!
//! Two levels of locking:
//! 1. `TASK_FD` mutex - protects the TID->FdTable mapping
//! 2. Per-table mutex - protects individual FD table operations
//!
//! Always acquire TASK_FD first, then the table mutex.

use alloc::sync::Arc;
use spin::Mutex;

use super::percpu::TASK_TABLE;
use super::{FdTable, Tid};
use crate::fs::File;

// =============================================================================
// Task FD accessors - uses Task.files field directly via TASK_TABLE
// =============================================================================

/// Initialize FD table for a new task
///
/// Called when creating the initial task or when a task needs a new FD table.
pub fn init_task_fd(tid: Tid, fd_table: Arc<Mutex<FdTable<File>>>) {
    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.files = Some(fd_table);
    }
}

/// Get the FD table for a task (returns cloned Arc)
///
/// Returns None if the task doesn't have an FD table registered.
pub fn get_task_fd(tid: Tid) -> Option<Arc<Mutex<FdTable<File>>>> {
    let table = TASK_TABLE.lock();
    table
        .tasks
        .iter()
        .find(|t| t.tid == tid)
        .and_then(|t| t.files.clone())
}

/// Remove FD table mapping when task exits
///
/// This decrements the Arc refcount. If this was the last reference
/// (no other tasks sharing this FD table), the table is dropped
/// and all file descriptors are closed.
pub fn exit_task_fd(tid: Tid) {
    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.files = None;
    }
}

/// Clone FD table for fork/clone
///
/// If `share` is true (CLONE_FILES set), the child shares the parent's FD table.
/// If `share` is false (normal fork), the child gets a deep copy.
///
/// # Arguments
/// * `parent_tid` - Parent task's TID
/// * `child_tid` - Child task's TID
/// * `share` - If true, share the same FD table (CLONE_FILES)
pub fn clone_task_fd(parent_tid: Tid, child_tid: Tid, share: bool) {
    let child_fd = if share {
        // CLONE_FILES: share the same Arc<Mutex<FdTable>>
        get_task_fd(parent_tid)
    } else {
        // Normal fork: deep copy the FD table
        get_task_fd(parent_tid).map(|fd_table| {
            let table = fd_table.lock();
            Arc::new(Mutex::new(table.deep_clone()))
        })
    };

    if let Some(fd) = child_fd {
        init_task_fd(child_tid, fd);
    } else {
        // Fallback: create new empty FD table
        init_task_fd(child_tid, Arc::new(Mutex::new(FdTable::new())));
    }
}

/// Create a new empty FD table
///
/// The init process is expected to open stdin/stdout/stderr itself
/// by opening /dev/console or similar.
pub fn create_empty_fd_table() -> Arc<Mutex<FdTable<File>>> {
    Arc::new(Mutex::new(FdTable::new()))
}
