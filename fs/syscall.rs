//! VFS syscall implementations
//!
//! This module re-exports syscalls from their specific modules and provides
//! common helpers and constants used by multiple syscall modules.
//!
//! All syscalls that access user memory use the uaccess primitives from
//! crate::uaccess to ensure proper validation and SMAP protection.

// Re-export syscalls from submodules
pub use super::dir::*;
pub use super::fd::*;
pub use super::io::*;
pub use super::iov::*;
pub use super::link::*;
pub use super::misc::*;
pub use super::nav::*;
pub use super::open::*;
pub use super::perm::*;
pub use super::pollsys::*;
pub use super::stat::*;
pub use super::sync::*;

use crate::task::fdtable::get_task_fd;
use crate::task::percpu::current_tid;
use crate::util::error::KernelError;

// =============================================================================
// RWF flags for preadv2/pwritev2
// =============================================================================

/// High priority request (hint, accepted but no-op)
pub const RWF_HIPRI: i32 = 0x00000001;
/// Per-IO O_DSYNC - sync data after write
pub const RWF_DSYNC: i32 = 0x00000002;
/// Per-IO O_SYNC - full sync after write
pub const RWF_SYNC: i32 = 0x00000004;
/// Return EAGAIN if operation would block
pub const RWF_NOWAIT: i32 = 0x00000008;
/// Per-IO O_APPEND - append to file
pub const RWF_APPEND: i32 = 0x00000010;
/// Negate O_APPEND (no-op in our implementation)
pub const RWF_NOAPPEND: i32 = 0x00000020;
/// Atomic write (not supported)
pub const RWF_ATOMIC: i32 = 0x00000040;
/// Drop cache after I/O (not supported)
pub const RWF_DONTCACHE: i32 = 0x00000080;
/// Prevent SIGPIPE generation on pipe/socket write errors
pub const RWF_NOSIGNAL: i32 = 0x00000100;
/// Mask of all supported RWF flags
pub const RWF_SUPPORTED: i32 = RWF_HIPRI
    | RWF_DSYNC
    | RWF_SYNC
    | RWF_NOWAIT
    | RWF_APPEND
    | RWF_NOAPPEND
    | RWF_ATOMIC
    | RWF_DONTCACHE
    | RWF_NOSIGNAL;

/// Maximum path length for user strings
pub const PATH_MAX: usize = 4096;

/// Largest single read/write transfer (Linux MAX_RW_COUNT = INT_MAX & PAGE_MASK);
/// file types copy straight between their data and the caller (`fs::iov_iter`)
pub const MAX_RW_COUNT: usize = 0x7fff_f000;

/// Maximum number of iovec entries (Linux default)
pub const IOV_MAX: usize = 1024;

/// The error of a failed descriptor-table operation (its errno: EMFILE,
/// EBADF, ENOMEM)
pub fn fd_err(e: i32) -> KernelError {
    KernelError::from_errno(e).unwrap_or(KernelError::Io)
}

// =============================================================================
// RLIMIT_NOFILE enforcement helpers
// =============================================================================

/// Get the RLIMIT_NOFILE limit for the current task.
///
/// Returns the soft limit, or u64::MAX if the limit is RLIM_INFINITY.
/// This value is passed to fd allocation functions which enforce the limit.
///
/// Following Linux pattern: RLIMIT_NOFILE is enforced inside fd allocation
/// functions (alloc, alloc_with_flags, etc.), not as separate pre-checks.
#[inline]
pub fn get_nofile_limit() -> u64 {
    let limit = crate::task::rlimit::rlimit(crate::task::rlimit::RLIMIT_NOFILE);
    if limit == crate::task::rlimit::RLIM_INFINITY {
        u64::MAX
    } else {
        limit
    }
}

/// Get the current task's FD table
///
/// Panics if the current task doesn't have an FD table registered,
/// which would indicate a kernel bug.
pub fn current_fd_table() -> alloc::sync::Arc<crate::task::fdtable::Files> {
    get_task_fd(current_tid()).expect("current task has no FD table")
}
