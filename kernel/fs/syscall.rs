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

use crate::fs::{File, KernelError, LookupFlags, Path, lookup_path_at};
use crate::task::fdtable::get_task_fd;
use crate::task::percpu::current_tid;

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
/// Prevent SIGPIPE (no-op, we don't generate SIGPIPE on pipes yet)
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

/// AT_FDCWD - special value meaning current working directory
///
/// When passed as the dirfd argument to *at syscalls (openat, etc.),
/// indicates that relative paths should be resolved from the current
/// working directory.
pub const AT_FDCWD: i32 = -100;

/// Maximum path length for user strings
pub const PATH_MAX: usize = 4096;

/// Maximum single I/O transfer size (1MB)
pub const MAX_RW_COUNT: usize = 1024 * 1024;

/// Maximum number of iovec entries (Linux default)
pub const IOV_MAX: usize = 1024;

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
    let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_NOFILE);
    if limit == crate::rlimit::RLIM_INFINITY {
        u64::MAX
    } else {
        limit
    }
}

// =============================================================================
// RLIMIT_FSIZE enforcement helpers
// =============================================================================

/// Check RLIMIT_FSIZE before a write operation
///
/// If the write would exceed RLIMIT_FSIZE, sends SIGXFSZ and returns EFBIG.
/// Returns Ok(()) if the write is within limits.
///
/// # Arguments
/// * `offset` - Starting offset for the write
/// * `count` - Number of bytes to write
#[inline]
pub fn check_fsize_limit(offset: u64, count: usize) -> Result<(), i64> {
    let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_FSIZE);
    if limit == crate::rlimit::RLIM_INFINITY {
        return Ok(());
    }

    let final_size = offset.saturating_add(count as u64);
    if final_size > limit {
        // Send SIGXFSZ before returning error (per POSIX/Linux requirement)
        let tid = current_tid();
        crate::signal::send_signal(tid, crate::signal::SIGXFSZ);
        return Err(KernelError::FileTooLarge.sysret());
    }
    Ok(())
}

/// Get the current task's FD table
///
/// Panics if the current task doesn't have an FD table registered,
/// which would indicate a kernel bug.
pub fn current_fd_table() -> alloc::sync::Arc<spin::Mutex<crate::task::FdTable<File>>> {
    get_task_fd(current_tid()).expect("current task has no FD table")
}

/// Small buffer size for stack-based I/O (4KB)
pub const SMALL_BUF_SIZE: usize = 4096;

///
/// Returns the parent dentry and the final component name.
pub fn lookup_parent_at(
    dirfd: i32,
    path: &str,
) -> Result<(alloc::sync::Arc<super::Dentry>, alloc::string::String), i64> {
    // Find the last path component
    let path = path.trim_end_matches('/');
    if path.is_empty() {
        return Err(KernelError::InvalidArgument.sysret());
    }

    let (parent_path, name) = match path.rfind('/') {
        Some(pos) => {
            let parent = if pos == 0 { "/" } else { &path[..pos] };
            let name = &path[pos + 1..];
            (parent, name)
        }
        None => {
            // No slash - parent is current directory (or dirfd)
            (".", path)
        }
    };

    if name.is_empty() {
        return Err(KernelError::InvalidArgument.sysret());
    }

    // Determine starting path
    let start: Option<Path> = if parent_path.starts_with('/') {
        None
    } else if dirfd == AT_FDCWD {
        crate::task::percpu::current_cwd()
    } else {
        let file = match current_fd_table().lock().get(dirfd) {
            Some(f) => f,
            None => return Err(KernelError::BadFd.sysret()),
        };
        if !file.is_dir() {
            return Err(KernelError::NotDirectory.sysret());
        }
        Path::from_dentry(file.dentry.clone())
    };

    // Look up parent directory
    let parent_dentry = match lookup_path_at(start, parent_path, LookupFlags::opendir()) {
        Ok(d) => d,
        Err(KernelError::NotFound) => return Err(KernelError::NotFound.sysret()),
        Err(KernelError::NotDirectory) => return Err(KernelError::NotDirectory.sysret()),
        Err(KernelError::TooManySymlinks) => return Err(KernelError::TooManySymlinks.sysret()),
        Err(_) => return Err(KernelError::InvalidArgument.sysret()),
    };

    Ok((parent_dentry, alloc::string::String::from(name)))
}
