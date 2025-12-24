//! VFS syscall implementations
//!
//! Implements file-related syscalls (open, read, close, getdents64).
//!
//! All syscalls that access user memory use the uaccess primitives from
//! crate::uaccess to ensure proper validation and SMAP protection.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;

use crate::arch::Uaccess;
use crate::console::console_write;
use crate::fs::{
    Dentry, File, FsError, InodeMode, LinuxStatFs, LookupFlags, Path, RAMFS_FILE_OPS, RwFlags,
    is_subdir, lock_rename, lookup_path_at, lookup_path_flags, unlock_rename,
};
use crate::uaccess::{UaccessArch, copy_to_user, put_user, strncpy_from_user};

use crate::storage::get_blkdev;
use crate::task::fdtable::get_task_fd;
use crate::task::percpu::current_tid;

/// Error numbers (negated for return)
pub const ENOENT: i64 = -2;
pub const ENXIO: i64 = -6;
pub const EBADF: i64 = -9;
pub const EAGAIN: i64 = -11;
pub const ENOMEM: i64 = -12;
pub const EFAULT: i64 = -14;
pub const ENOTDIR: i64 = -20;
pub const EISDIR: i64 = -21;
pub const EINVAL: i64 = -22;
pub const EMFILE: i64 = -24;
pub const ENOTTY: i64 = -25;
pub const EFBIG: i64 = -27;
pub const ESPIPE: i64 = -29;
pub const EPIPE: i64 = -32;
pub const ENOTEMPTY: i64 = -39;
pub const EOPNOTSUPP: i64 = -95;

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
const PATH_MAX: usize = 4096;

/// Maximum single I/O transfer size (1MB)
const MAX_RW_COUNT: usize = 1024 * 1024;

/// Maximum number of iovec entries (Linux default)
const IOV_MAX: usize = 1024;

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
fn get_nofile_limit() -> u64 {
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
fn check_fsize_limit(offset: u64, count: usize) -> Result<(), i64> {
    let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_FSIZE);
    if limit == crate::rlimit::RLIM_INFINITY {
        return Ok(());
    }

    let final_size = offset.saturating_add(count as u64);
    if final_size > limit {
        // Send SIGXFSZ before returning error (per POSIX/Linux requirement)
        let tid = current_tid();
        crate::signal::send_signal(tid, crate::signal::SIGXFSZ);
        return Err(EFBIG);
    }
    Ok(())
}

/// Get the current task's FD table
///
/// Panics if the current task doesn't have an FD table registered,
/// which would indicate a kernel bug.
fn current_fd_table() -> alloc::sync::Arc<spin::Mutex<crate::task::FdTable<File>>> {
    get_task_fd(current_tid()).expect("current task has no FD table")
}

/// Linux iovec structure for scatter/gather I/O
///
/// Used by readv/writev syscalls to specify multiple buffers
/// in a single system call.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct IoVec {
    /// Base address of the buffer (void* in userspace)
    pub iov_base: u64,
    /// Length of the buffer in bytes (size_t)
    pub iov_len: u64,
}

/// Create a file at the given path with the specified mode
///
/// Helper function for O_CREAT handling in sys_openat.
///
/// # Arguments
/// * `start` - Starting point for relative path resolution
/// * `path` - Full path string
/// * `mode` - File mode (permission bits)
///
/// # Returns
/// The dentry of the created file on success
fn create_file_at(start: Option<Path>, path: &str, mode: u32) -> Result<Arc<Dentry>, FsError> {
    // Find the last path component
    let path = path.trim_end_matches('/');
    if path.is_empty() {
        return Err(FsError::InvalidArgument);
    }

    let (parent_path, name) = match path.rfind('/') {
        Some(pos) => {
            let parent = if pos == 0 { "/" } else { &path[..pos] };
            let name = &path[pos + 1..];
            (parent, name)
        }
        None => {
            // Relative path with no slash - parent is start or root
            (".", path)
        }
    };

    if name.is_empty() {
        return Err(FsError::InvalidArgument);
    }

    // Look up the parent directory
    let parent_dentry = if parent_path == "." {
        // Use start or root
        start
            .map(|p| p.dentry.clone())
            .or_else(|| crate::fs::mount::current_mnt_ns().get_root_dentry())
            .ok_or(FsError::NotFound)?
    } else {
        lookup_path_at(start, parent_path, LookupFlags::opendir())?
    };

    let parent_inode = parent_dentry.get_inode().ok_or(FsError::NotFound)?;
    if !parent_inode.mode().is_dir() {
        return Err(FsError::NotADirectory);
    }

    // Lock parent directory (Linux i_rwsem pattern)
    parent_inode.inode_lock();

    // Check if file already exists (with lock held)
    if parent_dentry.lookup_child(name).is_some() {
        unsafe { parent_inode.inode_unlock() };
        return Err(FsError::AlreadyExists);
    }

    // Create the file with requested permission bits
    let file_mode = InodeMode::regular((mode & 0o7777) as u16);
    let new_inode = match parent_inode.i_op.create(&parent_inode, name, file_mode) {
        Ok(i) => i,
        Err(e) => {
            unsafe { parent_inode.inode_unlock() };
            return Err(e);
        }
    };

    // Create the dentry
    let new_dentry = Arc::new(Dentry::new(
        String::from(name),
        Some(new_inode),
        parent_dentry.sb.clone(),
    ));
    new_dentry.set_parent(&parent_dentry);
    parent_dentry.add_child(new_dentry.clone());

    // Unlock parent directory
    unsafe { parent_inode.inode_unlock() };

    Ok(new_dentry)
}

/// sys_open - open a file
///
/// Returns a file descriptor on success, negative errno on error.
/// This is a wrapper around sys_openat with AT_FDCWD.
pub fn sys_open(path_ptr: u64, flags: u32, mode: u32) -> i64 {
    sys_openat(AT_FDCWD, path_ptr, flags, mode)
}

/// sys_openat - open a file relative to a directory file descriptor
///
/// # Arguments
/// * `dirfd` - Directory file descriptor, or AT_FDCWD for current directory
/// * `path_ptr` - User pointer to path string
/// * `flags` - Open flags (O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, etc.)
/// * `mode` - File mode for O_CREAT (permission bits)
///
/// # Returns
/// File descriptor on success, negative errno on error.
pub fn sys_openat(dirfd: i32, path_ptr: u64, flags: u32, mode: u32) -> i64 {
    // Read path from user space with proper validation
    let path_str = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    // Determine starting path for relative paths
    let start: Option<Path> = if path_str.starts_with('/') {
        // Absolute path - lookup_path_at will use root
        None
    } else if dirfd == AT_FDCWD {
        // Use current working directory
        crate::task::percpu::current_cwd()
    } else {
        // Use directory from file descriptor
        let file = match current_fd_table().lock().get(dirfd) {
            Some(f) => f,
            None => return EBADF,
        };
        if !file.is_dir() {
            return ENOTDIR;
        }
        // Create Path from the file's dentry
        Path::from_dentry(file.dentry.clone())
    };

    // Set up lookup flags based on open flags
    let mut lookup_flags = LookupFlags::open();
    if flags & super::flags::O_DIRECTORY != 0 {
        lookup_flags.directory = true;
    }
    if flags & super::flags::O_NOFOLLOW != 0 {
        lookup_flags.follow = false;
    }

    // Look up the path
    let dentry = match lookup_path_at(start.clone(), &path_str, lookup_flags) {
        Ok(d) => {
            // File exists - check for O_EXCL
            if flags & super::flags::O_CREAT != 0 && flags & super::flags::O_EXCL != 0 {
                return EEXIST;
            }
            d
        }
        Err(FsError::NotFound) => {
            // File doesn't exist - try to create if O_CREAT is set
            if flags & super::flags::O_CREAT == 0 {
                return ENOENT;
            }
            // Create the file
            match create_file_at(start, &path_str, mode) {
                Ok(d) => d,
                Err(FsError::NotFound) => return ENOENT,
                Err(FsError::NotADirectory) => return ENOTDIR,
                Err(FsError::AlreadyExists) => return EEXIST,
                Err(FsError::PermissionDenied) => return EACCES,
                Err(_) => return EINVAL,
            }
        }
        Err(FsError::NotADirectory) => return ENOTDIR,
        Err(_) => return EINVAL,
    };

    // Check if trying to open directory without O_DIRECTORY when reading
    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    // Handle O_TRUNC - truncate file to zero length
    if flags & super::flags::O_TRUNC != 0 && !inode.mode().is_dir() {
        inode.i_op.truncate(&inode, 0).ok();
    }

    // Get the file operations based on inode type
    let f_op: &'static dyn super::FileOps = if inode.mode().is_blkdev() {
        // Block device - use block file operations
        &super::BLOCK_FILE_OPS
    } else if inode.mode().is_chrdev() {
        // Character device - use character device file operations
        &super::CHAR_FILE_OPS
    } else {
        // Regular file/directory - use filesystem operations
        dentry
            .superblock()
            .map(|sb| sb.fs_type.file_ops)
            .unwrap_or(&RAMFS_FILE_OPS)
    };

    // Create file object
    let file = Arc::new(File::new(dentry, flags, f_op));

    // Allocate file descriptor (RLIMIT_NOFILE enforced inside alloc)
    let fd_table = current_fd_table();
    let mut table = fd_table.lock();

    match table.alloc(file, get_nofile_limit()) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// sys_chdir - change working directory
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
///
/// # Returns
/// 0 on success, negative errno on error.
pub fn sys_chdir(path_ptr: u64) -> i64 {
    // Read path from user space
    let path_str = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    // Get current task's cwd as starting point for relative paths
    let start = crate::task::percpu::current_cwd();

    // Look up the path (must be a directory)
    let dentry = match lookup_path_at(start, &path_str, LookupFlags::opendir()) {
        Ok(d) => d,
        Err(FsError::NotFound) => return ENOENT,
        Err(FsError::NotADirectory) => return ENOTDIR,
        Err(_) => return EINVAL,
    };

    // Verify it's a directory
    if let Some(inode) = dentry.get_inode() {
        if !inode.mode().is_dir() {
            return ENOTDIR;
        }
    } else {
        return ENOENT;
    }

    // Create new Path and update FsStruct
    if let Some(fs) = crate::task::percpu::current_fs()
        && let Some(new_pwd) = Path::from_dentry(dentry)
    {
        fs.set_pwd(new_pwd);
    }

    0
}

/// sys_fchdir - change working directory via file descriptor
///
/// # Arguments
/// * `fd` - File descriptor of a directory
///
/// # Returns
/// 0 on success, negative errno on error.
pub fn sys_fchdir(fd: i32) -> i64 {
    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Must be a directory
    if !file.is_dir() {
        return ENOTDIR;
    }

    // Create new Path and update FsStruct
    if let Some(fs) = crate::task::percpu::current_fs()
        && let Some(new_pwd) = Path::from_dentry(file.dentry.clone())
    {
        fs.set_pwd(new_pwd);
    }

    0
}

/// ERANGE - buffer too small
const ERANGE: i64 = -34;

/// sys_getcwd - get current working directory
///
/// Returns the absolute pathname of the current working directory.
///
/// # Arguments
/// * `buf` - User buffer to store the pathname
/// * `size` - Size of the buffer
///
/// # Returns
/// Length of the pathname (including null terminator) on success,
/// negative errno on error:
/// - EFAULT: Invalid buffer address
/// - ENOENT: Current directory doesn't exist
/// - ERANGE: Buffer too small for pathname
pub fn sys_getcwd(buf: u64, size: u64) -> i64 {
    // Get current task's filesystem context
    let fs = match crate::task::percpu::current_fs() {
        Some(fs) => fs,
        None => return ENOENT,
    };

    // Get pwd and build path string
    let pwd = fs.get_pwd();
    let path_str = pwd.dentry.full_path();

    // Need space for path + null terminator
    let path_len = path_str.len() + 1;

    // Check buffer size
    if size < path_len as u64 {
        return ERANGE;
    }

    // Validate user buffer address
    if !Uaccess::access_ok(buf, path_len) {
        return EFAULT;
    }

    // Copy path to user buffer (with null terminator)
    let mut path_bytes = path_str.into_bytes();
    path_bytes.push(0); // null terminator

    if copy_to_user::<Uaccess>(buf, &path_bytes).is_err() {
        return EFAULT;
    }

    path_len as i64
}

/// Small buffer size for stack-based I/O (4KB)
const SMALL_BUF_SIZE: usize = 4096;

/// sys_read - read from a file descriptor
///
/// Returns number of bytes read, 0 on EOF, negative errno on error.
pub fn sys_read(fd: i32, buf_ptr: u64, count: u64) -> i64 {
    // Limit count to prevent allocation failure
    let count = core::cmp::min(count as usize, MAX_RW_COUNT);

    // Validate user buffer address
    if !Uaccess::access_ok(buf_ptr, count) {
        return EFAULT;
    }

    // Handle special fds (stdin)
    if fd == 0 {
        // stdin - not implemented yet
        return 0;
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Check if trying to read a directory
    if file.is_dir() {
        return EISDIR;
    }

    // Use stack buffer for small reads to avoid heap allocation
    if count <= SMALL_BUF_SIZE {
        let mut stack_buf = [0u8; SMALL_BUF_SIZE];
        let read_buf = &mut stack_buf[..count];

        // Perform read into stack buffer
        let bytes_read = match file.read(read_buf) {
            Ok(n) => n,
            Err(FsError::IsADirectory) => return EISDIR,
            Err(FsError::PermissionDenied) => return EBADF,
            Err(_) => return EINVAL,
        };

        // Copy from kernel buffer to user space
        if bytes_read > 0 && copy_to_user::<Uaccess>(buf_ptr, &read_buf[..bytes_read]).is_err() {
            return EFAULT;
        }

        bytes_read as i64
    } else {
        // Allocate a kernel buffer for large reads
        let mut kernel_buf = vec![0u8; count];

        // Perform read into kernel buffer
        let bytes_read = match file.read(&mut kernel_buf) {
            Ok(n) => n,
            Err(FsError::IsADirectory) => return EISDIR,
            Err(FsError::PermissionDenied) => return EBADF,
            Err(_) => return EINVAL,
        };

        // Copy from kernel buffer to user space
        if bytes_read > 0 && copy_to_user::<Uaccess>(buf_ptr, &kernel_buf[..bytes_read]).is_err() {
            return EFAULT;
        }

        bytes_read as i64
    }
}

/// sys_write - write to a file descriptor
///
/// Returns number of bytes written, negative errno on error.
pub fn sys_write(fd: i32, buf_ptr: u64, count: u64) -> i64 {
    // Limit count to prevent allocation failure
    let count = core::cmp::min(count as usize, MAX_RW_COUNT);

    // Validate user buffer address
    if !Uaccess::access_ok(buf_ptr, count) {
        return EFAULT;
    }

    // Handle special fds (stdout, stderr) - no RLIMIT_FSIZE check needed
    if fd == 1 || fd == 2 {
        // Use stack buffer for small writes
        if count <= SMALL_BUF_SIZE {
            let mut stack_buf = [0u8; SMALL_BUF_SIZE];
            let write_buf = &mut stack_buf[..count];
            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(buf_ptr as *const u8, write_buf.as_mut_ptr(), count);
                Uaccess::user_access_end();
            }
            console_write(write_buf);
        } else {
            let mut kernel_buf = vec![0u8; count];
            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(
                    buf_ptr as *const u8,
                    kernel_buf.as_mut_ptr(),
                    count,
                );
                Uaccess::user_access_end();
            }
            console_write(&kernel_buf);
        }
        return count as i64;
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Check RLIMIT_FSIZE for regular files (files with inodes)
    // Pipes and special files don't have size limits
    if file.get_inode().is_some()
        && let Err(e) = check_fsize_limit(file.get_pos(), count)
    {
        return e;
    }

    // Use stack buffer for small writes to avoid heap allocation
    if count <= SMALL_BUF_SIZE {
        let mut stack_buf = [0u8; SMALL_BUF_SIZE];
        let write_buf = &mut stack_buf[..count];

        // Copy from user space to kernel buffer
        unsafe {
            Uaccess::user_access_begin();
            core::ptr::copy_nonoverlapping(buf_ptr as *const u8, write_buf.as_mut_ptr(), count);
            Uaccess::user_access_end();
        }

        // Perform write
        match file.write(write_buf) {
            Ok(n) => n as i64,
            Err(FsError::PermissionDenied) => EBADF,
            Err(_) => EINVAL,
        }
    } else {
        // Allocate a kernel buffer for large writes
        let mut kernel_buf = vec![0u8; count];

        // Copy from user space to kernel buffer
        unsafe {
            Uaccess::user_access_begin();
            core::ptr::copy_nonoverlapping(buf_ptr as *const u8, kernel_buf.as_mut_ptr(), count);
            Uaccess::user_access_end();
        }

        // Perform write
        match file.write(&kernel_buf) {
            Ok(n) => n as i64,
            Err(FsError::PermissionDenied) => EBADF,
            Err(_) => EINVAL,
        }
    }
}

// ============================================================================
// pread64/pwrite64 syscalls - positioned read/write
// ============================================================================

/// sys_pread64 - read from file at given offset without changing file position
///
/// Like read(), but reads at an explicit offset without modifying the file position.
/// Returns -ESPIPE for files that don't support positioned I/O (pipes, sockets).
///
/// # Arguments
/// * `fd` - File descriptor
/// * `buf_ptr` - User buffer to read into
/// * `count` - Number of bytes to read
/// * `offset` - File offset to read from
///
/// # Returns
/// Number of bytes read, 0 on EOF, negative errno on error.
pub fn sys_pread64(fd: i32, buf_ptr: u64, count: u64, offset: i64) -> i64 {
    // Check offset validity (Linux returns -EINVAL for negative offsets)
    if offset < 0 {
        return EINVAL;
    }
    let offset = offset as u64;

    // Limit count to prevent allocation failure
    let count = core::cmp::min(count as usize, MAX_RW_COUNT);

    // Validate user buffer address
    if !Uaccess::access_ok(buf_ptr, count) {
        return EFAULT;
    }

    // Handle special fds (stdin) - not supported for pread
    if fd == 0 {
        return ESPIPE; // stdin is not seekable
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Check if trying to read a directory
    if file.is_dir() {
        return EISDIR;
    }

    // Use stack buffer for small reads to avoid heap allocation
    if count <= SMALL_BUF_SIZE {
        let mut stack_buf = [0u8; SMALL_BUF_SIZE];
        let read_buf = &mut stack_buf[..count];

        // Perform positioned read into stack buffer
        let bytes_read = match file.pread(read_buf, offset) {
            Ok(n) => n,
            Err(FsError::IsADirectory) => return EISDIR,
            Err(FsError::PermissionDenied) => return EBADF,
            Err(FsError::NotSupported) => return ESPIPE, // Not seekable
            Err(_) => return EINVAL,
        };

        // Copy from kernel buffer to user space
        if bytes_read > 0 && copy_to_user::<Uaccess>(buf_ptr, &read_buf[..bytes_read]).is_err() {
            return EFAULT;
        }

        bytes_read as i64
    } else {
        // Allocate a kernel buffer for large reads
        let mut kernel_buf = vec![0u8; count];

        // Perform positioned read into kernel buffer
        let bytes_read = match file.pread(&mut kernel_buf, offset) {
            Ok(n) => n,
            Err(FsError::IsADirectory) => return EISDIR,
            Err(FsError::PermissionDenied) => return EBADF,
            Err(FsError::NotSupported) => return ESPIPE, // Not seekable
            Err(_) => return EINVAL,
        };

        // Copy from kernel buffer to user space
        if bytes_read > 0 && copy_to_user::<Uaccess>(buf_ptr, &kernel_buf[..bytes_read]).is_err() {
            return EFAULT;
        }

        bytes_read as i64
    }
}

/// sys_pwrite64 - write to file at given offset without changing file position
///
/// Like write(), but writes at an explicit offset without modifying the file position.
/// Returns -ESPIPE for files that don't support positioned I/O (pipes, sockets).
///
/// # Arguments
/// * `fd` - File descriptor
/// * `buf_ptr` - User buffer containing data to write
/// * `count` - Number of bytes to write
/// * `offset` - File offset to write to
///
/// # Returns
/// Number of bytes written, negative errno on error.
pub fn sys_pwrite64(fd: i32, buf_ptr: u64, count: u64, offset: i64) -> i64 {
    // Check offset validity (Linux returns -EINVAL for negative offsets)
    if offset < 0 {
        return EINVAL;
    }
    let offset = offset as u64;

    // Limit count to prevent allocation failure
    let count = core::cmp::min(count as usize, MAX_RW_COUNT);

    // Validate user buffer address
    if !Uaccess::access_ok(buf_ptr, count) {
        return EFAULT;
    }

    // Handle special fds (stdout, stderr) - not supported for pwrite
    if fd == 1 || fd == 2 {
        return ESPIPE; // stdout/stderr are not seekable
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Check RLIMIT_FSIZE for regular files (pwrite uses explicit offset)
    if file.get_inode().is_some()
        && let Err(e) = check_fsize_limit(offset, count)
    {
        return e;
    }

    // Use stack buffer for small writes to avoid heap allocation
    if count <= SMALL_BUF_SIZE {
        let mut stack_buf = [0u8; SMALL_BUF_SIZE];
        let write_buf = &mut stack_buf[..count];

        // Copy from user space to kernel buffer
        unsafe {
            Uaccess::user_access_begin();
            core::ptr::copy_nonoverlapping(buf_ptr as *const u8, write_buf.as_mut_ptr(), count);
            Uaccess::user_access_end();
        }

        // Perform positioned write
        match file.pwrite(write_buf, offset) {
            Ok(n) => n as i64,
            Err(FsError::PermissionDenied) => EBADF,
            Err(FsError::NotSupported) => ESPIPE, // Not seekable
            Err(_) => EINVAL,
        }
    } else {
        // Allocate a kernel buffer for large writes
        let mut kernel_buf = vec![0u8; count];

        // Copy from user space to kernel buffer
        unsafe {
            Uaccess::user_access_begin();
            core::ptr::copy_nonoverlapping(buf_ptr as *const u8, kernel_buf.as_mut_ptr(), count);
            Uaccess::user_access_end();
        }

        // Perform positioned write
        match file.pwrite(&kernel_buf, offset) {
            Ok(n) => n as i64,
            Err(FsError::PermissionDenied) => EBADF,
            Err(FsError::NotSupported) => ESPIPE, // Not seekable
            Err(_) => EINVAL,
        }
    }
}

// ============================================================================
// readv/writev syscalls - scatter/gather I/O
// ============================================================================

/// Validate an iovec array from user space
///
/// Copies and validates the iovec array. Returns the validated iovecs
/// or an error code.
///
/// # Arguments
/// * `iov_ptr` - User pointer to array of iovec structures
/// * `iovcnt` - Number of iovec structures
///
/// # Returns
/// * `Ok(Vec<IoVec>)` - Validated iovec array
/// * `Err(errno)` - Error code (EINVAL, EFAULT)
fn validate_iovec_array(iov_ptr: u64, iovcnt: i32) -> Result<alloc::vec::Vec<IoVec>, i64> {
    // Check iovcnt bounds
    if iovcnt < 0 {
        return Err(EINVAL);
    }
    if iovcnt == 0 {
        return Ok(alloc::vec::Vec::new());
    }
    if iovcnt as usize > IOV_MAX {
        return Err(EINVAL);
    }

    let iovcnt = iovcnt as usize;
    let iov_size = core::mem::size_of::<IoVec>();
    let total_size = iovcnt * iov_size;

    // Validate iovec array pointer
    if !Uaccess::access_ok(iov_ptr, total_size) {
        return Err(EFAULT);
    }

    // Copy iovec array from user space
    let mut iovecs = alloc::vec::Vec::with_capacity(iovcnt);

    unsafe {
        Uaccess::user_access_begin();
        for i in 0..iovcnt {
            let iov = core::ptr::read((iov_ptr as *const IoVec).add(i));
            iovecs.push(iov);
        }
        Uaccess::user_access_end();
    }

    // Validate each iovec buffer (non-zero length only)
    for iov in &iovecs {
        if iov.iov_len == 0 {
            continue;
        }
        // Validate buffer address
        if !Uaccess::access_ok(iov.iov_base, iov.iov_len as usize) {
            return Err(EFAULT);
        }
    }

    Ok(iovecs)
}

/// sys_readv - scatter read from a file descriptor
///
/// Reads data from fd into multiple buffers (scatter I/O).
///
/// # Arguments
/// * `fd` - File descriptor to read from
/// * `iov_ptr` - User pointer to array of iovec structures
/// * `iovcnt` - Number of iovec structures
///
/// # Returns
/// Total bytes read on success, negative errno on error.
pub fn sys_readv(fd: i32, iov_ptr: u64, iovcnt: i32) -> i64 {
    // Validate and copy iovec array
    let iovecs = match validate_iovec_array(iov_ptr, iovcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Empty iovec array - return 0
    if iovecs.is_empty() {
        return 0;
    }

    // Handle special fds (stdin)
    if fd == 0 {
        return 0; // stdin not implemented
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Check if trying to read a directory
    if file.is_dir() {
        return EISDIR;
    }

    let mut total_read: usize = 0;

    // Process each iovec
    for iov in &iovecs {
        if iov.iov_len == 0 {
            continue;
        }

        // Limit to MAX_RW_COUNT - total already read
        let remaining_allowed = MAX_RW_COUNT.saturating_sub(total_read);
        if remaining_allowed == 0 {
            break;
        }

        let count = core::cmp::min(iov.iov_len as usize, remaining_allowed);

        // Use stack buffer for small reads, heap for large
        if count <= SMALL_BUF_SIZE {
            let mut stack_buf = [0u8; SMALL_BUF_SIZE];
            let read_buf = &mut stack_buf[..count];

            let bytes_read = match file.read(read_buf) {
                Ok(n) => n,
                Err(FsError::IsADirectory) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        EISDIR
                    };
                }
                Err(FsError::PermissionDenied) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        EBADF
                    };
                }
                Err(_) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        EINVAL
                    };
                }
            };

            if bytes_read > 0
                && copy_to_user::<Uaccess>(iov.iov_base, &read_buf[..bytes_read]).is_err()
            {
                return if total_read > 0 {
                    total_read as i64
                } else {
                    EFAULT
                };
            }

            total_read += bytes_read;

            // Short read means EOF or no more data - stop
            if bytes_read < count {
                break;
            }
        } else {
            let mut kernel_buf = vec![0u8; count];

            let bytes_read = match file.read(&mut kernel_buf) {
                Ok(n) => n,
                Err(FsError::IsADirectory) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        EISDIR
                    };
                }
                Err(FsError::PermissionDenied) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        EBADF
                    };
                }
                Err(_) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        EINVAL
                    };
                }
            };

            if bytes_read > 0
                && copy_to_user::<Uaccess>(iov.iov_base, &kernel_buf[..bytes_read]).is_err()
            {
                return if total_read > 0 {
                    total_read as i64
                } else {
                    EFAULT
                };
            }

            total_read += bytes_read;

            if bytes_read < count {
                break;
            }
        }
    }

    total_read as i64
}

/// Helper for writev to stdout/stderr (console)
///
/// Gathers data from all iovecs and writes to console.
fn writev_console(iovecs: &[IoVec]) -> i64 {
    let mut total_written: usize = 0;

    for iov in iovecs {
        if iov.iov_len == 0 {
            continue;
        }

        let count = core::cmp::min(iov.iov_len as usize, MAX_RW_COUNT - total_written);
        if count == 0 {
            break;
        }

        // Validate user buffer (already validated in validate_iovec_array, but double-check)
        if !Uaccess::access_ok(iov.iov_base, count) {
            return if total_written > 0 {
                total_written as i64
            } else {
                EFAULT
            };
        }

        if count <= SMALL_BUF_SIZE {
            let mut stack_buf = [0u8; SMALL_BUF_SIZE];
            let buf = &mut stack_buf[..count];

            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(iov.iov_base as *const u8, buf.as_mut_ptr(), count);
                Uaccess::user_access_end();
            }

            console_write(buf);
        } else {
            let mut kernel_buf = vec![0u8; count];

            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(
                    iov.iov_base as *const u8,
                    kernel_buf.as_mut_ptr(),
                    count,
                );
                Uaccess::user_access_end();
            }

            console_write(&kernel_buf);
        }

        total_written += count;
    }

    total_written as i64
}

/// sys_writev - gather write to a file descriptor
///
/// Writes data from multiple buffers to fd (gather I/O).
///
/// # Arguments
/// * `fd` - File descriptor to write to
/// * `iov_ptr` - User pointer to array of iovec structures
/// * `iovcnt` - Number of iovec structures
///
/// # Returns
/// Total bytes written on success, negative errno on error.
pub fn sys_writev(fd: i32, iov_ptr: u64, iovcnt: i32) -> i64 {
    // Validate and copy iovec array
    let iovecs = match validate_iovec_array(iov_ptr, iovcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Empty iovec array - return 0
    if iovecs.is_empty() {
        return 0;
    }

    // Handle special fds (stdout, stderr) - gather all data first
    if fd == 1 || fd == 2 {
        return writev_console(&iovecs);
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return EBADF,
    };

    let mut total_written: usize = 0;

    // Process each iovec
    for iov in &iovecs {
        if iov.iov_len == 0 {
            continue;
        }

        // Limit to MAX_RW_COUNT - total already written
        let remaining_allowed = MAX_RW_COUNT.saturating_sub(total_written);
        if remaining_allowed == 0 {
            break;
        }

        let count = core::cmp::min(iov.iov_len as usize, remaining_allowed);

        // Use stack buffer for small writes, heap for large
        if count <= SMALL_BUF_SIZE {
            let mut stack_buf = [0u8; SMALL_BUF_SIZE];
            let write_buf = &mut stack_buf[..count];

            // Copy from user space
            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(
                    iov.iov_base as *const u8,
                    write_buf.as_mut_ptr(),
                    count,
                );
                Uaccess::user_access_end();
            }

            let bytes_written = match file.write(write_buf) {
                Ok(n) => n,
                Err(FsError::PermissionDenied) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        EBADF
                    };
                }
                Err(_) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        EINVAL
                    };
                }
            };

            total_written += bytes_written;

            // Short write - stop
            if bytes_written < count {
                break;
            }
        } else {
            let mut kernel_buf = vec![0u8; count];

            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(
                    iov.iov_base as *const u8,
                    kernel_buf.as_mut_ptr(),
                    count,
                );
                Uaccess::user_access_end();
            }

            let bytes_written = match file.write(&kernel_buf) {
                Ok(n) => n,
                Err(FsError::PermissionDenied) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        EBADF
                    };
                }
                Err(_) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        EINVAL
                    };
                }
            };

            total_written += bytes_written;

            if bytes_written < count {
                break;
            }
        }
    }

    total_written as i64
}

/// sys_preadv - positioned scatter read from a file descriptor
///
/// Reads data from fd at the given offset into multiple buffers (scatter I/O)
/// without modifying the file position.
///
/// # Arguments
/// * `fd` - File descriptor to read from
/// * `iov_ptr` - User pointer to array of iovec structures
/// * `iovcnt` - Number of iovec structures
/// * `offset` - File offset to read from
///
/// # Returns
/// Total bytes read on success, negative errno on error.
/// Returns -ESPIPE if fd refers to a non-seekable file (pipe, socket).
pub fn sys_preadv(fd: i32, iov_ptr: u64, iovcnt: i32, offset: i64) -> i64 {
    // Validate offset
    if offset < 0 {
        return EINVAL;
    }
    let mut current_offset = offset as u64;

    // Validate and copy iovec array
    let iovecs = match validate_iovec_array(iov_ptr, iovcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Empty iovec array - return 0
    if iovecs.is_empty() {
        return 0;
    }

    // Handle stdin - pipes don't support positioned I/O
    if fd == 0 {
        return ESPIPE;
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Cannot preadv from directory
    if file.is_dir() {
        return EISDIR;
    }

    let mut total_read: usize = 0;

    // Process each iovec
    for iov in &iovecs {
        if iov.iov_len == 0 {
            continue;
        }

        // Limit to MAX_RW_COUNT - total already read
        let remaining_allowed = MAX_RW_COUNT.saturating_sub(total_read);
        if remaining_allowed == 0 {
            break;
        }

        let count = core::cmp::min(iov.iov_len as usize, remaining_allowed);

        // Use stack buffer for small reads, heap for large
        if count <= SMALL_BUF_SIZE {
            let mut stack_buf = [0u8; SMALL_BUF_SIZE];
            let read_buf = &mut stack_buf[..count];

            // Use positioned read (doesn't modify file position)
            let bytes_read = match file.pread(read_buf, current_offset) {
                Ok(n) => n,
                Err(FsError::NotSupported) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        ESPIPE // non-seekable file
                    };
                }
                Err(FsError::PermissionDenied) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        EBADF
                    };
                }
                Err(_) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        EINVAL
                    };
                }
            };

            // Copy to user space
            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(
                    read_buf.as_ptr(),
                    iov.iov_base as *mut u8,
                    bytes_read,
                );
                Uaccess::user_access_end();
            }

            total_read += bytes_read;
            current_offset += bytes_read as u64;

            // Short read (EOF or partial) - stop
            if bytes_read < count {
                break;
            }
        } else {
            let mut kernel_buf = vec![0u8; count];

            // Use positioned read (doesn't modify file position)
            let bytes_read = match file.pread(&mut kernel_buf, current_offset) {
                Ok(n) => n,
                Err(FsError::NotSupported) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        ESPIPE
                    };
                }
                Err(FsError::PermissionDenied) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        EBADF
                    };
                }
                Err(_) => {
                    return if total_read > 0 {
                        total_read as i64
                    } else {
                        EINVAL
                    };
                }
            };

            // Copy to user space
            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(
                    kernel_buf.as_ptr(),
                    iov.iov_base as *mut u8,
                    bytes_read,
                );
                Uaccess::user_access_end();
            }

            total_read += bytes_read;
            current_offset += bytes_read as u64;

            if bytes_read < count {
                break;
            }
        }
    }

    total_read as i64
}

/// sys_pwritev - positioned gather write to a file descriptor
///
/// Writes data from multiple buffers to fd at the given offset (gather I/O)
/// without modifying the file position.
///
/// # Arguments
/// * `fd` - File descriptor to write to
/// * `iov_ptr` - User pointer to array of iovec structures
/// * `iovcnt` - Number of iovec structures
/// * `offset` - File offset to write to
///
/// # Returns
/// Total bytes written on success, negative errno on error.
/// Returns -ESPIPE if fd refers to a non-seekable file (pipe, socket).
pub fn sys_pwritev(fd: i32, iov_ptr: u64, iovcnt: i32, offset: i64) -> i64 {
    // Validate offset
    if offset < 0 {
        return EINVAL;
    }
    let mut current_offset = offset as u64;

    // Validate and copy iovec array
    let iovecs = match validate_iovec_array(iov_ptr, iovcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Empty iovec array - return 0
    if iovecs.is_empty() {
        return 0;
    }

    // Handle stdout/stderr - these don't support positioned I/O
    if fd == 1 || fd == 2 {
        return ESPIPE;
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Cannot pwritev to directory
    if file.is_dir() {
        return EISDIR;
    }

    let mut total_written: usize = 0;

    // Process each iovec
    for iov in &iovecs {
        if iov.iov_len == 0 {
            continue;
        }

        // Limit to MAX_RW_COUNT - total already written
        let remaining_allowed = MAX_RW_COUNT.saturating_sub(total_written);
        if remaining_allowed == 0 {
            break;
        }

        let count = core::cmp::min(iov.iov_len as usize, remaining_allowed);

        // Use stack buffer for small writes, heap for large
        if count <= SMALL_BUF_SIZE {
            let mut stack_buf = [0u8; SMALL_BUF_SIZE];
            let write_buf = &mut stack_buf[..count];

            // Copy from user space
            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(
                    iov.iov_base as *const u8,
                    write_buf.as_mut_ptr(),
                    count,
                );
                Uaccess::user_access_end();
            }

            // Use positioned write (doesn't modify file position)
            let bytes_written = match file.pwrite(write_buf, current_offset) {
                Ok(n) => n,
                Err(FsError::NotSupported) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        ESPIPE // non-seekable file
                    };
                }
                Err(FsError::PermissionDenied) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        EBADF
                    };
                }
                Err(_) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        EINVAL
                    };
                }
            };

            total_written += bytes_written;
            current_offset += bytes_written as u64;

            // Short write - stop
            if bytes_written < count {
                break;
            }
        } else {
            let mut kernel_buf = vec![0u8; count];

            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(
                    iov.iov_base as *const u8,
                    kernel_buf.as_mut_ptr(),
                    count,
                );
                Uaccess::user_access_end();
            }

            // Use positioned write (doesn't modify file position)
            let bytes_written = match file.pwrite(&kernel_buf, current_offset) {
                Ok(n) => n,
                Err(FsError::NotSupported) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        ESPIPE
                    };
                }
                Err(FsError::PermissionDenied) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        EBADF
                    };
                }
                Err(_) => {
                    return if total_written > 0 {
                        total_written as i64
                    } else {
                        EINVAL
                    };
                }
            };

            total_written += bytes_written;
            current_offset += bytes_written as u64;

            if bytes_written < count {
                break;
            }
        }
    }

    total_written as i64
}

/// sys_preadv2 - positioned scatter read with flags
///
/// Enhanced version of preadv that supports per-I/O flags (RWF_*).
///
/// # Arguments
/// * `fd` - File descriptor to read from
/// * `iov_ptr` - User pointer to array of iovec structures
/// * `iovcnt` - Number of iovec structures
/// * `offset` - File offset to read from, or -1 to use current file position
/// * `flags` - RWF_* flags for this I/O operation
///
/// # Returns
/// Total bytes read on success, negative errno on error.
/// Returns -EOPNOTSUPP for unsupported flags.
pub fn sys_preadv2(fd: i32, iov_ptr: u64, iovcnt: i32, offset: i64, flags: i32) -> i64 {
    // Validate flags - unknown flags return EOPNOTSUPP
    if flags & !RWF_SUPPORTED != 0 {
        return EOPNOTSUPP;
    }

    // Unsupported flags - return EOPNOTSUPP
    if flags & (RWF_ATOMIC | RWF_DONTCACHE) != 0 {
        return EOPNOTSUPP;
    }

    // If RWF_NOWAIT not set, delegate to existing syscalls
    if flags & RWF_NOWAIT == 0 {
        if offset == -1 {
            return sys_readv(fd, iov_ptr, iovcnt);
        }
        return sys_preadv(fd, iov_ptr, iovcnt, offset);
    }

    // RWF_NOWAIT handling - use *_with_flags methods
    let rw_flags = RwFlags::with_nowait();

    // Validate and copy iovec array
    let iovecs = match validate_iovec_array(iov_ptr, iovcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if iovecs.is_empty() {
        return 0;
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return EBADF,
    };

    if file.is_dir() {
        return EISDIR;
    }

    // For offset == -1, use current file position
    let use_position = offset == -1;
    let mut current_offset = if use_position { file.get_pos() } else { offset as u64 };

    let mut total_read: usize = 0;

    for iov in &iovecs {
        if iov.iov_len == 0 {
            continue;
        }

        let remaining_allowed = MAX_RW_COUNT.saturating_sub(total_read);
        if remaining_allowed == 0 {
            break;
        }

        let count = core::cmp::min(iov.iov_len as usize, remaining_allowed);

        if count <= SMALL_BUF_SIZE {
            let mut stack_buf = [0u8; SMALL_BUF_SIZE];
            let read_buf = &mut stack_buf[..count];

            let result = if use_position {
                file.read_with_flags(read_buf, rw_flags)
            } else {
                file.pread_with_flags(read_buf, current_offset, rw_flags)
            };

            let bytes_read = match result {
                Ok(n) => n,
                Err(FsError::WouldBlock) => {
                    return if total_read > 0 { total_read as i64 } else { EAGAIN };
                }
                Err(FsError::NotSupported) => {
                    return if total_read > 0 { total_read as i64 } else { EOPNOTSUPP };
                }
                Err(FsError::PermissionDenied) => {
                    return if total_read > 0 { total_read as i64 } else { EBADF };
                }
                Err(_) => {
                    return if total_read > 0 { total_read as i64 } else { EINVAL };
                }
            };

            if bytes_read > 0
                && copy_to_user::<Uaccess>(iov.iov_base, &read_buf[..bytes_read]).is_err()
            {
                return if total_read > 0 { total_read as i64 } else { EFAULT };
            }

            total_read += bytes_read;
            current_offset += bytes_read as u64;

            if bytes_read < count {
                break;
            }
        } else {
            let mut kernel_buf = vec![0u8; count];

            let result = if use_position {
                file.read_with_flags(&mut kernel_buf, rw_flags)
            } else {
                file.pread_with_flags(&mut kernel_buf, current_offset, rw_flags)
            };

            let bytes_read = match result {
                Ok(n) => n,
                Err(FsError::WouldBlock) => {
                    return if total_read > 0 { total_read as i64 } else { EAGAIN };
                }
                Err(FsError::NotSupported) => {
                    return if total_read > 0 { total_read as i64 } else { EOPNOTSUPP };
                }
                Err(FsError::PermissionDenied) => {
                    return if total_read > 0 { total_read as i64 } else { EBADF };
                }
                Err(_) => {
                    return if total_read > 0 { total_read as i64 } else { EINVAL };
                }
            };

            if bytes_read > 0
                && copy_to_user::<Uaccess>(iov.iov_base, &kernel_buf[..bytes_read]).is_err()
            {
                return if total_read > 0 { total_read as i64 } else { EFAULT };
            }

            total_read += bytes_read;
            current_offset += bytes_read as u64;

            if bytes_read < count {
                break;
            }
        }
    }

    // Update file position if using current position
    if use_position && total_read > 0 {
        file.advance_pos(total_read as u64);
    }

    total_read as i64
}

/// sys_pwritev2 - positioned gather write with flags
///
/// Enhanced version of pwritev that supports per-I/O flags (RWF_*).
///
/// # Arguments
/// * `fd` - File descriptor to write to
/// * `iov_ptr` - User pointer to array of iovec structures
/// * `iovcnt` - Number of iovec structures
/// * `offset` - File offset to write to, or -1 to use current file position
/// * `flags` - RWF_* flags for this I/O operation
///
/// # Returns
/// Total bytes written on success, negative errno on error.
/// Returns -EOPNOTSUPP for unsupported flags.
pub fn sys_pwritev2(fd: i32, iov_ptr: u64, iovcnt: i32, offset: i64, flags: i32) -> i64 {
    // Validate flags - unknown flags return EOPNOTSUPP
    if flags & !RWF_SUPPORTED != 0 {
        return EOPNOTSUPP;
    }

    // Unsupported flags - return EOPNOTSUPP
    if flags & (RWF_ATOMIC | RWF_DONTCACHE) != 0 {
        return EOPNOTSUPP;
    }

    // If RWF_NOWAIT not set, delegate to existing syscalls
    if flags & RWF_NOWAIT == 0 {
        if offset == -1 {
            let result = sys_writev(fd, iov_ptr, iovcnt);
            if result > 0 && (flags & (RWF_SYNC | RWF_DSYNC)) != 0 {
                let _ = sys_fsync(fd);
            }
            return result;
        }

        // RWF_APPEND: get file size as offset
        let actual_offset = if flags & RWF_APPEND != 0 {
            let file = match current_fd_table().lock().get(fd) {
                Some(f) => f,
                None => return EBADF,
            };
            file.get_inode().map(|i| i.get_size() as i64).unwrap_or(0)
        } else {
            offset
        };

        let result = sys_pwritev(fd, iov_ptr, iovcnt, actual_offset);
        if result > 0 && (flags & (RWF_SYNC | RWF_DSYNC)) != 0 {
            let _ = sys_fsync(fd);
        }
        return result;
    }

    // RWF_NOWAIT handling - use *_with_flags methods
    let rw_flags = RwFlags::with_nowait();

    // Validate and copy iovec array
    let iovecs = match validate_iovec_array(iov_ptr, iovcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if iovecs.is_empty() {
        return 0;
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return EBADF,
    };

    if file.is_dir() {
        return EISDIR;
    }

    // For offset == -1, use current file position
    let use_position = offset == -1;

    // RWF_APPEND: get file size as offset
    let mut current_offset = if use_position {
        file.get_pos()
    } else if flags & RWF_APPEND != 0 {
        file.get_inode().map(|i| i.get_size()).unwrap_or(0)
    } else {
        offset as u64
    };

    let mut total_written: usize = 0;

    for iov in &iovecs {
        if iov.iov_len == 0 {
            continue;
        }

        let remaining_allowed = MAX_RW_COUNT.saturating_sub(total_written);
        if remaining_allowed == 0 {
            break;
        }

        let count = core::cmp::min(iov.iov_len as usize, remaining_allowed);

        if count <= SMALL_BUF_SIZE {
            let mut stack_buf = [0u8; SMALL_BUF_SIZE];
            let write_buf = &mut stack_buf[..count];

            // Copy from user space
            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(
                    iov.iov_base as *const u8,
                    write_buf.as_mut_ptr(),
                    count,
                );
                Uaccess::user_access_end();
            }

            let result = if use_position {
                file.write_with_flags(write_buf, rw_flags)
            } else {
                file.pwrite_with_flags(write_buf, current_offset, rw_flags)
            };

            let bytes_written = match result {
                Ok(n) => n,
                Err(FsError::WouldBlock) => {
                    return if total_written > 0 { total_written as i64 } else { EAGAIN };
                }
                Err(FsError::NotSupported) => {
                    return if total_written > 0 { total_written as i64 } else { EOPNOTSUPP };
                }
                Err(FsError::PermissionDenied) => {
                    return if total_written > 0 { total_written as i64 } else { EBADF };
                }
                Err(FsError::BrokenPipe) => {
                    return if total_written > 0 { total_written as i64 } else { EPIPE };
                }
                Err(_) => {
                    return if total_written > 0 { total_written as i64 } else { EINVAL };
                }
            };

            total_written += bytes_written;
            current_offset += bytes_written as u64;

            if bytes_written < count {
                break;
            }
        } else {
            let mut kernel_buf = vec![0u8; count];

            // Copy from user space
            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(
                    iov.iov_base as *const u8,
                    kernel_buf.as_mut_ptr(),
                    count,
                );
                Uaccess::user_access_end();
            }

            let result = if use_position {
                file.write_with_flags(&kernel_buf, rw_flags)
            } else {
                file.pwrite_with_flags(&kernel_buf, current_offset, rw_flags)
            };

            let bytes_written = match result {
                Ok(n) => n,
                Err(FsError::WouldBlock) => {
                    return if total_written > 0 { total_written as i64 } else { EAGAIN };
                }
                Err(FsError::NotSupported) => {
                    return if total_written > 0 { total_written as i64 } else { EOPNOTSUPP };
                }
                Err(FsError::PermissionDenied) => {
                    return if total_written > 0 { total_written as i64 } else { EBADF };
                }
                Err(FsError::BrokenPipe) => {
                    return if total_written > 0 { total_written as i64 } else { EPIPE };
                }
                Err(_) => {
                    return if total_written > 0 { total_written as i64 } else { EINVAL };
                }
            };

            total_written += bytes_written;
            current_offset += bytes_written as u64;

            if bytes_written < count {
                break;
            }
        }
    }

    // Update file position if using current position
    if use_position && total_written > 0 {
        file.advance_pos(total_written as u64);
    }

    // RWF_SYNC/RWF_DSYNC: sync after successful write
    if total_written > 0 && (flags & (RWF_SYNC | RWF_DSYNC)) != 0 {
        let _ = sys_fsync(fd);
    }

    total_written as i64
}

/// sys_close - close a file descriptor
///
/// Returns 0 on success, negative errno on error.
pub fn sys_close(fd: i32) -> i64 {
    // Don't close stdin/stdout/stderr
    if fd < 3 {
        return 0;
    }

    match current_fd_table().lock().close(fd) {
        Some(_) => 0,
        None => EBADF,
    }
}

/// sys_lseek - reposition read/write file offset
///
/// Repositions the file offset of the open file description associated with
/// the file descriptor fd to the argument offset according to the directive
/// whence.
///
/// # Arguments
/// * `fd` - File descriptor
/// * `offset` - New offset (interpretation depends on whence)
/// * `whence` - SEEK_SET (0), SEEK_CUR (1), or SEEK_END (2)
///
/// # Returns
/// The resulting offset location from the beginning of the file on success,
/// or negative errno on error.
pub fn sys_lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Perform the seek
    match file.lseek(offset, whence) {
        Ok(new_pos) => new_pos as i64,
        Err(FsError::InvalidArgument) => EINVAL,
        Err(FsError::NotSupported) => -29, // ESPIPE - illegal seek (e.g., on pipe)
        Err(_) => EINVAL,
    }
}

/// Helper to perform truncate on an inode with RLIMIT and error handling
fn do_truncate(inode: &alloc::sync::Arc<super::Inode>, length: u64) -> i64 {
    // Check RLIMIT_FSIZE when extending the file
    let current_size = inode.get_size();
    if length > current_size {
        let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_FSIZE);
        if limit != crate::rlimit::RLIM_INFINITY && length > limit {
            let tid = current_tid();
            crate::signal::send_signal(tid, crate::signal::SIGXFSZ);
            return EFBIG;
        }
    }

    // Perform truncate
    match inode.i_op.truncate(inode, length) {
        Ok(()) => 0,
        Err(FsError::IsADirectory) => EISDIR,
        Err(FsError::NotSupported) => EINVAL,
        Err(FsError::PermissionDenied) => EACCES,
        Err(FsError::FileTooLarge) => EFBIG,
        Err(_) => EINVAL,
    }
}

/// sys_ftruncate - truncate a file to a specified length
///
/// Truncates the file referred to by fd to the specified length.
/// If the file was larger, the extra data is discarded.
/// If the file was shorter, it is extended with null bytes.
///
/// # Arguments
/// * `fd` - File descriptor (must be open for writing)
/// * `length` - New file length
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_ftruncate(fd: i32, length: i64) -> i64 {
    if length < 0 {
        return EINVAL;
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Check file is writable
    if !file.is_writable() {
        return EINVAL; // EBADF or EINVAL depending on interpretation
    }

    // Get the inode
    let inode = match file.get_inode() {
        Some(i) => i,
        None => return EBADF,
    };

    do_truncate(&inode, length as u64)
}

/// sys_truncate - truncate a file to a specified length by path
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
/// * `length` - New file length
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_truncate(path_ptr: u64, length: i64) -> i64 {
    if length < 0 {
        return EINVAL;
    }

    // Read path from user space
    let path = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    if path.is_empty() {
        return ENOENT;
    }

    // Look up the file (follow symlinks for truncate)
    let dentry = match lookup_path_flags(&path, LookupFlags::open()) {
        Ok(d) => d,
        Err(FsError::NotFound) => return ENOENT,
        Err(FsError::NotADirectory) => return ENOTDIR,
        Err(_) => return EINVAL,
    };

    // Get the inode
    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    do_truncate(&inode, length as u64)
}

/// sys_dup - duplicate a file descriptor
///
/// Creates a copy of the file descriptor oldfd, using the lowest-numbered
/// unused file descriptor for the new descriptor.
///
/// # Arguments
/// * `oldfd` - File descriptor to duplicate
///
/// # Returns
/// New file descriptor on success, negative errno on error.
pub fn sys_dup(oldfd: i32) -> i64 {
    let fd_table = current_fd_table();
    let mut table = fd_table.lock();
    let file = match table.get(oldfd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Allocate fd (RLIMIT_NOFILE enforced inside alloc)
    match table.alloc(file, get_nofile_limit()) {
        Ok(newfd) => newfd as i64,
        Err(e) => -(e as i64),
    }
}

/// sys_dup2 - duplicate a file descriptor to a specific number
///
/// Makes newfd be a copy of oldfd, closing newfd first if necessary.
/// If oldfd == newfd, just checks that oldfd is valid.
///
/// # Arguments
/// * `oldfd` - File descriptor to duplicate
/// * `newfd` - Target file descriptor number
///
/// # Returns
/// newfd on success, negative errno on error.
pub fn sys_dup2(oldfd: i32, newfd: i32) -> i64 {
    if newfd < 0 {
        return EBADF;
    }

    // If oldfd == newfd, just verify oldfd is valid
    if oldfd == newfd {
        let fd_table = current_fd_table();
        let table = fd_table.lock();
        return if table.is_valid(oldfd) {
            newfd as i64
        } else {
            EBADF
        };
    }

    let fd_table = current_fd_table();
    let mut table = fd_table.lock();
    let file = match table.get(oldfd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Close newfd if open (silently ignore errors)
    table.close(newfd);

    // Allocate at specific fd (RLIMIT_NOFILE enforced inside)
    match table.alloc_at_with_flags(newfd, file, 0, get_nofile_limit()) {
        Ok(()) => newfd as i64,
        Err(e) => -(e as i64),
    }
}

/// sys_dup3 - duplicate a file descriptor with flags
///
/// Like dup2, but with additional flags. Currently only O_CLOEXEC is supported.
/// Unlike dup2, returns EINVAL if oldfd == newfd.
///
/// # Arguments
/// * `oldfd` - File descriptor to duplicate
/// * `newfd` - Target file descriptor number
/// * `flags` - Flags (only O_CLOEXEC supported)
///
/// # Returns
/// newfd on success, negative errno on error.
pub fn sys_dup3(oldfd: i32, newfd: i32, flags: u32) -> i64 {
    // dup3 requires oldfd != newfd (unlike dup2)
    if oldfd == newfd {
        return EINVAL;
    }
    if newfd < 0 {
        return EBADF;
    }

    // Only O_CLOEXEC is valid for dup3
    if flags & !super::file::flags::O_CLOEXEC != 0 {
        return EINVAL;
    }

    let fd_table = current_fd_table();
    let mut table = fd_table.lock();
    let file = match table.get(oldfd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Close newfd if open
    table.close(newfd);

    // Convert O_CLOEXEC to FD_CLOEXEC
    let fd_flags = if flags & super::file::flags::O_CLOEXEC != 0 {
        crate::task::FD_CLOEXEC
    } else {
        0
    };

    // Allocate at specific fd (RLIMIT_NOFILE enforced inside)
    match table.alloc_at_with_flags(newfd, file, fd_flags, get_nofile_limit()) {
        Ok(()) => newfd as i64,
        Err(e) => -(e as i64),
    }
}

/// Linux dirent64 structure for getdents64
#[repr(C, packed)]
struct LinuxDirent64 {
    d_ino: u64,
    d_off: i64,
    d_reclen: u16,
    d_type: u8,
    // d_name follows (variable length, null-terminated)
}

/// Directory entry types (DT_* values)
const DT_FIFO: u8 = 1;
const DT_CHR: u8 = 2;
const DT_DIR: u8 = 4;
const DT_BLK: u8 = 6;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;
const DT_SOCK: u8 = 12;

/// sys_getdents64 - get directory entries
///
/// Returns number of bytes read into buffer, 0 on end of directory, negative errno on error.
pub fn sys_getdents64(fd: i32, dirp: u64, count: u64) -> i64 {
    // Limit count to prevent allocation failure
    let count = core::cmp::min(count as usize, MAX_RW_COUNT);

    // Validate user buffer address
    if !Uaccess::access_ok(dirp, count) {
        return EFAULT;
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return EBADF,
    };

    if !file.is_dir() {
        return ENOTDIR;
    }

    // Use stack buffer for small directory listings
    let mut stack_buf = [0u8; SMALL_BUF_SIZE];
    let kernel_buf: &mut [u8] = if count <= SMALL_BUF_SIZE {
        &mut stack_buf[..count]
    } else {
        // For large buffers, just use the small stack buffer
        // Directory listings rarely need more than 4KB
        &mut stack_buf[..]
    };
    let mut offset = 0usize;
    let mut dir_offset = 0i64;

    let result = file.readdir(&mut |entry| {
        // Calculate record length (header + name + null + alignment)
        let name_len = entry.name.len();
        let reclen = core::mem::size_of::<LinuxDirent64>() + name_len + 1;
        let aligned_reclen = (reclen + 7) & !7; // 8-byte alignment

        // Check if we have space
        if offset + aligned_reclen > kernel_buf.len() {
            return false; // Stop iteration
        }

        // Determine d_type
        let d_type = match entry.file_type {
            super::FileType::Regular => DT_REG,
            super::FileType::Directory => DT_DIR,
            super::FileType::Symlink => DT_LNK,
            super::FileType::CharDev => DT_CHR,
            super::FileType::BlockDev => DT_BLK,
            super::FileType::Fifo => DT_FIFO,
            super::FileType::Socket => DT_SOCK,
        };

        dir_offset += 1;

        // Write dirent64 structure to kernel buffer
        unsafe {
            let dirent = &mut *(kernel_buf.as_mut_ptr().add(offset) as *mut LinuxDirent64);
            dirent.d_ino = entry.ino;
            dirent.d_off = dir_offset;
            dirent.d_reclen = aligned_reclen as u16;
            dirent.d_type = d_type;

            // Copy name after the header
            let name_ptr = kernel_buf
                .as_mut_ptr()
                .add(offset + core::mem::size_of::<LinuxDirent64>());
            core::ptr::copy_nonoverlapping(entry.name.as_ptr(), name_ptr, name_len);
            // Null terminate
            *name_ptr.add(name_len) = 0;
        }

        offset += aligned_reclen;
        true // Continue iteration
    });

    match result {
        Ok(()) => {
            // Copy from kernel buffer to user space
            if offset > 0 && copy_to_user::<Uaccess>(dirp, &kernel_buf[..offset]).is_err() {
                return EFAULT;
            }
            offset as i64
        }
        Err(FsError::NotADirectory) => ENOTDIR,
        Err(_) => EINVAL,
    }
}

/// Linux stat structure (x86-64)
///
/// This matches the kernel's `struct stat` for x86-64.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    pub __unused: [i64; 3],
}

/// Fill a Stat structure from an inode
fn fill_stat(inode: &super::Inode) -> Stat {
    let attr = inode.i_op.getattr(inode);

    // Get device ID from superblock (filesystem device)
    let st_dev = inode.superblock().map(|sb| sb.dev_id).unwrap_or(0);

    // Get rdev for device files (char/block device major/minor)
    let st_rdev = if attr.mode.is_device() {
        attr.rdev.encode() as u64
    } else {
        0
    };

    Stat {
        st_dev,
        st_ino: attr.ino,
        st_nlink: attr.nlink as u64,
        st_mode: attr.mode.raw() as u32,
        st_uid: attr.uid,
        st_gid: attr.gid,
        __pad0: 0,
        st_rdev,
        st_size: attr.size as i64,
        st_blksize: 4096,
        st_blocks: attr.size.div_ceil(512) as i64,
        st_atime: attr.atime.sec,
        st_atime_nsec: attr.atime.nsec as i64,
        st_mtime: attr.mtime.sec,
        st_mtime_nsec: attr.mtime.nsec as i64,
        st_ctime: attr.ctime.sec,
        st_ctime_nsec: attr.ctime.nsec as i64,
        __unused: [0; 3],
    }
}

/// sys_stat - get file status by path
///
/// Returns 0 on success, negative errno on error.
pub fn sys_stat(path_ptr: u64, statbuf: u64) -> i64 {
    // Read path from user space with proper validation
    let path = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    // Validate stat buffer address
    if !Uaccess::access_ok(statbuf, core::mem::size_of::<Stat>()) {
        return EFAULT;
    }

    // Look up the path (follow symlinks)
    let dentry = match lookup_path_flags(&path, LookupFlags::open()) {
        Ok(d) => d,
        Err(FsError::NotFound) => return ENOENT,
        Err(FsError::NotADirectory) => return ENOTDIR,
        Err(_) => return EINVAL,
    };

    // Get the inode
    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    // Fill the stat structure
    let stat = fill_stat(&inode);

    // Copy to user space using put_user for the entire structure
    if put_user::<Uaccess, Stat>(statbuf, stat).is_err() {
        return EFAULT;
    }

    0
}

/// sys_fstat - get file status by file descriptor
///
/// Returns 0 on success, negative errno on error.
pub fn sys_fstat(fd: i32, statbuf: u64) -> i64 {
    // Validate stat buffer address
    if !Uaccess::access_ok(statbuf, core::mem::size_of::<Stat>()) {
        return EFAULT;
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Get the inode
    let inode = match file.get_inode() {
        Some(i) => i,
        None => return EBADF,
    };

    // Fill the stat structure
    let stat = fill_stat(&inode);

    // Copy to user space using put_user for the entire structure
    if put_user::<Uaccess, Stat>(statbuf, stat).is_err() {
        return EFAULT;
    }

    0
}

/// sys_fstatat - get file status by path relative to directory fd
///
/// This is the *at variant of stat/lstat, supporting both absolute paths
/// and paths relative to a directory file descriptor.
///
/// # Arguments
/// * `dirfd` - Directory fd for relative paths, or AT_FDCWD for cwd
/// * `path_ptr` - User pointer to path string
/// * `statbuf` - User pointer to stat structure
/// * `flags` - AT_SYMLINK_NOFOLLOW to not follow final symlink, AT_EMPTY_PATH to stat dirfd
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_fstatat(dirfd: i32, path_ptr: u64, statbuf: u64, flags: i32) -> i64 {
    // AT_SYMLINK_NOFOLLOW and AT_EMPTY_PATH are the valid flags
    const AT_SYMLINK_NOFOLLOW_FLAG: i32 = 0x100;
    const AT_EMPTY_PATH_FLAG: i32 = 0x1000;
    let valid_flags = AT_SYMLINK_NOFOLLOW_FLAG | AT_EMPTY_PATH_FLAG;
    if flags & !valid_flags != 0 {
        return EINVAL;
    }

    // Validate stat buffer address
    if !Uaccess::access_ok(statbuf, core::mem::size_of::<Stat>()) {
        return EFAULT;
    }

    // Read path from user space
    let path_str = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    // Handle AT_EMPTY_PATH - stat the dirfd itself
    if (flags & AT_EMPTY_PATH_FLAG) != 0 && path_str.is_empty() {
        if dirfd == AT_FDCWD {
            return EINVAL;
        }
        // Stat the directory fd itself
        return sys_fstat(dirfd, statbuf);
    }

    // Determine starting path for relative paths
    let start: Option<Path> = if path_str.starts_with('/') {
        // Absolute path - lookup_path_at will use root
        None
    } else if dirfd == AT_FDCWD {
        // Use current working directory
        crate::task::percpu::current_cwd()
    } else {
        // Use directory from file descriptor
        let file = match current_fd_table().lock().get(dirfd) {
            Some(f) => f,
            None => return EBADF,
        };
        if !file.is_dir() {
            return ENOTDIR;
        }
        // Create Path from the file's dentry
        Path::from_dentry(file.dentry.clone())
    };

    // Set up lookup flags
    let lookup_flags = if (flags & AT_SYMLINK_NOFOLLOW_FLAG) != 0 {
        LookupFlags {
            follow: false,
            ..LookupFlags::open()
        }
    } else {
        LookupFlags::open()
    };

    // Look up the path
    let dentry = match lookup_path_at(start, &path_str, lookup_flags) {
        Ok(d) => d,
        Err(FsError::NotFound) => return ENOENT,
        Err(FsError::NotADirectory) => return ENOTDIR,
        Err(FsError::TooManySymlinks) => return ELOOP,
        Err(_) => return EINVAL,
    };

    // Get the inode
    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    // Fill the stat structure
    let stat = fill_stat(&inode);

    // Copy to user space
    if put_user::<Uaccess, Stat>(statbuf, stat).is_err() {
        return EFAULT;
    }

    0
}

// ============================================================================
// access, faccessat, faccessat2 syscalls
// ============================================================================

/// Permission denied error
const EACCES: i64 = -13;

// access() mode flags - what permissions to check
/// Check if file exists
const F_OK: i32 = 0;
/// Check execute permission
const X_OK: i32 = 1;
/// Check write permission
const W_OK: i32 = 2;
/// Check read permission
const R_OK: i32 = 4;

// faccessat() flags - how to perform the check
/// Use effective uid/gid instead of real uid/gid
const AT_EACCESS: i32 = 0x200;
/// Don't follow symbolic links
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
/// If pathname is empty, check dirfd itself
const AT_EMPTY_PATH: i32 = 0x1000;

/// Common helper for access/faccessat/faccessat2
///
/// Checks whether the calling process can access the file at the given path.
///
/// # Arguments
/// * `dirfd` - Directory fd for relative paths, or AT_FDCWD
/// * `path_ptr` - User pointer to path string
/// * `mode` - Access mode to check (F_OK, R_OK, W_OK, X_OK or combination)
/// * `flags` - Behavior flags (AT_EACCESS, AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH)
///
/// # Returns
/// 0 if access is permitted, negative errno on error
fn do_faccessat(dirfd: i32, path_ptr: u64, mode: i32, flags: i32) -> i64 {
    // Validate mode - only F_OK, R_OK, W_OK, X_OK are allowed
    if mode & !(F_OK | R_OK | W_OK | X_OK) != 0 {
        return EINVAL;
    }

    // Validate flags
    let valid_flags = AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;
    if flags & !valid_flags != 0 {
        return EINVAL;
    }

    // Read path from user space
    let path_str = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    // Handle AT_EMPTY_PATH
    if path_str.is_empty() {
        if flags & AT_EMPTY_PATH == 0 {
            return ENOENT;
        }
        // AT_EMPTY_PATH: stat the fd itself (needs fd table lookup and file stat)
        return EINVAL;
    }

    // Determine starting path for relative paths
    let start: Option<Path> = if path_str.starts_with('/') {
        // Absolute path - lookup_path_at will use root
        None
    } else if dirfd == AT_FDCWD {
        // Use current working directory
        crate::task::percpu::current_cwd()
    } else {
        // Use directory from file descriptor
        let file = match current_fd_table().lock().get(dirfd) {
            Some(f) => f,
            None => return EBADF,
        };
        if !file.is_dir() {
            return ENOTDIR;
        }
        // Create Path from the file's dentry
        Path::from_dentry(file.dentry.clone())
    };

    // Set up lookup flags
    let mut lookup_flags = LookupFlags::open();
    if flags & AT_SYMLINK_NOFOLLOW != 0 {
        lookup_flags.follow = false;
    }

    // Look up the path
    let dentry = match lookup_path_at(start, &path_str, lookup_flags) {
        Ok(d) => d,
        Err(FsError::NotFound) => return ENOENT,
        Err(FsError::NotADirectory) => return ENOTDIR,
        Err(FsError::PermissionDenied) => return EACCES,
        Err(_) => return EINVAL,
    };

    // F_OK just checks existence - path lookup succeeded
    if mode == F_OK {
        return 0;
    }

    // Get inode for permission check
    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    // Get credentials - use effective if AT_EACCESS, else real
    let cred = crate::task::percpu::current_cred();
    let (uid, gid) = if flags & AT_EACCESS != 0 {
        (cred.euid, cred.egid)
    } else {
        (cred.uid, cred.gid)
    };

    // Convert mode to permission mask
    let mut mask: u32 = 0;
    if mode & R_OK != 0 {
        mask |= super::MAY_READ;
    }
    if mode & W_OK != 0 {
        mask |= super::MAY_WRITE;
    }
    if mode & X_OK != 0 {
        mask |= super::MAY_EXEC;
    }

    // Check permissions
    match super::inode_permission(&inode, uid, gid, mask) {
        Ok(()) => 0,
        Err(_) => EACCES,
    }
}

/// sys_access - check file access permissions
///
/// Checks whether the calling process can access the file at pathname.
/// Uses real uid/gid (not effective).
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
/// * `mode` - Access mode to check (F_OK, R_OK, W_OK, X_OK or combination)
///
/// # Returns
/// 0 if access is permitted, negative errno on error
pub fn sys_access(path_ptr: u64, mode: i32) -> i64 {
    do_faccessat(AT_FDCWD, path_ptr, mode, 0)
}

/// sys_faccessat - check file access relative to directory fd
///
/// Like access(), but with a directory fd for relative paths and flags.
///
/// # Arguments
/// * `dirfd` - Directory fd for relative paths, or AT_FDCWD
/// * `path_ptr` - User pointer to path string
/// * `mode` - Access mode to check
/// * `flags` - Behavior flags (AT_EACCESS, AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH)
///
/// # Returns
/// 0 if access is permitted, negative errno on error
pub fn sys_faccessat(dirfd: i32, path_ptr: u64, mode: i32, flags: i32) -> i64 {
    do_faccessat(dirfd, path_ptr, mode, flags)
}

/// sys_faccessat2 - check file access (same as faccessat)
///
/// This is identical to faccessat. Linux introduced faccessat2 to add
/// the flags parameter, but on newer kernels faccessat also accepts flags.
///
/// # Arguments
/// * `dirfd` - Directory fd for relative paths, or AT_FDCWD
/// * `path_ptr` - User pointer to path string
/// * `mode` - Access mode to check
/// * `flags` - Behavior flags
///
/// # Returns
/// 0 if access is permitted, negative errno on error
pub fn sys_faccessat2(dirfd: i32, path_ptr: u64, mode: i32, flags: i32) -> i64 {
    do_faccessat(dirfd, path_ptr, mode, flags)
}

// ============================================================================
// lstat, symlink, readlink, link syscalls
// ============================================================================

/// Too many symbolic links encountered
const ELOOP: i64 = -40;
/// File exists
const EEXIST: i64 = -17;
/// Operation not permitted
const EPERM: i64 = -1;
/// Cross-device link
const EXDEV: i64 = -18;

/// sys_lstat - get file status without following symlinks
///
/// Like stat(), but does not follow symbolic links.
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
/// * `statbuf` - User pointer to stat structure
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_lstat(path_ptr: u64, statbuf: u64) -> i64 {
    // Read path from user space with proper validation
    let path = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    // Validate stat buffer address
    if !Uaccess::access_ok(statbuf, core::mem::size_of::<Stat>()) {
        return EFAULT;
    }

    // Look up the path without following symlinks
    let mut flags = LookupFlags::open();
    flags.follow = false;

    let dentry = match lookup_path_flags(&path, flags) {
        Ok(d) => d,
        Err(FsError::NotFound) => return ENOENT,
        Err(FsError::NotADirectory) => return ENOTDIR,
        Err(FsError::TooManySymlinks) => return ELOOP,
        Err(_) => return EINVAL,
    };

    // Get the inode
    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    // Fill the stat structure
    let stat = fill_stat(&inode);

    // Copy to user space using put_user for the entire structure
    if put_user::<Uaccess, Stat>(statbuf, stat).is_err() {
        return EFAULT;
    }

    0
}

/// sys_symlink - create a symbolic link
///
/// Creates a symbolic link named linkpath pointing to target.
///
/// # Arguments
/// * `target_ptr` - User pointer to target path string
/// * `linkpath_ptr` - User pointer to link path string
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_symlink(target_ptr: u64, linkpath_ptr: u64) -> i64 {
    sys_symlinkat(target_ptr, AT_FDCWD, linkpath_ptr)
}

/// sys_symlinkat - create a symbolic link relative to directory fd
///
/// # Arguments
/// * `target_ptr` - User pointer to target path string
/// * `newdirfd` - Directory fd for linkpath, or AT_FDCWD
/// * `linkpath_ptr` - User pointer to link path string
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_symlinkat(target_ptr: u64, newdirfd: i32, linkpath_ptr: u64) -> i64 {
    // Read target from user space
    let target = match strncpy_from_user::<Uaccess>(target_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    // Read linkpath from user space
    let linkpath = match strncpy_from_user::<Uaccess>(linkpath_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    if target.is_empty() || linkpath.is_empty() {
        return ENOENT;
    }

    // Look up parent directory of the new symlink
    let (parent_dentry, name) = match lookup_parent_at(newdirfd, &linkpath) {
        Ok(p) => p,
        Err(e) => return e,
    };

    // Get parent inode
    let parent_inode = match parent_dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    // Lock parent directory (Linux i_rwsem pattern)
    parent_inode.inode_lock();

    // Check if name already exists (with lock held)
    if parent_dentry.lookup_child(&name).is_some() {
        unsafe { parent_inode.inode_unlock() };
        return EEXIST;
    }

    // Create the symlink
    let new_inode = match parent_inode.i_op.symlink(&parent_inode, &name, &target) {
        Ok(i) => i,
        Err(e) => {
            unsafe { parent_inode.inode_unlock() };
            return match e {
                FsError::AlreadyExists => EEXIST,
                FsError::PermissionDenied => EACCES,
                FsError::NotSupported => EPERM,
                _ => EINVAL,
            };
        }
    };

    // Create dentry for the symlink
    let new_dentry = alloc::sync::Arc::new(super::Dentry::new(
        name,
        Some(new_inode),
        parent_dentry.sb.clone(),
    ));
    new_dentry.set_parent(&parent_dentry);
    parent_dentry.add_child(new_dentry);

    // Unlock parent directory
    unsafe { parent_inode.inode_unlock() };

    0
}

/// sys_readlink - read value of a symbolic link
///
/// Reads the target of a symbolic link into a buffer.
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
/// * `buf_ptr` - User buffer to store the target
/// * `bufsiz` - Size of the buffer
///
/// # Returns
/// Number of bytes placed in buffer (not null-terminated), negative errno on error
pub fn sys_readlink(path_ptr: u64, buf_ptr: u64, bufsiz: u64) -> i64 {
    sys_readlinkat(AT_FDCWD, path_ptr, buf_ptr, bufsiz)
}

/// sys_readlinkat - read value of a symbolic link relative to directory fd
///
/// # Arguments
/// * `dirfd` - Directory fd for relative paths, or AT_FDCWD
/// * `path_ptr` - User pointer to path string
/// * `buf_ptr` - User buffer to store the target
/// * `bufsiz` - Size of the buffer
///
/// # Returns
/// Number of bytes placed in buffer (not null-terminated), negative errno on error
pub fn sys_readlinkat(dirfd: i32, path_ptr: u64, buf_ptr: u64, bufsiz: u64) -> i64 {
    // Read path from user space
    let path = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    let bufsiz = bufsiz as usize;
    if bufsiz == 0 {
        return EINVAL;
    }

    // Validate user buffer address
    if !Uaccess::access_ok(buf_ptr, bufsiz) {
        return EFAULT;
    }

    // Determine starting path for relative paths
    let start: Option<Path> = if path.starts_with('/') {
        None
    } else if dirfd == AT_FDCWD {
        crate::task::percpu::current_cwd()
    } else {
        let file = match current_fd_table().lock().get(dirfd) {
            Some(f) => f,
            None => return EBADF,
        };
        if !file.is_dir() {
            return ENOTDIR;
        }
        Path::from_dentry(file.dentry.clone())
    };

    // Look up the path without following the final symlink
    let mut flags = LookupFlags::open();
    flags.follow = false;

    let dentry = match lookup_path_at(start, &path, flags) {
        Ok(d) => d,
        Err(FsError::NotFound) => return ENOENT,
        Err(FsError::NotADirectory) => return ENOTDIR,
        Err(FsError::TooManySymlinks) => return ELOOP,
        Err(_) => return EINVAL,
    };

    // Get inode
    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    // Must be a symlink
    if !inode.mode().is_symlink() {
        return EINVAL;
    }

    // Read the symlink target
    let target = match inode.i_op.readlink(&inode) {
        Ok(t) => t,
        Err(FsError::NotSupported) => return EINVAL,
        Err(_) => return EINVAL,
    };

    // Copy to user buffer (without null terminator)
    let copy_len = core::cmp::min(target.len(), bufsiz);
    if copy_to_user::<Uaccess>(buf_ptr, &target.as_bytes()[..copy_len]).is_err() {
        return EFAULT;
    }

    copy_len as i64
}

/// sys_link - create a hard link
///
/// Creates a new name for an existing file.
///
/// # Arguments
/// * `oldpath_ptr` - User pointer to existing path
/// * `newpath_ptr` - User pointer to new path
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_link(oldpath_ptr: u64, newpath_ptr: u64) -> i64 {
    sys_linkat(AT_FDCWD, oldpath_ptr, AT_FDCWD, newpath_ptr, 0)
}

/// sys_linkat - create a hard link relative to directory fds
///
/// # Arguments
/// * `olddirfd` - Directory fd for oldpath, or AT_FDCWD
/// * `oldpath_ptr` - User pointer to existing path
/// * `newdirfd` - Directory fd for newpath, or AT_FDCWD
/// * `newpath_ptr` - User pointer to new path
/// * `flags` - AT_SYMLINK_FOLLOW to follow symlinks in oldpath
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_linkat(
    olddirfd: i32,
    oldpath_ptr: u64,
    newdirfd: i32,
    newpath_ptr: u64,
    flags: i32,
) -> i64 {
    // Read oldpath from user space
    let oldpath = match strncpy_from_user::<Uaccess>(oldpath_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    // Read newpath from user space
    let newpath = match strncpy_from_user::<Uaccess>(newpath_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    if oldpath.is_empty() || newpath.is_empty() {
        return ENOENT;
    }

    // AT_SYMLINK_FOLLOW (0x400) means follow symlinks in oldpath
    let follow = flags & 0x400 != 0;

    // Look up the target file
    let old_start: Option<Path> = if oldpath.starts_with('/') {
        None
    } else if olddirfd == AT_FDCWD {
        crate::task::percpu::current_cwd()
    } else {
        let file = match current_fd_table().lock().get(olddirfd) {
            Some(f) => f,
            None => return EBADF,
        };
        if !file.is_dir() {
            return ENOTDIR;
        }
        Path::from_dentry(file.dentry.clone())
    };

    let mut lookup_flags = LookupFlags::open();
    lookup_flags.follow = follow;

    let old_dentry = match lookup_path_at(old_start, &oldpath, lookup_flags) {
        Ok(d) => d,
        Err(FsError::NotFound) => return ENOENT,
        Err(FsError::NotADirectory) => return ENOTDIR,
        Err(FsError::TooManySymlinks) => return ELOOP,
        Err(_) => return EINVAL,
    };

    let old_inode = match old_dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    // Cannot hard link directories
    if old_inode.mode().is_dir() {
        return EPERM;
    }

    // Look up parent directory of the new link
    let (parent_dentry, name) = match lookup_parent_at(newdirfd, &newpath) {
        Ok(p) => p,
        Err(e) => return e,
    };

    // Check same filesystem
    let old_sb = old_dentry.superblock();
    let new_sb = parent_dentry.superblock();
    if old_sb.map(|s| s.dev_id) != new_sb.map(|s| s.dev_id) {
        return EXDEV;
    }

    // Get parent inode
    let parent_inode = match parent_dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    // Lock parent directory (Linux i_rwsem pattern)
    parent_inode.inode_lock();

    // Check if name already exists (with lock held)
    if parent_dentry.lookup_child(&name).is_some() {
        unsafe { parent_inode.inode_unlock() };
        return EEXIST;
    }

    // Create the hard link
    let result = parent_inode.i_op.link(&parent_inode, &name, &old_inode);

    match result {
        Ok(()) => {
            // Create dentry for the new link
            let new_dentry = alloc::sync::Arc::new(super::Dentry::new(
                name,
                Some(old_inode),
                parent_dentry.sb.clone(),
            ));
            new_dentry.set_parent(&parent_dentry);
            parent_dentry.add_child(new_dentry);
            unsafe { parent_inode.inode_unlock() };
            0
        }
        Err(e) => {
            unsafe { parent_inode.inode_unlock() };
            match e {
                FsError::AlreadyExists => EEXIST,
                FsError::PermissionDenied => EACCES,
                FsError::NotSupported => EPERM,
                _ => EINVAL,
            }
        }
    }
}

// ============================================================================
// rename, renameat, renameat2 syscalls
// ============================================================================

/// sys_rename - rename a file
///
/// # Arguments
/// * `oldpath_ptr` - User pointer to existing path
/// * `newpath_ptr` - User pointer to new path
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_rename(oldpath_ptr: u64, newpath_ptr: u64) -> i64 {
    sys_renameat2(AT_FDCWD, oldpath_ptr, AT_FDCWD, newpath_ptr, 0)
}

/// sys_renameat - rename a file relative to directory fds
///
/// # Arguments
/// * `olddirfd` - Directory fd for oldpath, or AT_FDCWD
/// * `oldpath_ptr` - User pointer to existing path
/// * `newdirfd` - Directory fd for newpath, or AT_FDCWD
/// * `newpath_ptr` - User pointer to new path
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_renameat(olddirfd: i32, oldpath_ptr: u64, newdirfd: i32, newpath_ptr: u64) -> i64 {
    sys_renameat2(olddirfd, oldpath_ptr, newdirfd, newpath_ptr, 0)
}

/// sys_renameat2 - rename a file with flags
///
/// # Arguments
/// * `olddirfd` - Directory fd for oldpath, or AT_FDCWD
/// * `oldpath_ptr` - User pointer to existing path
/// * `newdirfd` - Directory fd for newpath, or AT_FDCWD
/// * `newpath_ptr` - User pointer to new path
/// * `flags` - RENAME_NOREPLACE, RENAME_EXCHANGE, etc.
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_renameat2(
    olddirfd: i32,
    oldpath_ptr: u64,
    newdirfd: i32,
    newpath_ptr: u64,
    flags: u32,
) -> i64 {
    // Read oldpath from user space
    let oldpath = match strncpy_from_user::<Uaccess>(oldpath_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    // Read newpath from user space
    let newpath = match strncpy_from_user::<Uaccess>(newpath_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    if oldpath.is_empty() || newpath.is_empty() {
        return ENOENT;
    }

    // Extract final components for validation
    let old_basename = oldpath.rsplit('/').next().unwrap_or(&oldpath);
    let new_basename = newpath.rsplit('/').next().unwrap_or(&newpath);

    // Cannot rename "." or ".." - these are special directory entries
    if old_basename == "." || old_basename == ".." {
        return EINVAL;
    }
    // Cannot rename TO "." or ".." either
    if new_basename == "." || new_basename == ".." {
        return EINVAL;
    }

    // Look up parent of oldpath and get the filename
    let (old_parent_dentry, old_name) = match lookup_parent_at(olddirfd, &oldpath) {
        Ok(p) => p,
        Err(e) => return e,
    };

    // Look up parent of newpath and get the filename
    let (new_parent_dentry, new_name) = match lookup_parent_at(newdirfd, &newpath) {
        Ok(p) => p,
        Err(e) => return e,
    };

    // Check same filesystem
    let old_sb = old_parent_dentry.superblock();
    let new_sb = new_parent_dentry.superblock();
    if old_sb.map(|s| s.dev_id) != new_sb.map(|s| s.dev_id) {
        return EXDEV;
    }

    // Get parent inodes
    let old_parent_inode = match old_parent_dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    let new_parent_inode = match new_parent_dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    // Lock directories for rename (Linux lock_rename pattern)
    // This ensures proper lock ordering to prevent deadlocks:
    // - If one directory is ancestor of other: lock ancestor first
    // - Otherwise: lock by address order
    let _trap = lock_rename(&old_parent_dentry, &new_parent_dentry);

    // Look up the source dentry for cycle detection and same-file check
    let old_dentry = old_parent_dentry.lookup_child(&old_name);

    // Look up target dentry for same-file check
    let new_dentry = new_parent_dentry.lookup_child(&new_name);

    // Same-inode check: if source and target are the same file, return success
    // (Linux vfs_rename: "if (source == target) return 0;")
    if let Some(ref src_dentry) = old_dentry
        && let Some(ref dst_dentry) = new_dentry
        && let (Some(src_inode), Some(dst_inode)) = (src_dentry.get_inode(), dst_dentry.get_inode())
        && src_inode.ino == dst_inode.ino
    {
        unlock_rename(&old_parent_dentry, &new_parent_dentry);
        return 0;
    }

    // Cycle detection: prevent moving a directory into its own subtree
    // This would create an unreachable directory loop
    if let Some(ref src_dentry) = old_dentry
        && let Some(src_inode) = src_dentry.get_inode()
        && src_inode.mode().is_dir()
        // Check if new_parent is a subdirectory of source
        // If so, this rename would create a cycle
        && is_subdir(&new_parent_dentry, src_dentry)
    {
        unlock_rename(&old_parent_dentry, &new_parent_dentry);
        return EINVAL;
    }

    // Perform the rename via inode ops
    let result = old_parent_inode.i_op.rename(
        &old_parent_inode,
        &old_name,
        &new_parent_inode,
        &new_name,
        flags,
    );

    // Unlock directories
    unlock_rename(&old_parent_dentry, &new_parent_dentry);

    // Handle result
    match result {
        Ok(()) => {}
        Err(FsError::NotFound) => return ENOENT,
        Err(FsError::AlreadyExists) => return EEXIST,
        Err(FsError::DirectoryNotEmpty) => return ENOTEMPTY,
        Err(FsError::NotSupported) => return EINVAL,
        Err(FsError::InvalidArgument) => return EINVAL,
        Err(_) => return EINVAL,
    }

    // Update dentry cache:
    // Remove old dentry from old parent - new lookup will re-create it
    // For cross-directory renames or name changes, also remove target dentry
    old_parent_dentry.remove_child(&old_name);
    new_parent_dentry.remove_child(&new_name);

    0
}

// ============================================================================
// mount, umount2 syscalls
// ============================================================================

/// Block device required
pub const ENOTBLK: i64 = -15;
/// Resource busy
pub const EBUSY: i64 = -16;
/// No such device or filesystem type
pub const ENODEV: i64 = -19;

/// sys_mount - mount a filesystem
///
/// # Arguments
/// * `source_ptr` - User pointer to device/source path (e.g., "/dev/rd1" for device-backed fs)
/// * `target_ptr` - User pointer to mount point path
/// * `fstype_ptr` - User pointer to filesystem type name string
/// * `flags` - Mount flags (MS_* flags, currently ignored)
/// * `_data` - Filesystem-specific data (currently unused)
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_mount(
    source_ptr: u64,
    target_ptr: u64,
    fstype_ptr: u64,
    _flags: u64,
    _data: u64,
) -> i64 {
    // Read source device path from user space (may be empty for pseudo-fs)
    let source = if source_ptr != 0 {
        strncpy_from_user::<Uaccess>(source_ptr, PATH_MAX).unwrap_or_default()
    } else {
        alloc::string::String::new()
    };

    // Read filesystem type from user space
    let fstype = match strncpy_from_user::<Uaccess>(fstype_ptr, PATH_MAX) {
        Ok(s) => s,
        Err(_) => return EFAULT,
    };

    // Read target path from user space
    let target = match strncpy_from_user::<Uaccess>(target_ptr, PATH_MAX) {
        Ok(s) => s,
        Err(_) => return EFAULT,
    };

    // Look up the filesystem type
    let fs_type = match super::superblock::find_filesystem(&fstype) {
        Some(ft) => ft,
        None => return ENODEV,
    };

    // Look up the mount point (must be a directory)
    let mountpoint_dentry = match lookup_path_flags(&target, LookupFlags::opendir()) {
        Ok(d) => d,
        Err(FsError::NotFound) => return ENOENT,
        Err(FsError::NotADirectory) => return ENOTDIR,
        Err(_) => return EINVAL,
    };

    // Verify it's a directory
    if let Some(inode) = mountpoint_dentry.get_inode() {
        if !inode.mode().is_dir() {
            return ENOTDIR;
        }
    } else {
        return ENOENT;
    }

    // Choose mount method based on filesystem type
    if fs_type.mount_dev.is_some() && !source.is_empty() {
        // Device-backed filesystem (vfat, ext4, etc.)
        match super::mount::do_mount_dev(fs_type, &source, Some(mountpoint_dentry)) {
            Ok(_mount) => 0,
            Err(FsError::NotABlockDevice) => ENOTBLK,
            Err(FsError::NoDevice) => ENODEV,
            Err(FsError::Busy) => EBUSY,
            Err(_) => EINVAL,
        }
    } else {
        // Pseudo-filesystem (ramfs, procfs, etc.)
        match super::mount::do_mount(fs_type, Some(mountpoint_dentry)) {
            Ok(_mount) => 0,
            Err(FsError::Busy) => EBUSY,
            Err(FsError::NoDevice) => ENODEV,
            Err(_) => EINVAL,
        }
    }
}

/// sys_umount2 - unmount a filesystem
///
/// # Arguments
/// * `target_ptr` - User pointer to mount point path
/// * `flags` - Umount flags (MNT_FORCE, MNT_DETACH, etc.)
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_umount2(target_ptr: u64, flags: i32) -> i64 {
    // Read target path from user space
    let target = match strncpy_from_user::<Uaccess>(target_ptr, PATH_MAX) {
        Ok(s) => s,
        Err(_) => return EFAULT,
    };

    // Set up lookup flags - respect UMOUNT_NOFOLLOW
    let mut lookup_flags = LookupFlags::open();
    if flags & super::mount::umount_flags::UMOUNT_NOFOLLOW != 0 {
        lookup_flags.follow = false;
    }

    // Look up the target path
    let target_dentry = match lookup_path_flags(&target, lookup_flags) {
        Ok(d) => d,
        Err(FsError::NotFound) => return ENOENT,
        Err(FsError::NotADirectory) => return ENOTDIR,
        Err(_) => return EINVAL,
    };

    // Find the mount at this path
    let mount = match super::mount::current_mnt_ns().find_mount_at(&target_dentry) {
        Some(m) => m,
        None => return EINVAL, // Not a mount point
    };

    // Perform the unmount
    match super::mount::do_umount(mount, flags) {
        Ok(()) => 0,
        Err(FsError::Busy) => EBUSY,
        Err(FsError::InvalidArgument) => EINVAL, // Can't unmount root
        Err(_) => EINVAL,
    }
}

/// Helper to look up parent directory for creating new entries
///
/// Returns the parent dentry and the final component name.
fn lookup_parent_at(
    dirfd: i32,
    path: &str,
) -> Result<(alloc::sync::Arc<super::Dentry>, alloc::string::String), i64> {
    // Find the last path component
    let path = path.trim_end_matches('/');
    if path.is_empty() {
        return Err(EINVAL);
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
        return Err(EINVAL);
    }

    // Determine starting path
    let start: Option<Path> = if parent_path.starts_with('/') {
        None
    } else if dirfd == AT_FDCWD {
        crate::task::percpu::current_cwd()
    } else {
        let file = match current_fd_table().lock().get(dirfd) {
            Some(f) => f,
            None => return Err(EBADF),
        };
        if !file.is_dir() {
            return Err(ENOTDIR);
        }
        Path::from_dentry(file.dentry.clone())
    };

    // Look up parent directory
    let parent_dentry = match lookup_path_at(start, parent_path, LookupFlags::opendir()) {
        Ok(d) => d,
        Err(FsError::NotFound) => return Err(ENOENT),
        Err(FsError::NotADirectory) => return Err(ENOTDIR),
        Err(FsError::TooManySymlinks) => return Err(ELOOP),
        Err(_) => return Err(EINVAL),
    };

    Ok((parent_dentry, alloc::string::String::from(name)))
}

/// sys_mkdir - create a directory
///
/// Creates a new directory at the given path.
///
/// # Arguments
/// * `pathname_ptr` - User pointer to path string
/// * `mode` - Permission bits for the new directory
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_mkdir(pathname_ptr: u64, mode: u32) -> i64 {
    sys_mkdirat(AT_FDCWD, pathname_ptr, mode)
}

/// sys_mkdirat - create a directory relative to directory fd
///
/// # Arguments
/// * `dirfd` - Directory fd for relative paths, or AT_FDCWD
/// * `pathname_ptr` - User pointer to path string
/// * `mode` - Permission bits for the new directory
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_mkdirat(dirfd: i32, pathname_ptr: u64, mode: u32) -> i64 {
    use super::InodeMode;

    // Read path from user space
    let path = match strncpy_from_user::<Uaccess>(pathname_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    if path.is_empty() {
        return ENOENT;
    }

    // Look up parent directory
    let (parent_dentry, name) = match lookup_parent_at(dirfd, &path) {
        Ok(p) => p,
        Err(e) => return e,
    };

    // Get parent inode
    let parent_inode = match parent_dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    // Lock parent directory (Linux i_rwsem pattern)
    parent_inode.inode_lock();

    // Check if name already exists (with lock held)
    if parent_dentry.lookup_child(&name).is_some() {
        unsafe { parent_inode.inode_unlock() };
        return EEXIST;
    }

    // Create directory mode with requested permissions (masked by typical umask of 0o22)
    let dir_mode = InodeMode::directory((mode & 0o7777) as u16);

    // Create the directory
    let new_inode = match parent_inode.i_op.mkdir(&parent_inode, &name, dir_mode) {
        Ok(i) => i,
        Err(e) => {
            unsafe { parent_inode.inode_unlock() };
            return match e {
                FsError::AlreadyExists => EEXIST,
                FsError::PermissionDenied => EACCES,
                FsError::NotSupported => EPERM,
                _ => EINVAL,
            };
        }
    };

    // Create dentry for the directory
    let new_dentry = alloc::sync::Arc::new(super::Dentry::new(
        name.clone(),
        Some(new_inode),
        parent_dentry.sb.clone(),
    ));
    new_dentry.set_parent(&parent_dentry);
    parent_dentry.add_child(new_dentry);

    // Unlock parent directory
    unsafe { parent_inode.inode_unlock() };

    0
}

/// sys_rmdir - remove a directory
///
/// Removes an empty directory at the given path.
///
/// # Arguments
/// * `pathname_ptr` - User pointer to path string
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_rmdir(pathname_ptr: u64) -> i64 {
    // Read path from user space
    let path = match strncpy_from_user::<Uaccess>(pathname_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    if path.is_empty() {
        return ENOENT;
    }

    // Look up parent directory and name
    let (parent_dentry, name) = match lookup_parent_at(AT_FDCWD, &path) {
        Ok(p) => p,
        Err(e) => return e,
    };

    // Get parent inode
    let parent_inode = match parent_dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    // Lock parent directory (Linux i_rwsem pattern)
    parent_inode.inode_lock();

    // Check that target exists (with lock held)
    let target_dentry = match parent_dentry.lookup_child(&name) {
        Some(d) => d,
        None => {
            unsafe { parent_inode.inode_unlock() };
            return ENOENT;
        }
    };

    // Verify it's a directory
    if let Some(target_inode) = target_dentry.get_inode()
        && !target_inode.mode().is_dir()
    {
        unsafe { parent_inode.inode_unlock() };
        return ENOTDIR;
    }

    // Call rmdir on the parent
    let result = parent_inode.i_op.rmdir(&parent_inode, &name);

    match result {
        Ok(()) => {
            // Remove dentry from parent's children
            parent_dentry.remove_child(&name);
            unsafe { parent_inode.inode_unlock() };
            0
        }
        Err(e) => {
            unsafe { parent_inode.inode_unlock() };
            match e {
                FsError::NotFound => ENOENT,
                FsError::NotADirectory => ENOTDIR,
                FsError::DirectoryNotEmpty => ENOTEMPTY,
                FsError::PermissionDenied => EACCES,
                FsError::Busy => -16, // EBUSY
                _ => EINVAL,
            }
        }
    }
}

/// sys_mknod - create a special or ordinary file
///
/// Creates a filesystem node (file, device special file, or named pipe).
///
/// # Arguments
/// * `pathname_ptr` - User pointer to path string
/// * `mode` - File type and permissions
/// * `dev` - Device number (for device files)
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_mknod(pathname_ptr: u64, mode: u32, dev: u64) -> i64 {
    sys_mknodat(AT_FDCWD, pathname_ptr, mode, dev)
}

/// sys_mknodat - create a special or ordinary file relative to directory fd
///
/// # Arguments
/// * `dirfd` - Directory fd for relative paths, or AT_FDCWD
/// * `pathname_ptr` - User pointer to path string
/// * `mode` - File type and permissions
/// * `dev` - Device number (for device files)
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_mknodat(dirfd: i32, pathname_ptr: u64, mode: u32, _dev: u64) -> i64 {
    use super::InodeMode;

    // File type bits from mode
    const S_IFREG: u32 = 0o100000;
    const S_IFCHR: u32 = 0o020000;
    const S_IFBLK: u32 = 0o060000;
    const S_IFIFO: u32 = 0o010000;
    const S_IFSOCK: u32 = 0o140000;
    const S_IFMT: u32 = 0o170000;

    // Read path from user space
    let path = match strncpy_from_user::<Uaccess>(pathname_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    if path.is_empty() {
        return ENOENT;
    }

    // Look up parent directory
    let (parent_dentry, name) = match lookup_parent_at(dirfd, &path) {
        Ok(p) => p,
        Err(e) => return e,
    };

    // Get parent inode
    let parent_inode = match parent_dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    // Lock parent directory (Linux i_rwsem pattern)
    parent_inode.inode_lock();

    // Check if name already exists (with lock held)
    if parent_dentry.lookup_child(&name).is_some() {
        unsafe { parent_inode.inode_unlock() };
        return EEXIST;
    }

    // Determine file type and create appropriate mode
    let file_type = mode & S_IFMT;
    let perm = (mode & 0o7777) as u16;

    let inode_mode = match file_type {
        S_IFREG | 0 => InodeMode::regular(perm), // Regular file (default if no type)
        S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK => {
            // Device nodes, FIFOs, sockets - for now just create as regular
            // Full device node support would require additional infrastructure
            InodeMode::regular(perm)
        }
        _ => {
            unsafe { parent_inode.inode_unlock() };
            return EINVAL; // Invalid type
        }
    };

    // Create the file using create() operation
    let new_inode = match parent_inode.i_op.create(&parent_inode, &name, inode_mode) {
        Ok(i) => i,
        Err(e) => {
            unsafe { parent_inode.inode_unlock() };
            return match e {
                FsError::AlreadyExists => EEXIST,
                FsError::PermissionDenied => EACCES,
                FsError::NotSupported => EPERM,
                _ => EINVAL,
            };
        }
    };

    // Create dentry for the new file
    let new_dentry = alloc::sync::Arc::new(super::Dentry::new(
        name.clone(),
        Some(new_inode),
        parent_dentry.sb.clone(),
    ));
    new_dentry.set_parent(&parent_dentry);
    parent_dentry.add_child(new_dentry);

    // Unlock parent directory
    unsafe { parent_inode.inode_unlock() };

    0
}

/// sys_unlink - delete a name from the filesystem
///
/// Removes a directory entry for a file. If this was the last link to the file
/// and no processes have it open, the file is deleted.
///
/// # Arguments
/// * `pathname_ptr` - User pointer to path string
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_unlink(pathname_ptr: u64) -> i64 {
    sys_unlinkat(AT_FDCWD, pathname_ptr, 0)
}

/// AT_REMOVEDIR flag for unlinkat - perform rmdir instead of unlink
const AT_REMOVEDIR: i32 = 0x200;

/// sys_unlinkat - delete a name relative to a directory file descriptor
///
/// If AT_REMOVEDIR is specified in flags, performs rmdir instead of unlink.
///
/// # Arguments
/// * `dirfd` - Directory file descriptor, or AT_FDCWD for current directory
/// * `pathname_ptr` - User pointer to path string
/// * `flags` - Flags (AT_REMOVEDIR to remove directory)
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_unlinkat(dirfd: i32, pathname_ptr: u64, flags: i32) -> i64 {
    // Read path from user space
    let path = match strncpy_from_user::<Uaccess>(pathname_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    if path.is_empty() {
        return ENOENT;
    }

    // If AT_REMOVEDIR is set, perform rmdir instead
    if flags & AT_REMOVEDIR != 0 {
        // For AT_REMOVEDIR, delegate to rmdir-like logic
        return sys_unlinkat_rmdir(dirfd, &path);
    }

    // Look up parent directory and name
    let (parent_dentry, name) = match lookup_parent_at(dirfd, &path) {
        Ok(p) => p,
        Err(e) => return e,
    };

    // Get parent inode
    let parent_inode = match parent_dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    // Lock parent directory (Linux i_rwsem pattern)
    parent_inode.inode_lock();

    // Check that target exists (with lock held)
    let target_dentry = match parent_dentry.lookup_child(&name) {
        Some(d) => d,
        None => {
            unsafe { parent_inode.inode_unlock() };
            return ENOENT;
        }
    };

    // Verify it's NOT a directory (use rmdir for directories)
    if let Some(target_inode) = target_dentry.get_inode()
        && target_inode.mode().is_dir()
    {
        unsafe { parent_inode.inode_unlock() };
        return EISDIR;
    }

    // Call unlink on the parent
    let result = parent_inode.i_op.unlink(&parent_inode, &name);

    match result {
        Ok(()) => {
            // Remove dentry from parent's children
            parent_dentry.remove_child(&name);
            unsafe { parent_inode.inode_unlock() };
            0
        }
        Err(e) => {
            unsafe { parent_inode.inode_unlock() };
            match e {
                FsError::NotFound => ENOENT,
                FsError::PermissionDenied => EACCES,
                FsError::IsADirectory => EISDIR,
                _ => EINVAL,
            }
        }
    }
}

/// Helper for unlinkat with AT_REMOVEDIR flag
fn sys_unlinkat_rmdir(dirfd: i32, path: &str) -> i64 {
    // Look up parent directory and name
    let (parent_dentry, name) = match lookup_parent_at(dirfd, path) {
        Ok(p) => p,
        Err(e) => return e,
    };

    // Get parent inode
    let parent_inode = match parent_dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    // Lock parent directory (Linux i_rwsem pattern)
    parent_inode.inode_lock();

    // Check that target exists (with lock held)
    let target_dentry = match parent_dentry.lookup_child(&name) {
        Some(d) => d,
        None => {
            unsafe { parent_inode.inode_unlock() };
            return ENOENT;
        }
    };

    // Verify it's a directory
    if let Some(target_inode) = target_dentry.get_inode()
        && !target_inode.mode().is_dir()
    {
        unsafe { parent_inode.inode_unlock() };
        return ENOTDIR;
    }

    // Call rmdir on the parent
    let result = parent_inode.i_op.rmdir(&parent_inode, &name);

    match result {
        Ok(()) => {
            // Remove dentry from parent's children
            parent_dentry.remove_child(&name);
            unsafe { parent_inode.inode_unlock() };
            0
        }
        Err(e) => {
            unsafe { parent_inode.inode_unlock() };
            match e {
                FsError::NotFound => ENOENT,
                FsError::NotADirectory => ENOTDIR,
                FsError::DirectoryNotEmpty => ENOTEMPTY,
                FsError::PermissionDenied => EACCES,
                FsError::Busy => -16, // EBUSY
                _ => EINVAL,
            }
        }
    }
}

// =============================================================================
// Permission modification syscalls
// =============================================================================

/// sys_fchmodat - change file permissions relative to directory fd
///
/// This is the core implementation used by chmod and fchmodat.
pub fn sys_fchmodat(dirfd: i32, pathname: u64, mode: u32, _flags: i32) -> i64 {
    // Copy path from user space
    let path_str = match strncpy_from_user::<Uaccess>(pathname, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    // Determine starting path for relative paths
    let start: Option<Path> = if path_str.starts_with('/') {
        // Absolute path - lookup_path_at will use root
        None
    } else if dirfd == AT_FDCWD {
        // Use current working directory
        crate::task::percpu::current_cwd()
    } else {
        // Use directory from file descriptor
        let file = match current_fd_table().lock().get(dirfd) {
            Some(f) => f,
            None => return EBADF,
        };
        if !file.is_dir() {
            return ENOTDIR;
        }
        Path::from_dentry(file.dentry.clone())
    };

    // Note: fchmodat follows symlinks by default (use AT_SYMLINK_NOFOLLOW to not follow)
    // Using open() flags which follow symlinks
    let dentry = match lookup_path_at(start, &path_str, LookupFlags::open()) {
        Ok(d) => d,
        Err(FsError::NotFound) => return ENOENT,
        Err(FsError::NotADirectory) => return ENOTDIR,
        Err(_) => return EINVAL,
    };

    // Get the inode
    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    // Update the permission bits (only lower 12 bits: rwxrwxrwx + setuid/setgid/sticky)
    inode.set_mode_perm((mode & 0o7777) as u16);

    0
}

/// sys_chmod - change file permissions
///
/// Implemented in terms of fchmodat(AT_FDCWD, pathname, mode, 0)
pub fn sys_chmod(pathname: u64, mode: u32) -> i64 {
    sys_fchmodat(AT_FDCWD, pathname, mode, 0)
}

/// sys_fchmod - change file permissions by fd
pub fn sys_fchmod(fd: i32, mode: u32) -> i64 {
    // Get the file from fd
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Get the inode
    let inode = match file.get_inode() {
        Some(i) => i,
        None => return EBADF,
    };

    // Update the permission bits
    inode.set_mode_perm((mode & 0o7777) as u16);

    0
}

// =============================================================================
// Ownership modification syscalls
// =============================================================================

/// sys_fchownat - change file ownership relative to directory fd
///
/// This is the core implementation used by chown, lchown, and fchownat.
/// A uid or gid of -1 (0xFFFFFFFF) means "don't change".
pub fn sys_fchownat(dirfd: i32, pathname: u64, owner: u32, group: u32, flags: i32) -> i64 {
    // Copy path from user space
    let path_str = match strncpy_from_user::<Uaccess>(pathname, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    // Determine starting path for relative paths
    let start: Option<Path> = if path_str.starts_with('/') {
        // Absolute path - lookup_path_at will use root
        None
    } else if dirfd == AT_FDCWD {
        // Use current working directory
        crate::task::percpu::current_cwd()
    } else {
        // Use directory from file descriptor
        let file = match current_fd_table().lock().get(dirfd) {
            Some(f) => f,
            None => return EBADF,
        };
        if !file.is_dir() {
            return ENOTDIR;
        }
        Path::from_dentry(file.dentry.clone())
    };

    // Determine lookup flags - AT_SYMLINK_NOFOLLOW means don't follow symlinks
    let lookup_flags = if (flags & AT_SYMLINK_NOFOLLOW) != 0 {
        LookupFlags {
            follow: false, // Don't follow final symlink
            ..LookupFlags::open()
        }
    } else {
        LookupFlags::open() // Follow symlinks (default for chown)
    };

    let dentry = match lookup_path_at(start, &path_str, lookup_flags) {
        Ok(d) => d,
        Err(FsError::NotFound) => return ENOENT,
        Err(FsError::NotADirectory) => return ENOTDIR,
        Err(_) => return EINVAL,
    };

    // Get the inode
    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    // Update owner if specified (owner != -1)
    if owner != 0xFFFFFFFF {
        inode.set_uid(owner);
    }

    // Update group if specified (group != -1)
    if group != 0xFFFFFFFF {
        inode.set_gid(group);
    }

    0
}

/// sys_chown - change file ownership
///
/// Follows symlinks. Implemented in terms of fchownat.
pub fn sys_chown(pathname: u64, owner: u32, group: u32) -> i64 {
    sys_fchownat(AT_FDCWD, pathname, owner, group, 0)
}

/// sys_lchown - change ownership of a symbolic link
///
/// Does NOT follow symlinks (operates on the link itself).
pub fn sys_lchown(pathname: u64, owner: u32, group: u32) -> i64 {
    sys_fchownat(AT_FDCWD, pathname, owner, group, AT_SYMLINK_NOFOLLOW)
}

/// sys_fchown - change file ownership by fd
pub fn sys_fchown(fd: i32, owner: u32, group: u32) -> i64 {
    // Get the file from fd
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Get the inode
    let inode = match file.get_inode() {
        Some(i) => i,
        None => return EBADF,
    };

    // Update owner if specified (owner != -1)
    if owner != 0xFFFFFFFF {
        inode.set_uid(owner);
    }

    // Update group if specified (group != -1)
    if group != 0xFFFFFFFF {
        inode.set_gid(group);
    }

    0
}

// =============================================================================
// File creation mask
// =============================================================================

/// sys_umask - set file creation mask
///
/// Sets the calling process's file mode creation mask (umask).
/// The umask is used by open(), mkdir(), and other file creation syscalls
/// to modify the permissions on newly created files.
///
/// # Arguments
/// * `mask` - New umask value (only the permission bits are used)
///
/// # Returns
/// The previous value of the umask.
pub fn sys_umask(mask: u32) -> i64 {
    // Only use lower 9 bits (standard permission bits)
    // Linux also allows setuid/setgid/sticky bits in umask
    let new_mask = (mask & 0o7777) as u16;

    if let Some(fs) = crate::task::percpu::current_fs() {
        fs.set_umask(new_mask) as i64
    } else {
        // Fallback: return typical default umask
        0o022
    }
}

// =============================================================================
// Timestamp modification syscalls
// =============================================================================

/// Special nsec value: set time to current time
const UTIME_NOW: i64 = 0x3fffffff;
/// Special nsec value: don't change this time
const UTIME_OMIT: i64 = 0x3ffffffe;

/// Userspace timespec structure (matches Linux)
#[repr(C)]
struct UserTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

/// Get current time from timekeeper
fn current_time() -> crate::time::Timespec {
    use crate::time::TIMEKEEPER;
    TIMEKEEPER.current_time()
}

/// sys_utimensat - change file timestamps with nanosecond precision
///
/// # Arguments
/// * `dirfd` - Directory file descriptor (or AT_FDCWD)
/// * `pathname` - Path to file (can be NULL if dirfd refers to a file)
/// * `times` - Pointer to array of 2 timespec: [atime, mtime], or NULL for current time
/// * `flags` - AT_SYMLINK_NOFOLLOW to not follow symlinks
///
/// # Special tv_nsec values
/// * UTIME_NOW (0x3fffffff): set to current time
/// * UTIME_OMIT (0x3ffffffe): don't change this timestamp
pub fn sys_utimensat(dirfd: i32, pathname: u64, times: u64, flags: i32) -> i64 {
    // Handle the case where pathname is NULL (operate on dirfd itself)
    let inode = if pathname == 0 {
        // pathname is NULL - operate on the file referred to by dirfd
        if dirfd == AT_FDCWD {
            return EINVAL; // Can't use NULL pathname with AT_FDCWD
        }
        let file = match current_fd_table().lock().get(dirfd) {
            Some(f) => f,
            None => return EBADF,
        };
        match file.get_inode() {
            Some(i) => i,
            None => return EBADF,
        }
    } else {
        // Copy path from user space
        let path_str = match strncpy_from_user::<Uaccess>(pathname, PATH_MAX) {
            Ok(p) => p,
            Err(_) => return EFAULT,
        };

        // Determine starting path for relative paths
        let start: Option<Path> = if path_str.starts_with('/') {
            None
        } else if dirfd == AT_FDCWD {
            crate::task::percpu::current_cwd()
        } else {
            let file = match current_fd_table().lock().get(dirfd) {
                Some(f) => f,
                None => return EBADF,
            };
            if !file.is_dir() {
                return ENOTDIR;
            }
            Path::from_dentry(file.dentry.clone())
        };

        // Determine lookup flags
        let lookup_flags = if (flags & AT_SYMLINK_NOFOLLOW) != 0 {
            LookupFlags {
                follow: false,
                ..LookupFlags::open()
            }
        } else {
            LookupFlags::open()
        };

        let dentry = match lookup_path_at(start, &path_str, lookup_flags) {
            Ok(d) => d,
            Err(FsError::NotFound) => return ENOENT,
            Err(FsError::NotADirectory) => return ENOTDIR,
            Err(_) => return EINVAL,
        };

        match dentry.get_inode() {
            Some(i) => i,
            None => return ENOENT,
        }
    };

    // Get current time for UTIME_NOW
    let now = current_time();

    // Determine new atime and mtime
    let (new_atime, new_mtime) = if times == 0 {
        // NULL times - set both to current time
        (Some(now), Some(now))
    } else {
        // Read the two timespec values from user space
        let size = core::mem::size_of::<[UserTimespec; 2]>();
        if !Uaccess::access_ok(times, size) {
            return EFAULT;
        }
        let ts: [UserTimespec; 2] = unsafe {
            Uaccess::user_access_begin();
            let val = core::ptr::read(times as *const [UserTimespec; 2]);
            Uaccess::user_access_end();
            val
        };

        // Process atime
        let atime = if ts[0].tv_nsec == UTIME_OMIT {
            None // Don't change
        } else if ts[0].tv_nsec == UTIME_NOW {
            Some(now)
        } else {
            Some(crate::time::Timespec {
                sec: ts[0].tv_sec,
                nsec: ts[0].tv_nsec as u32,
            })
        };

        // Process mtime
        let mtime = if ts[1].tv_nsec == UTIME_OMIT {
            None // Don't change
        } else if ts[1].tv_nsec == UTIME_NOW {
            Some(now)
        } else {
            Some(crate::time::Timespec {
                sec: ts[1].tv_sec,
                nsec: ts[1].tv_nsec as u32,
            })
        };

        (atime, mtime)
    };

    // Apply the changes with inode lock held (Linux i_rwsem pattern)
    // Caller must hold inode.lock when modifying timestamps
    {
        let _guard = inode.lock.write();
        if let Some(atime) = new_atime {
            inode.set_atime(atime);
        }
        if let Some(mtime) = new_mtime {
            inode.set_mtime(mtime);
        }

        // Update ctime (metadata change time) to current time
        inode.set_ctime(now);
    }

    0
}

/// sys_utimes - change file timestamps (microsecond precision)
///
/// Legacy syscall - implemented in terms of utimensat.
/// times is array of 2 timeval: [atime, mtime]
pub fn sys_utimes(pathname: u64, times: u64) -> i64 {
    if times == 0 {
        // NULL times - set to current time
        return sys_utimensat(AT_FDCWD, pathname, 0, 0);
    }

    // timeval structure (microseconds)
    #[repr(C)]
    struct Timeval {
        tv_sec: i64,
        tv_usec: i64,
    }

    // Read the two timeval values
    let size = core::mem::size_of::<[Timeval; 2]>();
    if !Uaccess::access_ok(times, size) {
        return EFAULT;
    }
    let tv: [Timeval; 2] = unsafe {
        Uaccess::user_access_begin();
        let val = core::ptr::read(times as *const [Timeval; 2]);
        Uaccess::user_access_end();
        val
    };

    // Convert timeval to timespec (microseconds to nanoseconds)
    let ts: [UserTimespec; 2] = [
        UserTimespec {
            tv_sec: tv[0].tv_sec,
            tv_nsec: tv[0].tv_usec * 1000,
        },
        UserTimespec {
            tv_sec: tv[1].tv_sec,
            tv_nsec: tv[1].tv_usec * 1000,
        },
    ];

    // Get inode and apply directly (can't easily pass converted struct to utimensat)
    let path_str = match strncpy_from_user::<Uaccess>(pathname, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    let start = crate::task::percpu::current_cwd();
    let dentry = match lookup_path_at(start, &path_str, LookupFlags::open()) {
        Ok(d) => d,
        Err(FsError::NotFound) => return ENOENT,
        Err(FsError::NotADirectory) => return ENOTDIR,
        Err(_) => return EINVAL,
    };

    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    let now = current_time();

    // Apply timestamps with inode lock held (Linux i_rwsem pattern)
    {
        let _guard = inode.lock.write();
        inode.set_atime(crate::time::Timespec {
            sec: ts[0].tv_sec,
            nsec: ts[0].tv_nsec as u32,
        });
        inode.set_mtime(crate::time::Timespec {
            sec: ts[1].tv_sec,
            nsec: ts[1].tv_nsec as u32,
        });
        inode.set_ctime(now);
    }

    0
}

/// sys_utime - change file timestamps (second precision)
///
/// Ancient syscall - implemented in terms of utimensat.
pub fn sys_utime(pathname: u64, times: u64) -> i64 {
    if times == 0 {
        // NULL times - set to current time
        return sys_utimensat(AT_FDCWD, pathname, 0, 0);
    }

    // utimbuf structure
    #[repr(C)]
    struct Utimbuf {
        actime: i64,  // access time
        modtime: i64, // modification time
    }

    let size = core::mem::size_of::<Utimbuf>();
    if !Uaccess::access_ok(times, size) {
        return EFAULT;
    }
    let buf: Utimbuf = unsafe {
        Uaccess::user_access_begin();
        let val = core::ptr::read(times as *const Utimbuf);
        Uaccess::user_access_end();
        val
    };

    // Get inode and apply
    let path_str = match strncpy_from_user::<Uaccess>(pathname, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    let start = crate::task::percpu::current_cwd();
    let dentry = match lookup_path_at(start, &path_str, LookupFlags::open()) {
        Ok(d) => d,
        Err(FsError::NotFound) => return ENOENT,
        Err(FsError::NotADirectory) => return ENOTDIR,
        Err(_) => return EINVAL,
    };

    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    let now = current_time();

    // Apply timestamps with inode lock held (Linux i_rwsem pattern)
    {
        let _guard = inode.lock.write();
        inode.set_atime(crate::time::Timespec::from_secs(buf.actime));
        inode.set_mtime(crate::time::Timespec::from_secs(buf.modtime));
        inode.set_ctime(now);
    }

    0
}

// ============================================================================
// Block device ioctl constants (Linux ABI)
// ============================================================================

/// BLKGETSIZE64 - get device size in bytes (returns u64)
const BLKGETSIZE64: u32 = 0x80081272;

/// BLKBSZGET - get block size (returns i32)
const BLKBSZGET: u32 = 0x80041270;

/// BLKFLSBUF - flush buffer cache
const BLKFLSBUF: u32 = 0x1261;

/// sys_ioctl - device control
///
/// Performs device-specific control operations.
///
/// # Arguments
/// * `fd` - File descriptor
/// * `cmd` - Ioctl command number
/// * `arg` - Command-specific argument (often a pointer)
///
/// # Returns
/// 0 on success, negative errno on error.
pub fn sys_ioctl(fd: i32, cmd: u32, arg: u64) -> i64 {
    // Get file from fd
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f.clone(),
        None => return EBADF,
    };

    // Get the inode to check file type
    let inode = match file.get_inode() {
        Some(i) => i,
        None => return EBADF,
    };

    // Block device ioctls
    if inode.mode().is_blkdev() {
        // Get the block device from rdev
        let bdev = match get_blkdev(inode.rdev) {
            Some(b) => b,
            None => return ENXIO,
        };

        match cmd {
            BLKGETSIZE64 => {
                // Return device size in bytes
                let size = bdev.capacity();
                if arg != 0 {
                    // Write size to userspace pointer
                    if !Uaccess::access_ok(arg, core::mem::size_of::<u64>()) {
                        return EFAULT;
                    }
                    if put_user::<Uaccess, u64>(arg, size).is_err() {
                        return EFAULT;
                    }
                }
                0
            }
            BLKBSZGET => {
                // Return block size (always 512 for now)
                let block_size: i32 = bdev.block_size() as i32;
                if arg != 0 {
                    if !Uaccess::access_ok(arg, core::mem::size_of::<i32>()) {
                        return EFAULT;
                    }
                    if put_user::<Uaccess, i32>(arg, block_size).is_err() {
                        return EFAULT;
                    }
                }
                0
            }
            BLKFLSBUF => {
                // Flush buffer cache - for RAM disk this is a no-op
                // (page cache IS the storage)
                0
            }
            _ => ENOTTY,
        }
    } else if inode.mode().is_chrdev() {
        // Character device ioctls - route to CharDevice::ioctl()
        use crate::chardev::get_chardev;

        let device = match get_chardev(inode.rdev) {
            Some(d) => d,
            None => return ENXIO,
        };

        match device.ioctl(cmd, arg) {
            Ok(result) => result,
            Err(crate::chardev::DeviceError::NotTty) => ENOTTY,
            Err(crate::chardev::DeviceError::InvalidArg) => EINVAL,
            Err(crate::chardev::DeviceError::NotSupported) => ENOTTY,
            Err(_) => EIO,
        }
    } else {
        // Not a device - ioctl not supported
        ENOTTY
    }
}

// ============================================================================
// Sync Syscalls - Flush dirty pages to backing store
// ============================================================================

/// Error code for I/O error
pub const EIO: i64 = -5;

/// sys_sync - sync all filesystems
///
/// Schedules writeback of all dirty pages in all address spaces.
/// Linux semantics: blocks until all I/O completes.
///
/// # Returns
/// Always returns 0 (sync never fails in our implementation)
pub fn sys_sync() -> i64 {
    use crate::mm::writeback::sync_all;

    // Sync all dirty pages across all address spaces
    // This uses the writeback infrastructure to:
    // 1. Iterate DIRTY_ADDRESS_SPACES
    // 2. Write dirty pages via do_writepages
    // 3. Wait for writeback to complete
    let _ = sync_all();

    0
}

/// sys_fsync - sync file data and metadata to backing store
///
/// Transfers all modified in-core data of the file to the storage device.
/// Includes flushing the file data and metadata.
///
/// # Arguments
/// * `fd` - File descriptor to sync
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_fsync(fd: i32) -> i64 {
    // Get file from fd
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f.clone(),
        None => return EBADF,
    };

    // Call the file's fsync operation
    match file.f_op.fsync(&file) {
        Ok(()) => 0,
        Err(FsError::IoError) => EIO,
        Err(_) => EINVAL,
    }
}

/// sys_fdatasync - sync file data (not metadata) to backing store
///
/// Similar to fsync, but does not flush modified metadata unless it
/// is needed for subsequent data retrieval. For our implementation,
/// this is identical to fsync since we don't have separate metadata writeback.
///
/// # Arguments
/// * `fd` - File descriptor to sync
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_fdatasync(fd: i32) -> i64 {
    // For our implementation, fdatasync is identical to fsync
    // since we don't distinguish between data and metadata writeback
    sys_fsync(fd)
}

/// sys_syncfs - sync filesystem containing file descriptor
///
/// Syncs all dirty pages for the filesystem that contains the file
/// referred to by fd. For block device-based filesystems (vfat, ext4, etc.),
/// this syncs all address spaces associated with that mount.
///
/// # Implementation
///
/// Linux syncfs:
/// 1. Gets the superblock from the file's mount (f_path.mnt->mnt_sb)
/// 2. Calls sync_filesystem(sb) which:
///    - Calls sb->s_op->sync_fs if defined
///    - Writes back all dirty inodes via writeback_inodes_sb
///    - Syncs the underlying block device via sync_blockdev
///
/// Our implementation uses the writeback module:
/// 1. Gets the mount from the file's dentry
/// 2. Uses writeback_all() to flush dirty pages with proper writeback tracking
/// 3. Returns 0 on success
///
/// # Arguments
/// * `fd` - File descriptor in the target filesystem
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_syncfs(fd: i32) -> i64 {
    use crate::mm::writeback::sync_all;

    // Validate fd exists (but we sync all filesystems currently)
    let _file = match current_fd_table().lock().get(fd) {
        Some(f) => f.clone(),
        None => return EBADF,
    };

    // Use the writeback module to sync all dirty pages
    // TODO: When we have per-superblock tracking, only sync the target filesystem
    let _ = sync_all();

    0
}

// =============================================================================
// Poll/Select Syscalls
// =============================================================================

/// poll - wait for events on file descriptors
///
/// poll() performs a similar task to select(2): it waits for one of a set
/// of file descriptors to become ready to perform I/O.
///
/// # Arguments
/// * `fds` - Pointer to array of pollfd structures
/// * `nfds` - Number of fds in the array
/// * `timeout_ms` - Timeout in milliseconds (-1 = infinite, 0 = immediate)
///
/// # Returns
/// * Number of fds with events (can be 0 on timeout)
/// * -EFAULT if fds is invalid
/// * -EINVAL if nfds exceeds limit
/// * -EINTR if interrupted by signal
pub fn sys_poll(fds: u64, nfds: u32, timeout_ms: i32) -> i64 {
    use crate::poll::{POLLNVAL, PollContext, PollFd, PollTable};
    use crate::task::percpu::current_tid;
    use crate::uaccess::{copy_from_user, copy_to_user};

    // Limit nfds to prevent DoS
    const MAX_NFDS: u32 = 1024;
    if nfds > MAX_NFDS {
        return EINVAL;
    }

    // Handle empty poll (just sleep for timeout)
    if nfds == 0 {
        if timeout_ms > 0 {
            // TODO: Implement proper timeout sleep
            let _deadline = timeout_ms as u64;
        }
        return 0;
    }

    // Copy pollfd array from user space
    let pollfd_size = core::mem::size_of::<PollFd>();
    let total_size = pollfd_size * nfds as usize;
    let mut pollfds = vec![PollFd::default(); nfds as usize];

    let bytes_slice =
        unsafe { core::slice::from_raw_parts_mut(pollfds.as_mut_ptr() as *mut u8, total_size) };

    if copy_from_user::<Uaccess>(bytes_slice, fds, total_size).is_err() {
        return EFAULT;
    }

    // Create poll context
    let mut ctx = PollContext::new(current_tid());

    // Do the poll loop
    let mut ready_count;
    let _timeout_remaining = timeout_ms; // For future timeout implementation

    loop {
        // Reset poll table for this iteration
        let mut poll_table = PollTable::new(&mut ctx);
        ready_count = 0;

        // Get FD table
        let fd_table = current_fd_table();
        let table = fd_table.lock();

        // Check each fd
        for pollfd in pollfds.iter_mut() {
            pollfd.revents = 0;

            if pollfd.fd < 0 {
                // Negative fd is ignored
                continue;
            }

            // Look up the file
            let file = match table.get(pollfd.fd) {
                Some(f) => f,
                None => {
                    // Invalid fd - set POLLNVAL
                    pollfd.revents = POLLNVAL as i16;
                    ready_count += 1;
                    continue;
                }
            };

            // Set key for this fd's events
            poll_table.set_key(pollfd.events as u16);

            // Call file's poll method
            let mask = file.poll(Some(&mut poll_table));

            // Check if any requested events are ready
            let revents =
                mask & (pollfd.events as u16 | crate::poll::POLLERR | crate::poll::POLLHUP);
            if revents != 0 {
                pollfd.revents = revents as i16;
                ready_count += 1;
                // Disable further registrations once we find ready fds
                poll_table.disable();
            }
        }

        drop(table);

        // If any fds are ready, or timeout is 0 (immediate), return
        if ready_count > 0 || timeout_ms == 0 {
            break;
        }

        // TODO: Implement proper waiting with timeout
        // For now, yield and retry a few times, then timeout
        static mut POLL_ITERATIONS: u32 = 0;
        unsafe {
            POLL_ITERATIONS += 1;
            if POLL_ITERATIONS > 100 || timeout_ms > 0 {
                POLL_ITERATIONS = 0;
                break;
            }
        }
        crate::task::percpu::yield_now();
    }

    // Copy results back to user space
    let result_bytes =
        unsafe { core::slice::from_raw_parts(pollfds.as_ptr() as *const u8, total_size) };

    if copy_to_user::<Uaccess>(fds, result_bytes).is_err() {
        return EFAULT;
    }

    ready_count
}

/// ppoll - wait for events on file descriptors with timespec timeout
///
/// Like poll(), but uses a timespec instead of milliseconds, and can
/// atomically set a signal mask during the wait.
///
/// # Arguments
/// * `fds` - Pointer to array of pollfd structures
/// * `nfds` - Number of fds in the array
/// * `tmo_p` - Pointer to timespec (NULL = infinite)
/// * `sigmask_ptr` - Pointer to signal mask (NULL = don't change)
/// * `sigsetsize` - Size of signal mask
///
/// # Returns
/// Same as poll()
pub fn sys_ppoll(fds: u64, nfds: u32, tmo_p: u64, _sigmask_ptr: u64, _sigsetsize: u64) -> i64 {
    use crate::uaccess::copy_from_user;

    // Convert timespec to milliseconds (or -1 for infinite)
    let timeout_ms = if tmo_p == 0 {
        -1i32 // Infinite wait
    } else {
        // Read timespec from user
        #[repr(C)]
        #[derive(Default, Copy, Clone)]
        struct Timespec {
            tv_sec: i64,
            tv_nsec: i64,
        }

        let mut ts = Timespec::default();
        let ts_bytes = unsafe {
            core::slice::from_raw_parts_mut(
                &mut ts as *mut Timespec as *mut u8,
                core::mem::size_of::<Timespec>(),
            )
        };

        if copy_from_user::<Uaccess>(ts_bytes, tmo_p, core::mem::size_of::<Timespec>()).is_err() {
            return EFAULT;
        }

        // Convert to milliseconds (clamped to i32 range)
        let ms = ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000;
        if ms > i32::MAX as i64 {
            i32::MAX
        } else if ms < 0 {
            0
        } else {
            ms as i32
        }
    };

    // TODO: Handle signal mask atomically
    // For now, we ignore the signal mask

    // Delegate to sys_poll
    sys_poll(fds, nfds, timeout_ms)
}

// =============================================================================
// Select Syscalls
// =============================================================================

/// select - synchronous I/O multiplexing
///
/// Allows a program to monitor multiple file descriptors, waiting until one or
/// more of the file descriptors become "ready" for some class of I/O operation.
///
/// # Arguments
/// * `nfds` - Highest-numbered fd in any of the sets, plus 1
/// * `readfds` - Optional pointer to fd_set for read readiness
/// * `writefds` - Optional pointer to fd_set for write readiness
/// * `exceptfds` - Optional pointer to fd_set for exceptional conditions
/// * `timeout` - Optional pointer to timeval (NULL = block indefinitely)
///
/// # Returns
/// * Number of ready fds on success
/// * 0 on timeout
/// * -EBADF if an invalid fd is in any set
/// * -EINVAL if nfds is negative or exceeds limit
/// * -EFAULT if any pointer is invalid
/// * -EINTR if interrupted by signal
pub fn sys_select(nfds: i32, readfds: u64, writefds: u64, exceptfds: u64, timeout: u64) -> i64 {
    use crate::poll::{FdSet, POLLERR, POLLHUP, POLLIN, POLLOUT, POLLPRI, PollContext, PollTable};
    use crate::task::percpu::current_tid;
    use crate::uaccess::{copy_from_user, copy_to_user};

    // Validate nfds
    const FD_SETSIZE: i32 = 1024;
    if !(0..=FD_SETSIZE).contains(&nfds) {
        return EINVAL;
    }

    // Handle empty select (just sleep for timeout)
    if nfds == 0 && readfds == 0 && writefds == 0 && exceptfds == 0 {
        if timeout != 0 {
            // TODO: Implement proper timeout sleep
        }
        return 0;
    }

    // Calculate how many bytes to copy
    let bytes_needed = FdSet::bytes_for_nfds(nfds);

    // Copy fd_sets from user space
    let mut read_set = FdSet::new();
    let mut write_set = FdSet::new();
    let mut except_set = FdSet::new();

    if readfds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(read_set.bits.as_mut_ptr() as *mut u8, bytes_needed)
        };
        if copy_from_user::<Uaccess>(bytes, readfds, bytes_needed).is_err() {
            return EFAULT;
        }
    }

    if writefds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(write_set.bits.as_mut_ptr() as *mut u8, bytes_needed)
        };
        if copy_from_user::<Uaccess>(bytes, writefds, bytes_needed).is_err() {
            return EFAULT;
        }
    }

    if exceptfds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(except_set.bits.as_mut_ptr() as *mut u8, bytes_needed)
        };
        if copy_from_user::<Uaccess>(bytes, exceptfds, bytes_needed).is_err() {
            return EFAULT;
        }
    }

    // Read timeout if provided
    let timeout_ms = if timeout != 0 {
        #[repr(C)]
        #[derive(Default, Copy, Clone)]
        struct Timeval {
            tv_sec: i64,
            tv_usec: i64,
        }

        let mut tv = Timeval::default();
        let tv_bytes = unsafe {
            core::slice::from_raw_parts_mut(
                &mut tv as *mut Timeval as *mut u8,
                core::mem::size_of::<Timeval>(),
            )
        };

        if copy_from_user::<Uaccess>(tv_bytes, timeout, core::mem::size_of::<Timeval>()).is_err() {
            return EFAULT;
        }

        // Convert to milliseconds
        let ms = tv.tv_sec * 1000 + tv.tv_usec / 1000;
        if ms > i32::MAX as i64 {
            i32::MAX
        } else if ms < 0 {
            0
        } else {
            ms as i32
        }
    } else {
        -1i32 // Infinite wait
    };

    // Create poll context
    let mut ctx = PollContext::new(current_tid());

    // Output sets (initially zeroed)
    let mut out_read = FdSet::new();
    let mut out_write = FdSet::new();
    let mut out_except = FdSet::new();

    // Do the select loop
    let mut ready_count;
    let _timeout_remaining = timeout_ms;

    loop {
        let mut poll_table = PollTable::new(&mut ctx);
        ready_count = 0i32;

        // Get FD table
        let fd_table = current_fd_table();
        let table = fd_table.lock();

        // Check each fd from 0 to nfds-1
        for fd in 0..nfds {
            let check_read = readfds != 0 && read_set.is_set(fd);
            let check_write = writefds != 0 && write_set.is_set(fd);
            let check_except = exceptfds != 0 && except_set.is_set(fd);

            if !check_read && !check_write && !check_except {
                continue;
            }

            // Look up the file - select returns EBADF for invalid fds (unlike poll)
            let file = match table.get(fd) {
                Some(f) => f,
                None => {
                    return EBADF;
                }
            };

            // Set key for events we're interested in
            let mut events = 0u16;
            if check_read {
                events |= POLLIN;
            }
            if check_write {
                events |= POLLOUT;
            }
            if check_except {
                events |= POLLPRI;
            }
            poll_table.set_key(events);

            // Call file's poll method
            let mask = file.poll(Some(&mut poll_table));

            // Check results
            let mut fd_ready = false;

            if check_read && (mask & (POLLIN | POLLERR | POLLHUP)) != 0 {
                out_read.set(fd);
                fd_ready = true;
            }

            if check_write && (mask & (POLLOUT | POLLERR | POLLHUP)) != 0 {
                out_write.set(fd);
                fd_ready = true;
            }

            if check_except && (mask & (POLLPRI | POLLERR)) != 0 {
                out_except.set(fd);
                fd_ready = true;
            }

            if fd_ready {
                ready_count += 1;
                poll_table.disable();
            }
        }

        drop(table);

        // If any fds are ready, or timeout is 0 (immediate), return
        if ready_count > 0 || timeout_ms == 0 {
            break;
        }

        // TODO: Implement proper waiting with timeout
        // For now, yield and retry a few times, then timeout
        static mut SELECT_ITERATIONS: u32 = 0;
        unsafe {
            SELECT_ITERATIONS += 1;
            if SELECT_ITERATIONS > 100 || timeout_ms > 0 {
                SELECT_ITERATIONS = 0;
                break;
            }
        }
        crate::task::percpu::yield_now();
    }

    // Copy results back to user space
    if readfds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts(out_read.bits.as_ptr() as *const u8, bytes_needed)
        };
        if copy_to_user::<Uaccess>(readfds, bytes).is_err() {
            return EFAULT;
        }
    }

    if writefds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts(out_write.bits.as_ptr() as *const u8, bytes_needed)
        };
        if copy_to_user::<Uaccess>(writefds, bytes).is_err() {
            return EFAULT;
        }
    }

    if exceptfds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts(out_except.bits.as_ptr() as *const u8, bytes_needed)
        };
        if copy_to_user::<Uaccess>(exceptfds, bytes).is_err() {
            return EFAULT;
        }
    }

    ready_count as i64
}

/// pselect6 - synchronous I/O multiplexing with timespec and signal mask
///
/// Like select(), but uses a timespec instead of timeval, and can atomically
/// set a signal mask during the wait.
///
/// # Arguments
/// * `nfds` - Highest-numbered fd in any of the sets, plus 1
/// * `readfds` - Optional pointer to fd_set for read readiness
/// * `writefds` - Optional pointer to fd_set for write readiness
/// * `exceptfds` - Optional pointer to fd_set for exceptional conditions
/// * `timeout` - Optional pointer to timespec (NULL = block indefinitely)
/// * `sigmask` - Pointer to pselect6_data struct containing sigmask
///
/// # Returns
/// Same as select()
pub fn sys_pselect6(
    nfds: i32,
    readfds: u64,
    writefds: u64,
    exceptfds: u64,
    timeout: u64,
    _sigmask: u64,
) -> i64 {
    use crate::uaccess::copy_from_user;

    // Convert timespec to timeval pointer or handle directly
    // pselect6 uses timespec instead of timeval
    let timeout_ms = if timeout != 0 {
        #[repr(C)]
        #[derive(Default, Copy, Clone)]
        struct Timespec {
            tv_sec: i64,
            tv_nsec: i64,
        }

        let mut ts = Timespec::default();
        let ts_bytes = unsafe {
            core::slice::from_raw_parts_mut(
                &mut ts as *mut Timespec as *mut u8,
                core::mem::size_of::<Timespec>(),
            )
        };

        if copy_from_user::<Uaccess>(ts_bytes, timeout, core::mem::size_of::<Timespec>()).is_err() {
            return EFAULT;
        }

        // Convert to milliseconds
        let ms = ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000;
        if ms > i32::MAX as i64 {
            i32::MAX
        } else if ms < 0 {
            0
        } else {
            ms as i32
        }
    } else {
        -1i32 // Infinite wait
    };

    // TODO: Handle signal mask atomically
    // The sigmask parameter in pselect6 is actually a pointer to a struct
    // containing { const sigset_t *ss; size_t ss_len; }

    // For now, delegate to a modified version of select with timeout_ms
    // We can't directly call sys_select because it expects timeval, not timespec
    sys_select_internal(nfds, readfds, writefds, exceptfds, timeout_ms)
}

/// Internal select implementation that takes timeout in milliseconds
fn sys_select_internal(
    nfds: i32,
    readfds: u64,
    writefds: u64,
    exceptfds: u64,
    timeout_ms: i32,
) -> i64 {
    use crate::poll::{FdSet, POLLERR, POLLHUP, POLLIN, POLLOUT, POLLPRI, PollContext, PollTable};
    use crate::task::percpu::current_tid;
    use crate::uaccess::{copy_from_user, copy_to_user};

    // Validate nfds
    const FD_SETSIZE: i32 = 1024;
    if !(0..=FD_SETSIZE).contains(&nfds) {
        return EINVAL;
    }

    // Handle empty select
    if nfds == 0 && readfds == 0 && writefds == 0 && exceptfds == 0 {
        return 0;
    }

    // Calculate how many bytes to copy
    let bytes_needed = FdSet::bytes_for_nfds(nfds);

    // Copy fd_sets from user space
    let mut read_set = FdSet::new();
    let mut write_set = FdSet::new();
    let mut except_set = FdSet::new();

    if readfds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(read_set.bits.as_mut_ptr() as *mut u8, bytes_needed)
        };
        if copy_from_user::<Uaccess>(bytes, readfds, bytes_needed).is_err() {
            return EFAULT;
        }
    }

    if writefds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(write_set.bits.as_mut_ptr() as *mut u8, bytes_needed)
        };
        if copy_from_user::<Uaccess>(bytes, writefds, bytes_needed).is_err() {
            return EFAULT;
        }
    }

    if exceptfds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(except_set.bits.as_mut_ptr() as *mut u8, bytes_needed)
        };
        if copy_from_user::<Uaccess>(bytes, exceptfds, bytes_needed).is_err() {
            return EFAULT;
        }
    }

    // Create poll context
    let mut ctx = PollContext::new(current_tid());

    // Output sets (initially zeroed)
    let mut out_read = FdSet::new();
    let mut out_write = FdSet::new();
    let mut out_except = FdSet::new();

    // Do the select loop
    let mut ready_count;

    loop {
        let mut poll_table = PollTable::new(&mut ctx);
        ready_count = 0i32;

        // Get FD table
        let fd_table = current_fd_table();
        let table = fd_table.lock();

        // Check each fd from 0 to nfds-1
        for fd in 0..nfds {
            let check_read = readfds != 0 && read_set.is_set(fd);
            let check_write = writefds != 0 && write_set.is_set(fd);
            let check_except = exceptfds != 0 && except_set.is_set(fd);

            if !check_read && !check_write && !check_except {
                continue;
            }

            // Look up the file
            let file = match table.get(fd) {
                Some(f) => f,
                None => {
                    return EBADF;
                }
            };

            // Set key for events we're interested in
            let mut events = 0u16;
            if check_read {
                events |= POLLIN;
            }
            if check_write {
                events |= POLLOUT;
            }
            if check_except {
                events |= POLLPRI;
            }
            poll_table.set_key(events);

            // Call file's poll method
            let mask = file.poll(Some(&mut poll_table));

            // Check results
            let mut fd_ready = false;

            if check_read && (mask & (POLLIN | POLLERR | POLLHUP)) != 0 {
                out_read.set(fd);
                fd_ready = true;
            }

            if check_write && (mask & (POLLOUT | POLLERR | POLLHUP)) != 0 {
                out_write.set(fd);
                fd_ready = true;
            }

            if check_except && (mask & (POLLPRI | POLLERR)) != 0 {
                out_except.set(fd);
                fd_ready = true;
            }

            if fd_ready {
                ready_count += 1;
                poll_table.disable();
            }
        }

        drop(table);

        // If any fds are ready, or timeout is 0 (immediate), return
        if ready_count > 0 || timeout_ms == 0 {
            break;
        }

        // TODO: Implement proper waiting with timeout
        static mut PSELECT_ITERATIONS: u32 = 0;
        unsafe {
            PSELECT_ITERATIONS += 1;
            if PSELECT_ITERATIONS > 100 || timeout_ms > 0 {
                PSELECT_ITERATIONS = 0;
                break;
            }
        }
        crate::task::percpu::yield_now();
    }

    // Copy results back to user space
    if readfds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts(out_read.bits.as_ptr() as *const u8, bytes_needed)
        };
        if copy_to_user::<Uaccess>(readfds, bytes).is_err() {
            return EFAULT;
        }
    }

    if writefds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts(out_write.bits.as_ptr() as *const u8, bytes_needed)
        };
        if copy_to_user::<Uaccess>(writefds, bytes).is_err() {
            return EFAULT;
        }
    }

    if exceptfds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts(out_except.bits.as_ptr() as *const u8, bytes_needed)
        };
        if copy_to_user::<Uaccess>(exceptfds, bytes).is_err() {
            return EFAULT;
        }
    }

    ready_count as i64
}

// =============================================================================
// Pipe Syscalls
// =============================================================================

/// pipe - create a pipe
///
/// Creates a pipe, a unidirectional data channel that can be used for
/// interprocess communication. The array pipefd is used to return two
/// file descriptors referring to the ends of the pipe.
///
/// # Arguments
/// * `pipefd` - Pointer to int[2] array. pipefd[0] = read end, pipefd[1] = write end
///
/// # Returns
/// * 0 on success
/// * -EFAULT if pipefd is invalid
/// * -EMFILE if too many file descriptors
pub fn sys_pipe(pipefd: u64) -> i64 {
    sys_pipe2(pipefd, 0)
}

/// pipe2 - create a pipe with flags
///
/// Like pipe(), but additionally allows flags to be specified.
///
/// # Arguments
/// * `pipefd` - Pointer to int[2] array
/// * `flags` - O_CLOEXEC | O_NONBLOCK
///
/// # Returns
/// * 0 on success
/// * -EFAULT if pipefd is invalid
/// * -EINVAL if invalid flags
/// * -EMFILE if too many file descriptors
pub fn sys_pipe2(pipefd: u64, flags: u32) -> i64 {
    use crate::fs::file::flags::{O_CLOEXEC, O_NONBLOCK};
    use crate::pipe::{FD_CLOEXEC, create_pipe};
    use crate::uaccess::copy_to_user;

    // Validate flags - only O_CLOEXEC and O_NONBLOCK are allowed
    const VALID_FLAGS: u32 = O_CLOEXEC | O_NONBLOCK;
    if flags & !VALID_FLAGS != 0 {
        return EINVAL;
    }

    // Validate user pointer
    if pipefd == 0 {
        return EFAULT;
    }

    // Create the pipe
    let (read_file, write_file) = match create_pipe(flags & O_NONBLOCK) {
        Ok((r, w)) => (r, w),
        Err(_) => return ENOMEM,
    };

    // Allocate file descriptors (RLIMIT_NOFILE enforced inside alloc)
    // Following Linux pattern: each get_unused_fd_flags() call checks limit
    let fd_table = current_fd_table();
    let mut table = fd_table.lock();
    let nofile = get_nofile_limit();

    // Determine fd flags
    let fd_flags = if flags & O_CLOEXEC != 0 {
        FD_CLOEXEC
    } else {
        0
    };

    let read_fd = match table.alloc_with_flags(read_file, fd_flags, nofile) {
        Ok(fd) => fd,
        Err(e) => return -(e as i64),
    };

    let write_fd = match table.alloc_with_flags(write_file, fd_flags, nofile) {
        Ok(fd) => fd,
        Err(e) => {
            // Clean up read fd on failure
            table.close(read_fd);
            return -(e as i64);
        }
    };

    drop(table);

    // Write file descriptors to user space
    let fds: [i32; 2] = [read_fd, write_fd];
    let fds_bytes = unsafe {
        core::slice::from_raw_parts(fds.as_ptr() as *const u8, core::mem::size_of::<[i32; 2]>())
    };

    match copy_to_user::<Uaccess>(pipefd, fds_bytes) {
        Ok(_) => 0,
        Err(_) => {
            // Clean up on error
            let mut table = fd_table.lock();
            table.close(read_fd);
            table.close(write_fd);
            EFAULT
        }
    }
}

/// fcntl command constants
mod fcntl_cmd {
    pub const F_DUPFD: i32 = 0;
    pub const F_GETFD: i32 = 1;
    pub const F_SETFD: i32 = 2;
    pub const F_GETFL: i32 = 3;
    pub const F_SETFL: i32 = 4;
    pub const F_DUPFD_CLOEXEC: i32 = 1030;
}

/// sys_fcntl - file control operations
///
/// Performs various operations on file descriptors.
///
/// # Arguments
/// * `fd` - File descriptor to operate on
/// * `cmd` - Operation to perform (F_DUPFD, F_GETFD, etc.)
/// * `arg` - Optional argument (meaning depends on cmd)
///
/// # Returns
/// * F_DUPFD/F_DUPFD_CLOEXEC: new fd on success
/// * F_GETFD: fd flags (FD_CLOEXEC)
/// * F_GETFL: file status flags
/// * F_SETFD/F_SETFL: 0 on success
/// * negative errno on error
pub fn sys_fcntl(fd: i32, cmd: i32, arg: u64) -> i64 {
    use fcntl_cmd::*;

    let fd_table = current_fd_table();
    let mut table = fd_table.lock();

    let nofile = get_nofile_limit();

    match cmd {
        F_DUPFD => {
            // Duplicate fd to lowest available >= arg
            let file = match table.get(fd) {
                Some(f) => f,
                None => return EBADF,
            };
            let min_fd = arg as i32;
            if min_fd < 0 {
                return EINVAL;
            }
            // Linux: if (from >= nofile) return -EINVAL
            if (min_fd as u64) >= nofile {
                return EINVAL;
            }
            // RLIMIT_NOFILE enforced inside alloc_at_or_above
            match table.alloc_at_or_above(file, min_fd, 0, nofile) {
                Ok(new_fd) => new_fd as i64,
                Err(e) => -(e as i64),
            }
        }

        F_DUPFD_CLOEXEC => {
            // Duplicate fd with FD_CLOEXEC set
            let file = match table.get(fd) {
                Some(f) => f,
                None => return EBADF,
            };
            let min_fd = arg as i32;
            if min_fd < 0 {
                return EINVAL;
            }
            // Linux: if (from >= nofile) return -EINVAL
            if (min_fd as u64) >= nofile {
                return EINVAL;
            }
            // RLIMIT_NOFILE enforced inside alloc_at_or_above
            match table.alloc_at_or_above(file, min_fd, crate::task::FD_CLOEXEC, nofile) {
                Ok(new_fd) => new_fd as i64,
                Err(e) => -(e as i64),
            }
        }

        F_GETFD => {
            // Get fd flags (FD_CLOEXEC)
            if !table.is_valid(fd) {
                return EBADF;
            }
            table.get_fd_flags(fd) as i64
        }

        F_SETFD => {
            // Set fd flags (only FD_CLOEXEC is valid)
            if !table.set_fd_flags(fd, arg as u32) {
                return EBADF;
            }
            0
        }

        F_GETFL => {
            // Get file status flags
            let file = match table.get(fd) {
                Some(f) => f,
                None => return EBADF,
            };
            file.get_flags() as i64
        }

        F_SETFL => {
            // Set file status flags (only O_APPEND, O_NONBLOCK can be changed)
            let file = match table.get(fd) {
                Some(f) => f,
                None => return EBADF,
            };
            file.set_status_flags(arg as u32);
            0
        }

        _ => EINVAL,
    }
}

// =============================================================================
// statx structures and constants
// =============================================================================

/// Timestamp for statx (16 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StatxTimestamp {
    /// Seconds since Unix epoch
    pub tv_sec: i64,
    /// Nanoseconds within the second
    pub tv_nsec: u32,
    /// Reserved for future use
    pub __reserved: i32,
}

/// Extended file status structure (256 bytes)
///
/// This matches the Linux kernel's `struct statx` for x86-64.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Statx {
    /// Bitmask of results returned
    pub stx_mask: u32,
    /// Preferred I/O block size
    pub stx_blksize: u32,
    /// File attributes (STATX_ATTR_*)
    pub stx_attributes: u64,
    /// Number of hard links
    pub stx_nlink: u32,
    /// User ID of owner
    pub stx_uid: u32,
    /// Group ID of owner
    pub stx_gid: u32,
    /// File type and mode
    pub stx_mode: u16,
    /// Padding
    pub __spare0: [u16; 1],
    /// Inode number
    pub stx_ino: u64,
    /// File size in bytes
    pub stx_size: u64,
    /// Number of 512-byte blocks allocated
    pub stx_blocks: u64,
    /// Supported attributes mask
    pub stx_attributes_mask: u64,
    /// Last access time
    pub stx_atime: StatxTimestamp,
    /// Birth/creation time
    pub stx_btime: StatxTimestamp,
    /// Last attribute change time
    pub stx_ctime: StatxTimestamp,
    /// Last data modification time
    pub stx_mtime: StatxTimestamp,
    /// Device major for special files
    pub stx_rdev_major: u32,
    /// Device minor for special files
    pub stx_rdev_minor: u32,
    /// Device major containing file
    pub stx_dev_major: u32,
    /// Device minor containing file
    pub stx_dev_minor: u32,
    /// Mount ID
    pub stx_mnt_id: u64,
    /// Direct I/O memory alignment
    pub stx_dio_mem_align: u32,
    /// Direct I/O offset alignment
    pub stx_dio_offset_align: u32,
    /// Subvolume ID
    pub stx_subvol: u64,
    /// Min atomic write unit in bytes
    pub stx_atomic_write_unit_min: u32,
    /// Max atomic write unit in bytes
    pub stx_atomic_write_unit_max: u32,
    /// Max atomic write segment count
    pub stx_atomic_write_segments_max: u32,
    /// Direct I/O read offset alignment
    pub stx_dio_read_offset_align: u32,
    /// Optimized max atomic write unit
    pub stx_atomic_write_unit_max_opt: u32,
    /// Padding
    pub __spare2: [u32; 1],
    /// Reserved for future use
    pub __spare3: [u64; 8],
}

// STATX mask bits - what fields caller wants / kernel provided
/// Want/got stx_mode & S_IFMT
pub const STATX_TYPE: u32 = 0x0001;
/// Want/got stx_mode & ~S_IFMT
pub const STATX_MODE: u32 = 0x0002;
/// Want/got stx_nlink
pub const STATX_NLINK: u32 = 0x0004;
/// Want/got stx_uid
pub const STATX_UID: u32 = 0x0008;
/// Want/got stx_gid
pub const STATX_GID: u32 = 0x0010;
/// Want/got stx_atime
pub const STATX_ATIME: u32 = 0x0020;
/// Want/got stx_mtime
pub const STATX_MTIME: u32 = 0x0040;
/// Want/got stx_ctime
pub const STATX_CTIME: u32 = 0x0080;
/// Want/got stx_ino
pub const STATX_INO: u32 = 0x0100;
/// Want/got stx_size
pub const STATX_SIZE: u32 = 0x0200;
/// Want/got stx_blocks
pub const STATX_BLOCKS: u32 = 0x0400;
/// Basic stats - everything in normal stat struct
pub const STATX_BASIC_STATS: u32 = 0x07ff;
/// Want/got stx_btime
pub const STATX_BTIME: u32 = 0x0800;
/// Got stx_mnt_id
pub const STATX_MNT_ID: u32 = 0x1000;

// AT_* flags used by statx (note: some already defined above)
/// Sync as stat (default)
pub const AT_STATX_SYNC_AS_STAT: i32 = 0x0000;
/// Force sync
pub const AT_STATX_FORCE_SYNC: i32 = 0x2000;
/// Don't sync
pub const AT_STATX_DONT_SYNC: i32 = 0x4000;

// =============================================================================
// statfs/fstatfs syscalls
// =============================================================================

/// sys_statfs - get filesystem statistics by path
///
/// # Arguments
/// * `path_ptr` - User pointer to null-terminated path string
/// * `buf` - User pointer to statfs structure to fill
///
/// # Returns
/// 0 on success, negative errno on error.
pub fn sys_statfs(path_ptr: u64, buf: u64) -> i64 {
    // Read path from user space
    let path = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    // Validate buffer
    if !Uaccess::access_ok(buf, core::mem::size_of::<LinuxStatFs>()) {
        return EFAULT;
    }

    // Look up path to get dentry/superblock
    let dentry = match lookup_path_flags(&path, LookupFlags::open()) {
        Ok(d) => d,
        Err(FsError::NotFound) => return ENOENT,
        Err(FsError::NotADirectory) => return ENOTDIR,
        Err(_) => return EINVAL,
    };

    // Get superblock
    let sb = match dentry.superblock() {
        Some(sb) => sb,
        None => return ENOENT,
    };

    // Get stats from filesystem
    let statfs = sb.s_op.statfs();
    let linux_statfs = statfs.to_linux(sb.dev_id, sb.flags);

    // Copy to user
    if put_user::<Uaccess, LinuxStatFs>(buf, linux_statfs).is_err() {
        return EFAULT;
    }

    0
}

/// sys_fstatfs - get filesystem statistics by file descriptor
///
/// # Arguments
/// * `fd` - File descriptor
/// * `buf` - User pointer to statfs structure to fill
///
/// # Returns
/// 0 on success, negative errno on error.
pub fn sys_fstatfs(fd: i32, buf: u64) -> i64 {
    // Validate buffer
    if !Uaccess::access_ok(buf, core::mem::size_of::<LinuxStatFs>()) {
        return EFAULT;
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Get superblock from file's dentry
    let sb = match file.dentry.superblock() {
        Some(sb) => sb,
        None => return EBADF,
    };

    // Get stats
    let statfs = sb.s_op.statfs();
    let linux_statfs = statfs.to_linux(sb.dev_id, sb.flags);

    // Copy to user
    if put_user::<Uaccess, LinuxStatFs>(buf, linux_statfs).is_err() {
        return EFAULT;
    }

    0
}

// =============================================================================
// statx syscall
// =============================================================================

use super::Inode;

/// Fill a Statx structure from an inode
fn fill_statx(inode: &Inode, _mask: u32) -> Statx {
    let attr = inode.i_op.getattr(inode);
    let st_dev = inode.superblock().map(|sb| sb.dev_id).unwrap_or(0);

    let st_rdev = if attr.mode.is_device() {
        attr.rdev.encode() as u64
    } else {
        0
    };

    Statx {
        stx_mask: STATX_BASIC_STATS, // Always provide basic stats
        stx_blksize: 4096,
        stx_attributes: 0,
        stx_nlink: attr.nlink,
        stx_uid: attr.uid,
        stx_gid: attr.gid,
        stx_mode: attr.mode.raw(),
        __spare0: [0],
        stx_ino: attr.ino,
        stx_size: attr.size,
        stx_blocks: attr.size.div_ceil(512),
        stx_attributes_mask: 0,
        stx_atime: StatxTimestamp {
            tv_sec: attr.atime.sec,
            tv_nsec: attr.atime.nsec,
            __reserved: 0,
        },
        stx_btime: StatxTimestamp {
            tv_sec: 0,
            tv_nsec: 0,
            __reserved: 0,
        }, // Birth time not tracked
        stx_ctime: StatxTimestamp {
            tv_sec: attr.ctime.sec,
            tv_nsec: attr.ctime.nsec,
            __reserved: 0,
        },
        stx_mtime: StatxTimestamp {
            tv_sec: attr.mtime.sec,
            tv_nsec: attr.mtime.nsec,
            __reserved: 0,
        },
        stx_rdev_major: ((st_rdev >> 8) & 0xfff) as u32,
        stx_rdev_minor: (st_rdev & 0xff) as u32 | ((st_rdev >> 12) & 0xfff00) as u32,
        stx_dev_major: ((st_dev >> 8) & 0xfff) as u32,
        stx_dev_minor: (st_dev & 0xff) as u32,
        stx_mnt_id: 0, // Not implemented yet
        stx_dio_mem_align: 0,
        stx_dio_offset_align: 0,
        stx_subvol: 0,
        stx_atomic_write_unit_min: 0,
        stx_atomic_write_unit_max: 0,
        stx_atomic_write_segments_max: 0,
        stx_dio_read_offset_align: 0,
        stx_atomic_write_unit_max_opt: 0,
        __spare2: [0],
        __spare3: [0; 8],
    }
}

/// sys_statx - get extended file status
///
/// # Arguments
/// * `dirfd` - Directory fd for relative paths, or AT_FDCWD
/// * `path_ptr` - User pointer to path string
/// * `flags` - AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH, etc.
/// * `mask` - STATX_* mask of what to return
/// * `buf` - User pointer to statx structure to fill
///
/// # Returns
/// 0 on success, negative errno on error.
pub fn sys_statx(dirfd: i32, path_ptr: u64, flags: i32, mask: u32, buf: u64) -> i64 {
    // Validate buffer
    if !Uaccess::access_ok(buf, core::mem::size_of::<Statx>()) {
        return EFAULT;
    }

    // Read path from user space
    let path = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return EFAULT,
    };

    // Handle AT_EMPTY_PATH (statx on fd itself)
    let dentry = if path.is_empty() && (flags & AT_EMPTY_PATH) != 0 {
        if dirfd < 0 {
            return EBADF;
        }
        match current_fd_table().lock().get(dirfd) {
            Some(f) => f.dentry.clone(),
            None => return EBADF,
        }
    } else {
        // Determine starting path for relative paths
        let start: Option<Path> = if path.starts_with('/') {
            None
        } else if dirfd == AT_FDCWD {
            crate::task::percpu::current_cwd()
        } else {
            let file = match current_fd_table().lock().get(dirfd) {
                Some(f) => f,
                None => return EBADF,
            };
            if !file.is_dir() {
                return ENOTDIR;
            }
            Path::from_dentry(file.dentry.clone())
        };

        // Determine lookup flags
        let lookup_flags = if (flags & AT_SYMLINK_NOFOLLOW) != 0 {
            LookupFlags {
                follow: false,
                ..LookupFlags::open()
            }
        } else {
            LookupFlags::open()
        };

        match lookup_path_at(start, &path, lookup_flags) {
            Ok(d) => d,
            Err(FsError::NotFound) => return ENOENT,
            Err(FsError::NotADirectory) => return ENOTDIR,
            Err(_) => return EINVAL,
        }
    };

    // Get inode
    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return ENOENT,
    };

    // Fill statx structure
    let statx = fill_statx(&inode, mask);

    // Copy to user
    if put_user::<Uaccess, Statx>(buf, statx).is_err() {
        return EFAULT;
    }

    0
}
