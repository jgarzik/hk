//! File open/close syscalls

use alloc::string::String;
use alloc::sync::Arc;

use crate::arch::Uaccess;
use crate::fs::{
    Dentry, File, InodeMode, KernelError, LookupFlags, Path, RAMFS_FILE_OPS, lookup_path_at,
};
use crate::uaccess::strncpy_from_user;

use super::syscall::{AT_FDCWD, PATH_MAX, current_fd_table, get_nofile_limit};

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
fn create_file_at(start: Option<Path>, path: &str, mode: u32) -> Result<Arc<Dentry>, KernelError> {
    // Find the last path component
    let path = path.trim_end_matches('/');
    if path.is_empty() {
        return Err(KernelError::InvalidArgument);
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
        return Err(KernelError::InvalidArgument);
    }

    // Look up the parent directory
    let parent_dentry = if parent_path == "." {
        // Use start or root
        start
            .map(|p| p.dentry.clone())
            .or_else(|| crate::fs::mount::current_mnt_ns().get_root_dentry())
            .ok_or(KernelError::NotFound)?
    } else {
        lookup_path_at(start, parent_path, LookupFlags::opendir())?
    };

    let parent_inode = parent_dentry.get_inode().ok_or(KernelError::NotFound)?;
    if !parent_inode.mode().is_dir() {
        return Err(KernelError::NotDirectory);
    }

    // Lock parent directory (Linux i_rwsem pattern)
    parent_inode.inode_lock();

    // Check if file already exists (with lock held)
    if parent_dentry.lookup_child(name).is_some() {
        unsafe { parent_inode.inode_unlock() };
        return Err(KernelError::AlreadyExists);
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
        Err(_) => return KernelError::BadAddress.sysret(),
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
            None => return KernelError::BadFd.sysret(),
        };
        if !file.is_dir() {
            return KernelError::NotDirectory.sysret();
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
                return KernelError::AlreadyExists.sysret();
            }
            d
        }
        Err(KernelError::NotFound) => {
            // File doesn't exist - try to create if O_CREAT is set
            if flags & super::flags::O_CREAT == 0 {
                return KernelError::NotFound.sysret();
            }
            // Create the file
            match create_file_at(start, &path_str, mode) {
                Ok(d) => d,
                Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
                Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
                Err(KernelError::AlreadyExists) => return KernelError::AlreadyExists.sysret(),
                Err(KernelError::PermissionDenied) => {
                    return KernelError::PermissionDenied.sysret();
                }
                Err(_) => return KernelError::InvalidArgument.sysret(),
            }
        }
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    };

    // Check if trying to open directory without O_DIRECTORY when reading
    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
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
        None => KernelError::BadFd.sysret(),
    }
}
