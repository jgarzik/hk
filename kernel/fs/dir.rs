//! Directory syscalls (getdents64, mkdir, mkdirat, rmdir, mknod, mknodat)

use alloc::sync::Arc;

use crate::arch::Uaccess;
use crate::fs::{Dentry, FileType, InodeMode, KernelError};
use crate::uaccess::{UaccessArch, copy_to_user, strncpy_from_user};

use super::syscall::{
    AT_FDCWD, MAX_RW_COUNT, PATH_MAX, SMALL_BUF_SIZE, current_fd_table, lookup_parent_at,
};

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
        return KernelError::BadAddress.sysret();
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    if !file.is_dir() {
        return KernelError::NotDirectory.sysret();
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
            FileType::Regular => DT_REG,
            FileType::Directory => DT_DIR,
            FileType::Symlink => DT_LNK,
            FileType::CharDev => DT_CHR,
            FileType::BlockDev => DT_BLK,
            FileType::Fifo => DT_FIFO,
            FileType::Socket => DT_SOCK,
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
                return KernelError::BadAddress.sysret();
            }
            offset as i64
        }
        Err(KernelError::NotDirectory) => KernelError::NotDirectory.sysret(),
        Err(_) => KernelError::InvalidArgument.sysret(),
    }
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
    // Read path from user space
    let path = match strncpy_from_user::<Uaccess>(pathname_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    if path.is_empty() {
        return KernelError::NotFound.sysret();
    }

    // Look up parent directory
    let (parent_dentry, name) = match lookup_parent_at(dirfd, &path) {
        Ok(p) => p,
        Err(e) => return e,
    };

    // Get parent inode
    let parent_inode = match parent_dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // Lock parent directory (Linux i_rwsem pattern)
    parent_inode.inode_lock();

    // Check if name already exists (with lock held)
    if parent_dentry.lookup_child(&name).is_some() {
        unsafe { parent_inode.inode_unlock() };
        return KernelError::AlreadyExists.sysret();
    }

    // Create directory mode with requested permissions (masked by typical umask of 0o22)
    let dir_mode = InodeMode::directory((mode & 0o7777) as u16);

    // Create the directory
    let new_inode = match parent_inode.i_op.mkdir(&parent_inode, &name, dir_mode) {
        Ok(i) => i,
        Err(e) => {
            unsafe { parent_inode.inode_unlock() };
            return match e {
                KernelError::AlreadyExists => KernelError::AlreadyExists.sysret(),
                KernelError::PermissionDenied => KernelError::PermissionDenied.sysret(),
                KernelError::OperationNotSupported => KernelError::NotPermitted.sysret(),
                _ => KernelError::InvalidArgument.sysret(),
            };
        }
    };

    // Create dentry for the directory
    let new_dentry = Arc::new(Dentry::new(
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
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    if path.is_empty() {
        return KernelError::NotFound.sysret();
    }

    // Look up parent directory and name
    let (parent_dentry, name) = match lookup_parent_at(AT_FDCWD, &path) {
        Ok(p) => p,
        Err(e) => return e,
    };

    // Get parent inode
    let parent_inode = match parent_dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // Lock parent directory (Linux i_rwsem pattern)
    parent_inode.inode_lock();

    // Check that target exists (with lock held)
    let target_dentry = match parent_dentry.lookup_child(&name) {
        Some(d) => d,
        None => {
            unsafe { parent_inode.inode_unlock() };
            return KernelError::NotFound.sysret();
        }
    };

    // Verify it's a directory
    if let Some(target_inode) = target_dentry.get_inode()
        && !target_inode.mode().is_dir()
    {
        unsafe { parent_inode.inode_unlock() };
        return KernelError::NotDirectory.sysret();
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
                KernelError::NotFound => KernelError::NotFound.sysret(),
                KernelError::NotDirectory => KernelError::NotDirectory.sysret(),
                KernelError::DirectoryNotEmpty => KernelError::DirectoryNotEmpty.sysret(),
                KernelError::PermissionDenied => KernelError::PermissionDenied.sysret(),
                KernelError::Busy => -16, // EBUSY
                _ => KernelError::InvalidArgument.sysret(),
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
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    if path.is_empty() {
        return KernelError::NotFound.sysret();
    }

    // Look up parent directory
    let (parent_dentry, name) = match lookup_parent_at(dirfd, &path) {
        Ok(p) => p,
        Err(e) => return e,
    };

    // Get parent inode
    let parent_inode = match parent_dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // Lock parent directory (Linux i_rwsem pattern)
    parent_inode.inode_lock();

    // Check if name already exists (with lock held)
    if parent_dentry.lookup_child(&name).is_some() {
        unsafe { parent_inode.inode_unlock() };
        return KernelError::AlreadyExists.sysret();
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
            return KernelError::InvalidArgument.sysret(); // Invalid type
        }
    };

    // Create the file using create() operation
    let new_inode = match parent_inode.i_op.create(&parent_inode, &name, inode_mode) {
        Ok(i) => i,
        Err(e) => {
            unsafe { parent_inode.inode_unlock() };
            return match e {
                KernelError::AlreadyExists => KernelError::AlreadyExists.sysret(),
                KernelError::PermissionDenied => KernelError::PermissionDenied.sysret(),
                KernelError::OperationNotSupported => KernelError::NotPermitted.sysret(),
                _ => KernelError::InvalidArgument.sysret(),
            };
        }
    };

    // Create dentry for the new file
    let new_dentry = Arc::new(Dentry::new(
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
