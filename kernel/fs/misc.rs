//! Miscellaneous filesystem syscalls
//!
//! This module contains:
//! - mount, umount2, pivot_root (filesystem mounting)
//! - ioctl (device control)
//! - xattr syscalls (extended attributes)
//! - readahead (file readahead)

use alloc::sync::Arc;
use alloc::vec;

use crate::arch::Uaccess;
use crate::fs::{KernelError, LookupFlags, Path, is_subdir, lookup_path_flags};
use crate::storage::get_blkdev;
use crate::uaccess::{UaccessArch, put_user, strncpy_from_user};

use super::syscall::{PATH_MAX, current_fd_table};

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
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Read target path from user space
    let target = match strncpy_from_user::<Uaccess>(target_ptr, PATH_MAX) {
        Ok(s) => s,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Look up the filesystem type
    let fs_type = match super::superblock::find_filesystem(&fstype) {
        Some(ft) => ft,
        None => return ENODEV,
    };

    // Look up the mount point (must be a directory)
    let mountpoint_dentry = match lookup_path_flags(&target, LookupFlags::opendir()) {
        Ok(d) => d,
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    };

    // Verify it's a directory
    if let Some(inode) = mountpoint_dentry.get_inode() {
        if !inode.mode().is_dir() {
            return KernelError::NotDirectory.sysret();
        }
    } else {
        return KernelError::NotFound.sysret();
    }

    // Choose mount method based on filesystem type
    if fs_type.mount_dev.is_some() && !source.is_empty() {
        // Device-backed filesystem (vfat, ext4, etc.)
        match super::mount::do_mount_dev(fs_type, &source, Some(mountpoint_dentry)) {
            Ok(_mount) => 0,
            Err(KernelError::NotBlockDevice) => ENOTBLK,
            Err(KernelError::NoDevice) => ENODEV,
            Err(KernelError::Busy) => EBUSY,
            Err(_) => KernelError::InvalidArgument.sysret(),
        }
    } else {
        // Pseudo-filesystem (ramfs, procfs, etc.)
        match super::mount::do_mount(fs_type, Some(mountpoint_dentry)) {
            Ok(_mount) => 0,
            Err(KernelError::Busy) => EBUSY,
            Err(KernelError::NoDevice) => ENODEV,
            Err(_) => KernelError::InvalidArgument.sysret(),
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
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Set up lookup flags - respect UMOUNT_NOFOLLOW
    let mut lookup_flags = LookupFlags::open();
    if flags & super::mount::umount_flags::UMOUNT_NOFOLLOW != 0 {
        lookup_flags.follow = false;
    }

    // Look up the target path
    let target_dentry = match lookup_path_flags(&target, lookup_flags) {
        Ok(d) => d,
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    };

    // Find the mount at this path
    let mount = match super::mount::current_mnt_ns().find_mount_at(&target_dentry) {
        Some(m) => m,
        None => return KernelError::InvalidArgument.sysret(), // Not a mount point
    };

    // Perform the unmount
    match super::mount::do_umount(mount, flags) {
        Ok(()) => 0,
        Err(KernelError::Busy) => EBUSY,
        Err(KernelError::InvalidArgument) => KernelError::InvalidArgument.sysret(), // Can't unmount root
        Err(_) => KernelError::InvalidArgument.sysret(),
    }
}

/// pivot_root - change the root filesystem
///
/// Moves the root filesystem of the calling process's mount namespace
/// to the directory `put_old` and makes `new_root` the new root filesystem.
///
/// # Arguments
/// * `new_root_ptr` - User pointer to path that will become the new root
/// * `put_old_ptr` - User pointer to path where old root will be moved
///
/// # Returns
/// 0 on success, negative errno on error
///
/// # Errors
/// * EPERM - Caller lacks CAP_SYS_ADMIN
/// * EINVAL - Various invalid configuration (not mountpoints, put_old not under new_root)
/// * ENOTDIR - new_root or put_old is not a directory
/// * ENOENT - Path not found
pub fn sys_pivot_root(new_root_ptr: u64, put_old_ptr: u64) -> i64 {
    // 1. Permission check: requires CAP_SYS_ADMIN
    if !crate::task::capable(crate::task::CAP_SYS_ADMIN) {
        return KernelError::NotPermitted.sysret();
    }

    // 2. Copy paths from user space
    let new_root_str = match strncpy_from_user::<Uaccess>(new_root_ptr, PATH_MAX) {
        Ok(s) => s,
        Err(_) => return KernelError::BadAddress.sysret(),
    };
    let put_old_str = match strncpy_from_user::<Uaccess>(put_old_ptr, PATH_MAX) {
        Ok(s) => s,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // 3. Look up new_root path (must be directory)
    let new_root_dentry = match lookup_path_flags(&new_root_str, LookupFlags::opendir()) {
        Ok(d) => d,
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    };

    // 4. Verify new_root is a mount point
    let mnt_ns = super::mount::current_mnt_ns();
    let new_mnt = match mnt_ns.find_mount_at(&new_root_dentry) {
        Some(m) => m,
        None => return KernelError::InvalidArgument.sysret(), // Not a mount point
    };

    // 5. Look up put_old path (must be directory)
    let put_old_dentry = match lookup_path_flags(&put_old_str, LookupFlags::opendir()) {
        Ok(d) => d,
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    };

    // 6. Verify put_old is at or under new_root
    if !is_subdir(&put_old_dentry, &new_root_dentry) {
        return KernelError::InvalidArgument.sysret();
    }

    // 7. Get old root mount - must exist
    let _old_root_mnt = match mnt_ns.get_root() {
        Some(m) => m,
        None => return KernelError::InvalidArgument.sysret(),
    };

    // 8. Verify new_root is not the same as current root
    // (pivoting to the same root is a no-op but Linux returns EBUSY)
    if let Some(root_dentry) = mnt_ns.get_root_dentry()
        && Arc::ptr_eq(&root_dentry, &new_root_dentry)
    {
        return EBUSY;
    }

    // 9. Set new root as namespace root
    mnt_ns.set_root(new_mnt.clone());

    // 10. Update task's fs root
    // The new root dentry becomes the task's root
    if let Some(fs) = crate::task::percpu::current_fs()
        && let Some(new_path) = Path::from_dentry(new_root_dentry)
    {
        fs.set_root(new_path);
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
        None => return KernelError::BadFd.sysret(),
    };

    // Get the inode to check file type
    let inode = match file.get_inode() {
        Some(i) => i,
        None => return KernelError::BadFd.sysret(),
    };

    // Block device ioctls
    if inode.mode().is_blkdev() {
        // Get the block device from rdev
        let bdev = match get_blkdev(inode.rdev) {
            Some(b) => b,
            None => return KernelError::NoDeviceOrAddress.sysret(),
        };

        match cmd {
            BLKGETSIZE64 => {
                // Return device size in bytes
                let size = bdev.capacity();
                if arg != 0 {
                    // Write size to userspace pointer
                    if !Uaccess::access_ok(arg, core::mem::size_of::<u64>()) {
                        return KernelError::BadAddress.sysret();
                    }
                    if put_user::<Uaccess, u64>(arg, size).is_err() {
                        return KernelError::BadAddress.sysret();
                    }
                }
                0
            }
            BLKBSZGET => {
                // Return block size (always 512 for now)
                let block_size: i32 = bdev.block_size() as i32;
                if arg != 0 {
                    if !Uaccess::access_ok(arg, core::mem::size_of::<i32>()) {
                        return KernelError::BadAddress.sysret();
                    }
                    if put_user::<Uaccess, i32>(arg, block_size).is_err() {
                        return KernelError::BadAddress.sysret();
                    }
                }
                0
            }
            BLKFLSBUF => {
                // Flush buffer cache - for RAM disk this is a no-op
                // (page cache IS the storage)
                0
            }
            _ => KernelError::NotTty.sysret(),
        }
    } else if inode.mode().is_chrdev() {
        // Character device ioctls - route to CharDevice::ioctl()
        use crate::chardev::get_chardev;

        let device = match get_chardev(inode.rdev) {
            Some(d) => d,
            None => return KernelError::NoDeviceOrAddress.sysret(),
        };

        match device.ioctl(cmd, arg) {
            Ok(result) => result,
            Err(crate::chardev::DeviceError::NotTty) => KernelError::NotTty.sysret(),
            Err(crate::chardev::DeviceError::InvalidArg) => KernelError::InvalidArgument.sysret(),
            Err(crate::chardev::DeviceError::NotSupported) => KernelError::NotTty.sysret(),
            Err(_) => KernelError::Io.sysret(),
        }
    } else {
        // Not a device - ioctl not supported
        KernelError::NotTty.sysret()
    }
}

// =============================================================================
// Extended attributes (xattr) syscalls
// =============================================================================

/// XATTR_CREATE - set value, fail if attr already exists
pub const XATTR_CREATE: u32 = 0x1;
/// XATTR_REPLACE - set value, fail if attr doesn't exist
pub const XATTR_REPLACE: u32 = 0x2;
/// Maximum attribute name length
pub const XATTR_NAME_MAX: usize = 255;
/// Maximum attribute value size (64KB)
pub const XATTR_SIZE_MAX: usize = 65536;

/// Helper to convert KernelError to errno for xattr operations
fn xattr_error_to_errno(e: KernelError) -> i64 {
    match e {
        KernelError::NotFound => KernelError::NotFound.sysret(),
        KernelError::NoData => KernelError::NoData.sysret(),
        KernelError::AlreadyExists => KernelError::AlreadyExists.sysret(),
        KernelError::Range => KernelError::Range.sysret(),
        KernelError::OperationNotSupported => KernelError::OperationNotSupported.sysret(),
        KernelError::PermissionDenied => KernelError::NotPermitted.sysret(),
        KernelError::Io => KernelError::Io.sysret(),
        _ => KernelError::InvalidArgument.sysret(),
    }
}

/// Copy xattr value from user space
fn copy_xattr_value_from_user(value_ptr: u64, size: u64) -> Result<alloc::vec::Vec<u8>, i64> {
    use crate::uaccess::copy_from_user;

    if size > XATTR_SIZE_MAX as u64 {
        return Err(KernelError::Range.sysret());
    }

    if size == 0 {
        return Ok(alloc::vec::Vec::new());
    }

    // Validate user buffer
    if !Uaccess::access_ok(value_ptr, size as usize) {
        return Err(KernelError::BadAddress.sysret());
    }

    // Allocate and copy value from user space
    let mut value = vec![0u8; size as usize];
    if copy_from_user::<Uaccess>(&mut value, value_ptr, size as usize).is_err() {
        return Err(KernelError::BadAddress.sysret());
    }
    Ok(value)
}

/// sys_setxattr - set an extended attribute value
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
/// * `name_ptr` - User pointer to attribute name string
/// * `value_ptr` - User pointer to attribute value
/// * `size` - Size of the value
/// * `flags` - XATTR_CREATE or XATTR_REPLACE
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_setxattr(path_ptr: u64, name_ptr: u64, value_ptr: u64, size: u64, flags: i32) -> i64 {
    do_setxattr(path_ptr, name_ptr, value_ptr, size, flags, true)
}

/// sys_lsetxattr - set an extended attribute value (don't follow symlinks)
pub fn sys_lsetxattr(path_ptr: u64, name_ptr: u64, value_ptr: u64, size: u64, flags: i32) -> i64 {
    do_setxattr(path_ptr, name_ptr, value_ptr, size, flags, false)
}

/// Internal helper for setxattr/lsetxattr
fn do_setxattr(
    path_ptr: u64,
    name_ptr: u64,
    value_ptr: u64,
    size: u64,
    flags: i32,
    follow_symlinks: bool,
) -> i64 {
    // Validate flags
    if flags as u32 & !(XATTR_CREATE | XATTR_REPLACE) != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Copy path from user
    let path = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Copy attribute name from user
    let name = match strncpy_from_user::<Uaccess>(name_ptr, XATTR_NAME_MAX + 1) {
        Ok(n) => n,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate name length
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return KernelError::Range.sysret();
    }

    // Copy value from user
    let value = match copy_xattr_value_from_user(value_ptr, size) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Lookup path
    let lookup_flags = if follow_symlinks {
        LookupFlags::open()
    } else {
        LookupFlags {
            follow: false,
            ..LookupFlags::open()
        }
    };

    let dentry = match lookup_path_flags(&path, lookup_flags) {
        Ok(d) => d,
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    };

    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // Call inode operation
    match inode.i_op.setxattr(&inode, &name, &value, flags as u32) {
        Ok(()) => 0,
        Err(e) => xattr_error_to_errno(e),
    }
}

/// sys_fsetxattr - set an extended attribute value on a file descriptor
pub fn sys_fsetxattr(fd: i32, name_ptr: u64, value_ptr: u64, size: u64, flags: i32) -> i64 {
    // Validate flags
    if flags as u32 & !(XATTR_CREATE | XATTR_REPLACE) != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Copy attribute name from user
    let name = match strncpy_from_user::<Uaccess>(name_ptr, XATTR_NAME_MAX + 1) {
        Ok(n) => n,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate name length
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return KernelError::Range.sysret();
    }

    // Copy value from user
    let value = match copy_xattr_value_from_user(value_ptr, size) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let inode = match file.get_inode() {
        Some(i) => i,
        None => return KernelError::BadFd.sysret(),
    };

    // Call inode operation
    match inode.i_op.setxattr(&inode, &name, &value, flags as u32) {
        Ok(()) => 0,
        Err(e) => xattr_error_to_errno(e),
    }
}

/// sys_getxattr - get an extended attribute value
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
/// * `name_ptr` - User pointer to attribute name string
/// * `value_ptr` - User pointer to buffer for attribute value
/// * `size` - Size of the buffer (0 to query size needed)
///
/// # Returns
/// Size of attribute value on success, negative errno on error
pub fn sys_getxattr(path_ptr: u64, name_ptr: u64, value_ptr: u64, size: u64) -> i64 {
    do_getxattr(path_ptr, name_ptr, value_ptr, size, true)
}

/// sys_lgetxattr - get an extended attribute value (don't follow symlinks)
pub fn sys_lgetxattr(path_ptr: u64, name_ptr: u64, value_ptr: u64, size: u64) -> i64 {
    do_getxattr(path_ptr, name_ptr, value_ptr, size, false)
}

/// Internal helper for getxattr/lgetxattr
fn do_getxattr(
    path_ptr: u64,
    name_ptr: u64,
    value_ptr: u64,
    size: u64,
    follow_symlinks: bool,
) -> i64 {
    // Copy path from user
    let path = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Copy attribute name from user
    let name = match strncpy_from_user::<Uaccess>(name_ptr, XATTR_NAME_MAX + 1) {
        Ok(n) => n,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate name length
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return KernelError::Range.sysret();
    }

    // Lookup path
    let lookup_flags = if follow_symlinks {
        LookupFlags::open()
    } else {
        LookupFlags {
            follow: false,
            ..LookupFlags::open()
        }
    };

    let dentry = match lookup_path_flags(&path, lookup_flags) {
        Ok(d) => d,
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    };

    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // If size is 0, query the size needed
    if size == 0 {
        let mut empty_buf: [u8; 0] = [];
        match inode.i_op.getxattr(&inode, &name, &mut empty_buf) {
            Ok(attr_size) => return attr_size as i64,
            Err(e) => return xattr_error_to_errno(e),
        }
    }

    // Validate size
    if size > XATTR_SIZE_MAX as u64 {
        return KernelError::Range.sysret();
    }

    // Validate user buffer
    if !Uaccess::access_ok(value_ptr, size as usize) {
        return KernelError::BadAddress.sysret();
    }

    // Allocate kernel buffer
    let mut value = vec![0u8; size as usize];

    // Get the attribute
    match inode.i_op.getxattr(&inode, &name, &mut value) {
        Ok(attr_size) => {
            // Copy to user
            unsafe {
                core::ptr::copy_nonoverlapping(value.as_ptr(), value_ptr as *mut u8, attr_size);
            }
            attr_size as i64
        }
        Err(e) => xattr_error_to_errno(e),
    }
}

/// sys_fgetxattr - get an extended attribute value from a file descriptor
pub fn sys_fgetxattr(fd: i32, name_ptr: u64, value_ptr: u64, size: u64) -> i64 {
    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Copy attribute name from user
    let name = match strncpy_from_user::<Uaccess>(name_ptr, XATTR_NAME_MAX + 1) {
        Ok(n) => n,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate name length
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return KernelError::Range.sysret();
    }

    let inode = match file.get_inode() {
        Some(i) => i,
        None => return KernelError::BadFd.sysret(),
    };

    // If size is 0, query the size needed
    if size == 0 {
        let mut empty_buf: [u8; 0] = [];
        match inode.i_op.getxattr(&inode, &name, &mut empty_buf) {
            Ok(attr_size) => return attr_size as i64,
            Err(e) => return xattr_error_to_errno(e),
        }
    }

    // Validate size
    if size > XATTR_SIZE_MAX as u64 {
        return KernelError::Range.sysret();
    }

    // Validate user buffer
    if !Uaccess::access_ok(value_ptr, size as usize) {
        return KernelError::BadAddress.sysret();
    }

    // Allocate kernel buffer
    let mut value = vec![0u8; size as usize];

    // Get the attribute
    match inode.i_op.getxattr(&inode, &name, &mut value) {
        Ok(attr_size) => {
            // Copy to user
            unsafe {
                core::ptr::copy_nonoverlapping(value.as_ptr(), value_ptr as *mut u8, attr_size);
            }
            attr_size as i64
        }
        Err(e) => xattr_error_to_errno(e),
    }
}

/// sys_listxattr - list extended attribute names
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
/// * `list_ptr` - User pointer to buffer for null-separated attribute names
/// * `size` - Size of the buffer (0 to query size needed)
///
/// # Returns
/// Total size of attribute names on success, negative errno on error
pub fn sys_listxattr(path_ptr: u64, list_ptr: u64, size: u64) -> i64 {
    do_listxattr(path_ptr, list_ptr, size, true)
}

/// sys_llistxattr - list extended attribute names (don't follow symlinks)
pub fn sys_llistxattr(path_ptr: u64, list_ptr: u64, size: u64) -> i64 {
    do_listxattr(path_ptr, list_ptr, size, false)
}

/// Internal helper for listxattr/llistxattr
fn do_listxattr(path_ptr: u64, list_ptr: u64, size: u64, follow_symlinks: bool) -> i64 {
    // Copy path from user
    let path = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Lookup path
    let lookup_flags = if follow_symlinks {
        LookupFlags::open()
    } else {
        LookupFlags {
            follow: false,
            ..LookupFlags::open()
        }
    };

    let dentry = match lookup_path_flags(&path, lookup_flags) {
        Ok(d) => d,
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    };

    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // If size is 0, query the size needed
    if size == 0 {
        let mut empty_buf: [u8; 0] = [];
        match inode.i_op.listxattr(&inode, &mut empty_buf) {
            Ok(list_size) => return list_size as i64,
            Err(e) => return xattr_error_to_errno(e),
        }
    }

    // Validate user buffer
    if !Uaccess::access_ok(list_ptr, size as usize) {
        return KernelError::BadAddress.sysret();
    }

    // Allocate kernel buffer
    let mut list = vec![0u8; size as usize];

    // Get the list
    match inode.i_op.listxattr(&inode, &mut list) {
        Ok(list_size) => {
            // Copy to user
            unsafe {
                core::ptr::copy_nonoverlapping(list.as_ptr(), list_ptr as *mut u8, list_size);
            }
            list_size as i64
        }
        Err(e) => xattr_error_to_errno(e),
    }
}

/// sys_flistxattr - list extended attribute names from a file descriptor
pub fn sys_flistxattr(fd: i32, list_ptr: u64, size: u64) -> i64 {
    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    let inode = match file.get_inode() {
        Some(i) => i,
        None => return KernelError::BadFd.sysret(),
    };

    // If size is 0, query the size needed
    if size == 0 {
        let mut empty_buf: [u8; 0] = [];
        match inode.i_op.listxattr(&inode, &mut empty_buf) {
            Ok(list_size) => return list_size as i64,
            Err(e) => return xattr_error_to_errno(e),
        }
    }

    // Validate user buffer
    if !Uaccess::access_ok(list_ptr, size as usize) {
        return KernelError::BadAddress.sysret();
    }

    // Allocate kernel buffer
    let mut list = vec![0u8; size as usize];

    // Get the list
    match inode.i_op.listxattr(&inode, &mut list) {
        Ok(list_size) => {
            // Copy to user
            unsafe {
                core::ptr::copy_nonoverlapping(list.as_ptr(), list_ptr as *mut u8, list_size);
            }
            list_size as i64
        }
        Err(e) => xattr_error_to_errno(e),
    }
}

/// sys_removexattr - remove an extended attribute
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
/// * `name_ptr` - User pointer to attribute name string
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_removexattr(path_ptr: u64, name_ptr: u64) -> i64 {
    do_removexattr(path_ptr, name_ptr, true)
}

/// sys_lremovexattr - remove an extended attribute (don't follow symlinks)
pub fn sys_lremovexattr(path_ptr: u64, name_ptr: u64) -> i64 {
    do_removexattr(path_ptr, name_ptr, false)
}

/// Internal helper for removexattr/lremovexattr
fn do_removexattr(path_ptr: u64, name_ptr: u64, follow_symlinks: bool) -> i64 {
    // Copy path from user
    let path = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Copy attribute name from user
    let name = match strncpy_from_user::<Uaccess>(name_ptr, XATTR_NAME_MAX + 1) {
        Ok(n) => n,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate name length
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return KernelError::Range.sysret();
    }

    // Lookup path
    let lookup_flags = if follow_symlinks {
        LookupFlags::open()
    } else {
        LookupFlags {
            follow: false,
            ..LookupFlags::open()
        }
    };

    let dentry = match lookup_path_flags(&path, lookup_flags) {
        Ok(d) => d,
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    };

    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // Call inode operation
    match inode.i_op.removexattr(&inode, &name) {
        Ok(()) => 0,
        Err(e) => xattr_error_to_errno(e),
    }
}

/// sys_fremovexattr - remove an extended attribute from a file descriptor
pub fn sys_fremovexattr(fd: i32, name_ptr: u64) -> i64 {
    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Copy attribute name from user
    let name = match strncpy_from_user::<Uaccess>(name_ptr, XATTR_NAME_MAX + 1) {
        Ok(n) => n,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate name length
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return KernelError::Range.sysret();
    }

    let inode = match file.get_inode() {
        Some(i) => i,
        None => return KernelError::BadFd.sysret(),
    };

    // Call inode operation
    match inode.i_op.removexattr(&inode, &name) {
        Ok(()) => 0,
        Err(e) => xattr_error_to_errno(e),
    }
}

// =============================================================================
// readahead syscall
// =============================================================================

/// sys_readahead - initiate file readahead into the page cache
///
/// This syscall initiates readahead on a file, populating the page cache
/// with pages from the file in preparation for future reads. This can
/// improve read performance by starting I/O before the data is needed.
///
/// # Arguments
/// * `fd` - File descriptor to read ahead
/// * `offset` - Starting offset in the file
/// * `count` - Number of bytes to read ahead
///
/// # Returns
/// 0 on success, negative errno on error:
/// * -EBADF: Invalid file descriptor or not open for reading
/// * -EINVAL: File type doesn't support readahead (e.g., pipes, sockets)
///
/// # Notes
/// This is a hint to the kernel - it may read more or less than requested,
/// and can be a no-op if the kernel doesn't have page cache support.
pub fn sys_readahead(fd: i32, offset: i64, count: usize) -> i64 {
    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Verify file is opened for reading
    if !file.is_readable() {
        return KernelError::BadFd.sysret();
    }

    // Check file type - only regular files and block devices support readahead
    if let Some(inode) = file.get_inode() {
        let mode = inode.mode();
        if !mode.is_file() && !mode.is_blkdev() {
            return KernelError::InvalidArgument.sysret();
        }
    } else {
        // No inode means special file (pipe, socket, etc.)
        return KernelError::InvalidArgument.sysret();
    }

    // Validate offset
    if offset < 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Currently a no-op since we don't have a full page cache.
    // In a full implementation, we would:
    // 1. Calculate page-aligned start and end
    // 2. Call the file's address_space->readahead() method
    // 3. Or use vfs_fadvise(POSIX_FADV_WILLNEED)
    let _ = count; // Suppress unused warning

    0 // Success (hint accepted, even if no action taken)
}
