//! Directory syscalls (getdents64, mkdir, mkdirat, rmdir, mknod, mknodat)

use crate::arch::Uaccess;
use crate::fs::path::{create_entry, delete_entry};
use crate::fs::{FileType, InodeMode, KernelError, dac};
use crate::task::CAP_MKNOD;
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
    let path = match strncpy_from_user::<Uaccess>(pathname_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };
    if path.is_empty() {
        return KernelError::NotFound.sysret();
    }
    let (parent, name) = match lookup_parent_at(dirfd, &path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    // vfs_mkdir: permission and sticky bits only, then umask; init_owner
    // adds S_ISGID under a SGID parent
    let r = create_entry(&parent, &name, |dir, c| {
        let perm = dac::create_mode(c, dir, (mode & 0o1777) as u16);
        dir.i_op.mkdir(dir, &name, InodeMode::directory(perm))
    });
    match r {
        Ok(_) => 0,
        Err(KernelError::OperationNotSupported) => KernelError::NotPermitted.sysret(),
        Err(e) => e.sysret(),
    }
}

/// sys_rmdir - remove an empty directory
pub fn sys_rmdir(pathname_ptr: u64) -> i64 {
    let path = match strncpy_from_user::<Uaccess>(pathname_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };
    do_rmdir(AT_FDCWD, &path)
}

/// rmdir / unlinkat(AT_REMOVEDIR) (Linux do_rmdir): "." is EINVAL,
/// ".." ENOTEMPTY, then may_delete and the file system's rmdir
pub fn do_rmdir(dirfd: i32, path: &str) -> i64 {
    if path.is_empty() {
        return KernelError::NotFound.sysret();
    }
    let (parent, name) = match lookup_parent_at(dirfd, path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match name.as_str() {
        "." => return KernelError::InvalidArgument.sysret(),
        ".." => return KernelError::DirectoryNotEmpty.sysret(),
        _ => {}
    }
    match delete_entry(&parent, &name, true) {
        Ok(()) => 0,
        Err(e) => e.sysret(),
    }
}

/// sys_mknod - create a special or ordinary file
pub fn sys_mknod(pathname_ptr: u64, mode: u32, dev: u64) -> i64 {
    sys_mknodat(AT_FDCWD, pathname_ptr, mode, dev)
}

/// sys_mknodat - create a special or ordinary file relative to directory fd
///
/// Device nodes need CAP_MKNOD (checked after the parent's permission,
/// like vfs_mknod). FIFOs, sockets and device nodes are created as
/// regular files for now.
pub fn sys_mknodat(dirfd: i32, pathname_ptr: u64, mode: u32, _dev: u64) -> i64 {
    const S_IFREG: u32 = 0o100000;
    const S_IFCHR: u32 = 0o020000;
    const S_IFBLK: u32 = 0o060000;
    const S_IFIFO: u32 = 0o010000;
    const S_IFSOCK: u32 = 0o140000;
    const S_IFDIR: u32 = 0o040000;
    const S_IFMT: u32 = 0o170000;

    let path = match strncpy_from_user::<Uaccess>(pathname_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };
    if path.is_empty() {
        return KernelError::NotFound.sysret();
    }

    // may_mknod: file type validity
    let ty = mode & S_IFMT;
    let dev = match ty {
        S_IFREG | 0 | S_IFIFO | S_IFSOCK => false,
        S_IFCHR | S_IFBLK => true,
        S_IFDIR => return KernelError::NotPermitted.sysret(),
        _ => return KernelError::InvalidArgument.sysret(),
    };

    let (parent, name) = match lookup_parent_at(dirfd, &path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let r = create_entry(&parent, &name, |dir, c| {
        if dev && !dac::capable(c, CAP_MKNOD) {
            return Err(KernelError::NotPermitted);
        }
        let perm = dac::create_mode(c, dir, (mode & 0o7777) as u16);
        dir.i_op.create(dir, &name, InodeMode::regular(perm))
    });
    match r {
        Ok(_) => 0,
        Err(KernelError::OperationNotSupported) => KernelError::NotPermitted.sysret(),
        Err(e) => e.sysret(),
    }
}
