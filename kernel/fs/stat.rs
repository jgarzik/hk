//! File status syscalls (stat, fstat, fstatat, lstat, statfs, fstatfs, statx)

use crate::arch::Uaccess;
use crate::fs::{
    Inode, KernelError, LinuxStatFs, LookupFlags, Path, lookup_path_at, lookup_path_flags,
};
use crate::uaccess::{UaccessArch, put_user, strncpy_from_user};

use super::syscall::{AT_FDCWD, PATH_MAX, current_fd_table};

// =============================================================================
// Stat structure and helpers
// =============================================================================

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
fn fill_stat(inode: &Inode) -> Stat {
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

// =============================================================================
// stat, fstat, fstatat, lstat syscalls
// =============================================================================

/// sys_stat - get file status by path
///
/// Returns 0 on success, negative errno on error.
pub fn sys_stat(path_ptr: u64, statbuf: u64) -> i64 {
    // Read path from user space with proper validation
    let path = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate stat buffer address
    if !Uaccess::access_ok(statbuf, core::mem::size_of::<Stat>()) {
        return KernelError::BadAddress.sysret();
    }

    // Look up the path (follow symlinks)
    let dentry = match lookup_path_flags(&path, LookupFlags::open()) {
        Ok(d) => d,
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    };

    // Get the inode
    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // Fill the stat structure
    let stat = fill_stat(&inode);

    // Copy to user space using put_user for the entire structure
    if put_user::<Uaccess, Stat>(statbuf, stat).is_err() {
        return KernelError::BadAddress.sysret();
    }

    0
}

/// sys_fstat - get file status by file descriptor
///
/// Returns 0 on success, negative errno on error.
pub fn sys_fstat(fd: i32, statbuf: u64) -> i64 {
    // Validate stat buffer address
    if !Uaccess::access_ok(statbuf, core::mem::size_of::<Stat>()) {
        return KernelError::BadAddress.sysret();
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Get the inode
    let inode = match file.get_inode() {
        Some(i) => i,
        None => return KernelError::BadFd.sysret(),
    };

    // Fill the stat structure
    let stat = fill_stat(&inode);

    // Copy to user space using put_user for the entire structure
    if put_user::<Uaccess, Stat>(statbuf, stat).is_err() {
        return KernelError::BadAddress.sysret();
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
        return KernelError::InvalidArgument.sysret();
    }

    // Validate stat buffer address
    if !Uaccess::access_ok(statbuf, core::mem::size_of::<Stat>()) {
        return KernelError::BadAddress.sysret();
    }

    // Read path from user space
    let path_str = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Handle AT_EMPTY_PATH - stat the dirfd itself
    if (flags & AT_EMPTY_PATH_FLAG) != 0 && path_str.is_empty() {
        if dirfd == AT_FDCWD {
            return KernelError::InvalidArgument.sysret();
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
            None => return KernelError::BadFd.sysret(),
        };
        if !file.is_dir() {
            return KernelError::NotDirectory.sysret();
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
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(KernelError::TooManySymlinks) => return KernelError::TooManySymlinks.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    };

    // Get the inode
    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // Fill the stat structure
    let stat = fill_stat(&inode);

    // Copy to user space
    if put_user::<Uaccess, Stat>(statbuf, stat).is_err() {
        return KernelError::BadAddress.sysret();
    }

    0
}

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
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate stat buffer address
    if !Uaccess::access_ok(statbuf, core::mem::size_of::<Stat>()) {
        return KernelError::BadAddress.sysret();
    }

    // Look up the path without following symlinks
    let mut flags = LookupFlags::open();
    flags.follow = false;

    let dentry = match lookup_path_flags(&path, flags) {
        Ok(d) => d,
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(KernelError::TooManySymlinks) => return KernelError::TooManySymlinks.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    };

    // Get the inode
    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // Fill the stat structure
    let stat = fill_stat(&inode);

    // Copy to user space using put_user for the entire structure
    if put_user::<Uaccess, Stat>(statbuf, stat).is_err() {
        return KernelError::BadAddress.sysret();
    }

    0
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

// AT_* flags used by statx
/// Sync as stat (default)
pub const AT_STATX_SYNC_AS_STAT: i32 = 0x0000;
/// Force sync
pub const AT_STATX_FORCE_SYNC: i32 = 0x2000;
/// Don't sync
pub const AT_STATX_DONT_SYNC: i32 = 0x4000;

/// Don't follow symbolic links
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
/// If pathname is empty, check dirfd itself
const AT_EMPTY_PATH: i32 = 0x1000;

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
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate buffer
    if !Uaccess::access_ok(buf, core::mem::size_of::<LinuxStatFs>()) {
        return KernelError::BadAddress.sysret();
    }

    // Look up path to get dentry/superblock
    let dentry = match lookup_path_flags(&path, LookupFlags::open()) {
        Ok(d) => d,
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    };

    // Get superblock
    let sb = match dentry.superblock() {
        Some(sb) => sb,
        None => return KernelError::NotFound.sysret(),
    };

    // Get stats from filesystem
    let statfs = sb.s_op.statfs();
    let linux_statfs = statfs.to_linux(sb.dev_id, sb.flags);

    // Copy to user
    if put_user::<Uaccess, LinuxStatFs>(buf, linux_statfs).is_err() {
        return KernelError::BadAddress.sysret();
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
        return KernelError::BadAddress.sysret();
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Get superblock from file's dentry
    let sb = match file.dentry.superblock() {
        Some(sb) => sb,
        None => return KernelError::BadFd.sysret(),
    };

    // Get stats
    let statfs = sb.s_op.statfs();
    let linux_statfs = statfs.to_linux(sb.dev_id, sb.flags);

    // Copy to user
    if put_user::<Uaccess, LinuxStatFs>(buf, linux_statfs).is_err() {
        return KernelError::BadAddress.sysret();
    }

    0
}

// =============================================================================
// statx syscall
// =============================================================================

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
        return KernelError::BadAddress.sysret();
    }

    // Read path from user space
    let path = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Handle AT_EMPTY_PATH (statx on fd itself)
    let dentry = if path.is_empty() && (flags & AT_EMPTY_PATH) != 0 {
        if dirfd < 0 {
            return KernelError::BadFd.sysret();
        }
        match current_fd_table().lock().get(dirfd) {
            Some(f) => f.dentry.clone(),
            None => return KernelError::BadFd.sysret(),
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
                None => return KernelError::BadFd.sysret(),
            };
            if !file.is_dir() {
                return KernelError::NotDirectory.sysret();
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
            Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
            Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
            Err(_) => return KernelError::InvalidArgument.sysret(),
        }
    };

    // Get inode
    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // Fill statx structure
    let statx = fill_statx(&inode, mask);

    // Copy to user
    if put_user::<Uaccess, Statx>(buf, statx).is_err() {
        return KernelError::BadAddress.sysret();
    }

    0
}
