//! File status syscalls (stat, fstat, fstatat, lstat, statfs, fstatfs, statx)

use crate::arch::Uaccess;
use crate::arch::uapi::Stat;
use crate::fs::namei::{filename_lookup, getname_maybe_null, user_path_at};
use crate::fs::{Inode, KernelError, LinuxStatFs, LookupFlags};
use crate::uaccess::{UaccessArch, put_user};

use super::file::flags::{AT_EMPTY_PATH, AT_FDCWD, AT_NO_AUTOMOUNT, AT_SYMLINK_NOFOLLOW};
use super::syscall::current_fd_table;

// =============================================================================
// Stat structure and helpers
// =============================================================================

/// Fill a Stat structure from an inode
fn fill_stat(inode: &Inode) -> Stat {
    let attr = inode.i_op.getattr(inode);

    // Get device ID from superblock (filesystem device)
    let st_dev = inode.superblock().map(|sb| sb.dev_id).unwrap_or(0);

    // Get rdev for device files (char/block device major/minor)
    let st_rdev = if attr.mode.is_device() {
        attr.rdev.to_user()
    } else {
        0
    };

    // Field types differ per arch (e.g. st_nlink/st_blksize width), hence `as _`
    Stat {
        st_dev,
        st_ino: attr.ino,
        st_nlink: attr.nlink as _,
        st_mode: attr.mode.raw() as u32,
        st_uid: attr.uid,
        st_gid: attr.gid,
        st_rdev,
        st_size: attr.size as i64,
        st_blksize: 4096,
        st_blocks: attr.size.div_ceil(512) as i64,
        st_atime: attr.atime.sec,
        st_atime_nsec: attr.atime.nsec as _,
        st_mtime: attr.mtime.sec,
        st_mtime_nsec: attr.mtime.nsec as _,
        st_ctime: attr.ctime.sec,
        st_ctime_nsec: attr.ctime.nsec as _,
        ..Default::default()
    }
}

// =============================================================================
// stat, fstat, fstatat, lstat syscalls
// =============================================================================

/// sys_stat - get file status by path
pub fn sys_stat(path_ptr: u64, statbuf: u64) -> i64 {
    ret(stat_path(AT_FDCWD, path_ptr, 0, statbuf))
}

/// stat/lstat/fstatat (Linux vfs_fstatat): flags of statx's set, the
/// stat copied out after the lookup
fn stat_path(dirfd: i32, path_ptr: u64, flags: i32, statbuf: u64) -> Result<(), KernelError> {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | AT_STATX_SYNC_TYPE) != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let path = getname_maybe_null(path_ptr, flags)?;
    let dentry = filename_lookup(dirfd, &path, LookupFlags::at(flags))?;
    let inode = dentry.get_inode().ok_or(KernelError::NotFound)?;
    put_user::<Uaccess, Stat>(statbuf, fill_stat(&inode)).map_err(|_| KernelError::BadAddress)
}

fn ret(r: Result<(), KernelError>) -> i64 {
    match r {
        Ok(()) => 0,
        Err(e) => e.sysret(),
    }
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

/// sys_fstatat - stat/lstat relative to a directory fd (newfstatat)
pub fn sys_fstatat(dirfd: i32, path_ptr: u64, statbuf: u64, flags: i32) -> i64 {
    ret(stat_path(dirfd, path_ptr, flags, statbuf))
}

/// sys_lstat - get file status without following a final symlink
pub fn sys_lstat(path_ptr: u64, statbuf: u64) -> i64 {
    ret(stat_path(AT_FDCWD, path_ptr, AT_SYMLINK_NOFOLLOW, statbuf))
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
crate::pod!(StatxTimestamp {
    tv_sec,
    tv_nsec,
    __reserved
});

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
crate::pod!(Statx {
    stx_mask,
    stx_blksize,
    stx_attributes,
    stx_nlink,
    stx_uid,
    stx_gid,
    stx_mode,
    __spare0,
    stx_ino,
    stx_size,
    stx_blocks,
    stx_attributes_mask,
    stx_atime,
    stx_btime,
    stx_ctime,
    stx_mtime,
    stx_rdev_major,
    stx_rdev_minor,
    stx_dev_major,
    stx_dev_minor,
    stx_mnt_id,
    stx_dio_mem_align,
    stx_dio_offset_align,
    stx_subvol,
    stx_atomic_write_unit_min,
    stx_atomic_write_unit_max,
    stx_atomic_write_segments_max,
    stx_dio_read_offset_align,
    stx_atomic_write_unit_max_opt,
    __spare2,
    __spare3
});

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
/// Got the never-reused mount id in stx_mnt_id
pub const STATX_MNT_ID_UNIQUE: u32 = 0x4000;

// AT_* flags used by statx
/// Sync as stat (default)
pub const AT_STATX_SYNC_AS_STAT: i32 = 0x0000;
/// Force sync
pub const AT_STATX_FORCE_SYNC: i32 = 0x2000;
/// Don't sync
pub const AT_STATX_DONT_SYNC: i32 = 0x4000;
/// The sync type bits
const AT_STATX_SYNC_TYPE: i32 = AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC;

// =============================================================================
// statfs/fstatfs syscalls
// =============================================================================

/// sys_statfs - get filesystem statistics by path
pub fn sys_statfs(path_ptr: u64, buf: u64) -> i64 {
    let r = user_path_at(AT_FDCWD, path_ptr, LookupFlags::open(), false).and_then(|path| {
        let sb = path.dentry.superblock().ok_or(KernelError::NotFound)?;
        let st = sb
            .s_op
            .statfs()
            .to_linux(sb.dev_id, st_flags(path.mnt.flags(), &sb));
        put_user::<Uaccess, LinuxStatFs>(buf, st).map_err(|_| KernelError::BadAddress)
    });
    ret(r)
}

/// statfs f_flags (Linux calculate_f_flags): ST_VALID, ST_RDONLY from
/// the superblock, ST_NOSUID/NODEV/NOEXEC from the mount
fn st_flags(mnt_flags: u32, sb: &super::SuperBlock) -> u64 {
    const ST_VALID: u64 = 0x20;
    // MNT_NOSUID/NODEV/NOEXEC (1, 2, 4) map to ST_NOSUID/NODEV/NOEXEC (2, 4, 8)
    let mnt = mnt_flags as u64;
    ST_VALID | sb.rdonly() as u64 | (mnt & 7) << 1
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
    let linux_statfs = statfs.to_linux(
        sb.dev_id,
        st_flags(file.f_path().map_or(0, |p| p.mnt.flags()), &sb),
    );

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
fn fill_statx(inode: &Inode, mask: u32, mnt: Option<&super::mount::Mount>) -> Statx {
    let attr = inode.i_op.getattr(inode);
    let st_dev = inode.superblock().map(|sb| sb.dev_id).unwrap_or(0);

    let st_rdev = if attr.mode.is_device() {
        attr.rdev.to_user()
    } else {
        0
    };

    Statx {
        // Basic stats, and the mount id: the unique one if asked for
        // (Linux vfs_getattr: STATX_MNT_ID_UNIQUE), else the reused one
        stx_mask: STATX_BASIC_STATS
            | if mask & STATX_MNT_ID_UNIQUE != 0 {
                STATX_MNT_ID_UNIQUE
            } else {
                STATX_MNT_ID
            },
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
        stx_mnt_id: match mnt {
            Some(m) if mask & STATX_MNT_ID_UNIQUE != 0 => m.mnt_id_unique,
            Some(m) => m.mnt_id as u64,
            None => 0,
        },
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

/// sys_statx - get extended file status (Linux do_statx + vfs_statx)
pub fn sys_statx(dirfd: i32, path_ptr: u64, flags: i32, mask: u32, buf: u64) -> i64 {
    const STATX_RESERVED: u32 = 0x8000_0000;
    let r = (|| {
        if mask & STATX_RESERVED != 0 || flags & AT_STATX_SYNC_TYPE == AT_STATX_SYNC_TYPE {
            return Err(KernelError::InvalidArgument);
        }
        if flags & !(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | AT_STATX_SYNC_TYPE)
            != 0
        {
            return Err(KernelError::InvalidArgument);
        }
        let path = getname_maybe_null(path_ptr, flags)?;
        let p = filename_lookup(dirfd, &path, LookupFlags::at(flags))?;
        let inode = p.dentry.get_inode().ok_or(KernelError::NotFound)?;
        put_user::<Uaccess, Statx>(buf, fill_statx(&inode, mask, Some(&p.mnt)))
            .map_err(|_| KernelError::BadAddress)
    })();
    ret(r)
}
