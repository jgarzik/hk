//! x86-64 userspace ABI structures and constants that differ between architectures
//!
//! Mirrors arch/x86/include/uapi/asm/ in Linux.

/// `struct stat` (arch/x86/include/uapi/asm/stat.h, x86_64 layout)
#[repr(C)]
#[derive(Clone, Copy, Default)]
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

// O_* flags whose values differ per arch (include/uapi/asm-generic/fcntl.h)
/// Must be a directory
pub const O_DIRECTORY: u32 = 0o200000;
/// Don't follow a trailing symlink
pub const O_NOFOLLOW: u32 = 0o400000;
