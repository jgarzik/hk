//! aarch64 userspace ABI structures and constants that differ between architectures
//!
//! arm64 mostly uses the asm-generic UAPI (include/uapi/asm-generic/) plus
//! overrides in arch/arm64/include/uapi/asm/ in Linux.

/// `struct stat` (include/uapi/asm-generic/stat.h)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub __pad1: u64,
    pub st_size: i64,
    pub st_blksize: i32,
    pub __pad2: i32,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: u64,
    pub st_mtime: i64,
    pub st_mtime_nsec: u64,
    pub st_ctime: i64,
    pub st_ctime_nsec: u64,
    pub __unused4: u32,
    pub __unused5: u32,
}

// O_* flags whose values differ per arch (arch/arm64/include/uapi/asm/fcntl.h)
/// Must be a directory
pub const O_DIRECTORY: u32 = 0o40000;
/// Don't follow a trailing symlink
pub const O_NOFOLLOW: u32 = 0o100000;

/// `struct epoll_event` (include/uapi/linux/eventpoll.h): not packed on
/// arm64, so 16 bytes with `data` at offset 8. `data` is a union in Linux.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EpollEvent {
    /// Event mask (EPOLLIN, EPOLLOUT, etc.)
    pub events: u32,
    /// Explicit padding: always zero so no kernel bytes leak to userspace
    pub __pad: u32,
    /// User data (passed back unchanged)
    pub data: u64,
}

impl EpollEvent {
    /// Build an event with zeroed padding
    pub const fn new(events: u32, data: u64) -> Self {
        Self {
            events,
            __pad: 0,
            data,
        }
    }
}

/// `struct semid64_ds` (include/uapi/asm-generic/sembuf.h)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Semid64Ds {
    pub sem_perm: crate::ipc::Ipc64Perm,
    pub sem_otime: i64,
    pub sem_ctime: i64,
    pub sem_nsems: u64,
    pub __unused3: u64,
    pub __unused4: u64,
}
