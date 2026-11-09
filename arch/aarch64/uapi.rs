//! aarch64 userspace ABI structures and constants that differ between architectures
//!
//! arm64 mostly uses the asm-generic UAPI (include/uapi/asm-generic/) plus
//! overrides in arch/arm64/include/uapi/asm/ in Linux.

/// prctl PR_GET_TSC/PR_SET_TSC exist (Linux GET_TSC_CTL)
pub const TSC_CTL: bool = false;

/// uname(2) machine (Linux UTS_MACHINE)
pub const UTS_MACHINE: &[u8] = b"aarch64";

/// The syscall ABI's audit and seccomp_data arch (Linux syscall_get_arch)
pub const AUDIT_ARCH: u32 = crate::seccomp::AUDIT_ARCH_AARCH64;

/// ELF e_machine of native executables (Linux ELF_ARCH)
pub const ELF_ARCH: u16 = crate::util::elf::EM_AARCH64;

/// The RELATIVE relocation type (Linux R_AARCH64_RELATIVE)
pub const R_RELATIVE: u32 = crate::util::elf::R_AARCH64_RELATIVE;

/// The syscalls seccomp strict mode allows: read, write, exit,
/// exit_group, rt_sigreturn (Linux __NR_seccomp_*; an int, like the
/// number seccomp checks)
pub const SECCOMP_STRICT: [i32; 5] = {
    use super::syscall::{SYS_EXIT, SYS_EXIT_GROUP, SYS_READ, SYS_RT_SIGRETURN, SYS_WRITE};
    // Syscall numbers fit an int
    [
        SYS_READ as i32,
        SYS_WRITE as i32,
        SYS_EXIT as i32,
        SYS_EXIT_GROUP as i32,
        SYS_RT_SIGRETURN as i32,
    ]
};

/// `st_nlink` from an inode link count; the field is u32 on this arch
pub fn st_nlink(n: u32) -> u32 {
    n
}

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
crate::pod!(Stat {
    st_dev,
    st_ino,
    st_mode,
    st_nlink,
    st_uid,
    st_gid,
    st_rdev,
    __pad1,
    st_size,
    st_blksize,
    __pad2,
    st_blocks,
    st_atime,
    st_atime_nsec,
    st_mtime,
    st_mtime_nsec,
    st_ctime,
    st_ctime_nsec,
    __unused4,
    __unused5
});

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
crate::pod!(EpollEvent {
    events,
    __pad,
    data
});

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
crate::pod!(Semid64Ds {
    sem_perm,
    sem_otime,
    sem_ctime,
    sem_nsems,
    __unused3,
    __unused4
});
