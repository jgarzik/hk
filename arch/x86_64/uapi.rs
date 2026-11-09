//! x86-64 userspace ABI structures and constants that differ between architectures
//!
//! Mirrors arch/x86/include/uapi/asm/ in Linux.

/// prctl PR_GET_TSC/PR_SET_TSC exist (Linux GET_TSC_CTL)
pub const TSC_CTL: bool = true;

/// uname(2) machine (Linux UTS_MACHINE)
pub const UTS_MACHINE: &[u8] = b"x86_64";

/// The syscall ABI's audit and seccomp_data arch (Linux syscall_get_arch)
pub const AUDIT_ARCH: u32 = crate::seccomp::AUDIT_ARCH_X86_64;

/// ELF e_machine of native executables (Linux ELF_ARCH)
pub const ELF_ARCH: u16 = crate::util::elf::EM_X86_64;

/// The smallest alternate signal stack sigaltstack takes (Linux
/// MINSIGSTKSZ, arch/x86/include/uapi/asm/signal.h)
pub const MINSIGSTKSZ: usize = 2048;

/// The RELATIVE relocation type (Linux R_X86_64_RELATIVE)
pub const R_RELATIVE: u32 = crate::util::elf::R_X86_64_RELATIVE;

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

/// `st_nlink` from an inode link count; the field is u64 on this arch
pub fn st_nlink(n: u32) -> u64 {
    u64::from(n)
}

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
crate::pod!(Stat {
    st_dev,
    st_ino,
    st_nlink,
    st_mode,
    st_uid,
    st_gid,
    __pad0,
    st_rdev,
    st_size,
    st_blksize,
    st_blocks,
    st_atime,
    st_atime_nsec,
    st_mtime,
    st_mtime_nsec,
    st_ctime,
    st_ctime_nsec,
    __unused
});

// O_* flags whose values differ per arch (include/uapi/asm-generic/fcntl.h)
/// Must be a directory
pub const O_DIRECTORY: u32 = 0o200000;
/// Large-file offsets (always on 64-bit; Linux sets it on every open
/// file, force_o_largefile)
pub const O_LARGEFILE: u32 = 0o100000;
/// Direct I/O, bypassing the page cache
pub const O_DIRECT: u32 = 0o40000;
/// Don't follow a trailing symlink
pub const O_NOFOLLOW: u32 = 0o400000;

/// `struct epoll_event` (include/uapi/linux/eventpoll.h): EPOLL_PACKED on
/// x86_64, so 12 bytes with `data` at offset 4. `data` is a union in Linux.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EpollEvent {
    /// Event mask (EPOLLIN, EPOLLOUT, etc.)
    pub events: u32,
    /// User data (passed back unchanged)
    pub data: u64,
}
crate::pod!(EpollEvent { events, data });

impl EpollEvent {
    /// Build an event
    pub const fn new(events: u32, data: u64) -> Self {
        Self { events, data }
    }
}

/// `struct semid64_ds` (arch/x86/include/uapi/asm/sembuf.h): x86_64 keeps
/// an unused word after each time field
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Semid64Ds {
    pub sem_perm: crate::ipc::Ipc64Perm,
    pub sem_otime: i64,
    pub __unused1: u64,
    pub sem_ctime: i64,
    pub __unused2: u64,
    pub sem_nsems: u64,
    pub __unused3: u64,
    pub __unused4: u64,
}
crate::pod!(Semid64Ds {
    sem_perm,
    sem_otime,
    __unused1,
    sem_ctime,
    __unused2,
    sem_nsems,
    __unused3,
    __unused4
});
