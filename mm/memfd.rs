//! memfd_create and file sealing (Linux mm/memfd.c)
//!
//! A memfd is an unnamed file on the kernel's tmpfs
//! (`fs::ramfs::tmpfs::shmem_file_setup`). Seals live with every tmpfs file
//! (`AddressSpace.seals`, Linux shmem_inode_info.seals): each starts
//! with F_SEAL_SEAL, which memfd_create clears for MFD_ALLOW_SEALING.
//! They are enforced where Linux shmem does: write_begin (WRITE,
//! FUTURE_WRITE, GROW), truncate (SHRINK, GROW), fallocate, chmod (EXEC)
//! and mmap (`check_seals_mmap`). F_SEAL_WRITE also denies new shared
//! writable mappings on the file's mapping for good
//! (`AddressSpace::deny_writable`).
//!
//! Locking: seals are added under the inode's i_rwsem and read lock-free
//! (Acquire). The deny is an atomic count (doc/LOCKING.md, page cache).

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::fs::flags::{O_LARGEFILE, O_RDWR};
use crate::fs::{File, FileRef};
use crate::uaccess::UserPtr;
use crate::util::error::{KernelError, KernelResult};

/// fcntl commands (Linux F_LINUX_SPECIFIC_BASE + 9, + 10)
pub const F_ADD_SEALS: i32 = 1033;
pub const F_GET_SEALS: i32 = 1034;

/// Seals (Linux include/uapi/linux/fcntl.h)
pub const F_SEAL_SEAL: u32 = 0x0001;
pub const F_SEAL_SHRINK: u32 = 0x0002;
pub const F_SEAL_GROW: u32 = 0x0004;
pub const F_SEAL_WRITE: u32 = 0x0008;
pub const F_SEAL_FUTURE_WRITE: u32 = 0x0010;
pub const F_SEAL_EXEC: u32 = 0x0020;
const F_ALL_SEALS: u32 =
    F_SEAL_SEAL | F_SEAL_EXEC | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE;

/// memfd_create flags (Linux include/uapi/linux/memfd.h)
const MFD_CLOEXEC: u32 = 0x0001;
const MFD_ALLOW_SEALING: u32 = 0x0002;
const MFD_HUGETLB: u32 = 0x0004;
const MFD_NOEXEC_SEAL: u32 = 0x0008;
const MFD_EXEC: u32 = 0x0010;
const MFD_ALL_FLAGS: u32 =
    MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB | MFD_NOEXEC_SEAL | MFD_EXEC;
/// The huge page size field with MFD_HUGETLB
const MFD_HUGE_SHIFT: u32 = 26;
const MFD_HUGE_MASK: u32 = 0x3f;

/// The name's prefix; the name with it fits NAME_MAX
const PREFIX: &[u8] = b"memfd:";
const NAME_MAX_LEN: usize = 255 - PREFIX.len();

/// vm.memfd_noexec values (Linux MEMFD_NOEXEC_SCOPE_*)
const SCOPE_NOEXEC_SEAL: u8 = 1;
const SCOPE_NOEXEC_ENFORCED: u8 = 2;

/// Linux sanitize_flags and check_sysctl_memfd_noexec: unknown flags or
/// MFD_EXEC with MFD_NOEXEC_SEAL are EINVAL; the pid namespace's
/// vm.memfd_noexec picks the default and may refuse MFD_EXEC (EACCES).
/// The flags in force.
fn sanitize(mut flags: u32) -> Result<u32, KernelError> {
    let allowed = if flags & MFD_HUGETLB != 0 {
        MFD_ALL_FLAGS | (MFD_HUGE_MASK << MFD_HUGE_SHIFT)
    } else {
        MFD_ALL_FLAGS
    };
    if flags & !allowed != 0 || flags & (MFD_EXEC | MFD_NOEXEC_SEAL) == MFD_EXEC | MFD_NOEXEC_SEAL {
        return Err(KernelError::InvalidArgument);
    }
    let scope = crate::task::pid::get_current_pid_ns().memfd_noexec();
    if flags & (MFD_EXEC | MFD_NOEXEC_SEAL) == 0 {
        flags |= if scope >= SCOPE_NOEXEC_SEAL {
            MFD_NOEXEC_SEAL
        } else {
            MFD_EXEC
        };
    }
    if flags & MFD_NOEXEC_SEAL == 0 && scope >= SCOPE_NOEXEC_ENFORCED {
        return Err(KernelError::PermissionDenied);
    }
    Ok(flags)
}

/// "memfd:" and the caller's name (Linux alloc_name): EFAULT, EINVAL
/// past NAME_MAX with the prefix
fn alloc_name(uname: UserPtr<u8>) -> Result<Vec<u8>, KernelError> {
    let name =
        crate::uaccess::strncpy_from_user(uname.addr(), NAME_MAX_LEN + 1).map_err(|e| match e {
            crate::uaccess::UaccessError::TooLong => KernelError::InvalidArgument,
            _ => KernelError::BadAddress,
        })?;
    let mut full = crate::util::kmem::try_vec(PREFIX.len() + name.len(), 0u8)?;
    full[..PREFIX.len()].copy_from_slice(PREFIX);
    full[PREFIX.len()..].copy_from_slice(&name);
    Ok(full)
}

/// memfd_create(name, flags): a new memfd's descriptor (Linux
/// SYSCALL_DEFINE2(memfd_create)); MFD_HUGETLB is ENOSYS (no hugetlbfs,
/// as Linux hugetlb_file_setup without CONFIG_HUGETLBFS)
pub fn sys_memfd_create(uname: UserPtr<u8>, flags: u32) -> KernelResult<i32> {
    let flags = sanitize(flags)?;
    let name = alloc_name(uname)?;
    if flags & MFD_HUGETLB != 0 {
        return Err(KernelError::NotImplemented);
    }
    let file = crate::fs::ramfs::tmpfs::shmem_file_setup(&name, 0, O_RDWR | O_LARGEFILE)?;
    let inode = file.get_inode().ok_or(KernelError::Io)?;
    if flags & MFD_NOEXEC_SEAL != 0 {
        inode.set_mode_perm(inode.mode().perm() & !0o111);
    }
    crate::fs::ramfs::with_seals(&inode, |s| {
        if flags & MFD_NOEXEC_SEAL != 0 {
            s.store(F_SEAL_EXEC, Ordering::Release);
        } else if flags & MFD_ALLOW_SEALING != 0 {
            s.fetch_and(!F_SEAL_SEAL, Ordering::AcqRel);
        }
    });
    let fd_flags = if flags & MFD_CLOEXEC != 0 {
        crate::task::FD_CLOEXEC
    } else {
        0
    };
    crate::fs::io::fd_install(file, fd_flags)
}

/// F_ADD_SEALS and F_GET_SEALS (Linux memfd_fcntl)
pub fn fcntl(file: &FileRef, cmd: i32, arg: u64) -> KernelResult<i64> {
    let inode = file.get_inode().ok_or(KernelError::InvalidArgument)?;
    if cmd == F_GET_SEALS {
        let s = crate::fs::ramfs::with_seals(&inode, |s| s.load(Ordering::Acquire));
        return s.map(i64::from).ok_or(KernelError::InvalidArgument);
    }
    // Linux memfd_add_seals: write access, known seals, then under the
    // inode lock a sealable file not sealed against it
    if !file.is_writable() {
        return Err(KernelError::NotPermitted);
    }
    // An unsigned int (Linux memfd_fcntl): the high bits are dropped
    let mut seals = arg as u32;
    if seals & !F_ALL_SEALS != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let _lock = inode.lock();
    crate::fs::ramfs::with_seals(&inode, |cur| {
        let now = cur.load(Ordering::Acquire);
        if now & F_SEAL_SEAL != 0 {
            return Err(KernelError::NotPermitted);
        }
        // F_SEAL_EXEC on an executable file makes it W^X from the start
        if seals & F_SEAL_EXEC != 0 && inode.mode().perm() & 0o111 != 0 {
            seals |= F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE;
        }
        // No shared writable mapping may exist or be made after it
        if seals & F_SEAL_WRITE != 0 && now & F_SEAL_WRITE == 0 {
            inode.i_data.deny_writable()?;
        }
        cur.fetch_or(seals, Ordering::AcqRel);
        Ok(0)
    })
    .ok_or(KernelError::InvalidArgument)?
}

/// mmap of a write-sealed file (Linux memfd_check_seals_mmap): a
/// shared writable mapping is EPERM, a read-only shared one may never
/// become writable (VM_NOMAYWRITE in the result); private mappings are
/// unaffected
pub fn check_seals_mmap(file: &File, prot: u32, shared: bool) -> Result<u32, KernelError> {
    let Some(inode) = file.get_inode() else {
        return Ok(0);
    };
    let seals = crate::fs::ramfs::with_seals(&inode, |s| s.load(Ordering::Acquire)).unwrap_or(0);
    if !shared || seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) == 0 {
        return Ok(0);
    }
    if prot & super::PROT_WRITE != 0 {
        return Err(KernelError::NotPermitted);
    }
    Ok(super::vma::VM_NOMAYWRITE)
}

/// vm.memfd_noexec, per pid namespace (Linux
/// pid_mfd_noexec_dointvec_minmax): CAP_SYS_ADMIN to write (EPERM), not
/// below the parent namespace's scope nor above 2 (EINVAL)
pub static MEMFD_CTLS: &[crate::sysctl::Ctl] = &[crate::sysctl::Ctl {
    path: "vm/memfd_noexec",
    mode: 0o644,
    show: || {
        alloc::vec![i64::from(
            crate::task::pid::get_current_pid_ns().memfd_noexec()
        )]
    },
    store: |v| {
        if !crate::task::capable(crate::task::CAP_SYS_ADMIN) {
            return Err(KernelError::NotPermitted);
        }
        let ns = crate::task::pid::get_current_pid_ns();
        let floor = ns.parent.as_ref().map_or(0, |p| p.memfd_noexec());
        crate::sysctl::range(v[0], i64::from(floor), 2)?;
        ns.memfd_noexec.store(v[0] as u8, Ordering::Relaxed);
        Ok(())
    },
    text: None,
}];
