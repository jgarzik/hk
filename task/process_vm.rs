//! process_vm_readv / process_vm_writev syscalls (Linux
//! mm/process_vm_access.c)
//!
//! Cross-process memory access syscalls for debugging, container runtimes,
//! and process inspection utilities.

extern crate alloc;

use alloc::vec::Vec;

use crate::arch::Uaccess;
use crate::fs::iov::{IoVec, import_iovec};
use crate::fs::syscall::IOV_MAX;
use crate::mm::MmRef;
use crate::mm::remote::{access_remote_vm_read, access_remote_vm_write};
use crate::task::percpu::current_tid;
use crate::task::{Pid, Tid};
use crate::uaccess::{UaccessArch, UserPtr, UserSlice, copy_from_user, copy_to_user};
use crate::util::error::{KernelError, KernelResult};

/// Bytes copied per step: the bounce buffer stays small whatever the
/// iovec lengths (Linux copies page by page)
const PVM_CHUNK: usize = 64 * 1024;

/// sys_process_vm_readv - copy from another process's memory (the
/// remote iovecs) into the caller's (the local ones)
///
/// Returns the bytes copied, or a negative errno if none were
pub fn sys_process_vm_readv(
    pid: i32,
    local_iov: UserPtr<IoVec>,
    liovcnt: u64,
    remote_iov: UserPtr<IoVec>,
    riovcnt: u64,
    flags: u64,
) -> KernelResult<u64> {
    process_vm_rw(pid, local_iov, liovcnt, remote_iov, riovcnt, flags, false)
}

/// sys_process_vm_writev - copy from the caller's memory (the local
/// iovecs) into another process's (the remote ones)
///
/// Returns the bytes copied, or a negative errno if none were
pub fn sys_process_vm_writev(
    pid: i32,
    local_iov: UserPtr<IoVec>,
    liovcnt: u64,
    remote_iov: UserPtr<IoVec>,
    riovcnt: u64,
    flags: u64,
) -> KernelResult<u64> {
    process_vm_rw(pid, local_iov, liovcnt, remote_iov, riovcnt, flags, true)
}

/// Linux process_vm_rw: flags (EINVAL), the local iovecs as readv
/// takes them (import_iovec: IOV_MAX and negative lengths EINVAL, an
/// address outside user space EFAULT, the total cut to MAX_RW_COUNT),
/// nothing to do if they hold no byte, then the remote iovecs
/// (iovec_from_user) and the copy
fn process_vm_rw(
    pid: i32,
    lvec: UserPtr<IoVec>,
    liovcnt: u64,
    rvec: UserPtr<IoVec>,
    riovcnt: u64,
    flags: u64,
    write: bool,
) -> KernelResult<u64> {
    if flags != 0 {
        return Err(KernelError::InvalidArgument);
    }
    // import_iovec takes the count as an unsigned int: truncated on
    // purpose, as in Linux; above IOV_MAX it is EINVAL either way
    let lcnt = i32::try_from(liovcnt as u32).unwrap_or(-1);
    let local = import_iovec(lvec.addr(), lcnt)?;
    if local.iter().all(|v| v.iov_len == 0) {
        return Ok(0);
    }
    let remote = remote_iovecs(rvec, riovcnt)?;
    process_vm_rw_core(pid, &local, &remote, write)
}

/// The remote iovecs (Linux iovec_from_user): none for a count of 0;
/// more than IOV_MAX, or a length negative as ssize_t, EINVAL; an
/// array outside user space EFAULT. Their addresses are the target's,
/// checked only when copied.
fn remote_iovecs(uvec: UserPtr<IoVec>, n: u64) -> KernelResult<Vec<IoVec>> {
    if n == 0 {
        return Ok(Vec::new());
    }
    let n = usize::try_from(n)
        .ok()
        .filter(|&n| n <= IOV_MAX)
        .ok_or(KernelError::InvalidArgument)?;
    let size = n * core::mem::size_of::<IoVec>();
    if !Uaccess::access_ok(uvec.addr(), size) {
        return Err(KernelError::BadAddress);
    }
    let mut v = crate::util::kmem::try_vec(n, IoVec::default())?;
    let mut r = UserSlice::new(uvec.addr(), size).reader();
    for iov in &mut v {
        *iov = r.read::<IoVec>()?;
        if i64::try_from(iov.iov_len).is_err() {
            return Err(KernelError::InvalidArgument);
        }
    }
    Ok(v)
}

/// Linux process_vm_rw_core: nothing to do if no remote iovec has a
/// byte; else the target (ESRCH), the caller's right to its memory
/// (mm_access: EPERM), and the copy: the bytes copied, or EFAULT if a
/// fault stopped it before the first
fn process_vm_rw_core(
    pid: i32,
    local: &[IoVec],
    remote: &[IoVec],
    write: bool,
) -> KernelResult<u64> {
    if remote.iter().all(|v| v.iov_len == 0) {
        return Ok(0);
    }
    let target = crate::task::percpu::find_task_by_vpid(pid as Pid)
        .map(|t| t.tid())
        .ok_or(KernelError::NoProcess)?;
    let mm = access_mm(target)?;
    let mut buf = crate::util::kmem::try_vec(PVM_CHUNK, 0u8)?;
    // The target's mmap_lock is held per remote access only, never
    // across a local user copy (which can fault and sleep, and takes
    // our own mmap_lock if it does)
    let done = copy_vecs(&mm, local, remote, &mut buf, write);
    if done > 0 {
        Ok(done)
    } else {
        Err(KernelError::BadAddress)
    }
}

/// Copy between the local and remote iovecs, in order, until either
/// runs out or a fault stops it; the bytes copied
fn copy_vecs(mm: &MmRef, local: &[IoVec], remote: &[IoVec], buf: &mut [u8], write: bool) -> u64 {
    let mut done = 0u64;
    let mut li = 0;
    let mut loff = 0u64;
    for r in remote {
        let (mut raddr, mut rleft) = (r.iov_base, r.iov_len);
        while rleft > 0 {
            while local.get(li).is_some_and(|l| loff == l.iov_len) {
                li += 1;
                loff = 0;
            }
            let Some(l) = local.get(li) else {
                return done;
            };
            // Both bounded by PVM_CHUNK, the local range checked by
            // import_iovec (no wrap)
            let n = rleft.min(l.iov_len - loff).min(PVM_CHUNK as u64) as usize;
            let got = copy_step(mm, l.iov_base + loff, raddr, &mut buf[..n], write);
            done += got as u64;
            if got < n {
                return done;
            }
            let Some(next) = raddr.checked_add(n as u64) else {
                return done;
            };
            raddr = next;
            rleft -= n as u64;
            loff += n as u64;
        }
    }
    done
}

/// One bounce-buffered copy of `buf.len()` bytes between local `laddr`
/// and the target's `raddr`; the bytes that made it all the way
fn copy_step(mm: &MmRef, laddr: u64, raddr: u64, buf: &mut [u8], write: bool) -> usize {
    if write {
        if copy_from_user::<Uaccess>(buf, laddr, buf.len()).is_err() {
            return 0;
        }
        access_remote_vm_write(mm, raddr, buf, false).unwrap_or(0)
    } else {
        let got = access_remote_vm_read(mm, raddr, buf, false).unwrap_or(0);
        match copy_to_user::<Uaccess>(laddr, &buf[..got]) {
            Ok(_) => got,
            Err(_) => 0,
        }
    }
}

/// May the caller access the target's memory (Linux process_vm_rw_core
/// -> mm_access, PTRACE_MODE_ATTACH_REALCREDS): its own address space
/// (any thread of it, or a CLONE_VM sharer), else the ptrace rules with
/// the real ids
fn check_process_vm_permission(target_tid: Tid) -> bool {
    let me = current_tid();
    if target_tid == me {
        return true;
    }
    let same_mm = match (
        crate::mm::get_task_mm(target_tid),
        crate::mm::get_task_mm(me),
    ) {
        (Some(a), Some(b)) => alloc::sync::Arc::ptr_eq(&a, &b),
        _ => false,
    };
    same_mm || crate::task::ptrace::may_access(|t| t.task.tid() == target_tid, false)
}

/// The target's address space if the caller may access it (Linux
/// mm_access): decided and taken under its cred_guard_mutex, so an exec
/// cannot swap in a new mm or dumpability in between. A user
/// reference: it cannot be torn down while we access it (Linux
/// get_task_mm)
fn access_mm(target_tid: Tid) -> Result<MmRef, KernelError> {
    let _g = crate::signal::ExecUpdateRead::lock(target_tid);
    if !check_process_vm_permission(target_tid) {
        return Err(KernelError::NotPermitted);
    }
    crate::mm::get_task_mm_users(target_tid).ok_or(KernelError::NoProcess)
}
