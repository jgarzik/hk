//! process_vm_readv / process_vm_writev syscalls
//!
//! Cross-process memory access syscalls for debugging, container runtimes,
//! and process inspection utilities.

extern crate alloc;

use alloc::vec::Vec;

use crate::arch::Uaccess;
use crate::error::KernelError;
use crate::fs::iov::IoVec;
use crate::mm::remote::{access_remote_vm_read, access_remote_vm_write};
use crate::task::percpu::{TASKLIST, current_tid};
use crate::task::{Pid, Tid};
use crate::uaccess::{UaccessArch, copy_from_user, copy_to_user};

/// Maximum number of iovec entries (same as IOV_MAX)
const IOV_MAX: usize = 1024;

/// sys_process_vm_readv - Read from another process's memory
///
/// # Arguments
/// * `pid` - Target process ID
/// * `local_iov` - User pointer to local iovec array (destination buffers)
/// * `liovcnt` - Number of local iovecs
/// * `remote_iov` - User pointer to remote iovec array (source addresses in target)
/// * `riovcnt` - Number of remote iovecs
/// * `flags` - Reserved (must be 0)
///
/// # Returns
/// Total bytes read on success, negative errno on error
/// Bytes copied per step: the bounce buffer stays small whatever the
/// iovec lengths (Linux copies page by page)
const PVM_CHUNK: usize = 64 * 1024;

pub fn sys_process_vm_readv(
    pid: i32,
    local_iov: u64,
    liovcnt: u64,
    remote_iov: u64,
    riovcnt: u64,
    flags: u64,
) -> i64 {
    // flags must be 0 (reserved for future use)
    if flags != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate iovec counts
    if liovcnt > IOV_MAX as u64 || riovcnt > IOV_MAX as u64 {
        return KernelError::InvalidArgument.sysret();
    }
    if liovcnt == 0 || riovcnt == 0 {
        return 0; // Nothing to do
    }

    // Find target task
    let target_tid = match find_task_by_pid(pid as Pid) {
        Some(tid) => tid,
        None => return KernelError::NoProcess.sysret(),
    };

    // Permission check and the mm it covers (Linux mm_access)
    let (target_mm, _) = match access_mm(target_tid) {
        Ok(x) => x,
        Err(e) => return e.sysret(),
    };

    // Copy iovec arrays from user space
    let local_iovecs = match copy_iovecs_from_user(local_iov, liovcnt as usize) {
        Ok(v) => v,
        Err(e) => return e.sysret(),
    };
    let remote_iovecs = match copy_iovecs_from_user(remote_iov, riovcnt as usize) {
        Ok(v) => v,
        Err(e) => return e.sysret(),
    };

    // Validate local buffers (destination) are in caller's address space
    for iov in &local_iovecs {
        if iov.iov_len > 0 && !Uaccess::access_ok(iov.iov_base, iov.iov_len as usize) {
            return KernelError::BadAddress.sysret();
        }
    }

    // The target mmap_lock is held per remote access only, never across
    // the local user copy (which can fault and sleep, and takes our own
    // mmap_lock if it does)

    // Transfer data: remote -> local
    let mut total_bytes = 0i64;
    let mut local_idx = 0usize;
    let mut local_offset = 0usize;

    for remote in &remote_iovecs {
        if remote.iov_len == 0 {
            continue;
        }

        let mut remote_remaining = remote.iov_len as usize;
        let mut remote_addr = remote.iov_base;

        while remote_remaining > 0 && local_idx < local_iovecs.len() {
            let local = &local_iovecs[local_idx];
            let local_remaining = (local.iov_len as usize).saturating_sub(local_offset);

            if local_remaining == 0 {
                local_idx += 1;
                local_offset = 0;
                continue;
            }

            let to_transfer = remote_remaining.min(local_remaining).min(PVM_CHUNK);

            // Read from remote into kernel buffer
            let mut buf = alloc::vec![0u8; to_transfer];
            let bytes_read = match access_remote_vm_read(
                &target_mm,
                &target_mm.mmap_read(),
                remote_addr,
                &mut buf,
            ) {
                Ok(n) => n,
                Err(_) => {
                    if total_bytes > 0 {
                        return total_bytes;
                    }
                    return KernelError::BadAddress.sysret();
                }
            };

            if bytes_read == 0 {
                if total_bytes > 0 {
                    return total_bytes;
                }
                return KernelError::BadAddress.sysret();
            }

            // Copy to local user buffer
            let local_addr = local.iov_base + local_offset as u64;
            if copy_to_user::<Uaccess>(local_addr, &buf[..bytes_read]).is_err() {
                return if total_bytes > 0 {
                    total_bytes
                } else {
                    KernelError::BadAddress.sysret()
                };
            }

            total_bytes += bytes_read as i64;
            remote_addr += bytes_read as u64;
            remote_remaining -= bytes_read;
            local_offset += bytes_read;

            // If we didn't read the full amount, stop
            if bytes_read < to_transfer {
                return total_bytes;
            }
        }
    }

    total_bytes
}

/// sys_process_vm_writev - Write to another process's memory
///
/// # Arguments
/// * `pid` - Target process ID
/// * `local_iov` - User pointer to local iovec array (source buffers)
/// * `liovcnt` - Number of local iovecs
/// * `remote_iov` - User pointer to remote iovec array (destination addresses in target)
/// * `riovcnt` - Number of remote iovecs
/// * `flags` - Reserved (must be 0)
///
/// # Returns
/// Total bytes written on success, negative errno on error
pub fn sys_process_vm_writev(
    pid: i32,
    local_iov: u64,
    liovcnt: u64,
    remote_iov: u64,
    riovcnt: u64,
    flags: u64,
) -> i64 {
    // flags must be 0
    if flags != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate iovec counts
    if liovcnt > IOV_MAX as u64 || riovcnt > IOV_MAX as u64 {
        return KernelError::InvalidArgument.sysret();
    }
    if liovcnt == 0 || riovcnt == 0 {
        return 0;
    }

    // Find target task
    let target_tid = match find_task_by_pid(pid as Pid) {
        Some(tid) => tid,
        None => return KernelError::NoProcess.sysret(),
    };

    // Permission check and the mm it covers (Linux mm_access)
    let (target_mm, _) = match access_mm(target_tid) {
        Ok(x) => x,
        Err(e) => return e.sysret(),
    };

    // Copy iovec arrays from user space
    let local_iovecs = match copy_iovecs_from_user(local_iov, liovcnt as usize) {
        Ok(v) => v,
        Err(e) => return e.sysret(),
    };
    let remote_iovecs = match copy_iovecs_from_user(remote_iov, riovcnt as usize) {
        Ok(v) => v,
        Err(e) => return e.sysret(),
    };

    // Validate local buffers (source) are in caller's address space
    for iov in &local_iovecs {
        if iov.iov_len > 0 && !Uaccess::access_ok(iov.iov_base, iov.iov_len as usize) {
            return KernelError::BadAddress.sysret();
        }
    }

    // The target mmap_lock is held per remote access only, never across
    // the local user copy (which can fault and sleep, and takes our own
    // mmap_lock if it does)

    // Transfer data: local -> remote
    let mut total_bytes = 0i64;
    let mut local_idx = 0usize;
    let mut local_offset = 0usize;

    for remote in &remote_iovecs {
        if remote.iov_len == 0 {
            continue;
        }

        let mut remote_remaining = remote.iov_len as usize;
        let mut remote_addr = remote.iov_base;

        while remote_remaining > 0 && local_idx < local_iovecs.len() {
            let local = &local_iovecs[local_idx];
            let local_remaining = (local.iov_len as usize).saturating_sub(local_offset);

            if local_remaining == 0 {
                local_idx += 1;
                local_offset = 0;
                continue;
            }

            let to_transfer = remote_remaining.min(local_remaining).min(PVM_CHUNK);

            // Read from local user buffer into kernel buffer
            let mut buf = alloc::vec![0u8; to_transfer];
            let local_addr = local.iov_base + local_offset as u64;
            if copy_from_user::<Uaccess>(&mut buf, local_addr, to_transfer).is_err() {
                return if total_bytes > 0 {
                    total_bytes
                } else {
                    KernelError::BadAddress.sysret()
                };
            }

            // Write to remote
            let bytes_written =
                match access_remote_vm_write(&target_mm, &target_mm.mmap_read(), remote_addr, &buf)
                {
                    Ok(n) => n,
                    Err(_) => {
                        if total_bytes > 0 {
                            return total_bytes;
                        }
                        return KernelError::BadAddress.sysret();
                    }
                };

            if bytes_written == 0 {
                if total_bytes > 0 {
                    return total_bytes;
                }
                return KernelError::BadAddress.sysret();
            }

            total_bytes += bytes_written as i64;
            remote_addr += bytes_written as u64;
            remote_remaining -= bytes_written;
            local_offset += bytes_written;

            if bytes_written < to_transfer {
                return total_bytes;
            }
        }
    }

    total_bytes
}

// ============================================================================
// Helper functions
// ============================================================================

/// Find a task by PID (returns TID of the main thread)
fn find_task_by_pid(pid: Pid) -> Option<Tid> {
    let table = TASKLIST.read();
    table.get(pid).map(|t| t.task.tid())
}

/// May the caller access the target's memory (Linux process_vm_rw_core
/// -> mm_access, PTRACE_MODE_ATTACH_REALCREDS): its own process, else
/// the ptrace rules with the real ids
fn check_process_vm_permission(target_tid: Tid) -> bool {
    target_tid == current_tid()
        || crate::task::ptrace::may_access(|t| t.task.tid() == target_tid, false)
}

/// The target's address space if the caller may access it (Linux
/// mm_access): decided and taken under its cred_guard_mutex, so an exec
/// cannot swap in a new mm or dumpability in between
fn access_mm(target_tid: Tid) -> Result<(crate::mm::MmRef, u64), KernelError> {
    let _g = crate::signal::ExecUpdateRead::lock(target_tid);
    if !check_process_vm_permission(target_tid) {
        return Err(KernelError::NotPermitted);
    }
    get_target_mm_and_pt(target_tid).ok_or(KernelError::NoProcess)
}

/// Get target's MmStruct and page table root physical address
fn get_target_mm_and_pt(target_tid: Tid) -> Option<(crate::mm::MmRef, u64)> {
    // A user reference: the address space cannot be torn down while we
    // access it (Linux get_task_mm)
    let mm = crate::mm::get_task_mm_users(target_tid)?;
    let pgd = mm.pgd();
    Some((mm, pgd))
}

/// Copy iovec array from user space
fn copy_iovecs_from_user(iov_ptr: u64, count: usize) -> Result<Vec<IoVec>, KernelError> {
    if count == 0 {
        return Ok(Vec::new());
    }

    let iov_size = core::mem::size_of::<IoVec>();
    let total_size = count * iov_size;

    if !Uaccess::access_ok(iov_ptr, total_size) {
        return Err(KernelError::BadAddress);
    }

    let mut iovecs = alloc::vec![IoVec::default(); count];
    // SAFETY: IoVec is repr(C) plain data; the byte view covers exactly the
    // `count` initialized elements of `iovecs`.
    let bytes =
        unsafe { core::slice::from_raw_parts_mut(iovecs.as_mut_ptr() as *mut u8, total_size) };
    if copy_from_user::<Uaccess>(bytes, iov_ptr, total_size).is_err() {
        return Err(KernelError::BadAddress);
    }

    Ok(iovecs)
}
