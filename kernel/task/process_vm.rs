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
use crate::task::percpu::{TASK_TABLE, current_cred, current_tid};
use crate::task::{CAP_SYS_PTRACE, Pid, Tid, capable};
use crate::uaccess::UaccessArch;

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

    // Permission check
    if !check_process_vm_permission(target_tid) {
        return KernelError::NotPermitted.sysret();
    }

    // Get target's mm and page table root
    let (target_mm, page_table_root) = match get_target_mm_and_pt(target_tid) {
        Some(x) => x,
        None => return KernelError::NoProcess.sysret(),
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

    // Lock target mm
    let mm_guard = target_mm.lock();

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

            let to_transfer = remote_remaining.min(local_remaining);

            // Read from remote into kernel buffer
            let mut buf = alloc::vec![0u8; to_transfer];
            let bytes_read =
                match access_remote_vm_read(&mm_guard, page_table_root, remote_addr, &mut buf) {
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
            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(buf.as_ptr(), local_addr as *mut u8, bytes_read);
                Uaccess::user_access_end();
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

    // Permission check
    if !check_process_vm_permission(target_tid) {
        return KernelError::NotPermitted.sysret();
    }

    // Get target's mm and page table root
    let (target_mm, page_table_root) = match get_target_mm_and_pt(target_tid) {
        Some(x) => x,
        None => return KernelError::NoProcess.sysret(),
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

    // Lock target mm
    let mm_guard = target_mm.lock();

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

            let to_transfer = remote_remaining.min(local_remaining);

            // Read from local user buffer into kernel buffer
            let mut buf = alloc::vec![0u8; to_transfer];
            let local_addr = local.iov_base + local_offset as u64;
            unsafe {
                Uaccess::user_access_begin();
                core::ptr::copy_nonoverlapping(
                    local_addr as *const u8,
                    buf.as_mut_ptr(),
                    to_transfer,
                );
                Uaccess::user_access_end();
            }

            // Write to remote
            let bytes_written =
                match access_remote_vm_write(&mm_guard, page_table_root, remote_addr, &buf) {
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
    let table = TASK_TABLE.lock();
    table.tasks.iter().find(|t| t.pid == pid).map(|t| t.tid)
}

/// Check permission for process_vm access
///
/// Allows access if:
/// - Caller has CAP_SYS_PTRACE capability, OR
/// - Caller and target have the same effective UID
fn check_process_vm_permission(target_tid: Tid) -> bool {
    // CAP_SYS_PTRACE bypasses all checks
    if capable(CAP_SYS_PTRACE) {
        return true;
    }

    // Same process always allowed
    if target_tid == current_tid() {
        return true;
    }

    // Get caller credentials
    let caller_cred = current_cred();

    // Get target credentials
    let target_euid = {
        let table = TASK_TABLE.lock();
        table
            .tasks
            .iter()
            .find(|t| t.tid == target_tid)
            .map(|t| t.cred.euid)
    };

    // Same effective UID check
    match target_euid {
        Some(euid) => caller_cred.euid == euid,
        None => false,
    }
}

/// Get target's MmStruct and page table root physical address
fn get_target_mm_and_pt(
    target_tid: Tid,
) -> Option<(alloc::sync::Arc<spin::Mutex<crate::mm::MmStruct>>, u64)> {
    let table = TASK_TABLE.lock();
    let task = table.tasks.iter().find(|t| t.tid == target_tid)?;

    let mm = task.mm.clone()?;
    let pt_root = task.page_table.root_table_phys();

    Some((mm, pt_root))
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

    let mut iovecs = Vec::with_capacity(count);

    unsafe {
        Uaccess::user_access_begin();
        for i in 0..count {
            let iov = core::ptr::read((iov_ptr as *const IoVec).add(i));
            iovecs.push(iov);
        }
        Uaccess::user_access_end();
    }

    Ok(iovecs)
}
