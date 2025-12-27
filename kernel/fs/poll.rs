//! Poll, select, and sync syscalls
//!
//! This module contains syscalls for I/O multiplexing and synchronization:
//! - poll, ppoll (polling file descriptors)
//! - select, pselect6 (selecting file descriptors)
//! - sync, fsync, fdatasync, syncfs (filesystem synchronization)

use alloc::vec;

use crate::arch::Uaccess;
use crate::fs::KernelError;

use super::syscall::current_fd_table;

// ============================================================================
// Sync Syscalls - Flush dirty pages to backing store
// ============================================================================

/// sys_sync - sync all filesystems
///
/// Schedules writeback of all dirty pages in all address spaces.
/// Linux semantics: blocks until all I/O completes.
///
/// # Returns
/// Always returns 0 (sync never fails in our implementation)
pub fn sys_sync() -> i64 {
    use crate::mm::writeback::sync_all;

    // Sync all dirty pages across all address spaces
    // This uses the writeback infrastructure to:
    // 1. Iterate DIRTY_ADDRESS_SPACES
    // 2. Write dirty pages via do_writepages
    // 3. Wait for writeback to complete
    let _ = sync_all();

    0
}

/// sys_fsync - sync file data and metadata to backing store
///
/// Transfers all modified in-core data of the file to the storage device.
/// Includes flushing the file data and metadata.
///
/// # Arguments
/// * `fd` - File descriptor to sync
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_fsync(fd: i32) -> i64 {
    // Get file from fd
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f.clone(),
        None => return KernelError::BadFd.sysret(),
    };

    // Call the file's fsync operation
    match file.f_op.fsync(&file) {
        Ok(()) => 0,
        Err(KernelError::Io) => KernelError::Io.sysret(),
        Err(_) => KernelError::InvalidArgument.sysret(),
    }
}

/// sys_fdatasync - sync file data (not metadata) to backing store
///
/// Similar to fsync, but does not flush modified metadata unless it
/// is needed for subsequent data retrieval. For our implementation,
/// this is identical to fsync since we don't have separate metadata writeback.
///
/// # Arguments
/// * `fd` - File descriptor to sync
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_fdatasync(fd: i32) -> i64 {
    // For our implementation, fdatasync is identical to fsync
    // since we don't distinguish between data and metadata writeback
    sys_fsync(fd)
}

/// sys_syncfs - sync filesystem containing file descriptor
///
/// Syncs all dirty pages for the filesystem that contains the file
/// referred to by fd. For block device-based filesystems (vfat, ext4, etc.),
/// this syncs all address spaces associated with that mount.
///
/// # Implementation
///
/// Linux syncfs:
/// 1. Gets the superblock from the file's mount (f_path.mnt->mnt_sb)
/// 2. Calls sync_filesystem(sb) which:
///    - Calls sb->s_op->sync_fs if defined
///    - Writes back all dirty inodes via writeback_inodes_sb
///    - Syncs the underlying block device via sync_blockdev
///
/// Our implementation uses the writeback module:
/// 1. Gets the mount from the file's dentry
/// 2. Uses writeback_all() to flush dirty pages with proper writeback tracking
/// 3. Returns 0 on success
///
/// # Arguments
/// * `fd` - File descriptor in the target filesystem
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_syncfs(fd: i32) -> i64 {
    use crate::mm::writeback::sync_all;

    // Validate fd exists (but we sync all filesystems currently)
    let _file = match current_fd_table().lock().get(fd) {
        Some(f) => f.clone(),
        None => return KernelError::BadFd.sysret(),
    };

    // Use the writeback module to sync all dirty pages
    // TODO: When we have per-superblock tracking, only sync the target filesystem
    let _ = sync_all();

    0
}

// =============================================================================
// Poll/Select Syscalls
// =============================================================================

/// poll - wait for events on file descriptors
///
/// poll() performs a similar task to select(2): it waits for one of a set
/// of file descriptors to become ready to perform I/O.
///
/// # Arguments
/// * `fds` - Pointer to array of pollfd structures
/// * `nfds` - Number of fds in the array
/// * `timeout_ms` - Timeout in milliseconds (-1 = infinite, 0 = immediate)
///
/// # Returns
/// * Number of fds with events (can be 0 on timeout)
/// * -EFAULT if fds is invalid
/// * -EINVAL if nfds exceeds limit
/// * -EINTR if interrupted by signal
pub fn sys_poll(fds: u64, nfds: u32, timeout_ms: i32) -> i64 {
    use crate::poll::{POLLNVAL, PollContext, PollFd, PollTable};
    use crate::task::percpu::current_tid;
    use crate::uaccess::{copy_from_user, copy_to_user};

    // Limit nfds to prevent DoS
    const MAX_NFDS: u32 = 1024;
    if nfds > MAX_NFDS {
        return KernelError::InvalidArgument.sysret();
    }

    // Handle empty poll (just sleep for timeout)
    if nfds == 0 {
        if timeout_ms > 0 {
            // TODO: Implement proper timeout sleep
            let _deadline = timeout_ms as u64;
        }
        return 0;
    }

    // Copy pollfd array from user space
    let pollfd_size = core::mem::size_of::<PollFd>();
    let total_size = pollfd_size * nfds as usize;
    let mut pollfds = vec![PollFd::default(); nfds as usize];

    let bytes_slice =
        unsafe { core::slice::from_raw_parts_mut(pollfds.as_mut_ptr() as *mut u8, total_size) };

    if copy_from_user::<Uaccess>(bytes_slice, fds, total_size).is_err() {
        return KernelError::BadAddress.sysret();
    }

    // Create poll context
    let mut ctx = PollContext::new(current_tid());

    // Do the poll loop
    let mut ready_count;

    // Calculate timeout end time (in milliseconds)
    let timeout_end = if timeout_ms < 0 {
        u64::MAX // Infinite timeout
    } else {
        crate::time::current_ticks().saturating_add(timeout_ms as u64)
    };

    loop {
        // Reset poll table for this iteration
        let mut poll_table = PollTable::new(&mut ctx);
        ready_count = 0;

        // Get FD table
        let fd_table = current_fd_table();
        let table = fd_table.lock();

        // Check each fd
        for pollfd in pollfds.iter_mut() {
            pollfd.revents = 0;

            if pollfd.fd < 0 {
                // Negative fd is ignored
                continue;
            }

            // Look up the file
            let file = match table.get(pollfd.fd) {
                Some(f) => f,
                None => {
                    // Invalid fd - set POLLNVAL
                    pollfd.revents = POLLNVAL as i16;
                    ready_count += 1;
                    continue;
                }
            };

            // Set key for this fd's events
            poll_table.set_key(pollfd.events as u16);

            // Call file's poll method
            let mask = file.poll(Some(&mut poll_table));

            // Check if any requested events are ready
            let revents =
                mask & (pollfd.events as u16 | crate::poll::POLLERR | crate::poll::POLLHUP);
            if revents != 0 {
                pollfd.revents = revents as i16;
                ready_count += 1;
                // Disable further registrations once we find ready fds
                poll_table.disable();
            }
        }

        drop(table);

        // If any fds are ready, or timeout is 0 (immediate), return
        if ready_count > 0 || timeout_ms == 0 {
            break;
        }

        // Wait for events with timeout
        // Use a simple polling loop with yields until we have proper timed waits

        // Yield to let other tasks run (e.g., child process can exit)
        crate::task::percpu::yield_now();

        // Check if timeout has elapsed
        let now = crate::time::current_ticks();
        if now >= timeout_end {
            break;
        }

        // Continue polling loop
    }

    // Copy results back to user space
    let result_bytes =
        unsafe { core::slice::from_raw_parts(pollfds.as_ptr() as *const u8, total_size) };

    if copy_to_user::<Uaccess>(fds, result_bytes).is_err() {
        return KernelError::BadAddress.sysret();
    }

    ready_count
}

/// ppoll - wait for events on file descriptors with timespec timeout
///
/// Like poll(), but uses a timespec instead of milliseconds, and can
/// atomically set a signal mask during the wait.
///
/// # Arguments
/// * `fds` - Pointer to array of pollfd structures
/// * `nfds` - Number of fds in the array
/// * `tmo_p` - Pointer to timespec (NULL = infinite)
/// * `sigmask_ptr` - Pointer to signal mask (NULL = don't change)
/// * `sigsetsize` - Size of signal mask
///
/// # Returns
/// Same as poll()
pub fn sys_ppoll(fds: u64, nfds: u32, tmo_p: u64, _sigmask_ptr: u64, _sigsetsize: u64) -> i64 {
    use crate::uaccess::copy_from_user;

    // Convert timespec to milliseconds (or -1 for infinite)
    let timeout_ms = if tmo_p == 0 {
        -1i32 // Infinite wait
    } else {
        // Read timespec from user
        #[repr(C)]
        #[derive(Default, Copy, Clone)]
        struct Timespec {
            tv_sec: i64,
            tv_nsec: i64,
        }

        let mut ts = Timespec::default();
        let ts_bytes = unsafe {
            core::slice::from_raw_parts_mut(
                &mut ts as *mut Timespec as *mut u8,
                core::mem::size_of::<Timespec>(),
            )
        };

        if copy_from_user::<Uaccess>(ts_bytes, tmo_p, core::mem::size_of::<Timespec>()).is_err() {
            return KernelError::BadAddress.sysret();
        }

        // Convert to milliseconds (clamped to i32 range)
        let ms = ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000;
        if ms > i32::MAX as i64 {
            i32::MAX
        } else if ms < 0 {
            0
        } else {
            ms as i32
        }
    };

    // TODO: Handle signal mask atomically
    // For now, we ignore the signal mask

    // Delegate to sys_poll
    sys_poll(fds, nfds, timeout_ms)
}

// =============================================================================
// Select Syscalls
// =============================================================================

/// select - synchronous I/O multiplexing
///
/// Allows a program to monitor multiple file descriptors, waiting until one or
/// more of the file descriptors become "ready" for some class of I/O operation.
///
/// # Arguments
/// * `nfds` - Highest-numbered fd in any of the sets, plus 1
/// * `readfds` - Optional pointer to fd_set for read readiness
/// * `writefds` - Optional pointer to fd_set for write readiness
/// * `exceptfds` - Optional pointer to fd_set for exceptional conditions
/// * `timeout` - Optional pointer to timeval (NULL = block indefinitely)
///
/// # Returns
/// * Number of ready fds on success
/// * 0 on timeout
/// * -EBADF if an invalid fd is in any set
/// * -EINVAL if nfds is negative or exceeds limit
/// * -EFAULT if any pointer is invalid
/// * -EINTR if interrupted by signal
pub fn sys_select(nfds: i32, readfds: u64, writefds: u64, exceptfds: u64, timeout: u64) -> i64 {
    use crate::poll::{FdSet, POLLERR, POLLHUP, POLLIN, POLLOUT, POLLPRI, PollContext, PollTable};
    use crate::task::percpu::current_tid;
    use crate::uaccess::{copy_from_user, copy_to_user};

    // Validate nfds
    const FD_SETSIZE: i32 = 1024;
    if !(0..=FD_SETSIZE).contains(&nfds) {
        return KernelError::InvalidArgument.sysret();
    }

    // Handle empty select (just sleep for timeout)
    if nfds == 0 && readfds == 0 && writefds == 0 && exceptfds == 0 {
        if timeout != 0 {
            // TODO: Implement proper timeout sleep
        }
        return 0;
    }

    // Calculate how many bytes to copy
    let bytes_needed = FdSet::bytes_for_nfds(nfds);

    // Copy fd_sets from user space
    let mut read_set = FdSet::new();
    let mut write_set = FdSet::new();
    let mut except_set = FdSet::new();

    if readfds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(read_set.bits.as_mut_ptr() as *mut u8, bytes_needed)
        };
        if copy_from_user::<Uaccess>(bytes, readfds, bytes_needed).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    if writefds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(write_set.bits.as_mut_ptr() as *mut u8, bytes_needed)
        };
        if copy_from_user::<Uaccess>(bytes, writefds, bytes_needed).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    if exceptfds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(except_set.bits.as_mut_ptr() as *mut u8, bytes_needed)
        };
        if copy_from_user::<Uaccess>(bytes, exceptfds, bytes_needed).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    // Read timeout if provided
    let timeout_ms = if timeout != 0 {
        #[repr(C)]
        #[derive(Default, Copy, Clone)]
        struct Timeval {
            tv_sec: i64,
            tv_usec: i64,
        }

        let mut tv = Timeval::default();
        let tv_bytes = unsafe {
            core::slice::from_raw_parts_mut(
                &mut tv as *mut Timeval as *mut u8,
                core::mem::size_of::<Timeval>(),
            )
        };

        if copy_from_user::<Uaccess>(tv_bytes, timeout, core::mem::size_of::<Timeval>()).is_err() {
            return KernelError::BadAddress.sysret();
        }

        // Convert to milliseconds
        let ms = tv.tv_sec * 1000 + tv.tv_usec / 1000;
        if ms > i32::MAX as i64 {
            i32::MAX
        } else if ms < 0 {
            0
        } else {
            ms as i32
        }
    } else {
        -1i32 // Infinite wait
    };

    // Create poll context
    let mut ctx = PollContext::new(current_tid());

    // Output sets (initially zeroed)
    let mut out_read = FdSet::new();
    let mut out_write = FdSet::new();
    let mut out_except = FdSet::new();

    // Do the select loop
    let mut ready_count;

    // Calculate timeout end time (in milliseconds)
    let timeout_end = if timeout_ms < 0 {
        u64::MAX // Infinite timeout
    } else {
        crate::time::current_ticks().saturating_add(timeout_ms as u64)
    };

    loop {
        let mut poll_table = PollTable::new(&mut ctx);
        ready_count = 0i32;

        // Get FD table
        let fd_table = current_fd_table();
        let table = fd_table.lock();

        // Check each fd from 0 to nfds-1
        for fd in 0..nfds {
            let check_read = readfds != 0 && read_set.is_set(fd);
            let check_write = writefds != 0 && write_set.is_set(fd);
            let check_except = exceptfds != 0 && except_set.is_set(fd);

            if !check_read && !check_write && !check_except {
                continue;
            }

            // Look up the file - select returns EBADF for invalid fds (unlike poll)
            let file = match table.get(fd) {
                Some(f) => f,
                None => {
                    return KernelError::BadFd.sysret();
                }
            };

            // Set key for events we're interested in
            let mut events = 0u16;
            if check_read {
                events |= POLLIN;
            }
            if check_write {
                events |= POLLOUT;
            }
            if check_except {
                events |= POLLPRI;
            }
            poll_table.set_key(events);

            // Call file's poll method
            let mask = file.poll(Some(&mut poll_table));

            // Check results
            let mut fd_ready = false;

            if check_read && (mask & (POLLIN | POLLERR | POLLHUP)) != 0 {
                out_read.set(fd);
                fd_ready = true;
            }

            if check_write && (mask & (POLLOUT | POLLERR | POLLHUP)) != 0 {
                out_write.set(fd);
                fd_ready = true;
            }

            if check_except && (mask & (POLLPRI | POLLERR)) != 0 {
                out_except.set(fd);
                fd_ready = true;
            }

            if fd_ready {
                ready_count += 1;
                poll_table.disable();
            }
        }

        drop(table);

        // If any fds are ready, or timeout is 0 (immediate), return
        if ready_count > 0 || timeout_ms == 0 {
            break;
        }

        // Yield to let other tasks run (e.g., child process can exit)
        crate::task::percpu::yield_now();

        // Check if timeout has elapsed
        let now = crate::time::current_ticks();
        if now >= timeout_end {
            break;
        }

        // Continue polling loop
    }

    // Copy results back to user space
    if readfds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts(out_read.bits.as_ptr() as *const u8, bytes_needed)
        };
        if copy_to_user::<Uaccess>(readfds, bytes).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    if writefds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts(out_write.bits.as_ptr() as *const u8, bytes_needed)
        };
        if copy_to_user::<Uaccess>(writefds, bytes).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    if exceptfds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts(out_except.bits.as_ptr() as *const u8, bytes_needed)
        };
        if copy_to_user::<Uaccess>(exceptfds, bytes).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    ready_count as i64
}

/// pselect6 - synchronous I/O multiplexing with timespec and signal mask
///
/// Like select(), but uses a timespec instead of timeval, and can atomically
/// set a signal mask during the wait.
///
/// # Arguments
/// * `nfds` - Highest-numbered fd in any of the sets, plus 1
/// * `readfds` - Optional pointer to fd_set for read readiness
/// * `writefds` - Optional pointer to fd_set for write readiness
/// * `exceptfds` - Optional pointer to fd_set for exceptional conditions
/// * `timeout` - Optional pointer to timespec (NULL = block indefinitely)
/// * `sigmask` - Pointer to pselect6_data struct containing sigmask
///
/// # Returns
/// Same as select()
pub fn sys_pselect6(
    nfds: i32,
    readfds: u64,
    writefds: u64,
    exceptfds: u64,
    timeout: u64,
    _sigmask: u64,
) -> i64 {
    use crate::uaccess::copy_from_user;

    // Convert timespec to timeval pointer or handle directly
    // pselect6 uses timespec instead of timeval
    let timeout_ms = if timeout != 0 {
        #[repr(C)]
        #[derive(Default, Copy, Clone)]
        struct Timespec {
            tv_sec: i64,
            tv_nsec: i64,
        }

        let mut ts = Timespec::default();
        let ts_bytes = unsafe {
            core::slice::from_raw_parts_mut(
                &mut ts as *mut Timespec as *mut u8,
                core::mem::size_of::<Timespec>(),
            )
        };

        if copy_from_user::<Uaccess>(ts_bytes, timeout, core::mem::size_of::<Timespec>()).is_err() {
            return KernelError::BadAddress.sysret();
        }

        // Convert to milliseconds
        let ms = ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000;
        if ms > i32::MAX as i64 {
            i32::MAX
        } else if ms < 0 {
            0
        } else {
            ms as i32
        }
    } else {
        -1i32 // Infinite wait
    };

    // TODO: Handle signal mask atomically
    // The sigmask parameter in pselect6 is actually a pointer to a struct
    // containing { const sigset_t *ss; size_t ss_len; }

    // For now, delegate to a modified version of select with timeout_ms
    // We can't directly call sys_select because it expects timeval, not timespec
    sys_select_internal(nfds, readfds, writefds, exceptfds, timeout_ms)
}

/// Internal select implementation that takes timeout in milliseconds
fn sys_select_internal(
    nfds: i32,
    readfds: u64,
    writefds: u64,
    exceptfds: u64,
    timeout_ms: i32,
) -> i64 {
    use crate::poll::{FdSet, POLLERR, POLLHUP, POLLIN, POLLOUT, POLLPRI, PollContext, PollTable};
    use crate::task::percpu::current_tid;
    use crate::uaccess::{copy_from_user, copy_to_user};

    // Validate nfds
    const FD_SETSIZE: i32 = 1024;
    if !(0..=FD_SETSIZE).contains(&nfds) {
        return KernelError::InvalidArgument.sysret();
    }

    // Handle empty select
    if nfds == 0 && readfds == 0 && writefds == 0 && exceptfds == 0 {
        return 0;
    }

    // Calculate how many bytes to copy
    let bytes_needed = FdSet::bytes_for_nfds(nfds);

    // Copy fd_sets from user space
    let mut read_set = FdSet::new();
    let mut write_set = FdSet::new();
    let mut except_set = FdSet::new();

    if readfds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(read_set.bits.as_mut_ptr() as *mut u8, bytes_needed)
        };
        if copy_from_user::<Uaccess>(bytes, readfds, bytes_needed).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    if writefds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(write_set.bits.as_mut_ptr() as *mut u8, bytes_needed)
        };
        if copy_from_user::<Uaccess>(bytes, writefds, bytes_needed).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    if exceptfds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(except_set.bits.as_mut_ptr() as *mut u8, bytes_needed)
        };
        if copy_from_user::<Uaccess>(bytes, exceptfds, bytes_needed).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    // Create poll context
    let mut ctx = PollContext::new(current_tid());

    // Output sets (initially zeroed)
    let mut out_read = FdSet::new();
    let mut out_write = FdSet::new();
    let mut out_except = FdSet::new();

    // Do the select loop
    let mut ready_count;

    // Calculate timeout end time (in milliseconds)
    let timeout_end = if timeout_ms < 0 {
        u64::MAX // Infinite timeout
    } else {
        crate::time::current_ticks().saturating_add(timeout_ms as u64)
    };

    loop {
        let mut poll_table = PollTable::new(&mut ctx);
        ready_count = 0i32;

        // Get FD table
        let fd_table = current_fd_table();
        let table = fd_table.lock();

        // Check each fd from 0 to nfds-1
        for fd in 0..nfds {
            let check_read = readfds != 0 && read_set.is_set(fd);
            let check_write = writefds != 0 && write_set.is_set(fd);
            let check_except = exceptfds != 0 && except_set.is_set(fd);

            if !check_read && !check_write && !check_except {
                continue;
            }

            // Look up the file
            let file = match table.get(fd) {
                Some(f) => f,
                None => {
                    return KernelError::BadFd.sysret();
                }
            };

            // Set key for events we're interested in
            let mut events = 0u16;
            if check_read {
                events |= POLLIN;
            }
            if check_write {
                events |= POLLOUT;
            }
            if check_except {
                events |= POLLPRI;
            }
            poll_table.set_key(events);

            // Call file's poll method
            let mask = file.poll(Some(&mut poll_table));

            // Check results
            let mut fd_ready = false;

            if check_read && (mask & (POLLIN | POLLERR | POLLHUP)) != 0 {
                out_read.set(fd);
                fd_ready = true;
            }

            if check_write && (mask & (POLLOUT | POLLERR | POLLHUP)) != 0 {
                out_write.set(fd);
                fd_ready = true;
            }

            if check_except && (mask & (POLLPRI | POLLERR)) != 0 {
                out_except.set(fd);
                fd_ready = true;
            }

            if fd_ready {
                ready_count += 1;
                poll_table.disable();
            }
        }

        drop(table);

        // If any fds are ready, or timeout is 0 (immediate), return
        if ready_count > 0 || timeout_ms == 0 {
            break;
        }

        // Yield to let other tasks run (e.g., child process can exit)
        crate::task::percpu::yield_now();

        // Check if timeout has elapsed
        let now = crate::time::current_ticks();
        if now >= timeout_end {
            break;
        }

        // Continue polling loop
    }

    // Copy results back to user space
    if readfds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts(out_read.bits.as_ptr() as *const u8, bytes_needed)
        };
        if copy_to_user::<Uaccess>(readfds, bytes).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    if writefds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts(out_write.bits.as_ptr() as *const u8, bytes_needed)
        };
        if copy_to_user::<Uaccess>(writefds, bytes).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    if exceptfds != 0 && bytes_needed > 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts(out_except.bits.as_ptr() as *const u8, bytes_needed)
        };
        if copy_to_user::<Uaccess>(exceptfds, bytes).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    ready_count as i64
}
