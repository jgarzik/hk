//! Poll, select, and sync syscalls
//!
//! This module contains syscalls for I/O multiplexing and synchronization:
//! - poll, ppoll (polling file descriptors)
//! - select, pselect6 (selecting file descriptors)
//! - sync, fsync, fdatasync, syncfs (filesystem synchronization)

use alloc::vec;

use crate::arch::Uaccess;
use crate::fs::KernelError;
use crate::signal::SigSet;
use crate::task::percpu::current_tid;

use super::syscall::current_fd_table;

// =============================================================================
// Signal Mask Helpers for ppoll/pselect6
// =============================================================================

/// Install ppoll/pselect6's temporary mask (TIF_RESTORE_SIGMASK);
/// returns the old one
fn set_poll_sigmask(new_mask: SigSet) -> Option<SigSet> {
    crate::signal::set_temp_sigmask(new_mask)
}

/// Put the old mask back after ppoll/pselect6, unless a signal
/// interrupted it (Linux poll_select_finish ->
/// restore_saved_sigmask_unless)
fn restore_poll_sigmask(result: i64) {
    crate::signal::restore_saved_sigmask_unless(result == KernelError::RestartNoHand.sysret());
}

// =============================================================================
// Poll sleep helpers
// =============================================================================

use crate::time::{Deadline, deadline_ms as poll_deadline};

/// The deadline of a (sec, nsec) timeout; EINVAL if invalid
fn ts_deadline(sec: i64, nsec: i64) -> Result<Deadline, i64> {
    crate::time::deadline_ts(sec, nsec).map_err(|e| e.sysret())
}

/// The user's timeout format
#[derive(Clone, Copy)]
enum PollTs {
    Timeval,
    Timespec,
}

/// Write the time left back to the user's timeout (Linux
/// poll_select_finish): not for a zero timeout; a fault turns a restart
/// into -EINTR (the restart could not see the time left)
fn poll_finish(deadline: Deadline, uptr: u64, kind: PollTs, ret: i64) -> i64 {
    use crate::uaccess::put_user;
    let Some(end) = deadline.filter(|&d| d != 0 && uptr != 0) else {
        return ret;
    };
    let left = end.saturating_sub(crate::time::monotonic_ns());
    let (sec, ns) = ((left / 1_000_000_000) as i64, (left % 1_000_000_000) as i64);
    let sub = match kind {
        PollTs::Timeval => ns / 1000,
        PollTs::Timespec => ns,
    };
    if put_user::<Uaccess, [i64; 2]>(uptr, [sec, sub]).is_ok() {
        return ret;
    }
    if ret == KernelError::RestartNoHand.sysret() {
        return KernelError::Interrupted.sysret();
    }
    ret
}

/// Read a user timeout (NULL = forever) as a [`Deadline`]; a timeval's
/// microseconds carry into seconds like Linux kern_select
fn read_ts(uptr: u64, kind: PollTs) -> Result<Deadline, i64> {
    use crate::uaccess::get_user;
    if uptr == 0 {
        return Ok(None);
    }
    let [sec, sub] =
        get_user::<Uaccess, [i64; 2]>(uptr).map_err(|_| KernelError::BadAddress.sysret())?;
    match kind {
        PollTs::Timespec => ts_deadline(sec, sub),
        PollTs::Timeval if sub < 0 => Err(KernelError::InvalidArgument.sysret()),
        PollTs::Timeval => ts_deadline(
            sec.saturating_add(sub / 1_000_000),
            (sub % 1_000_000) * 1000,
        ),
    }
}

/// Called after a scan (done with the task state set Interruptible) found
/// nothing ready: sleep until a registered wait queue fires, a signal, or
/// the deadline. Returns `Some(retval)` when the poll must stop.
fn poll_sleep(deadline: Deadline) -> Option<i64> {
    use crate::task::percpu::{SleepState, set_current_state};
    if crate::waitqueue::signal_pending() {
        set_current_state(SleepState::Running);
        return Some(KernelError::RestartNoHand.sysret());
    }
    if let Some(d) = deadline
        && crate::time::monotonic_ns() >= d
    {
        set_current_state(SleepState::Running);
        return Some(0);
    }
    crate::hrtimer::schedule_hrtimeout(deadline, crate::hrtimer::HrClock::Monotonic);
    None
}

/// Sleep with nothing to poll: until the deadline (`Ok`) or a signal
fn poll_sleep_only(deadline: Deadline) -> i64 {
    use crate::task::percpu::{SleepState, set_current_state};
    loop {
        set_current_state(SleepState::Interruptible);
        if let Some(r) = poll_sleep(deadline) {
            return r;
        }
    }
}

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
    do_poll_internal(fds, nfds, poll_deadline(timeout_ms))
}

/// Internal poll implementation
///
/// # Arguments
/// * `fds` - Pointer to array of pollfd structures
/// * `nfds` - Number of fds in the array
/// * `deadline` - None = infinite, Some(0) = immediate, else CLOCK_MONOTONIC ns
///
/// Sleeps on the polled files' wait queues; a deliverable signal ends the
/// wait with -ERESTARTNOHAND (EINTR once a handler runs).
fn do_poll_internal(fds: u64, nfds: u32, deadline: Deadline) -> i64 {
    use crate::poll::{POLLNVAL, PollContext, PollFd, PollTable};
    use crate::task::percpu::{SleepState, set_current_state};
    use crate::uaccess::{copy_from_user, copy_to_user};

    // Limit nfds to prevent DoS
    const MAX_NFDS: u32 = 1024;
    if nfds > MAX_NFDS {
        return KernelError::InvalidArgument.sysret();
    }

    let tid = current_tid();

    // Empty poll: just sleep for the timeout (or until a signal)
    if nfds == 0 {
        if deadline == Some(0) {
            return 0;
        }
        return poll_sleep_only(deadline);
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

    // Create poll context (wait queue registrations, dropped at return)
    let mut ctx = PollContext::new(tid);
    let mut first_pass = true;
    let mut ready_count;

    loop {
        // State first, then scan: a wakeup during the scan is not lost
        set_current_state(SleepState::Interruptible);

        // Register on wait queues during the first scan only
        let mut poll_table = PollTable::new(&mut ctx);
        if !first_pass || deadline == Some(0) {
            poll_table.disable();
        }
        first_pass = false;
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
            poll_table.hold_file(&file);

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
        if ready_count > 0 || deadline == Some(0) {
            set_current_state(SleepState::Running);
            break;
        }

        match poll_sleep(deadline) {
            Some(0) => break,
            Some(r) => return r,
            None => {}
        }
    }
    drop(ctx);

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
pub fn sys_ppoll(fds: u64, nfds: u32, tmo_p: u64, sigmask_ptr: u64, sigsetsize: u64) -> i64 {
    use crate::uaccess::get_user;

    let deadline = match read_ts(tmo_p, PollTs::Timespec) {
        Ok(d) => d,
        Err(e) => return e,
    };

    // Handle signal mask atomically
    let saved_mask = if sigmask_ptr != 0 {
        // Validate sigsetsize - must be 8 bytes (64-bit sigset_t)
        if sigsetsize != 8 {
            return KernelError::InvalidArgument.sysret();
        }

        // Read new mask from user space
        let new_mask_bits = match get_user::<Uaccess, u64>(sigmask_ptr) {
            Ok(v) => v,
            Err(_) => return KernelError::BadAddress.sysret(),
        };
        let new_mask = SigSet::from_bits(new_mask_bits);

        // Set new mask and save old
        set_poll_sigmask(new_mask)
    } else {
        None
    };

    let result = do_poll_internal(fds, nfds, deadline);
    let result = poll_finish(deadline, tmo_p, PollTs::Timespec, result);

    // Restore mask if we changed it, unless interrupted by a signal: then
    // the temporary mask stays in effect for signal delivery and do_signal()
    // restores saved_sigmask (Linux: restore_saved_sigmask_unless()).
    if saved_mask.is_some() {
        restore_poll_sigmask(result);
    }

    result
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
    let deadline = match read_ts(timeout, PollTs::Timeval) {
        Ok(d) => d,
        Err(e) => return e,
    };

    // select() doesn't change signal mask, so don't return EINTR for most signals
    let r = do_select_internal(nfds, readfds, writefds, exceptfds, deadline);
    poll_finish(deadline, timeout, PollTs::Timeval, r)
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
    sigmask: u64,
) -> i64 {
    use crate::uaccess::get_user;

    let deadline = match read_ts(timeout, PollTs::Timespec) {
        Ok(d) => d,
        Err(e) => return e,
    };

    // Handle signal mask atomically
    // The sigmask parameter in pselect6 is a pointer to a struct:
    // struct { const sigset_t *ss; size_t ss_len; }
    let saved_mask = if sigmask != 0 {
        // Read pointer to sigset_t
        let ss_ptr = match get_user::<Uaccess, u64>(sigmask) {
            Ok(v) => v,
            Err(_) => return KernelError::BadAddress.sysret(),
        };
        // Read sigset size
        let ss_len = match get_user::<Uaccess, u64>(sigmask + 8) {
            Ok(v) => v as usize,
            Err(_) => return KernelError::BadAddress.sysret(),
        };

        if ss_ptr != 0 {
            if ss_len != 8 {
                return KernelError::InvalidArgument.sysret();
            }

            let new_mask_bits = match get_user::<Uaccess, u64>(ss_ptr) {
                Ok(v) => v,
                Err(_) => return KernelError::BadAddress.sysret(),
            };
            let new_mask = SigSet::from_bits(new_mask_bits);
            set_poll_sigmask(new_mask)
        } else {
            None
        }
    } else {
        None
    };

    let result = do_select_internal(nfds, readfds, writefds, exceptfds, deadline);
    let result = poll_finish(deadline, timeout, PollTs::Timespec, result);

    // Restore mask if we changed it, unless interrupted by a signal: then
    // the temporary mask stays in effect for signal delivery and do_signal()
    // restores saved_sigmask (Linux: restore_saved_sigmask_unless()).
    if saved_mask.is_some() {
        restore_poll_sigmask(result);
    }

    result
}

/// Internal select implementation (see [`Deadline`])
///
/// # Arguments
/// * `nfds` - Highest-numbered fd in any of the sets, plus 1
/// * `readfds` - Optional pointer to fd_set for read readiness
/// * `writefds` - Optional pointer to fd_set for write readiness
/// * `exceptfds` - Optional pointer to fd_set for exceptional conditions
/// * `deadline` - None = infinite, Some(0) = immediate, else CLOCK_MONOTONIC ns
fn do_select_internal(
    nfds: i32,
    readfds: u64,
    writefds: u64,
    exceptfds: u64,
    deadline: Deadline,
) -> i64 {
    use crate::poll::{FdSet, POLLERR, POLLHUP, POLLIN, POLLOUT, POLLPRI, PollContext, PollTable};
    use crate::task::percpu::{SleepState, set_current_state};
    use crate::uaccess::{copy_from_user, copy_to_user};

    // Validate nfds
    const FD_SETSIZE: i32 = 1024;
    if !(0..=FD_SETSIZE).contains(&nfds) {
        return KernelError::InvalidArgument.sysret();
    }

    let tid = current_tid();

    // Empty select: just sleep for the timeout (or until a signal)
    if nfds == 0 && readfds == 0 && writefds == 0 && exceptfds == 0 {
        if deadline == Some(0) {
            return 0;
        }
        return poll_sleep_only(deadline);
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
    let mut ctx = PollContext::new(tid);

    // Output sets (initially zeroed)
    let mut out_read;
    let mut out_write;
    let mut out_except;

    let mut first_pass = true;
    let mut ready_count;

    loop {
        // State first, then scan: a wakeup during the scan is not lost
        set_current_state(SleepState::Interruptible);
        // Register on wait queues during the first scan only
        let mut poll_table = PollTable::new(&mut ctx);
        if !first_pass || deadline == Some(0) {
            poll_table.disable();
        }
        first_pass = false;
        ready_count = 0i32;
        out_read = FdSet::new();
        out_write = FdSet::new();
        out_except = FdSet::new();

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
                    set_current_state(SleepState::Running);
                    return KernelError::BadFd.sysret();
                }
            };
            poll_table.hold_file(&file);

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
        if ready_count > 0 || deadline == Some(0) {
            set_current_state(SleepState::Running);
            break;
        }

        match poll_sleep(deadline) {
            Some(0) => break,
            Some(r) => return r,
            None => {}
        }
    }
    drop(ctx);

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
