//! Poll and select syscalls: poll, ppoll, select, pselect6

use alloc::vec::Vec;

use crate::fs::KernelError;
use crate::io::poll::PollFd;
use crate::signal::SigSet;
use crate::time::time_syscall::{LinuxTimespec, Timeval};
use crate::uaccess::UserPtr;
use crate::util::error::KernelResult;

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
fn restore_poll_sigmask(result: &KernelResult<usize>) {
    crate::signal::restore_saved_sigmask_unless(*result == Err(KernelError::RestartNoHand));
}

// =============================================================================
// Poll sleep helpers
// =============================================================================

use crate::time::{Deadline, deadline_ms as poll_deadline};

/// The deadline of a (sec, nsec) timeout; EINVAL if invalid
fn ts_deadline(sec: i64, nsec: i64) -> KernelResult<Deadline> {
    crate::time::deadline_ts(sec, nsec)
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
fn poll_finish(
    deadline: Deadline,
    uptr: UserPtr<[i64; 2]>,
    kind: PollTs,
    ret: KernelResult<usize>,
) -> KernelResult<usize> {
    let Some(end) = deadline.filter(|&d| d != 0 && !uptr.is_null()) else {
        return ret;
    };
    let left = end.saturating_sub(crate::time::monotonic_ns());
    let (sec, ns) = ((left / 1_000_000_000) as i64, (left % 1_000_000_000) as i64);
    let sub = match kind {
        PollTs::Timeval => ns / 1000,
        PollTs::Timespec => ns,
    };
    if uptr.write(&[sec, sub]).is_err() && ret == Err(KernelError::RestartNoHand) {
        return Err(KernelError::Interrupted);
    }
    ret
}

/// Read a user timeout (NULL = forever) as a [`Deadline`]; a timeval's
/// microseconds carry into seconds like Linux kern_select
fn read_ts(uptr: UserPtr<[i64; 2]>, kind: PollTs) -> KernelResult<Deadline> {
    if uptr.is_null() {
        return Ok(None);
    }
    let [sec, sub] = uptr.read()?;
    match kind {
        PollTs::Timespec => ts_deadline(sec, sub),
        PollTs::Timeval if sub < 0 => Err(KernelError::InvalidArgument),
        PollTs::Timeval => ts_deadline(
            sec.saturating_add(sub / 1_000_000),
            (sub % 1_000_000) * 1000,
        ),
    }
}

/// Called after a scan (done with the task state set Interruptible) found
/// nothing ready: sleep until a registered wait queue fires, a signal, or
/// the deadline. Returns `Some` when the poll must stop: `Ok(0)` at the
/// deadline, ERESTARTNOHAND for a signal.
fn poll_sleep(deadline: Deadline) -> Option<KernelResult<usize>> {
    use crate::task::percpu::{SleepState, set_current_state};
    if crate::sync::waitqueue::signal_pending() {
        set_current_state(SleepState::Running);
        return Some(Err(KernelError::RestartNoHand));
    }
    if let Some(d) = deadline
        && crate::time::monotonic_ns() >= d
    {
        set_current_state(SleepState::Running);
        return Some(Ok(0));
    }
    crate::time::hrtimer::schedule_hrtimeout(deadline, crate::time::hrtimer::HrClock::Monotonic);
    None
}

/// Sleep with nothing to poll: until the deadline (`Ok`) or a signal
fn poll_sleep_only(deadline: Deadline) -> KernelResult<usize> {
    use crate::task::percpu::{SleepState, set_current_state};
    loop {
        set_current_state(SleepState::Interruptible);
        if let Some(r) = poll_sleep(deadline) {
            return r;
        }
    }
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
/// * EFAULT if fds is invalid
/// * EINVAL if nfds exceeds limit
/// * EINTR if interrupted by signal
pub fn sys_poll(fds: UserPtr<PollFd>, nfds: u32, timeout_ms: i32) -> KernelResult<usize> {
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
fn do_poll_internal(fds: UserPtr<PollFd>, nfds: u32, deadline: Deadline) -> KernelResult<usize> {
    use crate::io::poll::{POLLNVAL, PollContext, PollTable};
    use crate::task::percpu::{SleepState, set_current_state};
    use crate::uaccess::{copy_from_user, copy_to_user};

    // As many as the caller may have open (Linux do_sys_poll)
    if u64::from(nfds) > crate::task::rlimit::rlimit(crate::task::rlimit::RLIMIT_NOFILE) {
        return Err(KernelError::InvalidArgument);
    }

    // Empty poll: just sleep for the timeout (or until a signal)
    if nfds == 0 {
        if deadline == Some(0) {
            return Ok(0);
        }
        return poll_sleep_only(deadline);
    }

    // Copy pollfd array from user space
    let pollfd_size = core::mem::size_of::<PollFd>();
    let total_size = pollfd_size * nfds as usize;
    let mut pollfds = crate::util::kmem::try_vec(nfds as usize, PollFd::default())?;
    let bytes_slice = crate::util::pod::slice_bytes_mut(&mut pollfds);
    copy_from_user(bytes_slice, fds.addr(), total_size)?;

    // Create poll context (wait queue registrations, dropped at return;
    // only a poll that may sleep registers)
    let regs = if deadline == Some(0) {
        0
    } else {
        pollfds.iter().filter(|p| p.fd >= 0).count()
    };
    let mut ctx = PollContext::sized(regs);
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

        // Each file is looked up alone and polled with no lock held
        // (Linux fdget per fd): a poll method may sleep
        let fd_table = current_fd_table();

        // Check each fd
        for pollfd in pollfds.iter_mut() {
            pollfd.revents = 0;

            if pollfd.fd < 0 {
                // Negative fd is ignored
                continue;
            }

            // Look up the file
            let file = fd_table.lock().get(pollfd.fd);
            let Some(file) = file else {
                // Invalid fd - set POLLNVAL
                pollfd.revents = POLLNVAL as i16;
                ready_count += 1;
                continue;
            };

            // Set key for this fd's events
            poll_table.set_key(pollfd.events as u16);
            poll_table.hold_file(&file);

            // Call file's poll method
            let mask = file.poll(Some(&mut poll_table));

            // Check if any requested events are ready
            let revents =
                mask & (pollfd.events as u16 | crate::io::poll::POLLERR | crate::io::poll::POLLHUP);
            if revents != 0 {
                pollfd.revents = revents as i16;
                ready_count += 1;
                // Disable further registrations once we find ready fds
                poll_table.disable();
            }
        }

        // If any fds are ready, or timeout is 0 (immediate), return
        if ready_count > 0 || deadline == Some(0) {
            set_current_state(SleepState::Running);
            break;
        }
        // Nothing ready and a registration failed (Linux do_poll)
        if let Some(e) = ctx.error() {
            set_current_state(SleepState::Running);
            return Err(e);
        }

        match poll_sleep(deadline) {
            Some(Ok(_)) => break,
            Some(Err(e)) => return Err(e),
            None => {}
        }
    }
    drop(ctx);

    // Copy results back to user space
    copy_to_user(fds.addr(), crate::util::pod::slice_bytes(&pollfds))?;
    Ok(ready_count)
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
pub fn sys_ppoll(
    fds: UserPtr<PollFd>,
    nfds: u32,
    tmo_p: UserPtr<LinuxTimespec>,
    sigmask_ptr: UserPtr<u64>,
    sigsetsize: u64,
) -> KernelResult<usize> {
    let tmo_p = tmo_p.cast::<[i64; 2]>();
    let deadline = read_ts(tmo_p, PollTs::Timespec)?;

    // Handle signal mask atomically
    let saved_mask = if !sigmask_ptr.is_null() {
        // Validate sigsetsize - must be 8 bytes (64-bit sigset_t)
        if sigsetsize != 8 {
            return Err(KernelError::InvalidArgument);
        }
        set_poll_sigmask(SigSet::from_bits(sigmask_ptr.read()?))
    } else {
        None
    };

    let result = do_poll_internal(fds, nfds, deadline);

    // Restore mask if we changed it, unless interrupted by a signal: then
    // the temporary mask stays in effect for signal delivery and do_signal()
    // restores saved_sigmask (Linux: restore_saved_sigmask_unless()).
    // Decided before the time left is written back, which may turn the
    // restart into -EINTR (Linux poll_select_finish, in that order).
    if saved_mask.is_some() {
        restore_poll_sigmask(&result);
    }
    poll_finish(deadline, tmo_p, PollTs::Timespec, result)
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
/// * EBADF if an invalid fd is in any set
/// * EINVAL if nfds is negative or exceeds limit
/// * EFAULT if any pointer is invalid
/// * EINTR if interrupted by signal
pub fn sys_select(
    nfds: i32,
    readfds: UserPtr<u64>,
    writefds: UserPtr<u64>,
    exceptfds: UserPtr<u64>,
    timeout: UserPtr<Timeval>,
) -> KernelResult<usize> {
    let timeout = timeout.cast::<[i64; 2]>();
    let deadline = read_ts(timeout, PollTs::Timeval)?;

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
    readfds: UserPtr<u64>,
    writefds: UserPtr<u64>,
    exceptfds: UserPtr<u64>,
    timeout: UserPtr<LinuxTimespec>,
    sigmask: UserPtr<[u64; 2]>,
) -> KernelResult<usize> {
    let timeout = timeout.cast::<[i64; 2]>();
    let deadline = read_ts(timeout, PollTs::Timespec)?;

    // Handle signal mask atomically
    // The sigmask parameter in pselect6 is a pointer to a struct:
    // struct { const sigset_t *ss; size_t ss_len; }
    let saved_mask = if !sigmask.is_null() {
        // The pointer to the sigset_t and its size, read whole
        let [ss_ptr, ss_len] = sigmask.read()?;
        let ss = UserPtr::<u64>::new(ss_ptr);
        if !ss.is_null() {
            if ss_len != 8 {
                return Err(KernelError::InvalidArgument);
            }
            set_poll_sigmask(SigSet::from_bits(ss.read()?))
        } else {
            None
        }
    } else {
        None
    };

    let result = do_select_internal(nfds, readfds, writefds, exceptfds, deadline);

    // Restore mask if we changed it, unless interrupted by a signal: then
    // the temporary mask stays in effect for signal delivery and do_signal()
    // restores saved_sigmask (Linux: restore_saved_sigmask_unless()).
    // Decided before the time left is written back, which may turn the
    // restart into -EINTR (Linux poll_select_finish, in that order).
    if saved_mask.is_some() {
        restore_poll_sigmask(&result);
    }
    poll_finish(deadline, timeout, PollTs::Timespec, result)
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
    readfds: UserPtr<u64>,
    writefds: UserPtr<u64>,
    exceptfds: UserPtr<u64>,
    deadline: Deadline,
) -> KernelResult<usize> {
    use crate::io::poll::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLPRI, PollContext, PollTable};
    use crate::task::percpu::{SleepState, set_current_state};
    use crate::util::kmem::try_vec;

    if nfds < 0 {
        return Err(KernelError::InvalidArgument);
    }
    // Past the table's size nothing can be open (Linux core_sys_select)
    let n = (nfds as usize).min(current_fd_table().lock().max_fds());

    // Empty select: just sleep for the timeout (or until a signal)
    if n == 0 && readfds.is_null() && writefds.is_null() && exceptfds.is_null() {
        if deadline == Some(0) {
            return Ok(0);
        }
        return poll_sleep_only(deadline);
    }

    let [rd, wr, ex] = [
        get_fd_set(readfds, n)?,
        get_fd_set(writefds, n)?,
        get_fd_set(exceptfds, n)?,
    ];
    let words = n.div_ceil(64);
    let mut out = [try_vec(words, 0)?, try_vec(words, 0)?, try_vec(words, 0)?];
    let bit = |v: &[u64], fd: usize| v.get(fd / 64).is_some_and(|w| w & (1 << (fd % 64)) != 0);

    // Sized for the fds asked about (not nfds: select(FD_SETSIZE) with a
    // few bits set is the common case); only a select that may sleep
    // registers
    let asked = || {
        // Bits at or past n in the last word are not polled
        let mask = |i: usize| {
            if (i + 1) * 64 > n {
                (1u64 << (n % 64)) - 1
            } else {
                !0
            }
        };
        (0..words)
            .map(|i| ((rd[i] | wr[i] | ex[i]) & mask(i)).count_ones() as usize)
            .sum::<usize>()
    };
    let regs = if deadline == Some(0) { 0 } else { asked() };
    let mut ctx = PollContext::sized(regs);
    let mut first_pass = true;
    let mut ready_count;
    let fd_table = current_fd_table();
    loop {
        // State first, then scan: a wakeup during the scan is not lost
        set_current_state(SleepState::Interruptible);
        // Register on wait queues during the first scan only
        let mut poll_table = PollTable::new(&mut ctx);
        if !first_pass || deadline == Some(0) {
            poll_table.disable();
        }
        first_pass = false;
        ready_count = 0usize;
        for o in out.iter_mut() {
            o.fill(0);
        }
        for fd in 0..n {
            let (r, w, x) = (bit(&rd, fd), bit(&wr, fd), bit(&ex, fd));
            if !r && !w && !x {
                continue;
            }
            // Looked up alone, polled with no lock held (a poll may sleep)
            let file = fd_table.lock().get(fd as i32);
            let Some(file) = file else {
                set_current_state(SleepState::Running);
                return Err(KernelError::BadFd);
            };
            poll_table.hold_file(&file);
            let mut events = 0u16;
            if r {
                events |= POLLIN;
            }
            if w {
                events |= POLLOUT;
            }
            if x {
                events |= POLLPRI;
            }
            poll_table.set_key(events);
            let mask = file.poll(Some(&mut poll_table));
            let hits = [
                r && mask & (POLLIN | POLLERR | POLLHUP) != 0,
                w && mask & (POLLOUT | POLLERR | POLLHUP) != 0,
                x && mask & (POLLPRI | POLLERR) != 0,
            ];
            for (o, hit) in out.iter_mut().zip(hits) {
                if hit {
                    o[fd / 64] |= 1 << (fd % 64);
                }
            }
            // Each set bit counts (Linux do_select: retval per set)
            let set = hits.iter().filter(|&&h| h).count();
            if set > 0 {
                ready_count += set;
                poll_table.disable();
            }
        }
        if ready_count > 0 || deadline == Some(0) {
            set_current_state(SleepState::Running);
            break;
        }
        // Nothing ready and a registration failed (Linux do_select)
        if let Some(e) = ctx.error() {
            set_current_state(SleepState::Running);
            return Err(e);
        }
        match poll_sleep(deadline) {
            Some(Ok(_)) => break,
            Some(Err(e)) => return Err(e),
            None => {}
        }
    }
    drop(ctx);

    for (ptr, o) in [readfds, writefds, exceptfds].into_iter().zip(&out) {
        set_fd_set(ptr, o)?;
    }
    Ok(ready_count)
}

/// An fd_set of `n` bits from the user, whole words (Linux get_fd_set,
/// FDS_BYTES); all clear if `ptr` is null
fn get_fd_set(ptr: UserPtr<u64>, n: usize) -> KernelResult<Vec<u64>> {
    use crate::util::kmem::try_vec;
    let words = n.div_ceil(64);
    let mut v = try_vec(words, 0u64)?;
    if !ptr.is_null() && words > 0 {
        let mut raw = try_vec(words * 8, 0u8)?;
        crate::uaccess::copy_from_user(&mut raw, ptr.addr(), words * 8)?;
        for (w, b) in v.iter_mut().zip(raw.as_chunks::<8>().0) {
            *w = u64::from_ne_bytes(*b);
        }
    }
    Ok(v)
}

/// Copy a result set out (Linux set_fd_set): nothing if `ptr` is null
fn set_fd_set(ptr: UserPtr<u64>, v: &[u64]) -> KernelResult<()> {
    if ptr.is_null() || v.is_empty() {
        return Ok(());
    }
    let mut raw = crate::util::kmem::try_vec(v.len() * 8, 0u8)?;
    for (b, w) in raw.as_chunks_mut::<8>().0.iter_mut().zip(v) {
        *b = w.to_ne_bytes();
    }
    crate::uaccess::copy_to_user(ptr.addr(), &raw)?;
    Ok(())
}
