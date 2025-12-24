//! Time-related syscall implementations
//!
//! Implements clock_gettime, gettimeofday, and related syscalls.
//!
//! All syscalls that access user memory use the uaccess primitives from
//! crate::uaccess to ensure proper validation and SMAP protection.

use crate::arch::Uaccess;
use crate::time::{ClockId, TIMEKEEPER};
use crate::uaccess::{UaccessArch, get_user, put_user};

/// Linux clock IDs
pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;

/// Error numbers (negated for return)
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
#[allow(dead_code)]
const EINTR: i64 = -4;

/// TIMER_ABSTIME flag for clock_nanosleep
pub const TIMER_ABSTIME: i32 = 1;

/// Linux timespec structure for clock_gettime
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LinuxTimespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// Linux timeval structure for gettimeofday (x86_64 only - aarch64 uses clock_gettime)
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

/// Linux timezone structure for gettimeofday (deprecated, usually ignored)
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timezone {
    pub tz_minuteswest: i32,
    pub tz_dsttime: i32,
}

/// sys_clock_gettime - get time from specified clock
///
/// # Arguments
/// * `clockid` - Clock identifier (CLOCK_REALTIME or CLOCK_MONOTONIC)
/// * `tp` - Pointer to user space timespec structure
///
/// Returns 0 on success, negative errno on error.
pub fn sys_clock_gettime(clockid: i32, tp: u64) -> i64 {
    // Validate user buffer address
    if tp == 0 || !Uaccess::access_ok(tp, core::mem::size_of::<LinuxTimespec>()) {
        return EFAULT;
    }

    let clock_id = match clockid {
        CLOCK_REALTIME => ClockId::Realtime,
        CLOCK_MONOTONIC => ClockId::Monotonic,
        _ => return EINVAL,
    };

    let ts = TIMEKEEPER.read(clock_id, TIMEKEEPER.get_read_cycles());

    let result = LinuxTimespec {
        tv_sec: ts.sec,
        tv_nsec: ts.nsec as i64,
    };

    // Copy to user space using put_user
    if put_user::<Uaccess, LinuxTimespec>(tp, result).is_err() {
        return EFAULT;
    }

    0
}

/// sys_gettimeofday - get wall-clock time
///
/// # Arguments
/// * `tv` - Pointer to user space timeval structure (may be NULL)
/// * `tz` - Pointer to user space timezone structure (may be NULL, deprecated)
///
/// Returns 0 on success, negative errno on error.
#[cfg(target_arch = "x86_64")]
pub fn sys_gettimeofday(tv: u64, tz: u64) -> i64 {
    // Get wall-clock time (realtime)
    if tv != 0 {
        // Validate user buffer address
        if !Uaccess::access_ok(tv, core::mem::size_of::<Timeval>()) {
            return EFAULT;
        }

        let ts = TIMEKEEPER.read(ClockId::Realtime, TIMEKEEPER.get_read_cycles());

        let result = Timeval {
            tv_sec: ts.sec,
            tv_usec: ts.nsec as i64 / 1000, // Convert ns to us
        };

        // Copy to user space
        if put_user::<Uaccess, Timeval>(tv, result).is_err() {
            return EFAULT;
        }
    }

    // Timezone is deprecated; if provided, return zeros
    if tz != 0 {
        // Validate user buffer address
        if !Uaccess::access_ok(tz, core::mem::size_of::<Timezone>()) {
            return EFAULT;
        }

        let timezone = Timezone {
            tz_minuteswest: 0,
            tz_dsttime: 0,
        };

        if put_user::<Uaccess, Timezone>(tz, timezone).is_err() {
            return EFAULT;
        }
    }

    0
}

/// sys_nanosleep - high-resolution sleep
///
/// # Arguments
/// * `req` - Pointer to user space timespec with requested sleep duration
/// * `rem` - Pointer to user space timespec to store remaining time (may be NULL)
///
/// Returns 0 on success, -EINTR if interrupted (with remaining time in rem),
/// or negative errno on error.
pub fn sys_nanosleep(req: u64, rem: u64) -> i64 {
    // Validate and read request timespec
    if req == 0 || !Uaccess::access_ok(req, core::mem::size_of::<LinuxTimespec>()) {
        return EFAULT;
    }

    let request: LinuxTimespec = match get_user::<Uaccess, LinuxTimespec>(req) {
        Ok(ts) => ts,
        Err(_) => return EFAULT,
    };

    // Validate timespec values
    if request.tv_sec < 0 || request.tv_nsec < 0 || request.tv_nsec >= 1_000_000_000 {
        return EINVAL;
    }

    // Convert to ticks (10ms per tick = 100 ticks/second)
    // Each tick is 10,000,000 nanoseconds
    const NS_PER_TICK: i64 = 10_000_000;
    let total_ns = request.tv_sec * 1_000_000_000 + request.tv_nsec;
    let sleep_ticks = (total_ns + NS_PER_TICK - 1) / NS_PER_TICK; // Round up

    // Get current tick and calculate wake tick
    let current_tick = crate::task::percpu::get_ticks();
    let wake_tick = current_tick + sleep_ticks as u64;

    // Put current task to sleep
    do_nanosleep(wake_tick);

    // For now, assume successful completion (no signals)
    // EINTR handling blocked on signal infrastructure (task signal state,
    // rt_sigaction syscall, signal delivery in scheduler)
    let _ = rem;

    0
}

/// sys_clock_nanosleep - high-resolution sleep with specified clock
///
/// # Arguments
/// * `clockid` - Clock to use (CLOCK_REALTIME or CLOCK_MONOTONIC)
/// * `flags` - Flags (TIMER_ABSTIME for absolute time)
/// * `req` - Pointer to user space timespec with sleep time
/// * `rem` - Pointer to user space timespec to store remaining time (may be NULL)
///
/// Returns 0 on success, or negative errno on error.
pub fn sys_clock_nanosleep(clockid: i32, flags: i32, req: u64, rem: u64) -> i64 {
    // Validate clock ID
    if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC {
        return EINVAL;
    }

    // Validate and read request timespec
    if req == 0 || !Uaccess::access_ok(req, core::mem::size_of::<LinuxTimespec>()) {
        return EFAULT;
    }

    let request: LinuxTimespec = match get_user::<Uaccess, LinuxTimespec>(req) {
        Ok(ts) => ts,
        Err(_) => return EFAULT,
    };

    // Validate timespec values
    if request.tv_sec < 0 || request.tv_nsec < 0 || request.tv_nsec >= 1_000_000_000 {
        return EINVAL;
    }

    const NS_PER_TICK: i64 = 10_000_000;

    let wake_tick = if flags & TIMER_ABSTIME != 0 {
        // Absolute time - calculate ticks from epoch
        // For now, simplified: just use monotonic time as ticks
        let target_ns = request.tv_sec * 1_000_000_000 + request.tv_nsec;
        let target_ticks = target_ns / NS_PER_TICK;
        target_ticks as u64
    } else {
        // Relative time - same as nanosleep
        let total_ns = request.tv_sec * 1_000_000_000 + request.tv_nsec;
        let sleep_ticks = (total_ns + NS_PER_TICK - 1) / NS_PER_TICK;
        let current_tick = crate::task::percpu::get_ticks();
        current_tick + sleep_ticks as u64
    };

    // Put current task to sleep
    do_nanosleep(wake_tick);

    // EINTR handling blocked on signal infrastructure
    let _ = rem;
    0
}

/// sys_clock_getres - get resolution of specified clock
///
/// # Arguments
/// * `clockid` - Clock identifier (CLOCK_REALTIME or CLOCK_MONOTONIC)
/// * `res` - Pointer to user space timespec structure (may be NULL)
///
/// Returns 0 on success, negative errno on error.
pub fn sys_clock_getres(clockid: i32, res: u64) -> i64 {
    // Validate clock ID first (even if res is NULL per POSIX)
    if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC {
        return EINVAL;
    }

    // If res is NULL, just return success (validates clock ID only)
    if res == 0 {
        return 0;
    }

    // Validate user buffer address
    if !Uaccess::access_ok(res, core::mem::size_of::<LinuxTimespec>()) {
        return EFAULT;
    }

    // Return 1 nanosecond resolution (high-resolution mode)
    let result = LinuxTimespec {
        tv_sec: 0,
        tv_nsec: 1,
    };

    if put_user::<Uaccess, LinuxTimespec>(res, result).is_err() {
        return EFAULT;
    }

    0
}

/// sys_time - get time in seconds since epoch (x86_64 only)
///
/// # Arguments
/// * `tloc` - Pointer to user space time_t (may be NULL)
///
/// Returns seconds since epoch on success, negative errno on error.
///
/// Note: This is a legacy syscall. aarch64 uses clock_gettime instead.
#[cfg(target_arch = "x86_64")]
pub fn sys_time(tloc: u64) -> i64 {
    // Get current real time
    let ts = TIMEKEEPER.read(ClockId::Realtime, TIMEKEEPER.get_read_cycles());
    let seconds = ts.sec;

    // If tloc is provided, write time to user space
    if tloc != 0 {
        if !Uaccess::access_ok(tloc, core::mem::size_of::<i64>()) {
            return EFAULT;
        }
        if put_user::<Uaccess, i64>(tloc, seconds).is_err() {
            return EFAULT;
        }
    }

    // Return seconds since epoch
    seconds
}

/// Internal sleep implementation
fn do_nanosleep(wake_tick: u64) {
    // Get current task TID
    let tid = crate::task::percpu::current_tid();
    if tid == 0 {
        return; // No current task
    }

    // Add to sleep queue and yield
    // The scheduler will wake us when wake_tick is reached
    crate::task::percpu::sleep_current_until(wake_tick);
}

/// sys_clock_settime - set time for specified clock
///
/// # Arguments
/// * `clockid` - Clock identifier (only CLOCK_REALTIME can be set)
/// * `tp` - Pointer to user space timespec structure with new time
///
/// Returns 0 on success, negative errno on error.
///
/// # Errors
/// - EINVAL: Invalid clock ID (CLOCK_MONOTONIC cannot be set)
/// - EINVAL: Invalid timespec (tv_nsec out of range)
/// - EFAULT: Invalid tp pointer
pub fn sys_clock_settime(clockid: i32, tp: u64) -> i64 {
    // Validate user buffer address
    if tp == 0 || !Uaccess::access_ok(tp, core::mem::size_of::<LinuxTimespec>()) {
        return EFAULT;
    }

    // Only CLOCK_REALTIME can be set
    if clockid != CLOCK_REALTIME {
        return EINVAL;
    }

    // Read timespec from user space
    let ts: LinuxTimespec = match get_user::<Uaccess, LinuxTimespec>(tp) {
        Ok(ts) => ts,
        Err(_) => return EFAULT,
    };

    // Validate timespec values
    if ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return EINVAL;
    }

    // Convert to Timespec and set
    let new_time = crate::time::Timespec {
        sec: ts.tv_sec,
        nsec: ts.tv_nsec as u32,
    };

    if TIMEKEEPER.set_realtime(new_time) {
        0
    } else {
        // Timekeeper not initialized
        EINVAL
    }
}

/// sys_settimeofday - set wall-clock time (x86_64 only)
///
/// # Arguments
/// * `tv` - Pointer to user space timeval structure (may be NULL)
/// * `tz` - Pointer to user space timezone structure (may be NULL, deprecated)
///
/// Returns 0 on success, negative errno on error.
///
/// # Errors
/// - EINVAL: tv_usec out of range [0, 999999]
/// - EFAULT: Invalid pointer
///
/// Note: This is a legacy syscall. aarch64 uses clock_settime instead.
#[cfg(target_arch = "x86_64")]
pub fn sys_settimeofday(tv: u64, tz: u64) -> i64 {
    // If tv is provided, set the time
    if tv != 0 {
        // Validate user buffer address
        if !Uaccess::access_ok(tv, core::mem::size_of::<Timeval>()) {
            return EFAULT;
        }

        let timeval: Timeval = match get_user::<Uaccess, Timeval>(tv) {
            Ok(tv) => tv,
            Err(_) => return EFAULT,
        };

        // Validate timeval values
        if timeval.tv_usec < 0 || timeval.tv_usec >= 1_000_000 {
            return EINVAL;
        }

        // Convert timeval to Timespec (us -> ns)
        let new_time = crate::time::Timespec {
            sec: timeval.tv_sec,
            nsec: (timeval.tv_usec * 1000) as u32,
        };

        if !TIMEKEEPER.set_realtime(new_time) {
            return EINVAL; // Timekeeper not initialized
        }
    }

    // Timezone is deprecated; we accept but ignore it
    // Just validate the pointer if provided
    if tz != 0 && !Uaccess::access_ok(tz, core::mem::size_of::<Timezone>()) {
        return EFAULT;
    }

    0
}

// =============================================================================
// Timerfd syscalls
// =============================================================================

use crate::pipe::FD_CLOEXEC;
use crate::task::fdtable::get_task_fd;
use crate::task::percpu::current_tid;
use crate::timerfd::{ITimerSpec, create_timerfd, get_timerfd, tfd_flags, tfd_timer_flags};

/// Error numbers
const EBADF: i64 = -9;
const EMFILE: i64 = -24;

/// Get the RLIMIT_NOFILE limit for the current task
fn get_nofile_limit() -> u64 {
    let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_NOFILE);
    if limit == crate::rlimit::RLIM_INFINITY {
        u64::MAX
    } else {
        limit
    }
}

/// sys_timerfd_create - create a timerfd file descriptor
///
/// # Arguments
/// * `clockid` - Clock to use (CLOCK_REALTIME or CLOCK_MONOTONIC)
/// * `flags` - TFD_CLOEXEC | TFD_NONBLOCK
///
/// Returns fd on success, negative errno on error.
pub fn sys_timerfd_create(clockid: i32, flags: i32) -> i64 {
    // Validate clockid
    if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC {
        return EINVAL;
    }

    // Validate flags (only TFD_CLOEXEC and TFD_NONBLOCK are allowed)
    let valid_flags = tfd_flags::TFD_CLOEXEC | tfd_flags::TFD_NONBLOCK;
    if flags & !valid_flags != 0 {
        return EINVAL;
    }

    // Create the timerfd file
    let file = match create_timerfd(clockid, flags) {
        Ok(f) => f,
        Err(_) => return EMFILE,
    };

    // Get the FD table and allocate a file descriptor
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return EMFILE,
    };
    let mut table = fd_table.lock();
    let fd_flags = if flags & tfd_flags::TFD_CLOEXEC != 0 {
        FD_CLOEXEC
    } else {
        0
    };

    match table.alloc_with_flags(file, fd_flags, get_nofile_limit()) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// sys_timerfd_settime - arm/disarm a timerfd
///
/// # Arguments
/// * `fd` - Timerfd file descriptor
/// * `flags` - TFD_TIMER_ABSTIME for absolute time
/// * `new_value` - Pointer to new itimerspec
/// * `old_value` - Pointer to store old itimerspec (may be NULL)
///
/// Returns 0 on success, negative errno on error.
pub fn sys_timerfd_settime(fd: i32, flags: i32, new_value: u64, old_value: u64) -> i64 {
    // Validate flags
    let valid_flags = tfd_timer_flags::TFD_TIMER_ABSTIME | tfd_timer_flags::TFD_TIMER_CANCEL_ON_SET;
    if flags & !valid_flags != 0 {
        return EINVAL;
    }

    // Validate new_value pointer
    if new_value == 0 || !Uaccess::access_ok(new_value, core::mem::size_of::<ITimerSpec>()) {
        return EFAULT;
    }

    // Read new_value from user space
    let new_spec: ITimerSpec = match get_user::<Uaccess, ITimerSpec>(new_value) {
        Ok(spec) => spec,
        Err(_) => return EFAULT,
    };

    // Validate timespec values
    if new_spec.it_value.tv_nsec < 0
        || new_spec.it_value.tv_nsec >= 1_000_000_000
        || new_spec.it_interval.tv_nsec < 0
        || new_spec.it_interval.tv_nsec >= 1_000_000_000
    {
        return EINVAL;
    }

    // Get the file from fd
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return EBADF,
    };
    let file = match fd_table.lock().get(fd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Get the timerfd from the file
    let timerfd = match get_timerfd(&file) {
        Some(t) => t,
        None => return EBADF, // Not a timerfd
    };

    // Set the timer and get the old value
    let old_spec = timerfd.settime(&new_spec, flags);

    // Write old_value if provided
    if old_value != 0 {
        if !Uaccess::access_ok(old_value, core::mem::size_of::<ITimerSpec>()) {
            return EFAULT;
        }
        if put_user::<Uaccess, ITimerSpec>(old_value, old_spec).is_err() {
            return EFAULT;
        }
    }

    0
}

/// sys_timerfd_gettime - get current timer value
///
/// # Arguments
/// * `fd` - Timerfd file descriptor
/// * `curr_value` - Pointer to store current itimerspec
///
/// Returns 0 on success, negative errno on error.
pub fn sys_timerfd_gettime(fd: i32, curr_value: u64) -> i64 {
    // Validate curr_value pointer
    if curr_value == 0 || !Uaccess::access_ok(curr_value, core::mem::size_of::<ITimerSpec>()) {
        return EFAULT;
    }

    // Get the file from fd
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return EBADF,
    };
    let file = match fd_table.lock().get(fd) {
        Some(f) => f,
        None => return EBADF,
    };

    // Get the timerfd from the file
    let timerfd = match get_timerfd(&file) {
        Some(t) => t,
        None => return EBADF, // Not a timerfd
    };

    // Get current timer value
    let curr_spec = timerfd.gettime();

    // Write to user space
    if put_user::<Uaccess, ITimerSpec>(curr_value, curr_spec).is_err() {
        return EFAULT;
    }

    0
}
