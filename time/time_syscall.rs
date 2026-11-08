//! Time-related syscall implementations
//!
//! Implements clock_gettime, gettimeofday, and related syscalls.
//!
//! All syscalls that access user memory use the uaccess primitives from
//! crate::uaccess to ensure proper validation and SMAP protection.

use crate::arch::Uaccess;
use crate::time::hrtimer::HrClock;
use crate::time::{ClockId, STA_NANO, STA_UNSYNC, TIMEKEEPER};
use crate::uaccess::{UaccessArch, get_user, put_user};
use crate::util::error::KernelError;

/// Linux clock IDs
pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;
pub const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
pub const CLOCK_THREAD_CPUTIME_ID: i32 = 3;
pub const CLOCK_MONOTONIC_RAW: i32 = 4;
pub const CLOCK_REALTIME_COARSE: i32 = 5;
pub const CLOCK_MONOTONIC_COARSE: i32 = 6;
pub const CLOCK_BOOTTIME: i32 = 7;
pub const CLOCK_REALTIME_ALARM: i32 = 8;
pub const CLOCK_BOOTTIME_ALARM: i32 = 9;
pub const CLOCK_TAI: i32 = 11;

/// CPU clock kinds (Linux CPUCLOCK_PROF/VIRT/SCHED): user+system,
/// user only, scheduler runtime (user+system on hk)
pub const CPUCLOCK_PROF: u8 = 0;
pub const CPUCLOCK_VIRT: u8 = 1;
pub const CPUCLOCK_SCHED: u8 = 2;

/// A clock id decoded (Linux clockid_to_kclock and the CPU clock
/// encoding of posix-cpu-timers)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PosixClock {
    Realtime,
    Monotonic,
    MonotonicRaw,
    RealtimeCoarse,
    MonotonicCoarse,
    Boottime,
    RealtimeAlarm,
    BoottimeAlarm,
    Tai,
    /// Process or thread CPU time: `pid` 0 is the caller
    Cpu {
        pid: u64,
        thread: bool,
        which: u8,
    },
}

impl PosixClock {
    /// Decode a clockid_t; None for an id Linux rejects (EINVAL). A
    /// negative id is a CPU clock: ~pid << 3 | thread << 2 | which.
    pub fn decode(id: i32) -> Option<Self> {
        if id < 0 {
            let which = (id & 3) as u8;
            if which > CPUCLOCK_SCHED {
                return None;
            }
            let pid = (!id >> 3) as u64;
            let thread = id & 4 != 0;
            return Some(Self::Cpu { pid, thread, which });
        }
        let cpu = |thread| Self::Cpu {
            pid: 0,
            thread,
            which: CPUCLOCK_SCHED,
        };
        Some(match id {
            CLOCK_REALTIME => Self::Realtime,
            CLOCK_MONOTONIC => Self::Monotonic,
            CLOCK_PROCESS_CPUTIME_ID => cpu(false),
            CLOCK_THREAD_CPUTIME_ID => cpu(true),
            CLOCK_MONOTONIC_RAW => Self::MonotonicRaw,
            CLOCK_REALTIME_COARSE => Self::RealtimeCoarse,
            CLOCK_MONOTONIC_COARSE => Self::MonotonicCoarse,
            CLOCK_BOOTTIME => Self::Boottime,
            CLOCK_REALTIME_ALARM => Self::RealtimeAlarm,
            CLOCK_BOOTTIME_ALARM => Self::BoottimeAlarm,
            CLOCK_TAI => Self::Tai,
            _ => return None,
        })
    }

    /// The hrtimer base a timer or sleep on this clock runs on, if it
    /// can have one: realtime-based clocks follow clock_settime. hk
    /// never suspends, so boottime is monotonic.
    pub fn timer_base(self) -> Option<HrClock> {
        match self {
            Self::Realtime | Self::RealtimeAlarm | Self::Tai => Some(HrClock::Realtime),
            Self::Monotonic | Self::Boottime | Self::BoottimeAlarm => Some(HrClock::Monotonic),
            _ => None,
        }
    }

    /// The clock's resolution in ns (Linux clock_getres: hrtimer clocks
    /// 1, coarse clocks a tick, CPU clocks 1 for SCHED else a tick)
    pub fn res_ns(self) -> u64 {
        match self {
            Self::RealtimeCoarse | Self::MonotonicCoarse => crate::task::percpu::TICK_NS,
            Self::Cpu {
                which: CPUCLOCK_PROF | CPUCLOCK_VIRT,
                ..
            } => crate::task::percpu::TICK_NS,
            _ => 1,
        }
    }

    /// The clock's time now in ns; Err for a CPU clock whose task does
    /// not exist or may not be read (EINVAL)
    pub fn now_ns(self) -> Result<i128, KernelError> {
        let read = |c| TIMEKEEPER.read(c, TIMEKEEPER.get_read_cycles()).to_nanos();
        let coarse = |ns: i128| ns - ns.rem_euclid(i128::from(crate::task::percpu::TICK_NS));
        Ok(match self {
            Self::Realtime | Self::RealtimeAlarm => read(ClockId::Realtime),
            Self::Monotonic | Self::MonotonicRaw | Self::Boottime | Self::BoottimeAlarm => {
                read(ClockId::Monotonic)
            }
            Self::RealtimeCoarse => coarse(read(ClockId::Realtime)),
            Self::MonotonicCoarse => coarse(read(ClockId::Monotonic)),
            Self::Tai => read(ClockId::Tai),
            Self::Cpu { pid, thread, which } => i128::from(cpu_clock_ns(pid, thread, which, true)?),
        })
    }

    /// The clock exists for clock_getres (Linux posix_cpu_clock_getres:
    /// lookup_task without gettime, so a process clock needs a group
    /// leader's pid, not the caller's own tid)
    pub fn getres_ok(self) -> bool {
        match self {
            Self::Cpu { pid, thread, which } => cpu_clock_ns(pid, thread, which, false).is_ok(),
            _ => self.now_ns().is_ok(),
        }
    }
}

/// The root number of a CPU clock's pid, which the caller numbers (0,
/// the caller, stays 0): None if it sees no such task (Linux
/// lookup_task: find_task_by_vpid)
pub fn clock_pid(pid: u64) -> Option<u64> {
    if pid == 0 {
        Some(0)
    } else {
        crate::task::pid::from_vnr(pid)
    }
}

/// TAI - UTC (adjtimex ADJ_TAI), in ns
pub fn tai_offset_ns() -> i128 {
    i128::from(TIMEKEEPER.tai_offset()) * 1_000_000_000
}

/// A CPU clock's time (Linux posix_cpu_clock_get / lookup_task): a
/// thread clock only for the caller's thread group, a process clock
/// only for a thread group leader, or (`gettime`: clock_gettime) the
/// caller's own tid
fn cpu_clock_ns(pid: u64, thread: bool, which: u8, gettime: bool) -> Result<u64, KernelError> {
    use crate::task::percpu;
    let pid = clock_pid(pid).ok_or(KernelError::InvalidArgument)?;
    let me = percpu::current_tid();
    let (utime, stime) = if thread {
        let tid = if pid == 0 {
            me
        } else {
            pid as crate::task::Tid
        };
        let table = percpu::TASKLIST.read();
        let t = table.get(tid).ok_or(KernelError::InvalidArgument)?;
        if t.task.pid != percpu::current_pid() {
            return Err(KernelError::InvalidArgument);
        }
        t.task.cputime(crate::time::monotonic_ns())
    } else {
        // Linux pid_for_clock (gettime): pid 0, or the caller's own tid
        // from any thread, is its process
        let tgid = if pid == 0 || (gettime && pid == me) {
            percpu::current_pid()
        } else {
            let table = percpu::TASKLIST.read();
            let t = table.get(pid as crate::task::Tid);
            if !t.is_some_and(|t| t.task.pid == pid) {
                return Err(KernelError::InvalidArgument);
            }
            pid
        };
        percpu::get_process_times(tgid)
    };
    Ok(match which {
        CPUCLOCK_VIRT => utime,
        _ => utime.saturating_add(stime), // PROF, SCHED
    })
}

/// clock_nanosleep on a process CPU clock (Linux posix_cpu_nsleep): a
/// relative sleep interrupted by a signal writes the CPU time left to
/// `rem` and is ERESTART_RESTARTBLOCK-like (hk restarts with the
/// original request: ERESTARTNOHAND); an absolute one restarts as is
fn cpu_nanosleep(clockid: i32, flags: i32, req: u64, rem: u64) -> i64 {
    if req == 0 || !Uaccess::access_ok(req, core::mem::size_of::<LinuxTimespec>()) {
        return KernelError::BadAddress.sysret();
    }
    let Ok(request) = get_user::<Uaccess, LinuxTimespec>(req) else {
        return KernelError::BadAddress.sysret();
    };
    if request.tv_sec < 0 || request.tv_nsec < 0 || request.tv_nsec >= 1_000_000_000 {
        return KernelError::InvalidArgument.sysret();
    }
    let ns = crate::time::timespec_to_ns(request.tv_sec, request.tv_nsec);
    let abs = flags & TIMER_ABSTIME != 0;
    match crate::time::posix_timer::cpu_nanosleep(clockid, abs, ns) {
        Ok(()) => 0,
        Err((KernelError::Interrupted, left)) => {
            if !abs && rem != 0 {
                let ts = LinuxTimespec {
                    tv_sec: (left / 1_000_000_000) as i64,
                    tv_nsec: (left % 1_000_000_000) as i64,
                };
                if put_user::<Uaccess, LinuxTimespec>(rem, ts).is_err() {
                    return KernelError::BadAddress.sysret();
                }
            }
            KernelError::RestartNoHand.sysret()
        }
        Err((e, _)) => e.sysret(),
    }
}

/// TIMER_ABSTIME flag for clock_nanosleep
pub const TIMER_ABSTIME: i32 = 1;

/// Linux timespec structure for clock_gettime
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LinuxTimespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}
crate::pod!(LinuxTimespec { tv_sec, tv_nsec });

/// Linux timeval structure (gettimeofday, itimerval)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}
crate::pod!(Timeval { tv_sec, tv_usec });

/// Linux timezone structure for gettimeofday (deprecated, usually ignored)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timezone {
    pub tz_minuteswest: i32,
    pub tz_dsttime: i32,
}
crate::pod!(Timezone {
    tz_minuteswest,
    tz_dsttime
});

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
        return KernelError::BadAddress.sysret();
    }

    let Some(Ok(ns)) = PosixClock::decode(clockid).map(PosixClock::now_ns) else {
        return KernelError::InvalidArgument.sysret();
    };
    let ts = crate::time::Timespec::from_nanos(ns);
    let result = LinuxTimespec {
        tv_sec: ts.sec,
        tv_nsec: i64::from(ts.nsec),
    };

    // Copy to user space using put_user
    if put_user::<Uaccess, LinuxTimespec>(tp, result).is_err() {
        return KernelError::BadAddress.sysret();
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
pub fn sys_gettimeofday(tv: u64, tz: u64) -> i64 {
    // Get wall-clock time (realtime)
    if tv != 0 {
        // Validate user buffer address
        if !Uaccess::access_ok(tv, core::mem::size_of::<Timeval>()) {
            return KernelError::BadAddress.sysret();
        }

        let ts = TIMEKEEPER.read(ClockId::Realtime, TIMEKEEPER.get_read_cycles());

        let result = Timeval {
            tv_sec: ts.sec,
            tv_usec: i64::from(ts.nsec) / 1000, // Convert ns to us
        };

        // Copy to user space
        if put_user::<Uaccess, Timeval>(tv, result).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    // Timezone is deprecated; if provided, return zeros
    if tz != 0 {
        // Validate user buffer address
        if !Uaccess::access_ok(tz, core::mem::size_of::<Timezone>()) {
            return KernelError::BadAddress.sysret();
        }

        let timezone = Timezone {
            tz_minuteswest: 0,
            tz_dsttime: 0,
        };

        if put_user::<Uaccess, Timezone>(tz, timezone).is_err() {
            return KernelError::BadAddress.sysret();
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
        return KernelError::BadAddress.sysret();
    }

    let request: LinuxTimespec = match get_user::<Uaccess, LinuxTimespec>(req) {
        Ok(ts) => ts,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate timespec values
    if request.tv_sec < 0 || request.tv_nsec < 0 || request.tv_nsec >= 1_000_000_000 {
        return KernelError::InvalidArgument.sysret();
    }

    let total_ns = crate::time::timespec_to_ns(request.tv_sec, request.tv_nsec);
    let deadline = crate::time::deadline_after(crate::time::monotonic_ns(), total_ns);
    do_nanosleep(deadline, rem)
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
    // Linux: an unknown clock is EINVAL, one that cannot sleep
    // EOPNOTSUPP (coarse, raw, thread CPU clocks: no nsleep); a process
    // CPU clock sleeps until that process has used the time
    // (posix_cpu_nsleep; the caller's own process here, BUGS.md)
    let Some(pclock) = PosixClock::decode(clockid) else {
        return KernelError::InvalidArgument.sysret();
    };
    let base = match pclock.timer_base() {
        Some(b) => b,
        None if matches!(pclock, PosixClock::Cpu { thread: false, .. }) => {
            return cpu_nanosleep(clockid, flags, req, rem);
        }
        None => return KernelError::OperationNotSupported.sysret(),
    };

    // Validate and read request timespec
    if req == 0 || !Uaccess::access_ok(req, core::mem::size_of::<LinuxTimespec>()) {
        return KernelError::BadAddress.sysret();
    }

    let request: LinuxTimespec = match get_user::<Uaccess, LinuxTimespec>(req) {
        Ok(ts) => ts,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate timespec values
    if request.tv_sec < 0 || request.tv_nsec < 0 || request.tv_nsec >= 1_000_000_000 {
        return KernelError::InvalidArgument.sysret();
    }

    let req_ns = crate::time::timespec_to_ns(request.tv_sec, request.tv_nsec);
    if flags & TIMER_ABSTIME != 0 {
        // Absolute time on `clockid`, kept on that clock: a realtime
        // sleep follows clock_settime (Linux hrtimer_nanosleep)
        // A TAI deadline is a realtime one TAI - UTC earlier
        let deadline = if pclock == PosixClock::Tai {
            (i128::from(req_ns) - tai_offset_ns()).max(0) as u64
        } else {
            req_ns
        };
        // Absolute sleeps are restarted unchanged; no remaining time
        match crate::task::percpu::sleep_until(deadline, base, true) {
            Ok(()) => 0,
            Err(_) => KernelError::RestartNoHand.sysret(),
        }
    } else {
        let now = crate::time::monotonic_ns();
        do_nanosleep(crate::time::deadline_after(now, req_ns), rem)
    }
}

/// sys_clock_getres - get resolution of specified clock
///
/// # Arguments
/// * `clockid` - Clock identifier (CLOCK_REALTIME or CLOCK_MONOTONIC)
/// * `res` - Pointer to user space timespec structure (may be NULL)
///
/// Returns 0 on success, negative errno on error.
pub fn sys_clock_getres(clockid: i32, res: u64) -> i64 {
    // Validate clock ID first (even if res is NULL per POSIX); a CPU
    // clock's task must exist
    let pclock = match PosixClock::decode(clockid) {
        Some(c) if c.getres_ok() => c,
        _ => return KernelError::InvalidArgument.sysret(),
    };

    // If res is NULL, just return success (validates clock ID only)
    if res == 0 {
        return 0;
    }

    // Validate user buffer address
    if !Uaccess::access_ok(res, core::mem::size_of::<LinuxTimespec>()) {
        return KernelError::BadAddress.sysret();
    }

    let res_ns = pclock.res_ns();
    let result = LinuxTimespec {
        tv_sec: (res_ns / 1_000_000_000) as i64,
        tv_nsec: (res_ns % 1_000_000_000) as i64,
    };

    if put_user::<Uaccess, LinuxTimespec>(res, result).is_err() {
        return KernelError::BadAddress.sysret();
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
            return KernelError::BadAddress.sysret();
        }
        if put_user::<Uaccess, i64>(tloc, seconds).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    // Return seconds since epoch
    seconds
}

/// Sleep until the CLOCK_MONOTONIC `deadline`, interruptibly
///
/// On a signal, stores the remaining time in `rem` (if non-NULL) and returns
/// -ERESTARTNOHAND: -EINTR once a handler runs (Linux returns
/// -ERESTART_RESTARTBLOCK and restarts with the remaining time when no
/// handler runs; hk restarts with the original request).
fn do_nanosleep(deadline: u64, rem: u64) -> i64 {
    match crate::task::percpu::sleep_until_ns(deadline, true) {
        Ok(()) => 0,
        Err(left) => {
            if rem != 0 {
                let ts = LinuxTimespec {
                    tv_sec: (left / 1_000_000_000) as i64,
                    tv_nsec: (left % 1_000_000_000) as i64,
                };
                if put_user::<Uaccess, LinuxTimespec>(rem, ts).is_err() {
                    return KernelError::BadAddress.sysret();
                }
            }
            KernelError::RestartNoHand.sysret()
        }
    }
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
    // Only CLOCK_REALTIME can be set (Linux: no clock_set is EINVAL,
    // before the copy)
    if clockid != CLOCK_REALTIME {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate user buffer address
    if tp == 0 || !Uaccess::access_ok(tp, core::mem::size_of::<LinuxTimespec>()) {
        return KernelError::BadAddress.sysret();
    }

    // Read timespec from user space
    let ts: LinuxTimespec = match get_user::<Uaccess, LinuxTimespec>(tp) {
        Ok(ts) => ts,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate timespec values
    if ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return KernelError::InvalidArgument.sysret();
    }
    // Linux do_sys_settimeofday64 -> security_settime64 (cap_settime)
    if !crate::task::capable(crate::task::CAP_SYS_TIME) {
        return KernelError::NotPermitted.sysret();
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
        KernelError::InvalidArgument.sysret()
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
pub fn sys_settimeofday(tv: u64, tz: u64) -> i64 {
    // If tv is provided, set the time
    if tv != 0 {
        // Validate user buffer address
        if !Uaccess::access_ok(tv, core::mem::size_of::<Timeval>()) {
            return KernelError::BadAddress.sysret();
        }

        let timeval: Timeval = match get_user::<Uaccess, Timeval>(tv) {
            Ok(tv) => tv,
            Err(_) => return KernelError::BadAddress.sysret(),
        };

        // Validate timeval values
        if timeval.tv_usec < 0 || timeval.tv_usec >= 1_000_000 {
            return KernelError::InvalidArgument.sysret();
        }

        // Convert timeval to Timespec (us -> ns)
        let new_time = crate::time::Timespec {
            sec: timeval.tv_sec,
            nsec: (timeval.tv_usec * 1000) as u32,
        };

        // Linux copies the timezone, then checks CAP_SYS_TIME
        // (security_settime64)
        if tz != 0 && !Uaccess::access_ok(tz, core::mem::size_of::<Timezone>()) {
            return KernelError::BadAddress.sysret();
        }
        if !crate::task::capable(crate::task::CAP_SYS_TIME) {
            return KernelError::NotPermitted.sysret();
        }
        if !TIMEKEEPER.set_realtime(new_time) {
            return KernelError::InvalidArgument.sysret(); // Timekeeper not initialized
        }
        return 0;
    }

    // Timezone is deprecated; we accept but ignore it
    // Just validate the pointer if provided
    if tz != 0 && !Uaccess::access_ok(tz, core::mem::size_of::<Timezone>()) {
        return KernelError::BadAddress.sysret();
    }
    // Linux: even a timezone-only (or empty) call needs CAP_SYS_TIME
    if !crate::task::capable(crate::task::CAP_SYS_TIME) {
        return KernelError::NotPermitted.sysret();
    }

    0
}

// =============================================================================
// Timerfd syscalls
// =============================================================================

use crate::io::eventfd::{create_eventfd, efd_flags};
use crate::io::pipe::FD_CLOEXEC;
use crate::task::fdtable::get_task_fd;
use crate::task::percpu::current_tid;
use crate::time::timerfd::{ITimerSpec, create_timerfd, get_timerfd, tfd_flags, tfd_timer_flags};

/// Get the RLIMIT_NOFILE limit for the current task
fn get_nofile_limit() -> u64 {
    let limit = crate::task::rlimit::rlimit(crate::task::rlimit::RLIMIT_NOFILE);
    if limit == crate::task::rlimit::RLIM_INFINITY {
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
    // Linux timerfd_create: realtime, monotonic, boottime and the two
    // alarm clocks (CAP_WAKE_ALARM, else EPERM)
    match clockid {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME => {}
        CLOCK_REALTIME_ALARM | CLOCK_BOOTTIME_ALARM => {
            if !crate::task::capable(crate::task::CAP_WAKE_ALARM) {
                return KernelError::NotPermitted.sysret();
            }
        }
        _ => return KernelError::InvalidArgument.sysret(),
    }

    // Validate flags (only TFD_CLOEXEC and TFD_NONBLOCK are allowed)
    let valid_flags = tfd_flags::TFD_CLOEXEC | tfd_flags::TFD_NONBLOCK;
    if flags & !valid_flags != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Create the timerfd file
    let Ok(file) = create_timerfd(clockid, flags) else {
        return KernelError::ProcessFileLimit.sysret();
    };

    // Get the FD table and allocate a file descriptor
    let Some(fd_table) = get_task_fd(current_tid()) else {
        return KernelError::ProcessFileLimit.sysret();
    };
    let mut table = fd_table.lock();
    let fd_flags = if flags & tfd_flags::TFD_CLOEXEC != 0 {
        FD_CLOEXEC
    } else {
        0
    };

    match table.alloc_with_flags(file, fd_flags, get_nofile_limit()) {
        Ok(fd) => i64::from(fd),
        Err(e) => -i64::from(e),
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
        return KernelError::InvalidArgument.sysret();
    }

    // Validate new_value pointer
    if new_value == 0 || !Uaccess::access_ok(new_value, core::mem::size_of::<ITimerSpec>()) {
        return KernelError::BadAddress.sysret();
    }

    // Read new_value from user space
    let new_spec: ITimerSpec = match get_user::<Uaccess, ITimerSpec>(new_value) {
        Ok(spec) => spec,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate timespec values (Linux itimerspec64_valid)
    if !new_spec.is_valid() {
        return KernelError::InvalidArgument.sysret();
    }

    // Get the file from fd
    let Some(fd_table) = get_task_fd(current_tid()) else {
        return KernelError::BadFd.sysret();
    };
    let Some(file) = fd_table.lock().get(fd) else {
        return KernelError::BadFd.sysret();
    };

    // Get the timerfd from the file
    let Some(timerfd) = get_timerfd(&file) else {
        // Not a timerfd
        return KernelError::BadFd.sysret();
    };

    // Set the timer and get the old value
    let old_spec = timerfd.settime(&new_spec, flags);

    // Write old_value if provided
    if old_value != 0 {
        if !Uaccess::access_ok(old_value, core::mem::size_of::<ITimerSpec>()) {
            return KernelError::BadAddress.sysret();
        }
        if put_user::<Uaccess, ITimerSpec>(old_value, old_spec).is_err() {
            return KernelError::BadAddress.sysret();
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
        return KernelError::BadAddress.sysret();
    }

    // Get the file from fd
    let Some(fd_table) = get_task_fd(current_tid()) else {
        return KernelError::BadFd.sysret();
    };
    let Some(file) = fd_table.lock().get(fd) else {
        return KernelError::BadFd.sysret();
    };

    // Get the timerfd from the file
    let Some(timerfd) = get_timerfd(&file) else {
        // Not a timerfd
        return KernelError::BadFd.sysret();
    };

    // Get current timer value
    let curr_spec = timerfd.gettime();

    // Write to user space
    if put_user::<Uaccess, ITimerSpec>(curr_value, curr_spec).is_err() {
        return KernelError::BadAddress.sysret();
    }

    0
}

// ============================================================================
// eventfd syscalls
// ============================================================================

/// sys_eventfd2 - create an eventfd file descriptor
///
/// # Arguments
/// * `initval` - Initial value for the counter
/// * `flags` - EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE
///
/// Returns fd on success, negative errno on error.
pub fn sys_eventfd2(initval: u32, flags: i32) -> i64 {
    // Validate flags (only EFD_CLOEXEC, EFD_NONBLOCK, and EFD_SEMAPHORE are allowed)
    let valid_flags = efd_flags::EFD_CLOEXEC | efd_flags::EFD_NONBLOCK | efd_flags::EFD_SEMAPHORE;
    if flags & !valid_flags != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Create the eventfd file
    let Ok(file) = create_eventfd(u64::from(initval), flags) else {
        return KernelError::ProcessFileLimit.sysret();
    };

    // Get the FD table and allocate a file descriptor
    let Some(fd_table) = get_task_fd(current_tid()) else {
        return KernelError::ProcessFileLimit.sysret();
    };
    let mut table = fd_table.lock();
    let fd_flags = if flags & efd_flags::EFD_CLOEXEC != 0 {
        FD_CLOEXEC
    } else {
        0
    };

    match table.alloc_with_flags(file, fd_flags, get_nofile_limit()) {
        Ok(fd) => i64::from(fd),
        Err(e) => -i64::from(e),
    }
}

/// sys_eventfd - create an eventfd file descriptor (legacy, x86_64 only)
///
/// # Arguments
/// * `initval` - Initial value for the counter
///
/// Returns fd on success, negative errno on error.
#[cfg(target_arch = "x86_64")]
pub fn sys_eventfd(initval: u32) -> i64 {
    sys_eventfd2(initval, 0)
}

// ============================================================================
// adjtimex syscall
// ============================================================================

/// Linux __kernel_timex_timeval (used inside timex)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TimexTimeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}
crate::pod!(TimexTimeval { tv_sec, tv_usec });

/// Linux __kernel_timex structure for adjtimex syscall
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timex {
    /// Mode selector (ADJ_* flags)
    pub modes: u32,
    _pad1: i32,
    /// Time offset (usec or nsec depending on ADJ_NANO)
    pub offset: i64,
    /// Frequency offset (scaled PPM)
    pub freq: i64,
    /// Maximum error (usec)
    pub maxerror: i64,
    /// Estimated error (usec)
    pub esterror: i64,
    /// Clock status (STA_* flags)
    pub status: i32,
    _pad2: i32,
    /// PLL time constant
    pub constant: i64,
    /// Clock precision (usec, read-only)
    pub precision: i64,
    /// Clock frequency tolerance (ppm, read-only)
    pub tolerance: i64,
    /// Current time (read-only except for ADJ_SETOFFSET)
    pub time: TimexTimeval,
    /// Usec between clock ticks
    pub tick: i64,
    /// PPS frequency (scaled ppm, read-only)
    pub ppsfreq: i64,
    /// PPS jitter (usec, read-only)
    pub jitter: i64,
    /// Interval duration shift (read-only)
    pub shift: i32,
    _pad3: i32,
    /// PPS stability (scaled ppm, read-only)
    pub stabil: i64,
    /// Jitter limit exceeded (read-only)
    pub jitcnt: i64,
    /// Calibration intervals (read-only)
    pub calcnt: i64,
    /// Calibration errors (read-only)
    pub errcnt: i64,
    /// Stability limit exceeded (read-only)
    pub stbcnt: i64,
    /// TAI offset (read-only)
    pub tai: i32,
    /// Padding for 11 more i32 fields
    _reserved: [i32; 11],
}
crate::pod!(Timex {
    modes,
    _pad1,
    offset,
    freq,
    maxerror,
    esterror,
    status,
    _pad2,
    constant,
    precision,
    tolerance,
    time,
    tick,
    ppsfreq,
    jitter,
    shift,
    _pad3,
    stabil,
    jitcnt,
    calcnt,
    errcnt,
    stbcnt,
    tai,
    _reserved
});

impl Default for Timex {
    fn default() -> Self {
        <Self as crate::util::pod::FromBytes>::zeroed()
    }
}

/// ADJ_* mode flags for adjtimex
pub const ADJ_FREQUENCY: u32 = 0x0002;
pub const ADJ_MAXERROR: u32 = 0x0004;
pub const ADJ_ESTERROR: u32 = 0x0008;
pub const ADJ_STATUS: u32 = 0x0010;
pub const ADJ_TIMECONST: u32 = 0x0020;
pub const ADJ_TAI: u32 = 0x0080;
pub const ADJ_SETOFFSET: u32 = 0x0100;
pub const ADJ_MICRO: u32 = 0x1000;
pub const ADJ_NANO: u32 = 0x2000;
pub const ADJ_TICK: u32 = 0x4000;

/// Clock time states (return values)
pub const TIME_OK: i32 = 0;
pub const TIME_ERROR: i32 = 5;

/// Largest time constant (Linux MAXTC)
const MAXTC: i64 = 10;

/// timex.freq (ppm << 16) to time_freq (ns/s << 32), clamped to
/// MAXFREQ (Linux ADJ_FREQUENCY: freq * PPM_SCALE)
fn freq_set(freq: i64) -> i64 {
    const PPM_SCALE: i64 = 1000 << (32 - 16);
    const MAXFREQ_SCALED: i64 = 500_000 << 32;
    freq.saturating_mul(PPM_SCALE)
        .clamp(-MAXFREQ_SCALED, MAXFREQ_SCALED)
}

/// time_freq back to timex.freq (Linux __do_adjtimex's fixed-point
/// inverse, rounding as it does)
fn freq_get(time_freq: i64) -> i64 {
    const PPM_SCALE: i64 = 1000 << (32 - 16);
    const INV_SHIFT: u32 = 19;
    const PPM_SCALE_INV: i64 = (1 << (INV_SHIFT + 32)) / PPM_SCALE + 1;
    let x = (time_freq >> INV_SHIFT) * PPM_SCALE_INV;
    // Linux shift_right: toward zero
    if x < 0 { -((-x) >> 32) } else { x >> 32 }
}

/// Writable STA_* status flags (read-write mask)
const STA_RW_MASK: i32 = crate::time::STA_PLL
    | crate::time::STA_PPSFREQ
    | crate::time::STA_PPSTIME
    | crate::time::STA_FLL
    | crate::time::STA_INS
    | crate::time::STA_DEL
    | crate::time::STA_UNSYNC
    | crate::time::STA_FREQHOLD;

/// sys_adjtimex - read or set kernel time variables
///
/// # Arguments
/// * `txc_p` - Pointer to user space timex structure
///
/// Returns TIME_OK (0) on success if clock is synchronized,
/// or TIME_ERROR (5) if unsynchronized,
/// or negative errno on error.
///
/// # Privilege
/// Reading (modes=0) is always allowed.
/// Setting values requires CAP_SYS_TIME capability.
pub fn sys_adjtimex(txc_p: u64) -> i64 {
    // Validate user buffer
    if txc_p == 0 || !Uaccess::access_ok(txc_p, core::mem::size_of::<Timex>()) {
        return KernelError::BadAddress.sysret();
    }

    // Read timex from user space
    let mut txc: Timex = match get_user::<Uaccess, Timex>(txc_p) {
        Ok(t) => t,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Check if any modifications are requested
    let is_read_only = txc.modes == 0;

    // Linux timekeeping_validate_timex: changing anything needs
    // CAP_SYS_TIME; the old adjtime mode only with its read-only bit
    // does not; ADJ_SETOFFSET always does
    const ADJ_ADJTIME: u32 = 0x8000;
    const ADJ_OFFSET_SINGLESHOT: u32 = 0x0001;
    const ADJ_OFFSET_READONLY: u32 = 0x2000;
    let cap = || crate::task::capable(crate::task::CAP_SYS_TIME);
    if txc.modes & ADJ_ADJTIME != 0 {
        if txc.modes & ADJ_OFFSET_SINGLESHOT == 0 {
            return KernelError::InvalidArgument.sysret();
        }
        if txc.modes & ADJ_OFFSET_READONLY == 0 && !cap() {
            return KernelError::NotPermitted.sysret();
        }
    } else if txc.modes != 0 && !cap() {
        return KernelError::NotPermitted.sysret();
    }
    if txc.modes & ADJ_SETOFFSET != 0 && !cap() {
        return KernelError::NotPermitted.sysret();
    }
    if !is_read_only {
        // Validate tick range if being set
        if txc.modes & ADJ_TICK != 0 {
            // Tick must be within 10% of nominal (10000 usec = 10ms for 100Hz)
            if txc.tick < 9000 || txc.tick > 11000 {
                return KernelError::InvalidArgument.sysret();
            }
        }

        // Validate offset if ADJ_SETOFFSET is used
        if txc.modes & ADJ_SETOFFSET != 0 {
            if txc.time.tv_usec < 0 {
                return KernelError::InvalidArgument.sysret();
            }
            if txc.modes & ADJ_NANO != 0 {
                if txc.time.tv_usec >= 1_000_000_000 {
                    return KernelError::InvalidArgument.sysret();
                }
            } else if txc.time.tv_usec >= 1_000_000 {
                return KernelError::InvalidArgument.sysret();
            }
        }
    }

    // Linux __do_adjtimex: in the old adjtime mode only the single-shot
    // offset (not kept by hk) is looked at, no other mode bit applies
    let user_modes = txc.modes;
    if txc.modes & ADJ_ADJTIME != 0 {
        txc.modes = 0;
    }

    // ADJ_SETOFFSET first, in its own write section (Linux do_adjtimex:
    // timekeeping_inject_offset before the NTP state)
    if txc.modes & ADJ_SETOFFSET != 0 {
        let offset_ns = if txc.modes & ADJ_NANO != 0 {
            txc.time
                .tv_sec
                .saturating_mul(1_000_000_000)
                .saturating_add(txc.time.tv_usec)
        } else {
            txc.time
                .tv_sec
                .saturating_mul(1_000_000_000)
                .saturating_add(txc.time.tv_usec.saturating_mul(1000))
        };
        if !TIMEKEEPER.inject_offset(offset_ns) {
            return KernelError::InvalidArgument.sysret();
        }
    }

    // The NTP state changes and the read-back under one hold of the
    // timekeeper lock (Linux __do_adjtimex)
    let modes = txc.modes;
    let (ntp, tai, ts) = TIMEKEEPER.ntp_update(|n| {
        // In Linux process_adjtimex_modes' order
        if modes & ADJ_STATUS != 0 {
            // Only allow setting writable status bits
            n.status = (n.status & !STA_RW_MASK) | (txc.status & STA_RW_MASK);
        }
        if modes & ADJ_NANO != 0 {
            n.status |= crate::time::STA_NANO;
        }
        if modes & ADJ_MICRO != 0 {
            n.status &= !crate::time::STA_NANO;
        }
        if modes & ADJ_FREQUENCY != 0 {
            n.freq = freq_set(txc.freq);
        }
        let limit = crate::time::NTP_PHASE_LIMIT;
        if modes & ADJ_MAXERROR != 0 {
            n.maxerror = txc.maxerror.clamp(0, limit);
        }
        if modes & ADJ_ESTERROR != 0 {
            n.esterror = txc.esterror.clamp(0, limit);
        }
        if modes & ADJ_TIMECONST != 0 {
            let mut c = txc.constant.clamp(0, MAXTC);
            if n.status & crate::time::STA_NANO == 0 {
                c += 4;
            }
            n.constant = c.clamp(0, MAXTC);
        }
        if modes & ADJ_TICK != 0 {
            n.tick = txc.tick;
        }
        // Linux __do_adjtimex: the new TAI offset is `constant`, ignored
        // outside 0..=MAX_TAI_OFFSET (`tai` is only read back)
        (modes & ADJ_TAI != 0 && (0..=100_000).contains(&txc.constant))
            .then_some(txc.constant as i32)
    });
    let status = ntp.status;

    txc.offset = 0; // No ongoing adjustment
    txc.freq = freq_get(ntp.freq);
    txc.maxerror = ntp.maxerror;
    txc.esterror = ntp.esterror;
    txc.status = status;
    txc.constant = ntp.constant;
    txc.precision = 1; // 1 microsecond precision
    txc.tolerance = 500; // 500 ppm tolerance
    txc.time.tv_sec = ts.sec;
    txc.time.tv_usec = if status & STA_NANO != 0 {
        i64::from(ts.nsec)
    } else {
        i64::from(ts.nsec) / 1000
    };
    txc.tick = ntp.tick;
    txc.ppsfreq = 0;
    txc.jitter = 0;
    txc.shift = 0;
    txc.stabil = 0;
    txc.jitcnt = 0;
    txc.calcnt = 0;
    txc.errcnt = 0;
    txc.stbcnt = 0;
    txc.tai = tai;

    // Copy result back to user space
    txc.modes = user_modes;
    if put_user::<Uaccess, Timex>(txc_p, txc).is_err() {
        return KernelError::BadAddress.sysret();
    }

    // Return clock state
    if status & STA_UNSYNC != 0 {
        i64::from(TIME_ERROR)
    } else {
        i64::from(TIME_OK)
    }
}

#[cfg(test)]
mod clock_tests {
    use super::*;

    /// Linux MAKE_PROCESS_CPUCLOCK / MAKE_THREAD_CPUCLOCK
    fn cpuclock(pid: i32, thread: bool, which: i32) -> i32 {
        (!pid << 3) | if thread { 4 } else { 0 } | which
    }

    #[test]
    fn decode_fixed_ids() {
        assert_eq!(PosixClock::decode(0), Some(PosixClock::Realtime));
        assert_eq!(PosixClock::decode(7), Some(PosixClock::Boottime));
        assert_eq!(PosixClock::decode(11), Some(PosixClock::Tai));
        assert_eq!(
            PosixClock::decode(CLOCK_THREAD_CPUTIME_ID),
            Some(PosixClock::Cpu {
                pid: 0,
                thread: true,
                which: CPUCLOCK_SCHED
            })
        );
        // CLOCK_SGI_CYCLE (10) and unknown ids
        assert_eq!(PosixClock::decode(10), None);
        assert_eq!(PosixClock::decode(16), None);
    }

    #[test]
    fn decode_cpu_ids() {
        let c = PosixClock::decode(cpuclock(42, false, CPUCLOCK_PROF as i32));
        assert_eq!(
            c,
            Some(PosixClock::Cpu {
                pid: 42,
                thread: false,
                which: CPUCLOCK_PROF
            })
        );
        let c = PosixClock::decode(cpuclock(7, true, CPUCLOCK_VIRT as i32));
        assert_eq!(
            c,
            Some(PosixClock::Cpu {
                pid: 7,
                thread: true,
                which: CPUCLOCK_VIRT
            })
        );
        // CPUCLOCK_MAX (3) is not a clock
        assert_eq!(PosixClock::decode(cpuclock(1, false, 3)), None);
    }

    #[test]
    fn timer_bases() {
        assert_eq!(PosixClock::Tai.timer_base(), Some(HrClock::Realtime));
        assert_eq!(PosixClock::Boottime.timer_base(), Some(HrClock::Monotonic));
        assert_eq!(PosixClock::MonotonicRaw.timer_base(), None);
        assert_eq!(
            PosixClock::RealtimeCoarse.res_ns(),
            crate::task::percpu::TICK_NS
        );
        assert_eq!(PosixClock::Monotonic.res_ns(), 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// timex.freq round-trips through time_freq as on Linux, clamped at
    /// MAXFREQ (500 ppm)
    #[test]
    fn freq_scaling() {
        for f in [0i64, 1, 65536, -65536, 100 << 16] {
            assert_eq!(freq_get(freq_set(f)), f);
        }
        assert_eq!(freq_get(freq_set(600 << 16)), 500 << 16);
        assert_eq!(freq_get(freq_set(-(600 << 16))), -(500 << 16));
    }
}
