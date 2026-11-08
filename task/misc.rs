//! Miscellaneous task syscalls
//!
//! This module contains various task-related syscalls:
//! - sysinfo, getrusage, getrandom (system info)
//! - prctl, arch_prctl, personality (process control)
//! - syslog (kernel logging)
//! - capget, capset (capabilities)
//! - pidfd_open, pidfd_send_signal, pidfd_getfd (pidfd operations)

use crate::fs::file::File;
use crate::signal::Signal;
use crate::uaccess::UserPtr;
use crate::util::error::{KernelError, KernelResult};
use crate::util::kalloc::try_arc;
use crate::util::pod::FromBytes;

use super::Pid;

// =============================================================================
// sysinfo and getrusage syscalls
// =============================================================================

/// Linux sysinfo structure (matches Linux kernel struct sysinfo layout)
///
/// Used by the sysinfo(2) syscall to return system-wide statistics.
/// All padding is explicit so no uninitialized bytes reach userspace.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SysInfo {
    /// Seconds since boot
    pub uptime: i64,
    /// 1, 5, and 15 minute load averages (fixed-point)
    pub loads: [u64; 3],
    /// Total usable main memory size
    pub totalram: u64,
    /// Available memory size
    pub freeram: u64,
    /// Amount of shared memory (0 for us)
    pub sharedram: u64,
    /// Memory used by buffers (0 for us)
    pub bufferram: u64,
    /// Total swap space size (0 for us)
    pub totalswap: u64,
    /// Swap space still available (0 for us)
    pub freeswap: u64,
    /// Number of current processes
    pub procs: u16,
    /// Padding for alignment
    pub pad: u16,
    /// Explicit padding for u64 alignment (always zero)
    pub _pad2: u32,
    /// Total high memory size (0 for 64-bit)
    pub totalhigh: u64,
    /// Available high memory size (0 for 64-bit)
    pub freehigh: u64,
    /// Memory unit size in bytes (1 = bytes)
    pub mem_unit: u32,
    /// Explicit tail padding (Linux `_f[20-2*sizeof(long)-sizeof(int)]` is
    /// empty on 64-bit; this covers the struct alignment tail). Always zero.
    pub _f: u32,
}
crate::pod!(SysInfo {
    uptime,
    loads,
    totalram,
    freeram,
    sharedram,
    bufferram,
    totalswap,
    freeswap,
    procs,
    pad,
    _pad2,
    totalhigh,
    freehigh,
    mem_unit,
    _f
});

// Compile-time assertion that SysInfo is 112 bytes (matches Linux and userspace)
const _: () = assert!(core::mem::size_of::<SysInfo>() == 112);

/// Timeval structure for rusage (matches Linux)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Timeval {
    /// Seconds
    pub tv_sec: i64,
    /// Microseconds
    pub tv_usec: i64,
}
crate::pod!(Timeval { tv_sec, tv_usec });

/// Linux rusage structure (144 bytes)
///
/// This matches the Linux kernel's struct rusage layout exactly.
/// Used by getrusage(2) to return resource usage statistics.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Rusage {
    /// User CPU time used
    pub ru_utime: Timeval,
    /// System CPU time used
    pub ru_stime: Timeval,
    /// Maximum resident set size (in kilobytes)
    pub ru_maxrss: i64,
    /// Integral shared memory size (unused)
    pub ru_ixrss: i64,
    /// Integral unshared data size (unused)
    pub ru_idrss: i64,
    /// Integral unshared stack size (unused)
    pub ru_isrss: i64,
    /// Page reclaims (soft page faults)
    pub ru_minflt: i64,
    /// Page faults (hard page faults)
    pub ru_majflt: i64,
    /// Swaps (unused)
    pub ru_nswap: i64,
    /// Block input operations (unused for now)
    pub ru_inblock: i64,
    /// Block output operations (unused for now)
    pub ru_oublock: i64,
    /// IPC messages sent (unused)
    pub ru_msgsnd: i64,
    /// IPC messages received (unused)
    pub ru_msgrcv: i64,
    /// Signals received (unused)
    pub ru_nsignals: i64,
    /// Voluntary context switches
    pub ru_nvcsw: i64,
    /// Involuntary context switches
    pub ru_nivcsw: i64,
}
crate::pod!(Rusage {
    ru_utime,
    ru_stime,
    ru_maxrss,
    ru_ixrss,
    ru_idrss,
    ru_isrss,
    ru_minflt,
    ru_majflt,
    ru_nswap,
    ru_inblock,
    ru_oublock,
    ru_msgsnd,
    ru_msgrcv,
    ru_nsignals,
    ru_nvcsw,
    ru_nivcsw
});

// Compile-time assertion that Rusage is 144 bytes (matches Linux)
const _: () = assert!(core::mem::size_of::<Rusage>() == 144);

/// RUSAGE_SELF - get resource usage of calling process
pub const RUSAGE_SELF: i32 = 0;
/// RUSAGE_CHILDREN - get resource usage of terminated children
pub const RUSAGE_CHILDREN: i32 = -1;
/// RUSAGE_THREAD - get resource usage of calling thread
pub const RUSAGE_THREAD: i32 = 1;

/// sys_sysinfo - return system information
///
/// Returns system-wide statistics in a SysInfo structure.
///
/// # Arguments
/// * `info_ptr` - User pointer to struct sysinfo
///
/// # Returns
/// * 0 on success
/// * -EFAULT if copy to user fails
///
/// # Locking
/// Reads memory stats and process count with brief lock holds.
/// Reads time without locking (seqlock-protected).
pub fn sys_sysinfo<A: crate::uaccess::UaccessArch>(info_ptr: UserPtr<SysInfo>) -> KernelResult<()> {
    use crate::FRAME_ALLOCATOR;
    use crate::time::{ClockId, TIMEKEEPER};
    use crate::uaccess::put_user;

    // Get uptime (monotonic time since boot, in seconds)
    let mono = TIMEKEEPER.read(ClockId::Monotonic, TIMEKEEPER.get_read_cycles());
    let uptime_secs = mono.sec;

    // Get memory statistics from frame allocator
    let mem_stats = FRAME_ALLOCATOR.stats();

    let (swap_total, swap_free) = crate::mm::swap::swap_totals();
    // Get process count from scheduler
    let procs = super::percpu::task_count() as u16;

    // Build the sysinfo structure
    let info = SysInfo {
        uptime: uptime_secs,
        // Linux: avenrun << (SI_LOAD_SHIFT - FSHIFT)
        loads: crate::task::loadavg::avenrun().map(|a| a << (16 - crate::task::loadavg::FSHIFT)),
        totalram: mem_stats.total_bytes,
        freeram: mem_stats.free_bytes,
        totalswap: swap_total * 4096,
        freeswap: swap_free * 4096,
        procs,
        mem_unit: 1, // All sizes in bytes
        ..FromBytes::zeroed()
    };

    put_user::<A, SysInfo>(info_ptr.addr(), info)?;
    Ok(())
}

/// Convert nanoseconds to Timeval
fn timeval_from_ns(ns: u64) -> Timeval {
    Timeval {
        tv_sec: (ns / 1_000_000_000) as i64,
        tv_usec: ((ns % 1_000_000_000) / 1000) as i64,
    }
}

/// Write a `struct rusage` holding the given CPU times to user space.
///
/// Used by waitid()/wait4() to report a reaped child's resource usage.
/// Fields other than utime/stime are not tracked and are zeroed.
pub fn put_rusage_times(usage: UserPtr<Rusage>, utime_ns: u64, stime_ns: u64) -> KernelResult<()> {
    let r = Rusage {
        ru_utime: timeval_from_ns(utime_ns),
        ru_stime: timeval_from_ns(stime_ns),
        ..Rusage::default()
    };
    Ok(usage.write(&r)?)
}

/// struct tms (Linux include/uapi/linux/times.h), in clock ticks
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Tms {
    tms_utime: i64,
    tms_stime: i64,
    tms_cutime: i64,
    tms_cstime: i64,
}
crate::pod!(Tms {
    tms_utime,
    tms_stime,
    tms_cutime,
    tms_cstime
});

fn ns_to_clock_t(ns: u64) -> i64 {
    crate::time::ns_to_clock_t(ns) as i64
}

/// times(2) (Linux kernel/sys.c sys_times): the process's and its
/// reaped children's user and system time into `buf` (if not NULL),
/// and the clock ticks since boot (Linux jiffies in USER_HZ units,
/// counted from 0 where Linux starts 5 minutes before the wrap)
pub fn sys_times<A: crate::uaccess::UaccessArch>(buf: UserPtr<Tms>) -> KernelResult<i64> {
    use crate::task::percpu;
    if !buf.is_null() {
        let (utime, stime) = percpu::get_process_times(percpu::current_pid());
        let (cutime, cstime) = percpu::children_times();
        let t = Tms {
            tms_utime: ns_to_clock_t(utime),
            tms_stime: ns_to_clock_t(stime),
            tms_cutime: ns_to_clock_t(cutime),
            tms_cstime: ns_to_clock_t(cstime),
        };
        crate::uaccess::put_user::<A, Tms>(buf.addr(), t)?;
    }
    Ok(crate::time::ticks_to_clock_t(percpu::get_ticks()) as i64)
}

/// sys_getrusage - get resource usage
///
/// Returns resource usage statistics for the specified target.
///
/// # Arguments
/// * `who` - RUSAGE_SELF, RUSAGE_CHILDREN, or RUSAGE_THREAD
/// * `usage_ptr` - User pointer to struct rusage
///
/// # Returns
/// * 0 on success
/// * -EINVAL for invalid `who` value
/// * -EFAULT if copy to user fails
///
/// # Locking
/// Acquires TASKLIST lock to read task CPU times.
///
/// # Implementation Notes
/// Returns utime and stime for the current task/process. Other fields
/// like maxrss, page faults, and context switches are also populated
/// when available.
pub fn sys_getrusage<A: crate::uaccess::UaccessArch>(
    who: i32,
    usage_ptr: UserPtr<Rusage>,
) -> KernelResult<()> {
    use crate::task::percpu;
    use crate::uaccess::put_user;

    // Validate who parameter
    // Build rusage structure
    let usage = match who {
        RUSAGE_THREAD => {
            // RUSAGE_THREAD: return current thread's stats only
            let (utime_ns, stime_ns) = percpu::get_task_times(&percpu::current());
            Rusage {
                ru_utime: timeval_from_ns(utime_ns),
                ru_stime: timeval_from_ns(stime_ns),
                ..Rusage::default()
            }
        }
        RUSAGE_SELF => {
            // RUSAGE_SELF: return aggregate stats for all threads in process
            let pid = percpu::current_pid();
            let (utime_ns, stime_ns) = percpu::get_process_times(pid);
            Rusage {
                ru_utime: timeval_from_ns(utime_ns),
                ru_stime: timeval_from_ns(stime_ns),
                ..Rusage::default()
            }
        }
        RUSAGE_CHILDREN => {
            // Reaped children and theirs (Linux signal->cutime/cstime)
            let (utime_ns, stime_ns) = percpu::children_times();
            Rusage {
                ru_utime: timeval_from_ns(utime_ns),
                ru_stime: timeval_from_ns(stime_ns),
                ..Rusage::default()
            }
        }
        _ => return Err(KernelError::InvalidArgument),
    };
    put_user::<A, Rusage>(usage_ptr.addr(), usage)?;
    Ok(())
}

/// sys_getrandom - get random bytes
///
/// Fills a buffer with random bytes from the kernel CRNG.
///
/// # Arguments
/// * `buf` - User pointer to buffer to fill
/// * `buflen` - Number of bytes to generate
/// * `flags` - GRND_NONBLOCK, GRND_RANDOM, GRND_INSECURE
///
/// # Returns
/// Number of bytes written on success, negative errno on error.
///
/// # Errors
/// * EFAULT - Invalid buffer pointer
/// * EINVAL - Invalid flags
pub fn sys_getrandom<A: crate::uaccess::UaccessArch>(
    buf: UserPtr<u8>,
    buflen: usize,
    flags: u32,
) -> KernelResult<usize> {
    use crate::random;
    use crate::uaccess::copy_to_user;

    // Flags first (EINVAL even for an empty buffer, as on Linux)
    random::get_random_bytes(&mut [], flags)?;
    // Linux getrandom: at most MAX_RW_COUNT per call; a fault before
    // any byte is EFAULT, after some returns the count
    let len = buflen.min(crate::fs::syscall::MAX_RW_COUNT);
    if len == 0 {
        return Ok(0);
    }
    if !A::access_ok(buf.addr(), len) {
        return Err(KernelError::BadAddress);
    }
    let n = random::stream(len, |off, b| {
        copy_to_user::<A>(buf.addr() + off as u64, b).is_ok()
    });
    if n == 0 {
        return Err(KernelError::BadAddress);
    }
    Ok(n)
}

// =============================================================================
// prctl syscall
// =============================================================================

use crate::task::prctl_ops::{
    PR_GET_CHILD_SUBREAPER, PR_GET_DUMPABLE, PR_GET_KEEPCAPS, PR_GET_NAME, PR_GET_NO_NEW_PRIVS,
    PR_GET_PDEATHSIG, PR_GET_SECCOMP, PR_GET_THP_DISABLE, PR_GET_TIMERSLACK,
    PR_SET_CHILD_SUBREAPER, PR_SET_DUMPABLE, PR_SET_KEEPCAPS, PR_SET_NAME, PR_SET_NO_NEW_PRIVS,
    PR_SET_PDEATHSIG, PR_SET_SECCOMP, PR_SET_THP_DISABLE, PR_SET_TIMERSLACK,
};
#[cfg(target_arch = "x86_64")]
use crate::task::prctl_ops::{PR_GET_TSC, PR_SET_TSC, PR_TSC_ENABLE, PR_TSC_SIGSEGV};

/// sys_prctl - Process/thread control operations
///
/// Provides various process/thread control operations. Unlike arch_prctl,
/// this syscall is portable across architectures.
///
/// Supported operations:
/// - PR_SET_PDEATHSIG (1): Set parent death signal (arg2 = signal, 0 to disable)
/// - PR_GET_PDEATHSIG (2): Get parent death signal (arg2 = int* for result)
/// - PR_SET_DUMPABLE (4): Set core dump flag (arg2 = 0, 1, or 2)
/// - PR_GET_DUMPABLE (3): Get core dump flag (returns value)
/// - PR_SET_KEEPCAPS (8): Keep capabilities across setuid (arg2 = 0 or 1)
/// - PR_GET_KEEPCAPS (7): Get keep_caps flag (returns 0 or 1)
/// - PR_SET_NAME (15): Set thread name (16-byte max, arg2 = char*)
/// - PR_GET_NAME (16): Get thread name (arg2 = char* buffer)
/// - PR_SET_TIMERSLACK (29): Set timer slack (arg2 = nanoseconds)
/// - PR_GET_TIMERSLACK (30): Get timer slack (returns nanoseconds)
/// - PR_SET_CHILD_SUBREAPER (36): Make process a subreaper (arg2 = 0 or 1)
/// - PR_GET_CHILD_SUBREAPER (37): Get subreaper flag (arg2 = int* for result)
/// - PR_SET_NO_NEW_PRIVS (38): Disable privilege escalation (arg2 = 1, irreversible)
/// - PR_GET_NO_NEW_PRIVS (39): Get no_new_privs flag (returns 0 or 1)
///
/// Returns 0 on success, or the value for GET operations. arg2 is a
/// number or a user pointer, by option.
pub fn sys_prctl(option: i32, arg2: u64, arg3: u64, _arg4: u64, _arg5: u64) -> KernelResult<i64> {
    use crate::task::dumpable::{SUID_DUMP_DISABLE, SUID_DUMP_USER};
    use crate::task::percpu::{TASKLIST, current_tid};

    let tid = current_tid();
    let int_ptr = UserPtr::<i32>::new(arg2);

    match option {
        PR_SET_PDEATHSIG => {
            // The signal sent when the parent dies, 0 for none; EINVAL
            // past NSIG, the whole unsigned long (Linux valid_signal)
            let sig = crate::signal::valid_signal(arg2).ok_or(KernelError::InvalidArgument)?;

            let mut table = TASKLIST.write();
            let mut task = table.get_mut(tid).ok_or(KernelError::NoProcess)?;
            task.pdeath_signal = sig;
            Ok(0)
        }

        PR_GET_PDEATHSIG => {
            // Get current parent death signal, stored at arg2 (int *)
            let sig = {
                let table = TASKLIST.read();
                table.get(tid).ok_or(KernelError::NoProcess)?.pdeath_signal
            };
            // An int, 0 for none
            let sig: i32 = sig.map_or(0, i32::from);
            int_ptr.write(&sig)?;
            Ok(0)
        }

        PR_SET_NAME => {
            // Rename the calling thread under its task_lock (Linux
            // set_task_comm)
            let name = read_comm(arg2)?;
            super::percpu::current().task_lock().set_comm(name);
            Ok(0)
        }

        PR_GET_NAME => {
            // Get thread name and write to user buffer (16 bytes)
            let name = super::percpu::current().comm();
            crate::uaccess::copy_to_user::<crate::arch::Uaccess>(arg2, &name)?;
            Ok(0)
        }

        PR_SET_DUMPABLE => {
            // Only 0/1 are settable; SUID_DUMP_ROOT (2) is reserved to the
            // suid_dumpable sysctl (Linux kernel/sys.c PR_SET_DUMPABLE)
            if arg2 != u64::from(SUID_DUMP_DISABLE) && arg2 != u64::from(SUID_DUMP_USER) {
                return Err(KernelError::InvalidArgument);
            }
            // On the mm, shared by every thread (Linux set_dumpable)
            let mm = crate::task::percpu::current()
                .mm()
                .ok_or(KernelError::NoProcess)?;
            mm.set_dumpable(arg2 as u8);
            Ok(0)
        }

        PR_GET_DUMPABLE => {
            let mm = crate::task::percpu::current()
                .mm()
                .ok_or(KernelError::NoProcess)?;
            Ok(i64::from(mm.dumpable()))
        }

        PR_SET_NO_NEW_PRIVS => {
            // Set no_new_privs flag (irreversible once set)
            // arg2 must be 1 to enable, any other value is EINVAL
            if arg2 != 1 {
                return Err(KernelError::InvalidArgument);
            }
            let mut table = TASKLIST.write();
            let mut task = table.get_mut(tid).ok_or(KernelError::NoProcess)?;
            task.prctl.no_new_privs = true;
            Ok(0)
        }

        PR_GET_NO_NEW_PRIVS => {
            let table = TASKLIST.read();
            let task = table.get(tid).ok_or(KernelError::NoProcess)?;
            Ok(i64::from(task.prctl.no_new_privs))
        }

        PR_SET_TIMERSLACK => {
            // Set timer slack in nanoseconds
            // arg2 of 0 resets to default (50,000 ns)
            let slack = if arg2 == 0 { 50_000 } else { arg2 };
            let mut table = TASKLIST.write();
            let mut task = table.get_mut(tid).ok_or(KernelError::NoProcess)?;
            task.prctl.timer_slack_ns = slack;
            Ok(0)
        }

        PR_GET_TIMERSLACK => {
            let table = TASKLIST.read();
            let task = table.get(tid).ok_or(KernelError::NoProcess)?;
            Ok(task.prctl.timer_slack_ns as i64)
        }

        PR_GET_SECCOMP => Ok(crate::seccomp::prctl_get_seccomp()),

        // arg2 = mode, arg3 = filter (for FILTER mode)
        PR_SET_SECCOMP => crate::seccomp::prctl_set_seccomp(arg2, UserPtr::new(arg3)),

        PR_SET_KEEPCAPS => {
            // Set keep capabilities flag
            // arg2 must be 0 or 1
            if arg2 > 1 {
                return Err(KernelError::InvalidArgument);
            }
            let mut table = TASKLIST.write();
            let mut task = table.get_mut(tid).ok_or(KernelError::NoProcess)?;
            task.prctl.keep_caps = arg2 != 0;
            Ok(0)
        }

        PR_GET_KEEPCAPS => {
            let table = TASKLIST.read();
            let task = table.get(tid).ok_or(KernelError::NoProcess)?;
            Ok(i64::from(task.prctl.keep_caps))
        }

        PR_SET_CHILD_SUBREAPER => {
            // The process's flag (Linux signal->is_child_subreaper),
            // whichever thread sets it; arg2 nonzero sets it
            let sig = crate::signal::get_task_signal_struct(&crate::task::percpu::current())
                .ok_or(KernelError::NoProcess)?;
            sig.set_subreaper(&mut TASKLIST.write(), arg2 != 0);
            Ok(0)
        }

        PR_GET_CHILD_SUBREAPER => {
            // The process's flag, stored at arg2 (int *)
            let sig = crate::signal::get_task_signal_struct(&crate::task::percpu::current())
                .ok_or(KernelError::NoProcess)?;
            let is_subreaper = sig.subreaper(&TASKLIST.read());
            int_ptr.write(&i32::from(is_subreaper))?;
            Ok(0)
        }

        #[cfg(target_arch = "x86_64")]
        PR_GET_TSC => {
            // Get TSC mode (x86-64 only), stored at arg2 (int *)
            let tsc_mode = {
                let table = TASKLIST.read();
                table.get(tid).ok_or(KernelError::NoProcess)?.prctl.tsc_mode
            };
            int_ptr.write(&i32::from(tsc_mode))?;
            Ok(0)
        }

        #[cfg(target_arch = "x86_64")]
        PR_SET_TSC => {
            // Set TSC mode (x86-64 only)
            // arg2: PR_TSC_ENABLE (1) or PR_TSC_SIGSEGV (2)
            let mode = arg2 as i32;
            if mode != PR_TSC_ENABLE && mode != PR_TSC_SIGSEGV {
                return Err(KernelError::InvalidArgument);
            }
            let mut table = TASKLIST.write();
            let mut task = table.get_mut(tid).ok_or(KernelError::NoProcess)?;
            // Note: Actually enabling TSC faulting requires CR4.TSD manipulation
            // For now, just store the preference
            task.prctl.tsc_mode = mode as u8;
            Ok(0)
        }

        PR_SET_THP_DISABLE => {
            // Disable transparent huge pages for this process
            let mut table = TASKLIST.write();
            let mut task = table.get_mut(tid).ok_or(KernelError::NoProcess)?;
            task.prctl.thp_disable = arg2 != 0;
            Ok(0)
        }

        PR_GET_THP_DISABLE => {
            let table = TASKLIST.read();
            let task = table.get(tid).ok_or(KernelError::NoProcess)?;
            Ok(i64::from(task.prctl.thp_disable))
        }

        _ => Err(KernelError::InvalidArgument), // unsupported operation
    }
}

/// PR_SET_NAME's name: up to 16 bytes from `addr`, stopping at a NUL,
/// the last always NUL; EFAULT
fn read_comm(addr: u64) -> KernelResult<[u8; 16]> {
    let mut name = [0u8; 16];
    for (i, slot) in name.iter_mut().enumerate() {
        let p = UserPtr::<u8>::new(addr).offset(i);
        *slot = p.ok_or(KernelError::BadAddress)?.read()?;
        if *slot == 0 {
            break;
        }
    }
    name[15] = 0;
    Ok(name)
}

// =============================================================================
// Thread-Local Storage syscalls
// =============================================================================

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::percpu::{
    ARCH_GET_CPUID, ARCH_GET_FS, ARCH_GET_GS, ARCH_SET_CPUID, ARCH_SET_FS, ARCH_SET_GS,
    read_fs_base, write_fs_base,
};

/// sys_arch_prctl - Architecture-specific thread state (x86_64 only)
///
/// Controls architecture-specific thread state. On x86_64, this is used
/// primarily for setting the FS and GS base registers for thread-local storage.
///
/// Supported operations:
/// - ARCH_SET_FS (0x1002): Set FS base address (user TLS pointer)
/// - ARCH_GET_FS (0x1003): Get FS base address
/// - ARCH_SET_GS (0x1001): Set the user GS base
/// - ARCH_GET_GS (0x1004): Get the user GS base
/// - ARCH_GET_CPUID (0x1011): Returns 1 (CPUID enabled; no faulting support)
/// - ARCH_SET_CPUID (0x1012): -ENODEV (CPUID faulting not supported)
///
/// Returns 0 on success, negative errno on error.
#[cfg(target_arch = "x86_64")]
pub fn sys_arch_prctl(code: i32, addr: u64) -> KernelResult<i64> {
    // addr is a value for the SET codes, a u64 * for the GET ones
    let out = UserPtr::<u64>::new(addr);

    match code {
        ARCH_SET_FS => {
            // Set FS base - user TLS pointer
            if !crate::arch::user_tls_ok(addr) {
                return Err(KernelError::NotPermitted);
            }
            super::percpu::current()
                .tls
                .store(addr, core::sync::atomic::Ordering::Relaxed);
            write_fs_base(addr);
            Ok(0)
        }
        ARCH_GET_FS => {
            // Get FS base - return via user pointer
            // The live register (user code may have changed it)
            let tls = read_fs_base();

            out.write(&tls)?;
            Ok(0)
        }
        // CPUID faulting is not supported, so CPUID is always enabled.
        // Matches Linux on CPUs without X86_FEATURE_CPUID_FAULT
        // (arch/x86/kernel/process.c get_cpuid_mode/set_cpuid_mode).
        ARCH_GET_CPUID => Ok(1),
        ARCH_SET_CPUID => Err(KernelError::NoDevice),
        ARCH_SET_GS => {
            // The user GS base (the kernel's per-CPU base is swapped in
            // on entry): null selector, then the base, like Linux
            // do_arch_prctl_64
            if !crate::arch::user_tls_ok(addr) {
                return Err(KernelError::NotPermitted);
            }
            crate::arch::x86_64::percpu::load_user_gs_null();
            crate::arch::write_user_gsbase(addr);
            super::percpu::current()
                .gsbase
                .store(addr, core::sync::atomic::Ordering::Relaxed);
            Ok(0)
        }
        ARCH_GET_GS => {
            // The live user base (`mov gs` may have changed it)
            let gs = crate::arch::read_user_gsbase();
            out.write(&gs)?;
            Ok(0)
        }
        _ => Err(KernelError::InvalidArgument),
    }
}

/// sys_arch_prctl stub for non-x86_64 architectures
#[cfg(not(target_arch = "x86_64"))]
pub fn sys_arch_prctl(_code: i32, _addr: u64) -> KernelResult<i64> {
    // arch_prctl is x86_64-specific
    Err(KernelError::NotImplemented)
}

// =============================================================================
// personality syscall - Process execution domain
// =============================================================================

/// sys_personality - set process execution domain
///
/// The personality syscall controls various execution behaviors like
/// how the kernel reports certain system information. Used primarily
/// for running programs compiled for different ABIs.
///
/// # Arguments
/// * `personality` - New personality value, or 0xFFFFFFFF to query current
///
/// # Returns
/// * Previous personality value on success
///
/// # Linux ABI
/// If personality is 0xFFFFFFFF, returns current personality without changing it.
/// Otherwise, sets new personality and returns old value.
pub fn sys_personality(personality: u32) -> i64 {
    // Get current personality
    let old = super::percpu::get_current_personality();

    // If querying only, return current value
    if personality == 0xFFFFFFFF {
        return i64::from(old);
    }

    // Set new personality
    super::percpu::set_current_personality(personality);

    i64::from(old)
}

// =============================================================================
// syslog syscall - Kernel logging operations
// =============================================================================

/// Syslog action codes (from Linux include/linux/syslog.h)
pub mod syslog_action {
    /// Close the log (nop for us)
    pub const SYSLOG_ACTION_CLOSE: i32 = 0;
    /// Open the log (nop for us)
    pub const SYSLOG_ACTION_OPEN: i32 = 1;
    /// Read from the log
    pub const SYSLOG_ACTION_READ: i32 = 2;
    /// Read all messages (and mark as read)
    pub const SYSLOG_ACTION_READ_ALL: i32 = 3;
    /// Read all messages and clear ring buffer
    pub const SYSLOG_ACTION_READ_CLEAR: i32 = 4;
    /// Clear ring buffer
    pub const SYSLOG_ACTION_CLEAR: i32 = 5;
    /// Disable printk to console
    pub const SYSLOG_ACTION_CONSOLE_OFF: i32 = 6;
    /// Enable printk to console
    pub const SYSLOG_ACTION_CONSOLE_ON: i32 = 7;
    /// Set console log level
    pub const SYSLOG_ACTION_CONSOLE_LEVEL: i32 = 8;
    /// Return number of unread characters
    pub const SYSLOG_ACTION_SIZE_UNREAD: i32 = 9;
    /// Return size of the log buffer
    pub const SYSLOG_ACTION_SIZE_BUFFER: i32 = 10;
}

/// sys_syslog - read and/or clear kernel message ring buffer
///
/// Provides access to the kernel's message buffer (dmesg).
///
/// # Arguments
/// * `type_` - Operation to perform (SYSLOG_ACTION_*)
/// * `buf` - User buffer for read operations
/// * `len` - Length of buffer
///
/// # Returns
/// * >= 0 on success (depends on operation)
/// * < 0 on error
///
/// # Permissions
/// Most operations require CAP_SYSLOG or CAP_SYS_ADMIN.
pub fn sys_syslog<A: crate::uaccess::UaccessArch>(
    type_: i32,
    buf: UserPtr<u8>,
    len: i32,
) -> KernelResult<i64> {
    use syslog_action::*;

    // Basic validation
    if len < 0 {
        return Err(KernelError::InvalidArgument);
    }

    // Linux check_syslog_permissions with dmesg_restrict = 1
    // (syslog_action_restricted is then true for every action): all of
    // them need CAP_SYSLOG
    if !crate::kmsg::syslog_read_allowed() {
        return Err(KernelError::NotPermitted);
    }

    match type_ {
        SYSLOG_ACTION_CLOSE | SYSLOG_ACTION_OPEN => {
            // No-op, just return success
            Ok(0)
        }

        SYSLOG_ACTION_READ | SYSLOG_ACTION_READ_ALL | SYSLOG_ACTION_READ_CLEAR => {
            // Read from kernel log buffer
            if buf.is_null() || len == 0 {
                return Err(KernelError::InvalidArgument);
            }
            if !A::access_ok(buf.addr(), len as usize) {
                return Err(KernelError::BadAddress);
            }

            let data = match type_ {
                SYSLOG_ACTION_READ => crate::kmsg::syslog_read(len as usize)?,
                _ => crate::kmsg::syslog_read_all(len as usize, type_ == SYSLOG_ACTION_READ_CLEAR),
            };
            crate::uaccess::copy_to_user::<A>(buf.addr(), &data)?;
            Ok(data.len() as i64)
        }

        SYSLOG_ACTION_CLEAR => {
            crate::kmsg::syslog_clear();
            Ok(0)
        }

        SYSLOG_ACTION_CONSOLE_OFF => {
            // Disable console logging - no-op for now
            Ok(0)
        }

        SYSLOG_ACTION_CONSOLE_ON => {
            // Enable console logging - no-op for now
            Ok(0)
        }

        SYSLOG_ACTION_CONSOLE_LEVEL => {
            // Set console log level
            // len parameter is the log level (1-8 typically)
            if !(1..=8).contains(&len) {
                return Err(KernelError::InvalidArgument);
            }
            // No-op for now
            Ok(0)
        }

        SYSLOG_ACTION_SIZE_UNREAD => Ok(crate::kmsg::syslog_size_unread() as i64),

        SYSLOG_ACTION_SIZE_BUFFER => Ok(crate::kmsg::syslog_size_buffer() as i64),

        _ => Err(KernelError::InvalidArgument),
    }
}

// =============================================================================
// Capability syscalls (capget, capset)
// =============================================================================

use super::{
    _LINUX_CAPABILITY_U32S_3, _LINUX_CAPABILITY_VERSION_1, _LINUX_CAPABILITY_VERSION_2,
    _LINUX_CAPABILITY_VERSION_3, CapUserData, CapUserHeader, KernelCap,
};

/// Validate capability header version and return number of u32s to copy
///
/// If the version is invalid, writes the current version back to the header
/// and returns EINVAL.
fn cap_validate_magic<A: crate::uaccess::UaccessArch>(
    header: UserPtr<CapUserHeader>,
) -> KernelResult<(usize, i32)> {
    use crate::uaccess::{get_user, put_user};

    if header.is_null() {
        return Err(KernelError::BadAddress);
    }
    let hdr: CapUserHeader = get_user::<A, CapUserHeader>(header.addr())?;
    match hdr.version {
        // Legacy 32-bit version - only 1 u32 per set
        _LINUX_CAPABILITY_VERSION_1 => Ok((1, hdr.pid)),
        // 64-bit versions - 2 u32s per set
        _LINUX_CAPABILITY_VERSION_2 | _LINUX_CAPABILITY_VERSION_3 => {
            Ok((_LINUX_CAPABILITY_U32S_3, hdr.pid))
        }
        _ => {
            // Invalid version - write current version back and return EINVAL
            let current_version = CapUserHeader {
                version: _LINUX_CAPABILITY_VERSION_3,
                pid: 0,
            };
            let _ = put_user::<A, CapUserHeader>(header.addr(), current_version);
            Err(KernelError::InvalidArgument)
        }
    }
}

/// sys_capget - get capabilities of a process
///
/// Gets the capabilities of the target process. The target can be:
/// - 0: current process
/// - current pid: current process
/// - other pid: that process (requires appropriate permissions)
///
/// If dataptr is NULL and the version is valid, returns 0 (version query).
/// Otherwise, copies capability data to userspace.
pub fn sys_capget<A: crate::uaccess::UaccessArch>(
    header: UserPtr<CapUserHeader>,
    data: UserPtr<CapUserData>,
) -> KernelResult<()> {
    use crate::uaccess::put_user;

    // Validate version and get number of u32s to copy
    let (tocopy, pid) = match cap_validate_magic::<A>(header) {
        Ok(r) => r,
        // If dataptr is NULL and we got EINVAL, this is a version query
        Err(KernelError::InvalidArgument) if data.is_null() => return Ok(()),
        Err(e) => return Err(e),
    };

    // If dataptr is NULL, this is just a version query (already validated)
    if data.is_null() {
        return Ok(());
    }

    // Get current pid
    let current_pid = super::pid::vnr(super::percpu::current_pid()) as i32;

    // Determine which credentials to read
    let cred = if pid == 0 || pid == current_pid {
        // Query our own capabilities
        super::current_cred()
    } else if pid < 0 {
        return Err(KernelError::InvalidArgument);
    } else {
        // Query another process's capabilities
        // For now, only support querying current process
        // Full implementation would use find_task_by_vpid and RCU
        return Err(KernelError::NoProcess);
    };

    // Build capability data arrays
    // Linux uses 2 CapUserData structs for 64-bit capability representation
    let mut kdata = [CapUserData::default(); 2];
    kdata[0].effective = cred.cap_effective.low();
    kdata[1].effective = cred.cap_effective.high();
    kdata[0].permitted = cred.cap_permitted.low();
    kdata[1].permitted = cred.cap_permitted.high();
    kdata[0].inheritable = cred.cap_inheritable.low();
    kdata[1].inheritable = cred.cap_inheritable.high();

    // Copy to user space
    for (i, item) in kdata.iter().enumerate().take(tocopy) {
        let dst = data.offset(i).ok_or(KernelError::BadAddress)?;
        put_user::<A, CapUserData>(dst.addr(), *item)?;
    }
    Ok(())
}

/// sys_capset - set capabilities of current process
///
/// Sets the capabilities of the current process. The pid in the header
/// must be 0 or the current process's pid.
///
/// Restrictions:
/// - I (inheritable): raised bits must be subset of old permitted
/// - P (permitted): raised bits must be subset of old permitted
/// - E (effective): must be subset of new permitted
pub fn sys_capset<A: crate::uaccess::UaccessArch>(
    header: UserPtr<CapUserHeader>,
    data: UserPtr<CapUserData>,
) -> KernelResult<()> {
    use crate::uaccess::get_user;

    // Validate version and get number of u32s to copy
    let (tocopy, pid) = cap_validate_magic::<A>(header)?;

    // Get current pid
    let current_pid = super::pid::vnr(super::percpu::current_pid()) as i32;

    // May only affect current process (Linux restriction since kernel 2.6.27)
    if pid != 0 && pid != current_pid {
        return Err(KernelError::NotPermitted);
    }

    // Read capability data from user space
    let mut kdata = [CapUserData::default(); 2];
    for (i, item) in kdata.iter_mut().enumerate().take(tocopy) {
        let src = data.offset(i).ok_or(KernelError::BadAddress)?;
        *item = get_user::<A, CapUserData>(src.addr())?;
    }

    // Combine 32-bit values into 64-bit capabilities
    let effective = KernelCap::from_u32s(kdata[0].effective, kdata[1].effective);
    let permitted = KernelCap::from_u32s(kdata[0].permitted, kdata[1].permitted);
    let inheritable = KernelCap::from_u32s(kdata[0].inheritable, kdata[1].inheritable);

    // Get current credentials
    let old_cred = super::current_cred();

    // Validate capability changes (Linux security rules from kernel/capability.c):
    //
    // 1. New inheritable must not add any capabilities not in old permitted
    //    (can only inherit what we're permitted to use)
    // 2. New permitted must not add any capabilities not in old permitted
    //    (can't gain capabilities we don't already have)
    // 3. New effective must be subset of new permitted
    //    (can't use capabilities we're not permitted to use)
    if !inheritable.is_subset(&old_cred.cap_permitted)
        || !permitted.is_subset(&old_cred.cap_permitted)
        || !effective.is_subset(&permitted)
    {
        return Err(KernelError::NotPermitted);
    }

    // Create new credentials with updated capabilities
    let mut new_cred = old_cred;
    new_cred.cap_effective = effective;
    new_cred.cap_permitted = permitted;
    new_cred.cap_inheritable = inheritable;
    // Note: bset and ambient are not modified by capset
    super::commit_creds(try_arc(new_cred)?);
    Ok(())
}

// ============================================================================
// pidfd syscalls
// ============================================================================

/// sys_pidfd_open - obtain a file descriptor for a process
///
/// # Arguments
/// * `pid` - Process ID to obtain pidfd for
/// * `flags` - PIDFD_NONBLOCK, PIDFD_THREAD (any thread, Linux 6.9)
///
/// # Returns
/// * A file descriptor on success, always close-on-exec (Linux
///   pidfd_prepare's get_unused_fd_flags(O_CLOEXEC))
/// * -EINVAL: Invalid flags or pid
/// * -ESRCH: No such process
/// * -ENOENT: `pid` is a thread that does not lead its process, and no
///   PIDFD_THREAD
pub fn sys_pidfd_open(pid: i64, flags: u32) -> KernelResult<i32> {
    use crate::task::pidfd::pidfd_flags::{PIDFD_NONBLOCK, PIDFD_THREAD};
    if flags & !(PIDFD_NONBLOCK | PIDFD_THREAD) != 0 || pid <= 0 {
        return Err(KernelError::InvalidArgument);
    }
    let pidfd_file = crate::task::pidfd::open_pidfd(pid as Pid, flags)?;
    crate::fs::io::fd_install(pidfd_file, super::FD_CLOEXEC)
}

/// sys_pidfd_send_signal - send a signal to a process via a pidfd
///
/// # Arguments
/// * `pidfd` - File descriptor referring to the target process
/// * `sig` - Signal number to send
/// * `info` - Optional siginfo_t to send (else kill's, or tkill's to
///   a thread)
/// * `flags` - At most one scope: PIDFD_SIGNAL_THREAD, _THREAD_GROUP,
///   _PROCESS_GROUP (the group whose id is the pidfd's pid); none: the
///   pidfd's own (its thread for a PIDFD_THREAD pidfd, else its process)
///
/// # Returns
/// * 0 on success
/// * -EBADF: Invalid file descriptor
/// * -EINVAL: Invalid signal number or flags
/// * -ESRCH: Process no longer exists
pub fn sys_pidfd_send_signal(
    pidfd: i32,
    sig: i32,
    info: UserPtr<crate::signal::SigInfo>,
    flags: u32,
) -> KernelResult<()> {
    const SCOPES: u32 =
        PIDFD_SIGNAL_THREAD | PIDFD_SIGNAL_THREAD_GROUP | PIDFD_SIGNAL_PROCESS_GROUP;
    if flags & !SCOPES != 0 || flags.count_ones() > 1 {
        return Err(KernelError::InvalidArgument);
    }
    let file = crate::fs::io::fget(pidfd)?;
    let pidfd = crate::task::pidfd::get_pidfd(&file).ok_or(KernelError::BadFd)?;
    // The scope (Linux do_pidfd_send_signal's pid_type)
    let scope = match flags {
        PIDFD_SIGNAL_THREAD => Scope::Thread,
        PIDFD_SIGNAL_THREAD_GROUP => Scope::Process,
        PIDFD_SIGNAL_PROCESS_GROUP => Scope::Pgrp,
        _ if pidfd.thread() => Scope::Thread,
        _ => Scope::Process,
    };
    let info = pidfd_info(info, sig, pidfd.pid(), scope)?;
    // Permission check and send to the pidfd's struct pid itself (Linux
    // kill_pid_info_type, kill_pgrp_info), so a released task's reused
    // number never gets it. Signal 0 (None) is a permission/existence
    // probe; a bad number (a negative one too) is EINVAL from the check,
    // once the receiver is found, so it is never sent.
    let ksig = crate::signal::syscall::kill_sig(u32::try_from(sig).unwrap_or(u32::MAX));
    let me = crate::signal::syscall::Sender::current();
    let check = |t: &super::percpu::TaskView<'_>| me.may_kill(t, ksig);
    let (sig, pid) = (ksig.unwrap_or(None), pidfd.pid_ref());
    match scope {
        Scope::Thread => {
            crate::signal::kill_pid_info_type(pid, sig, info, crate::signal::PidType::Pid, check)
        }
        Scope::Process => {
            crate::signal::kill_pid_info_type(pid, sig, info, crate::signal::PidType::Tgid, check)
        }
        Scope::Pgrp => crate::signal::kill_pgrp_info(pid, sig, info, check),
    }
}

/// pidfd_send_signal's scope flags (include/uapi/linux/pidfd.h)
const PIDFD_SIGNAL_THREAD: u32 = 1 << 0;
const PIDFD_SIGNAL_THREAD_GROUP: u32 = 1 << 1;
const PIDFD_SIGNAL_PROCESS_GROUP: u32 = 1 << 2;

/// Whom pidfd_send_signal signals (Linux PIDTYPE_PID, _TGID, _PGID)
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    Thread,
    Process,
    Pgrp,
}

/// The info pidfd_send_signal sends to `pid`'s `scope` (Linux
/// do_pidfd_send_signal): without `uinfo`, kill's (tkill's, SI_TKILL,
/// to a thread: prepare_kill_siginfo); else that siginfo, which must be
/// for `sig`, the number as given (EINVAL), with a code reserved to the
/// kernel only to the caller's own thread or process (EPERM)
fn pidfd_info(
    uinfo: UserPtr<crate::signal::SigInfo>,
    sig: i32,
    pid: u64,
    scope: Scope,
) -> KernelResult<crate::signal::SendInfo> {
    use crate::signal::{SendInfo, SigInfo, si_code};
    if uinfo.is_null() {
        // Kill's info, none to make for a probe (0), which sends nothing
        let sig = Signal::from_int(sig);
        let Some(sig) = sig.filter(|_| scope == Scope::Thread) else {
            return Ok(SendInfo::User);
        };
        let me = super::pid::vnr(super::percpu::current_pid()) as i32;
        let uid = crate::task::current_cred().uid;
        return Ok(SendInfo::Info(SigInfo::kill(
            sig,
            si_code::SI_TKILL,
            me,
            uid,
        )));
    }
    let info = SigInfo::copy_from_user(uinfo.addr())?;
    if info.signo != sig {
        return Err(KernelError::InvalidArgument);
    }
    let me = super::percpu::current_tid();
    if (me != pid || scope == Scope::Pgrp) && crate::signal::syscall::reserved_to_kernel(info.code)
    {
        return Err(KernelError::NotPermitted);
    }
    Ok(SendInfo::Info(info))
}

/// sys_pidfd_getfd - obtain a duplicate of another process's file descriptor
///
/// This syscall duplicates a file descriptor from another process identified
/// by a pidfd. The new fd is allocated in the caller's fd table with O_CLOEXEC set.
///
/// # Arguments
/// * `pidfd` - File descriptor referring to the target process (from pidfd_open)
/// * `targetfd` - File descriptor number in the target process to duplicate
/// * `flags` - Flags (must be 0, reserved for future use)
///
/// # Returns
/// * >= 0: New file descriptor on success
/// * -EBADF: pidfd is not a valid fd or not a pidfd, or targetfd is invalid in target
/// * -ESRCH: Target process doesn't exist or has exited
/// * -EPERM: Permission denied (caller cannot access target's fds)
/// * -EINVAL: flags is non-zero
/// * -EMFILE: Too many open files in caller's process
///
/// # Permission Model
/// Simplified PTRACE_MODE_ATTACH: allow if caller has CAP_SYS_PTRACE or same euid.
pub fn sys_pidfd_getfd(pidfd: i32, targetfd: i32, flags: u32) -> KernelResult<i32> {
    // Validate flags (must be 0)
    if flags != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let pidfd_file = crate::fs::io::fget(pidfd)?;
    let target_file = pidfd_fget(&pidfd_file, targetfd)?;
    // A new fd in the caller's table with FD_CLOEXEC, exec_update
    // dropped (Linux pidfd_getfd: receive_fd after __pidfd_fget)
    crate::fs::io::fd_install(target_file, super::FD_CLOEXEC)
}

/// File `targetfd` of the process `pidfd_file` refers to (Linux
/// __pidfd_fget): looked up under that process's exec_update read lock,
/// with PTRACE_MODE_ATTACH_REALCREDS access
fn pidfd_fget(pidfd_file: &File, targetfd: i32) -> KernelResult<alloc::sync::Arc<File>> {
    // The pidfd's process itself, while it is still there
    let target = crate::task::pidfd::pidfd_task(pidfd_file)?;

    let _exec = crate::signal::ExecUpdateRead::lock(&target);
    if !super::ptrace::may_access_task(&target, false) {
        return Err(KernelError::NotPermitted);
    }

    // Get target's fd table (none: process exiting)
    let target_fd_table = super::fdtable::get_task_fd(&target).ok_or(KernelError::NoProcess)?;
    // Its process still being that task; else its files are gone
    // (Linux fget_task: EBADF)
    let same = crate::task::pidfd::pidfd_task(pidfd_file)
        .is_ok_and(|t| alloc::sync::Arc::ptr_eq(&t, &target));
    if !same {
        return Err(KernelError::BadFd);
    }
    target_fd_table
        .lock()
        .get(targetfd)
        .ok_or(KernelError::BadFd)
}

// =============================================================================
// I/O port permissions (x86-64 only)
// =============================================================================

/// iopl - Set I/O privilege level (x86-64 only)
///
/// Changes the I/O privilege level of the calling thread. The IOPL determines
/// which I/O ports the thread can access.
///
/// # Arguments
/// * `level` - The new IOPL level (0-3). Level 3 grants access to all I/O ports.
///
/// # Returns
/// * 0 on success
/// * -EINVAL if level > 3
/// * -EPERM if trying to raise privilege without CAP_SYS_RAWIO
///
/// # Security
/// Lowering the privilege level is always allowed. Raising it requires
/// CAP_SYS_RAWIO capability.
///
/// # Note
/// This is an emulated IOPL - it doesn't modify the CPU's actual IOPL register.
/// The kernel stores the level per-task and uses it for permission checks.
#[cfg(target_arch = "x86_64")]
pub fn sys_iopl(level: u32) -> KernelResult<()> {
    use crate::task::{CAP_SYS_RAWIO, capable};

    // Validate level (must be 0-3)
    if level > 3 {
        return Err(KernelError::InvalidArgument);
    }

    // Get current IOPL level
    let old = super::percpu::current_iopl_emul();

    // No change? Done.
    if level == u32::from(old) {
        return Ok(());
    }

    // Lowering privilege is always allowed
    if level < u32::from(old) {
        super::percpu::set_current_iopl_emul(level as u8);
        return Ok(());
    }

    // Raising privilege requires CAP_SYS_RAWIO
    if !capable(CAP_SYS_RAWIO) {
        return Err(KernelError::NotPermitted);
    }

    // Set new level
    super::percpu::set_current_iopl_emul(level as u8);
    Ok(())
}

/// ioperm - Set port input/output permissions (x86-64 only, stub)
///
/// This syscall allows fine-grained control over individual I/O ports (0-0x3ff).
///
/// # Arguments
/// * `from` - Starting port number
/// * `num` - Number of ports
/// * `turn_on` - 1 to enable access, 0 to disable
///
/// # Returns
/// * -ENOSYS - Not implemented (requires TSS I/O bitmap infrastructure)
///
/// # Note
/// Full ioperm implementation requires per-task I/O permission bitmaps in the TSS.
/// This is not yet implemented. Use iopl(3) for full I/O port access.
#[cfg(target_arch = "x86_64")]
pub fn sys_ioperm(_from: u64, _num: u64, _turn_on: i32) -> KernelResult<()> {
    Err(KernelError::NotImplemented)
}
