//! Process accounting implementation
//!
//! Provides BSD-style process accounting via the acct() syscall.
//! When enabled, writes accounting records to a file when processes exit.
//!
//! ## Usage
//!
//! ```text
//! acct("/var/account/acct")  // Enable accounting, write to file
//! acct(NULL)                  // Disable accounting
//! ```
//!
//! ## Record Format
//!
//! Uses Linux acct_v3 format (64 bytes per record).
//! Records are written when processes exit (group leader exits).
//!
//! Accounting is per pid namespace (Linux pid_namespace->bacct): acct(2)
//! sets the caller's namespace's file, and an exiting process writes
//! its record to the file of its namespace and of each one above it,
//! numbered as that namespace sees it.

use crate::util::kalloc::try_arc;
use alloc::sync::Arc;

use crate::fs::KernelError;
use crate::fs::file::File;
use crate::ns::PidNamespace;
use crate::sync::spin::Mutex;
use crate::task::CAP_SYS_PACCT;
use crate::task::Tid;
use crate::uaccess::UserPtr;
use crate::util::error::KernelResult;
use crate::util::pod::IntoBytes;

// =============================================================================
// Accounting Flags
// =============================================================================

/// Process forked but didn't exec
pub const AFORK: u8 = 0x01;
/// Used superuser privileges
pub const ASU: u8 = 0x02;
/// Compatibility mode (unused)
pub const ACOMPAT: u8 = 0x04;
/// Dumped core
pub const ACORE: u8 = 0x08;
/// Killed by a signal
pub const AXSIG: u8 = 0x10;

/// Accounting version
pub const ACCT_VERSION: u8 = 3;

// =============================================================================
// Accounting Record Structure (Linux ABI - acct_v3)
// =============================================================================

/// Linux acct_v3 structure (64 bytes, every field naturally aligned)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AcctV3 {
    /// Flags: AFORK, ASU, ACORE, AXSIG
    pub ac_flag: u8,
    /// Always ACCT_VERSION (3)
    pub ac_version: u8,
    /// Controlling terminal (dev_t)
    pub ac_tty: u16,
    /// Exit code
    pub ac_exitcode: u32,
    /// Real user ID
    pub ac_uid: u32,
    /// Real group ID
    pub ac_gid: u32,
    /// Process ID
    pub ac_pid: u32,
    /// Parent process ID
    pub ac_ppid: u32,
    /// Process creation time (Unix timestamp)
    pub ac_btime: u32,
    /// Elapsed time (IEEE float encoding)
    pub ac_etime: u32,
    /// User CPU time (comp_t)
    pub ac_utime: u16,
    /// System CPU time (comp_t)
    pub ac_stime: u16,
    /// Average memory usage (comp_t)
    pub ac_mem: u16,
    /// Characters transferred (comp_t)
    pub ac_io: u16,
    /// Blocks read/written (comp_t)
    pub ac_rw: u16,
    /// Minor page faults (comp_t)
    pub ac_minflt: u16,
    /// Major page faults (comp_t)
    pub ac_majflt: u16,
    /// Number of swaps (comp_t)
    pub ac_swaps: u16,
    /// Command name (16 bytes, no null terminator in v3)
    pub ac_comm: [u8; 16],
}

/// Size of acct_v3 record
pub const ACCT_V3_SIZE: usize = core::mem::size_of::<AcctV3>();

// Compile-time check that AcctV3 is 64 bytes
const _: () = assert!(ACCT_V3_SIZE == 64);

crate::pod!(AcctV3 {
    ac_flag,
    ac_version,
    ac_tty,
    ac_exitcode,
    ac_uid,
    ac_gid,
    ac_pid,
    ac_ppid,
    ac_btime,
    ac_etime,
    ac_utime,
    ac_stime,
    ac_mem,
    ac_io,
    ac_rw,
    ac_minflt,
    ac_majflt,
    ac_swaps,
    ac_comm,
});

// =============================================================================
// comp_t Encoding
// =============================================================================

/// AHZ: the accounting clock (Linux acct v3: USER_HZ)
const AHZ: u64 = 100;

/// Nanoseconds as AHZ ticks (Linux nsec_to_AHZ)
fn nsec_to_ahz(ns: u64) -> u64 {
    ns / (1_000_000_000 / AHZ)
}

/// comp_t: 13-bit mantissa, 3-bit base-8 exponent, rounded on the last
/// bit shifted out; past its range 0xffff (Linux encode_comp_t)
pub fn encode_comp_t(mut value: u64) -> u16 {
    const MANTSIZE: u32 = 13;
    const EXPSIZE: u32 = 3;
    const MAXFRACT: u64 = (1 << MANTSIZE) - 1;
    let (mut exp, mut rnd) = (0u32, 0u64);
    while value > MAXFRACT {
        rnd = value & (1 << (EXPSIZE - 1));
        value >>= EXPSIZE;
        exp += 1;
    }
    if rnd != 0 {
        value += 1;
        if value > MAXFRACT {
            value >>= EXPSIZE;
            exp += 1;
        }
    }
    if exp > u32::from(u16::MAX >> MANTSIZE) {
        return u16::MAX;
    }
    (u64::from(exp << MANTSIZE) + value) as u16
}

/// An IEEE single of `value` with its mantissa truncated, as Linux
/// encode_float (acct v3 ac_etime)
fn encode_float(mut value: u64) -> u32 {
    if value == 0 {
        return 0;
    }
    let mut exp = 190u32;
    while (value as i64) > 0 {
        value <<= 1;
        exp -= 1;
    }
    ((value >> 40) as u32 & 0x7f_ffff) | (exp << 23)
}

// =============================================================================
// Accounting State
// =============================================================================

/// A pid namespace's accounting file (Linux pid_namespace->bacct,
/// acct->file). A leaf spin lock, thread context only: users clone the
/// file out and write with no lock held (the write sleeps), and a
/// replaced file is released after unlocking.
pub struct Acct(Mutex<Option<Arc<File>>>);

impl Default for Acct {
    fn default() -> Self {
        Self(Mutex::new(None))
    }
}

impl Acct {
    /// The file, if accounting is on
    fn get(&self) -> Option<Arc<File>> {
        self.0.lock().clone()
    }

    /// Install `file`, returning the old one
    fn replace(&self, file: Option<Arc<File>>) -> Option<Arc<File>> {
        core::mem::replace(&mut *self.0.lock(), file)
    }
}

/// Install `file` as the caller's namespace's (None: accounting off).
/// The old file gets a record for the calling process before it is
/// released, with no lock held (Linux acct_pin_kill ->
/// do_acct_process(current))
fn set_acct_file(file: Option<Arc<File>>) {
    let ns = crate::task::pid::current_pid_ns();
    if let Some(old) = ns.bacct.replace(file) {
        close(&old, ns);
    }
}

/// The record of the calling process into `old`, which is then
/// released (Linux acct_pin_kill)
fn close(old: &File, ns: &PidNamespace) {
    let tid = crate::task::percpu::current_tid();
    if let Some(info) = get_task_info(tid) {
        write_record(old, ns, tid, &info, 0);
    }
}

/// Namespace `ns` is ending (its init is past the zap): its accounting
/// stops with a record of the caller, its init (Linux acct_exit_ns)
pub fn exit_ns(ns: &PidNamespace) {
    if let Some(old) = ns.bacct.replace(None) {
        close(&old, ns);
    }
}

// =============================================================================
// Syscall Implementation
// =============================================================================

/// sys_acct(filename) - enable/disable process accounting
///
/// If filename is non-null: enable accounting, writing records to that file.
/// If filename is null: disable accounting.
///
pub fn sys_acct(filename: UserPtr<u8>) -> KernelResult<()> {
    // Check CAP_SYS_PACCT capability
    if !crate::task::capable(CAP_SYS_PACCT) {
        return Err(KernelError::NotPermitted);
    }

    // A NULL filename disables accounting
    if filename.is_null() {
        set_acct_file(None);
        return Ok(());
    }

    // Copy filename from user, open the file for appending
    let filename = crate::fs::namei::getname(filename.addr(), false)?;
    set_acct_file(Some(open_acct_file(&filename)?));
    Ok(())
}

/// Open the accounting file
fn open_acct_file(path: &[u8]) -> KernelResult<Arc<File>> {
    use crate::fs::file::flags;
    use crate::fs::{LookupFlags, dac};

    // Any lookup error as is (Linux filp_open)
    let (mnt, dentry) = crate::fs::namei::path_lookupat(
        crate::task::percpu::current_cwd(),
        path,
        LookupFlags::open(),
    )?
    .into_parts();

    // file_open_name(O_WRONLY | O_APPEND): may_open, then a regular file
    if let Some(inode) = dentry.get_inode() {
        let wflags = flags::O_WRONLY | flags::O_APPEND;
        dac::may_open(&dac::cred(), &inode, dac::acc_mode(wflags), wflags)?;
        if !inode.mode().is_file() {
            return Err(KernelError::PermissionDenied); // not a regular file
        }
    }

    // Open for writing: hold write access (EROFS on a read-only fs)
    let w = match dentry.get_inode() {
        Some(_) => Some(mnt.want_write()?),
        None => None,
    };
    // The filesystem's file operations, as an open(2) of it gets
    // (NULL_FILE_OPS made every record write fail)
    let f_op: &'static dyn crate::fs::FileOps = dentry
        .superblock()
        .map(|sb| sb.fs_type.file_ops)
        .unwrap_or(&crate::fs::ramfs::RAMFS_FILE_OPS);
    let mut file = File::new(dentry, Some(mnt), flags::O_WRONLY | flags::O_APPEND, f_op);
    file.write_access = w;
    try_arc(file)
}

// =============================================================================
// Process Exit Hook
// =============================================================================

/// Write accounting record for an exiting process
///
/// Called by a process's last exiting thread before it releases its
/// mm and files (Linux acct_process from do_exit): into the accounting
/// file of its pid namespace and of each one above it.
/// It's best-effort - failures are silently ignored to not block the exit path.
pub fn write_acct_record(tid: Tid, exit_status: i32) {
    let mut info = None;
    let mut ns = Some(crate::task::pid::current_pid_ns());
    while let Some(n) = ns {
        // Accounting on there? (the file is used with no lock held)
        if let Some(file) = n.bacct.get() {
            if info.is_none() {
                info = get_task_info(tid);
            }
            if let Some(i) = &info {
                write_record(&file, n, tid, i, exit_status);
            }
        }
        ns = n.parent.as_deref();
    }
}

/// Write the record of the process of thread `tid` to `file`, the
/// accounting file of `ns`, which numbers it (Linux fill_ac: ac_pid
/// and ac_ppid by task_tgid_nr_ns with acct->ns)
fn write_record(file: &File, ns: &PidNamespace, tid: Tid, task_info: &TaskInfo, exit_status: i32) {
    // Compute flags
    let mut ac_flag: u8 = 0;

    // Linux acct_collect: forked and not exec'd (PF_FORKNOEXEC), used a
    // capability (PF_SUPERPRIV)
    if task_info.forknoexec {
        ac_flag |= AFORK;
    }
    if task_info.superpriv {
        ac_flag |= ASU;
    }

    // Check exit reason
    if exit_status & 0x80 != 0 {
        // Core dumped (WCOREDUMP)
        ac_flag |= ACORE;
    }
    if exit_status & 0x7f != 0 {
        // Killed by signal (WIFSIGNALED)
        ac_flag |= AXSIG;
    }

    // Build accounting record
    let record = AcctV3 {
        ac_flag,
        ac_version: ACCT_VERSION,
        ac_tty: task_info.tty,
        ac_exitcode: exit_status as u32,
        ac_uid: task_info.uid,
        ac_gid: task_info.gid,
        ac_pid: task_info.tgid.as_ref().map_or(0, |p| p.nr_ns(ns)),
        ac_ppid: task_info.parent.as_ref().map_or(0, |p| p.nr_ns(ns)),
        ac_btime: task_info.start_time,
        ac_etime: encode_float(nsec_to_ahz(task_info.elapsed_ns)),
        ac_utime: encode_comp_t(nsec_to_ahz(task_info.utime_ns)),
        ac_stime: encode_comp_t(nsec_to_ahz(task_info.stime_ns)),
        ac_mem: 0, // TODO: Track memory usage
        ac_io: 0,  // TODO: Track I/O
        ac_rw: 0,  // TODO: Track block I/O
        ac_minflt: encode_comp_t(task_info.minflt),
        ac_majflt: encode_comp_t(task_info.majflt),
        ac_swaps: 0, // Swaps not tracked
        ac_comm: task_info.comm,
    };

    // Write to file (best-effort, ignore errors)
    // The record is not subject to the process's RLIMIT_FSIZE (no
    // SIGXFSZ, no lost record): unlimited across the write (Linux
    // do_acct_process)
    use crate::task::rlimit::{RLIM_INFINITY, RLIMIT_FSIZE};
    let sig = crate::signal::get_task_signal_struct(tid);
    let old = sig
        .as_ref()
        .map(|s| s.swap_rlimit_cur(RLIMIT_FSIZE, RLIM_INFINITY));
    let _ = write_record_to_file(file, &record);
    if let (Some(s), Some(o)) = (&sig, old) {
        s.swap_rlimit_cur(RLIMIT_FSIZE, o);
    }
}

/// Task information gathered for accounting
struct TaskInfo {
    uid: u32,
    gid: u32,
    /// Its process's and its parent's pids (Linux task_tgid of current
    /// and of real_parent), numbered per file
    tgid: Option<Arc<crate::task::pid::Pid>>,
    parent: Option<Arc<crate::task::pid::Pid>>,
    tty: u16,
    start_time: u32,
    elapsed_ns: u64,
    utime_ns: u64,
    stime_ns: u64,
    minflt: u64,
    majflt: u64,
    comm: [u8; 16],
    /// Forked and not exec'd (PF_FORKNOEXEC)
    forknoexec: bool,
    /// Used a capability (PF_SUPERPRIV)
    superpriv: bool,
}

/// Get task information for accounting
fn get_task_info(tid: Tid) -> Option<TaskInfo> {
    use crate::task::percpu::TASKLIST;

    let table = TASKLIST.read();
    let task = table.get(tid)?;

    // Its name (NUL-terminated, Linux get_task_comm)
    let comm = task.task.task_lock().comm();

    // Get credentials - Arc<Cred> can be dereferenced directly
    let cred = &task.cred();
    let (uid, gid) = (cred.uid, cred.gid);

    // Calculate elapsed time using task.start_time (monotonic ns since boot)
    let now_ns = crate::time::monotonic_ns();
    let elapsed_ns = now_ns.saturating_sub(task.task.start_time());

    // Get start time as Unix timestamp (seconds since epoch)
    // Convert from monotonic start_time to wall clock using TIMEKEEPER
    use crate::time::{ClockId, TIMEKEEPER};
    let realtime_ts = TIMEKEEPER.read(ClockId::Realtime, TIMEKEEPER.get_read_cycles());
    let mono_ts = TIMEKEEPER.read(ClockId::Monotonic, TIMEKEEPER.get_read_cycles());
    let realtime_ns = realtime_ts.to_nanos() as u64;
    let mono_ns = mono_ts.to_nanos() as u64;
    // Calculate the realtime offset and apply it to start_time
    let realtime_start_ns = if realtime_ns >= mono_ns {
        task.task.start_time().saturating_add(realtime_ns - mono_ns)
    } else {
        task.task.start_time().saturating_sub(mono_ns - realtime_ns)
    };
    let start_time = (realtime_start_ns / 1_000_000_000) as u32;

    // Taken under TASKLIST, released after it (3.1.1 rule 4)
    let pid_of = |p| table.get(p).and_then(|t| t.thread_pid.clone());
    Some(TaskInfo {
        uid,
        gid,
        tgid: pid_of(task.task.pid),
        parent: pid_of(task.task.ppid()),
        tty: 0, // TODO: Get controlling terminal
        start_time,
        elapsed_ns,
        utime_ns: task.task.utime.load(core::sync::atomic::Ordering::Relaxed),
        stime_ns: task.task.stime.load(core::sync::atomic::Ordering::Relaxed),
        minflt: task
            .task
            .min_flt
            .load(core::sync::atomic::Ordering::Relaxed),
        majflt: task
            .task
            .maj_flt
            .load(core::sync::atomic::Ordering::Relaxed),
        comm,
        forknoexec: task.task.has_flag(crate::task::pf::FORKNOEXEC),
        superpriv: task.task.has_flag(crate::task::pf::SUPERPRIV),
    })
}

/// Write an accounting record to the file
fn write_record_to_file(file: &File, record: &AcctV3) -> Result<(), KernelError> {
    // Get the bytes
    let bytes = record.as_bytes();

    // Through the file's write path (Linux __kernel_write): O_APPEND
    // places it at the end, the inode lock and size are kept
    file.write(bytes)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comp_t() {
        assert_eq!(encode_comp_t(0), 0);
        assert_eq!(encode_comp_t(8191), 8191);
        assert_eq!(encode_comp_t(8192), 0x2000 | 1024);
        // The last bit shifted out rounds up
        assert_eq!(encode_comp_t(8196), 0x2000 | 1025);
        // Rounding past the mantissa moves to the next exponent
        assert_eq!(encode_comp_t(65532), 0x4000 | 1024);
        assert_eq!(encode_comp_t(u64::MAX), 0xffff);
    }

    #[test]
    fn float_bits() {
        assert_eq!(encode_float(0), 0);
        assert_eq!(encode_float(1), 1.0f32.to_bits());
        assert_eq!(encode_float(100), 100.0f32.to_bits());
        // Truncated, not rounded: 2^24 + 1 keeps 2^24
        assert_eq!(encode_float((1 << 24) + 1), 16_777_216.0f32.to_bits());
        assert_eq!(nsec_to_ahz(2_500_000_000), 250);
    }
}
