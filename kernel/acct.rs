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

use alloc::string::String;
use alloc::sync::Arc;

use crate::arch::IrqSpinlock;
use crate::fs::KernelError;
use crate::fs::file::File;
use crate::task::CAP_SYS_PACCT;
use crate::task::Pid;
use crate::task::Tid;

// =============================================================================
// Accounting Flags
// =============================================================================

/// Process forked but didn't exec
pub const AFORK: u8 = 0x01;
/// Used superuser privileges
pub const ASU: u8 = 0x02;
/// Compatibility mode (unused)
#[allow(dead_code)]
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

/// Linux acct_v3 structure (64 bytes)
#[repr(C, packed)]
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

impl AcctV3 {
    /// Get the record as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const AcctV3 as *const u8, ACCT_V3_SIZE) }
    }
}

// =============================================================================
// comp_t Encoding
// =============================================================================

/// Encode a value into comp_t format
///
/// comp_t is a 16-bit floating point with:
/// - 3-bit base-8 exponent (bits 13-15)
/// - 13-bit mantissa (bits 0-12)
///
/// Value = mantissa * 8^exponent
pub fn encode_comp_t(value: u64) -> u16 {
    if value == 0 {
        return 0;
    }

    let mut exp: u32 = 0;
    let mut mantissa = value;

    // Scale down until mantissa fits in 13 bits (0x1FFF = 8191)
    while mantissa > 0x1FFF && exp < 7 {
        mantissa >>= 3; // Divide by 8
        exp += 1;
    }

    // Clamp mantissa to 13 bits if still too large
    if mantissa > 0x1FFF {
        mantissa = 0x1FFF;
    }

    ((exp as u16) << 13) | (mantissa as u16)
}

/// Encode elapsed time as IEEE float
///
/// Linux uses a simple float representation for elapsed time in acct_v3.
/// This encodes nanoseconds as seconds in float format.
fn encode_elapsed_float(elapsed_ns: u64) -> u32 {
    // Convert nanoseconds to seconds as f32
    let seconds = elapsed_ns as f64 / 1_000_000_000.0;

    // Convert to IEEE 754 single precision float bits
    (seconds as f32).to_bits()
}

// =============================================================================
// Accounting State
// =============================================================================

/// Accounting state
struct AcctState {
    /// File to write accounting records to
    file: Arc<File>,
    /// Path to accounting file (for reference)
    #[allow(dead_code)]
    path: String,
}

/// Global accounting state
static ACCT_STATE: IrqSpinlock<Option<AcctState>> = IrqSpinlock::new(None);

// =============================================================================
// Syscall Implementation
// =============================================================================

/// sys_acct(filename) - enable/disable process accounting
///
/// If filename is non-null: enable accounting, writing records to that file.
/// If filename is null: disable accounting.
///
/// Returns 0 on success, negative errno on error.
pub fn sys_acct(filename_ptr: u64) -> i64 {
    // Check CAP_SYS_PACCT capability
    if !crate::task::capable(CAP_SYS_PACCT) {
        return -1; // EPERM
    }

    // If filename_ptr == 0, disable accounting
    if filename_ptr == 0 {
        let mut state = ACCT_STATE.lock();
        *state = None;
        return 0;
    }

    // Copy filename from user
    let filename =
        match crate::uaccess::strncpy_from_user::<crate::arch::Uaccess>(filename_ptr, 4096) {
            Ok(f) => f,
            Err(_) => return -14, // EFAULT
        };

    // Open the file for appending
    let file = match open_acct_file(&filename) {
        Ok(f) => f,
        Err(e) => return e,
    };

    // Enable accounting
    let mut state = ACCT_STATE.lock();
    *state = Some(AcctState {
        file,
        path: filename,
    });

    0
}

/// Open the accounting file
fn open_acct_file(path: &str) -> Result<Arc<File>, i64> {
    use crate::fs::file::flags;
    use crate::fs::{LookupFlags, lookup_path_at};

    // Lookup the file
    let dentry = match lookup_path_at(None, path, LookupFlags::open()) {
        Ok(d) => d,
        Err(e) => {
            return Err(match e {
                KernelError::NotFound => -2,          // ENOENT
                KernelError::NotDirectory => -20,     // ENOTDIR
                KernelError::PermissionDenied => -13, // EACCES
                _ => -22,                             // EINVAL
            });
        }
    };

    // Check it's a regular file
    if let Some(inode) = dentry.get_inode()
        && !inode.mode().is_file()
    {
        return Err(-13); // EACCES - not a regular file
    }

    // Create file for writing (append mode)
    let file = Arc::new(File::new(
        dentry,
        flags::O_WRONLY | flags::O_APPEND,
        &crate::fs::file::NULL_FILE_OPS,
    ));

    Ok(file)
}

// =============================================================================
// Process Exit Hook
// =============================================================================

/// Write accounting record for an exiting process
///
/// This should be called from mark_zombie() when a process exits.
/// It's best-effort - failures are silently ignored to not block the exit path.
pub fn write_acct_record(tid: Tid, pid: Pid, exit_status: i32) {
    // Check if accounting is enabled
    let state = ACCT_STATE.lock();
    let state = match state.as_ref() {
        Some(s) => s,
        None => return, // Accounting not enabled
    };

    // Get task information
    let task_info = match get_task_info(tid, pid) {
        Some(info) => info,
        None => return, // Task not found
    };

    // Compute flags
    let mut ac_flag: u8 = 0;

    // Check if forked but didn't exec
    if task_info.did_fork && !task_info.did_exec {
        ac_flag |= AFORK;
    }

    // Check if used superuser privileges
    if task_info.uid == 0 || task_info.euid == 0 {
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
        ac_pid: pid as u32,
        ac_ppid: task_info.ppid as u32,
        ac_btime: task_info.start_time,
        ac_etime: encode_elapsed_float(task_info.elapsed_ns),
        ac_utime: encode_comp_t(task_info.utime_ns / 10_000_000), // Convert to centiseconds
        ac_stime: encode_comp_t(task_info.stime_ns / 10_000_000), // Convert to centiseconds
        ac_mem: 0,                                                // TODO: Track memory usage
        ac_io: 0,                                                 // TODO: Track I/O
        ac_rw: 0,                                                 // TODO: Track block I/O
        ac_minflt: encode_comp_t(task_info.minflt),
        ac_majflt: encode_comp_t(task_info.majflt),
        ac_swaps: 0, // Swaps not tracked
        ac_comm: task_info.comm,
    };

    // Write to file (best-effort, ignore errors)
    let _ = write_record_to_file(&state.file, &record);
}

/// Task information gathered for accounting
struct TaskInfo {
    uid: u32,
    euid: u32,
    gid: u32,
    ppid: Pid,
    tty: u16,
    start_time: u32,
    elapsed_ns: u64,
    utime_ns: u64,
    stime_ns: u64,
    minflt: u64,
    majflt: u64,
    comm: [u8; 16],
    did_fork: bool,
    did_exec: bool,
}

/// Get task information for accounting
fn get_task_info(tid: Tid, pid: Pid) -> Option<TaskInfo> {
    use crate::task::percpu::TASK_TABLE;

    let table = TASK_TABLE.lock();
    let task = table.tasks.iter().find(|t| t.tid == tid)?;

    // Get command name from prctl state
    let mut comm = [0u8; 16];
    // Copy the task name, which is stored as bytes in prctl.name
    let name_bytes = &task.prctl.name;
    // Find the null terminator or use full length
    let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(16);
    comm[..name_len].copy_from_slice(&name_bytes[..name_len]);

    // Get credentials - Arc<Cred> can be dereferenced directly
    let cred = &*task.cred;
    let (uid, euid, gid) = (cred.uid, cred.euid, cred.gid);

    // Calculate elapsed time - use monotonic clock
    // Note: Task struct doesn't track start_time_ns, so we use current time as approximation
    use crate::time::{ClockId, TIMEKEEPER};
    let now_ts = TIMEKEEPER.read(ClockId::Monotonic, TIMEKEEPER.get_read_cycles());
    let now_ns = now_ts.to_nanos() as u64;
    // Since we don't track start time, elapsed is approximated as 0
    let elapsed_ns = 0u64;

    // Get start time as Unix timestamp (seconds since epoch)
    // Use current time as approximation since Task doesn't store start time
    let start_time = (now_ns / 1_000_000_000) as u32;

    Some(TaskInfo {
        uid,
        euid,
        gid,
        ppid: task.ppid,
        tty: 0, // TODO: Get controlling terminal
        start_time,
        elapsed_ns,
        utime_ns: 0, // TODO: Track user CPU time
        stime_ns: 0, // TODO: Track system CPU time
        minflt: 0,   // TODO: Track minor page faults
        majflt: 0,   // TODO: Track major page faults
        comm,
        did_fork: pid != tid as Pid, // Simple heuristic: different PID/TID means forked
        did_exec: task.prctl.name[0] != 0, // Has a name means exec'd
    })
}

/// Write an accounting record to the file
fn write_record_to_file(file: &File, record: &AcctV3) -> Result<(), KernelError> {
    // Get the bytes
    let bytes = record.as_bytes();

    // Write to file
    file.f_op.write(file, bytes)?;

    Ok(())
}

// =============================================================================
// Public API for integration
// =============================================================================

/// Check if accounting is enabled
#[allow(dead_code)]
pub fn is_enabled() -> bool {
    ACCT_STATE.lock().is_some()
}
