//! Seccomp (secure computing) subsystem
//!
//! Seccomp provides a mechanism to restrict the system calls a process can make.
//! This is used for sandboxing applications.
//!
//! ## Modes
//!
//! - **STRICT**: Only read, write, exit, and sigreturn are allowed
//! - **FILTER**: User-provided BPF program decides per-syscall
//!
//! ## Usage
//!
//! ```text
//! // Enable STRICT mode via prctl
//! prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
//!
//! // Or enable FILTER mode via seccomp syscall
//! seccomp(SECCOMP_SET_MODE_FILTER, 0, &filter_prog);
//! ```

pub mod check;
mod filter;
mod syscall;

pub use check::check_syscall;
pub use filter::SeccompFilter;
pub use syscall::{prctl_get_seccomp, prctl_set_seccomp, sys_seccomp};

// =============================================================================
// Seccomp Modes (matches Linux uapi/linux/seccomp.h)
// =============================================================================

/// Seccomp is disabled
pub const SECCOMP_MODE_DISABLED: u8 = 0;
/// Strict mode: only read/write/exit/sigreturn allowed
pub const SECCOMP_MODE_STRICT: u8 = 1;
/// Filter mode: BPF program decides
pub const SECCOMP_MODE_FILTER: u8 = 2;

// =============================================================================
// Seccomp Operations (for seccomp syscall)
// =============================================================================

/// Set STRICT mode
pub const SECCOMP_SET_MODE_STRICT: u32 = 0;
/// Set FILTER mode with BPF program
pub const SECCOMP_SET_MODE_FILTER: u32 = 1;
/// Query if an action is available
pub const SECCOMP_GET_ACTION_AVAIL: u32 = 2;
/// Get notification sizes
pub const SECCOMP_GET_NOTIF_SIZES: u32 = 3;

// =============================================================================
// Seccomp Filter Flags
// =============================================================================

/// Sync new filter across all threads
pub const SECCOMP_FILTER_FLAG_TSYNC: u32 = 1 << 0;
/// Log all non-ALLOW actions
pub const SECCOMP_FILTER_FLAG_LOG: u32 = 1 << 1;
/// Disable SSB (Speculative Store Bypass) mitigation
pub const SECCOMP_FILTER_FLAG_SPEC_ALLOW: u32 = 1 << 2;
/// Create a notification fd
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: u32 = 1 << 3;
/// TSYNC returns error count
pub const SECCOMP_FILTER_FLAG_TSYNC_ESRCH: u32 = 1 << 4;
/// Wait in killable state for notifications
pub const SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: u32 = 1 << 5;

// =============================================================================
// Seccomp Return Actions
//
// The upper 16 bits are the action, lower 16 bits are data.
// Actions are ordered from most to least restrictive.
// =============================================================================

/// Kill the entire process immediately
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
/// Kill the thread (same as KILL for single-threaded)
pub const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
/// Alias for KILL_THREAD
pub const SECCOMP_RET_KILL: u32 = SECCOMP_RET_KILL_THREAD;
/// Disallow and send SIGSYS
pub const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
/// Return an errno value (in data field)
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
/// Notify userspace supervisor (fd-based)
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
/// Pass to ptrace tracer or disallow
pub const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
/// Allow after logging
pub const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
/// Allow the syscall
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

/// Mask for action field (upper 16 bits, but bit 15 is sign)
pub const SECCOMP_RET_ACTION_FULL: u32 = 0xffff_0000;
/// Mask for action field (unsigned comparison)
pub const SECCOMP_RET_ACTION: u32 = 0x7fff_0000;
/// Mask for data field (lower 16 bits)
pub const SECCOMP_RET_DATA: u32 = 0x0000_ffff;

// =============================================================================
// seccomp_data - The context passed to BPF filters
// =============================================================================

/// Data passed to seccomp BPF filters
///
/// This struct is passed as the context to the BPF program.
/// It contains information about the syscall being attempted.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SeccompData {
    /// Syscall number
    pub nr: i32,
    /// Architecture (AUDIT_ARCH_*)
    pub arch: u32,
    /// Instruction pointer at time of syscall
    pub instruction_pointer: u64,
    /// Syscall arguments (always 64-bit, regardless of arch)
    pub args: [u64; 6],
}

impl SeccompData {
    /// Size of the seccomp_data struct in bytes
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

// =============================================================================
// Architecture identifiers (AUDIT_ARCH_*)
// =============================================================================

/// x86_64 architecture
pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
/// aarch64 architecture
pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

/// Get the AUDIT_ARCH value for the current architecture
#[inline]
pub fn current_audit_arch() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        AUDIT_ARCH_X86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        AUDIT_ARCH_AARCH64
    }
}

// =============================================================================
// Maximum errno value that can be returned via SECCOMP_RET_ERRNO
// =============================================================================

/// Maximum errno value (Linux uses 4095)
pub const MAX_ERRNO: u32 = 4095;

// =============================================================================
// Task Exit Cleanup
// =============================================================================

use crate::task::Tid;
use crate::task::percpu::TASK_TABLE;

/// Clean up seccomp state when a task exits
///
/// This releases the seccomp filter reference early (rather than waiting
/// for the Task to be reaped). This follows the pattern used by other
/// subsystems like namespaces and signal handling.
pub fn exit_seccomp(tid: Tid) {
    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.seccomp_mode = SECCOMP_MODE_DISABLED;
        task.seccomp_filter = None;
    }
}
