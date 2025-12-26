//! membarrier system call implementation
//!
//! The membarrier() system call helps distribute memory barriers across
//! multiple CPUs for userspace-RCU (read-copy-update) algorithms. It provides
//! ordering guarantees across multiple threads without requiring expensive
//! explicit memory barriers in critical fast paths.
//!
//! Linux reference: kernel/sched/membarrier.c

use core::sync::atomic::{Ordering, fence};

// =============================================================================
// membarrier commands (Linux ABI)
// =============================================================================

/// Query supported commands
pub const MEMBARRIER_CMD_QUERY: i32 = 0;
/// Execute a memory barrier on all running threads
pub const MEMBARRIER_CMD_GLOBAL: i32 = 1 << 0;
/// Execute memory barrier on registered threads (expedited)
pub const MEMBARRIER_CMD_GLOBAL_EXPEDITED: i32 = 1 << 1;
/// Register for expedited global barriers
pub const MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED: i32 = 1 << 2;
/// Execute memory barrier on caller's process threads (expedited)
pub const MEMBARRIER_CMD_PRIVATE_EXPEDITED: i32 = 1 << 3;
/// Register for expedited private barriers
pub const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED: i32 = 1 << 4;
/// Execute memory barrier with core serialization
pub const MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE: i32 = 1 << 5;
/// Register for expedited sync core barriers
pub const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: i32 = 1 << 6;
/// Execute memory barrier for rseq critical sections
pub const MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ: i32 = 1 << 7;
/// Register for expedited rseq barriers
pub const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ: i32 = 1 << 8;
/// Query current registrations
pub const MEMBARRIER_CMD_GET_REGISTRATIONS: i32 = 1 << 9;

/// Flag to target specific CPU
pub const MEMBARRIER_CMD_FLAG_CPU: u32 = 1 << 0;

// =============================================================================
// Supported commands bitmask
// =============================================================================

/// Commands we support in this implementation
///
/// We support:
/// - QUERY: Return supported commands
/// - GLOBAL: Full memory barrier (via fence)
/// - PRIVATE_EXPEDITED: Process-local barrier
/// - REGISTER_PRIVATE_EXPEDITED: Registration (no-op, always allowed)
/// - GET_REGISTRATIONS: Query registrations
const SUPPORTED_CMDS: i32 = MEMBARRIER_CMD_GLOBAL
    | MEMBARRIER_CMD_PRIVATE_EXPEDITED
    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
    | MEMBARRIER_CMD_GET_REGISTRATIONS;

// =============================================================================
// Per-process registration state
// =============================================================================

// For a full implementation, we'd track per-process registration state.
// For now, we always allow expedited commands (simpler, slightly less efficient).

// =============================================================================
// membarrier syscall
// =============================================================================

/// membarrier(cmd, flags, cpu_id) - memory barrier across threads
///
/// This system call helps synchronize memory access ordering between threads.
/// It's primarily used by userspace-RCU implementations.
///
/// # Arguments
/// * `cmd` - Command to execute (MEMBARRIER_CMD_*)
/// * `flags` - Flags (e.g., MEMBARRIER_CMD_FLAG_CPU)
/// * `cpu_id` - Target CPU (only used with FLAG_CPU)
///
/// # Returns
/// * For QUERY: bitmask of supported commands
/// * For other commands: 0 on success, negative errno on error
///
/// # Errors
/// * -EINVAL: Invalid command or flags
/// * -EPERM: Command requires prior registration
pub fn sys_membarrier(cmd: i32, flags: u32, _cpu_id: i32) -> i64 {
    // Validate flags based on command
    match cmd {
        MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ => {
            // RSEQ allows FLAG_CPU
            if flags != 0 && flags != MEMBARRIER_CMD_FLAG_CPU {
                return -22; // EINVAL
            }
        }
        _ => {
            // Other commands don't accept flags
            if flags != 0 {
                return -22; // EINVAL
            }
        }
    }

    match cmd {
        MEMBARRIER_CMD_QUERY => {
            // Return supported commands
            SUPPORTED_CMDS as i64
        }

        MEMBARRIER_CMD_GLOBAL => {
            // Full memory barrier across all CPUs
            // In a single-CPU implementation, a fence is sufficient.
            // For SMP, we'd need to IPI all CPUs.
            fence(Ordering::SeqCst);
            0
        }

        MEMBARRIER_CMD_GLOBAL_EXPEDITED => {
            // Expedited global barrier - requires registration, which we don't track
            // Return -EPERM since no one has registered
            -1 // EPERM
        }

        MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED => {
            // Register for global expedited barriers
            // We don't track this, but return success
            -22 // EINVAL - not supported
        }

        MEMBARRIER_CMD_PRIVATE_EXPEDITED => {
            // Memory barrier for threads in same process
            // For single-threaded or our simplified model, just fence
            fence(Ordering::SeqCst);
            0
        }

        MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED => {
            // Register for private expedited barriers
            // Always succeeds (we don't require registration)
            0
        }

        MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE => {
            // Sync core serialization - not implemented
            -22 // EINVAL
        }

        MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE => {
            // Not implemented
            -22 // EINVAL
        }

        MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ => {
            // RSEQ barriers - not implemented
            -22 // EINVAL
        }

        MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ => {
            // Not implemented
            -22 // EINVAL
        }

        MEMBARRIER_CMD_GET_REGISTRATIONS => {
            // Return currently registered commands
            // We always allow PRIVATE_EXPEDITED
            MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED as i64
        }

        _ => -22, // EINVAL
    }
}
