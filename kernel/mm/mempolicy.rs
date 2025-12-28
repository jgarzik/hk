//! NUMA Memory Policy Syscalls
//!
//! Implements get_mempolicy, set_mempolicy, and mbind syscalls.
//! This is a stub implementation for single-node systems that provides
//! API compatibility without actual NUMA functionality.

use crate::arch::Uaccess;
use crate::error::KernelError;
use crate::uaccess::UaccessArch;

// ============================================================================
// Policy modes (MPOL_*)
// ============================================================================

/// Default policy: allocate on local node
pub const MPOL_DEFAULT: i32 = 0;
/// Prefer a specific node, fallback to others
pub const MPOL_PREFERRED: i32 = 1;
/// Restrict allocation to specific nodes only
pub const MPOL_BIND: i32 = 2;
/// Round-robin allocation across nodes
pub const MPOL_INTERLEAVE: i32 = 3;
/// Allocate on local CPU's node
pub const MPOL_LOCAL: i32 = 4;
/// Prefer a set of nodes (newer variant)
pub const MPOL_PREFERRED_MANY: i32 = 5;
/// Maximum policy value (for validation)
pub const MPOL_MAX: i32 = 6;

// ============================================================================
// Mode flags (combined with policy mode)
// ============================================================================

/// Use static node set (don't remap on cpuset changes)
pub const MPOL_F_STATIC_NODES: u64 = 1 << 15;
/// Use relative node set
pub const MPOL_F_RELATIVE_NODES: u64 = 1 << 14;
/// Enable NUMA balancing optimization
pub const MPOL_F_NUMA_BALANCING: u64 = 1 << 13;

/// Mask for mode flags
pub const MPOL_MODE_FLAGS: u64 =
    MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES | MPOL_F_NUMA_BALANCING;

// ============================================================================
// get_mempolicy flags
// ============================================================================

/// Return next interleave node, not mask
pub const MPOL_F_NODE: u64 = 1 << 0;
/// Look up VMA policy at addr
pub const MPOL_F_ADDR: u64 = 1 << 1;
/// Return allowed memories
pub const MPOL_F_MEMS_ALLOWED: u64 = 1 << 2;

// ============================================================================
// mbind flags (MPOL_MF_*)
// ============================================================================

/// Verify existing pages conform to policy
pub const MPOL_MF_STRICT: u32 = 1 << 0;
/// Move pages to conform to policy
pub const MPOL_MF_MOVE: u32 = 1 << 1;
/// Move all pages (requires CAP_SYS_NICE)
pub const MPOL_MF_MOVE_ALL: u32 = 1 << 2;
/// Unsupported: lazy migration on fault
#[allow(dead_code)]
pub const MPOL_MF_LAZY: u32 = 1 << 3;

/// Valid mbind flags mask
pub const MPOL_MF_VALID: u32 = MPOL_MF_STRICT | MPOL_MF_MOVE | MPOL_MF_MOVE_ALL;

// ============================================================================
// Syscall implementations
// ============================================================================

/// sys_get_mempolicy - Get memory policy for process or VMA
///
/// # Arguments
/// * `policy_ptr` - Output pointer for policy mode (can be NULL)
/// * `nmask_ptr` - Output pointer for node mask (can be NULL)
/// * `maxnode` - Size of node mask in bits
/// * `addr` - Address for MPOL_F_ADDR lookup (ignored otherwise)
/// * `flags` - MPOL_F_NODE, MPOL_F_ADDR, MPOL_F_MEMS_ALLOWED
///
/// # Returns
/// 0 on success, negative errno on error
///
/// # Single-node behavior
/// Always returns MPOL_DEFAULT/MPOL_LOCAL and node mask with bit 0 set.
pub fn sys_get_mempolicy(
    policy_ptr: u64,
    nmask_ptr: u64,
    maxnode: u64,
    _addr: u64,
    flags: u64,
) -> i64 {
    // Validate flags
    let valid_flags = MPOL_F_NODE | MPOL_F_ADDR | MPOL_F_MEMS_ALLOWED;
    if flags & !valid_flags != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // MPOL_F_NODE and MPOL_F_ADDR are mutually exclusive when no policy is set
    if flags & MPOL_F_NODE != 0 && flags & MPOL_F_ADDR != 0 {
        // This combination is allowed but has special semantics
        // For single-node, just return node 0
    }

    // Return policy if requested
    if policy_ptr != 0 {
        if !Uaccess::access_ok(policy_ptr, core::mem::size_of::<i32>()) {
            return KernelError::BadAddress.sysret();
        }

        // For single-node system, default policy is MPOL_LOCAL (allocate on local node)
        let policy = if flags & MPOL_F_MEMS_ALLOWED != 0 {
            // Special case: return 0 for MEMS_ALLOWED query
            0i32
        } else {
            MPOL_LOCAL
        };

        unsafe {
            Uaccess::user_access_begin();
            core::ptr::write(policy_ptr as *mut i32, policy);
            Uaccess::user_access_end();
        }
    }

    // Return node mask if requested
    if nmask_ptr != 0 && maxnode > 0 {
        // Calculate mask size in bytes (rounded up to unsigned long boundary)
        let mask_bytes = maxnode.div_ceil(64) * 8;

        if !Uaccess::access_ok(nmask_ptr, mask_bytes as usize) {
            return KernelError::BadAddress.sysret();
        }

        // For single-node system, only node 0 is available
        // Set bit 0, clear all other bits
        unsafe {
            Uaccess::user_access_begin();

            // Write first word with bit 0 set
            core::ptr::write(nmask_ptr as *mut u64, 1u64);

            // Clear remaining words if any
            for i in 1..(mask_bytes / 8) {
                core::ptr::write((nmask_ptr as *mut u64).add(i as usize), 0u64);
            }

            Uaccess::user_access_end();
        }
    }

    0
}

/// sys_set_mempolicy - Set memory policy for process
///
/// # Arguments
/// * `mode` - Policy mode (MPOL_DEFAULT, MPOL_BIND, etc.) with optional flags
/// * `nmask_ptr` - User pointer to node mask
/// * `maxnode` - Size of node mask in bits
///
/// # Returns
/// 0 on success, negative errno on error
///
/// # Single-node behavior
/// Accepts any valid policy for node 0, silently ignores actual policy
/// (since there's only one node, policy has no effect).
pub fn sys_set_mempolicy(mode: i32, nmask_ptr: u64, maxnode: u64) -> i64 {
    // Extract mode and flags
    let policy_mode = mode & 0x7fff; // Lower 15 bits are mode
    let mode_flags = (mode as u64) & MPOL_MODE_FLAGS;

    // Validate policy mode
    if !(0..MPOL_MAX).contains(&policy_mode) {
        return KernelError::InvalidArgument.sysret();
    }

    // MPOL_DEFAULT doesn't use nodemask
    if policy_mode == MPOL_DEFAULT {
        // Ignore any mode flags for DEFAULT
        return 0;
    }

    // MPOL_LOCAL doesn't use nodemask
    if policy_mode == MPOL_LOCAL {
        return 0;
    }

    // Other policies require a node mask
    if nmask_ptr == 0 || maxnode == 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Read and validate node mask (only node 0 is valid)
    let mask_bytes = maxnode.min(64).div_ceil(64) * 8;
    if !Uaccess::access_ok(nmask_ptr, mask_bytes as usize) {
        return KernelError::BadAddress.sysret();
    }

    let nodemask: u64 = unsafe {
        Uaccess::user_access_begin();
        let mask = core::ptr::read(nmask_ptr as *const u64);
        Uaccess::user_access_end();
        mask
    };

    // For single-node system, only bit 0 (node 0) should be set
    // We accept any mask that includes node 0 for compatibility
    if nodemask == 0 {
        // Empty mask is invalid for most policies
        return KernelError::InvalidArgument.sysret();
    }

    // Validate mode flags combinations
    if mode_flags & MPOL_F_STATIC_NODES != 0 && mode_flags & MPOL_F_RELATIVE_NODES != 0 {
        // Mutually exclusive flags
        return KernelError::InvalidArgument.sysret();
    }

    // For MPOL_PREFERRED, only one node should be set
    if policy_mode == MPOL_PREFERRED && nodemask.count_ones() > 1 {
        return KernelError::InvalidArgument.sysret();
    }

    // Accept the policy (no actual effect on single-node system)
    // In a real multi-node implementation, we would store the policy
    // in the task structure and use it during page allocation.

    0
}

/// sys_mbind - Set memory policy for a memory range
///
/// # Arguments
/// * `start` - Start address of range (must be page-aligned)
/// * `len` - Length of range (will be rounded up to page boundary)
/// * `mode` - Policy mode with optional flags
/// * `nmask_ptr` - User pointer to node mask
/// * `maxnode` - Size of node mask in bits
/// * `flags` - MPOL_MF_STRICT, MPOL_MF_MOVE, MPOL_MF_MOVE_ALL
///
/// # Returns
/// 0 on success, negative errno on error
///
/// # Single-node behavior
/// Validates arguments and returns success. No page migration occurs
/// since all pages are already on node 0.
pub fn sys_mbind(start: u64, len: u64, mode: u64, nmask_ptr: u64, maxnode: u64, flags: u32) -> i64 {
    use super::PAGE_SIZE;

    // Validate flags
    if flags & !MPOL_MF_VALID != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate address alignment
    if start & (PAGE_SIZE - 1) != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Zero length is a no-op
    if len == 0 {
        return 0;
    }

    // Extract policy mode (lower bits)
    let policy_mode = (mode & 0x7fff) as i32;

    // Validate policy mode
    if !(0..MPOL_MAX).contains(&policy_mode) {
        return KernelError::InvalidArgument.sysret();
    }

    // MPOL_DEFAULT doesn't use nodemask
    if policy_mode != MPOL_DEFAULT && policy_mode != MPOL_LOCAL {
        if nmask_ptr == 0 || maxnode == 0 {
            return KernelError::InvalidArgument.sysret();
        }

        // Validate node mask access
        let mask_bytes = maxnode.min(64).div_ceil(64) * 8;
        if !Uaccess::access_ok(nmask_ptr, mask_bytes as usize) {
            return KernelError::BadAddress.sysret();
        }

        // Read node mask
        let nodemask: u64 = unsafe {
            Uaccess::user_access_begin();
            let mask = core::ptr::read(nmask_ptr as *const u64);
            Uaccess::user_access_end();
            mask
        };

        // Empty mask is invalid
        if nodemask == 0 {
            return KernelError::InvalidArgument.sysret();
        }
    }

    // MPOL_MF_MOVE_ALL requires CAP_SYS_NICE
    if flags & MPOL_MF_MOVE_ALL != 0 && !crate::task::capable(crate::task::CAP_SYS_NICE) {
        return KernelError::NotPermitted.sysret();
    }

    // On single-node system:
    // - MPOL_MF_STRICT: All pages are already on node 0, always passes
    // - MPOL_MF_MOVE: No migration needed, all pages on node 0
    // - MPOL_MF_MOVE_ALL: No migration needed
    //
    // In a real multi-node implementation, we would:
    // 1. Find all VMAs in the range
    // 2. Set the VMA policy
    // 3. Optionally migrate existing pages

    0
}
