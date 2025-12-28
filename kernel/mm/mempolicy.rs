//! NUMA Memory Policy Syscalls
//!
//! Implements get_mempolicy, set_mempolicy, mbind, migrate_pages, and move_pages.
//! Uses the NUMA topology discovered from ACPI SRAT (x86-64) or device tree (aarch64).

use crate::arch::Uaccess;
use crate::error::KernelError;
use crate::numa::NUMA_TOPOLOGY;
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
// Per-task NUMA memory policy
// ============================================================================

/// Per-task NUMA memory policy
///
/// Stores the memory policy set via set_mempolicy() for this task.
/// Inherited by child tasks on fork.
#[derive(Clone, Copy, Debug)]
pub struct TaskMempolicy {
    /// Policy mode (MPOL_DEFAULT, MPOL_BIND, etc.)
    pub mode: i32,
    /// Bitmask of allowed NUMA nodes
    pub nodemask: u64,
    /// Mode flags (MPOL_F_STATIC_NODES, etc.)
    pub flags: u32,
    /// Preferred node for MPOL_PREFERRED (-1 = none)
    pub preferred_node: i32,
}

impl Default for TaskMempolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskMempolicy {
    /// Create a new default memory policy (MPOL_DEFAULT)
    pub const fn new() -> Self {
        Self {
            mode: MPOL_DEFAULT,
            nodemask: 0,
            flags: 0,
            preferred_node: -1,
        }
    }

    /// Create a LOCAL policy (allocate on current CPU's node)
    pub const fn local() -> Self {
        Self {
            mode: MPOL_LOCAL,
            nodemask: 0,
            flags: 0,
            preferred_node: -1,
        }
    }

    /// Check if this is the default policy
    pub fn is_default(&self) -> bool {
        self.mode == MPOL_DEFAULT || self.mode == MPOL_LOCAL
    }
}

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
    }

    // Return policy if requested
    if policy_ptr != 0 {
        if !Uaccess::access_ok(policy_ptr, core::mem::size_of::<i32>()) {
            return KernelError::BadAddress.sysret();
        }

        // Default policy is MPOL_LOCAL (allocate on local node)
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

        // Get the online node mask from real topology
        let online_mask = NUMA_TOPOLOGY.lock().online_mask();

        unsafe {
            Uaccess::user_access_begin();

            // Write first word with online nodes mask
            core::ptr::write(nmask_ptr as *mut u64, online_mask);

            // Clear remaining words if any (we only support up to 64 nodes)
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
/// Validates nodemask against real online NUMA nodes.
/// Policy storage in task struct is handled in Phase 3.
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

    // Read node mask from user space
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

    // Empty mask is invalid for most policies
    if nodemask == 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate that all specified nodes are online
    let online_mask = NUMA_TOPOLOGY.lock().online_mask();
    if nodemask & !online_mask != 0 {
        // Requested nodes that don't exist
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

    // Policy validated - actual storage in task struct is Phase 3
    // For now, accept valid policies (they have no effect until Phase 4)

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
/// Validates nodemask against real online NUMA nodes.
/// VMA policy storage is handled in Phase 3.
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

        // Validate that all specified nodes are online
        let online_mask = NUMA_TOPOLOGY.lock().online_mask();
        if nodemask & !online_mask != 0 {
            return KernelError::InvalidArgument.sysret();
        }
    }

    // MPOL_MF_MOVE_ALL requires CAP_SYS_NICE
    if flags & MPOL_MF_MOVE_ALL != 0 && !crate::task::capable(crate::task::CAP_SYS_NICE) {
        return KernelError::NotPermitted.sysret();
    }

    // Policy validated - VMA policy storage is Phase 3
    // Page migration is Phase 5

    0
}

/// sys_migrate_pages - Migrate process pages between NUMA nodes
///
/// # Arguments
/// * `pid` - Target process ID (0 = current process)
/// * `maxnode` - Maximum node number in masks + 1
/// * `old_nodes_ptr` - User pointer to old nodes bitmask
/// * `new_nodes_ptr` - User pointer to new nodes bitmask
///
/// # Returns
/// Number of pages that could not be moved, or negative errno
///
/// Validates node masks against real online NUMA nodes.
/// Actual page migration is implemented in Phase 5.
///
/// # Permission Requirements
/// - Operating on own process: always allowed
/// - Operating on other processes: requires CAP_SYS_NICE or appropriate ptrace access
pub fn sys_migrate_pages(pid: i64, maxnode: u64, old_nodes_ptr: u64, new_nodes_ptr: u64) -> i64 {
    // Validate maxnode - must be at least 1 to have any nodes
    if maxnode == 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Permission check for operating on other processes
    let current_pid = crate::task::percpu::current_pid();
    if pid != 0 && pid != current_pid as i64 {
        // Operating on another process requires CAP_SYS_NICE
        if !crate::task::capable(crate::task::CAP_SYS_NICE) {
            return KernelError::NotPermitted.sysret();
        }
        // Check if target process exists
        if !crate::task::percpu::task_exists(pid as u64) {
            return KernelError::NoProcess.sysret();
        }
    }

    let mask_bytes = maxnode.div_ceil(64) * 8;
    let online_mask = NUMA_TOPOLOGY.lock().online_mask();

    // Validate and read old_nodes if provided
    if old_nodes_ptr != 0 {
        if !Uaccess::access_ok(old_nodes_ptr, mask_bytes as usize) {
            return KernelError::BadAddress.sysret();
        }
        let old_mask: u64 = unsafe {
            Uaccess::user_access_begin();
            let mask = core::ptr::read(old_nodes_ptr as *const u64);
            Uaccess::user_access_end();
            mask
        };
        // Validate old_nodes are online
        if old_mask != 0 && old_mask & !online_mask != 0 {
            return KernelError::InvalidArgument.sysret();
        }
    }

    // Validate and read new_nodes if provided
    if new_nodes_ptr != 0 {
        if !Uaccess::access_ok(new_nodes_ptr, mask_bytes as usize) {
            return KernelError::BadAddress.sysret();
        }
        let new_mask: u64 = unsafe {
            Uaccess::user_access_begin();
            let mask = core::ptr::read(new_nodes_ptr as *const u64);
            Uaccess::user_access_end();
            mask
        };
        // Validate new_nodes are online
        if new_mask != 0 && new_mask & !online_mask != 0 {
            return KernelError::InvalidArgument.sysret();
        }
    }

    // Node masks validated - actual page migration is Phase 5
    // For now, return 0 (no pages failed to migrate)
    0
}

/// sys_move_pages - Move individual pages to specific NUMA nodes
///
/// # Arguments
/// * `pid` - Target process ID (0 = current process)
/// * `nr_pages` - Number of pages to move
/// * `pages_ptr` - User pointer to array of page addresses
/// * `nodes_ptr` - User pointer to array of target node IDs (or NULL for status query)
/// * `status_ptr` - User pointer to array for status results
/// * `flags` - MPOL_MF_MOVE or MPOL_MF_MOVE_ALL
///
/// # Returns
/// 0 on success, negative errno on error
///
/// Validates nodes against real online NUMA nodes.
/// Actual page migration is implemented in Phase 5.
///
/// # Permission Requirements
/// - MPOL_MF_MOVE_ALL requires CAP_SYS_NICE
/// - Operating on other processes requires CAP_SYS_NICE or ptrace access
pub fn sys_move_pages(
    pid: i64,
    nr_pages: u64,
    pages_ptr: u64,
    nodes_ptr: u64,
    status_ptr: u64,
    flags: i32,
) -> i64 {
    // Validate flags
    let valid_flags = MPOL_MF_MOVE | MPOL_MF_MOVE_ALL;
    if (flags as u32) & !valid_flags != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Zero pages is a no-op
    if nr_pages == 0 {
        return 0;
    }

    // Permission check for MPOL_MF_MOVE_ALL
    if (flags as u32) & MPOL_MF_MOVE_ALL != 0 && !crate::task::capable(crate::task::CAP_SYS_NICE) {
        return KernelError::NotPermitted.sysret();
    }

    // Permission check for operating on other processes
    let current_pid = crate::task::percpu::current_pid();
    if pid != 0 && pid != current_pid as i64 {
        if !crate::task::capable(crate::task::CAP_SYS_NICE) {
            return KernelError::NotPermitted.sysret();
        }
        if !crate::task::percpu::task_exists(pid as u64) {
            return KernelError::NoProcess.sysret();
        }
    }

    // Validate pages array pointer
    let pages_size = nr_pages as usize * core::mem::size_of::<u64>();
    if pages_ptr == 0 || !Uaccess::access_ok(pages_ptr, pages_size) {
        return KernelError::BadAddress.sysret();
    }

    // Validate status array pointer (required)
    let status_size = nr_pages as usize * core::mem::size_of::<i32>();
    if status_ptr == 0 || !Uaccess::access_ok(status_ptr, status_size) {
        return KernelError::BadAddress.sysret();
    }

    // Validate nodes array pointer if provided
    if nodes_ptr != 0 {
        let nodes_size = nr_pages as usize * core::mem::size_of::<i32>();
        if !Uaccess::access_ok(nodes_ptr, nodes_size) {
            return KernelError::BadAddress.sysret();
        }
    }

    // Get online nodes mask
    let online_mask = NUMA_TOPOLOGY.lock().online_mask();

    // Write status for each page
    unsafe {
        Uaccess::user_access_begin();

        for i in 0..nr_pages as usize {
            let status: i32 = if nodes_ptr == 0 {
                // Query mode: return current node (node 0 for now)
                // Real implementation in Phase 5 will look up actual page node
                0
            } else {
                // Move mode: check if target node is online
                let node = core::ptr::read((nodes_ptr as *const i32).add(i));
                if node == -1 {
                    // "don't move": success
                    0
                } else if node >= 0 && (online_mask & (1u64 << node)) != 0 {
                    // Node is online: success (actual migration in Phase 5)
                    0
                } else {
                    // Node doesn't exist: -ENODEV
                    -19 // ENODEV
                }
            };
            core::ptr::write((status_ptr as *mut i32).add(i), status);
        }

        Uaccess::user_access_end();
    }

    0
}
