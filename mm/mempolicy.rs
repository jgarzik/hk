//! NUMA Memory Policy Syscalls
//!
//! Implements get_mempolicy, set_mempolicy, mbind, migrate_pages, and move_pages.
//! Uses the NUMA topology discovered from ACPI SRAT (x86-64) or device tree (aarch64).

use crate::arch::Uaccess;
use crate::mm::numa::NUMA_TOPOLOGY;
use crate::uaccess::{UaccessArch, copy_to_user, get_user, put_user};
use crate::util::error::KernelError;

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

        if put_user::<Uaccess, i32>(policy_ptr, policy).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    // Return node mask if requested
    if nmask_ptr != 0 && maxnode > 0 {
        // The copy is sized by the user: bound it (no huge allocation)
        if maxnode > MAX_MASK_BITS + 1 {
            return KernelError::InvalidArgument.sysret();
        }
        // Calculate mask size in bytes (rounded up to unsigned long boundary)
        let mask_bytes = maxnode.div_ceil(64) * 8;

        if !Uaccess::access_ok(nmask_ptr, mask_bytes as usize) {
            return KernelError::BadAddress.sysret();
        }

        // Get the online node mask from real topology
        let online_mask = NUMA_TOPOLOGY.lock().online_mask();

        // First word holds the online nodes; remaining words are zero
        // (we only support up to 64 nodes)
        let mut words = alloc::vec![0u64; (mask_bytes / 8) as usize];
        words[0] = online_mask;
        let bytes: alloc::vec::Vec<u8> = words.iter().flat_map(|w| w.to_ne_bytes()).collect();
        if copy_to_user::<Uaccess>(nmask_ptr, &bytes).is_err() {
            return KernelError::BadAddress.sysret();
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
/// Validates nodemask against real online NUMA nodes; the policy is
/// not stored yet (BUGS.md).
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

    let nodemask: u64 = match get_user::<Uaccess, u64>(nmask_ptr) {
        Ok(m) => m,
        Err(_) => return KernelError::BadAddress.sysret(),
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

    // Valid, but not stored and not used by the allocator (BUGS.md)
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
/// Validates nodemask against real online NUMA nodes; the policy is
/// not stored yet (BUGS.md).
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
        let nodemask: u64 = match get_user::<Uaccess, u64>(nmask_ptr) {
            Ok(m) => m,
            Err(_) => return KernelError::BadAddress.sysret(),
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

    // Valid, but not stored and nothing is migrated (BUGS.md)
    0
}

/// The process migrate_pages and move_pages act on (Linux
/// kernel_migrate_pages, find_mm_struct): the caller for pid 0; else
/// ESRCH if there is none, EPERM unless the caller may inspect it
/// (ptrace_may_access, PTRACE_MODE_READ_REALCREDS), EINVAL without an
/// address space; decided under its exec_update_lock, so an exec cannot
/// swap the mm or dumpability meanwhile
fn mm_target(pid: i64) -> Result<(), KernelError> {
    if pid == 0 {
        return Ok(());
    }
    let tid = crate::task::percpu::find_task_by_vpid(pid as u64)
        .map(|t| t.tid())
        .ok_or(KernelError::NoProcess)?;
    let _g = crate::signal::ExecUpdateRead::lock(tid);
    if !crate::task::ptrace::may_access_tid(tid, false) {
        return Err(KernelError::NotPermitted);
    }
    crate::mm::get_task_mm(tid)
        .map(|_| ())
        .ok_or(KernelError::InvalidArgument)
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
/// Validates node masks against real online NUMA nodes; no page is
/// migrated yet (BUGS.md).
///
/// Linux kernel_migrate_pages order: the masks (EFAULT, EINVAL), the
/// target ([`mm_target`]: ESRCH, EPERM), then new nodes outside the
/// online ones (cpuset_mems_allowed) need CAP_SYS_NICE (EPERM), and
/// none online is EINVAL
pub fn sys_migrate_pages(pid: i64, maxnode: u64, old_nodes_ptr: u64, new_nodes_ptr: u64) -> i64 {
    // get_nodes: maxnode 0 leaves no bit count (EINVAL)
    if maxnode == 0 {
        return KernelError::InvalidArgument.sysret();
    }

    if maxnode > MAX_MASK_BITS + 1 {
        return KernelError::InvalidArgument.sysret();
    }
    let mask_bytes = maxnode.div_ceil(64) * 8;
    let online_mask = NUMA_TOPOLOGY.lock().online_mask();

    // Validate and read old_nodes if provided
    if old_nodes_ptr != 0 {
        if !Uaccess::access_ok(old_nodes_ptr, mask_bytes as usize) {
            return KernelError::BadAddress.sysret();
        }
        if get_user::<Uaccess, u64>(old_nodes_ptr).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    // Validate and read new_nodes if provided; NULL is an empty mask
    let mut new_mask: u64 = 0;
    if new_nodes_ptr != 0 {
        if !Uaccess::access_ok(new_nodes_ptr, mask_bytes as usize) {
            return KernelError::BadAddress.sysret();
        }
        new_mask = match get_user::<Uaccess, u64>(new_nodes_ptr) {
            Ok(m) => m,
            Err(_) => return KernelError::BadAddress.sysret(),
        };
    }

    if let Err(e) = mm_target(pid) {
        return e.sysret();
    }
    // Nodes the target may not use (no cpusets: the online ones)
    if new_mask & !online_mask != 0 && !crate::task::capable(crate::task::CAP_SYS_NICE) {
        return KernelError::NotPermitted.sysret();
    }
    // No allowed target node: EINVAL (Linux kernel_migrate_pages)
    if new_mask & online_mask == 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Nothing is migrated yet (BUGS.md): no page failed
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
/// Validates nodes against real online NUMA nodes; no page is moved
/// yet (BUGS.md).
///
/// # Permission Requirements
/// - MPOL_MF_MOVE_ALL requires CAP_SYS_NICE
/// - Another process: [`mm_target`] (Linux find_mm_struct), before
///   anything else is looked at
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

    // Permission check for MPOL_MF_MOVE_ALL
    if (flags as u32) & MPOL_MF_MOVE_ALL != 0 && !crate::task::capable(crate::task::CAP_SYS_NICE) {
        return KernelError::NotPermitted.sysret();
    }

    // The target before anything else (Linux kernel_move_pages ->
    // find_mm_struct)
    if let Err(e) = mm_target(pid) {
        return e.sysret();
    }

    // Zero pages is a no-op
    if nr_pages == 0 {
        return 0;
    }

    // Validate the user arrays; sizes are user-controlled, so an
    // overflowing size is EFAULT (never a wrapped address)
    let array_ok = |ptr: u64, elem: u64| {
        nr_pages
            .checked_mul(elem)
            .is_some_and(|size| ptr != 0 && Uaccess::access_ok(ptr, size as usize))
    };
    if !array_ok(pages_ptr, 8) || !array_ok(status_ptr, 4) {
        return KernelError::BadAddress.sysret();
    }
    if nodes_ptr != 0 && !array_ok(nodes_ptr, 4) {
        return KernelError::BadAddress.sysret();
    }

    // Get online nodes mask
    let online_mask = NUMA_TOPOLOGY.lock().online_mask();

    // Any invalid or offline target node fails the whole call with ENODEV
    // (Linux mm/migrate.c do_pages_move)
    if nodes_ptr != 0 {
        for i in 0..nr_pages {
            if let Err(e) = move_pages_resched(i) {
                return e;
            }
            // In range: access_ok checked nodes_ptr + nr_pages * 4
            let node = match get_user::<Uaccess, i32>(nodes_ptr + i * 4) {
                Ok(n) => n,
                Err(_) => return KernelError::BadAddress.sysret(),
            };
            if !(0..64).contains(&node) || online_mask & (1u64 << node) == 0 {
                return KernelError::NoDevice.sysret();
            }
        }
    }

    // Write status for each page
    for i in 0..nr_pages {
        if let Err(e) = move_pages_resched(i) {
            return e;
        }
        let status: i32 = if nodes_ptr == 0 {
            // Query mode: node 0, not the page's node (BUGS.md)
            0
        } else {
            // Move mode: nodes validated above, nothing moved (BUGS.md)
            0
        };
        if put_user::<Uaccess, i32>(status_ptr + i * 4, status).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    0
}

/// Entries handled between scheduling points in move_pages (Linux works
/// in chunks with cond_resched)
const MOVE_PAGES_CHUNK: u64 = 1024;

/// Every `MOVE_PAGES_CHUNK` entries: a scheduling point (the kernel is
/// not preemptive, so a huge user-supplied count would otherwise
/// monopolize the CPU) and a stop for a pending signal (restartable: the
/// work done so far is idempotent)
fn move_pages_resched(i: u64) -> Result<(), i64> {
    if i > 0 && i.is_multiple_of(MOVE_PAGES_CHUNK) {
        crate::task::percpu::cond_resched();
        if crate::sync::waitqueue::signal_pending() {
            return Err(KernelError::RestartSys.sysret());
        }
    }
    Ok(())
}

/// Largest node mask accepted from/copied to user space: one page of bits
/// (Linux get_nodes / copy_nodes_to_user)
const MAX_MASK_BITS: u64 = 4096 * 8;
