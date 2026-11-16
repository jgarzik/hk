//! NUMA Memory Policy Syscalls (Linux mm/mempolicy.c)
//!
//! Implements get_mempolicy, set_mempolicy, mbind, migrate_pages, and move_pages.
//! Uses the NUMA topology discovered from ACPI SRAT (x86-64) or device tree (aarch64).
//!
//! A task's policy lives in its `mempolicy` field (Linux task->mempolicy,
//! under task_lock), copied by fork. Nodemasks are one `u64`:
//! [`MAX_NUMNODES`] is 64 (Linux CONFIG_NODES_SHIFT=6), and every node
//! that is online has memory and is allowed (no cpusets: Linux
//! cpuset_current_mems_allowed = node_states[N_MEMORY]).

use crate::mm::PAGE_SIZE;
use crate::mm::numa::{MAX_NUMA_NODES, NUMA_TOPOLOGY};
use crate::uaccess::{UserPtr, access_ok, copy_to_user};
use crate::util::error::{KernelError, KernelResult};

// ============================================================================
// Policy modes (MPOL_*)
// ============================================================================

/// Default policy: the task's, else allocate on the local node
pub const MPOL_DEFAULT: u16 = 0;
/// Prefer a specific node, fallback to others
pub const MPOL_PREFERRED: u16 = 1;
/// Restrict allocation to specific nodes only
pub const MPOL_BIND: u16 = 2;
/// Round-robin allocation across nodes
pub const MPOL_INTERLEAVE: u16 = 3;
/// Allocate on local CPU's node
pub const MPOL_LOCAL: u16 = 4;
/// Prefer a set of nodes (newer variant)
pub const MPOL_PREFERRED_MANY: u16 = 5;
/// Round-robin by node weight (Linux 6.9)
pub const MPOL_WEIGHTED_INTERLEAVE: u16 = 6;
/// Maximum policy value (for validation)
pub const MPOL_MAX: u16 = 7;

// ============================================================================
// Mode flags (combined with policy mode)
// ============================================================================

/// Use static node set (don't remap on cpuset changes)
pub const MPOL_F_STATIC_NODES: u16 = 1 << 15;
/// Use relative node set
pub const MPOL_F_RELATIVE_NODES: u16 = 1 << 14;
/// Enable NUMA balancing optimization
pub const MPOL_F_NUMA_BALANCING: u16 = 1 << 13;

/// Mask for mode flags
pub const MPOL_MODE_FLAGS: u16 =
    MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES | MPOL_F_NUMA_BALANCING;

/// The flags that keep the caller's nodemask
const MPOL_USER_NODEMASK_FLAGS: u16 = MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES;

/// Internal: migrate on fault (Linux MPOL_F_MOF)
const MPOL_F_MOF: u16 = 1 << 3;
/// Internal: migrate on protnone reference on node (Linux MPOL_F_MORON)
const MPOL_F_MORON: u16 = 1 << 4;

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

/// Nodes a nodemask holds (Linux MAX_NUMNODES)
pub const MAX_NUMNODES: u64 = MAX_NUMA_NODES as u64;

// ============================================================================
// Policies
// ============================================================================

/// A memory policy (Linux struct mempolicy); MPOL_DEFAULT is the absence
/// of one (`None`)
#[derive(Clone, Copy, Debug)]
pub struct Mempolicy {
    /// MPOL_PREFERRED .. MPOL_WEIGHTED_INTERLEAVE, never MPOL_DEFAULT
    pub mode: u16,
    /// Mode flags (MPOL_F_*), with the internal MPOL_F_MOF/MORON
    pub flags: u16,
    /// The nodes it uses (MPOL_PREFERRED: one; MPOL_LOCAL: none)
    pub nodes: u64,
    /// The caller's nodemask, kept for MPOL_F_STATIC_NODES and
    /// MPOL_F_RELATIVE_NODES (Linux w.user_nodemask); else 0
    pub user_nodes: u64,
}

impl Mempolicy {
    /// It keeps the caller's nodemask (Linux mpol_store_user_nodemask)
    fn store_user(&self) -> bool {
        self.flags & MPOL_USER_NODEMASK_FLAGS != 0
    }

    /// The nodemask get_mempolicy reports (Linux do_get_mempolicy,
    /// get_policy_nodemask)
    pub fn query_nodes(&self) -> u64 {
        if self.store_user() {
            self.user_nodes
        } else if self.mode == MPOL_LOCAL {
            0
        } else {
            self.nodes
        }
    }

    /// Same policy (Linux __mpol_equal; hk keeps no home node)
    fn same(&self, b: &Mempolicy) -> bool {
        self.mode == b.mode
            && self.flags == b.flags
            && (!self.store_user() || self.user_nodes == b.user_nodes)
            && (self.mode == MPOL_LOCAL || self.nodes == b.nodes)
    }
}

/// Two optional policies are the same (Linux mpol_equal)
pub fn mpol_equal(a: Option<&Mempolicy>, b: Option<&Mempolicy>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => a.same(b),
        _ => false,
    }
}

/// A task's memory policy state (Linux task->mempolicy, il_prev): an
/// `alloc_lock` field, copied by fork
#[derive(Clone, Copy, Debug)]
pub struct TaskMempolicy {
    /// set_mempolicy's policy; None: MPOL_DEFAULT
    pub pol: Option<Mempolicy>,
    /// Last node interleaved on (Linux il_prev)
    pub il_prev: u32,
}

impl TaskMempolicy {
    /// MPOL_DEFAULT
    pub const fn new() -> Self {
        Self {
            pol: None,
            il_prev: 0,
        }
    }
}

// ============================================================================
// Nodemask helpers (pure: unit-tested)
// ============================================================================

/// Bits of `orig` folded modulo `sz` (Linux bitmap_fold)
fn nodes_fold(orig: u64, sz: u32) -> u64 {
    if sz == 0 {
        return 0;
    }
    (0..64)
        .filter(|n| orig & (1u64 << n) != 0)
        .fold(0, |m, n| m | 1u64 << (n % sz))
}

/// Bit n of `orig` set as the n-th set bit of `rel` (Linux bitmap_onto)
fn nodes_onto(orig: u64, rel: u64) -> u64 {
    let mut out = 0;
    let mut r = rel;
    let mut n = 0;
    while r != 0 {
        let bit = r.trailing_zeros();
        if orig & (1u64 << n) != 0 {
            out |= 1u64 << bit;
        }
        r &= r - 1;
        n += 1;
    }
    out
}

/// `orig` relative to `rel` (Linux mpol_relative_nodemask)
fn mpol_relative_nodemask(orig: u64, rel: u64) -> u64 {
    nodes_onto(nodes_fold(orig, rel.count_ones()), rel)
}

/// The first set node after `node`, wrapping (Linux next_node_in);
/// MAX_NUMNODES if `mask` is empty
fn next_node_in(node: u32, mask: u64) -> u32 {
    let after = if node >= 63 {
        0
    } else {
        mask & !((2u64 << node) - 1)
    };
    if after != 0 {
        after.trailing_zeros()
    } else if mask != 0 {
        mask.trailing_zeros()
    } else {
        MAX_NUMNODES as u32
    }
}

/// Mode and flags of set_mempolicy's or mbind's `mode` (Linux
/// sanitize_mpol_flags); MPOL_F_NUMA_BALANCING only for MPOL_BIND and
/// MPOL_PREFERRED_MANY (Linux 6.10)
fn sanitize_mpol_flags(mode: i32) -> KernelResult<(u16, u16)> {
    let mut flags = (mode as u32 & u32::from(MPOL_MODE_FLAGS)) as u16;
    let mode = mode as u32 & !u32::from(MPOL_MODE_FLAGS);
    if mode >= u32::from(MPOL_MAX) {
        return Err(KernelError::InvalidArgument);
    }
    let mode = mode as u16;
    if flags & MPOL_F_STATIC_NODES != 0 && flags & MPOL_F_RELATIVE_NODES != 0 {
        return Err(KernelError::InvalidArgument);
    }
    if flags & MPOL_F_NUMA_BALANCING != 0 {
        if mode != MPOL_BIND && mode != MPOL_PREFERRED_MANY {
            return Err(KernelError::InvalidArgument);
        }
        flags |= MPOL_F_MOF | MPOL_F_MORON;
    }
    Ok((mode, flags))
}

/// A node mask of `maxnode` - 1 bits from user space, word `i` read by
/// `word(i)` (Linux get_nodes; `null`: no mask). Bits past
/// MAX_NUMNODES must be zero, checked a word at a time from the top
/// (whole words: Linux get_bitmap masks by the count, not the word's
/// place); more than a page of bits is EINVAL.
fn get_nodes_with(
    null: bool,
    maxnode: u64,
    mut word: impl FnMut(u64) -> KernelResult<u64>,
) -> KernelResult<u64> {
    let mut maxnode = maxnode.wrapping_sub(1);
    if maxnode == 0 || null {
        return Ok(0);
    }
    if maxnode > PAGE_SIZE * 8 {
        return Err(KernelError::InvalidArgument);
    }
    while maxnode > MAX_NUMNODES {
        let bits = maxnode.min(64);
        let mut t = bitmap_word(word((maxnode - 1) / 64)?, bits);
        if maxnode - bits >= MAX_NUMNODES {
            maxnode -= bits;
        } else {
            maxnode = MAX_NUMNODES;
            t &= !((1u64 << (MAX_NUMNODES % 64)) - 1);
        }
        if t != 0 {
            return Err(KernelError::InvalidArgument);
        }
    }
    Ok(bitmap_word(word(0)?, maxnode))
}

/// The low `bits` bits of `w` (Linux get_bitmap of one word)
fn bitmap_word(w: u64, bits: u64) -> u64 {
    if !bits.is_multiple_of(64) {
        w & ((1u64 << (bits % 64)) - 1)
    } else {
        w
    }
}

/// `get_nodes_with` from the user mask `nmask`: EFAULT if unreadable
fn get_nodes(nmask: UserPtr<u64>, maxnode: u64) -> KernelResult<u64> {
    get_nodes_with(nmask.is_null(), maxnode, |i| Ok(nth(nmask, i)?.read()?))
}

/// (bytes to copy, bytes to clear after them) of a node mask for a
/// `maxnode`-bit user buffer (Linux copy_nodes_to_user: whole words up
/// to bit maxnode - 1; past the `nr_node_ids` bits the kernel has, the
/// rest is zeroed, at most a page). The caller checked maxnode >=
/// nr_node_ids >= 1.
fn copy_nodes_len(maxnode: u64, nr_node_ids: u64) -> KernelResult<(u64, u64)> {
    let copy = (maxnode.wrapping_sub(1).wrapping_add(63) & !63) / 8;
    let nbytes = nr_node_ids.div_ceil(64) * 8;
    if copy <= nbytes {
        return Ok((copy, 0));
    }
    if copy > PAGE_SIZE {
        return Err(KernelError::InvalidArgument);
    }
    Ok((nbytes, copy - nbytes))
}

/// Zeros for clearing user memory (at most a page)
static ZEROS: [u8; PAGE_SIZE as usize] = [0; PAGE_SIZE as usize];

/// Copy `nodes` to the user mask `mask` of `maxnode` bits (Linux
/// copy_nodes_to_user)
fn copy_nodes_to_user(
    mask: UserPtr<u64>,
    maxnode: u64,
    nodes: u64,
    nr_node_ids: u64,
) -> KernelResult<()> {
    let (copy, clear) = copy_nodes_len(maxnode, nr_node_ids)?;
    if clear > 0 {
        copy_to_user(mask.addr().wrapping_add(copy), &ZEROS[..clear as usize])?;
    }
    copy_to_user(mask.addr(), &nodes.to_ne_bytes()[..copy as usize])?;
    Ok(())
}

/// A new policy, its nodes not yet set (Linux mpol_new): None for
/// MPOL_DEFAULT (EINVAL with nodes); MPOL_PREFERRED without nodes is
/// MPOL_LOCAL (EINVAL with MPOL_F_STATIC_NODES or
/// MPOL_F_RELATIVE_NODES, as is MPOL_LOCAL with nodes or those flags);
/// every other mode needs nodes
fn mpol_new(mode: u16, flags: u16, nodes: u64) -> KernelResult<Option<Mempolicy>> {
    if mode == MPOL_DEFAULT {
        if nodes != 0 {
            return Err(KernelError::InvalidArgument);
        }
        return Ok(None);
    }
    let user = flags & MPOL_USER_NODEMASK_FLAGS != 0;
    let mode = match mode {
        MPOL_PREFERRED if nodes == 0 && user => return Err(KernelError::InvalidArgument),
        MPOL_PREFERRED if nodes == 0 => MPOL_LOCAL,
        MPOL_LOCAL if nodes != 0 || user => return Err(KernelError::InvalidArgument),
        MPOL_LOCAL | MPOL_PREFERRED => mode,
        _ if nodes == 0 => return Err(KernelError::InvalidArgument),
        _ => mode,
    };
    Ok(Some(Mempolicy {
        mode,
        flags,
        nodes: 0,
        user_nodes: 0,
    }))
}

/// Set `pol`'s nodes from the caller's `nodes` and the nodes it may use,
/// `allowed` (Linux mpol_set_nodemask and the mode's create): relative
/// to them with MPOL_F_RELATIVE_NODES, else those of them it names;
/// EINVAL if none is left; MPOL_PREFERRED keeps the first
fn mpol_set_nodemask(mut pol: Mempolicy, nodes: u64, allowed: u64) -> KernelResult<Mempolicy> {
    if pol.mode == MPOL_LOCAL {
        return Ok(pol);
    }
    let usable = if pol.flags & MPOL_F_RELATIVE_NODES != 0 {
        mpol_relative_nodemask(nodes, allowed)
    } else {
        nodes & allowed
    };
    if pol.store_user() {
        pol.user_nodes = nodes;
    }
    if usable == 0 {
        return Err(KernelError::InvalidArgument);
    }
    pol.nodes = if pol.mode == MPOL_PREFERRED {
        usable.isolate_lowest_one()
    } else {
        usable
    };
    Ok(pol)
}

/// The nodes a policy may use: those with memory (Linux
/// node_states[N_MEMORY]; with no cpusets also
/// cpuset_current_mems_allowed)
fn mems_allowed() -> u64 {
    NUMA_TOPOLOGY.lock().online_mask()
}

/// One past the highest possible node (Linux nr_node_ids)
fn nr_node_ids(allowed: u64) -> u64 {
    (64 - u64::from(allowed.leading_zeros())).max(1)
}

// ============================================================================
// Syscall implementations
// ============================================================================

/// sys_get_mempolicy - Get memory policy for process or VMA (Linux
/// kernel_get_mempolicy): a `nmask` of fewer than nr_node_ids bits is
/// EINVAL; the policy (`do_get_mempolicy`), then the mask
pub fn sys_get_mempolicy(
    policy: UserPtr<i32>,
    nmask: UserPtr<u64>,
    maxnode: u64,
    addr: u64,
    flags: u64,
) -> KernelResult<()> {
    let allowed = mems_allowed();
    let nr = nr_node_ids(allowed);
    if !nmask.is_null() && maxnode < nr {
        return Err(KernelError::InvalidArgument);
    }
    let (pval, nodes) = do_get_mempolicy(addr, flags, allowed)?;
    if !policy.is_null() {
        policy.write(&pval)?;
    }
    if !nmask.is_null() {
        copy_nodes_to_user(nmask, maxnode, nodes, nr)?;
    }
    Ok(())
}

/// The policy value and nodemask get_mempolicy reports (Linux
/// do_get_mempolicy): MPOL_F_MEMS_ALLOWED alone gives 0 and the allowed
/// nodes; MPOL_F_ADDR the policy of the VMA at `addr` (EFAULT if none;
/// MPOL_DEFAULT if it has none, never the task's), else `addr` must be
/// 0; MPOL_F_NODE the node of the page at `addr` with MPOL_F_ADDR, else
/// the task's next interleave node (EINVAL for any other policy);
/// otherwise the mode with its mode flags
fn do_get_mempolicy(addr: u64, flags: u64, allowed: u64) -> KernelResult<(i32, u64)> {
    if flags & !(MPOL_F_NODE | MPOL_F_ADDR | MPOL_F_MEMS_ALLOWED) != 0 {
        return Err(KernelError::InvalidArgument);
    }
    if flags & MPOL_F_MEMS_ALLOWED != 0 {
        if flags & (MPOL_F_NODE | MPOL_F_ADDR) != 0 {
            return Err(KernelError::InvalidArgument);
        }
        return Ok((0, allowed));
    }
    let me = crate::task::percpu::current();
    let task = me.task_lock().mempolicy();
    let pol = if flags & MPOL_F_ADDR != 0 {
        vma_policy(addr)?
    } else if addr != 0 {
        return Err(KernelError::InvalidArgument);
    } else {
        task.pol
    };
    let nodes = pol.map_or(0, |p| p.query_nodes());
    if flags & MPOL_F_NODE == 0 {
        let pval = pol.map_or(MPOL_DEFAULT, |p| p.mode | (p.flags & MPOL_MODE_FLAGS));
        return Ok((i32::from(pval), nodes));
    }
    if flags & MPOL_F_ADDR != 0 {
        return Ok((lookup_node(addr)?, nodes));
    }
    match pol {
        Some(p) if p.mode == MPOL_INTERLEAVE || p.mode == MPOL_WEIGHTED_INTERLEAVE => {
            // hk keeps no interleave weight (Linux il_weight 0)
            Ok((next_node_in(task.il_prev, p.nodes) as i32, nodes))
        }
        _ => Err(KernelError::InvalidArgument),
    }
}

/// The policy of the current task's VMA at `addr` (Linux vma_lookup,
/// __get_vma_policy): EFAULT if no VMA holds it
fn vma_policy(addr: u64) -> KernelResult<Option<Mempolicy>> {
    let mm = crate::task::percpu::current()
        .mm()
        .ok_or(KernelError::BadAddress)?;
    let map = mm.mmap_read();
    Ok(map.find_vma(addr).ok_or(KernelError::BadAddress)?.mempolicy)
}

/// The node of the page at `addr`, faulted in for reading if missing
/// (Linux lookup_node: get_user_pages_fast); its error if it cannot be
fn lookup_node(addr: u64) -> KernelResult<i32> {
    let mut pages = crate::mm::gup::PinnedPages::new(1)?;
    crate::mm::gup::pin_user(&mut pages, addr & !(PAGE_SIZE - 1), 1, false, 1)?;
    let phys = pages.segs().first().ok_or(KernelError::BadAddress)?.phys;
    Ok(NUMA_TOPOLOGY.lock().pfn_to_node(phys / PAGE_SIZE) as i32)
}

/// sys_set_mempolicy - Set the calling task's memory policy (Linux
/// kernel_set_mempolicy): `mode` with its flags checked, the nodemask
/// read, then installed (`do_set_mempolicy`)
pub fn sys_set_mempolicy(mode: i32, nmask: UserPtr<u64>, maxnode: u64) -> KernelResult<()> {
    let (mode, flags) = sanitize_mpol_flags(mode)?;
    let nodes = get_nodes(nmask, maxnode)?;
    do_set_mempolicy(mode, flags, nodes)
}

/// Make the policy and install it as the task's under its alloc_lock
/// (Linux do_set_mempolicy); a new interleave starts over (il_prev at
/// the last node)
fn do_set_mempolicy(mode: u16, flags: u16, nodes: u64) -> KernelResult<()> {
    let allowed = mems_allowed();
    let new = mpol_new(mode, flags, nodes)?
        .map(|p| mpol_set_nodemask(p, nodes, allowed))
        .transpose()?;
    let me = crate::task::percpu::current();
    let mut t = me.task_lock();
    let mut tp = t.mempolicy();
    tp.pol = new;
    if new.is_some_and(|p| p.mode == MPOL_INTERLEAVE || p.mode == MPOL_WEIGHTED_INTERLEAVE) {
        tp.il_prev = MAX_NUMNODES as u32 - 1;
    }
    t.set_mempolicy(tp);
    Ok(())
}

/// sys_mbind - Set the memory policy of a range (Linux kernel_mbind):
/// `mode` (its int, as Linux takes it) with its flags checked, the
/// nodemask read, then [`do_mbind`]
pub fn sys_mbind(
    start: u64,
    len: u64,
    mode: u64,
    nmask: UserPtr<u64>,
    maxnode: u64,
    flags: u32,
) -> KernelResult<()> {
    let (mode, mode_flags) = sanitize_mpol_flags(mode as i32)?;
    let nodes = get_nodes(nmask, maxnode)?;
    do_mbind(start, len, mode, mode_flags, nodes, flags)
}

/// Give the VMAs of [start, start + len) the policy (Linux do_mbind):
/// unknown flags EINVAL, MPOL_MF_MOVE_ALL without CAP_SYS_NICE EPERM,
/// an unaligned start EINVAL, a wrapping range EINVAL, an empty one
/// nothing. Under the mmap_lock for writing, the pages of the range are
/// checked (`queue_pages`: a hole is EFAULT unless the policy is
/// MPOL_DEFAULT, a range with no VMA always; a misplaced page with
/// MPOL_MF_STRICT alone EIO, nothing changed), then each VMA is split
/// at the range edges and takes the policy (`mbind_vmas`). With
/// MPOL_MF_STRICT, a misplaced page left in place is EIO after that
/// (MPOL_DEFAULT drops MPOL_MF_STRICT). Nothing is migrated (BUGS.md):
/// with MPOL_MF_MOVE a page is in place only where the policy would
/// put it anyway.
fn do_mbind(
    start: u64,
    len: u64,
    mode: u16,
    mode_flags: u16,
    nmask: u64,
    mut flags: u32,
) -> KernelResult<()> {
    if flags & !MPOL_MF_VALID != 0 {
        return Err(KernelError::InvalidArgument);
    }
    if flags & MPOL_MF_MOVE_ALL != 0 && !crate::task::capable(crate::task::CAP_SYS_NICE) {
        return Err(KernelError::NotPermitted);
    }
    if start & (PAGE_SIZE - 1) != 0 {
        return Err(KernelError::InvalidArgument);
    }
    if mode == MPOL_DEFAULT {
        flags &= !MPOL_MF_STRICT;
    }
    let len = len.wrapping_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let end = start.wrapping_add(len);
    if end < start {
        return Err(KernelError::InvalidArgument);
    }
    if end == start {
        return Ok(());
    }
    let new = mpol_new(mode, mode_flags, nmask)?;
    let allowed = mems_allowed();
    let mm = crate::task::percpu::current()
        .mm()
        .ok_or(KernelError::BadAddress)?;
    let mut map = mm.mmap_write();
    let new = new
        .map(|p| mpol_set_nodemask(p, nmask, allowed))
        .transpose()?;
    let mut q = Queue {
        nmask,
        flags,
        target: target_nodes(new.as_ref()),
        failed: 0,
    };
    q.range(&mm, &map, start, end, new.is_none())?;
    mbind_vmas(&mut map, start, end, new)?;
    if q.failed > 0 && flags & MPOL_MF_STRICT != 0 {
        return Err(KernelError::Io);
    }
    Ok(())
}

/// The nodes `pol` allocates on, where a migration would put a page:
/// the local node for MPOL_LOCAL and MPOL_DEFAULT
fn target_nodes(pol: Option<&Mempolicy>) -> u64 {
    match pol {
        Some(p) if p.mode != MPOL_LOCAL => p.nodes,
        _ => 1u64 << NUMA_TOPOLOGY.lock().cpu_to_node(crate::cpu::this_id()),
    }
}

/// mbind's page check (Linux struct queue_pages, MPOL_MF_INVERT): a
/// present page off the nodes of `nmask` is misplaced, and a failure
/// unless MPOL_MF_MOVE would leave it where it is (`target`)
struct Queue {
    nmask: u64,
    flags: u32,
    target: u64,
    failed: u64,
}

impl Queue {
    /// Check the VMAs of [start, end) in `map` (Linux queue_pages_range,
    /// queue_pages_test_walk): EFAULT at a hole unless `discontig`, and
    /// with no VMA there at all; pages are looked at only for
    /// MPOL_MF_STRICT or a move, EIO at the first misplaced one for
    /// MPOL_MF_STRICT alone
    fn range(
        &mut self,
        mm: &crate::mm::Mm,
        map: &crate::mm::MmStruct,
        start: u64,
        end: u64,
        discontig: bool,
    ) -> KernelResult<()> {
        let t = crate::mm::pgtable::PgTables::new(mm, map);
        let mut vmas = map
            .iter()
            .filter(|v| v.end > start && v.start < end)
            .peekable();
        let mut first = true;
        while let Some(v) = vmas.next() {
            if first && !discontig && start < v.start {
                return Err(KernelError::BadAddress);
            }
            first = false;
            let hole = v.end < end && vmas.peek().is_none_or(|n| v.end < n.start);
            if hole && !discontig {
                return Err(KernelError::BadAddress);
            }
            if self.flags & MPOL_MF_VALID != 0 {
                let (s, e) = (start.max(v.start), end.min(v.end));
                crate::mm::pagewalk::walk_pte_range(t, s, e, self).map_err(|()| KernelError::Io)?;
            }
        }
        if first {
            return Err(KernelError::BadAddress);
        }
        Ok(())
    }

    /// The page at `phys` (Linux queue_folio_required and the checks
    /// after it); Err stops the walk (MPOL_MF_STRICT alone)
    fn page(&mut self, phys: u64) -> Result<(), ()> {
        if crate::mm::page::phys_to_page(phys).is_none() {
            return Ok(());
        }
        let node = NUMA_TOPOLOGY.lock().pfn_to_node(phys / PAGE_SIZE);
        let bit = 1u64 << node;
        let moving = self.flags & (MPOL_MF_MOVE | MPOL_MF_MOVE_ALL) != 0;
        if self.nmask & bit != 0 || (moving && self.target & bit != 0) {
            return Ok(());
        }
        self.failed += 1;
        if moving { Ok(()) } else { Err(()) }
    }
}

impl crate::mm::pagewalk::PteWalk for Queue {
    type Err = ();

    fn huge(&mut self, pmd: crate::mm::pgtable::Pmd<'_>, _: u64, _: u64) -> Result<bool, ()> {
        use crate::mm::huge_page::HUGE_PAGE_MASK;
        self.page(crate::arch::paging::pte_addr(pmd.settled()) & !HUGE_PAGE_MASK)?;
        Ok(true)
    }

    fn pte(&mut self, e: &core::sync::atomic::AtomicU64, _: u64) -> Result<(), ()> {
        let pte = e.load(core::sync::atomic::Ordering::Acquire);
        if crate::arch::paging::pte_present(pte) {
            self.page(crate::arch::paging::pte_addr(pte))?;
        }
        Ok(())
    }
}

/// Give the VMAs of [start, end) the policy `new` (Linux mbind_range,
/// vma_modify_policy): a VMA that has it already is left alone, else
/// split at the range edges (ENOMEM at vm.max_map_count), given it and
/// merged with neighbours that have the same
fn mbind_vmas(
    map: &mut crate::mm::MmStruct,
    start: u64,
    end: u64,
    new: Option<Mempolicy>,
) -> KernelResult<()> {
    let mut addr = start;
    while addr < end {
        let Some(v) = map.next_vma(addr).and_then(|i| map.get_vma(i)) else {
            break;
        };
        if v.start >= end {
            break;
        }
        let (s, e) = (addr.max(v.start), v.end.min(end));
        if !mpol_equal(v.mempolicy.as_ref(), new.as_ref()) {
            map.split_at_checked(s)?;
            map.split_at_checked(e)?;
            if let Some(j) = map.find_vma_exact(s) {
                if let Some(v) = map.get_vma_mut(j) {
                    v.mempolicy = new;
                }
                map.merge_adjacent(j);
            }
        }
        addr = e;
    }
    Ok(())
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
    let t = crate::task::percpu::find_task_by_vpid(pid as u64).ok_or(KernelError::NoProcess)?;
    let _g = crate::signal::ExecUpdateRead::lock(&t);
    if !crate::task::ptrace::may_access_task(&t, false) {
        return Err(KernelError::NotPermitted);
    }
    crate::mm::get_task_mm(&t)
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
pub fn sys_migrate_pages(
    pid: i64,
    maxnode: u64,
    old_nodes: UserPtr<u64>,
    new_nodes: UserPtr<u64>,
) -> KernelResult<u64> {
    // get_nodes: maxnode 0 leaves no bit count (EINVAL)
    if maxnode == 0 {
        return Err(KernelError::InvalidArgument);
    }

    if maxnode > MAX_MASK_BITS + 1 {
        return Err(KernelError::InvalidArgument);
    }
    let mask_bytes = maxnode.div_ceil(64) * 8;
    let online_mask = NUMA_TOPOLOGY.lock().online_mask();

    // Validate and read old_nodes if provided
    if !old_nodes.is_null() {
        if !access_ok(old_nodes.addr(), mask_bytes as usize) {
            return Err(KernelError::BadAddress);
        }
        old_nodes.read()?;
    }

    // Validate and read new_nodes if provided; NULL is an empty mask
    let mut new_mask: u64 = 0;
    if !new_nodes.is_null() {
        if !access_ok(new_nodes.addr(), mask_bytes as usize) {
            return Err(KernelError::BadAddress);
        }
        new_mask = new_nodes.read()?;
    }

    mm_target(pid)?;
    // Nodes the target may not use (no cpusets: the online ones)
    if new_mask & !online_mask != 0 && !crate::task::capable(crate::task::CAP_SYS_NICE) {
        return Err(KernelError::NotPermitted);
    }
    // No allowed target node: EINVAL (Linux kernel_migrate_pages)
    if new_mask & online_mask == 0 {
        return Err(KernelError::InvalidArgument);
    }

    // Nothing is migrated yet (BUGS.md): no page failed
    Ok(0)
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
    pages: UserPtr<u64>,
    nodes: UserPtr<i32>,
    status: UserPtr<i32>,
    flags: i32,
) -> KernelResult<()> {
    // Validate flags
    let valid_flags = MPOL_MF_MOVE | MPOL_MF_MOVE_ALL;
    if (flags as u32) & !valid_flags != 0 {
        return Err(KernelError::InvalidArgument);
    }

    // Permission check for MPOL_MF_MOVE_ALL
    if (flags as u32) & MPOL_MF_MOVE_ALL != 0 && !crate::task::capable(crate::task::CAP_SYS_NICE) {
        return Err(KernelError::NotPermitted);
    }

    // The target before anything else (Linux kernel_move_pages ->
    // find_mm_struct)
    mm_target(pid)?;

    // Zero pages is a no-op
    if nr_pages == 0 {
        return Ok(());
    }

    // Validate the user arrays; sizes are user-controlled, so an
    // overflowing size is EFAULT (never a wrapped address)
    let array_ok = |ptr: u64, elem: u64| {
        nr_pages
            .checked_mul(elem)
            .is_some_and(|size| ptr != 0 && access_ok(ptr, size as usize))
    };
    if !array_ok(pages.addr(), 8) || !array_ok(status.addr(), 4) {
        return Err(KernelError::BadAddress);
    }
    if !nodes.is_null() && !array_ok(nodes.addr(), 4) {
        return Err(KernelError::BadAddress);
    }

    // Get online nodes mask
    let online_mask = NUMA_TOPOLOGY.lock().online_mask();

    // Any invalid or offline target node fails the whole call with ENODEV
    // (Linux mm/migrate.c do_pages_move)
    if !nodes.is_null() {
        for i in 0..nr_pages {
            move_pages_resched(i)?;
            // In range: access_ok checked nodes + nr_pages * 4
            let node = nth(nodes, i)?.read()?;
            if !(0..64).contains(&node) || online_mask & (1u64 << node) == 0 {
                return Err(KernelError::NoDevice);
            }
        }
    }

    // Write status for each page
    for i in 0..nr_pages {
        move_pages_resched(i)?;
        let st: i32 = if nodes.is_null() {
            // Query mode: node 0, not the page's node (BUGS.md)
            0
        } else {
            // Move mode: nodes validated above, nothing moved (BUGS.md)
            0
        };
        nth(status, i)?.write(&st)?;
    }

    Ok(())
}

/// Element `i` of a user array
fn nth<T>(p: UserPtr<T>, i: u64) -> KernelResult<UserPtr<T>> {
    usize::try_from(i)
        .ok()
        .and_then(|i| p.offset(i))
        .ok_or(KernelError::BadAddress)
}

/// Entries handled between scheduling points in move_pages (Linux works
/// in chunks with cond_resched)
const MOVE_PAGES_CHUNK: u64 = 1024;

/// Every `MOVE_PAGES_CHUNK` entries: a scheduling point (the kernel is
/// not preemptive, so a huge user-supplied count would otherwise
/// monopolize the CPU) and a stop for a pending signal (restartable: the
/// work done so far is idempotent)
fn move_pages_resched(i: u64) -> KernelResult<()> {
    if i > 0 && i.is_multiple_of(MOVE_PAGES_CHUNK) {
        crate::task::percpu::cond_resched();
        if crate::sync::waitqueue::signal_pending() {
            return Err(KernelError::RestartSys);
        }
    }
    Ok(())
}

/// Largest node mask accepted from/copied to user space: one page of bits
/// (Linux get_nodes / copy_nodes_to_user)
const MAX_MASK_BITS: u64 = PAGE_SIZE * 8;

#[cfg(test)]
mod tests {
    use super::*;

    const EINVAL: Result<u64, KernelError> = Err(KernelError::InvalidArgument);

    /// get_nodes over the words `w` (missing words: EFAULT)
    fn nodes(w: &[u64], maxnode: u64) -> KernelResult<u64> {
        get_nodes_with(false, maxnode, |i| {
            w.get(i as usize).copied().ok_or(KernelError::BadAddress)
        })
    }

    #[test]
    fn get_nodes_counts() {
        assert_eq!(get_nodes_with(true, 64, |_| unreachable!()), Ok(0));
        assert_eq!(nodes(&[], 0), EINVAL);
        assert_eq!(nodes(&[], 1), Ok(0));
        assert_eq!(nodes(&[!0], 2), Ok(1));
        // maxnode counts one past the last bit
        assert_eq!(nodes(&[!0], 64), Ok(!0 >> 1));
        assert_eq!(nodes(&[!0], 65), Ok(!0));
    }

    #[test]
    fn get_nodes_high_bits() {
        assert_eq!(nodes(&[1, 0], 128), Ok(1));
        assert_eq!(nodes(&[1, 1 << 5], 128), EINVAL);
        // The whole last word is checked, past maxnode too
        assert_eq!(nodes(&[1, 1 << 60], 101), EINVAL);
        assert_eq!(nodes(&[1, 1], 66), EINVAL);
        assert_eq!(nodes(&[1, 0], 66), Ok(1));
        let page = [0u64; 512];
        assert_eq!(nodes(&page, PAGE_SIZE * 8 + 1), Ok(0));
        assert_eq!(nodes(&page, PAGE_SIZE * 8 + 2), EINVAL);
        assert_eq!(nodes(&[1], 128), Err(KernelError::BadAddress));
    }

    #[test]
    fn copy_nodes_lengths() {
        assert_eq!(copy_nodes_len(1, 1), Ok((0, 0)));
        assert_eq!(copy_nodes_len(64, 1), Ok((8, 0)));
        assert_eq!(copy_nodes_len(65, 1), Ok((8, 0)));
        assert_eq!(copy_nodes_len(66, 1), Ok((8, 8)));
        assert_eq!(copy_nodes_len(PAGE_SIZE * 8 + 1, 1), Ok((8, PAGE_SIZE - 8)));
        assert_eq!(
            copy_nodes_len(PAGE_SIZE * 8 + 2, 1),
            Err(KernelError::InvalidArgument)
        );
    }

    #[test]
    fn sanitize() {
        let s = sanitize_mpol_flags;
        assert_eq!(s(MPOL_BIND as i32), Ok((MPOL_BIND, 0)));
        assert!(s(MPOL_MAX as i32).is_err());
        assert!(s(-1).is_err());
        assert!(s(1 << 16 | MPOL_BIND as i32).is_err());
        let both = MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES;
        assert!(s(i32::from(both) | MPOL_BIND as i32).is_err());
        let nb = i32::from(MPOL_F_NUMA_BALANCING);
        assert_eq!(
            s(nb | MPOL_BIND as i32),
            Ok((MPOL_BIND, MPOL_F_NUMA_BALANCING | MPOL_F_MOF | MPOL_F_MORON))
        );
        assert!(s(nb | MPOL_PREFERRED_MANY as i32).is_ok());
        assert!(s(nb | MPOL_INTERLEAVE as i32).is_err());
    }

    #[test]
    fn new_policies() {
        let mode = |m, f, n| mpol_new(m, f, n).map(|p| p.map(|p| p.mode));
        assert_eq!(mode(MPOL_DEFAULT, 0, 0), Ok(None));
        assert!(mode(MPOL_DEFAULT, 0, 1).is_err());
        assert_eq!(mode(MPOL_PREFERRED, 0, 0), Ok(Some(MPOL_LOCAL)));
        assert!(mode(MPOL_PREFERRED, MPOL_F_STATIC_NODES, 0).is_err());
        assert_eq!(mode(MPOL_LOCAL, 0, 0), Ok(Some(MPOL_LOCAL)));
        assert!(mode(MPOL_LOCAL, 0, 1).is_err());
        assert!(mode(MPOL_LOCAL, MPOL_F_RELATIVE_NODES, 0).is_err());
        assert!(mode(MPOL_BIND, 0, 0).is_err());
        assert_eq!(mode(MPOL_INTERLEAVE, 0, 3), Ok(Some(MPOL_INTERLEAVE)));
    }

    /// mpol_new + mpol_set_nodemask: (nodes, user_nodes)
    fn set(mode: u16, flags: u16, nodes: u64, allowed: u64) -> KernelResult<(u64, u64)> {
        let p = mpol_new(mode, flags, nodes)?.unwrap();
        mpol_set_nodemask(p, nodes, allowed).map(|p| (p.nodes, p.user_nodes))
    }

    #[test]
    fn set_nodemask() {
        // Nodes without memory are dropped; none left is EINVAL
        assert_eq!(set(MPOL_BIND, 0, 0b100001, 1), Ok((1, 0)));
        assert_eq!(
            set(MPOL_BIND, 0, 0b10, 1),
            Err(KernelError::InvalidArgument)
        );
        assert_eq!(set(MPOL_PREFERRED, 0, 0b1100, 0b1111), Ok((0b100, 0)));
        assert_eq!(set(MPOL_BIND, MPOL_F_STATIC_NODES, 0b11, 1), Ok((1, 0b11)));
        // Relative: node n is the n-th allowed one, folded
        assert_eq!(
            set(MPOL_BIND, MPOL_F_RELATIVE_NODES, 0b10, 0b1010),
            Ok((0b1000, 0b10))
        );
        assert_eq!(
            set(MPOL_BIND, MPOL_F_RELATIVE_NODES, 0b100, 1),
            Ok((1, 0b100))
        );
        assert_eq!(set(MPOL_LOCAL, 0, 0, 1), Ok((0, 0)));
    }

    #[test]
    fn interleave_next() {
        assert_eq!(next_node_in(63, 0b1010), 1);
        assert_eq!(next_node_in(1, 0b1010), 3);
        assert_eq!(next_node_in(3, 0b1010), 1);
        assert_eq!(next_node_in(0, 0), MAX_NUMNODES as u32);
    }

    #[test]
    fn mbind_splits_and_merges() {
        use crate::mm::{MAP_ANONYMOUS, MAP_PRIVATE, MmStruct, PROT_READ, Vma};
        let mut m = MmStruct::new(0x7000_0000);
        m.insert_vma(Vma::new(
            0x10000,
            0x14000,
            PROT_READ,
            MAP_PRIVATE | MAP_ANONYMOUS,
        ));
        let bind = mpol_set_nodemask(mpol_new(MPOL_BIND, 0, 1).unwrap().unwrap(), 1, 1).unwrap();
        let spans = |m: &MmStruct| -> alloc::vec::Vec<(u64, u64, bool)> {
            m.iter()
                .map(|v| (v.start, v.end, v.mempolicy.is_some()))
                .collect()
        };
        mbind_vmas(&mut m, 0x11000, 0x13000, Some(bind)).unwrap();
        assert_eq!(
            spans(&m),
            [
                (0x10000, 0x11000, false),
                (0x11000, 0x13000, true),
                (0x13000, 0x14000, false)
            ]
        );
        // The same policy again: no change
        mbind_vmas(&mut m, 0x11000, 0x12000, Some(bind)).unwrap();
        assert_eq!(m.iter().count(), 3);
        // Default over all of it: one VMA again
        mbind_vmas(&mut m, 0x10000, 0x14000, None).unwrap();
        assert_eq!(spans(&m), [(0x10000, 0x14000, false)]);
    }

    #[test]
    fn equal() {
        let a = mpol_set_nodemask(mpol_new(MPOL_BIND, 0, 1).unwrap().unwrap(), 1, 1).unwrap();
        let mut b = a;
        assert!(mpol_equal(Some(&a), Some(&b)));
        assert!(!mpol_equal(Some(&a), None));
        assert!(mpol_equal(None, None));
        b.nodes = 3;
        assert!(!mpol_equal(Some(&a), Some(&b)));
    }
}
