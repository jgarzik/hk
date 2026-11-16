//! TCP memory accounting (Linux tcp_memory_allocated, sysctl_tcp_mem,
//! tcp_memory_pressure, tcp_sockets_allocated; the policy is
//! `TcpCb::mem_schedule`, Linux __sk_mem_raise_allocated).
//!
//! Global, as Linux: one count of the quanta all connections' queues
//! hold, limited by `tcp_mem` (min, pressure, max) sized from RAM at
//! boot (tcp_init_mem) and set through /proc/sys/net/ipv4/tcp_mem.
//! Connections add before their queues grow and subtract on failure, so
//! a check never races its charge. Each CPU batches its changes in a
//! forward reserve and moves it to the global count past
//! net.core.mem_pcpu_rsv either way (Linux per_cpu_fw_alloc), so the
//! shared count is touched once per megabyte, not per segment; the
//! limits are checked against the global count, which lags by up to the
//! reserve per CPU, as Linux. Relaxed throughout: these are counts and a
//! mode flag, publishing no other data.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicIsize, AtomicU64, AtomicUsize, Ordering};

use crate::cpu::PerCpu;

use crate::util::error::KernelError;

/// Accounting quantum (Linux PAGE_SIZE: sk_forward_alloc is charged in
/// whole pages)
pub const QUANTUM: usize = 4096;

/// Quanta held by all connections, less what the CPUs' reserves hold
/// (Linux tcp_memory_allocated)
static ALLOCATED: AtomicIsize = AtomicIsize::new(0);
/// Each CPU's changes not yet in `ALLOCATED` (Linux
/// tcp_memory_per_cpu_fw_alloc). An atomic RMW on the slot, so a task
/// moved to another CPU between two steps only changes that CPU's
/// reserve (Linux this_cpu ops)
static FW_ALLOC: PerCpu<AtomicIsize> = crate::percpu![AtomicIsize::new(0)];
/// Linux SK_MEMORY_PCPU_RESERVE: 1 MiB in quanta, the default and the
/// least net.core.mem_pcpu_rsv takes
const PCPU_RSV_MIN: i32 = (1 << 20) / QUANTUM as i32;
/// net.core.mem_pcpu_rsv
static PCPU_RSV: AtomicI32 = AtomicI32::new(PCPU_RSV_MIN);
/// tcp_mem in quanta; the boot value is the floor tcp_init_mem
/// allows (128) until `init` sizes it
static LIMITS: [AtomicUsize; 3] = [
    AtomicUsize::new(96),
    AtomicUsize::new(128),
    AtomicUsize::new(192),
];
/// Linux tcp_memory_pressure: past tcp_mem[1], until back under [0];
/// when it began (ms, never 0), 0 when off
static PRESSURE: AtomicU64 = AtomicU64::new(0);
/// TCP control blocks alive (Linux tcp_sockets_allocated)
static SOCKETS: AtomicUsize = AtomicUsize::new(0);
/// Orphaned connections, every namespace's, per CPU (Linux
/// tcp_orphan_count): a part may go negative, the sum does not
static ORPHANS: PerCpu<AtomicIsize> = crate::percpu![AtomicIsize::new(0)];

/// Quanta covering `bytes` (Linux sk_mem_pages)
pub fn quanta(bytes: usize) -> usize {
    bytes.div_ceil(QUANTUM)
}

/// Size tcp_mem from free memory (Linux tcp_init_mem: 1/16 of the
/// buffer pages, at least 128, as 3/4 : 1 : 3/2 of it)
pub fn init() {
    let limit = (crate::FRAME_ALLOCATOR.buffer_pages() / 16).max(128);
    set_limits([limit / 4 * 3, limit, limit / 4 * 3 * 2]);
}

fn set_limits(v: [usize; 3]) {
    for (l, x) in LIMITS.iter().zip(v) {
        l.store(x, Ordering::Relaxed);
    }
}

/// tcp_mem[i] (Linux sk_prot_mem_limits)
pub fn limit(i: usize) -> usize {
    LIMITS[i].load(Ordering::Relaxed)
}

fn rsv() -> isize {
    PCPU_RSV.load(Ordering::Relaxed) as isize
}

/// Add `amt` quanta (Linux sk_memory_allocated_add)
pub fn add(amt: usize) {
    let v = FW_ALLOC.this().fetch_add(amt as isize, Ordering::Relaxed) + amt as isize;
    if v >= rsv() {
        drain();
    }
}

/// Give back `amt` quanta (Linux sk_memory_allocated_sub)
pub fn sub(amt: usize) {
    let v = FW_ALLOC.this().fetch_sub(amt as isize, Ordering::Relaxed) - amt as isize;
    if v <= -rsv() {
        drain();
    }
}

/// Move this CPU's reserve to the global count (Linux
/// proto_memory_pcpu_drain)
fn drain() {
    let v = FW_ALLOC.this().swap(0, Ordering::Relaxed);
    if v != 0 {
        ALLOCATED.fetch_add(v, Ordering::Relaxed);
    }
}

/// Quanta held, as the limits see it (Linux sk_memory_allocated /
/// proto_memory_allocated: the global count, never below 0)
pub fn allocated() -> usize {
    ALLOCATED.load(Ordering::Relaxed).max(0) as usize
}

pub fn under_pressure() -> bool {
    PRESSURE.load(Ordering::Relaxed) != 0
}

/// Linux tcp_enter_memory_pressure (a mode, not a decision; the load
/// spares the cache line): true for the one caller that began it
pub fn enter_pressure() -> bool {
    if PRESSURE.load(Ordering::Relaxed) != 0 {
        return false;
    }
    let now = super::timer::now_ms().max(1);
    PRESSURE
        .compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

/// Linux tcp_leave_memory_pressure: how long it lasted (ms), for the
/// one caller that ended it
pub fn leave_pressure() -> Option<u64> {
    if PRESSURE.load(Ordering::Relaxed) == 0 {
        return None;
    }
    match PRESSURE.swap(0, Ordering::Relaxed) {
        0 => None,
        t => Some(super::timer::now_ms().saturating_sub(t)),
    }
}

pub fn sockets() -> usize {
    SOCKETS.load(Ordering::Relaxed)
}

/// Orphaned connections (Linux tcp_orphan_count_sum)
pub fn orphans() -> usize {
    let n: isize = ORPHANS
        .for_each_possible()
        .map(|(_, c)| c.load(Ordering::Relaxed))
        .sum();
    n.max(0) as usize
}

/// A connection counted as an orphan (closed by its owner, or a child
/// its listener let go) until it is destroyed or dropped (Linux
/// this_cpu_inc(tcp_orphan_count) in __tcp_close and
/// inet_child_forget, the dec in inet_csk_destroy_sock)
pub struct Orphan(());

impl Orphan {
    pub fn new() -> Self {
        ORPHANS.this().fetch_add(1, Ordering::Relaxed);
        Self(())
    }
}

impl Drop for Orphan {
    fn drop(&mut self) {
        ORPHANS.this().fetch_sub(1, Ordering::Relaxed);
    }
}

/// A connection's quanta in the global count: the queues' bytes rounded
/// up, never more (Linux sk_forward_alloc, reclaimed below a page on
/// every uncharge). Counts the socket while it lives (Linux
/// sk_sockets_allocated_inc/dec) and returns the quanta on drop.
pub struct Held(usize);

impl Held {
    /// Quanta held
    pub fn get(&self) -> usize {
        self.0
    }

    /// Hold `n` quanta: the caller has added or subtracted the change
    pub fn set(&mut self, n: usize) {
        self.0 = n;
    }
}

impl Default for Held {
    fn default() -> Self {
        SOCKETS.fetch_add(1, Ordering::Relaxed);
        Self(0)
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        sub(self.0);
        SOCKETS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A connection with `wmem` bytes of its own queued while the total is
/// past the hard limit (Linux tcp_out_of_memory: SOCK_MIN_SNDBUF, half
/// of it in hk's byte counts)
pub fn out_of_memory(wmem: usize) -> bool {
    wmem > crate::net::sock::MIN_SNDBUF as usize / 2 && allocated() > limit(2)
}

/// /proc/sys/net/ipv4/tcp_mem
pub fn sysctl_show() -> Vec<i64> {
    (0..3).map(|i| limit(i) as i64).collect()
}

/// These sysctls are machine-wide: Linux registers them for the initial
/// network namespace only. hk's /proc/sys is one tree, so another
/// namespace sees them, but may not change them (EPERM: CAP_NET_ADMIN
/// over a container's own namespace is no right over the host's TCP)
fn init_net_only() -> Result<(), KernelError> {
    let net = crate::net::current_net_ns();
    if net.id == crate::net::init_net_ns().id {
        Ok(())
    } else {
        Err(KernelError::NotPermitted)
    }
}

/// /proc/sys/net/core/mem_pcpu_rsv
pub fn rsv_show() -> Vec<i64> {
    alloc::vec![i64::from(PCPU_RSV.load(Ordering::Relaxed))]
}

/// mem_pcpu_rsv write (Linux proc_dointvec_minmax, at least
/// SK_MEMORY_PCPU_RESERVE)
pub fn rsv_store(v: &[i64]) -> Result<(), KernelError> {
    init_net_only()?;
    crate::sysctl::range(v[0], i64::from(PCPU_RSV_MIN), i64::from(i32::MAX))?;
    PCPU_RSV.store(v[0] as i32, Ordering::Relaxed);
    Ok(())
}

/// tcp_mem write (Linux proc_doulongvec_minmax without bounds:
/// negative values are EINVAL)
pub fn sysctl_store(v: &[i64]) -> Result<(), KernelError> {
    init_net_only()?;
    if v.iter().any(|&x| x < 0) {
        return Err(KernelError::InvalidArgument);
    }
    set_limits([v[0] as usize, v[1] as usize, v[2] as usize]);
    Ok(())
}
