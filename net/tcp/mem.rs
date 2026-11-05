//! TCP memory accounting (Linux tcp_memory_allocated, sysctl_tcp_mem,
//! tcp_memory_pressure, tcp_sockets_allocated; the policy is
//! `TcpCb::mem_schedule`, Linux __sk_mem_raise_allocated).
//!
//! Global, as Linux: one count of the quanta all connections' queues
//! hold, limited by `tcp_mem` (min, pressure, max) sized from RAM at
//! boot (tcp_init_mem) and set through /proc/sys/net/ipv4/tcp_mem.
//! Connections add before their queues grow and subtract on failure, so
//! a check never races its charge. Relaxed throughout: these are counts
//! and a mode flag, publishing no other data.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::util::error::KernelError;

/// Accounting quantum (Linux PAGE_SIZE: sk_forward_alloc is charged in
/// whole pages)
pub const QUANTUM: usize = 4096;

/// Quanta held by all connections
static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
/// tcp_mem in quanta; the boot value is the floor tcp_init_mem
/// allows (128) until `init` sizes it
static LIMITS: [AtomicUsize; 3] = [
    AtomicUsize::new(96),
    AtomicUsize::new(128),
    AtomicUsize::new(192),
];
/// Linux tcp_memory_pressure: past tcp_mem[1], until back under [0]
static PRESSURE: AtomicBool = AtomicBool::new(false);
/// TCP control blocks alive (Linux tcp_sockets_allocated)
static SOCKETS: AtomicUsize = AtomicUsize::new(0);

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

/// Add `amt` quanta; the new total (Linux sk_memory_allocated_add)
pub fn add(amt: usize) -> usize {
    ALLOCATED.fetch_add(amt, Ordering::Relaxed) + amt
}

/// Give back `amt` quanta (Linux sk_memory_allocated_sub)
pub fn sub(amt: usize) {
    ALLOCATED.fetch_sub(amt, Ordering::Relaxed);
}

/// Quanta held now (Linux sk_memory_allocated)
pub fn allocated() -> usize {
    ALLOCATED.load(Ordering::Relaxed)
}

pub fn under_pressure() -> bool {
    PRESSURE.load(Ordering::Relaxed)
}

/// Linux tcp_enter_memory_pressure (a mode, not a decision: racing
/// callers store the same value; the load spares the cache line)
pub fn enter_pressure() {
    if !PRESSURE.load(Ordering::Relaxed) {
        PRESSURE.store(true, Ordering::Relaxed);
    }
}

/// Linux tcp_leave_memory_pressure
pub fn leave_pressure() {
    if PRESSURE.load(Ordering::Relaxed) {
        PRESSURE.store(false, Ordering::Relaxed);
    }
}

pub fn sockets() -> usize {
    SOCKETS.load(Ordering::Relaxed)
}

pub fn socket_inc() {
    SOCKETS.fetch_add(1, Ordering::Relaxed);
}

pub fn socket_dec() {
    SOCKETS.fetch_sub(1, Ordering::Relaxed);
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

/// tcp_mem write (Linux proc_doulongvec_minmax without bounds:
/// negative values are EINVAL)
pub fn sysctl_store(v: &[i64]) -> Result<(), KernelError> {
    if v.iter().any(|&x| x < 0) {
        return Err(KernelError::InvalidArgument);
    }
    set_limits([v[0] as usize, v[1] as usize, v[2] as usize]);
    Ok(())
}
