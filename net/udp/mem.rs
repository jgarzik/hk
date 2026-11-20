//! UDP memory accounting (Linux udp_memory_allocated,
//! udp_memory_per_cpu_fw_alloc, sysctl_udp_mem; the policy is Linux
//! __sk_mem_raise_allocated / __sk_mem_reduce_allocated for a protocol
//! with no memory pressure state, as udp_prot has none).
//!
//! Global, as Linux: one count of the pages every UDP socket's receive
//! queue holds forward-allocated, limited by `udp_mem` (min, pressure,
//! max) sized from RAM at boot (udp_init) and set through
//! /proc/sys/net/ipv4/udp_mem. Each CPU batches its changes in a
//! forward reserve moved to the global count past net.core.mem_pcpu_rsv
//! either way (Linux sk_memory_allocated_add/sub,
//! proto_memory_pcpu_drain); limits and /proc/net/sockstat read the
//! global count, which lags by up to the reserve per CPU, as Linux.
//! Relaxed throughout: counts publishing no other data.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};

use crate::util::error::KernelError;

/// Accounting quantum (Linux PAGE_SIZE)
pub const QUANTUM: usize = 4096;

/// Pages held by all UDP sockets, less what the CPUs' reserves hold
/// (Linux udp_memory_allocated)
static ALLOCATED: AtomicIsize = AtomicIsize::new(0);
crate::percpu! {
    /// Each CPU's changes not yet in `ALLOCATED` (Linux
    /// udp_memory_per_cpu_fw_alloc): written and drained only by its
    /// CPU, with this_cpu adds
    static FW_ALLOC: AtomicIsize = AtomicIsize::new(0);
}
/// udp_mem in pages; the boot value is udp_init's floor (128) until
/// `init` sizes it
static LIMITS: [AtomicUsize; 3] = [
    AtomicUsize::new(96),
    AtomicUsize::new(128),
    AtomicUsize::new(192),
];

/// Pages covering `bytes` (Linux sk_mem_pages)
pub fn pages(bytes: usize) -> usize {
    bytes.div_ceil(QUANTUM)
}

/// Size udp_mem from free memory (Linux udp_init: 1/8 of the buffer
/// pages, at least 128, as 3/4 : 1 : 3/2 of it)
pub fn init() {
    let limit = (crate::FRAME_ALLOCATOR.buffer_pages() / 8).max(128);
    set_limits([limit / 4 * 3, limit, limit / 4 * 3 * 2]);
}

fn set_limits(v: [usize; 3]) {
    for (l, x) in LIMITS.iter().zip(v) {
        l.store(x, Ordering::Relaxed);
    }
}

/// udp_mem[i] (Linux sk_prot_mem_limits)
fn limit(i: usize) -> usize {
    LIMITS[i].load(Ordering::Relaxed)
}

/// Add `amt` pages (Linux sk_memory_allocated_add)
fn add(amt: usize) {
    let v = FW_ALLOC.this_add_return(amt as i64) as isize;
    if v >= crate::net::tcp::mem::rsv() {
        drain();
    }
}

/// Give back `amt` pages (Linux sk_memory_allocated_sub)
fn sub(amt: usize) {
    let v = FW_ALLOC.this_add_return(-(amt as i64)) as isize;
    if v <= -crate::net::tcp::mem::rsv() {
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

/// The global count as the limits and sockstat see it (Linux
/// sk_memory_allocated / proto_memory_allocated, never below 0)
pub fn allocated() -> usize {
    ALLOCATED.load(Ordering::Relaxed).max(0) as usize
}

/// Charge `amt` more pages to a socket whose queue holds `rmem` bytes
/// (Linux __sk_mem_raise_allocated, SK_MEM_RECV): under udp_mem[0]
/// always, past udp_mem[2] never, between only while the socket holds
/// less than `rmem_min` (net.ipv4.udp_rmem_min); UDP has no pressure
/// state, so no fair-share admission. False: nothing stays charged.
pub fn raise(amt: usize, rmem: usize, rmem_min: usize) -> bool {
    add(amt);
    let a = allocated();
    if a == 0 || a <= limit(0) {
        return true;
    }
    if a <= limit(2) && rmem < rmem_min {
        return true;
    }
    sub(amt);
    false
}

/// Uncharge `amt` pages (Linux __sk_mem_reduce_allocated)
pub fn reduce(amt: usize) {
    sub(amt);
}

/// /proc/sys/net/ipv4/udp_mem
pub fn sysctl_show() -> Vec<i64> {
    (0..3).map(|i| limit(i) as i64).collect()
}

/// udp_mem write (Linux proc_doulongvec_minmax without bounds: negative
/// values are EINVAL). Machine-wide, registered for the initial
/// namespace only (`net::sysctl::INIT_CTLS`: absent elsewhere)
pub fn sysctl_store(v: &[i64]) -> Result<(), KernelError> {
    if v.iter().any(|&x| x < 0) {
        return Err(KernelError::InvalidArgument);
    }
    set_limits([v[0] as usize, v[1] as usize, v[2] as usize]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Linux sk_mem_pages rounds up to whole pages
    #[test]
    fn pages_round_up() {
        assert_eq!(pages(0), 0);
        assert_eq!(pages(1), 1);
        assert_eq!(pages(QUANTUM), 1);
        assert_eq!(pages(QUANTUM + 1), 2);
    }
}
