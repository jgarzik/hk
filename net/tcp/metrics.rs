//! The Fast Open cookie cache of tcp_metrics (Linux v6.8
//! net/ipv4/tcp_metrics.c: tcp_metrics_block's tcpm_fastopen,
//! tcp_fastopen_cache_get / tcp_fastopen_cache_set)
//!
//! One table for every namespace (Linux tcp_metrics_hash, keyed by
//! source and destination address and namespace, hashed by destination
//! and net_hash_mix): 16 Ki buckets with at least 512 MiB of memory,
//! else 8 Ki (tcp_metrics_init); a chain grows to
//! `RECLAIM_DEPTH` + 1 entries, then a new destination takes over the
//! oldest one's block, its Fast Open state cleared (tcpm_new's reclaim).
//! Each bucket is a spin leaf (Linux: tcp_metrics_lock and RCU for the
//! chains, fastopen_seqlock for these fields); entries are allocated
//! GFP_ATOMIC under it. hk keeps only the Fast Open fields: the rest of
//! tcp_metrics (RTT, cwnd, ssthresh, reordering, the TCP_METRICS
//! genetlink family) is missing.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::cb::Foc;
use crate::mm::page_alloc::Gfp;
use crate::net::NetNamespace;
use crate::net::ipv4::Ipv4Addr;
use crate::sync::spin::Mutex;
use crate::util::kalloc::with_gfp;

/// Linux TCP_METRICS_RECLAIM_DEPTH
const RECLAIM_DEPTH: usize = 5;
/// Linux TCP_METRICS_TIMEOUT (ms): an older block is refreshed
const TIMEOUT: u64 = 60 * 60 * 1000;

/// A block's Fast Open state (Linux struct tcp_fastopen_metrics)
#[derive(Clone, Copy)]
struct Entry {
    net: usize,
    saddr: u32,
    daddr: u32,
    /// Linux tcpm_stamp (ms)
    stamp: u64,
    mss: u16,
    syn_loss: u16,
    try_exp: u16,
    last_syn_loss: u64,
    cookie: Foc,
}

struct Table {
    buckets: Box<[Mutex<Vec<Entry>>]>,
    log: u32,
}

static TABLE: spin::Once<Table> = spin::Once::new();

/// Size the table (Linux tcp_metrics_init: 16 Ki slots with at least
/// 128 Ki pages, else 8 Ki)
pub fn init() {
    let slots: usize = if crate::FRAME_ALLOCATOR.buffer_pages() >= 128 * 1024 {
        16 * 1024
    } else {
        8 * 1024
    };
    let mut v = Vec::new();
    v.resize_with(slots, || Mutex::new(Vec::new()));
    TABLE.call_once(|| Table {
        buckets: v.into_boxed_slice(),
        log: slots.trailing_zeros(),
    });
}

/// The namespace's identity in the table (as `table::net_id`)
fn net_id(net: &NetNamespace) -> usize {
    core::ptr::from_ref(&net.tcp).addr()
}

/// A namespace as the table knows it: its identity and hash mix
#[derive(Clone, Copy)]
pub struct Key {
    id: usize,
    mix: u32,
}

impl Key {
    pub fn of(net: &NetNamespace) -> Self {
        Self {
            id: net_id(net),
            mix: net.hash_mix,
        }
    }
}

/// Linux: ipv4_addr_hash(daddr) ^ net_hash_mix(net), hash_32
fn bucket(t: &Table, net: Key, daddr: Ipv4Addr) -> &Mutex<Vec<Entry>> {
    let h = daddr.0.to_be() ^ net.mix;
    let i = h.wrapping_mul(0x61C8_8647) >> (32 - t.log);
    &t.buckets[i as usize]
}

/// Linux tcpm_check_stamp: a block older than TCP_METRICS_TIMEOUT is
/// refreshed (tcpm_suck_dst without clearing Fast Open)
fn check_stamp(e: &mut Entry, now: u64) {
    if now > e.stamp + TIMEOUT {
        e.stamp = now;
    }
}

/// What a connection from `saddr` to `daddr` reads (Linux
/// tcp_fastopen_cache_get): the cached MSS (0: none) and cookie (length
/// 0: none yet; `exp` when the experimental option should be tried)
pub fn cache_get(net: Key, saddr: Ipv4Addr, daddr: Ipv4Addr, now: u64) -> (u16, Foc) {
    let Some(t) = TABLE.get() else {
        return (0, Foc::default());
    };
    let id = net.id;
    let mut b = bucket(t, net, daddr).lock();
    let Some(e) = b
        .iter_mut()
        .find(|e| e.net == id && e.saddr == saddr.0 && e.daddr == daddr.0)
    else {
        return (0, Foc::default());
    };
    check_stamp(e, now);
    let mut c = e.cookie;
    if c.len == 0 && e.try_exp == 1 {
        c.exp = true;
    }
    (e.mss, c)
}

/// Linux tcp_fastopen_cache_set: note the SYN-ACK's MSS and cookie
/// (`cookie` None or empty: keep the old one, maybe switch option
/// format, `try_exp`) and whether the SYN was lost, creating the block
#[allow(clippy::too_many_arguments)]
pub fn cache_set(
    net: Key,
    saddr: Ipv4Addr,
    daddr: Ipv4Addr,
    mss: u16,
    cookie: Option<Foc>,
    syn_lost: bool,
    try_exp: u16,
    now: u64,
) {
    let Some(t) = TABLE.get() else {
        return;
    };
    let id = net.id;
    let mut b = bucket(t, net, daddr).lock();
    let pos = b
        .iter()
        .position(|e| e.net == id && e.saddr == saddr.0 && e.daddr == daddr.0);
    let fresh = Entry {
        net: id,
        saddr: saddr.0,
        daddr: daddr.0,
        stamp: now,
        mss: 0,
        syn_loss: 0,
        try_exp: 0,
        last_syn_loss: 0,
        cookie: Foc::default(),
    };
    let i = match pos {
        Some(i) => {
            check_stamp(&mut b[i], now);
            i
        }
        // tcp_get_encode: past RECLAIM_DEPTH the oldest block is taken
        None if b.len() > RECLAIM_DEPTH => {
            let (i, _) = b
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.stamp)
                .unwrap_or((0, &fresh));
            b[i] = fresh;
            i
        }
        None => {
            if with_gfp(Gfp::ATOMIC, || b.try_reserve(1)).is_err() {
                return;
            }
            b.push(fresh);
            b.len() - 1
        }
    };
    let e = &mut b[i];
    if mss != 0 {
        e.mss = mss;
    }
    match cookie {
        Some(c) if c.len > 0 => e.cookie = c,
        _ if try_exp > e.try_exp && e.cookie.len == 0 && !e.cookie.exp => e.try_exp = try_exp,
        _ => {}
    }
    if syn_lost {
        e.syn_loss = e.syn_loss.wrapping_add(1);
        e.last_syn_loss = now;
    } else {
        e.syn_loss = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cookie is kept per destination; an empty one leaves it; a
    /// failed request switches the option format (try_exp)
    #[test]
    fn cookie_cache() {
        init();
        let net = Key { id: 1, mix: 7 };
        let (s, d) = (Ipv4Addr(0x0a00_0001), Ipv4Addr(0x0a00_0002));
        assert_eq!(cache_get(net, s, d, 0), (0, Foc::default()));
        let mut c = Foc {
            len: 8,
            ..Foc::default()
        };
        c.val[0] = 5;
        cache_set(net, s, d, 1460, Some(c), false, 0, 0);
        assert_eq!(cache_get(net, s, d, 0), (1460, c));
        cache_set(net, s, d, 0, None, false, 0, 0);
        assert_eq!(cache_get(net, s, d, 0), (1460, c));
        let d2 = Ipv4Addr(0x0a00_0003);
        cache_set(net, s, d2, 0, None, false, 1, 0);
        assert!(cache_get(net, s, d2, 0).1.exp);
    }
}
