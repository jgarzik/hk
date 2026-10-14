//! /proc/net files (generated per reader's network namespace)

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::Ordering;

/// `/proc/net/dev`: per-interface counters in Linux's format
/// (net/core/net-procfs.c dev_seq_show)
pub fn proc_net_dev() -> Vec<u8> {
    let mut out = String::new();
    out.push_str("Inter-|   Receive                                                |  Transmit\n");
    out.push_str(
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n",
    );
    for dev in crate::net::current_net_ns().devices() {
        let s = &dev.stats;
        let g = |a: &core::sync::atomic::AtomicU64| a.load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "{:>6}:{:8} {:7} {:4} {:4} {:4} {:5} {:10} {:9} {:8} {:7} {:4} {:4} {:4} {:5} {:7} {:10}",
            dev.name(),
            g(&s.rx_bytes),
            g(&s.rx_packets),
            g(&s.rx_errors),
            g(&s.rx_dropped),
            0, // fifo
            0, // frame
            0, // compressed
            g(&s.multicast),
            g(&s.tx_bytes),
            g(&s.tx_packets),
            g(&s.tx_errors),
            g(&s.tx_dropped),
            0, // fifo
            g(&s.collisions),
            0, // carrier
            0, // compressed
        );
    }
    out.into_bytes()
}
