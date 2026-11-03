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

/// `/proc/net/route`: the main table in Linux's legacy format
/// (net/ipv4/fib_trie.c fib_route_seq_show): addresses as the raw
/// network-order u32 in hex, every line padded to 127 columns
pub fn proc_net_route() -> Vec<u8> {
    use crate::net::inet::fib::{RT_TABLE_MAIN, RouteType};
    const RTF_UP: u32 = 0x0001;
    const RTF_GATEWAY: u32 = 0x0002;
    const RTF_HOST: u32 = 0x0004;
    const RTF_REJECT: u32 = 0x0200;
    let mut out = String::new();
    let pad = |out: &mut String, line: &str| {
        let _ = writeln!(out, "{:<127}", line);
    };
    pad(
        &mut out,
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT",
    );
    let raw = |a: crate::net::Ipv4Addr| u32::from_ne_bytes(a.to_be_bytes());
    let net = crate::net::current_net_ns();
    for e in net.fib.table(RT_TABLE_MAIN) {
        if matches!(e.rtype, RouteType::Broadcast | RouteType::Multicast) {
            continue;
        }
        let mask = crate::net::inet::ifaddr::inet_make_mask(e.dst_len);
        let mut flags = RTF_UP;
        if matches!(e.rtype, RouteType::Unreachable | RouteType::Prohibit) {
            flags |= RTF_REJECT;
        }
        if e.gateway.is_some() {
            flags |= RTF_GATEWAY;
        }
        if e.dst_len == 32 {
            flags |= RTF_HOST;
        }
        let line = alloc::format!(
            "{}\t{:08X}\t{:08X}\t{:04X}\t{}\t{}\t{}\t{:08X}\t{}\t{}\t{}",
            e.dev.as_ref().map_or("*", |d| d.name()),
            raw(e.dst),
            raw(e.gateway.unwrap_or_default()),
            flags,
            0,
            0,
            e.priority as i32,
            raw(mask),
            0,
            0,
            0
        );
        pad(&mut out, &line);
    }
    out.into_bytes()
}
