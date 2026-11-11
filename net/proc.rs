//! /proc/net files (generated per reader's network namespace)

use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::Ordering;

/// `/proc/net/dev`: per-interface counters in Linux's format
/// (net/core/net-procfs.c dev_seq_show), the devices walked under RCU
/// into a fixed buffer (Linux dev_seq_start's rcu_read_lock)
pub fn proc_net_dev() -> Vec<u8> {
    let net = crate::net::current_net_ns();
    crate::fs::proc::seq::generate(|m| {
        let _ = m.write_str(concat!(
            "Inter-|   Receive                                                |  Transmit\n",
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n",
        ));
        let g = crate::sync::rcu::read_lock();
        for dev in net.devices_rcu(&g) {
            dev_seq_show(m, dev);
        }
    })
}

/// One device's line of `/proc/net/dev` (Linux dev_seq_printf_stats)
fn dev_seq_show(m: &mut crate::fs::proc::seq::SeqBuf, dev: &crate::net::device::NetDevice) {
    let s = &dev.stats;
    let g = |a: &core::sync::atomic::AtomicU64| a.load(Ordering::Relaxed);
    let _ = writeln!(
        m,
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

/// `/proc/net/route`: the main table in Linux's legacy format
/// (net/ipv4/fib_trie.c fib_route_seq_show): addresses as the raw
/// network-order u32 in hex, every line padded to 127 columns; the
/// table walked under RCU into a fixed buffer
pub fn proc_net_route() -> Vec<u8> {
    use crate::net::inet::fib::RT_TABLE_MAIN;
    let net = crate::net::current_net_ns();
    crate::fs::proc::seq::generate(|m| {
        let _ = writeln!(
            m,
            "{:<127}",
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT"
        );
        let g = crate::sync::rcu::read_lock();
        if let Some(t) = net.fib.get_table(&g, RT_TABLE_MAIN) {
            for e in t.entries(&g) {
                route_seq_show(m, e);
            }
        }
    })
}

/// One route's line of `/proc/net/route` (Linux fib_route_seq_show)
fn route_seq_show(m: &mut crate::fs::proc::seq::SeqBuf, e: &crate::net::inet::fib::FibEntry) {
    use crate::net::inet::fib::RouteType;
    const RTF_UP: u32 = 0x0001;
    const RTF_GATEWAY: u32 = 0x0002;
    const RTF_HOST: u32 = 0x0004;
    const RTF_REJECT: u32 = 0x0200;
    if matches!(e.rtype, RouteType::Broadcast | RouteType::Multicast) {
        return;
    }
    let raw = |a: crate::net::Ipv4Addr| u32::from_ne_bytes(a.to_be_bytes());
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
    m.setwidth(127);
    let _ = write!(
        m,
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
    m.pad('\n');
}
