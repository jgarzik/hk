//! Network device tests: /proc/net/dev, loopback counters, eth0 RX
//!
//! - PROC_NET_DEV: Linux header and an `lo:` line (both kernels)
//! - LO_COUNTERS: UDP over 127.0.0.1 raises lo rx/tx packets (both)
//! - NETNS_PROC_NET_DEV: a new network namespace lists only lo (both)
//! - ETH0_DNS (hk only; Linux harness has no NIC yet): a DNS query to the
//!   QEMU slirp resolver 10.0.2.3:53 over eth0 gets a reply, which proves
//!   ARP + TX + RX + IRQ + DMA end to end

use hk_syscall::{
    sys_bind, sys_close, sys_exit, sys_fork, sys_open, sys_poll, sys_read, sys_recvfrom,
    sys_sendto, sys_socket, sys_unshare, sys_wait4, htonl, htons, make_ipv4, PollFd, SockAddrIn,
    AF_INET, CLONE_NEWNET, O_RDONLY, POLLIN, SOCK_DGRAM,
};

use super::helpers::{host_mode, print, print_num, println, skip};

pub fn run_tests() {
    println(b"=== Netdev Tests ===");
    test_proc_net_dev();
    test_lo_counters();
    test_netns_proc_net_dev();
    test_eth0_dns();
}

/// Read /proc/net/dev into `buf`; returns the length (or <0)
fn read_proc_net_dev(buf: &mut [u8]) -> i64 {
    let fd = sys_open(b"/proc/net/dev\0".as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return fd;
    }
    let mut total = 0usize;
    loop {
        let n = sys_read(fd as u64, buf[total..].as_mut_ptr(), (buf.len() - total) as u64);
        if n <= 0 {
            break;
        }
        total += n as usize;
        if total == buf.len() {
            break;
        }
    }
    sys_close(fd as u64);
    total as i64
}

/// Find the line for interface `name` ("lo", "eth0"): returns its 16
/// counters (rx bytes, packets, errs, drop, fifo, frame, compressed,
/// multicast, tx bytes, packets, errs, drop, fifo, colls, carrier,
/// compressed)
fn dev_counters(text: &[u8], name: &[u8]) -> Option<[u64; 16]> {
    for line in text.split(|&b| b == b'\n') {
        let colon = match line.iter().position(|&b| b == b':') {
            Some(c) => c,
            None => continue,
        };
        let ifname = trim(&line[..colon]);
        if ifname != name {
            continue;
        }
        let mut vals = [0u64; 16];
        let mut n = 0;
        for field in line[colon + 1..].split(|&b| b == b' ').filter(|f| !f.is_empty()) {
            if n == 16 {
                return None;
            }
            let mut v = 0u64;
            for &c in field {
                if !c.is_ascii_digit() {
                    return None;
                }
                v = v * 10 + (c - b'0') as u64;
            }
            vals[n] = v;
            n += 1;
        }
        return if n == 16 { Some(vals) } else { None };
    }
    None
}

fn trim(s: &[u8]) -> &[u8] {
    let a = s.iter().position(|&b| b != b' ').unwrap_or(s.len());
    let b = s.iter().rposition(|&b| b != b' ').map_or(a, |p| p + 1);
    &s[a..b]
}

fn test_proc_net_dev() {
    let mut buf = [0u8; 4096];
    let n = read_proc_net_dev(&mut buf);
    if n <= 0 {
        print(b"PROC_NET_DEV:FAIL open/read ");
        print_num(n);
        println(b"");
        return;
    }
    let text = &buf[..n as usize];
    let header_ok = text.starts_with(b"Inter-|   Receive")
        && text
            .windows(b" face |bytes    packets errs drop".len())
            .any(|w| w == b" face |bytes    packets errs drop");
    if !header_ok {
        println(b"PROC_NET_DEV:FAIL header");
        return;
    }
    if dev_counters(text, b"lo").is_none() {
        println(b"PROC_NET_DEV:FAIL no lo line");
        return;
    }
    println(b"PROC_NET_DEV:OK");
}

fn lo_counters() -> Option<[u64; 16]> {
    let mut buf = [0u8; 4096];
    let n = read_proc_net_dev(&mut buf);
    if n <= 0 {
        return None;
    }
    dev_counters(&buf[..n as usize], b"lo")
}

fn sockaddr(a: u8, b: u8, c: u8, d: u8, port: u16) -> SockAddrIn {
    SockAddrIn::new(AF_INET as u16, htons(port), htonl(make_ipv4(a, b, c, d)))
}

/// Wait up to `ms` for `fd` to become readable
fn wait_readable(fd: i32, ms: i32) -> bool {
    let mut pfd = PollFd::new(fd, POLLIN);
    sys_poll(&mut pfd, 1, ms) == 1 && pfd.revents & POLLIN != 0
}

fn test_lo_counters() {
    const PORT: u16 = 8971;
    let Some(before) = lo_counters() else {
        println(b"LO_COUNTERS:FAIL no lo counters");
        return;
    };

    let fd = sys_socket(AF_INET, SOCK_DGRAM, 0);
    if fd < 0 {
        println(b"LO_COUNTERS:FAIL socket");
        return;
    }
    let fd = fd as i32;
    let addr = sockaddr(127, 0, 0, 1, PORT);
    let alen = core::mem::size_of::<SockAddrIn>() as u32;
    if sys_bind(fd, &addr as *const SockAddrIn as *const u8, alen) != 0 {
        sys_close(fd as u64);
        println(b"LO_COUNTERS:FAIL bind");
        return;
    }
    let msg = b"lo counter probe";
    let sent = sys_sendto(fd, msg.as_ptr(), msg.len(), 0, &addr as *const SockAddrIn as *const u8, alen);
    let mut rbuf = [0u8; 64];
    let got = if wait_readable(fd, 5000) {
        sys_recvfrom(fd, rbuf.as_mut_ptr(), rbuf.len(), 0, core::ptr::null_mut(), core::ptr::null_mut())
    } else {
        -11
    };
    sys_close(fd as u64);
    if sent != msg.len() as i64 || got != msg.len() as i64 || &rbuf[..msg.len()] != msg {
        print(b"LO_COUNTERS:FAIL loopback datagram sent=");
        print_num(sent);
        print(b" got=");
        print_num(got);
        println(b"");
        return;
    }

    let Some(after) = lo_counters() else {
        println(b"LO_COUNTERS:FAIL no lo counters after");
        return;
    };
    // rx/tx packets (fields 1 and 9) and bytes (0 and 8) must grow
    let grew = after[1] > before[1] && after[9] > before[9] && after[0] > before[0] && after[8] > before[8];
    if grew {
        println(b"LO_COUNTERS:OK");
    } else {
        print(b"LO_COUNTERS:FAIL rx_packets ");
        print_num(before[1] as i64);
        print(b"->");
        print_num(after[1] as i64);
        print(b" tx_packets ");
        print_num(before[9] as i64);
        print(b"->");
        print_num(after[9] as i64);
        println(b"");
    }
}

/// A fresh network namespace has exactly one device, lo
fn test_netns_proc_net_dev() {
    let pid = sys_fork();
    if pid < 0 {
        println(b"NETNS_PROC_NET_DEV:FAIL fork");
        return;
    }
    if pid == 0 {
        if sys_unshare(CLONE_NEWNET) != 0 {
            sys_exit(2);
        }
        let mut buf = [0u8; 4096];
        let n = read_proc_net_dev(&mut buf);
        if n <= 0 {
            sys_exit(3);
        }
        let text = &buf[..n as usize];
        let lines = text.split(|&b| b == b'\n').filter(|l| !l.is_empty()).count();
        let ok = lines == 3 && dev_counters(text, b"lo").is_some();
        sys_exit(if ok { 0 } else { 4 });
    }
    let mut status: i32 = 0;
    sys_wait4(pid, &mut status, 0, 0);
    let code = (status >> 8) & 0xff;
    if status & 0x7f == 0 && code == 0 {
        println(b"NETNS_PROC_NET_DEV:OK");
    } else if code == 2 && host_mode() {
        // Unprivileged harness without CAP_SYS_ADMIN
        skip(b"NETNS_PROC_NET_DEV", b"unshare(CLONE_NEWNET) not permitted");
    } else {
        print(b"NETNS_PROC_NET_DEV:FAIL code=");
        print_num(code as i64);
        println(b"");
    }
}

/// Minimal DNS query: A record for "localhost", recursion desired
fn dns_query(id: u16, out: &mut [u8; 64]) -> usize {
    let mut n = 0;
    let mut put = |b: &[u8]| {
        out[n..n + b.len()].copy_from_slice(b);
        n += b.len();
    };
    put(&id.to_be_bytes());
    put(&[0x01, 0x00]); // flags: RD
    put(&[0, 1, 0, 0, 0, 0, 0, 0]); // QDCOUNT=1
    put(&[9]);
    put(b"localhost");
    put(&[0]);
    put(&[0, 1, 0, 1]); // QTYPE=A, QCLASS=IN
    n
}

fn test_eth0_dns() {
    if host_mode() {
        skip(b"ETH0_DNS", b"no NIC in the Linux harness");
        return;
    }
    let mut buf = [0u8; 4096];
    let n = read_proc_net_dev(&mut buf);
    let Some(eth_before) = (if n > 0 { dev_counters(&buf[..n as usize], b"eth0") } else { None }) else {
        println(b"ETH0_DNS:FAIL no eth0 in /proc/net/dev");
        return;
    };

    let fd = sys_socket(AF_INET, SOCK_DGRAM, 0);
    if fd < 0 {
        println(b"ETH0_DNS:FAIL socket");
        return;
    }
    let fd = fd as i32;
    let server = sockaddr(10, 0, 2, 3, 53);
    let alen = core::mem::size_of::<SockAddrIn>() as u32;
    let mut q = [0u8; 64];
    let mut reply = [0u8; 512];
    let mut got = -1i64;
    let mut id = 0x4b31u16;
    // A few tries: the first query also waits for ARP resolution
    for _ in 0..3 {
        let qlen = dns_query(id, &mut q);
        let s = sys_sendto(fd, q.as_ptr(), qlen, 0, &server as *const SockAddrIn as *const u8, alen);
        if s != qlen as i64 {
            print(b"ETH0_DNS:FAIL sendto ");
            print_num(s);
            println(b"");
            sys_close(fd as u64);
            return;
        }
        if wait_readable(fd, 3000) {
            got = sys_recvfrom(fd, reply.as_mut_ptr(), reply.len(), 0, core::ptr::null_mut(), core::ptr::null_mut());
            if got >= 12 && u16::from_be_bytes([reply[0], reply[1]]) == id {
                break;
            }
        }
        id = id.wrapping_add(1);
    }
    sys_close(fd as u64);

    let n = read_proc_net_dev(&mut buf);
    let eth_after = if n > 0 { dev_counters(&buf[..n as usize], b"eth0") } else { None };
    let (rx, tx) = match eth_after {
        Some(a) => (a[1] - eth_before[1], a[9] - eth_before[9]),
        None => (0, 0),
    };
    let reply_ok = got >= 12 && u16::from_be_bytes([reply[0], reply[1]]) == id && reply[2] & 0x80 != 0;
    if reply_ok {
        print(b"eth0: DNS reply ");
        print_num(got);
        print(b" bytes, rcode=");
        print_num((reply[3] & 0x0f) as i64);
        print(b", eth0 rx+");
        print_num(rx as i64);
        print(b" tx+");
        print_num(tx as i64);
        println(b"");
        println(b"ETH0_DNS:OK");
    } else {
        print(b"ETH0_DNS:FAIL no reply (recv=");
        print_num(got);
        print(b", eth0 rx+");
        print_num(rx as i64);
        print(b" tx+");
        print_num(tx as i64);
        println(b")");
    }
}
