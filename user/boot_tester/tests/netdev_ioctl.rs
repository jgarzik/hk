//! SIOC* interface ioctls and /proc/net/route (hk and Linux)
//!
//! Link queries/changes on lo and the first Ethernet link, classful
//! SIOCSIFADDR + netmask/broadcast, SIOCGIFCONF sizing, SIOCADDRT/DELRT
//! with struct rtentry, the /proc/net/route format, EFAULT and EPERM.
//! Leaves the Ethernet link down without addresses.

use hk_syscall::{
    AF_INET, MAP_PRIVATE, O_CREAT, O_RDONLY, O_RDWR, O_TRUNC, PROT_READ, SOCK_DGRAM, SOCK_RAW,
    sys_close, sys_exit, sys_fork, sys_ioctl, sys_mmap, sys_munmap, sys_open, sys_read, sys_socket,
    sys_unlink, sys_wait4, sys_write,
};

use super::helpers::{print, print_num, println};
use super::netlink::drop_caps;
use super::nl::{AF_NETLINK, NETLINK_ROUTE};

const SIOCADDRT: u64 = 0x890B;
const SIOCDELRT: u64 = 0x890C;
const SIOCGIFNAME: u64 = 0x8910;
const SIOCGIFCONF: u64 = 0x8912;
const SIOCGIFFLAGS: u64 = 0x8913;
const SIOCSIFFLAGS: u64 = 0x8914;
const SIOCGIFADDR: u64 = 0x8915;
const SIOCSIFADDR: u64 = 0x8916;
const SIOCGIFBRDADDR: u64 = 0x8919;
const SIOCGIFNETMASK: u64 = 0x891B;
const SIOCSIFNETMASK: u64 = 0x891C;
const SIOCGIFMTU: u64 = 0x8921;
const SIOCSIFMTU: u64 = 0x8922;
const SIOCGIFHWADDR: u64 = 0x8927;
const SIOCGIFINDEX: u64 = 0x8933;

const IFF_UP: u16 = 0x1;
const IFF_LOOPBACK: u16 = 0x8;
const IFF_RUNNING: u16 = 0x40;
const RTF_UP: u16 = 0x1;
const RTF_GATEWAY: u16 = 0x2;

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EFAULT: i64 = -14;
const EEXIST: i64 = -17;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;
const EAFNOSUPPORT: i64 = -97;
const EADDRNOTAVAIL: i64 = -99;

pub fn run_tests() {
    println(b"=== Netdev ioctl Tests ===");
    let fd = sys_socket(AF_INET, SOCK_DGRAM, 0) as i32;
    if fd < 0 {
        println(b"IOC_SOCKET:FAIL");
        return;
    }
    let eth = find_ether(fd);
    test_index_name(fd);
    test_lo(fd);
    test_eth_link(fd, &eth);
    test_eth_addr(fd, &eth);
    test_ifconf(fd);
    test_rt(fd, &eth);
    test_rt_dev_fault(fd);
    test_proc_route();
    test_netlink_fd();
    test_errors(fd, &eth);
    sys_close(fd as u64);
}

/// struct ifreq
#[derive(Clone, Copy)]
struct Ifr([u8; 40]);

impl Ifr {
    fn named(name: &[u8]) -> Self {
        let mut r = [0u8; 40];
        r[..name.len()].copy_from_slice(name);
        Ifr(r)
    }
    fn i32(&self) -> i32 {
        i32::from_ne_bytes([self.0[16], self.0[17], self.0[18], self.0[19]])
    }
    fn set_i32(&mut self, v: i32) {
        self.0[16..20].copy_from_slice(&v.to_ne_bytes());
    }
    fn short(&self) -> u16 {
        u16::from_ne_bytes([self.0[16], self.0[17]])
    }
    fn set_short(&mut self, v: u16) {
        self.0[16..18].copy_from_slice(&v.to_ne_bytes());
    }
    fn sin(&self) -> [u8; 4] {
        [self.0[20], self.0[21], self.0[22], self.0[23]]
    }
    fn set_sin(&mut self, a: [u8; 4]) {
        self.0[16..40].fill(0);
        self.0[16..18].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
        self.0[20..24].copy_from_slice(&a);
    }
    fn name(&self) -> &[u8] {
        let n = self.0[..16].iter().position(|&c| c == 0).unwrap_or(16);
        &self.0[..n]
    }
}

fn ioc(fd: i32, cmd: u64, r: &mut Ifr) -> i64 {
    sys_ioctl(fd, cmd, r.0.as_mut_ptr() as u64)
}

fn fail(name: &[u8], why: &[u8], v: i64) {
    print(name);
    print(b":FAIL ");
    print(why);
    print(b" ");
    print_num(v);
    println(b"");
}

fn ok(name: &[u8]) {
    print(name);
    println(b":OK");
}

/// The first Ethernet interface (SIOCGIFNAME over small indices +
/// SIOCGIFHWADDR family ARPHRD_ETHER)
fn find_ether(fd: i32) -> Ifr {
    for idx in 1..32 {
        let mut r = Ifr([0; 40]);
        r.set_i32(idx);
        if ioc(fd, SIOCGIFNAME, &mut r) != 0 {
            continue;
        }
        let mut h = Ifr::named(r.name());
        if ioc(fd, SIOCGIFHWADDR, &mut h) == 0 && h.short() == 1 {
            return Ifr::named(r.name());
        }
    }
    Ifr([0; 40])
}

fn test_index_name(fd: i32) {
    const N: &[u8] = b"IOC_INDEX_NAME";
    let mut r = Ifr::named(b"lo");
    if ioc(fd, SIOCGIFINDEX, &mut r) != 0 || r.i32() != 1 {
        return fail(N, b"lo index", r.i32() as i64);
    }
    let mut r = Ifr([0; 40]);
    r.set_i32(1);
    if ioc(fd, SIOCGIFNAME, &mut r) != 0 || r.name() != b"lo" {
        return fail(N, b"index 1 name", 0);
    }
    r.set_i32(99999);
    let e1 = ioc(fd, SIOCGIFNAME, &mut r);
    let mut r = Ifr::named(b"nosuchif9");
    let e2 = ioc(fd, SIOCGIFINDEX, &mut r);
    if e1 != ENODEV || e2 != ENODEV {
        return fail(N, b"missing device", e1 * 1000 + e2);
    }
    ok(N);
}

fn test_lo(fd: i32) {
    const N: &[u8] = b"IOC_LO";
    let mut r = Ifr::named(b"lo");
    ioc(fd, SIOCGIFFLAGS, &mut r);
    let want = IFF_UP | IFF_LOOPBACK | IFF_RUNNING;
    if r.short() & want != want {
        return fail(N, b"flags", r.short() as i64);
    }
    let mut r = Ifr::named(b"lo");
    if ioc(fd, SIOCGIFADDR, &mut r) != 0 || r.sin() != [127, 0, 0, 1] {
        return fail(N, b"address", 0);
    }
    let mut r = Ifr::named(b"lo");
    if ioc(fd, SIOCGIFNETMASK, &mut r) != 0 || r.sin() != [255, 0, 0, 0] {
        return fail(N, b"netmask", 0);
    }
    let mut r = Ifr::named(b"lo");
    if ioc(fd, SIOCGIFHWADDR, &mut r) != 0 || r.short() != 772 {
        return fail(N, b"hwaddr family", r.short() as i64);
    }
    let mut r = Ifr::named(b"lo");
    if ioc(fd, SIOCGIFMTU, &mut r) != 0 || r.i32() != 65536 {
        return fail(N, b"mtu", r.i32() as i64);
    }
    ok(N);
}

fn set_up(fd: i32, eth: &Ifr, up: bool) -> i64 {
    let mut r = *eth;
    ioc(fd, SIOCGIFFLAGS, &mut r);
    let f = if up {
        r.short() | IFF_UP
    } else {
        r.short() & !IFF_UP
    };
    r.set_short(f);
    ioc(fd, SIOCSIFFLAGS, &mut r)
}

fn test_eth_link(fd: i32, eth: &Ifr) {
    const N: &[u8] = b"IOC_ETH_LINK";
    if eth.name().is_empty() {
        return fail(N, b"no ethernet link", 0);
    }
    let mut r = *eth;
    if ioc(fd, SIOCGIFHWADDR, &mut r) != 0 || r.0[18..24] == [0; 6] {
        return fail(N, b"hwaddr", 0);
    }
    let mut r = *eth;
    if ioc(fd, SIOCGIFFLAGS, &mut r) != 0 || r.short() & IFF_UP != 0 {
        return fail(N, b"initially up", r.short() as i64);
    }
    if set_up(fd, eth, true) != 0 {
        return fail(N, b"set up", 0);
    }
    let mut r = *eth;
    ioc(fd, SIOCGIFFLAGS, &mut r);
    let upf = r.short();
    // MTU round trip and range
    let mut m = *eth;
    m.set_i32(1400);
    let s1 = ioc(fd, SIOCSIFMTU, &mut m);
    let mut g = *eth;
    ioc(fd, SIOCGIFMTU, &mut g);
    let got = g.i32();
    m.set_i32(10);
    let s2 = ioc(fd, SIOCSIFMTU, &mut m);
    m.set_i32(1500);
    ioc(fd, SIOCSIFMTU, &mut m);
    set_up(fd, eth, false);
    let mut r = *eth;
    ioc(fd, SIOCGIFFLAGS, &mut r);
    if upf & IFF_UP == 0 || r.short() & IFF_UP != 0 {
        return fail(N, b"up/down flags", upf as i64);
    }
    if s1 != 0 || got != 1400 || s2 != EINVAL {
        return fail(N, b"mtu", got as i64);
    }
    ok(N);
}

fn test_eth_addr(fd: i32, eth: &Ifr) {
    const N: &[u8] = b"IOC_ETH_ADDR";
    let mut r = *eth;
    if ioc(fd, SIOCGIFADDR, &mut r) != EADDRNOTAVAIL {
        return fail(N, b"unconfigured address", 0);
    }
    // Classful default: 192.0.2.20 -> /24, broadcast .255
    let mut r = *eth;
    r.set_sin([192, 0, 2, 20]);
    if ioc(fd, SIOCSIFADDR, &mut r) != 0 {
        return fail(N, b"SIOCSIFADDR", 0);
    }
    let get = |cmd: u64| {
        let mut r = *eth;
        let e = ioc(fd, cmd, &mut r);
        (e, r.sin())
    };
    let res = (|| -> Result<(), (&'static [u8], i64)> {
        if get(SIOCGIFADDR) != (0, [192, 0, 2, 20]) {
            return Err((b"address", 0));
        }
        if get(SIOCGIFNETMASK) != (0, [255, 255, 255, 0]) {
            return Err((b"classful netmask", 0));
        }
        if get(SIOCGIFBRDADDR) != (0, [192, 0, 2, 255]) {
            return Err((b"broadcast", 0));
        }
        let mut m = *eth;
        m.set_sin([255, 255, 255, 128]);
        if ioc(fd, SIOCSIFNETMASK, &mut m) != 0 {
            return Err((b"SIOCSIFNETMASK", 0));
        }
        if get(SIOCGIFNETMASK) != (0, [255, 255, 255, 128]) {
            return Err((b"new netmask", 0));
        }
        if get(SIOCGIFBRDADDR) != (0, [192, 0, 2, 127]) {
            return Err((b"broadcast follows netmask", 0));
        }
        let mut m = *eth;
        m.set_sin([255, 0, 255, 0]);
        let e = ioc(fd, SIOCSIFNETMASK, &mut m);
        if e != EINVAL {
            return Err((b"non-contiguous netmask", e));
        }
        Ok(())
    })();
    // 0.0.0.0 removes the address
    let mut z = *eth;
    z.set_sin([0, 0, 0, 0]);
    let ez = ioc(fd, SIOCSIFADDR, &mut z);
    if let Err((what, v)) = res {
        return fail(N, what, v);
    }
    if ez != 0 || get(SIOCGIFADDR).0 != EADDRNOTAVAIL {
        return fail(N, b"remove with 0.0.0.0", ez);
    }
    ok(N);
}

fn test_ifconf(fd: i32) {
    const N: &[u8] = b"IOC_IFCONF";
    // struct ifconf { int len; char *buf; }
    let mut ifc = [0u8; 16];
    if sys_ioctl(fd, SIOCGIFCONF, ifc.as_mut_ptr() as u64) != 0 {
        return fail(N, b"size query", 0);
    }
    let need = i32::from_ne_bytes([ifc[0], ifc[1], ifc[2], ifc[3]]);
    if need < 40 || need % 40 != 0 {
        return fail(N, b"size", need as i64);
    }
    let mut buf = [0u8; 400];
    ifc[..4].copy_from_slice(&400i32.to_ne_bytes());
    ifc[8..16].copy_from_slice(&(buf.as_mut_ptr() as u64).to_ne_bytes());
    sys_ioctl(fd, SIOCGIFCONF, ifc.as_mut_ptr() as u64);
    let got = i32::from_ne_bytes([ifc[0], ifc[1], ifc[2], ifc[3]]) as usize;
    let lo = buf[..got.min(400)]
        .chunks(40)
        .any(|e| &e[..3] == b"lo\0" && e[20..24] == [127, 0, 0, 1]);
    if got != need as usize || !lo {
        return fail(N, b"entries", got as i64);
    }
    ok(N);
}

/// struct rtentry (64-bit): dst @8, gateway @24, genmask @40,
/// flags @56, metric @80, dev @88
fn rtentry(dst: [u8; 4], mask: [u8; 4], gw: [u8; 4], flags: u16, dev: *const u8) -> [u8; 120] {
    let mut r = [0u8; 120];
    let sa = |r: &mut [u8; 120], off: usize, a: [u8; 4]| {
        r[off..off + 2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
        r[off + 4..off + 8].copy_from_slice(&a);
    };
    sa(&mut r, 8, dst);
    sa(&mut r, 24, gw);
    sa(&mut r, 40, mask);
    r[56..58].copy_from_slice(&flags.to_ne_bytes());
    r[88..96].copy_from_slice(&(dev as u64).to_ne_bytes());
    r
}

fn read_file(path: &[u8], buf: &mut [u8]) -> usize {
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return 0;
    }
    let mut total = 0;
    loop {
        let n = sys_read(
            fd as u64,
            buf[total..].as_mut_ptr(),
            (buf.len() - total) as u64,
        );
        if n <= 0 {
            break;
        }
        total += n as usize;
        if total == buf.len() {
            break;
        }
    }
    sys_close(fd as u64);
    total
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn test_rt(fd: i32, eth: &Ifr) {
    const N: &[u8] = b"IOC_ROUTE";
    set_up(fd, eth, true);
    let mut a = *eth;
    a.set_sin([192, 0, 2, 20]);
    ioc(fd, SIOCSIFADDR, &mut a);
    let mut rt = rtentry(
        [198, 51, 100, 0],
        [255, 255, 255, 0],
        [192, 0, 2, 1],
        RTF_UP | RTF_GATEWAY,
        core::ptr::null(),
    );
    let p = rt.as_mut_ptr() as u64;
    let add = sys_ioctl(fd, SIOCADDRT, p);
    let dup = sys_ioctl(fd, SIOCADDRT, p);
    let mut text = [0u8; 4096];
    let n = read_file(b"/proc/net/route\0", &mut text);
    // 198.51.100.0 and 192.0.2.1 as raw network-order words (both test
    // arches are little-endian), flags RTF_UP|RTF_GATEWAY
    let line = contains(&text[..n], b"\t006433C6\t010200C0\t0003\t");
    let del = sys_ioctl(fd, SIOCDELRT, p);
    let del2 = sys_ioctl(fd, SIOCDELRT, p);
    let mut bad = rtentry(
        [198, 51, 100, 0],
        [255, 255, 255, 0],
        [0; 4],
        RTF_UP,
        core::ptr::null(),
    );
    bad[8] = 10; // AF_INET6 destination
    let eaf = sys_ioctl(fd, SIOCADDRT, bad.as_mut_ptr() as u64);
    let mut z = *eth;
    z.set_sin([0; 4]);
    ioc(fd, SIOCSIFADDR, &mut z);
    set_up(fd, eth, false);
    if add != 0 || dup != EEXIST {
        return fail(N, b"add/dup", add * 1000 + dup);
    }
    if !line {
        return fail(N, b"/proc/net/route line", n as i64);
    }
    if del != 0 || del2 != ESRCH || eaf != EAFNOSUPPORT {
        return fail(N, b"del/del2/eafnosupport", del);
    }
    ok(N);
}

/// SIOCADDRT/DELRT whose rt_dev name sits in a file page not faulted
/// in yet: Linux copies it under RTNL (rtentry_to_fib_config), so the
/// page fault runs with RTNL held (a sleeping lock)
fn test_rt_dev_fault(fd: i32) {
    const N: &[u8] = b"IOC_ROUTE_DEV_FAULT";
    const PATH: &[u8] = b"/tmp/rt_dev_name\0";
    let f = sys_open(PATH.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o600);
    sys_write(f as u64, b"lo\0".as_ptr(), 3);
    let m = sys_mmap(0, 4096, PROT_READ, MAP_PRIVATE, f as i32, 0);
    sys_close(f as u64);
    sys_unlink(PATH.as_ptr());
    if m < 0 {
        return fail(N, b"mmap", m);
    }
    let mut rt = rtentry(
        [198, 51, 100, 0],
        [255, 255, 255, 0],
        [0; 4],
        RTF_UP,
        m as *const u8,
    );
    let p = rt.as_mut_ptr() as u64;
    let add = sys_ioctl(fd, SIOCADDRT, p);
    let del = sys_ioctl(fd, SIOCDELRT, p);
    sys_munmap(m as u64, 4096);
    if add != 0 || del != 0 {
        return fail(N, b"add/del", add * 1000 + del);
    }
    ok(N);
}

fn test_proc_route() {
    const N: &[u8] = b"PROC_NET_ROUTE";
    let mut text = [0u8; 4096];
    let n = read_file(b"/proc/net/route\0", &mut text);
    let hdr =
        b"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT";
    if n < hdr.len() || &text[..hdr.len()] != hdr {
        return fail(N, b"header", n as i64);
    }
    // Every line is padded to 127 columns
    let first = text[..n].iter().position(|&c| c == b'\n').unwrap_or(0);
    if first != 127 {
        return fail(N, b"line width", first as i64);
    }
    ok(N);
}

/// Link ioctls work on any socket family (Linux dev_ioctl fallback)
fn test_netlink_fd() {
    const N: &[u8] = b"IOC_NETLINK_FD";
    let fd = sys_socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) as i32;
    let mut r = Ifr::named(b"lo");
    let e = ioc(fd, SIOCGIFINDEX, &mut r);
    sys_close(fd as u64);
    if e != 0 || r.i32() != 1 {
        return fail(N, b"SIOCGIFINDEX", e);
    }
    ok(N);
}

fn test_errors(fd: i32, eth: &Ifr) {
    const N: &[u8] = b"IOC_ERRORS";
    // Unmapped ifreq pointer
    let e = sys_ioctl(fd, SIOCGIFFLAGS, 8);
    if e != EFAULT {
        return fail(N, b"EFAULT", e);
    }
    let pid = sys_fork();
    if pid == 0 {
        if !drop_caps() {
            sys_exit(2);
        }
        let mut m = *eth;
        m.set_i32(1400);
        let e1 = ioc(fd, SIOCSIFMTU, &mut m);
        let mut a = *eth;
        a.set_sin([192, 0, 2, 30]);
        let e2 = ioc(fd, SIOCSIFADDR, &mut a);
        let mut g = Ifr::named(b"lo");
        let e3 = ioc(fd, SIOCGIFFLAGS, &mut g);
        sys_exit(if e1 == EPERM && e2 == EPERM && e3 == 0 {
            0
        } else {
            3
        });
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    if st != 0 {
        return fail(N, b"EPERM child status", st as i64);
    }
    ok(N);
}
