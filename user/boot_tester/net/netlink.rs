//! NETLINK_ROUTE tests (hk and Linux): socket/bind semantics, dump
//! shapes, ACK/error codes, link up/down, address and route changes,
//! route get, notifications, PEEK|TRUNC sizing, options, strict dumps,
//! permissions. Assertions are semantic: AF_INET entries are filtered,
//! no byte-exact dumps, ifindex values only for lo (1).
//!
//! Runs before ETH0_DNS configures the Ethernet link, so it starts
//! unconfigured; every test leaves it down without addresses.
//!
//! - NL_AUTOBIND_PIDNS: in a new pid and network namespace, the
//!   autobound port id is the caller's pid there (Linux netlink_autobind:
//!   task_tgid_vnr), 1 for the namespace's init
//! - NL_ADDR_ORDER: addresses dump in Linux's list order (a primary
//!   after the last primary, a secondary last), and NLM_F_REPLACE
//!   changes an address in place
//! - NL_NETNS_ADDR_EXIT: namespaces with addresses, created and left
//!   many times, leave none of them local in the initial namespace

use hk_syscall::{
    _LINUX_CAPABILITY_VERSION_3, CapUserData, CapUserHeader, IoVec, MsgHdr, SOCK_DGRAM, SOCK_RAW,
    SOCK_STREAM, sys_bind, sys_capget, sys_capset, sys_close, sys_exit, sys_fork, sys_getpid,
    sys_getsockname, sys_getsockopt, sys_pidfd_getfd, sys_pidfd_open, sys_pipe2, sys_read,
    sys_recvfrom, sys_recvmsg, sys_sendmsg, sys_sendto, sys_setsockopt, sys_socket, sys_wait4,
    sys_write,
};

use crate::harness::{fail_why, pass};
use crate::helpers::{print, print_num, println};
use crate::net::nl::*;

const EPERM: i32 = -1;
const ESRCH: i32 = -3;
const EFAULT: i32 = -14;
const ENODEV: i32 = -19;
const EEXIST: i32 = -17;
const EINVAL: i32 = -22;
const EBUSY: i32 = -16;
const EAGAIN: i32 = -11;
const ENOBUFS: i32 = -105;
const SOL_SOCKET: i32 = 1;
const SO_RCVBUF: i32 = 8;
const MSG_DONTWAIT: i32 = 0x40;
const EMSGSIZE: i32 = -90;
const ENOPROTOOPT: i32 = -92;
const EPROTONOSUPPORT: i32 = -93;
const ESOCKTNOSUPPORT: i32 = -94;
const EOPNOTSUPP: i32 = -95;
const EADDRINUSE: i32 = -98;
const EADDRNOTAVAIL: i32 = -99;
const ENETUNREACH: i32 = -101;
const MSG_PEEK: i32 = 2;
const MSG_TRUNC: i32 = 0x20;

const TEST_IP: [u8; 4] = [192, 0, 2, 10];
const TEST_GW: [u8; 4] = [192, 0, 2, 1];
const TEST_NET: [u8; 4] = [198, 51, 100, 0];

pub fn run_tests() {
    println(b"=== Netlink Tests ===");
    test_socket();
    test_autobind();
    test_autobind_pidns();
    test_link_dump();
    test_unconfigured();
    test_getlink();
    test_ack();
    test_updown();
    test_addr_route();
    test_addr_order();
    test_netns_addr_exit();
    test_notify();
    test_peek_trunc();
    test_peek_dump();
    test_sockopt();
    test_strict_dump();
    test_other_dumps();
    test_eperm();
    test_overflow();
    test_dump_resume();
    test_overrun();
    test_mtu_negative();
    test_deputy();
    test_dead_receiver();
    test_passcred();
}

/// Check `got == want`, printing a failure; returns success
fn expect(name: &[u8], why: &[u8], got: i32, want: i32) -> bool {
    if got != want {
        fail_why(name, why, got as i64);
        return false;
    }
    true
}

fn test_socket() {
    const N: &[u8] = b"NL_SOCKET";
    for t in [SOCK_RAW, SOCK_DGRAM] {
        let fd = sys_socket(AF_NETLINK, t, NETLINK_ROUTE);
        if fd < 0 {
            return fail_why(N, b"socket", fd);
        }
        sys_close(fd as u64);
    }
    let r = sys_socket(AF_NETLINK, SOCK_RAW, 32) as i32;
    if !expect(N, b"protocol 32", r, EPROTONOSUPPORT) {
        return;
    }
    let r = sys_socket(AF_NETLINK, SOCK_STREAM, NETLINK_ROUTE) as i32;
    if !expect(N, b"SOCK_STREAM", r, ESOCKTNOSUPPORT) {
        return;
    }
    pass(N);
}

/// getsockname: (family, pid, groups)
fn sockname(fd: i32) -> (u16, u32, u32) {
    let mut a = [0u8; 12];
    let mut len: u32 = 12;
    sys_getsockname(fd, a.as_mut_ptr(), &mut len);
    (
        u16::from_ne_bytes([a[0], a[1]]),
        u32::from_ne_bytes([a[4], a[5], a[6], a[7]]),
        u32::from_ne_bytes([a[8], a[9], a[10], a[11]]),
    )
}

/// A namespace's init autobinds to port 1
fn test_autobind_pidns() {
    const CLONE_NEWPID: u64 = 0x2000_0000;
    const CLONE_NEWNET: u64 = 0x4000_0000;
    const SIGCHLD: u64 = 17;
    let y = hk_syscall::sys_clone(CLONE_NEWPID | CLONE_NEWNET | SIGCHLD, 0, 0, 0, 0);
    if y == 0 {
        let fd = sys_socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) as i32;
        let any = nladdr(0, 0);
        let r = sys_bind(fd, any.as_ptr(), 12);
        let port = sockname(fd).1;
        let step = [fd >= 0, r == 0, sys_getpid() == 1, port == 1]
            .iter()
            .position(|ok| !ok)
            .map_or(0, |i| i + 1);
        sys_exit(step as u64);
    }
    let mut st = 0;
    let w = sys_wait4(y, &mut st, 0, 0);
    // The failed step, 100 + a killing signal, 99 if the wait failed
    let step = if w != y {
        99
    } else if st & 0x7f != 0 {
        100 + i64::from(st & 0x7f)
    } else {
        i64::from((st >> 8) & 0xff)
    };
    crate::harness::report_step(b"NL_AUTOBIND_PIDNS", step);
}

fn test_autobind() {
    const N: &[u8] = b"NL_AUTOBIND";
    let a = sys_socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) as i32;
    let b = sys_socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) as i32;
    let c = sys_socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) as i32;
    let done = || {
        sys_close(a as u64);
        sys_close(b as u64);
        sys_close(c as u64);
    };
    let (fam, pid, _) = sockname(a);
    if fam != AF_NETLINK as u16 || pid != 0 {
        done();
        return fail_why(N, b"unbound getsockname pid", pid as i64);
    }
    let any = nladdr(0, 0);
    sys_bind(a, any.as_ptr(), 12);
    sys_bind(b, any.as_ptr(), 12);
    let pa = sockname(a).1;
    let pb = sockname(b).1;
    if pa != sys_getpid() as u32 {
        done();
        return fail_why(N, b"first autobind pid != tgid", pa as i64);
    }
    if (pb as i32) >= 0 || pb == pa {
        done();
        return fail_why(N, b"second autobind pid not negative", pb as i32 as i64);
    }
    // Rebinding to another pid; taking a used pid; short address
    let other = nladdr(pa.wrapping_add(7777), 0);
    let r = sys_bind(a, other.as_ptr(), 12) as i32;
    let taken = nladdr(pa, 0);
    let r2 = sys_bind(c, taken.as_ptr(), 12) as i32;
    let r3 = sys_bind(c, any.as_ptr(), 8) as i32;
    done();
    if expect(N, b"rebind", r, EINVAL)
        && expect(N, b"pid in use", r2, EADDRINUSE)
        && expect(N, b"short addr", r3, EINVAL)
    {
        pass(N);
    }
}

fn test_link_dump() {
    const N: &[u8] = b"NL_LINK_DUMP";
    let Some(mut nl) = Nl::open() else {
        return fail_why(N, b"open", 0);
    };
    let (mut lo_ok, mut eth_ok, mut bad) = (false, false, 0);
    let mut r = Req::new(RTM_GETLINK, 0, &ifinfo(0, 0, 0));
    let n = nl.dump(&mut r, &mut |m| {
        if m.ty != RTM_NEWLINK || m.flags & NLM_F_MULTI == 0 {
            bad += 1;
            return;
        }
        let l = link_of(m);
        if l.index == 1 {
            lo_ok = m.attr_str(16, IFLA_IFNAME) == Some(b"lo")
                && l.ltype == ARPHRD_LOOPBACK
                && l.flags & IFF_LOOPBACK != 0
                && l.flags & IFF_UP != 0;
        }
        if l.ltype == ARPHRD_ETHER {
            eth_ok = m.attr(16, IFLA_ADDRESS).is_some_and(|a| a.len() == 6)
                && l.mtu == 1500
                && l.operstate != 255;
        }
    });
    if n < 2 {
        return fail_why(N, b"dump count/error", n as i64);
    }
    if bad != 0 || !lo_ok || !eth_ok {
        print(N);
        print(b":FAIL bad=");
        print_num(bad);
        print(b" lo=");
        print_num(lo_ok as i64);
        print(b" eth=");
        print_num(eth_ok as i64);
        println(b"");
        return;
    }
    pass(N);
}

const IFA_RT_PRIORITY: u16 = 9;
const NLM_F_REPLACE: u16 = 0x100;
const IFA_F_SECONDARY: u8 = 0x01;

/// Our addresses on lo in dump order: (last octet, secondary, metric)
fn order_on_lo(nl: &mut Nl, out: &mut [(u8, bool, u32); 4]) -> (i32, usize) {
    let mut n = 0;
    let mut r = Req::new(RTM_GETADDR, 0, &ifaddr(AF_INET, 0, 0));
    let res = nl.dump(&mut r, &mut |m| {
        if m.ty != RTM_NEWADDR || m.body[0] != AF_INET || m.u32_at(4) != 1 {
            return;
        }
        let Some(ip) = m.attr_ip(8, IFA_LOCAL) else {
            return;
        };
        if (ip[..3] == ORDER_NET || ip[..3] == ORDER_NET2) && n < out.len() {
            let prio = m.attr_u32(8, IFA_RT_PRIORITY).unwrap_or(0);
            out[n] = (ip[3], m.body[2] & IFA_F_SECONDARY != 0, prio);
            n += 1;
        }
    });
    (res, n)
}

const ORDER_NET: [u8; 3] = [203, 0, 113];
const ORDER_NET2: [u8; 3] = [198, 18, 0];

/// Linux __inet_insert_ifa order: a new primary goes after the last
/// primary of its scope, a secondary (same subnet) last; NLM_F_REPLACE
/// changes an address in place, keeping its position
fn test_addr_order() {
    const N: &[u8] = b"NL_ADDR_ORDER";
    let Some(mut nl) = Nl::open() else {
        return fail_why(N, b"open", 0);
    };
    let ce = NLM_F_CREATE | NLM_F_EXCL;
    let a = [203, 0, 113, 10];
    let b = [203, 0, 113, 11];
    let c = [198, 18, 0, 1];
    let result = (|| -> Result<(), (&'static [u8], i64)> {
        let chk = |what: &'static [u8], got: i32| {
            if got == 0 {
                Ok(())
            } else {
                Err((what, got as i64))
            }
        };
        chk(b"add primary", addr(&mut nl, true, 1, a, 24, ce))?;
        chk(b"add secondary", addr(&mut nl, true, 1, b, 24, ce))?;
        chk(b"add second primary", addr(&mut nl, true, 1, c, 24, ce))?;
        let mut o = [(0, false, 0); 4];
        let (res, n) = order_on_lo(&mut nl, &mut o);
        chk(b"dump", res.min(0))?;
        let want = [(10, false, 0), (1, false, 0), (11, true, 0)];
        if n != 3 || o[..3] != want {
            return Err((b"order", (n as i64) * 1000 + i64::from(o[1].0)));
        }
        let mut r = Req::new(RTM_NEWADDR, NLM_F_REPLACE, &ifaddr(AF_INET, 24, 1));
        r.attr(IFA_LOCAL, &a)
            .attr(IFA_ADDRESS, &a)
            .attr(IFA_BROADCAST, &[203, 0, 113, 255])
            .u32(IFA_RT_PRIORITY, 77);
        chk(b"replace", nl.ack(&mut r))?;
        let (res, n) = order_on_lo(&mut nl, &mut o);
        chk(b"dump after replace", res.min(0))?;
        let want = [(10, false, 77), (1, false, 0), (11, true, 0)];
        if n != 3 || o[..3] != want {
            return Err((
                b"order after replace",
                (n as i64) * 1000 + i64::from(o[0].2),
            ));
        }
        Ok(())
    })();
    addr(&mut nl, false, 1, b, 24, 0);
    addr(&mut nl, false, 1, a, 24, 0);
    addr(&mut nl, false, 1, c, 24, 0);
    match result {
        Ok(()) => pass(N),
        Err((why, v)) => fail_why(N, why, v),
    }
}

const EXIT_IP: [u8; 4] = [192, 0, 2, 77];

/// In a new network namespace: lo up (127.0.0.1) with EXIT_IP added,
/// both bindable there; returns the failed step (0: none)
fn netns_with_addr() -> u64 {
    if hk_syscall::sys_unshare(hk_syscall::CLONE_NEWNET) != 0 {
        return 1;
    }
    let Some(mut nl) = Nl::open() else { return 2 };
    if set_link_up(&mut nl, 1, true) != 0 {
        return 3;
    }
    if addr(&mut nl, true, 1, EXIT_IP, 24, NLM_F_CREATE | NLM_F_EXCL) != 0 {
        return 4;
    }
    for (step, ip) in [(5, EXIT_IP), (6, [127, 0, 0, 1])] {
        let fd = crate::net::sk::udp();
        let r = crate::net::sk::bind(fd, ip, 0);
        crate::net::sk::close(fd);
        if r != 0 {
            return step;
        }
    }
    0
}

/// Namespaces created with addressed devices and left, many times
/// (Linux cleanup_net unregisters their devices, taking the addresses
/// out of the address hash): each works while it lives, and none of
/// their addresses is local in the initial namespace afterwards
fn test_netns_addr_exit() {
    const N: &[u8] = b"NL_NETNS_ADDR_EXIT";
    const ROUNDS: u64 = 32;
    for i in 0..ROUNDS {
        let pid = sys_fork();
        if pid == 0 {
            sys_exit(netns_with_addr());
        }
        let mut st = 0;
        if pid < 0 || sys_wait4(pid, &mut st, 0, 0) != pid {
            return fail_why(N, b"fork/wait", pid);
        }
        if st != 0 {
            return fail_why(N, b"child step", (i as i64) * 1000 + i64::from(st >> 8));
        }
    }
    let fd = crate::net::sk::udp();
    let r = crate::net::sk::bind(fd, EXIT_IP, 0);
    crate::net::sk::close(fd);
    if r != crate::net::sk::EADDRNOTAVAIL {
        return fail_why(N, b"bind in init ns", r);
    }
    pass(N);
}

/// IPv4 addresses on link `index` (count) and whether `ip` is among them
fn addrs_on(nl: &mut Nl, index: u32, ip: [u8; 4]) -> (i32, bool) {
    let (mut cnt, mut has) = (0, false);
    let mut r = Req::new(RTM_GETADDR, 0, &ifaddr(AF_INET, 0, 0));
    let n = nl.dump(&mut r, &mut |m| {
        if m.ty == RTM_NEWADDR && m.body[0] == AF_INET && m.u32_at(4) == index {
            cnt += 1;
            has |= m.attr_ip(8, IFA_LOCAL) == Some(ip);
        }
    });
    if n < 0 {
        return (n, false);
    }
    (cnt, has)
}

fn test_unconfigured() {
    const N: &[u8] = b"NL_ETH_UNCONFIGURED";
    let Some(mut nl) = Nl::open() else {
        return fail_why(N, b"open", 0);
    };
    let Some(eth) = first_ether(&mut nl) else {
        return fail_why(N, b"no ethernet link", 0);
    };
    if eth.flags & (IFF_UP | IFF_RUNNING) != 0 {
        return fail_why(N, b"flags", eth.flags as i64);
    }
    if eth.operstate != IF_OPER_DOWN {
        return fail_why(N, b"operstate", eth.operstate as i64);
    }
    let (cnt, _) = addrs_on(&mut nl, eth.index, [0; 4]);
    if cnt != 0 {
        return fail_why(N, b"ipv4 addresses", cnt as i64);
    }
    // lo has exactly 127.0.0.1/8
    let (cnt, has) = addrs_on(&mut nl, 1, [127, 0, 0, 1]);
    if cnt != 1 || !has {
        return fail_why(N, b"lo addresses", cnt as i64);
    }
    pass(N);
}

fn test_getlink() {
    const N: &[u8] = b"NL_GETLINK";
    let Some(mut nl) = Nl::open() else {
        return fail_why(N, b"open", 0);
    };
    let Some(lo) = get_link(&mut nl, 1) else {
        return fail_why(N, b"by index", 0);
    };
    if lo.ltype != ARPHRD_LOOPBACK {
        return fail_why(N, b"lo type", lo.ltype as i64);
    }
    // By name
    let mut r = Req::new(RTM_GETLINK, 0, &ifinfo(0, 0, 0));
    r.attr(IFLA_IFNAME, b"lo\0");
    let seq = nl.send(&mut r);
    let buf = rxbuf();
    let n = nl.recv(buf, 0);
    let mut idx = 0;
    if n > 0 {
        each_msg(&buf[..n as usize], &mut |m| {
            if m.seq == seq && m.ty == RTM_NEWLINK {
                idx = m.u32_at(4);
            }
        });
    }
    if idx != 1 {
        return fail_why(N, b"by name index", idx as i64);
    }
    let e1 = nl.ack(&mut Req::new(RTM_GETLINK, 0, &ifinfo(99999, 0, 0)));
    let mut r = Req::new(RTM_GETLINK, 0, &ifinfo(0, 0, 0));
    r.attr(IFLA_IFNAME, b"nosuchif9\0");
    let e2 = nl.ack(&mut r);
    if expect(N, b"bad index", e1, ENODEV) && expect(N, b"bad name", e2, ENODEV) {
        pass(N);
    }
}

fn test_ack() {
    const N: &[u8] = b"NL_ACK";
    let Some(mut nl) = Nl::open() else {
        return fail_why(N, b"open", 0);
    };
    let (_, mypid, _) = sockname(nl.fd);
    // Success ACK: error 0, capped, our seq and portid
    let mut r = Req::new(RTM_NEWLINK, NLM_F_ACK, &ifinfo(1, 0, 0));
    let seq = nl.send(&mut r);
    let buf = rxbuf();
    let n = nl.recv(buf, 0);
    let mut good = false;
    if n > 0 {
        each_msg(&buf[..n as usize], &mut |m| {
            good = m.ty == NLMSG_ERROR
                && m.seq == seq
                && m.pid == mypid
                && m.error() == 0
                && m.flags & NLM_F_CAPPED != 0
                && m.body.len() == 20;
        });
    }
    if !good {
        return fail_why(N, b"success ack", n);
    }
    // Error: whole request echoed (missing IFA_LOCAL -> EINVAL)
    let mut r = Req::new(
        RTM_NEWADDR,
        NLM_F_ACK | NLM_F_CREATE,
        &ifaddr(AF_INET, 24, 1),
    );
    let reqlen = r.bytes(0).len();
    let seq = nl.send(&mut r);
    let n = nl.recv(buf, 0);
    let mut elen = 0;
    let mut code = 0;
    if n > 0 {
        each_msg(&buf[..n as usize], &mut |m| {
            if m.seq == seq && m.ty == NLMSG_ERROR {
                code = m.error();
                elen = m.body.len();
            }
        });
    }
    if code != EINVAL || elen != 4 + reqlen {
        print(N);
        print(b":FAIL error echo code=");
        print_num(code as i64);
        print(b" len=");
        print_num(elen as i64);
        println(b"");
        return;
    }
    // Unknown message type
    let e = nl.ack(&mut Req::new(200, 0, &[0u8; 4]));
    if !expect(N, b"unknown type", e, EOPNOTSUPP) {
        return;
    }
    // A request without NLM_F_ACK that succeeds produces no reply
    let mut r = Req::new(RTM_NEWLINK, 0, &ifinfo(1, 0, 0));
    nl.send(&mut r);
    if wait_readable(nl.fd, 200) {
        return fail_why(N, b"unexpected reply without NLM_F_ACK", 0);
    }
    pass(N);
}

/// Wait up to 3 s for link `index` to satisfy `f`
fn link_wait(nl: &mut Nl, index: u32, f: &dyn Fn(&Link) -> bool) -> Option<Link> {
    let mut last = None;
    for _ in 0..30 {
        last = get_link(nl, index);
        if last.as_ref().is_some_and(f) {
            return last;
        }
        msleep(100);
    }
    last
}

fn test_updown() {
    const N: &[u8] = b"NL_LINK_UPDOWN";
    let Some(mut nl) = Nl::open() else {
        return fail_why(N, b"open", 0);
    };
    let Some(eth) = first_ether(&mut nl) else {
        return fail_why(N, b"no ethernet link", 0);
    };
    if set_link_up(&mut nl, eth.index, true) != 0 {
        return fail_why(N, b"up", 0);
    }
    let up = link_wait(&mut nl, eth.index, &|l| {
        l.flags & (IFF_UP | IFF_RUNNING | IFF_LOWER_UP) == IFF_UP | IFF_RUNNING | IFF_LOWER_UP
            && l.operstate == IF_OPER_UP
    });
    let up_ok = up.is_some_and(|l| l.operstate == IF_OPER_UP && l.flags & IFF_RUNNING != 0);
    let r = set_link_up(&mut nl, eth.index, false);
    let down = get_link(&mut nl, eth.index).unwrap_or_default();
    if !up_ok {
        return fail_why(
            N,
            b"not running after up, flags",
            up.map_or(-1, |l| l.flags as i64),
        );
    }
    if r != 0 || down.flags & (IFF_UP | IFF_RUNNING) != 0 || down.operstate != IF_OPER_DOWN {
        return fail_why(N, b"after down, flags", down.flags as i64);
    }
    pass(N);
}

/// Route facts gathered from a dump
#[derive(Default)]
struct RouteSeen {
    prefix: bool,
    local: bool,
    bcast: bool,
    via: bool,
}

fn route_scan(nl: &mut Nl, index: u32) -> RouteSeen {
    let mut s = RouteSeen::default();
    let mut r = Req::new(RTM_GETROUTE, 0, &rtmsg(0, 0, 0, 0, 0));
    nl.dump(&mut r, &mut |m| {
        if m.ty != RTM_NEWROUTE || m.body[0] != AF_INET {
            return;
        }
        let (dlen, table, proto, scope, rtype) =
            (m.body[1], m.body[4], m.body[5], m.body[6], m.body[7]);
        let dst = m.attr_ip(12, RTA_DST).unwrap_or([0; 4]);
        let oif = m.attr_u32(12, RTA_OIF).unwrap_or(0);
        if oif != index {
            return;
        }
        if table == RT_TABLE_MAIN && dlen == 24 && dst == [192, 0, 2, 0] {
            s.prefix = proto == RTPROT_KERNEL
                && scope == RT_SCOPE_LINK
                && rtype == RTN_UNICAST
                && m.attr_ip(12, RTA_PREFSRC) == Some(TEST_IP);
        }
        if table == RT_TABLE_LOCAL && dlen == 32 && dst == TEST_IP && rtype == RTN_LOCAL {
            s.local = true;
        }
        if table == RT_TABLE_LOCAL
            && dlen == 32
            && dst == [192, 0, 2, 255]
            && rtype == RTN_BROADCAST
        {
            s.bcast = true;
        }
        if table == RT_TABLE_MAIN && dlen == 24 && dst == TEST_NET {
            s.via = m.attr_ip(12, RTA_GATEWAY) == Some(TEST_GW);
        }
    });
    s
}

/// "ip route get": (oif, gateway, prefsrc, type)
fn route_get(nl: &mut Nl, dst: [u8; 4]) -> Result<(u32, [u8; 4], [u8; 4], u8), i32> {
    let mut r = Req::new(RTM_GETROUTE, 0, &rtmsg(32, 0, 0, 0, 0));
    r.attr(RTA_DST, &dst);
    let seq = nl.send(&mut r);
    let buf = rxbuf();
    let n = nl.recv(buf, 0);
    let mut out = Err(-10000);
    if n > 0 {
        each_msg(&buf[..n as usize], &mut |m| {
            if m.seq != seq {
                return;
            }
            if m.ty == NLMSG_ERROR {
                out = Err(m.error());
            } else if m.ty == RTM_NEWROUTE {
                out = Ok((
                    m.attr_u32(12, RTA_OIF).unwrap_or(0),
                    m.attr_ip(12, RTA_GATEWAY).unwrap_or([0; 4]),
                    m.attr_ip(12, RTA_PREFSRC).unwrap_or([0; 4]),
                    m.body[7],
                ));
            }
        });
    }
    out
}

fn test_addr_route() {
    const N: &[u8] = b"NL_ADDR_ROUTE";
    let Some(mut nl) = Nl::open() else {
        return fail_why(N, b"open", 0);
    };
    let Some(eth) = first_ether(&mut nl) else {
        return fail_why(N, b"no ethernet link", 0);
    };
    let i = eth.index;
    set_link_up(&mut nl, i, true);
    let ce = NLM_F_CREATE | NLM_F_EXCL;
    let result = (|| -> Result<(), (&'static [u8], i64)> {
        let chk = |what: &'static [u8], got: i32, want: i32| {
            if got == want {
                Ok(())
            } else {
                Err((what, got as i64))
            }
        };
        chk(b"newaddr", addr(&mut nl, true, i, TEST_IP, 24, ce), 0)?;
        chk(
            b"newaddr dup",
            addr(&mut nl, true, i, TEST_IP, 24, ce),
            EEXIST,
        )?;
        chk(
            b"newaddr bad dev",
            addr(&mut nl, true, 99999, TEST_IP, 24, ce),
            ENODEV,
        )?;
        let (_, has) = addrs_on(&mut nl, i, TEST_IP);
        if !has {
            return Err((b"address not in dump", 0));
        }
        let s = route_scan(&mut nl, i);
        if !(s.prefix && s.local && s.bcast) {
            let v = (s.prefix as i64) | (s.local as i64) << 1 | (s.bcast as i64) << 2;
            return Err((b"kernel routes (prefix|local|bcast bits)", v));
        }
        chk(
            b"newroute",
            route(&mut nl, true, TEST_NET, 24, TEST_GW, 0, ce),
            0,
        )?;
        chk(
            b"newroute dup",
            route(&mut nl, true, TEST_NET, 24, TEST_GW, 0, ce),
            EEXIST,
        )?;
        chk(
            b"unreachable gw",
            route(&mut nl, true, [203, 0, 113, 0], 24, [10, 99, 99, 1], 0, ce),
            ENETUNREACH,
        )?;
        if !route_scan(&mut nl, i).via {
            return Err((b"gateway route not in dump", 0));
        }
        match route_get(&mut nl, [198, 51, 100, 7]) {
            Ok((oif, gw, src, _)) if oif == i && gw == TEST_GW && src == TEST_IP => {}
            Ok((oif, ..)) => return Err((b"route get via: oif", oif as i64)),
            Err(e) => return Err((b"route get via", e as i64)),
        }
        match route_get(&mut nl, TEST_IP) {
            Ok((oif, _, _, t)) if oif == 1 && t == RTN_LOCAL => {}
            Ok((oif, ..)) => return Err((b"route get local: oif", oif as i64)),
            Err(e) => return Err((b"route get local", e as i64)),
        }
        chk(
            b"route get no route",
            route_get(&mut nl, [203, 0, 113, 9]).err().unwrap_or(0),
            ENETUNREACH,
        )?;
        chk(
            b"delroute",
            route(&mut nl, false, TEST_NET, 24, [0; 4], 0, 0),
            0,
        )?;
        chk(
            b"delroute again",
            route(&mut nl, false, TEST_NET, 24, [0; 4], 0, 0),
            ESRCH,
        )?;
        chk(b"deladdr", addr(&mut nl, false, i, TEST_IP, 24, 0), 0)?;
        chk(
            b"deladdr again",
            addr(&mut nl, false, i, TEST_IP, 24, 0),
            EADDRNOTAVAIL,
        )?;
        let s = route_scan(&mut nl, i);
        if s.prefix || s.local || s.bcast {
            return Err((b"routes left after deladdr", 0));
        }
        Ok(())
    })();
    // Cleanup regardless of the outcome
    route(&mut nl, false, TEST_NET, 24, [0; 4], 0, 0);
    addr(&mut nl, false, i, TEST_IP, 24, 0);
    set_link_up(&mut nl, i, false);
    match result {
        Ok(()) => pass(N),
        Err((what, v)) => fail_why(N, what, v),
    }
}

fn test_notify() {
    const N: &[u8] = b"NL_NOTIFY";
    let (Some(mut nl), Some(mon)) = (Nl::open(), Nl::open()) else {
        return fail_why(N, b"open", 0);
    };
    let Some(eth) = first_ether(&mut nl) else {
        return fail_why(N, b"no ethernet link", 0);
    };
    // Groups by bind (IFADDR; rebinding a bound socket must name its own
    // port id) and by setsockopt (LINK)
    let g = nladdr(sockname(mon.fd).1, RTMGRP_IPV4_IFADDR);
    let r1 = sys_bind(mon.fd, g.as_ptr(), 12);
    let one = RTNLGRP_LINK;
    let r2 = sys_setsockopt(
        mon.fd,
        SOL_NETLINK,
        NETLINK_ADD_MEMBERSHIP,
        &one as *const i32 as *const u8,
        4,
    );
    if r1 != 0 || r2 != 0 || sockname(mon.fd).2 & RTMGRP_IPV4_IFADDR == 0 {
        return fail_why(N, b"subscribe", r1 | r2);
    }
    let added = addr(
        &mut nl,
        true,
        eth.index,
        TEST_IP,
        24,
        NLM_F_CREATE | NLM_F_EXCL,
    );
    let seen_new = wait_notify(&mon, RTM_NEWADDR, eth.index);
    let deleted = addr(&mut nl, false, eth.index, TEST_IP, 24, 0);
    let seen_del = wait_notify(&mon, RTM_DELADDR, eth.index);
    set_link_up(&mut nl, eth.index, true);
    let seen_link = wait_notify(&mon, RTM_NEWLINK, eth.index);
    set_link_up(&mut nl, eth.index, false);
    if added != 0 || deleted != 0 {
        return fail_why(N, b"addr add/del", (added | deleted) as i64);
    }
    if !seen_new || !seen_del || !seen_link {
        let v = seen_new as i64 | (seen_del as i64) << 1 | (seen_link as i64) << 2;
        return fail_why(N, b"notifications seen (new|del|link bits)", v);
    }
    pass(N);
}

/// Read notifications until one of type `ty` for link `index` (2 s)
fn wait_notify(mon: &Nl, ty: u16, index: u32) -> bool {
    for _ in 0..32 {
        if !wait_readable(mon.fd, 2000) {
            return false;
        }
        let buf = rxbuf();
        let n = mon.recv(buf, 0);
        if n <= 0 {
            return false;
        }
        let mut hit = false;
        each_msg(&buf[..n as usize], &mut |m| {
            if m.ty != ty {
                return;
            }
            let idx = m.u32_at(4);
            let fam_ok = ty == RTM_NEWLINK || m.body[0] == AF_INET;
            let ip_ok = ty == RTM_NEWLINK || m.attr_ip(8, IFA_LOCAL) == Some(TEST_IP);
            hit |= idx == index && fam_ok && ip_ok;
        });
        if hit {
            return true;
        }
    }
    false
}

fn recvmsg(fd: i32, buf: &mut [u8], flags: i32) -> (i64, i32) {
    let mut iov = IoVec {
        iov_base: buf.as_mut_ptr(),
        iov_len: buf.len(),
    };
    let mut msg = MsgHdr::new(&mut iov, 1);
    let r = sys_recvmsg(fd, &mut msg, flags);
    (r, msg.msg_flags)
}

fn test_peek_trunc() {
    const N: &[u8] = b"NL_PEEK_TRUNC";
    let Some(mut nl) = Nl::open() else {
        return fail_why(N, b"open", 0);
    };
    let mut r = Req::new(RTM_GETLINK, NLM_F_DUMP, &ifinfo(0, 0, 0));
    nl.send(&mut r);
    if !wait_readable(nl.fd, 5000) {
        return fail_why(N, b"no reply", 0);
    }
    let mut small = [0u8; 16];
    // Size the first datagram without consuming it
    let (full, f1) = recvmsg(nl.fd, &mut small, MSG_PEEK | MSG_TRUNC);
    if full <= 16 || f1 & MSG_TRUNC == 0 {
        return fail_why(N, b"peek|trunc size", full);
    }
    let buf = rxbuf();
    let (got, f2) = recvmsg(nl.fd, &mut buf[..full as usize], 0);
    if got != full || f2 & MSG_TRUNC != 0 {
        return fail_why(N, b"full read", got);
    }
    // Next datagram (more links or DONE) read short: truncated, consumed
    let mut r = Req::new(RTM_GETLINK, NLM_F_DUMP, &ifinfo(0, 0, 0));
    nl.send(&mut r);
    wait_readable(nl.fd, 5000);
    let (cut, f3) = recvmsg(nl.fd, &mut small, 0);
    if cut != 16 || f3 & MSG_TRUNC == 0 {
        return fail_why(N, b"truncated read", cut);
    }
    pass(N);
}

/// MSG_PEEK of a dump part returns its bytes and leaves it queued: a
/// second peek and the read that follows see the same part
fn test_peek_dump() {
    const N: &[u8] = b"NL_PEEK_DUMP";
    let Some(mut nl) = Nl::open() else {
        return fail_why(N, b"open", 0);
    };
    let mut r = Req::new(RTM_GETLINK, NLM_F_DUMP, &ifinfo(0, 0, 0));
    nl.send(&mut r);
    if !wait_readable(nl.fd, 5000) {
        return fail_why(N, b"no reply", 0);
    }
    let (peek, read) = rxbuf().split_at_mut(16384);
    let (n1, _) = recvmsg(nl.fd, peek, MSG_PEEK);
    let mut first = (0u16, 0u16);
    each_msg(&peek[..n1.max(0) as usize], &mut |m| {
        if first.0 == 0 {
            first = (m.ty, m.flags);
        }
    });
    if n1 <= 16 || first.0 != RTM_NEWLINK || first.1 & NLM_F_MULTI == 0 {
        return fail_why(N, b"peeked part", n1);
    }
    let (n2, _) = recvmsg(nl.fd, read, MSG_PEEK);
    if n2 != n1 || read[..n2 as usize] != peek[..n1 as usize] {
        return fail_why(N, b"second peek", n2);
    }
    read.fill(0);
    let (n3, _) = recvmsg(nl.fd, read, 0);
    if n3 != n1 || read[..n3 as usize] != peek[..n1 as usize] {
        return fail_why(N, b"read after peek", n3);
    }
    pass(N);
}

fn getopt(fd: i32, level: i32, opt: i32) -> (i64, i32) {
    let mut v: i32 = -1;
    let mut len: u32 = 4;
    let r = sys_getsockopt(fd, level, opt, &mut v as *mut i32 as *mut u8, &mut len);
    (r, v)
}

fn test_sockopt() {
    const N: &[u8] = b"NL_SOCKOPT";
    let Some(nl) = Nl::open() else {
        return fail_why(N, b"open", 0);
    };
    let one: i32 = 1;
    let p1 = &one as *const i32 as *const u8;
    for o in [
        NETLINK_EXT_ACK,
        NETLINK_GET_STRICT_CHK,
        NETLINK_CAP_ACK,
        NETLINK_NO_ENOBUFS,
        NETLINK_PKTINFO,
    ] {
        let r = sys_setsockopt(nl.fd, SOL_NETLINK, o, p1, 4);
        let (g, v) = getopt(nl.fd, SOL_NETLINK, o);
        if r != 0 || g != 0 || v != 1 {
            return fail_why(N, b"option", o as i64);
        }
    }
    let sz: i32 = 32768;
    sys_setsockopt(nl.fd, 1, 8, &sz as *const i32 as *const u8, 4); // SO_RCVBUF
    let (_, v) = getopt(nl.fd, 1, 8);
    if v != 65536 {
        return fail_why(N, b"SO_RCVBUF doubled", v as i64);
    }
    let zero: i32 = 0;
    let r = sys_setsockopt(
        nl.fd,
        SOL_NETLINK,
        NETLINK_ADD_MEMBERSHIP,
        &zero as *const i32 as *const u8,
        4,
    ) as i32;
    if !expect(N, b"group 0", r, EINVAL) {
        return;
    }
    let r = sys_setsockopt(nl.fd, SOL_NETLINK, 99, p1, 4) as i32;
    if !expect(N, b"unknown option", r, ENOPROTOOPT) {
        return;
    }
    let (_, ty) = getopt(nl.fd, 1, 3); // SO_TYPE
    if ty != SOCK_RAW {
        return fail_why(N, b"SO_TYPE", ty as i64);
    }
    pass(N);
}

fn test_strict_dump() {
    const N: &[u8] = b"NL_STRICT_DUMP";
    let Some(mut nl) = Nl::open() else {
        return fail_why(N, b"open", 0);
    };
    let one: i32 = 1;
    sys_setsockopt(
        nl.fd,
        SOL_NETLINK,
        NETLINK_GET_STRICT_CHK,
        &one as *const i32 as *const u8,
        4,
    );
    let (mut other, mut lo, mut filtered) = (0, 0, true);
    let mut r = Req::new(RTM_GETADDR, 0, &ifaddr(AF_INET, 0, 1));
    let n = nl.dump(&mut r, &mut |m| {
        if m.u32_at(4) == 1 && m.body[0] == AF_INET {
            lo += 1;
        } else {
            other += 1;
        }
        filtered &= m.flags & NLM_F_DUMP_FILTERED != 0;
    });
    if n < 0 || lo != 1 || other != 0 || !filtered {
        return fail_why(N, b"ifindex filter", n as i64);
    }
    let mut r = Req::new(RTM_GETADDR, 0, &ifaddr(AF_INET, 8, 0));
    let n = nl.dump(&mut r, &mut |_| {});
    if !expect(N, b"bad header", n, EINVAL) {
        return;
    }
    pass(N);
}

fn test_other_dumps() {
    const N: &[u8] = b"NL_DUMPS";
    let Some(mut nl) = Nl::open() else {
        return fail_why(N, b"open", 0);
    };
    // Route dump: AF_INET messages; lo's 127.0.0.1 local route present
    let (mut bad, mut lo_local) = (0, false);
    let mut r = Req::new(RTM_GETROUTE, 0, &rtmsg(0, 0, 0, 0, 0));
    let n = nl.dump(&mut r, &mut |m| {
        if m.ty != RTM_NEWROUTE || m.body[0] != AF_INET {
            bad += 1;
        }
        if m.body[4] == RT_TABLE_LOCAL
            && m.body[7] == RTN_LOCAL
            && m.attr_ip(12, RTA_DST) == Some([127, 0, 0, 1])
        {
            lo_local = true;
        }
    });
    if n < 1 || bad != 0 || !lo_local {
        return fail_why(N, b"route dump", n as i64);
    }
    // IPv6 address dump: no IPv4 entries
    let mut v4 = 0;
    let mut r = Req::new(RTM_GETADDR, 0, &ifaddr(AF_INET6, 0, 0));
    let n = nl.dump(&mut r, &mut |m| {
        if m.body[0] == AF_INET {
            v4 += 1;
        }
    });
    if n < 0 || v4 != 0 {
        return fail_why(N, b"inet6 addr dump", n as i64);
    }
    // Neighbours and rules: well-formed dumps
    let mut r = Req::new(RTM_GETNEIGH, 0, &[AF_INET, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let mut nbad = 0;
    let n = nl.dump(&mut r, &mut |m| nbad += (m.ty != RTM_NEWNEIGH) as i32);
    if n < 0 || nbad != 0 {
        return fail_why(N, b"neigh dump", n as i64);
    }
    let mut r = Req::new(RTM_GETRULE, 0, &[AF_INET, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let mut rbad = 0;
    let n = nl.dump(&mut r, &mut |m| rbad += (m.ty != RTM_NEWRULE) as i32);
    if n < 0 || rbad != 0 {
        return fail_why(N, b"rule dump", n as i64);
    }
    pass(N);
}

/// Drop all effective capabilities of this process
pub fn drop_caps() -> bool {
    set_eff(false)
}

/// Clear (or restore from permitted) the effective capability set
fn set_eff(on: bool) -> bool {
    let mut h = CapUserHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut d = [CapUserData::default(); 2];
    if sys_capget(&mut h, d.as_mut_ptr()) != 0 {
        return false;
    }
    d[0].effective = if on { d[0].permitted } else { 0 };
    d[1].effective = if on { d[1].permitted } else { 0 };
    sys_capset(&h, d.as_ptr()) == 0
}

fn test_eperm() {
    const N: &[u8] = b"NL_EPERM";
    let pid = sys_fork();
    if pid == 0 {
        if !drop_caps() {
            sys_exit(2);
        }
        let Some(mut nl) = Nl::open() else {
            sys_exit(3)
        };
        let e = addr(&mut nl, true, 1, TEST_IP, 24, NLM_F_CREATE);
        let mut r = Req::new(RTM_GETLINK, 0, &ifinfo(0, 0, 0));
        let n = nl.dump(&mut r, &mut |_| {});
        sys_exit(if e == EPERM && n >= 1 { 0 } else { 4 });
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    let code = (st >> 8) & 0xff;
    if st & 0x7f != 0 || code != 0 {
        return fail_why(N, b"child code", code as i64);
    }
    pass(N);
}

fn sendmsg_iov(fd: i32, iov: &mut [IoVec]) -> i32 {
    let msg = MsgHdr::new(iov.as_mut_ptr(), iov.len());
    sys_sendmsg(fd, &msg, 0) as i32
}

/// Hostile lengths: huge iov_len (EFAULT), totals above sndbuf - 32
/// (EMSGSIZE, before copying anything), oversized sendto lengths
/// (clamped, then EMSGSIZE), more than UIO_MAXIOV segments (EMSGSIZE)
fn test_overflow() {
    const N: &[u8] = b"NL_OVERFLOW";
    let Some(nl) = Nl::open() else {
        return fail_why(N, b"open", 0);
    };
    let buf = rxbuf();
    let p = buf.as_ptr();
    let mut huge = [
        IoVec {
            iov_base: p,
            iov_len: 16,
        },
        IoVec {
            iov_base: p,
            iov_len: usize::MAX / 2,
        },
    ];
    if !expect(N, b"huge iov_len", sendmsg_iov(nl.fd, &mut huge), EFAULT) {
        return;
    }
    // 10 x 32 KB = 320 KB > default sndbuf (212992)
    let mut big = [IoVec {
        iov_base: p,
        iov_len: buf.len(),
    }; 10];
    if !expect(N, b"total > sndbuf", sendmsg_iov(nl.fd, &mut big), EMSGSIZE) {
        return;
    }
    let k = nladdr(0, 0);
    let r = sys_sendto(nl.fd, p, usize::MAX, 0, k.as_ptr(), 12) as i32;
    if !expect(N, b"sendto len max", r, EMSGSIZE) {
        return;
    }
    // 1025 segments (zero length) inside the 32 KB receive buffer
    let many = unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut IoVec, 1025) };
    for v in many.iter_mut() {
        *v = IoVec {
            iov_base: p,
            iov_len: 0,
        };
    }
    if !expect(N, b"iovlen 1025", sendmsg_iov(nl.fd, many), EMSGSIZE) {
        return;
    }
    pass(N);
}

/// Smallest receive buffer (SO_RCVBUF 0 -> SOCK_MIN_RCVBUF)
fn tiny_rcvbuf(fd: i32) {
    let v: i32 = 0;
    sys_setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &v as *const i32 as *const u8, 4);
}

const N_ROUTES: u32 = 400;

fn many_route(i: u32) -> [u8; 4] {
    [10, 99, (i / 250) as u8, (i % 250 + 1) as u8]
}

/// Route dump with an optional concurrent second dump: (routes of
/// ours seen, DONE seen, error of the second dump, datagrams)
fn route_dump(nl: &mut Nl, second: bool) -> (u32, bool, i32, i64) {
    let mut d1 = Req::new(RTM_GETROUTE, NLM_F_DUMP, &rtmsg(0, 0, 0, 0, 0));
    let s1 = nl.send(&mut d1);
    let mut s2 = 0;
    if second {
        s2 = nl.send(&mut Req::new(RTM_GETLINK, NLM_F_DUMP, &ifinfo(0, 0, 0)));
    }
    let (mut seen, mut done, mut busy, mut parts) = (0u32, false, 0, 0);
    while !(done && (busy != 0 || !second)) && parts < 200 {
        let buf = rxbuf();
        let n = nl.recv(buf, 0);
        if n <= 0 {
            return (seen, done, n as i32, parts);
        }
        parts += 1;
        each_msg(&buf[..n as usize], &mut |m| {
            let ours = m
                .attr_ip(12, RTA_DST)
                .is_some_and(|d| d[0] == 10 && d[1] == 99);
            if m.seq == s1 && m.ty == RTM_NEWROUTE && ours {
                seen += 1;
            } else if m.seq == s1 && m.ty == NLMSG_DONE {
                done = true;
            } else if second && m.seq == s2 && m.ty == NLMSG_ERROR {
                busy = m.error();
            }
        });
    }
    (seen, done, busy, parts)
}

/// A dump larger than the receive buffer continues as it is read (all
/// entries arrive, DONE last); a second dump while one runs is EBUSY;
/// /proc/net/route, larger than a page, lists every route
fn test_dump_resume() {
    const N: &[u8] = b"NL_DUMP_RESUME";
    let (Some(mut cfg), Some(mut small), Some(mut nl)) = (Nl::open(), Nl::open(), Nl::open())
    else {
        return fail_why(N, b"open", 0);
    };
    for i in 0..N_ROUTES {
        let r = route(
            &mut cfg,
            true,
            many_route(i),
            32,
            [0; 4],
            1,
            NLM_F_CREATE | NLM_F_EXCL,
        );
        if r != 0 {
            return fail_why(N, b"route add", r as i64);
        }
    }
    tiny_rcvbuf(small.fd);
    // Link messages (~1 KB+) exceed half of the minimal buffer each
    let links = small.dump(&mut Req::new(RTM_GETLINK, 0, &ifinfo(0, 0, 0)), &mut |_| {});
    if links < 2 {
        return fail_why(N, b"small rcvbuf: link dump", links as i64);
    }
    let (seen, done, err, parts) = route_dump(&mut small, false);
    let (seen2, done2, busy, _) = route_dump(&mut nl, true);
    let (proc_len, proc_seen) = proc_routes();
    for i in 0..N_ROUTES {
        route(&mut cfg, false, many_route(i), 32, [0; 4], 1, 0);
    }
    if seen != N_ROUTES || !done || err != 0 || parts < 2 {
        print_num(err as i64);
        print(b" ");
        print_num(parts);
        return fail_why(N, b"small rcvbuf: routes", seen as i64);
    }
    if seen2 != N_ROUTES || !done2 {
        return fail_why(N, b"routes", seen2 as i64);
    }
    if !expect(N, b"second dump", busy, EBUSY) {
        return;
    }
    if proc_len <= 4096 || proc_seen != N_ROUTES {
        print_num(proc_len);
        return fail_why(N, b"/proc/net/route", proc_seen as i64);
    }
    pass(N);
}

const PROC_ROUTE_LEN: usize = 65536;
static mut PROC_ROUTE: [u8; PROC_ROUTE_LEN] = [0; PROC_ROUTE_LEN];

/// /proc/net/route (more than a page with our routes): its length and
/// how many of our 10.99/16 routes it lists (Destination is the raw
/// network-order word in hex: little-endian "....630A")
fn proc_routes() -> (i64, u32) {
    // SAFETY: single-threaded test program; no other user of the buffer
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(PROC_ROUTE) };
    let n = crate::helpers::read_file(b"/proc/net/route\0", buf);
    if n <= 0 {
        return (n, 0);
    }
    let mut seen = 0;
    for line in buf[..n as usize].split(|&c| c == b'\n') {
        let mut f = line.split(|&c| c == b'\t');
        let (Some(_), Some(dst)) = (f.next(), f.next()) else {
            continue;
        };
        if dst.len() == 8 && &dst[4..] == b"630A" {
            seen += 1;
        }
    }
    (n, seen)
}

/// Change lo's MTU (one RTM_NEWLINK notification each)
fn lo_mtu(nl: &mut Nl, mtu: u32) -> i32 {
    let mut r = Req::new(RTM_NEWLINK, 0, &ifinfo(1, 0, 0));
    r.u32(IFLA_MTU, mtu);
    nl.ack(&mut r)
}

/// Read a monitor without blocking: (ENOBUFS seen first, messages)
fn drain(fd: i32) -> (bool, i32) {
    let buf = rxbuf();
    let mut first = true;
    let (mut enobufs, mut msgs) = (false, 0);
    loop {
        let r = sys_recvfrom(
            fd,
            buf.as_mut_ptr(),
            buf.len(),
            MSG_DONTWAIT,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        ) as i32;
        if r == ENOBUFS && first {
            enobufs = true;
        } else if r == EAGAIN {
            return (enobufs, msgs);
        } else if r < 0 {
            return (enobufs, r);
        } else {
            msgs += 1;
        }
        first = false;
    }
}

/// Notifications beyond the receive buffer are dropped and reported
/// once with ENOBUFS (not with NETLINK_NO_ENOBUFS)
fn test_overrun() {
    const N: &[u8] = b"NL_OVERRUN";
    let (Some(mut cfg), Some(mon), Some(quiet)) = (Nl::open(), Nl::open(), Nl::open()) else {
        return fail_why(N, b"open", 0);
    };
    let one: i32 = 1;
    let g: i32 = RTNLGRP_LINK;
    for fd in [mon.fd, quiet.fd] {
        tiny_rcvbuf(fd);
        sys_setsockopt(
            fd,
            SOL_NETLINK,
            NETLINK_ADD_MEMBERSHIP,
            &g as *const i32 as *const u8,
            4,
        );
    }
    sys_setsockopt(
        quiet.fd,
        SOL_NETLINK,
        NETLINK_NO_ENOBUFS,
        &one as *const i32 as *const u8,
        4,
    );
    for i in 0..10 {
        let r = lo_mtu(&mut cfg, if i % 2 == 0 { 65535 } else { 65536 });
        if r != 0 {
            return fail_why(N, b"mtu", r as i64);
        }
    }
    let (e1, m1) = drain(mon.fd);
    let (e2, m2) = drain(quiet.fd);
    if !e1 || m1 < 1 || m1 >= 10 {
        return fail_why(N, b"monitor msgs", m1 as i64);
    }
    if e2 || m2 < 1 || m2 >= 10 {
        return fail_why(N, b"NO_ENOBUFS msgs", m2 as i64);
    }
    pass(N);
}

/// IFLA_MTU is a u32 the kernel takes as an int: above INT_MAX it is a
/// negative MTU, EINVAL even on lo, which has no maximum (Linux
/// dev_validate_mtu); the MTU stays as it was
fn test_mtu_negative() {
    const N: &[u8] = b"RTNL_MTU_NEGATIVE";
    const RTM_SETLINK: u16 = 19;
    let Some(mut nl) = Nl::open() else {
        return fail_why(N, b"open", 0);
    };
    let Some(before) = get_link(&mut nl, 1) else {
        return fail_why(N, b"getlink", 0);
    };
    for mtu in [0x8000_0000u32, u32::MAX] {
        let mut r = Req::new(RTM_SETLINK, 0, &ifinfo(1, 0, 0));
        r.u32(IFLA_MTU, mtu);
        let e = nl.ack(&mut r);
        if e != EINVAL {
            lo_mtu(&mut nl, before.mtu);
            return fail_why(N, b"mtu > INT_MAX", e as i64);
        }
    }
    match get_link(&mut nl, 1) {
        Some(l) if l.mtu == before.mtu => pass(N),
        l => fail_why(N, b"mtu changed", l.map_or(-1, |l| l.mtu as i64)),
    }
}

/// NEWADDR of TEST_IP on lo through `fd`, sent with write() (no
/// destination address) or sendto() to the kernel; returns the ACK code
fn newaddr_on(fd: i32, write: bool) -> i32 {
    let mut nl = Nl::from_fd(fd);
    let mut r = Req::new(
        RTM_NEWADDR,
        NLM_F_CREATE | NLM_F_ACK,
        &ifaddr(AF_INET, 24, 1),
    );
    r.attr(IFA_LOCAL, &TEST_IP).attr(IFA_ADDRESS, &TEST_IP);
    let code = if write {
        let b = r.bytes(7777);
        sys_write(fd as u64, b.as_ptr(), b.len() as u64);
        nl.wait_ack(7777)
    } else {
        nl.ack(&mut r)
    };
    core::mem::forget(nl);
    if code == 0 {
        if let Some(mut c) = Nl::open() {
            addr(&mut c, false, 1, TEST_IP, 24, 0);
        }
    }
    code
}

/// Confused deputy (Linux __netlink_ns_capable): a request written
/// without a destination address needs CAP_NET_ADMIN of the socket's
/// opener as well as of the sender. (1) A privileged process writing to
/// a socket opened unprivileged (fetched with pidfd_getfd) gets EPERM;
/// naming the kernel with sendto() is allowed (NETLINK_SKB_DST). (2) A
/// socket opened unprivileged, written after regaining the capability:
/// EPERM. (3) The sender always needs the capability.
fn test_deputy() {
    const N: &[u8] = b"NL_DEPUTY";
    let mut p = [0i32; 2];
    let mut q = [0i32; 2];
    if sys_pipe2(p.as_mut_ptr(), 0) != 0 || sys_pipe2(q.as_mut_ptr(), 0) != 0 {
        return fail_why(N, b"pipe", 0);
    }
    let pid = sys_fork();
    if pid == 0 {
        if !drop_caps() {
            sys_exit(2);
        }
        let Some(nl) = Nl::open() else { sys_exit(3) };
        let fd = nl.fd;
        sys_write(p[1] as u64, &fd as *const i32 as *const u8, 4);
        let mut b = [0u8; 1];
        sys_read(q[0] as u64, b.as_mut_ptr(), 1);
        sys_exit(0);
    }
    let mut cfd: i32 = -1;
    sys_read(p[0] as u64, &mut cfd as *mut i32 as *mut u8, 4);
    let pidfd = sys_pidfd_open(pid as i32, 0) as i32;
    let fd = if pidfd >= 0 {
        sys_pidfd_getfd(pidfd, cfd, 0) as i32
    } else {
        pidfd
    };
    let (w1, s1) = if fd >= 0 {
        (newaddr_on(fd, true), newaddr_on(fd, false))
    } else {
        (fd, fd)
    };
    sys_write(q[1] as u64, b"x".as_ptr(), 1);
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    for f in [p[0], p[1], q[0], q[1], pidfd, fd] {
        if f >= 0 {
            sys_close(f as u64);
        }
    }
    if !expect(N, b"write, unprivileged opener", w1, EPERM) || !expect(N, b"sendto kernel", s1, 0) {
        return;
    }
    let pid = sys_fork();
    if pid == 0 {
        set_eff(false);
        let Some(nl) = Nl::open() else { sys_exit(3) };
        if !set_eff(true) {
            sys_exit(2);
        }
        let w = newaddr_on(nl.fd, true);
        drop_caps();
        let s = newaddr_on(nl.fd, false);
        sys_exit(if w == EPERM && s == EPERM { 0 } else { 4 });
    }
    sys_wait4(pid, &mut st, 0, 0);
    let code = (st >> 8) & 0xff;
    if st & 0x7f != 0 || code != 0 {
        return fail_why(N, b"regained caps / sender, code", code as i64);
    }
    pass(N);
}

/// A sender blocked on a full user socket is woken when the receiver's
/// last reference is closed and fails with ECONNREFUSED (Linux
/// netlink_release wakes it; netlink_attachskb sees SOCK_DEAD)
fn test_dead_receiver() {
    const N: &[u8] = b"NL_DEAD_RECEIVER";
    const ECONNREFUSED: i32 = -111;
    const SO_SNDTIMEO: i32 = 21;
    let rx = sys_socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) as i32;
    let tx = sys_socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) as i32;
    tiny_rcvbuf(rx);
    let any = nladdr(0, 0);
    sys_bind(rx, any.as_ptr(), 12);
    sys_bind(tx, any.as_ptr(), 12);
    let (_, port, _) = sockname(rx);
    // A missed wakeup ends in EAGAIN after 5 s instead of hanging
    let tv = [5i64, 0];
    sys_setsockopt(tx, SOL_SOCKET, SO_SNDTIMEO, tv.as_ptr() as *const u8, 16);
    let pid = sys_fork();
    if pid == 0 {
        // Holds the last reference once the parent closed its copy
        msleep(300);
        sys_close(rx as u64);
        sys_exit(0);
    }
    sys_close(rx as u64);
    let dst = nladdr(port, 0);
    let msg = [0u8; 1024];
    let t0 = crate::net::sk::now_ms();
    let mut r = 0;
    for _ in 0..1000 {
        r = sys_sendto(tx, msg.as_ptr(), msg.len(), 0, dst.as_ptr(), 12) as i32;
        if r < 0 {
            break;
        }
    }
    let ms = crate::net::sk::now_ms() - t0;
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    sys_close(tx as u64);
    if r != ECONNREFUSED {
        return fail_why(N, b"send", r as i64);
    }
    if ms >= 4000 {
        return fail_why(N, b"woken after ms", ms as i64);
    }
    pass(N);
}

/// SO_PASSCRED: kernel messages carry pid/uid/gid 0, a peer's carry its
/// tgid and ids (Linux netlink_recvmsg -> scm_recv)
fn test_passcred() {
    const N: &[u8] = b"NL_PASSCRED";
    const SO_PASSCRED: i32 = 16;
    let (Some(mut a), Some(b)) = (Nl::open(), Nl::open()) else {
        return fail_why(N, b"open", 0);
    };
    let one: i32 = 1;
    let on = |fd: i32| {
        sys_setsockopt(
            fd,
            SOL_SOCKET,
            SO_PASSCRED,
            &one as *const i32 as *const u8,
            4,
        )
    };
    if on(a.fd) != 0 || on(b.fd) != 0 {
        return fail_why(N, b"setsockopt", 0);
    }
    let mut r = Req::new(RTM_GETLINK, 0, &ifinfo(1, 0, 0));
    a.send(&mut r);
    let buf = rxbuf();
    let (n, c) = recv_creds(a.fd, buf);
    if n <= 0 || c != Some((0, 0, 0)) {
        let pid = c.map_or(-1, |c| c.0 as i64);
        return fail_why(N, b"kernel creds pid", if n <= 0 { n } else { pid });
    }
    let dst = nladdr(sockname(b.fd).1, 0);
    let msg = [0u8; 16];
    sys_sendto(a.fd, msg.as_ptr(), msg.len(), 0, dst.as_ptr(), 12);
    let (n, c) = recv_creds(b.fd, buf);
    let me = sys_getpid() as i32;
    match c {
        Some((pid, 0, 0)) if n == 16 && pid == me => pass(N),
        _ => fail_why(N, b"peer creds pid", c.map_or(n, |c| c.0 as i64)),
    }
}
