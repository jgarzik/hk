//! TCP SYN_RECEIVED on close (hk and Linux), seen on the wire: a peer
//! played with raw IP segments from an address routed out lo (segments
//! to it loop back and find no socket, unanswered: TCP_LO_ROUTE), its
//! segments captured by an ETH_P_IP packet socket on lo.
//!
//! - TCP_SIMOPEN_CLOSE: a simultaneous open closed in SYN_RECEIVED
//!   sends a FIN, not a RST (Linux __tcp_close: tcp_close_state goes to
//!   FIN_WAIT_1, tcp_send_fin); the timeout resends the SYN-ACK; the
//!   peer's ACK and FIN take it to TIME_WAIT
//! - TCP_SIMOPEN_SYNACK: crossed SYNs, then the peer's bare SYN-ACK:
//!   answered by an ACK, ESTABLISHED (Linux 6.11 23e89e8ee7be:
//!   tcp_validate_incoming lets it through; Ubuntu's 6.8 has it too)
//! - TCP_LISTEN_CLOSE_REQ: a listener closed with a half-open
//!   connection sends nothing (Linux inet_csk_listen_stop leaves request
//!   socks alone; reqsk_timer_handler drops them silently); the peer's
//!   ACK afterwards gets the RST of no socket
//! - TCP_LISTEN_CLOSE_REBIND: a half-open connection holds no port
//!   (Linux request socks are not in bhash; the child inherits the port
//!   in tcp_v4_syn_recv_sock): the closed listener's port binds again
//!   at once without SO_REUSEADDR
//! - TCP_LISTEN_CLOSE_ACCEPTQ: a listener closed with a completed,
//!   unaccepted connection resets it (inet_child_forget): ECONNRESET

use hk_syscall::{
    AF_INET, SOCK_DGRAM, SOCK_NONBLOCK, SOCK_RAW, SOCK_STREAM, sys_bind, sys_getsockopt,
    sys_listen, sys_recvfrom, sys_socket,
};

use crate::harness::T;
use crate::net::nl::{NLM_F_CREATE, NLM_F_EXCL, Nl, route};
use crate::net::sk::*;
use crate::net::tcp_xfer::set_timeo;

/// The played peer's address (TEST-NET-1), routed out lo
const VOID: [u8; 4] = [192, 0, 2, 78];
const PEER_PORT: u16 = 7781;
const AF_PACKET: i32 = 17;
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_RAW: i32 = 255;
const ECONNRESET: i64 = -104;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

pub fn run_tests() {
    crate::helpers::println(b"=== TCP SYN_RECEIVED Close Tests ===");
    test_simopen_close();
    test_simopen_synack();
    test_listen_close_req();
    test_listen_close_rebind();
    test_listen_close_acceptq();
}

/// A TCP segment as captured
#[derive(Clone, Copy, Default)]
struct Seg {
    saddr: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
}

/// The played peer: the route, a raw socket to send, a packet socket
/// to capture
struct Peer {
    nl: Nl,
    lo: u32,
    raw: i32,
    cap: i32,
}

impl Peer {
    fn new(t: &mut T) -> Option<Self> {
        let Some(mut nl) = Nl::open() else {
            t.ok(b"netlink", false, 0);
            return None;
        };
        let lo = crate::net::packet::ifindex(b"lo") as u32;
        let r = route(
            &mut nl,
            true,
            VOID,
            32,
            [0; 4],
            lo,
            NLM_F_CREATE | NLM_F_EXCL,
        );
        if !t.eq(b"route add", r as i64, 0) {
            return None;
        }
        let raw = sys_socket(AF_INET, SOCK_RAW, IPPROTO_RAW) as i32;
        let cap = sys_socket(AF_PACKET, SOCK_DGRAM, ETH_P_IP.to_be() as i32) as i32;
        let mut sll = [0u8; 20];
        sll[0..2].copy_from_slice(&(AF_PACKET as u16).to_ne_bytes());
        sll[2..4].copy_from_slice(&ETH_P_IP.to_be_bytes());
        sll[4..8].copy_from_slice(&(lo as i32).to_ne_bytes());
        let b = sys_bind(cap, sll.as_ptr(), 20);
        let p = Self { nl, lo, raw, cap };
        if !t.ok(b"sockets", raw >= 0 && cap >= 0 && b == 0, b) {
            return None;
        }
        Some(p)
    }

    /// Send a segment VOID:PEER_PORT -> 127.0.0.1:`dport` (no options)
    fn send(&self, dport: u16, seq: u32, ack: u32, flags: u8) -> i64 {
        let mut p = [0u8; 40];
        p[..20].copy_from_slice(&[
            0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1,
        ]);
        p[12..16].copy_from_slice(&VOID);
        let h = &mut p[20..];
        h[0..2].copy_from_slice(&PEER_PORT.to_be_bytes());
        h[2..4].copy_from_slice(&dport.to_be_bytes());
        h[4..8].copy_from_slice(&seq.to_be_bytes());
        h[8..12].copy_from_slice(&ack.to_be_bytes());
        h[12] = 5 << 4;
        h[13] = flags;
        h[14..16].copy_from_slice(&65535u16.to_be_bytes());
        let c = tcp_csum(&p[12..16], &p[16..20], &p[20..]);
        p[36..38].copy_from_slice(&c.to_be_bytes());
        send_to(self.raw, &p, LO, 0, 0)
    }

    /// The next segment within `ms` from 127.0.0.1:`port` to the peer
    fn from(&self, port: u16, ms: u64) -> Option<Seg> {
        let end = now_ms() + ms;
        let mut b = [0u8; 256];
        loop {
            let left = end.saturating_sub(now_ms());
            if left == 0 || poll1(self.cap, 1, left as i32).0 != 1 {
                return None;
            }
            let n = sys_recvfrom(
                self.cap,
                b.as_mut_ptr(),
                b.len(),
                MSG_DONTWAIT,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
            if let Some(s) = parse(&b[..n.max(0) as usize])
                && s.saddr == LO
                && s.sport == port
                && s.dport == PEER_PORT
            {
                return Some(s);
            }
        }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        route(&mut self.nl, false, VOID, 32, [0; 4], self.lo, 0);
        close(self.raw);
        close(self.cap);
    }
}

/// A captured IPv4 TCP segment
fn parse(b: &[u8]) -> Option<Seg> {
    if b.len() < 20 || b[0] >> 4 != 4 || b[9] != 6 {
        return None;
    }
    let ihl = usize::from(b[0] & 15) * 4;
    let h = b.get(ihl..ihl + 20)?;
    let be = |o: usize| u32::from_be_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]);
    Some(Seg {
        saddr: [b[12], b[13], b[14], b[15]],
        sport: u16::from_be_bytes([h[0], h[1]]),
        dport: u16::from_be_bytes([h[2], h[3]]),
        seq: be(4),
        ack: be(8),
        flags: h[13],
    })
}

/// TCP checksum over the pseudo header and `seg`
fn tcp_csum(src: &[u8], dst: &[u8], seg: &[u8]) -> u16 {
    let mut s: u32 = 6 + seg.len() as u32;
    for c in src.chunks(2).chain(dst.chunks(2)).chain(seg.chunks(2)) {
        s += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

/// TCP_INFO's tcpi_state
fn tcp_state(fd: i32) -> i64 {
    let mut b = [0u8; 8];
    let mut len = b.len() as u32;
    sys_getsockopt(fd, IPPROTO_TCP, 11, b.as_mut_ptr(), &mut len);
    i64::from(b[0])
}

/// The flags and numbers of `s`, or a sign it never came
fn got(s: Option<Seg>) -> (i64, u32, u32) {
    s.map_or((-1, 0, 0), |s| (i64::from(s.flags), s.seq, s.ack))
}

fn test_simopen_close() {
    const SYN_RECV: i64 = 3;
    const Y: u32 = 0x1000_0000;
    let mut t = T::new(b"TCP_SIMOPEN_CLOSE");
    let Some(peer) = Peer::new(&mut t) else {
        return t.done();
    };
    let a = sys_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0) as i32;
    bind(a, LO, 0);
    let pa = port(a);
    t.eq(b"connect", connect(a, VOID, PEER_PORT), EINPROGRESS);
    let (f, iss, _) = got(peer.from(pa, 1000));
    t.eq(b"syn", f, i64::from(SYN));
    // Crossed SYNs: SYN_RECEIVED, a SYN-ACK
    t.eq(b"peer syn", peer.send(pa, Y, 0, SYN), 40);
    let (f, seq, ack) = got(peer.from(pa, 1000));
    t.ok(
        b"syn-ack",
        f == i64::from(SYN | ACK) && seq == iss && ack == Y + 1,
        f,
    );
    t.eq(b"syn_recv", tcp_state(a), SYN_RECV);
    close(a);
    let (f, seq, ack) = got(peer.from(pa, 1000));
    t.eq(b"close sends fin", f, i64::from(FIN | ACK));
    t.ok(b"fin numbers", seq == iss + 1 && ack == Y + 1, seq as i64);
    // FIN_WAIT_1 with the SYN-ACK unacknowledged: the timeout resends
    // the SYN-ACK
    let (f, seq, ack) = got(peer.from(pa, 5000));
    t.ok(
        b"syn-ack again",
        f == i64::from(SYN | ACK) && seq == iss && ack == Y + 1,
        f,
    );
    // SYN and FIN acknowledged, then the peer's FIN: TIME_WAIT's ACK
    t.eq(b"peer ack", peer.send(pa, Y + 1, iss + 2, ACK), 40);
    t.eq(b"peer fin", peer.send(pa, Y + 1, iss + 2, FIN | ACK), 40);
    let (f, seq, ack) = got(peer.from(pa, 1000));
    t.ok(
        b"fin acked",
        f == i64::from(ACK) && seq == iss + 2 && ack == Y + 2,
        f,
    );
    t.done();
}

fn test_simopen_synack() {
    const ESTABLISHED: i64 = 1;
    const Y: u32 = 0x3000_0000;
    let mut t = T::new(b"TCP_SIMOPEN_SYNACK");
    let Some(peer) = Peer::new(&mut t) else {
        return t.done();
    };
    let a = sys_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0) as i32;
    bind(a, LO, 0);
    let pa = port(a);
    t.eq(b"connect", connect(a, VOID, PEER_PORT), EINPROGRESS);
    let (f, iss, _) = got(peer.from(pa, 1000));
    t.eq(b"syn", f, i64::from(SYN));
    t.eq(b"peer syn", peer.send(pa, Y, 0, SYN), 40);
    let (f, _, _) = got(peer.from(pa, 1000));
    t.eq(b"syn-ack", f, i64::from(SYN | ACK));
    t.eq(b"peer syn-ack", peer.send(pa, Y, iss + 1, SYN | ACK), 40);
    let (f, seq, ack) = got(peer.from(pa, 1000));
    t.ok(
        b"acked",
        f == i64::from(ACK) && seq == iss + 1 && ack == Y + 1,
        f,
    );
    // Ubuntu's 6.8 (CI's reference) carries the 6.11 change too
    t.eq(b"state", tcp_state(a), ESTABLISHED);
    close(a);
    t.done();
}

fn test_listen_close_req() {
    const Y: u32 = 0x2000_0000;
    let mut t = T::new(b"TCP_LISTEN_CLOSE_REQ");
    let Some(peer) = Peer::new(&mut t) else {
        return t.done();
    };
    let l = tcp();
    bind(l, LO, 0);
    let pl = port(l);
    t.eq(b"listen", sys_listen(l, 8), 0);
    t.eq(b"peer syn", peer.send(pl, Y, 0, SYN), 40);
    let (f, s, ack) = got(peer.from(pl, 1000));
    t.ok(b"syn-ack", f == i64::from(SYN | ACK) && ack == Y + 1, f);
    // Neither a RST at close nor a SYN-ACK resent after it
    close(l);
    t.eq(b"silent", got(peer.from(pl, 1500)).0, -1);
    // The request is gone: the completing ACK finds no socket
    t.eq(b"peer ack", peer.send(pl, Y + 1, s + 1, ACK), 40);
    let (f, seq, _) = got(peer.from(pl, 1000));
    t.eq(b"reset", f, i64::from(RST));
    t.ok(b"reset seq", seq == s + 1, seq as i64);
    t.done();
}

fn test_listen_close_rebind() {
    const Y: u32 = 0x4000_0000;
    let mut t = T::new(b"TCP_LISTEN_CLOSE_REBIND");
    let Some(peer) = Peer::new(&mut t) else {
        return t.done();
    };
    let l = tcp();
    bind(l, LO, 0);
    let pl = port(l);
    t.eq(b"listen", sys_listen(l, 8), 0);
    t.eq(b"peer syn", peer.send(pl, Y, 0, SYN), 40);
    t.eq(b"syn-ack", got(peer.from(pl, 1000)).0, i64::from(SYN | ACK));
    close(l);
    let n = tcp();
    t.eq(b"rebind", bind(n, LO, pl), 0);
    close(n);
    t.done();
}

fn test_listen_close_acceptq() {
    let mut t = T::new(b"TCP_LISTEN_CLOSE_ACCEPTQ");
    let l = tcp();
    bind(l, LO, 0);
    sys_listen(l, 8);
    let c = tcp();
    set_timeo(c, 5000);
    t.eq(b"connect", connect(c, LO, port(l)), 0);
    close(l);
    let mut b = [0u8; 4];
    t.eq(b"reset", recv(c, &mut b, 0), ECONNRESET);
    close(c);
    t.done();
}
