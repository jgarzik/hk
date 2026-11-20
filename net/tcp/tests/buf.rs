//! Receive window, buffers and memory limits (Linux tcp_input.c's
//! buffer tuning, tcp_select_initial_window, tcp_try_rmem_schedule)

use super::*;
use crate::net::mib::*;

/// A connected pair counting into one MIB, b's buffer `rcvbuf` and
/// locks `locks`
fn mib_pair_buf(mss: u32, rcvbuf: u32, locks: u8) -> (Pair, alloc::sync::Arc<NetMib>) {
    let m = NetMib::new().unwrap();
    let mut p = Pair::bare();
    p.a.mib = Some(m.clone());
    let mut out = Out::default();
    p.a.connect(open(1000, mss), p.now, &mut out);
    p.take(true, out);
    let (_, syn) = p.wire.pop_front().unwrap();
    let mut out = Out::default();
    p.b.mib = Some(m.clone());
    p.b.rcvbuf = rcvbuf;
    p.b.userlocks = locks;
    p.b.passive_in(&seg_in(&syn), open(5000, mss), p.now, &mut out);
    p.take(false, out);
    p.run();
    assert_eq!(p.b.state, TcpState::Established);
    (p, m)
}

/// The SYN's and SYN-ACK's windows come from the buffer as Linux
/// tcp_select_initial_window makes them: tcp_rmem[1]'s 131072 bytes
/// hold 131072 * 65 / 256 (TCP_DEFAULT_SCALING_RATIO) = 33280, rounded
/// down to whole segments; the scale fits tcp_rmem[2]; once
/// established the clamp keeps a segment of the buffer back
/// (tcp_init_buffer_space) and rcv_ssthresh starts within it
#[test]
fn initial_window_from_buffer() {
    let mut a = TcpCb::new(cfg(), Default::default());
    a.rcvbuf = 131_072;
    let mut out = Out::default();
    a.connect(open(1, 65_483), 0, &mut out);
    let syn = wire(&out).remove(0);
    assert_eq!((syn.wnd, syn.ws), (33_280, Some(7)));
    let mut a = TcpCb::new(cfg(), Default::default());
    a.rcvbuf = 131_072;
    let mut out = Out::default();
    a.connect(open(1, 1460), 0, &mut out);
    let syn = wire(&out).remove(0);
    // 22 segments of 1460
    assert_eq!(syn.wnd, 32_120);
    // The SYN-ACK: segments less the timestamp option
    let mut b = TcpCb::new(cfg(), Default::default());
    b.rcvbuf = 131_072;
    let mut o2 = Out::default();
    b.passive_in(&seg_in(&syn), open(2, 1460), 0, &mut o2);
    let synack = wire(&o2).remove(0);
    assert_eq!(synack.wnd, 22 * 1448);
    let mut o3 = Out::default();
    a.feed(&seg_in(&synack), 1, &mut o3);
    assert_eq!(a.state, TcpState::Established);
    assert_eq!(a.window_clamp(), 33_280 - 1460);
    assert_eq!(a.rcv_ssthresh(), 33_280 - 1460);
    // A fixed SO_RCVBUF bounds the clamp, and so the scale
    let mut c = TcpCb::new(cfg(), Default::default());
    c.rcvbuf = 4096;
    c.userlocks = crate::net::tcp::buf::RCVBUF_LOCK;
    let mut out = Out::default();
    c.connect(open(1, 1460), 0, &mut out);
    let syn = wire(&out).remove(0);
    assert_eq!((syn.wnd, syn.ws), (1040, Some(0)));
}

/// TCP_WINDOW_CLAMP (Linux tcp_set_window_clamp): at least
/// SOCK_MIN_RCVBUF / 2, 0 only while closed; a smaller clamp lowers
/// rcv_ssthresh and the window offered
#[test]
fn window_clamp_option() {
    let mut c = TcpCb::new(cfg(), Default::default());
    assert_eq!(c.window_clamp(), 0);
    c.set_window_clamp(100).unwrap();
    assert_eq!(c.window_clamp(), 1152);
    c.set_window_clamp(0).unwrap();
    assert_eq!(c.window_clamp(), 0);
    c.set_window_clamp(20_000).unwrap();
    // The next connection starts from it
    let mut out = Out::default();
    c.connect(open(1, 1460), 0, &mut out);
    assert_eq!(c.window_clamp(), 20_000);
    let mut p = Pair::with_cap(1460, 1 << 20);
    assert_eq!(p.b.set_window_clamp(0), Err(KernelError::InvalidArgument));
    p.b.set_window_clamp(5000).unwrap();
    assert_eq!(p.b.rcv_ssthresh(), 5000);
    assert!(p.b.window_now() <= 5000_u32.next_multiple_of(1 << p.b.rcv_wscale));
    // Raised again: rcv_ssthresh follows to the window offered
    let offered = p.b.rcv_wnd_adv();
    p.b.set_window_clamp(1 << 20).unwrap();
    assert_eq!(p.b.rcv_ssthresh(), offered.max(5000));
}

/// rcv_ssthresh grows as segments with little overhead arrive (Linux
/// tcp_grow_window), up to the clamp, and TCP_INFO reports it
#[test]
fn rcv_ssthresh_grows() {
    let mut p = Pair::with_cap(1460, 1 << 20);
    let start = p.b.rcv_ssthresh();
    assert_eq!(start, 65_535);
    let data = pattern(400_000);
    assert_eq!(transfer(&mut p, &data, 10_000), data);
    let ssth = p.b.rcv_ssthresh();
    assert!(ssth > start && ssth <= p.b.window_clamp(), "{ssth}");
    let info = super::super::info::tcp_info(&p.b, p.now);
    let at = |o: usize| u32::from_ne_bytes(info[o..o + 4].try_into().unwrap());
    assert_eq!(at(64), ssth);
}

/// Past a fixed receive buffer (Linux tcp_try_rmem_schedule's
/// sk_rmem_alloc > sk_rcvbuf): tcp_prune_queue cuts rcv_ssthresh
/// (tcp_clamp_window), prunes the out-of-order queue from the top down
/// to the incoming skb (OfoPruned) and, still over, drops it
/// (RcvPruned, TCPOFODrop); an in-order skb prunes what lies above
/// it, and with data queued and nothing to prune it is dropped
/// (TCPRcvQDrop) with a zero window
#[test]
fn rcvbuf_limit_prunes() {
    let (mut p, m) = mib_pair_buf(1460, 4000, crate::net::tcp::buf::RCVBUF_LOCK);
    let base = p.b.rcv_nxt;
    let ack = p.b.snd_una;
    let one = |p: &mut Pair, off: u32| {
        let d = [7u8];
        let s = SegIn {
            seq: base.wrapping_add(off),
            ack,
            flags: flags::ACK,
            wnd: 8000,
            data: &d,
            ..Default::default()
        };
        let mut out = Out::default();
        p.b.feed(&s, p.now, &mut out);
        wire(&out)
    };
    // One-byte skbs beyond a hole, each a whole skb of truesize
    let mut off = 2;
    while p.b.rmem_alloc() <= p.b.rcvbuf as usize {
        one(&mut p, off);
        off += 2;
    }
    assert_eq!(m.net.fold(LINUX_MIB_RCVPRUNED), 0);
    // Landing last, nothing to prune below it: dropped
    let held = p.b.ooo.pieces();
    one(&mut p, off);
    assert_eq!(p.b.ooo.pieces(), held);
    assert_eq!(m.net.fold(LINUX_MIB_PRUNECALLED), 1);
    assert_eq!(m.net.fold(LINUX_MIB_RCVPRUNED), 1);
    assert_eq!(m.net.fold(LINUX_MIB_TCPOFODROP), 1);
    assert_eq!(m.net.fold(LINUX_MIB_OFOPRUNED), 0);
    assert_eq!(p.b.rcv_ssthresh(), p.b.window_clamp().min(2 * 1460));
    // In order: the out-of-order skbs above it go
    one(&mut p, 0);
    assert_eq!(m.net.fold(LINUX_MIB_OFOPRUNED), 1);
    assert!(p.b.ooo.pieces() < held);
    assert_eq!(p.b.rcvq_len(), 1);
    // Fill the buffer in order (nothing out of order is left to prune)
    p.b.ooo = super::super::cb::Ooo::default();
    let mut n = 1;
    while p.b.rmem_alloc() <= p.b.rcvbuf as usize {
        one(&mut p, n);
        n += 1;
    }
    let segs = one(&mut p, n);
    assert_eq!(m.net.fold(LINUX_MIB_TCPRCVQDROP), 1);
    assert_eq!(p.b.rcvq_len(), n as usize);
    assert_eq!(segs.last().map(|s| s.wnd), Some(0));
}
