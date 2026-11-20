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

/// Push `data` from a to b, b reading what arrived every `step` ms of
/// the virtual clock (a receive RTT for tcp_rcv_space_adjust)
fn paced(p: &mut Pair, data: &[u8], step: u64) -> usize {
    let (mut sent, mut got) = (0, 0);
    for _ in 0..100_000 {
        if sent < data.len() {
            sent += p.send_a(&data[sent..]);
        }
        p.run();
        got += p.read_b(1 << 20).len();
        p.run();
        if got >= data.len() {
            break;
        }
        p.now += step;
        if p.wire.is_empty() {
            p.tick();
        }
    }
    got
}

/// Dynamic right-sizing (Linux tcp_rcv_space_adjust): a reader taking
/// more each receive RTT gets a buffer for it, up to tcp_rmem[2], and
/// the window clamp follows; TCP_INFO reports the receive RTT and the
/// space. A fixed SO_RCVBUF or tcp_moderate_rcvbuf 0 leaves the buffer
#[test]
fn rcvbuf_autotuning() {
    let data = pattern(3 << 20);
    let mut p = Pair::with_cap(1460, 131_072);
    let clamp = p.b.window_clamp();
    assert_eq!(paced(&mut p, &data, 1), data.len());
    assert!(p.b.rcvbuf > 131_072, "{}", p.b.rcvbuf);
    assert!(p.b.rcvbuf <= p.b.cfg.rmem_max);
    assert!(p.b.window_clamp() > clamp);
    assert_eq!(
        p.b.window_clamp(),
        p.b.win_from_space(i64::from(p.b.rcvbuf)) as u32
    );
    let info = super::super::info::tcp_info(&p.b, p.now);
    let at = |o: usize| u32::from_ne_bytes(info[o..o + 4].try_into().unwrap());
    assert!(at(92) > 0, "rcv_rtt");
    assert_eq!(at(96), p.b.rcvq_space.space);
    assert!(at(96) > 0);
    // SO_RCVBUF set
    let mut p = Pair::with_cap(1460, 131_072);
    p.b.userlocks = crate::net::tcp::buf::RCVBUF_LOCK;
    assert_eq!(paced(&mut p, &data, 1), data.len());
    assert_eq!(p.b.rcvbuf, 131_072);
    // tcp_moderate_rcvbuf 0
    let mut c = cfg();
    c.moderate_rcvbuf = false;
    let mut p = Pair::with_cfgs(1460, 131_072, cfg(), c);
    assert_eq!(paced(&mut p, &data, 1), data.len());
    assert_eq!(p.b.rcvbuf, 131_072);
}

/// SO_RCVLOWAT on TCP (Linux tcp_set_rcvlowat): at most half of
/// tcp_rmem[2] (of a fixed buffer), and an unfixed buffer grows to
/// offer it as window, the clamp with it
#[test]
fn rcvlowat_grows_buffer() {
    let mut c = TcpCb::new(cfg(), Default::default());
    c.rcvbuf = 131_072;
    assert_eq!(c.set_rcvlowat(i32::MAX), (6 * 1024 * 1024) / 2);
    let mut c = TcpCb::new(cfg(), Default::default());
    c.rcvbuf = 131_072;
    assert_eq!(c.set_rcvlowat(100_000), 100_000);
    assert_eq!(c.rcvbuf, c.space_from_win(100_000) as u32);
    assert_eq!(c.window_clamp(), 100_000);
    c.userlocks = crate::net::tcp::buf::RCVBUF_LOCK;
    assert_eq!(c.set_rcvlowat(i32::MAX), c.rcvbuf as i32 / 2);
}

/// A pair whose a starts from tcp_wmem[1]'s 16 KiB send buffer, with
/// `locks`
fn snd_pair(locks: u8) -> Pair {
    let mut p = Pair::bare();
    p.a.sndbuf = 16_384;
    p.a.userlocks = locks;
    let mut out = Out::default();
    p.a.connect(open(1000, 1460), p.now, &mut out);
    p.take(true, out);
    let (_, syn) = p.wire.pop_front().unwrap();
    let mut out = Out::default();
    p.b.rcvbuf = 1 << 22;
    p.b.passive_in(&seg_in(&syn), open(5000, 1460), p.now, &mut out);
    p.take(false, out);
    p.run();
    assert_eq!(p.a.state, TcpState::Established);
    p
}

/// Linux tcp_sndbuf_expand when established (tcp_init_buffer_space):
/// twice the initial window of worst-case skbs, each
/// roundup_pow_of_two(MSS + MAX_TCP_HEADER + shinfo) + sk_buff; as the
/// window grows, an ACK freeing space for a sender that found the
/// buffer full expands it again (tcp_new_space); never a set SO_SNDBUF
#[test]
fn sndbuf_expand() {
    use core::sync::atomic::Ordering;
    let mut p = snd_pair(0);
    assert_eq!(p.a.sndbuf, 2 * 10 * (4096 + 256));
    let data = pattern(2 << 20);
    let (mut sent, mut got) = (0, 0);
    for _ in 0..10_000 {
        if sent < data.len() {
            let n = p.send_a(&data[sent..]);
            sent += n;
            if sent < data.len() {
                // The sender found the buffer full (sk_stream_wait_memory)
                p.a.live.nospace.store(true, Ordering::Release);
            }
        }
        p.run();
        got += p.read_b(1 << 22).len();
        if got == data.len() {
            break;
        }
        if p.wire.is_empty() {
            p.tick();
        }
    }
    assert_eq!(got, data.len());
    // Expanded for a window of more than ten segments, a whole number
    // of worst-case skbs
    assert!(p.a.sndbuf > 2 * 10 * (4096 + 256), "{}", p.a.sndbuf);
    assert_eq!(p.a.sndbuf % (2 * (4096 + 256)), 0);
    let p = snd_pair(crate::net::tcp::buf::SNDBUF_LOCK);
    assert_eq!(p.a.sndbuf, 16_384);
}

/// Linux sk_stream_moderate_sndbuf: half of what is queued
/// (sk_wmem_queued), at least SOCK_MIN_SNDBUF; a set SO_SNDBUF stays
#[test]
fn sndbuf_moderate() {
    let mut p = snd_pair(0);
    p.filter = drop_all;
    let sent = p.send_a(&pattern(30_000));
    assert_eq!(sent, 30_000);
    let q = p.a.wmem_queued;
    p.a.moderate_sndbuf();
    assert_eq!(p.a.sndbuf as usize, q / 2);
    let mut p = snd_pair(0);
    p.a.moderate_sndbuf();
    assert_eq!(p.a.sndbuf, crate::net::sock::MIN_SNDBUF);
    let mut p = snd_pair(crate::net::tcp::buf::SNDBUF_LOCK);
    p.a.moderate_sndbuf();
    assert_eq!(p.a.sndbuf, 16_384);
}

/// Remote-sized values wrap where Linux's unsigned C arithmetic
/// wraps, never panicking: tcp_rcv_space_adjust's u64 growth for a
/// huge copy, tcp_init_buffer_space's u32 sum with a huge clamp
#[test]
fn buffer_arithmetic_wraps() {
    let mut c = TcpCb::new(cfg(), Default::default());
    c.adv_mss = 1460;
    c.rcvq_space.space = 1;
    c.rcvbuf_grow(u32::MAX);
    assert!(c.rcvbuf <= c.cfg.rmem_max);
    let mut c = TcpCb::new(cfg(), Default::default());
    c.adv_mss = 1460;
    c.rcvbuf = 1 << 20;
    c.window_clamp = u32::MAX - 100;
    c.init_buffer_space();
    assert_eq!(c.window_clamp(), c.full_space() - 1460);
    c.set_window_clamp(-1).unwrap();
    c.init_buffer_space();
}

/// Challenge ACKs of connections sharing `net` at `now`, one in-window
/// SYN each (RFC 5961 4.2): how many went out
fn challenges(net: &alloc::sync::Arc<crate::net::tcp::netns::TcpNet>, n: usize, now: u64) -> usize {
    let mut sent = 0;
    for _ in 0..n {
        let mut p = Pair::new(1460);
        p.b.net = Some(net.clone());
        let syn = SegIn {
            seq: p.b.rcv_nxt,
            flags: flags::SYN,
            ..Default::default()
        };
        let mut out = Out::default();
        p.b.feed(&syn, now, &mut out);
        sent += wire(&out).len();
    }
    sent
}

/// The namespace's challenge-ACK budget (Linux tcp_send_challenge_ack,
/// tcp_challenge_ack_limit): by default (INT_MAX) none; with a limit,
/// each second draws a budget from [limit/2, limit*3/2) shared by every
/// connection
#[test]
fn challenge_ack_budget() {
    let net = alloc::sync::Arc::new(crate::net::tcp::netns::TcpNet::default());
    assert_eq!(net.challenge_limit(), i32::MAX);
    assert_eq!(challenges(&net, 8, 5000), 8);
    net.set_challenge_limit(2).unwrap();
    // A budget of 1 or 2 for second 6
    let n = challenges(&net, 8, 6000);
    assert!((1..=2).contains(&n), "{n}");
    assert_eq!(challenges(&net, 8, 6500), 0);
    // A new second, a new budget
    assert!(challenges(&net, 8, 7000) >= 1);
}

/// Linux inet_twsk_alloc's tcp_max_tw_buckets: refused once as many
/// entries are scheduled; a negative limit compares as a huge one
#[test]
fn tw_buckets_limit() {
    let net = crate::net::tcp::netns::TcpNet::default();
    net.set_max_tw_buckets(2).unwrap();
    assert!(!net.tw_full());
    net.tw_add();
    net.tw_add();
    assert!(net.tw_full());
    net.tw_sub();
    assert!(!net.tw_full());
    net.set_max_tw_buckets(0).unwrap();
    assert!(net.tw_full());
    net.set_max_tw_buckets(-1).unwrap();
    assert!(!net.tw_full());
}

/// A timewait entry in the FIN_WAIT2 substate (Linux
/// tcp_timewait_state_process): a duplicate ACK does nothing, new data
/// or a SYN resets, an in-window RST ends it, an out-of-window segment
/// is ACKed, and the peer's FIN makes it a true TIME_WAIT for 2MSL
#[test]
fn fin_wait2_timewait_entry() {
    let mut p = Pair::new(1460);
    let mut out = Out::default();
    p.a.close(false, p.now, &mut out);
    p.take(true, out);
    p.run();
    assert!(p.a_out.timewait);
    let tw0 = TwCb::from_cb(&p.a);
    assert_eq!(tw0.substate(), TcpState::FinWait2);
    let (nxt, una) = (tw0.rcv_nxt, p.a.snd_max);
    let seg = |seq: u32, fl: u8, data: &[u8]| {
        let mut h = SegIn {
            seq,
            ack: una,
            flags: fl,
            ..Default::default()
        }
        .hdr();
        h.set_len(data.len() as u32);
        h
    };
    let now = p.now + 10;
    let mut tw = tw0.clone();
    assert_eq!(
        tw.rcv(&seg(nxt, flags::ACK, &[]), now, false, None),
        TwStatus::Success
    );
    assert_eq!(
        tw.rcv(&seg(nxt, flags::ACK, &[1, 2]), now, false, None),
        TwStatus::Rst
    );
    assert_eq!(
        tw.rcv(&seg(nxt, flags::SYN, &[]), now, false, None),
        TwStatus::Rst
    );
    assert_eq!(
        tw.rcv(&seg(nxt, flags::RST, &[]), now, false, None),
        TwStatus::Kill
    );
    let far = nxt.wrapping_add(1 << 30);
    assert_eq!(
        tw.rcv(&seg(far, flags::ACK, &[]), now, false, None),
        TwStatus::Ack
    );
    let fin = seg(nxt, flags::ACK | flags::FIN, &[]);
    assert_eq!(tw.rcv(&fin, now, false, None), TwStatus::Ack);
    assert_eq!(tw.substate(), TcpState::TimeWait);
    assert_eq!(tw.rcv_nxt, nxt.wrapping_add(1));
    assert_eq!(tw.expires(), now + TIMEWAIT_LEN);
    assert_eq!(tw.ack(now).ack, nxt.wrapping_add(1));
}

/// Linux tcp_space subtracts the socket's backlog (sk_backlog.len): the
/// window offered shrinks while segments wait for the owner
#[test]
fn backlog_counts_in_space() {
    use core::sync::atomic::Ordering;
    let mut p = Pair::with_cap(1460, 1 << 16);
    let free = p.b.space();
    p.b.live.backlog_len.store(1 << 15, Ordering::Relaxed);
    assert_eq!(p.b.space(), free - p.b.win_from_space(1 << 15));
    p.b.live.backlog_len.store(1 << 16, Ordering::Relaxed);
    assert_eq!(p.b.window_now(), 0);
}

/// The send queues' truesize (Linux sk_wmem_queued)
fn queued_truesize(c: &TcpCb) -> usize {
    c.wq.iter().map(|s| s.truesize()).sum::<usize>()
        + c.rtx.iter().map(|s| s.truesize()).sum::<usize>()
}

/// Send memory is skb truesize against all of SO_SNDBUF (Linux
/// sk_wmem_queued, sk_stream_memory_free): charged as skbs are queued
/// or split, released as they are acknowledged or merged, through
/// losses, SACK and retransmission; the buffer takes payload up to it
#[test]
fn send_memory_is_truesize() {
    let mut p = Pair::with_cap(1000, 1 << 20);
    p.a.sndbuf = 64 * 1024;
    p.filter = drop_all;
    let n = p.send_a(&pattern(200_000));
    assert_eq!(p.a.wmem_queued, queued_truesize(&p.a));
    // Up to one skb past the buffer, payload short of it
    let skb = p.a.wq.iter().next().map(|s| s.truesize()).unwrap();
    assert!(p.a.wmem_queued >= 64 * 1024 && p.a.wmem_queued < 64 * 1024 + skb);
    assert!(n < 64 * 1024 && n > 32 * 1024, "{n}");
    assert!(!p.a.memory_free());
    assert!(!p.a.writable());
    let mut p = Pair::with_cap(1000, 1 << 20);
    p.filter = lossy;
    let data = pattern(300_000);
    let mut sent = 0;
    for _ in 0..20_000 {
        if sent < data.len() {
            sent += p.send_a(&data[sent..]);
        }
        p.run();
        assert_eq!(p.a.wmem_queued, queued_truesize(&p.a));
        p.read_b(1 << 20);
        if sent == data.len() && p.a.snd_una == p.a.snd_max {
            break;
        }
        if p.wire.is_empty() {
            p.tick();
        }
    }
    assert_eq!(p.a.snd_una, p.a.snd_max);
    assert_eq!(p.a.wmem_queued, 0);
}
