//! Deterministic tests of the I/O-free control block: two control
//! blocks over a simulated network with a virtual clock, where a filter
//! may drop, duplicate or reorder segments.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::cb::{
    Cfg, MSS_DEFAULT, Open, Out, RCV_SHUTDOWN, RTO_MAX, TIMEWAIT_LEN, TcpCb, TcpState, flags, wake,
};
use super::output::HEAD_TRUESIZE;
use super::timewait::{TwCb, TwStatus};
use crate::mm::page_alloc::Gfp;
use crate::net::skb::{Sacks, SkBuff};
use crate::util::error::KernelError;

/// Buffers and memory (`buf.rs`)
mod buf;

/// A segment as the wire sees it: header fields and payload
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Seg {
    seq: u32,
    ack: u32,
    flags: u8,
    wnd: u16,
    mss: Option<u16>,
    ws: Option<u8>,
    ts: Option<(u32, u32)>,
    sack_perm: bool,
    sack: Sacks,
    data: Vec<u8>,
}

impl Seg {
    fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }
}

/// A segment to feed a control block
#[derive(Clone, Copy, Debug, Default)]
struct SegIn<'a> {
    seq: u32,
    ack: u32,
    flags: u8,
    wnd: u16,
    mss: Option<u16>,
    ws: Option<u8>,
    ts: Option<(u32, u32)>,
    sack_perm: bool,
    sack: Sacks,
    data: &'a [u8],
}

impl SegIn<'_> {
    /// An skb holding its payload, its control block filled (Linux
    /// tcp_v4_fill_cb)
    fn skb(&self) -> Box<SkBuff> {
        let h = self.hdr();
        let mut skb = SkBuff::alloc_tx(self.data.len(), Gfp::KERNEL).unwrap();
        skb.put_slice(self.data).unwrap();
        let t = skb.tcp_mut();
        t.seq = h.seq;
        t.end_seq = h.end_seq;
        t.ack_seq = h.ack;
        t.flags = h.flags;
        skb
    }

    /// Its header as parsed
    fn hdr(&self) -> super::cb::Seg {
        let mut h = super::cb::Seg {
            seq: self.seq,
            ack: self.ack,
            flags: self.flags,
            wnd: self.wnd,
            mss: self.mss,
            ws: self.ws,
            ts: self.ts,
            sack_perm: self.sack_perm,
            sack: self.sack,
            ..Default::default()
        };
        h.set_len(self.data.len() as u32);
        h
    }
}

/// Feeding segments given as header + payload slice
trait Feed {
    fn feed(&mut self, s: &SegIn<'_>, now: u64, out: &mut Out);
    fn passive_in(&mut self, s: &SegIn<'_>, o: Open, now: u64, out: &mut Out);
}

impl Feed for TcpCb {
    /// Feed `s`; a request's completing ACK is handed back, as the
    /// socket layer does with a listener that has room
    /// (`TcpSock::syn_recv_sock`): made a full socket, fed again
    fn feed(&mut self, s: &SegIn<'_>, now: u64, out: &mut Out) {
        let h = s.hdr();
        self.input(&h, s.skb(), now, out);
        if let Some(skb) = out.req_ack.take() {
            self.req_full = true;
            self.input(&h, skb, now, out);
        }
    }

    fn passive_in(&mut self, s: &SegIn<'_>, o: Open, now: u64, out: &mut Out) {
        self.passive(&s.hdr(), o, now, out);
    }
}

/// The segments `out` holds, as the wire sees them
fn wire(out: &Out) -> Vec<Seg> {
    out.segs
        .iter()
        .map(|skb| {
            let (h, doff) = super::output::parse(skb.data()).unwrap();
            Seg {
                seq: h.seq,
                ack: h.ack,
                flags: h.flags,
                wnd: h.wnd,
                mss: h.mss,
                ws: h.ws,
                ts: h.ts,
                sack_perm: h.sack_perm,
                sack: h.sack,
                data: skb.data()[doff..].to_vec(),
            }
        })
        .collect()
}

fn seg_in(s: &Seg) -> SegIn<'_> {
    SegIn {
        seq: s.seq,
        ack: s.ack,
        flags: s.flags,
        wnd: s.wnd,
        mss: s.mss,
        ws: s.ws,
        ts: s.ts,
        sack_perm: s.sack_perm,
        sack: s.sack,
        data: &s.data,
    }
}

/// Opening values: ISS `iss`, our MSS `mss`
fn open(iss: u32, mss: u32) -> Open {
    Open {
        iss,
        ts_off: iss.wrapping_mul(7919),
        mss,
    }
}

/// A passive open for `syn` with receive buffer `cap`
fn passive(syn: &Seg, iss: u32, mss: u32, cap: usize, now: u64, out: &mut Out) -> TcpCb {
    let mut b = TcpCb::new(cfg(), Default::default());
    b.rcvbuf = cap as u32;
    b.passive_in(&seg_in(syn), open(iss, mss), now, out);
    b
}

/// What the filter does with a segment
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fate {
    Pass,
    Drop,
    Dup,
    /// Deliver after the next segment in the same direction
    Delay,
}

/// Two endpoints and the wire between them
struct Pair {
    a: TcpCb,
    b: TcpCb,
    now: u64,
    /// (to b?, segment)
    wire: VecDeque<(bool, Seg)>,
    held: Option<(bool, Seg)>,
    filter: fn(&Pair, bool, &Seg, usize) -> Fate,
    /// Segments seen per direction (a->b, b->a)
    count: [usize; 2],
    /// Everything that went over the wire, with the time
    log: Vec<(u64, bool, Seg)>,
    a_out: Out,
    b_out: Out,
}

const BUFS: (usize, usize) = (64 * 1024, 64 * 1024);

fn pass(_: &Pair, _: bool, _: &Seg, _: usize) -> Fate {
    Fate::Pass
}

fn cfg() -> Cfg {
    Cfg {
        syn_retries: 2,
        synack_retries: 2,
        retries2: 15,
        fin_timeout: 60_000,
        ..Cfg::default()
    }
}

impl Pair {
    /// A connected pair (a active, b passive); `mss` both ways
    fn new(mss: u32) -> Self {
        Self::with_cap(mss, 64 * 1024)
    }

    /// Same, b's receive buffer `cap` bytes
    fn with_cap(mss: u32, cap: usize) -> Self {
        Self::with_cfgs(mss, cap, cfg(), cfg())
    }

    /// Same, with a's and b's knobs
    fn with_cfgs(mss: u32, cap: usize, ca: Cfg, cb: Cfg) -> Self {
        let mut p = Self::bare();
        p.a = TcpCb::new(ca, Default::default());
        let mut out = Out::default();
        p.a.connect(open(1000, mss), p.now, &mut out);
        p.take(true, out);
        let (_, syn) = p.wire.pop_front().unwrap();
        let mut out = Out::default();
        p.b = TcpCb::new(cb, Default::default());
        p.b.rcvbuf = cap as u32;
        p.b.passive_in(&seg_in(&syn), open(5000, mss), p.now, &mut out);
        p.take(false, out);
        p.run();
        assert_eq!(p.a.state, TcpState::Established);
        assert_eq!(p.b.state, TcpState::Established);
        p
    }

    fn bare() -> Self {
        Self {
            a: TcpCb::new(cfg(), Default::default()),
            b: TcpCb::new(cfg(), Default::default()),
            now: 0,
            wire: VecDeque::new(),
            held: None,
            filter: pass,
            count: [0, 0],
            log: Vec::new(),
            a_out: Out::default(),
            b_out: Out::default(),
        }
    }

    /// Put `out`'s segments on the wire (from a if `from_a`)
    fn take(&mut self, from_a: bool, out: Out) {
        for s in wire(&out) {
            let to_b = from_a;
            let i = self.count[!to_b as usize];
            self.count[!to_b as usize] += 1;
            self.log.push((self.now, to_b, s.clone()));
            match (self.filter)(self, to_b, &s, i) {
                Fate::Pass => self.wire.push_back((to_b, s)),
                Fate::Drop => {}
                Fate::Dup => {
                    self.wire.push_back((to_b, s.clone()));
                    self.wire.push_back((to_b, s));
                }
                Fate::Delay => {
                    if let Some(h) = self.held.take() {
                        self.wire.push_back(h);
                    }
                    self.held = Some((to_b, s));
                }
            }
        }
        let rest = out;
        let acc = if from_a {
            &mut self.a_out
        } else {
            &mut self.b_out
        };
        acc.shut |= rest.shut;
        acc.wake |= rest.wake;
        acc.done |= rest.done;
        acc.timewait |= rest.timewait;
        acc.established |= rest.established;
        if rest.err.is_some() {
            acc.err = rest.err;
        }
    }

    /// Deliver one segment; false if the wire is empty
    fn step(&mut self) -> bool {
        let Some((to_b, s)) = self.wire.pop_front().or_else(|| self.held.take()) else {
            return false;
        };
        let mut out = Out::default();
        if to_b {
            self.b.feed(&seg_in(&s), self.now, &mut out);
        } else {
            self.a.feed(&seg_in(&s), self.now, &mut out);
        }
        self.take(!to_b, out);
        true
    }

    /// Deliver until the wire is empty
    fn run(&mut self) {
        let mut n = 0;
        while self.step() {
            n += 1;
            assert!(n < 1_000_000, "segment storm");
        }
    }

    /// Advance the clock to the next timer and fire it; false if none
    fn tick(&mut self) -> bool {
        let next = match (self.a.next_timer(), self.b.next_timer()) {
            (Some(x), Some(y)) => x.min(y),
            (x, y) => match x.or(y) {
                Some(t) => t,
                None => return false,
            },
        };
        self.now = self.now.max(next);
        let mut out = Out::default();
        self.a.on_timer(self.now, &mut out);
        self.take(true, out);
        let mut out = Out::default();
        self.b.on_timer(self.now, &mut out);
        self.take(false, out);
        true
    }

    /// Run the network and timers until `done` or no progress is possible
    fn until(&mut self, mut done: impl FnMut(&mut Pair) -> bool, limit: usize) -> bool {
        for _ in 0..limit {
            self.run();
            if done(self) {
                return true;
            }
            if !self.tick() {
                return done(self);
            }
        }
        false
    }

    fn send_a(&mut self, data: &[u8]) -> usize {
        let n = self.a.send(data);
        let mut out = Out::default();
        self.a.output(self.now, &mut out);
        self.take(true, out);
        n
    }

    fn read_b(&mut self, max: usize) -> Vec<u8> {
        let mut buf = alloc::vec![0u8; max];
        let mut out = Out::default();
        let n = self.b.recv(&mut buf, 0, true, &mut out);
        self.take(false, out);
        buf.truncate(n);
        buf
    }
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 + i / 251) as u8).collect()
}

/// Push `data` from a to b, b reading everything; returns what b got
fn transfer(p: &mut Pair, data: &[u8], limit: usize) -> Vec<u8> {
    let mut sent = 0;
    let mut got = Vec::new();
    for _ in 0..limit {
        if sent < data.len() {
            sent += p.send_a(&data[sent..]);
        }
        p.run();
        assert_eq!(p.a.wmem_queued, queued_truesize(&p.a));
        got.extend(p.read_b(1 << 20));
        p.run();
        if got.len() >= data.len() {
            break;
        }
        let idle = sent == data.len() && p.b.rcvq_len() == 0;
        if p.wire.is_empty() && !p.tick() && idle {
            break;
        }
    }
    got
}

#[test]
fn handshake_options_and_isn() {
    let p = Pair::new(1460);
    let syn = &p.log[0].2;
    assert!(syn.has(flags::SYN) && !syn.has(flags::ACK));
    assert_eq!((syn.seq, syn.mss), (1000, Some(1460)));
    let synack = &p.log[1].2;
    assert!(synack.has(flags::SYN | flags::ACK));
    assert_eq!((synack.seq, synack.ack), (5000, 1001));
    // Timestamps (12 option bytes) come off the MSS
    assert_eq!((p.a.live.mss.get(), p.b.live.mss.get()), (1448, 1448));
    assert!(p.a.ts_ok && p.b.ts_ok && p.a.wscale_ok && p.b.wscale_ok);
    assert_eq!(syn.ws, Some(p.a.rcv_wscale));
    assert_eq!(synack.ws, Some(p.b.rcv_wscale));
    assert_eq!(p.a.snd_wscale, p.b.rcv_wscale);
    // tcp_rmem[2] = 6 MB: scale 7 (Linux tcp_select_initial_window)
    assert_eq!(p.a.rcv_wscale, 7);
    // The SYN-ACK echoes the SYN's TSval
    assert_eq!(synack.ts.unwrap().1, syn.ts.unwrap().0);
    assert_eq!(p.a.snd_una, 1001);
    assert_eq!(p.b.rcv_nxt, 1001);
}

#[test]
fn mss_default_without_option() {
    let mut a = TcpCb::new(cfg(), Default::default());
    let mut out = Out::default();
    a.connect(open(1, 1460), 0, &mut out);
    let synack = SegIn {
        seq: 77,
        ack: 2,
        flags: flags::SYN | flags::ACK,
        wnd: 8000,
        ..Default::default()
    };
    let mut out = Out::default();
    a.feed(&synack, 5, &mut out);
    assert_eq!(a.state, TcpState::Established);
    assert_eq!(a.live.mss.get(), MSS_DEFAULT);
    assert!(out.established);
}

#[test]
fn bulk_transfer_both_ways() {
    let mut p = Pair::new(1460);
    let data = pattern(300_000);
    assert_eq!(transfer(&mut p, &data, 100_000), data);
    // Reverse direction
    core::mem::swap(&mut p.a, &mut p.b);
    let got = transfer(&mut p, &data[..123_457], 100_000);
    assert_eq!(got, &data[..123_457]);
}

fn lossy(_: &Pair, to_b: bool, s: &Seg, i: usize) -> Fate {
    if to_b && !s.data.is_empty() && i % 7 == 3 {
        Fate::Drop
    } else if !to_b && i % 11 == 5 {
        Fate::Drop
    } else {
        Fate::Pass
    }
}

/// The send queues' truesize (Linux sk_wmem_queued); each skb's is its
/// head and its payload, however it was split, merged or trimmed, and
/// it holds at most a page more
fn queued_truesize(c: &TcpCb) -> usize {
    tight(c);
    for s in c.wq.iter().chain(c.rtx.iter()) {
        assert_eq!(s.truesize(), HEAD_TRUESIZE + s.len());
    }
    c.wq.iter().map(|s| s.truesize()).sum::<usize>()
        + c.rtx.iter().map(|s| s.truesize()).sum::<usize>()
}

/// Every queued send skb holds at most a page more than it is charged
/// (Linux's page frag slack)
fn tight(c: &TcpCb) {
    for s in c.wq.iter().chain(c.rtx.iter()) {
        let slack = s.mem_size() - s.truesize();
        assert!(slack <= 4096, "{} bytes held past {}", slack, s.truesize());
    }
}

#[test]
fn loss_recovers() {
    let mut p = Pair::new(1000);
    p.filter = lossy;
    let data = pattern(200_000);
    assert_eq!(transfer(&mut p, &data, 200_000), data);
}

fn messy(_: &Pair, to_b: bool, _: &Seg, i: usize) -> Fate {
    match (to_b, i % 9) {
        (true, 2) => Fate::Dup,
        (true, 4) => Fate::Delay,
        (true, 7) => Fate::Drop,
        (false, 3) => Fate::Dup,
        _ => Fate::Pass,
    }
}

#[test]
fn dup_and_reorder() {
    let mut p = Pair::new(500);
    p.filter = messy;
    let data = pattern(100_000);
    assert_eq!(transfer(&mut p, &data, 200_000), data);
}

fn drop_all(_: &Pair, _: bool, _: &Seg, _: usize) -> Fate {
    Fate::Drop
}

#[test]
fn syn_retries_then_etimedout() {
    let mut p = Pair::bare();
    p.filter = drop_all;
    let mut out = Out::default();
    p.a.connect(open(1, 1460), 0, &mut out);
    p.take(true, out);
    p.until(|p| p.a.state == TcpState::Closed, 100);
    let syns: Vec<u64> = p.log.iter().map(|l| l.0).collect();
    // syn_retries 2: SYN at 0, 1 s, 3 s; give up at 7 s
    assert_eq!(syns, [0, 1000, 3000]);
    assert_eq!(p.now, 7000);
    assert_eq!(p.a_out.err, Some(KernelError::TimedOut));
    assert!(p.a_out.done);
}

#[test]
fn soft_error_reported_on_timeout() {
    let mut p = Pair::bare();
    p.filter = drop_all;
    let mut out = Out::default();
    p.a.connect(open(1, 1460), 0, &mut out);
    p.a.soft_err = Some(KernelError::HostUnreachable);
    p.take(true, out);
    p.until(|p| p.a.state == TcpState::Closed, 100);
    assert_eq!(p.a_out.err, Some(KernelError::HostUnreachable));
}

#[test]
fn rto_backoff_and_give_up() {
    let mut p = Pair::new(1460);
    p.filter = drop_all;
    p.log.clear();
    p.send_a(b"hello");
    let t0 = p.now;
    p.until(|p| p.a.state == TcpState::Closed, 100);
    let times: Vec<u64> = p.log.iter().filter(|l| l.1).map(|l| l.0 - t0).collect();
    // The simulated handshake's RTT is 1 us: srtt_us 8, rttvar_us
    // TCP_RTO_MIN, so RTO = 1 + 200000 us, 201 ms rounded up (Linux
    // __tcp_set_rto). First the tail loss probe after 2 RTT + RTO_MIN
    // (Linux tcp_schedule_loss_probe, a lone packet), the RTO
    // restarting from it, doubling up to 120 s; given up once
    // tcp_retries2's model time, (2^10 - 1) * 200 ms + 6 * 120 s,
    // passed since the first retransmission (Linux
    // retransmits_timed_out): 15 retransmissions
    assert_eq!((p.a.srtt_us, p.a.rttvar_us), (8, 200_000));
    assert_eq!(times.len(), 17);
    let gaps: Vec<u64> = times.windows(2).map(|w| w[1] - w[0]).collect();
    let model = 1023 * 200 + 6 * RTO_MAX;
    let last = times[times.len() - 1] - times[2];
    assert!(last < model && last + RTO_MAX >= model, "{last}");
    assert_eq!(&gaps[..7], &[201, 201, 402, 804, 1608, 3216, 6432]);
    assert!(gaps.iter().all(|&g| g <= RTO_MAX));
    assert_eq!(*gaps.last().unwrap(), RTO_MAX);
    assert_eq!(p.a_out.err, Some(KernelError::TimedOut));
}

#[test]
fn karn_and_rtt_estimate() {
    let mut p = Pair::new(1460);
    // A 100 ms round trip
    p.send_a(b"x");
    p.now += 100;
    p.run();
    let (srtt, var) = p.a.rtt();
    assert!(srtt > 0 && srtt <= 100_000, "srtt {}", srtt);
    assert!(var > 0);
    let rto = p.a.rto_cur();
    assert!((200..=1000).contains(&rto), "rto {}", rto);
}

#[test]
fn zero_window_then_recovery() {
    let mut p = Pair::with_cap(1000, 4000);
    let data = pattern(30_000);
    let mut sent = p.send_a(&data);
    p.run();
    // b reads nothing: the window closes and a probes
    for _ in 0..6 {
        p.tick();
        p.run();
    }
    assert_eq!(p.a.snd_wnd, 0);
    // The scaled window (unit 128) may round past the window space,
    // never past twice what the buffer holds
    let q = p.b.rcvq_len();
    assert!(q >= 1000 && q <= 2 * p.b.full_space() as usize, "{q}");
    let una = p.a.snd_una.wrapping_sub(1);
    let probes = p.log.iter().filter(|l| l.1 && l.2.seq == una).count();
    assert!(probes >= 3, "zero window probes: {}", probes);
    // b reads slowly: everything arrives in order
    let mut got = Vec::new();
    for _ in 0..10_000 {
        got.extend(p.read_b(1000));
        if sent < data.len() {
            sent += p.send_a(&data[sent..]);
        }
        p.run();
        if got.len() == data.len() {
            break;
        }
        if p.wire.is_empty() && p.b.rcvq_len() == 0 {
            p.tick();
        }
    }
    assert_eq!(got, data);
}

fn drop_window_updates(p: &Pair, to_b: bool, s: &Seg, _: usize) -> Fate {
    // Lose b's pure ACKs while its queue holds data: only probes help
    if !to_b && s.data.is_empty() && s.wnd > 0 && p.b.rcvq_len() > 0 && p.now < 50_000 {
        Fate::Drop
    } else {
        Fate::Pass
    }
}

#[test]
fn lost_window_update_recovered_by_probe() {
    let mut p = Pair::with_cap(1000, 6000);
    let data = pattern(3000);
    p.send_a(&data);
    p.run();
    let rest = pattern(5000);
    p.send_a(&rest);
    // b's window shuts with part of the data held (its delayed ACKs
    // fire; a's segments are at most half b's small window)
    assert!(p.until(|p| p.a.snd_wnd == 0, 20));
    let held = p.b.rcvq_len();
    assert!((2000..8000).contains(&held), "{held}");
    p.filter = drop_window_updates;
    let first = p.read_b(10_000);
    p.run();
    // The update was lost; the persist timer finds the open window
    let ok = p.until(|p| p.b.rcvq_len() > 0, 50);
    assert!(ok, "probe should find the window");
    assert_eq!(first.len(), held);
}

/// Data in flight is lost while the peer shuts its window (it dropped
/// what it could not hold, Linux tcp_data_queue under memory pressure):
/// each retransmission timeout resends the queue's head as a zero-window
/// probe, beyond tcp_retries2 while the peer keeps answering, and the
/// connection times out only once the peer has been silent for twice
/// RTO_MAX (Linux tcp_retransmit_timer's shrunk-window branch,
/// tcp_rtx_probe0_timed_out)
#[test]
fn shrunk_window_retransmits_probe_head() {
    let mut p = Pair::new(1000);
    p.filter = |_, to_b, s, _| {
        if to_b && !s.data.is_empty() {
            Fate::Drop
        } else {
            Fate::Pass
        }
    };
    let data = pattern(3000);
    assert_eq!(p.send_a(&data), 3000);
    p.run();
    let una = p.a.snd_una;
    assert_ne!(una, p.a.snd_max, "data in flight");
    // The peer's ACK: nothing new, its window shut
    let shut = |p: &Pair| SegIn {
        seq: p.a.rcv_nxt,
        ack: una,
        flags: flags::ACK,
        wnd: 0,
        ..Default::default()
    };
    let mut out = Out::default();
    let now = p.now;
    p.a.feed(&shut(&p), now, &mut out);
    assert_eq!(p.a.snd_wnd, 0);
    // The tail loss probe finds no window for the tail (Linux
    // __tcp_retransmit_skb -EAGAIN) and gives way to the RTO
    let t = p.a.next_timer().expect("loss probe armed");
    p.now = t;
    let mut out = Out::default();
    p.a.on_timer(t, &mut out);
    assert!(wire(&out).is_empty());
    // Answered probes: past retries2, never a timeout
    for i in 0..(cfg().retries2 + 5) {
        let t = p.a.next_timer().expect("retransmit timer armed");
        p.now = t;
        let mut out = Out::default();
        p.a.on_timer(t, &mut out);
        let segs = wire(&out);
        assert!(
            segs.iter().any(|s| s.seq == una && !s.data.is_empty()),
            "timeout {i}: head resent as a probe"
        );
        assert_eq!(p.a.state, TcpState::Established, "timeout {i}");
        let mut out = Out::default();
        p.a.feed(&shut(&p), t, &mut out);
    }
    // A silent peer: timed out after twice RTO_MAX without an ACK
    let quiet = p.now;
    let mut out = Out::default();
    for _ in 0..100 {
        let Some(t) = p.a.next_timer() else {
            break;
        };
        p.now = t;
        p.a.on_timer(t, &mut out);
        if p.a.state != TcpState::Established {
            break;
        }
    }
    assert_eq!(p.a.state, TcpState::Closed);
    assert_eq!(out.err, Some(KernelError::TimedOut));
    assert!(p.now - quiet > 2 * RTO_MAX);
}

/// After shrunk-window probing past tcp_retries2, the peer reopens its
/// window acking only the probed head: the rest of the lost flight goes
/// out at once, and the probes never count as retransmission timeouts,
/// so the next ordinary RTO does not time the connection out (Linux:
/// tcp_enter_loss marks the flight lost; icsk_retransmits stays 0 in
/// the shrunk-window branch)
#[test]
fn shrunk_window_reopen_resends_rest() {
    let mut p = Pair::new(1000);
    p.filter = |_, to_b, s, _| {
        if to_b && !s.data.is_empty() {
            Fate::Drop
        } else {
            Fate::Pass
        }
    };
    assert_eq!(p.send_a(&pattern(3000)), 3000);
    p.run();
    let una = p.a.snd_una;
    let ack = |p: &Pair, ack: u32, wnd: u16| SegIn {
        seq: p.a.rcv_nxt,
        ack,
        flags: flags::ACK,
        wnd,
        ..Default::default()
    };
    let mut out = Out::default();
    let now = p.now;
    p.a.feed(&ack(&p, una, 0), now, &mut out);
    for _ in 0..(cfg().retries2 + 5) {
        let t = p.a.next_timer().expect("armed");
        p.now = t;
        let mut out = Out::default();
        p.a.on_timer(t, &mut out);
        let mut out = Out::default();
        p.a.feed(&ack(&p, una, 0), t, &mut out);
    }
    // The window opens, the head acked: the rest goes out now
    let head = una.wrapping_add(1000);
    let mut out = Out::default();
    let now = p.now;
    p.a.feed(&ack(&p, head, 60_000), now, &mut out);
    assert_eq!(p.a.wmem_queued, queued_truesize(&p.a));
    assert!(
        wire(&out)
            .iter()
            .any(|s| s.seq == head && !s.data.is_empty()),
        "rest of the flight resent at once"
    );
    // The next ordinary timeout retransmits; no ETIMEDOUT
    let t = p.a.next_timer().expect("armed");
    p.now = t;
    let mut out = Out::default();
    p.a.on_timer(t, &mut out);
    assert_eq!(p.a.state, TcpState::Established);
    assert_eq!(out.err, None);
}

/// A control block made over a socket's lockless fields (a reconnect)
/// starts with no timeouts counted (Linux tcp_disconnect clears
/// icsk_retransmits with icsk_backoff and icsk_probes_out)
#[test]
fn new_control_block_clears_timeout_counts() {
    let live: alloc::sync::Arc<super::cb::Live> = Default::default();
    live.retransmits.set(7);
    live.backoff.set(7);
    live.probes.set(7);
    let cb = TcpCb::new(cfg(), live);
    assert_eq!(cb.live.retransmits.get(), 0);
    assert_eq!(cb.live.backoff.get(), 0);
    assert_eq!(cb.live.probes.get(), 0);
}

#[test]
fn window_edge_never_moves_left() {
    let mut p = Pair::with_cap(1000, 8000);
    let data = pattern(50_000);
    let mut sent = 0;
    let mut edge = 0u32;
    for i in 0..2000 {
        if sent < data.len() {
            sent += p.send_a(&data[sent..]);
        }
        p.run();
        for (_, _, s) in p.log.iter().filter(|l| !l.1 && !l.2.has(flags::SYN)) {
            let e = s.ack.wrapping_add((s.wnd as u32) << p.b.rcv_wscale);
            if edge != 0 {
                assert!(!super::cb::before(e, edge), "window shrank");
            }
            edge = e;
        }
        p.log.clear();
        assert_eq!(p.a.wmem_queued, queued_truesize(&p.a));
        if i % 3 == 0 {
            p.read_b(1500);
        }
        if p.wire.is_empty() && !p.tick() && sent == data.len() && p.b.rcvq_len() == 0 {
            break;
        }
    }
}

#[test]
fn active_close_and_time_wait() {
    let mut p = Pair::new(1460);
    let mut out = Out::default();
    p.a.close(false, p.now, &mut out);
    p.take(true, out);
    assert_eq!(p.a.state, TcpState::FinWait1);
    p.run();
    assert_eq!(p.a.state, TcpState::FinWait2);
    assert_eq!(p.b.state, TcpState::CloseWait);
    assert_eq!(p.b_out.shut & RCV_SHUTDOWN, RCV_SHUTDOWN);
    let mut out = Out::default();
    p.b.close(false, p.now, &mut out);
    p.take(false, out);
    assert_eq!(p.b.state, TcpState::LastAck);
    p.run();
    assert_eq!(p.a.state, TcpState::TimeWait);
    assert!(p.a_out.timewait);
    assert_eq!(p.b.state, TcpState::Closed);
    assert!(p.b_out.done);
    // Handed to its timewait entry, which owns 2MSL: the control block
    // keeps no timer (Linux tcp_time_wait)
    assert_eq!(p.a.next_timer(), None);
}

/// a's control block taken to TIME_WAIT by an orderly close (a closes
/// first): its entry's fields and b's FIN
fn tw_pair() -> (Pair, TwCb, Seg) {
    let mut p = Pair::new(1460);
    let (tw, fin) = tw_close(&mut p);
    (p, tw, fin)
}

/// `tw_pair` on an established `p`
fn tw_close(p: &mut Pair) -> (TwCb, Seg) {
    let mut out = Out::default();
    p.a.close(false, p.now, &mut out);
    p.take(true, out);
    p.run();
    let mut out = Out::default();
    p.b.close(false, p.now, &mut out);
    p.take(false, out);
    // Keep b's FIN to replay it
    let fin = p.wire.back().unwrap().1.clone();
    p.run();
    assert_eq!(p.a.state, TcpState::TimeWait);
    let tw = TwCb::from_cb(&p.a);
    assert!(tw.expires() <= p.now + TIMEWAIT_LEN);
    (tw, fin)
}

/// A bare TIME_WAIT header
fn tw_seg(seq: u32, fl: u8, ts: Option<(u32, u32)>) -> super::cb::Seg {
    SegIn {
        seq,
        flags: fl,
        ts,
        ..Default::default()
    }
    .hdr()
}

/// A retransmitted FIN is ACKed at once and restarts 2MSL (Linux
/// tcp_timewait_state_process: out of window, reschedule and ACK)
#[test]
fn time_wait_reacks_fin_and_restarts() {
    let (mut p, mut tw, fin) = tw_pair();
    p.now += 30_000;
    let st = tw.rcv(&seg_in(&fin).hdr(), p.now, false, None);
    assert_eq!(st, TwStatus::Ack);
    let a = tw.ack(p.now);
    assert!(a.has(flags::ACK) && !a.has(flags::SYN | flags::FIN | flags::RST));
    assert_eq!(a.ack, fin.seq.wrapping_add(1));
    assert_eq!(a.seq, p.a.snd_max);
    assert!(a.ts.is_some_and(|(_, e)| e == tw.ts_recent));
    assert_eq!(tw.expires(), p.now + TIMEWAIT_LEN);
}

/// A bare in-window ACK restarts 2MSL and needs no answer; an
/// in-window RST ends the entry, unless tcp_rfc1337
#[test]
fn time_wait_bare_ack_and_rst() {
    let (mut p, mut tw, _) = tw_pair();
    p.now += 1000;
    let ack = tw_seg(tw.rcv_nxt, flags::ACK, None);
    assert_eq!(tw.rcv(&ack, p.now, false, None), TwStatus::Success);
    let at = p.now + TIMEWAIT_LEN;
    assert_eq!(tw.expires(), at);
    let rst = tw_seg(tw.rcv_nxt, flags::RST, None);
    p.now += 1000;
    // RFC 1337: ignored, no reschedule either
    assert_eq!(tw.rcv(&rst, p.now, true, None), TwStatus::Success);
    assert_eq!(tw.expires(), at);
    assert_eq!(tw.rcv(&rst, p.now, false, None), TwStatus::Kill);
    // Out of window: dropped, the entry stays
    let far = tw_seg(tw.rcv_nxt.wrapping_add(1000), flags::RST, None);
    assert_eq!(tw.rcv(&far, p.now, false, None), TwStatus::Success);
}

/// Out-of-window ACKs are rate limited (Linux tcp_oow_rate_limited,
/// TCPACKSkippedTimeWait); a segment with sequence space never is
#[test]
fn time_wait_oow_rate_limit() {
    use crate::net::mib::*;
    let m = NetMib::new().unwrap();
    let (mut p, mut tw, fin) = tw_pair();
    let old = tw_seg(tw.rcv_nxt.wrapping_sub(5), flags::ACK, None);
    assert_eq!(tw.rcv(&old, p.now, false, Some(&m)), TwStatus::Ack);
    p.now += 100;
    assert_eq!(tw.rcv(&old, p.now, false, Some(&m)), TwStatus::Success);
    assert_eq!(m.net.fold(LINUX_MIB_TCPACKSKIPPEDTIMEWAIT), 1);
    let fin = seg_in(&fin).hdr();
    assert_eq!(tw.rcv(&fin, p.now, false, Some(&m)), TwStatus::Ack);
    p.now += super::cb::OOW_RATELIMIT;
    assert_eq!(tw.rcv(&old, p.now, false, Some(&m)), TwStatus::Ack);
}

#[test]
fn passive_close_last_ack() {
    let mut p = Pair::new(1460);
    let mut out = Out::default();
    p.b.close(false, p.now, &mut out);
    p.take(false, out);
    p.run();
    assert_eq!(p.a.state, TcpState::CloseWait);
    // CLOSE_WAIT still sends
    p.send_a(b"late data");
    p.run();
    // b's reader is gone: data in FIN_WAIT_2 for a closed socket resets
    assert_eq!(p.b.state, TcpState::Closed);
    assert_eq!(p.b.rcvq_len(), 0);
    assert_eq!(p.a_out.err, Some(KernelError::BrokenPipe));
}

#[test]
fn half_close_keeps_receiving() {
    let mut p = Pair::new(1460);
    let mut out = Out::default();
    assert!(p.a.shutdown_wr(p.now, &mut out));
    p.take(true, out);
    p.run();
    assert_eq!(p.a.state, TcpState::FinWait2);
    assert_eq!(p.b.state, TcpState::CloseWait);
    // b keeps sending to a, which keeps reading
    core::mem::swap(&mut p.a, &mut p.b);
    let data = pattern(20_000);
    assert_eq!(transfer(&mut p, &data, 10_000), data);
    core::mem::swap(&mut p.a, &mut p.b);
    let mut out = Out::default();
    p.b.close(false, p.now, &mut out);
    p.take(false, out);
    p.run();
    assert_eq!(p.a.state, TcpState::TimeWait);
    assert_eq!(p.b.state, TcpState::Closed);
}

#[test]
fn simultaneous_close() {
    let mut p = Pair::new(1460);
    let mut o1 = Out::default();
    p.a.close(false, p.now, &mut o1);
    let mut o2 = Out::default();
    p.b.close(false, p.now, &mut o2);
    p.take(true, o1);
    p.take(false, o2);
    // Both FINs cross
    p.step();
    p.step();
    assert_eq!(p.a.state, TcpState::Closing);
    assert_eq!(p.b.state, TcpState::Closing);
    p.run();
    assert_eq!(p.a.state, TcpState::TimeWait);
    assert_eq!(p.b.state, TcpState::TimeWait);
}

#[test]
fn simultaneous_open() {
    let mut p = Pair::bare();
    let mut o1 = Out::default();
    p.a.connect(open(100, 1460), 0, &mut o1);
    let mut o2 = Out::default();
    p.b.connect(open(900, 1460), 0, &mut o2);
    p.take(true, o1);
    p.take(false, o2);
    p.step();
    p.step();
    assert_eq!(p.a.state, TcpState::SynReceived);
    assert_eq!(p.b.state, TcpState::SynReceived);
    p.run();
    assert_eq!(p.a.state, TcpState::Established);
    assert_eq!(p.b.state, TcpState::Established);
    let data = pattern(5000);
    assert_eq!(transfer(&mut p, &data, 1000), data);
}

#[test]
fn rst_rules_rfc5961() {
    let mut p = Pair::new(1460);
    let nxt = p.a.rcv_nxt;
    let rst = |seq| SegIn {
        seq,
        flags: flags::RST,
        ..Default::default()
    };
    // In window, not exact: challenge ACK (spaced past the 500 ms
    // per-connection rate limit)
    let mut out = Out::default();
    p.a.feed(&rst(nxt + 10), 1000, &mut out);
    assert_eq!(p.a.state, TcpState::Established);
    assert_eq!(wire(&out).len(), 1);
    assert!(wire(&out)[0].has(flags::ACK) && wire(&out)[0].ack == nxt);
    // Out of window: silently dropped
    let mut out = Out::default();
    p.a.feed(&rst(nxt.wrapping_sub(100_000)), 2000, &mut out);
    assert!(wire(&out).is_empty() && p.a.state == TcpState::Established);
    // SYN on an established connection: challenge ACK
    let syn = SegIn {
        flags: flags::SYN,
        ..rst(nxt)
    };
    let mut out = Out::default();
    p.a.feed(&syn, 3000, &mut out);
    assert_eq!(p.a.state, TcpState::Established);
    assert!(wire(&out)[0].has(flags::ACK));
    // ACK of data never sent: ACK back, segment dropped
    let bad = SegIn {
        flags: flags::ACK,
        ack: p.a.snd_max.wrapping_add(1000),
        data: b"zz",
        ..rst(nxt)
    };
    let mut out = Out::default();
    p.a.feed(&bad, 4000, &mut out);
    assert_eq!(p.a.rcvq_len(), 0);
    assert!(wire(&out)[0].has(flags::ACK));
    // Exact: reset
    let mut out = Out::default();
    p.a.feed(&rst(nxt), 5000, &mut out);
    assert_eq!(p.a.state, TcpState::Closed);
    assert_eq!(out.err, Some(KernelError::ConnectionReset));
    assert!(out.done);
}

#[test]
fn syn_sent_refused_and_bad_ack() {
    let mut a = TcpCb::new(cfg(), Default::default());
    let mut out = Out::default();
    a.connect(open(500, 1460), 0, &mut out);
    // An ACK for something else: RST from its ACK, still SYN_SENT
    let bad = SegIn {
        seq: 9,
        ack: 77,
        flags: flags::ACK,
        ..Default::default()
    };
    let mut out = Out::default();
    a.feed(&bad, 0, &mut out);
    assert_eq!(a.state, TcpState::SynSent);
    assert_eq!((wire(&out)[0].flags, wire(&out)[0].seq), (flags::RST, 77));
    // RST without ACK: ignored
    let mut out = Out::default();
    a.feed(
        &SegIn {
            flags: flags::RST,
            ..bad
        },
        0,
        &mut out,
    );
    assert_eq!(a.state, TcpState::SynSent);
    // RST+ACK of our SYN: refused
    let mut out = Out::default();
    a.feed(
        &SegIn {
            flags: flags::RST | flags::ACK,
            ack: 501,
            ..bad
        },
        0,
        &mut out,
    );
    assert_eq!(a.state, TcpState::Closed);
    assert_eq!(out.err, Some(KernelError::ConnectionRefused));
}

#[test]
fn reset_errors_by_state() {
    let mut p = Pair::new(1460);
    let mut out = Out::default();
    p.b.close(false, p.now, &mut out);
    p.take(false, out);
    p.run();
    assert_eq!(p.a.state, TcpState::CloseWait);
    let rst = SegIn {
        seq: p.a.rcv_nxt,
        flags: flags::RST,
        ..Default::default()
    };
    let mut out = Out::default();
    p.a.feed(&rst, 0, &mut out);
    assert_eq!(out.err, Some(KernelError::BrokenPipe));
}

/// Linux tcp_disconnect: RST and ECONNRESET for a connection, a bare
/// error report (no state change wakeup) for a closed socket
#[test]
fn disconnect_reports() {
    let mut p = Pair::new(1460);
    let mut out = Out::default();
    p.a.disconnect(&mut out);
    assert_eq!(p.a.state, TcpState::Closed);
    assert!(wire(&out)[0].has(flags::RST));
    assert_eq!(out.err, Some(KernelError::ConnectionReset));
    assert_eq!(out.wake & (wake::STATE | wake::ERR), wake::ERR);
    let mut out = Out::default();
    p.a.disconnect(&mut out);
    assert!(wire(&out).is_empty());
    assert_eq!(out.err, None);
    assert_eq!(out.wake, wake::ERR);
}

#[test]
fn close_with_unread_data_resets() {
    let mut p = Pair::new(1460);
    p.send_a(b"unread");
    p.run();
    assert_eq!(p.b.rcvq_len(), 6);
    let mut out = Out::default();
    p.b.close(false, p.now, &mut out);
    assert_eq!(p.b.state, TcpState::Closed);
    assert!(wire(&out)[0].has(flags::RST));
    p.take(false, out);
    p.run();
    assert_eq!(p.a.state, TcpState::Closed);
    assert_eq!(p.a_out.err, Some(KernelError::ConnectionReset));
}

/// Linux __tcp_close: unread data resets in LAST_ACK too (not a
/// need-reset state), the FIN still unacknowledged
#[test]
fn close_with_unread_data_resets_in_last_ack() {
    let mut p = Pair::new(1460);
    p.send_a(b"unread");
    let mut out = Out::default();
    assert!(p.a.shutdown_wr(p.now, &mut out));
    p.take(true, out);
    p.run();
    assert_eq!(p.b.state, TcpState::CloseWait);
    let mut out = Out::default();
    assert!(p.b.shutdown_wr(p.now, &mut out));
    assert_eq!(p.b.state, TcpState::LastAck);
    let mut out = Out::default();
    p.b.close(false, p.now, &mut out);
    assert_eq!(p.b.state, TcpState::Closed);
    assert!(wire(&out).iter().any(|s| s.has(flags::RST)));
}

#[test]
fn linger_zero_resets() {
    let mut p = Pair::new(1460);
    let mut out = Out::default();
    p.a.close(true, p.now, &mut out);
    assert!(wire(&out)[0].has(flags::RST));
    p.take(true, out);
    p.run();
    assert_eq!(p.b.state, TcpState::Closed);
    assert_eq!(p.b_out.err, Some(KernelError::ConnectionReset));
}

#[test]
fn orphan_fin_wait2_times_out() {
    // tcp_fin_timeout within TIME_WAIT's length: the ACK of our FIN
    // hands the orphan to a timewait entry in the FIN_WAIT2 substate
    // for it (Linux tcp_rcv_state_process -> tcp_time_wait)
    let mut p = Pair::new(1460);
    let mut out = Out::default();
    p.a.close(false, p.now, &mut out);
    p.take(true, out);
    p.run();
    assert_eq!(p.a.state, TcpState::FinWait2);
    assert!(p.a_out.timewait);
    let tw = TwCb::from_cb(&p.a);
    assert_eq!(tw.substate(), TcpState::FinWait2);
    assert_eq!(tw.expires() - p.a.clock, 60_000);
    // Past it: the keepalive timer waits out the excess, then a
    // timewait entry for the excess again (Linux tcp_keepalive_timer)
    let mut c = cfg();
    c.fin_timeout = 100_000;
    let mut p = Pair::with_cfgs(1460, 64 * 1024, c, cfg());
    let mut out = Out::default();
    p.a.close(false, p.now, &mut out);
    p.take(true, out);
    p.run();
    assert!(!p.a_out.timewait);
    let t = p.now;
    assert!(p.until(|p| p.a_out.timewait, 10));
    assert_eq!(p.now - t, 40_000);
    assert_eq!(TwCb::from_cb(&p.a).expires() - p.now, 40_000);
    // Not orphaned (shutdown only): no timeout
    let mut p = Pair::new(1460);
    let mut out = Out::default();
    p.a.shutdown_wr(p.now, &mut out);
    p.take(true, out);
    p.run();
    assert_eq!(p.a.state, TcpState::FinWait2);
    assert_eq!(p.a.next_timer(), None);
}

#[test]
fn duplicate_syn_resends_synack() {
    let mut a = TcpCb::new(cfg(), Default::default());
    let mut out = Out::default();
    a.connect(open(10, 1460), 0, &mut out);
    let syn = wire(&out)[0].clone();
    let mut out = Out::default();
    let mut b = passive(&syn, 99, 1460, BUFS.0, 0, &mut out);
    let synack = wire(&out)[0].clone();
    let mut out = Out::default();
    b.feed(&seg_in(&syn), 1, &mut out);
    // The same SYN-ACK, but a fresh TSval
    let again = Seg {
        ts: synack.ts,
        ..wire(&out)[0].clone()
    };
    assert_eq!(wire(&out).len(), 1);
    assert_eq!(again, synack);
    assert_eq!(b.state, TcpState::SynReceived);
    assert_eq!(b.stats.total_retrans, 1);
    // Rate limited (Linux tcp_oow_rate_limited), resent after that
    let mut out = Out::default();
    b.feed(&seg_in(&syn), 100, &mut out);
    assert!(wire(&out).is_empty());
    let mut out = Out::default();
    b.feed(&seg_in(&syn), 600, &mut out);
    assert_eq!(wire(&out).len(), 1);
    assert!(wire(&out)[0].flags & flags::SYN != 0);
}

#[test]
fn new_syn_resets_request() {
    let mut a = TcpCb::new(cfg(), Default::default());
    let mut out = Out::default();
    a.connect(open(10, 1460), 0, &mut out);
    let syn = wire(&out)[0].clone();
    let mut out = Out::default();
    let mut b = passive(&syn, 99, 1460, BUFS.0, 0, &mut out);
    // A SYN at RCV.NXT (in window, another ISN): Linux tcp_check_req
    // resets and drops the request
    let syn2 = Seg { seq: 11, ..syn };
    let mut out = Out::default();
    b.feed(&seg_in(&syn2), 1, &mut out);
    assert_eq!(b.state, TcpState::Closed);
    assert_eq!(wire(&out).len(), 1);
    assert_eq!(wire(&out)[0].flags, flags::RST | flags::ACK);
    assert_eq!(wire(&out)[0].ack, 12);
}

#[test]
fn synack_retries_then_give_up() {
    let mut p = Pair::bare();
    let mut out = Out::default();
    p.a.connect(open(1, 1460), 0, &mut out);
    let syn = wire(&out)[0].clone();
    let mut out = Out::default();
    p.b = passive(&syn, 2, 1460, BUFS.0, 0, &mut out);
    p.filter = drop_all;
    p.a = TcpCb::new(cfg(), Default::default());
    p.until(|p| p.b.state == TcpState::Closed, 20);
    let times: Vec<u64> = p.log.iter().filter(|l| !l.1).map(|l| l.0).collect();
    assert_eq!(times, [1000, 3000]);
    assert_eq!(p.now, 7000);
}

#[test]
fn ack_with_data_completes_handshake() {
    let mut a = TcpCb::new(cfg(), Default::default());
    let mut out = Out::default();
    a.connect(open(10, 1460), 0, &mut out);
    let syn = wire(&out)[0].clone();
    let mut out = Out::default();
    let mut b = passive(&syn, 99, 1460, BUFS.0, 0, &mut out);
    let ack = SegIn {
        seq: 11,
        ack: 100,
        flags: flags::ACK | flags::PSH,
        wnd: 1000,
        data: b"payload",
        ..Default::default()
    };
    let mut out = Out::default();
    b.feed(&ack, 1, &mut out);
    assert_eq!(b.state, TcpState::Established);
    assert!(out.established);
    assert_eq!(b.rcvq_len(), 7);
}

#[test]
fn fast_retransmit_on_dupacks() {
    let mut p = Pair::new(1000);
    fn drop_second(_: &Pair, to_b: bool, _: &Seg, i: usize) -> Fate {
        if to_b && i == 3 {
            Fate::Drop
        } else {
            Fate::Pass
        }
    }
    p.filter = drop_second;
    p.a.live.cwnd.set(20);
    p.send_a(&pattern(10_000));
    let t = p.now;
    p.run();
    // Repaired without waiting for the RTO
    assert_eq!(p.now, t);
    assert_eq!(p.b.rcvq_len(), 10_000);
    assert_eq!(p.a.snd_una, p.a.snd_max);
}

#[test]
fn pmtu_shrinks_segments() {
    let mut p = Pair::new(1460);
    p.filter = drop_all;
    p.send_a(&pattern(3000));
    let mut out = Out::default();
    p.a.pmtu(576, p.now, &mut out);
    assert_eq!(p.a.live.mss.get(), 524);
    assert!(!wire(&out).is_empty());
    assert!(wire(&out).iter().all(|s| s.data.len() <= 524));
    assert_eq!(p.a.wmem_queued, queued_truesize(&p.a));
}

/// An skb of `len` bytes of `v` at `seq`
fn piece(seq: u32, len: usize, v: u8) -> Box<SkBuff> {
    SegIn {
        seq,
        data: &alloc::vec![v; len],
        ..Default::default()
    }
    .skb()
}

/// tcp_data_queue_ofo: a covered skb is dropped, one starting where
/// another starts and reaching past it replaces it and the ones it
/// covers; partial overlaps are trimmed as they reach RCV.NXT
#[test]
fn ooo_insert_and_take() {
    use super::cb::{Ins, Ooo};
    use super::sack::Dsack;
    let mut o = Ooo::default();
    let q = |o: &mut Ooo, s| o.insert(s, None).0;
    assert_eq!(q(&mut o, piece(110, 10, 1)), Ins::Queued);
    assert_eq!(q(&mut o, piece(130, 10, 3)), Ins::Queued);
    // Covered: dropped, its bytes D-SACKed
    let mut d = Dsack::default();
    assert_eq!(o.insert(piece(112, 4, 9), Some(&mut d)), (Ins::Covered, 1));
    assert_eq!((d.on, d.blk), (true, (112, 116)));
    // A partial overlap with the one before (and the one after)
    let mut d = Dsack::default();
    assert_eq!(o.insert(piece(118, 14, 2), Some(&mut d)), (Ins::Queued, 1));
    assert_eq!(d.blk, (118, 120));
    assert_eq!((o.pieces(), o.bytes()), (3, 34));
    assert!(o.take(100, 100, None).0.is_none());
    let a = o.take(110, 110, None).0.unwrap();
    assert_eq!((a.tcp().seq, a.data()), (110, &[1u8; 10][..]));
    // Bytes RCV.NXT passed before the walk are D-SACKed
    let mut d = Dsack::default();
    let (b, n) = o.take(120, 120, Some(&mut d));
    let b = b.unwrap();
    assert_eq!((b.tcp().seq, b.data()), (120, &[2u8; 12][..]));
    assert_eq!((n, d.blk), (1, (118, 120)));
    let c = o.take(132, 132, None).0.unwrap();
    assert_eq!((c.tcp().seq, c.data()), (132, &[3u8; 8][..]));
    assert!(o.is_empty() && o.bytes() == 0);
    // Same start, longer: replaces and swallows what it covers
    q(&mut o, piece(200, 5, 1));
    q(&mut o, piece(210, 5, 2));
    q(&mut o, piece(220, 5, 3));
    let mut d = Dsack::default();
    assert_eq!(o.insert(piece(200, 22, 7), Some(&mut d)), (Ins::Queued, 1));
    assert_eq!(
        d.blk,
        (200, 205),
        "only blocks touching the first extend it"
    );
    assert_eq!((o.pieces(), o.bytes()), (2, 27));
    // An skb RCV.NXT already passed is dropped on the way
    assert_eq!(o.take(230, 230, None).0.map(|s| s.tcp().seq), None);
    assert!(o.is_empty());
}

#[test]
fn ooo_prune_from_the_top() {
    use super::cb::Ooo;
    let mut o = Ooo::default();
    o.insert(piece(110, 10, 1), None);
    o.insert(piece(130, 10, 3), None);
    // Only skbs at or beyond the incoming segment go, highest first
    // (Linux tcp_prune_ofo_queue stops where it would land last)
    let ts = piece(0, 10, 1).truesize();
    assert_eq!(o.prune_after(120), Some(ts));
    assert_eq!(o.bytes(), 10);
    assert_eq!(o.prune_after(120), None);
    assert_eq!(o.prune_after(110), Some(ts));
    assert!(o.is_empty() && o.prune_after(100).is_none());
}

#[test]
fn rcv_nxt_only_over_accepted_bytes() {
    // A 40000-byte buffer offers 40000 * 65 / 256 (Linux
    // TCP_DEFAULT_SCALING_RATIO before any segment is measured)
    let mut p = Pair::with_cap(60_000, 40_000);
    // b offers 10156; a 30000-byte flood is cut at the window edge
    let flood = pattern(30_000);
    let big = SegIn {
        seq: p.b.rcv_nxt,
        ack: p.b.snd_una,
        flags: flags::ACK,
        wnd: 1000,
        data: &flood,
        ..Default::default()
    };
    let (start, edge) = (p.b.rcv_nxt, p.b.rcv_nxt.wrapping_add(p.b.rcv_wnd()));
    assert_eq!(p.b.rcv_wnd(), 10_156);
    let mut out = Out::default();
    p.b.feed(&big, p.now, &mut out);
    assert_eq!(p.b.rcv_nxt, edge);
    assert_eq!(p.b.rcvq_len(), edge.wrapping_sub(start) as usize);
    // Its ACK offers a zero window
    assert_eq!(wire(&out).last().unwrap().wnd, 0);
}

#[test]
fn covered_ooo_intervals_do_not_block_fin() {
    let mut p = Pair::new(1460);
    let base = p.b.rcv_nxt;
    let seg = |off: u32, len: usize, fl: u8| (base.wrapping_add(off), alloc::vec![7u8; len], fl);
    let ack = p.b.snd_una;
    let mut feed = |b: &mut TcpCb, (seq, d, fl): (u32, Vec<u8>, u8)| {
        let s = SegIn {
            seq,
            ack,
            flags: flags::ACK | fl,
            wnd: 8000,
            data: &d,
            ..Default::default()
        };
        let mut out = Out::default();
        b.feed(&s, 0, &mut out);
        out
    };
    feed(&mut p.b, seg(100, 100, 0));
    feed(&mut p.b, seg(300, 100, 0));
    // A go-back-N retransmission covers both holes and both intervals
    feed(&mut p.b, seg(0, 400, 0));
    assert_eq!(p.b.rcvq_len(), 400);
    let out = feed(&mut p.b, seg(400, 0, flags::FIN));
    assert_eq!(p.b.state, TcpState::CloseWait);
    assert_eq!(wire(&out).last().unwrap().ack, base.wrapping_add(401));
}

/// A simultaneous open with both ends in SYN_RECEIVED, each one's
/// SYN-ACK on the wire
fn crossed_syns() -> Pair {
    let mut p = Pair::bare();
    let mut o1 = Out::default();
    p.a.connect(open(100, 1460), 0, &mut o1);
    let mut o2 = Out::default();
    p.b.connect(open(900, 1460), 0, &mut o2);
    p.take(true, o1);
    p.take(false, o2);
    p.step();
    p.step();
    assert_eq!(p.a.state, TcpState::SynReceived);
    assert_eq!(p.b.state, TcpState::SynReceived);
    p
}

#[test]
fn crossed_synack_establishes() {
    let mut p = crossed_syns();
    // b's bare SYN-ACK completes a's handshake (Linux 6.11+
    // tcp_validate_incoming), answered by an ACK (a duplicate SYN)
    let i = p.wire.iter().position(|(to_b, _)| !to_b).unwrap();
    let (_, synack) = p.wire.remove(i).unwrap();
    assert_eq!(synack.flags, flags::SYN | flags::ACK);
    let mut out = Out::default();
    p.a.feed(&seg_in(&synack), p.now, &mut out);
    assert_eq!(p.a.state, TcpState::Established);
    assert!(out.established);
    let w = wire(&out);
    assert_eq!(w.len(), 1);
    assert_eq!(w[0].flags, flags::ACK);
    assert_eq!((w[0].seq, w[0].ack), (101, 901));
    // Anything but a bare SYN-ACK for our SYN still gets a challenge ACK
    let mut q = crossed_syns();
    let i = q.wire.iter().position(|(to_b, _)| !to_b).unwrap();
    let (_, synack) = q.wire.remove(i).unwrap();
    let mut out = Out::default();
    let bad = Seg { ack: 100, ..synack };
    q.a.feed(&seg_in(&bad), q.now, &mut out);
    assert_eq!(q.a.state, TcpState::SynReceived);
}

#[test]
fn shutdown_in_syn_received_sends_fin() {
    let mut p = crossed_syns();
    let mut out = Out::default();
    assert!(p.a.shutdown_wr(p.now, &mut out));
    // Linux tcp_close_state: FIN_WAIT_1 and the FIN at once, behind the
    // unacknowledged SYN-ACK
    assert_eq!(p.a.state, TcpState::FinWait1);
    let w = wire(&out);
    assert_eq!(w.len(), 1);
    assert_eq!(w[0].flags, flags::FIN | flags::ACK);
    assert_eq!(w[0].seq, 101);
    p.take(true, out);
    p.run();
    assert_eq!(p.a.state, TcpState::FinWait2);
    assert_eq!(p.b.state, TcpState::CloseWait);
}

#[test]
fn close_in_syn_received_sends_fin() {
    let mut p = crossed_syns();
    let mut out = Out::default();
    p.a.close(false, p.now, &mut out);
    // A FIN, not a RST (Linux __tcp_close: no unread data, no linger 0)
    assert_eq!(p.a.state, TcpState::FinWait1);
    let w = wire(&out);
    assert_eq!(w.len(), 1);
    assert_eq!(w[0].flags, flags::FIN | flags::ACK);
    assert_eq!((w[0].seq, w[0].ack), (101, 901));
    assert!(!out.done && out.err.is_none());
    p.take(true, out);
    p.run();
    assert_eq!(p.a.state, TcpState::FinWait2);
    assert_eq!(p.b.state, TcpState::CloseWait);
    assert!(!p.log.iter().any(|(_, _, s)| s.has(flags::RST)));
}

#[test]
fn fin_wait1_resends_unacked_synack() {
    let mut p = crossed_syns();
    p.wire.clear();
    p.filter = |_, to_b, _, _| if to_b { Fate::Drop } else { Fate::Pass };
    let mut out = Out::default();
    p.a.close(false, p.now, &mut out);
    p.take(true, out);
    // The tail loss probe resends the FIN (Linux tcp_send_loss_probe:
    // the last skb), then the timeout resends the SYN-ACK alone (Linux:
    // the head of the retransmit queue, still in FIN_WAIT_1), then the
    // FIN once it is acknowledged
    let n = p.log.len();
    assert!(p.tick());
    let probe: Vec<&Seg> = p.log[n..].iter().filter(|l| l.1).map(|l| &l.2).collect();
    assert_eq!(probe.len(), 1);
    assert_eq!(
        (probe[0].flags, probe[0].seq),
        (flags::FIN | flags::ACK, 101)
    );
    let n2 = p.log.len();
    assert!(p.tick());
    assert!(n2 > n);
    let n = n2;
    let w: Vec<Seg> = p.log[n..]
        .iter()
        .filter(|(_, to_b, _)| *to_b)
        .map(|(_, _, s)| s.clone())
        .collect();
    assert_eq!(w.len(), 1);
    assert_eq!(w[0].flags, flags::SYN | flags::ACK);
    assert_eq!((w[0].seq, w[0].ack), (100, 901));
    assert!(w[0].mss.is_some());
    assert_eq!(p.a.state, TcpState::FinWait1);
    assert_eq!(p.a.stats.total_retrans, 2);
    p.filter = pass;
    let mut out = Out::default();
    let ack = SegIn {
        seq: 901,
        ack: 101,
        flags: flags::ACK,
        wnd: 1000,
        ..Default::default()
    };
    p.a.feed(&ack, p.now, &mut out);
    // The ACK of the SYN-ACK clears the retransmission stamp, so the
    // timeout looks spurious and is undone (Linux tcp_process_loss ->
    // tcp_try_undo_loss, FLAG_SYN_ACKED): the FIN waits for the timer
    assert!(wire(&out).is_empty());
    // Disorder, not Open: the FIN skb was retransmitted (the probe)
    assert_eq!(p.a.ca_state, super::recovery::CaState::Disorder);
    let n = p.log.len();
    p.wire.clear();
    p.filter = |_, to_b, _, _| if to_b { Fate::Pass } else { Fate::Drop };
    while !p.log[n..].iter().any(|l| l.1) {
        assert!(p.tick());
    }
    let w: Vec<Seg> = p.log[n..]
        .iter()
        .filter(|(_, to_b, _)| *to_b)
        .map(|(_, _, s)| s.clone())
        .collect();
    assert_eq!(w.len(), 1);
    assert_eq!(w[0].flags, flags::FIN | flags::ACK);
    assert_eq!(w[0].seq, 101);
    p.wire.clear();
    assert_eq!(p.a.state, TcpState::FinWait1);
    let mut out = Out::default();
    p.a.feed(&SegIn { ack: 102, ..ack }, p.now, &mut out);
    assert_eq!(p.a.state, TcpState::FinWait2);
}

#[test]
fn ooo_truesize() {
    use super::cb::Ooo;
    let mut o = Ooo::default();
    // Many tiny scattered segments: each charged its truesize
    let ts = piece(0, 1, 1).truesize();
    for i in 0..2000u32 {
        o.insert(piece(10 + i * 3, 1, 1), None);
    }
    assert_eq!(o.pieces(), 2000);
    assert_eq!(o.truesize(), 2000 * ts);
    // Sequence numbers wrap
    let mut o = Ooo::default();
    o.insert(piece(0xffff_fffc, 8, 4), None);
    o.insert(piece(10, 4, 5), None);
    assert_eq!(
        o.take(0xffff_fffe, 0xffff_fffe, None).0.unwrap().data(),
        &[4u8; 6][..]
    );
    assert_eq!(o.take(10, 10, None).0.unwrap().data(), &[5u8; 4][..]);
}

// ============================================================================
// P7: options, delayed ACK, Nagle/cork, keepalive, congestion
// ============================================================================

fn no_opts() -> Cfg {
    Cfg {
        wscale: false,
        ts: 0,
        ..cfg()
    }
}

#[test]
fn peer_without_wscale_or_ts() {
    // b does not do window scaling or timestamps: a falls back to both off
    let mut p = Pair::with_cfgs(1460, 200_000, cfg(), no_opts());
    let (syn, synack) = (p.log[0].2.clone(), p.log[1].2.clone());
    assert!(syn.ws.is_some() && syn.ts.is_some());
    assert_eq!((synack.ws, synack.ts), (None, None));
    for c in [&p.a, &p.b] {
        assert!(!c.wscale_ok && !c.ts_ok);
        assert_eq!((c.snd_wscale, c.rcv_wscale), (0, 0));
        assert_eq!(c.live.mss.get(), 1460);
    }
    // Windows stay below 64 KB, data flows, no options on the wire
    let data = pattern(150_000);
    assert_eq!(transfer(&mut p, &data, 10_000), data);
    assert!(
        p.log[1..]
            .iter()
            .all(|l| l.2.ts.is_none() && l.2.ws.is_none())
    );
    assert!(p.a.snd_wnd <= 65535);
    // The other way round: only a lacks them
    let p = Pair::with_cfgs(1460, 200_000, no_opts(), cfg());
    assert_eq!((p.log[0].2.ws, p.log[0].2.ts), (None, None));
    assert_eq!((p.log[1].2.ws, p.log[1].2.ts), (None, None));
    assert!(!p.b.wscale_ok && !p.b.ts_ok);
}

#[test]
fn wscale_opens_large_window() {
    // A 1 MB buffer: the scaled window exceeds 64 KB on the wire
    let mut p = Pair::with_cap(1460, 1 << 20);
    assert_eq!(p.b.rcv_wscale, 7);
    let data = pattern(600_000);
    p.send_a(&data[..400_000]);
    p.run();
    assert!(p.a.snd_wnd > 65535, "snd_wnd {}", p.a.snd_wnd);
    let ack = p.log.iter().rev().find(|l| !l.1).unwrap().2.clone();
    assert_eq!((ack.wnd as u32) << 7, p.a.snd_wnd);
    // ... and more than 64 KB can be in flight
    p.a.live.cwnd.set(1000);
    p.filter = drop_all;
    p.send_a(&data[400_000..]);
    assert!(p.a.snd_max.wrapping_sub(p.a.snd_una) > 65535);
    // The locked buffer picks its own scale (Linux SOCK_RCVBUF_LOCK)
    let mut b = TcpCb::new(cfg(), Default::default());
    b.rcvbuf = 4096;
    b.userlocks = super::buf::RCVBUF_LOCK;
    let mut a = TcpCb::new(cfg(), Default::default());
    let mut out = Out::default();
    a.connect(open(1, 1460), 0, &mut out);
    let mut o2 = Out::default();
    b.passive_in(&seg_in(&wire(&out)[0]), open(2, 1460), 0, &mut o2);
    assert_eq!(b.rcv_wscale, 0);
    assert_eq!(wire(&o2)[0].ws, Some(0));
}

#[test]
fn timestamps_echo_and_rtt() {
    let mut p = Pair::new(1460);
    // A 100 ms round trip measured from the TS echo
    p.send_a(b"ping");
    let seg = p.log.last().unwrap().2.clone();
    let (v, e) = seg.ts.unwrap();
    assert_eq!(e, p.a.ts_recent);
    p.now += 100;
    p.run();
    let ack = p.log.last().unwrap().2.clone();
    assert_eq!(ack.ts.unwrap().1, v, "ACK echoes the data's TSval");
    // SRTT about 0 from the handshake, then the data's 100 ms (its send
    // time, not the echo: Linux prefers seq_rtt_us): about 100 / 8
    assert!((12_500..=12_501).contains(&p.a.rtt().0), "{}", p.a.rtt().0);
    let s1 = p.a.srtt_us;
    // The minimum: the handshake's 1 us on the simulated wire
    assert_eq!(p.a.min_rtt(), 1);
    // A retransmission is timed too (Karn would skip it)
    p.filter = drop_all;
    p.send_a(b"lost");
    let t0 = p.now;
    p.tick();
    assert!(p.now > t0);
    p.filter = pass;
    p.now += 50;
    let rexmit = p.log.iter().rev().find(|l| l.1).unwrap().2.clone();
    p.wire.push_back((true, rexmit));
    p.run();
    // The retransmission's echo gives a sample of 50 ms (Karn: no send
    // time sample; Linux tcp_rtt_tsopt_us), by tcp_rtt_estimator
    let want = (s1 as i64 + (50_000 - i64::from(s1 >> 3))) as u32;
    assert_eq!(p.a.srtt_us, want);
}

#[test]
fn paws_rejects_old_timestamps() {
    let mut p = Pair::new(1460);
    p.send_a(b"one");
    p.now += 10;
    p.run();
    let old = p
        .log
        .iter()
        .find(|l| l.1 && !l.2.data.is_empty())
        .unwrap()
        .2
        .clone();
    p.now += 1000;
    p.send_a(b"two");
    p.run();
    assert_eq!(p.b.rcvq_len(), 6);
    // A segment with an older TSval (a wrapped sequence replay): dropped
    // with a duplicate ACK
    let mut replay = old.clone();
    replay.seq = p.b.rcv_nxt;
    replay.data = b"evil".to_vec();
    let mut out = Out::default();
    p.b.feed(&seg_in(&replay), p.now, &mut out);
    assert_eq!(p.b.rcvq_len(), 6);
    assert_eq!(wire(&out).len(), 1);
    assert_eq!(wire(&out)[0].ack, p.b.rcv_nxt);
    // The same with a fresh TSval is accepted
    replay.ts = Some((old.ts.unwrap().0.wrapping_add(5000), 0));
    let mut out = Out::default();
    p.b.feed(&seg_in(&replay), p.now, &mut out);
    assert_eq!(p.b.rcvq_len(), 10);
    // An old RST is still honoured (RFC 7323 5.3 / Linux)
    let rst = Seg {
        seq: p.b.rcv_nxt,
        flags: flags::RST,
        ts: old.ts,
        ..Default::default()
    };
    let mut out = Out::default();
    p.b.feed(&seg_in(&rst), p.now, &mut out);
    assert_eq!(p.b.state, TcpState::Closed);
}

#[test]
fn ts_recent_follows_last_ack_sent() {
    // TS.Recent is taken only from segments at or before Last.ACK.sent:
    // with ACKs delayed it echoes the earliest unacknowledged segment
    let mut p = Pair::new(1000);
    p.b.live.quick.set(0);
    p.b.live.ato.set(40);
    p.send_a(&pattern(500));
    let first = p.log.last().unwrap().2.ts.unwrap().0;
    p.step();
    p.now += 5;
    p.send_a(&pattern(500));
    p.step();
    assert_eq!(p.b.ts_recent, first);
    // Delayed: the ACK goes out with the timer and echoes the first
    assert!(p.wire.is_empty());
    p.tick();
    let ack = p.log.last().unwrap().2.clone();
    assert!(!ack.has(flags::SYN) && ack.data.is_empty());
    assert_eq!(ack.ts.unwrap().1, first);
}

#[test]
fn delayed_ack_timing() {
    let mut p = Pair::new(1000);
    // Quickack mode at the start: the first ACKs are immediate
    p.send_a(&pattern(100));
    p.run();
    assert_eq!(p.a.snd_una, p.a.snd_max);
    assert!(p.b.live.quick.get() > 0);
    // Leave quickack mode: a lone small segment waits for the ATO
    p.b.live.quick.set(0);
    let t = p.now;
    p.send_a(&pattern(100));
    p.run();
    assert_ne!(p.a.snd_una, p.a.snd_max);
    assert_eq!(p.b.dack.at, Some(t + 40));
    p.tick();
    p.run();
    assert_eq!(p.now, t + 40);
    assert_eq!(p.a.snd_una, p.a.snd_max);
    // Two full segments are acknowledged at once
    // by the reader making room (Linux tcp_cleanup_rbuf), or on arrival
    // if the right edge advances by what arrived
    p.read_b(1 << 20);
    p.b.live.quick.set(0);
    p.log.clear();
    let mss = p.a.live.mss.get() as usize;
    p.send_a(&pattern(2 * mss));
    p.step();
    assert!(p.wire.len() == 1, "first segment: ACK delayed");
    p.step();
    p.read_b(1 << 20);
    p.run();
    assert_eq!(p.a.snd_una, p.a.snd_max);
    let acks = p.log.iter().filter(|l| !l.1).count();
    assert_eq!(acks, 1, "one ACK for two segments");
    // A reply carries the ACK (no separate pure ACK)
    p.b.live.quick.set(0);
    p.send_a(&pattern(10));
    p.run();
    p.log.clear();
    let mut out = Out::default();
    p.b.send(b"reply");
    p.b.output(p.now, &mut out);
    assert_eq!(wire(&out).len(), 1);
    assert_eq!(wire(&out)[0].ack, p.b.rcv_nxt);
    assert_eq!(p.b.dack.at, None);
}

#[test]
fn quickack_option() {
    let mut p = Pair::new(1000);
    assert!(p.b.quickack());
    let mut out = Out::default();
    p.b.set_quickack(0, &mut out);
    assert!(!p.b.quickack());
    // An owed ACK goes out when quickack is turned on
    p.send_a(&pattern(100));
    p.run();
    assert!(p.b.dack.pending, "pingpong delays the ACK");
    let mut out = Out::default();
    p.b.set_quickack(1, &mut out);
    assert!(p.b.quickack());
    assert_eq!(wire(&out).len(), 1);
    assert!(!p.b.dack.pending);
}

#[test]
fn nagle_coalesces_small_writes() {
    let mut p = Pair::new(1000);
    p.b.live.quick.set(0);
    p.b.set_quickack(0, &mut Out::default());
    p.log.clear();
    // The first small write goes out; the next ones wait for its ACK
    for _ in 0..5 {
        p.send_a(b"0123456789");
    }
    let sent: Vec<usize> = p
        .log
        .iter()
        .filter(|l| l.1)
        .map(|l| l.2.data.len())
        .collect();
    assert_eq!(sent, [10]);
    p.until(|p| p.b.rcvq_len() == 50, 20);
    let sent: Vec<usize> = p
        .log
        .iter()
        .filter(|l| l.1)
        .map(|l| l.2.data.len())
        .collect();
    assert_eq!(sent, [10, 40]);
    // TCP_NODELAY: each write is a segment
    p.a.opts.nodelay = true;
    p.log.clear();
    for _ in 0..3 {
        p.send_a(b"abc");
    }
    let sent: Vec<usize> = p
        .log
        .iter()
        .filter(|l| l.1)
        .map(|l| l.2.data.len())
        .collect();
    assert_eq!(sent, [3, 3, 3]);
}

#[test]
fn cork_holds_partial_segments() {
    let mut p = Pair::new(1000);
    let m = p.a.live.mss.get() as usize;
    p.a.opts.cork = true;
    p.log.clear();
    let t = p.now;
    p.send_a(&pattern(2 * m + 500));
    // Two full segments go, the 500-byte tail waits
    let sent: Vec<usize> = p
        .log
        .iter()
        .filter(|l| l.1)
        .map(|l| l.2.data.len())
        .collect();
    assert_eq!(sent, [m, m]);
    p.run();
    assert_eq!(p.b.rcvq_len(), 2 * m);
    // ... until the 200 ms probe timer pushes it
    p.until(|p| p.b.rcvq_len() == 2 * m + 500, 10);
    assert_eq!(p.b.rcvq_len(), 2 * m + 500);
    assert!(p.now - t >= 200, "pushed after {} ms", p.now - t);
    // Uncorking sends at once
    p.send_a(&pattern(300));
    assert_eq!(p.wire.len(), 0);
    p.a.opts.cork = false;
    let mut out = Out::default();
    p.a.output(p.now, &mut out);
    assert_eq!(wire(&out).len(), 1);
    assert_eq!(wire(&out)[0].data.len(), 300);
    // MSG_MORE holds the tail of that send only
    p.take(true, out);
    p.run();
    p.log.clear();
    p.a.send(&pattern(m + 200));
    let mut out = Out::default();
    p.a.output_more(p.now, &mut out);
    let sent: Vec<usize> = wire(&out).iter().map(|s| s.data.len()).collect();
    assert_eq!(sent, [m]);
}

#[test]
fn iw10_slow_start_growth() {
    let mut p = Pair::new(1000);
    let mss = p.a.live.mss.get() as usize;
    assert_eq!(p.a.cong.snd_cwnd(), 10);
    p.filter = drop_all;
    p.log.clear();
    p.send_a(&pattern(100_000));
    // The initial window: ten segments
    assert_eq!(p.log.len(), 10);
    // Slow start roughly doubles per round trip: a round delivers the
    // data on the wire, then the ACKs it drew
    let mut p = Pair::with_cap(1000, 1 << 20);
    p.a.sndbuf = 1 << 20;
    let mut rounds = Vec::new();
    p.send_a(&pattern(300_000));
    for _ in 0..3 {
        let before = p.a.snd_max;
        for _ in 0..2 {
            for _ in 0..p.wire.len() {
                p.step();
            }
        }
        rounds.push(p.a.snd_max.wrapping_sub(before) as usize / mss);
    }
    assert!(rounds[1] >= 16, "rounds {:?}", rounds);
    // Congestion avoidance: about one segment per window
    let c = &mut p.a.cong;
    c.set_ssthresh(c.snd_cwnd());
    let w = c.snd_cwnd();
    c.cong_avoid_ai(w, w);
    assert_eq!(c.snd_cwnd(), w + 1);
}

#[test]
fn keepalive_dead_peer_times_out() {
    let mut p = Pair::new(1460);
    p.a.opts.keepidle = 10;
    p.a.opts.keepintvl = 2;
    p.a.opts.keepcnt = 3;
    p.a.set_keepalive(true, p.now);
    let t0 = p.now;
    // A live peer answers every probe: nothing happens
    p.until(|p| p.now >= t0 + 60_000, 50);
    assert_eq!(p.a.state, TcpState::Established);
    let probes = p
        .log
        .iter()
        .filter(|l| l.1 && l.2.seq == p.a.snd_una.wrapping_sub(1))
        .count();
    assert!(probes >= 5);
    // The peer dies: 3 unanswered probes 2 s apart, then a reset
    p.filter = drop_all;
    p.log.clear();
    let t1 = p.now;
    p.until(|p| p.a.state == TcpState::Closed, 50);
    assert_eq!(p.a_out.err, Some(KernelError::TimedOut));
    let sent: Vec<u64> = p.log.iter().filter(|l| l.1).map(|l| l.0 - t1).collect();
    assert_eq!(sent.len(), 4, "3 probes and a RST: {:?}", sent);
    assert!(p.log.last().unwrap().2.has(flags::RST));
    assert!(p.now - t1 <= 10_000 + 3 * 2000);
}

#[test]
fn keepalive_waits_for_idle() {
    let mut p = Pair::new(1460);
    p.a.opts.keepidle = 10;
    p.a.set_keepalive(true, p.now);
    assert_eq!(p.a.next_timer(), Some(p.now + 10_000));
    // Traffic pushes the probe back
    p.now += 6000;
    p.send_a(b"x");
    p.run();
    p.log.clear();
    // At 10 s it finds 4 s idle and waits 6 s more
    p.tick();
    assert_eq!((p.now, p.a.live.keep_at.get()), (10_000, Some(16_000)));
    p.tick();
    assert_eq!(p.now, 16_000);
    let probes = p
        .log
        .iter()
        .filter(|l| l.1 && l.2.seq == p.a.snd_una.wrapping_sub(1))
        .count();
    assert_eq!(probes, 1);
    // Off: no timer
    p.a.set_keepalive(false, p.now);
    assert!(p.a.live.keep_at.get().is_none());
}

#[test]
fn user_timeout_bounds_retransmission() {
    let mut p = Pair::new(1460);
    p.a.opts.user_timeout = 5000;
    p.filter = drop_all;
    let t0 = p.now;
    p.send_a(b"data");
    p.until(|p| p.a.state == TcpState::Closed, 100);
    assert_eq!(p.a_out.err, Some(KernelError::TimedOut));
    // Gave up 5 s after the first retransmission (the loss probe at
    // 201 ms, the RTO at 402 ms; Linux retransmits_timed_out from
    // retrans_stamp, the timer clamped to it), not after 15
    // retransmissions
    let dt = p.now - t0;
    assert_eq!(dt, 5402, "gave up after {} ms", dt);
}

#[test]
fn zero_window_probes_with_options() {
    // Persist with timestamps and scaling: probes are answered with the
    // window, and a dead peer is given up on
    let mut p = Pair::with_cap(1000, 4000);
    p.send_a(&pattern(10_000));
    assert!(p.until(|p| p.a.snd_wnd == 0, 20));
    p.filter = drop_all;
    p.until(|p| p.a.state == TcpState::Closed, 100);
    assert_eq!(p.a_out.err, Some(KernelError::TimedOut));
}

#[test]
fn tw_reopens_with_newer_timestamp() {
    let (p, mut tw, _) = tw_pair();
    let now = p.now;
    let old = tw.rcv_nxt.wrapping_sub(10);
    let (r, next) = (tw.ts_recent, tw.rcv_nxt.wrapping_add(1));
    // An old SYN with an older timestamp fails PAWS: ACKed, no takeover
    let s = tw_seg(old, flags::SYN, Some((r.wrapping_sub(1), 0)));
    assert_eq!(tw.rcv(&s, now, false, None), TwStatus::Ack);
    // The new connection's ISN is past the old one's sequence space
    // (Linux tcp_tw_isn = tw_snd_nxt + 65535 + 2)
    let isn = tw.snd_nxt.wrapping_add(65537);
    let s = tw_seg(old, flags::SYN, Some((r.wrapping_add(1), 0)));
    assert_eq!(tw.rcv(&s, now, false, None), TwStatus::Syn(isn));
    let s = tw_seg(next, flags::SYN, None);
    assert_eq!(tw.rcv(&s, now, false, None), TwStatus::Syn(isn));
    // Not with ACK
    let s = tw_seg(next, flags::SYN | flags::ACK, None);
    assert!(!matches!(tw.rcv(&s, now, false, None), TwStatus::Syn(_)));
}

/// A SYN cookie handshake (Linux tcp_conn_request with want_cookie, then
/// cookie_v4_check): the stateless SYN-ACK carries the SYN's options in
/// its timestamp, the ACK rebuilds the request with the cookie's MSS,
/// and the child, ESTABLISHED by that ACK, carries data both ways
#[test]
fn syncookie_handshake() {
    use super::output::Tuple;
    use super::syncookies::{Req, Synack, check, init_sequence, request, synack, timestamp_decode};
    use crate::net::ipv4::Ipv4Addr;
    let t = Tuple {
        laddr: Ipv4Addr(0x0a00_0001),
        lport: 80,
        raddr: Ipv4Addr(0x0a00_0002),
        rport: 40000,
    };
    let mut p = Pair::bare();
    p.now = 100_000;
    let mut out = Out::default();
    p.a.connect(open(1000, 1452), p.now, &mut out);
    let syn = seg_in(&wire(&out)[0]).hdr();
    let c = cfg();
    let (r, mss) = request(&syn, &c, 0);
    assert_eq!(mss, 1452);
    let (isn, m) = init_sequence(&t, syn.seq, mss, p.now);
    assert_eq!(m, 1440);
    let lim = Synack {
        rcvbuf: 128 * 1024,
        rcvbuf_locked: false,
        window_clamp: 0,
        user_mss: 0,
        adv_mss: 1460,
        ts_off: 0,
    };
    let sa = synack(&syn, &r, isn, &c, &lim, p.now);
    assert!(sa.ws.is_some() && sa.sack_perm && sa.ts.is_some());
    assert_eq!(sa.ack, syn.seq.wrapping_add(1));
    p.now += 10;
    let mut out = Out::default();
    let skb = SkBuff::alloc_tx(0, Gfp::KERNEL).unwrap();
    p.a.input(&sa, skb, p.now, &mut out);
    assert_eq!(p.a.state, TcpState::Established);
    let ack = wire(&out).remove(0);
    let ah = seg_in(&ack).hdr();
    let mss = check(&t, ah.seq, ah.ack, p.now);
    assert_eq!(mss, 1440);
    let req = Req {
        r: timestamp_decode(ah.ts, &c).unwrap(),
        mss,
        tsoff: 0,
    };
    assert_eq!(req.r, r);
    p.b.rcvbuf = 128 * 1024;
    let o = Open {
        iss: ah.ack.wrapping_sub(1),
        ts_off: 0,
        mss: 1460,
    };
    p.b.cookie_open(&req.syn(&ah), o, p.now);
    let mut out = Out::default();
    p.b.feed(&seg_in(&ack), p.now, &mut out);
    assert_eq!(p.b.state, TcpState::Established);
    assert!(p.b.ts_ok && p.b.sack_ok != 0 && p.b.wscale_ok);
    assert_eq!(p.b.snd_wscale, p.a.rcv_wscale);
    assert_eq!(Some(p.b.rcv_wscale), sa.ws);
    assert_eq!(p.b.peer_mss, 1440);
    p.take(false, out);
    let data = pattern(100_000);
    assert_eq!(transfer(&mut p, &data, 500), data);
    core::mem::swap(&mut p.a, &mut p.b);
    assert_eq!(transfer(&mut p, &data, 500), data);
}

// ============================================================================
// Review findings (reproduce first)
// ============================================================================

#[test]
fn ts_recent_needs_valid_ack() {
    // An in-window segment with an impossible ACK must not move
    // TS.Recent (Linux updates it only after the ACK checks): else a blind
    // attacker pushes TS.Recent ahead and PAWS drops the real peer
    let mut p = Pair::new(1460);
    let before_ts = p.b.ts_recent;
    let bogus = SegIn {
        seq: p.b.rcv_nxt,
        ack: p.b.snd_max.wrapping_add(100_000),
        flags: flags::ACK,
        wnd: 1000,
        ts: Some((before_ts.wrapping_add(0x7fff_0000), 0)),
        ..Default::default()
    };
    p.b.feed(&bogus, p.now, &mut Out::default());
    assert_eq!(p.b.ts_recent, before_ts);
    // The real peer still gets through
    let data = pattern(1000);
    assert_eq!(transfer(&mut p, &data, 1000), data);
}

#[test]
fn old_ack_does_not_update_window() {
    // An ACK below SND.UNA (Linux old_ack) carries no window update
    let mut p = Pair::new(1000);
    p.send_a(&pattern(5000));
    p.run();
    let wnd = p.a.snd_wnd;
    assert!(wnd > 0);
    let old = SegIn {
        seq: p.a.rcv_nxt.wrapping_add(10),
        ack: p.a.snd_una.wrapping_sub(500),
        flags: flags::ACK,
        wnd: 0,
        ts: Some((p.a.ts_recent.wrapping_add(1), 0)),
        ..Default::default()
    };
    p.a.feed(&old, p.now, &mut Out::default());
    assert_eq!(p.a.snd_wnd, wnd);
    // The acceptable ACK range is bounded by the bytes acknowledged so
    // far (Linux: min(max_window, bytes_acked))
    let mut q = Pair::new(1000);
    q.send_a(b"x");
    q.run();
    let far = SegIn {
        seq: q.a.rcv_nxt,
        ack: q.a.snd_una.wrapping_sub(5000),
        flags: flags::ACK,
        wnd: 0,
        ts: Some((q.a.ts_recent.wrapping_add(1), 0)),
        ..Default::default()
    };
    let mut out = Out::default();
    q.a.feed(&far, q.now, &mut out);
    assert!(q.a.snd_wnd > 0);
    assert_eq!(
        wire(&out).len(),
        1,
        "challenge ACK for an ACK below the range"
    );
}

#[test]
fn corked_segment_is_retransmitted() {
    // A lost corked partial segment must be retransmitted (Linux
    // tcp_retransmit_skb ignores Nagle and cork)
    let mut p = Pair::new(1000);
    p.a.opts.cork = true;
    fn drop_first_data(_: &Pair, to_b: bool, s: &Seg, i: usize) -> Fate {
        if to_b && !s.data.is_empty() && i == 2 {
            Fate::Drop
        } else {
            Fate::Pass
        }
    }
    p.filter = drop_first_data;
    p.send_a(&pattern(100));
    // The probe pushes it (lost), the RTO must resend it
    p.until(
        |p| p.b.rcvq_len() == 100 || p.a.state == TcpState::Closed,
        30,
    );
    assert_eq!(p.a.state, TcpState::Established);
    assert_eq!(p.b.rcvq_len(), 100);
}

#[test]
fn oow_acks_rate_limited() {
    // Out-of-window pure segments get at most one dupack per 500 ms
    // (Linux tcp_oow_rate_limited); data segments are not limited
    let mut p = Pair::new(1460);
    let stale = SegIn {
        seq: p.a.rcv_nxt.wrapping_sub(5000),
        ack: p.a.snd_una,
        flags: flags::ACK,
        wnd: 1000,
        ..Default::default()
    };
    let mut n = 0;
    for _ in 0..10 {
        let mut out = Out::default();
        p.a.feed(&stale, p.now, &mut out);
        n += wire(&out).len();
    }
    assert_eq!(n, 1);
    let mut out = Out::default();
    p.a.feed(&stale, p.now + 500, &mut out);
    assert_eq!(wire(&out).len(), 1);
    // Challenge ACKs (in-window RST) share the limit
    let rst = SegIn {
        seq: p.a.rcv_nxt.wrapping_add(10),
        flags: flags::RST,
        ..Default::default()
    };
    let mut out = Out::default();
    p.a.feed(&rst, p.now + 600, &mut out);
    assert!(wire(&out).is_empty());
    assert_eq!(p.a.state, TcpState::Established);
}

#[test]
fn time_wait_entry_is_compact() {
    let cb = core::mem::size_of::<super::cb::TcpCb>();
    // The whole `Arc<TimeWait>` block, the embedded 2MSL timer included
    // (Linux tcp_timewait_sock has its tw_timer too), comes from its own
    // cache at that exact size (Linux twsk_slab), no kmalloc rounding;
    // well under the control block
    let tw = crate::util::kalloc::arc_layout::<super::timewait::TimeWait>().size();
    assert!(tw <= 512 && tw < cb, "Arc<TimeWait> {tw} B vs TcpCb {cb} B");
}

/// A pair counting in one namespace's MIBs (as over loopback)
fn mib_pair() -> (Pair, alloc::sync::Arc<crate::net::mib::NetMib>) {
    let m = crate::net::mib::NetMib::new().unwrap();
    let mut p = Pair::bare();
    p.a.mib = Some(m.clone());
    let mut out = Out::default();
    p.a.connect(open(1000, 1460), p.now, &mut out);
    p.take(true, out);
    let (_, syn) = p.wire.pop_front().unwrap();
    let mut out = Out::default();
    p.b.mib = Some(m.clone());
    p.b.passive_in(&seg_in(&syn), open(5000, 1460), p.now, &mut out);
    p.take(false, out);
    p.run();
    assert_eq!(p.b.state, TcpState::Established);
    (p, m)
}

/// Linux tcp_set_state / tcp_connect / tcp_create_openreq_child and
/// tcp_transmit_skb counting: a handshake, then an orderly close
#[test]
fn mib_open_close() {
    use crate::net::mib::*;
    let (mut p, m) = mib_pair();
    assert_eq!(m.tcp.fold(TCP_MIB_ACTIVEOPENS), 1);
    assert_eq!(m.tcp.fold(TCP_MIB_PASSIVEOPENS), 1);
    assert_eq!(m.tcp.fold(TCP_MIB_CURRESTAB), 2);
    // SYN, SYN-ACK, ACK
    assert_eq!(m.tcp.fold(TCP_MIB_OUTSEGS), 3);
    let mut out = Out::default();
    p.a.close(false, p.now, &mut out);
    p.take(true, out);
    p.run();
    // FIN_WAIT_2 left ESTABLISHED, CLOSE_WAIT is still counted
    assert_eq!(m.tcp.fold(TCP_MIB_CURRESTAB), 1);
    let mut out = Out::default();
    p.b.close(false, p.now, &mut out);
    p.take(false, out);
    p.run();
    assert_eq!(p.a.state, TcpState::TimeWait);
    assert_eq!(m.tcp.fold(TCP_MIB_CURRESTAB), 0);
    assert_eq!(m.tcp.fold(TCP_MIB_ESTABRESETS), 0);
    // FIN, ACK, FIN, ACK
    assert_eq!(m.tcp.fold(TCP_MIB_OUTSEGS), 7);
    assert_eq!(m.tcp.fold(TCP_MIB_RETRANSSEGS), 0);
    // Both FINs were new sequence space
    assert_eq!(m.net.fold(LINUX_MIB_TCPORIGDATASENT), 2);
    // a's SYN and both FINs; the ACKs of the FINs are pure
    assert_eq!(m.net.fold(LINUX_MIB_TCPDELIVERED), 3);
    // The third ACK and the two FINs' ACKs (Linux: tcp_ack's slow
    // path, the handshake's included)
    assert_eq!(m.net.fold(LINUX_MIB_TCPPUREACKS), 3);
}

/// A TIME_WAIT socket rejects an old-timestamp pure ACK as any PAWS
/// failure (Linux tcp_timewait_state_process: PAWSTimewait, an ACK
/// back), not as an established socket's silent old ACK
#[test]
fn mib_timewait_paws_rejects() {
    use crate::net::mib::*;
    let (mut p, m) = mib_pair();
    let (mut tw, _) = tw_close(&mut p);
    let last = p.log.iter().rev().find(|l| !l.1).unwrap().2.clone();
    let (tsv, tse) = last.ts.unwrap();
    let old = Seg {
        seq: tw.rcv_nxt.wrapping_sub(1),
        ack: last.ack,
        flags: flags::ACK,
        wnd: last.wnd,
        ts: Some((tsv.wrapping_sub(1000), tse)),
        ..Default::default()
    };
    p.now += 10;
    let st = tw.rcv(&seg_in(&old).hdr(), p.now, false, Some(&m));
    assert_eq!(m.net.fold(LINUX_MIB_PAWS_TW_REJECTED), 1);
    assert_eq!(m.net.fold(LINUX_MIB_PAWS_OLD_ACK), 0);
    assert_eq!(st, TwStatus::Ack);
    assert_eq!(tw.expires(), p.now + TIMEWAIT_LEN);
    // An in-window RST with an old timestamp is rejected until
    // TS.Recent is PAWS_MSL (60 s) old (Linux tcp_paws_reject)
    let rst = Seg {
        seq: tw.rcv_nxt,
        flags: flags::RST,
        ts: Some((tsv.wrapping_sub(1000), 0)),
        ..Default::default()
    };
    let rst = seg_in(&rst).hdr();
    assert_eq!(tw.rcv(&rst, p.now, false, Some(&m)), TwStatus::Success);
    assert_eq!(m.net.fold(LINUX_MIB_PAWS_TW_REJECTED), 2);
    let st = tw.rcv(&rst, p.now + 61_000, false, Some(&m));
    assert_eq!(st, TwStatus::Kill);
}

/// An abort resets both ends: EstabResets on each, one OutRst
#[test]
fn mib_reset() {
    use crate::net::mib::*;
    let (mut p, m) = mib_pair();
    let mut out = Out::default();
    p.a.close(true, p.now, &mut out);
    p.take(true, out);
    p.run();
    assert_eq!(p.b.state, TcpState::Closed);
    assert_eq!(m.tcp.fold(TCP_MIB_CURRESTAB), 0);
    assert_eq!(m.tcp.fold(TCP_MIB_ESTABRESETS), 2);
    assert_eq!(m.tcp.fold(TCP_MIB_OUTRSTS), 1);
    assert_eq!(m.net.fold(LINUX_MIB_TCPABORTONDATA), 1);
    assert_eq!(m.tcp.fold(TCP_MIB_ATTEMPTFAILS), 0);
}

/// A lost data segment: one timeout, one retransmission, which is not
/// in OutSegs
#[test]
fn mib_retransmit() {
    use crate::net::mib::*;
    let (mut p, m) = mib_pair();
    let segs = m.tcp.fold(TCP_MIB_OUTSEGS);
    p.filter = |_, to_b, s, _| {
        if to_b && !s.data.is_empty() {
            Fate::Drop
        } else {
            Fate::Pass
        }
    };
    p.send_a(b"lost");
    p.run();
    p.filter = pass;
    p.until(|p| p.b.rcvq_len() == 4, 10);
    // A tail loss probe repairs it before the RTO (Linux TLP)
    assert_eq!(m.net.fold(LINUX_MIB_TCPTIMEOUTS), 0);
    assert_eq!(m.net.fold(LINUX_MIB_TCPLOSSPROBES), 1);
    assert_eq!(m.tcp.fold(TCP_MIB_RETRANSSEGS), 1);
    // The data once, b's ACK of the retransmission
    assert_eq!(m.tcp.fold(TCP_MIB_OUTSEGS), segs + 2);
}

/// A refused connect is a failed attempt
#[test]
fn mib_refused() {
    use crate::net::mib::*;
    let m = crate::net::mib::NetMib::new().unwrap();
    let mut a = TcpCb::new(cfg(), Default::default());
    a.mib = Some(m.clone());
    let mut out = Out::default();
    a.connect(open(1000, 1460), 0, &mut out);
    let syn = wire(&out)[0].clone();
    let rst = SegIn {
        seq: 0,
        ack: syn.seq.wrapping_add(1),
        flags: flags::RST | flags::ACK,
        ..Default::default()
    };
    let mut out = Out::default();
    a.feed(&rst, 1, &mut out);
    assert_eq!(a.state, TcpState::Closed);
    assert_eq!(m.tcp.fold(TCP_MIB_ACTIVEOPENS), 1);
    assert_eq!(m.tcp.fold(TCP_MIB_ATTEMPTFAILS), 1);
    assert_eq!(m.tcp.fold(TCP_MIB_CURRESTAB), 0);
}

/// SACK is offered on the SYN and SYN-ACK when tcp_sack allows, and
/// used only when both did (Linux tcp_syn_options, tcp_parse_options)
#[test]
fn sack_negotiation() {
    let p = Pair::new(1460);
    assert!(p.log[0].2.sack_perm && p.log[1].2.sack_perm);
    assert!(p.a.sack_ok != 0 && p.b.sack_ok != 0);
    let off = Cfg {
        sack: false,
        ..cfg()
    };
    // Off at the passive end: no SACK_PERM on its SYN-ACK
    let p = Pair::with_cfgs(1460, 64 * 1024, cfg(), off);
    assert!(p.log[0].2.sack_perm && !p.log[1].2.sack_perm);
    assert!(p.a.sack_ok == 0 && p.b.sack_ok == 0);
    // Off at the active end: not offered, so not accepted
    let p = Pair::with_cfgs(1460, 64 * 1024, off, cfg());
    assert!(!p.log[0].2.sack_perm && !p.log[1].2.sack_perm);
    assert!(p.a.sack_ok == 0 && p.b.sack_ok == 0);
}

/// Segments queued for b, taken off the wire undelivered
fn take_to_b(p: &mut Pair) -> Vec<Seg> {
    let mut v = Vec::new();
    while let Some((to_b, s)) = p.wire.pop_front() {
        assert!(to_b);
        v.push(s);
    }
    v
}

/// Feed `s` to b; what b sends back
fn feed_b(p: &mut Pair, s: &Seg) -> Vec<Seg> {
    let mut out = Out::default();
    p.b.feed(&seg_in(s), p.now, &mut out);
    wire(&out)
}

/// Out-of-order data is reported newest block first, merged as holes
/// fill, three blocks beside the timestamp (Linux
/// tcp_sack_new_ofo_skb, tcp_sack_remove, tcp_established_options)
#[test]
fn sack_blocks_for_out_of_order_data() {
    let mut p = Pair::new(1000);
    let mss = p.a.live.mss.get();
    p.send_a(&pattern(10 * mss as usize));
    let segs = take_to_b(&mut p);
    assert_eq!(segs.len(), 10);
    let base = segs[0].seq;
    let blk = |i: u32, j: u32| (base + i * mss, base + j * mss);
    // 1, 3, 5, 7 lost: each arrival beyond a hole is SACKed at once
    let mut acks = Vec::new();
    for i in [0, 2, 4, 6, 8, 9] {
        acks.extend(feed_b(&mut p, &segs[i]));
    }
    let last = acks.last().unwrap();
    assert_eq!(last.ack, blk(1, 1).0);
    assert_eq!(last.sack.blocks(), &[blk(8, 10), blk(6, 7), blk(4, 5)]);
    // Filling hole 3 merges two blocks; the oldest reappears
    let a = feed_b(&mut p, &segs[3]);
    assert_eq!(a[0].sack.blocks(), &[blk(2, 5), blk(8, 10), blk(6, 7)]);
    // Filling hole 1 moves RCV.NXT past a block
    let a = feed_b(&mut p, &segs[1]);
    assert_eq!(a[0].ack, blk(5, 5).0);
    assert_eq!(a[0].sack.blocks(), &[blk(8, 10), blk(6, 7)]);
    feed_b(&mut p, &segs[5]);
    let a = feed_b(&mut p, &segs[7]);
    assert_eq!((a[0].ack, a[0].sack.n), (blk(10, 10).0, 0));
    // Without SACK no blocks
    let mut p = Pair::with_cfgs(
        1000,
        64 * 1024,
        Cfg {
            sack: false,
            ..cfg()
        },
        cfg(),
    );
    p.send_a(&pattern(3000));
    let segs = take_to_b(&mut p);
    let a = feed_b(&mut p, &segs[2]);
    assert_eq!(a[0].sack.n, 0);
}

/// A duplicate is reported once in a D-SACK block ahead of the SACK
/// blocks (Linux tcp_dsack_set, TCPDSACKOldSent / TCPDSACKOfoSent)
#[test]
fn dsack_reports_duplicates() {
    let mut p = Pair::new(1000);
    let mib = crate::net::mib::NetMib::new().unwrap();
    p.b.mib = Some(mib.clone());
    let mss = p.a.live.mss.get();
    p.send_a(&pattern(3 * mss as usize));
    let segs = take_to_b(&mut p);
    feed_b(&mut p, &segs[0]);
    // An old duplicate: D-SACK of it, nothing else
    let a = feed_b(&mut p, &segs[0]);
    assert_eq!(a[0].sack.blocks(), &[(segs[0].seq, segs[1].seq)]);
    // ... sent once
    let a = feed_b(&mut p, &segs[2]);
    let ofo = (segs[2].seq, segs[2].seq + mss);
    assert_eq!(a[0].sack.blocks(), &[ofo]);
    // An out-of-order duplicate: D-SACK first, then the block
    let a = feed_b(&mut p, &segs[2]);
    assert_eq!(a[0].sack.blocks(), &[ofo, ofo]);
    use crate::net::mib::*;
    assert_eq!(mib.net.fold(LINUX_MIB_TCPDSACKOLDSENT), 1);
    assert_eq!(mib.net.fold(LINUX_MIB_TCPDSACKOFOSENT), 1);
    // tcp_dsack=0: none
    let mut p = Pair::with_cfgs(
        1000,
        64 * 1024,
        cfg(),
        Cfg {
            dsack: false,
            ..cfg()
        },
    );
    p.send_a(&pattern(1000));
    let segs = take_to_b(&mut p);
    feed_b(&mut p, &segs[0]);
    assert_eq!(feed_b(&mut p, &segs[0])[0].sack.n, 0);
}

/// A pair without SACK, a's MIBs counted
fn reno_pair(mss: u32) -> (Pair, alloc::sync::Arc<crate::net::mib::NetMib>) {
    let off = Cfg {
        sack: false,
        ..cfg()
    };
    let mut p = Pair::with_cfgs(mss, 64 * 1024, off, off);
    let m = crate::net::mib::NetMib::new().unwrap();
    p.a.mib = Some(m.clone());
    (p, m)
}

/// Data segments a sent, by seq: how often each went out
fn sends(p: &Pair) -> alloc::collections::BTreeMap<u32, usize> {
    let mut m = alloc::collections::BTreeMap::new();
    for (_, to_b, s) in &p.log {
        if *to_b && !s.data.is_empty() {
            *m.entry(s.seq).or_insert(0) += 1;
        }
    }
    m
}

/// Without SACK, three duplicate ACKs mark the head lost (Linux
/// tcp_newreno_mark_lost): Recovery, one fast retransmission, the window
/// reduced by PRR and set to ssthresh when recovery ends
#[test]
fn reno_fast_recovery_as_linux() {
    use super::recovery::CaState;
    use crate::net::mib::*;
    let (mut p, m) = reno_pair(1000);
    p.filter = |_, to_b, s, _| {
        static DROPPED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
        let third = s.seq == 1001 + 2 * 988;
        if to_b && third && !DROPPED.swap(true, core::sync::atomic::Ordering::Relaxed) {
            Fate::Drop
        } else {
            Fate::Pass
        }
    };
    p.a.cong.set_cwnd(20);
    p.send_a(&pattern(10 * 988));
    let t = p.now;
    p.run();
    assert_eq!(p.now, t, "no timeout");
    assert_eq!(p.b.rcvq_len(), 10 * 988);
    assert_eq!(m.net.fold(LINUX_MIB_TCPRENORECOVERY), 1);
    assert_eq!(m.net.fold(LINUX_MIB_TCPFASTRETRANS), 1);
    assert_eq!(m.tcp.fold(TCP_MIB_RETRANSSEGS), 1);
    assert_eq!(m.net.fold(LINUX_MIB_TCPTIMEOUTS), 0);
    let s = sends(&p);
    assert_eq!(s.values().filter(|&&n| n > 1).count(), 1);
    assert_eq!(s[&(1001 + 2 * 988)], 2);
    // Reno holds Recovery until data above high_seq is acked (RFC
    // 6582, Linux tcp_is_non_sack_preventing_reopen)
    assert_eq!(p.a.ca_state, CaState::Recovery);
    p.send_a(&pattern(988));
    p.run();
    assert_eq!(p.a.ca_state, CaState::Open);
    assert_eq!(
        (
            p.a.packets_out,
            p.a.sacked_out,
            p.a.lost_out,
            p.a.retrans_out
        ),
        (0, 0, 0, 0)
    );
    // ssthresh: half the window of 20 at the third duplicate (Linux
    // tcp_reno_ssthresh); recovery ends at it
    assert_eq!(p.a.cong.snd_ssthresh(), 10);
    assert_eq!(p.a.cong.snd_cwnd(), 10);
}

/// A timeout marks the flight lost and slow-starts from one packet
/// (Linux tcp_enter_loss, CA_Loss, TCPSlowStartRetrans)
#[test]
fn rto_enters_loss_as_linux() {
    use super::recovery::CaState;
    use crate::net::mib::*;
    let (mut p, m) = reno_pair(1000);
    p.filter = drop_all;
    p.send_a(&pattern(6 * 988));
    p.run();
    assert_eq!(p.a.packets_out, 6);
    p.filter = |_, to_b, _, _| if to_b { Fate::Drop } else { Fate::Pass };
    assert!(p.tick());
    assert_eq!(p.a.ca_state, CaState::Loss);
    assert_eq!((p.a.lost_out, p.a.retrans_out), (6, 1));
    assert_eq!(p.a.cong.snd_cwnd(), 1);
    p.wire.clear();
    p.filter = pass;
    assert!(p.until(|p| p.b.rcvq_len() == 6 * 988, 20));
    assert_eq!(m.net.fold(LINUX_MIB_TCPTIMEOUTS), 2);
    assert_eq!(m.net.fold(LINUX_MIB_TCPSLOWSTARTRETRANS), 5);
    assert_eq!(p.a.ca_state, CaState::Loss);
    p.send_a(&pattern(988));
    p.run();
    assert_eq!(p.a.ca_state, CaState::Open);
    assert_eq!((p.a.packets_out, p.a.lost_out, p.a.retrans_out), (0, 0, 0));
}

/// A pair with SACK, a's MIBs counted
fn sack_pair(mss: u32) -> (Pair, alloc::sync::Arc<crate::net::mib::NetMib>) {
    let mut p = Pair::new(mss);
    let m = crate::net::mib::NetMib::new().unwrap();
    p.a.mib = Some(m.clone());
    (p, m)
}

/// Drop the first transmission of data at the seqs listed in `DROP`
/// (a filter's state lives in a static: filters are fn pointers; one
/// test uses it)
fn drop_listed(_: &Pair, to_b: bool, s: &Seg, _: usize) -> Fate {
    use core::sync::atomic::Ordering::Relaxed;
    if !to_b || s.data.is_empty() {
        return Fate::Pass;
    }
    for d in DROP.iter() {
        if d.load(Relaxed) == s.seq {
            d.store(0, Relaxed);
            return Fate::Drop;
        }
    }
    Fate::Pass
}

static DROP: [core::sync::atomic::AtomicU32; 3] =
    [const { core::sync::atomic::AtomicU32::new(0) }; 3];

/// Losses in a window are found by SACK and RACK and repaired by fast
/// retransmissions of just the lost segments, no timeout (Linux
/// tcp_sacktag_write_queue, tcp_rack_mark_lost, tcp_enter_recovery,
/// tcp_xmit_retransmit_queue)
#[test]
fn sack_recovers_lost_segments_only() {
    use super::recovery::CaState;
    use crate::net::mib::*;
    use core::sync::atomic::Ordering::Relaxed;
    let (mut p, m) = sack_pair(1000);
    let mss = p.a.live.mss.get();
    let base = p.a.snd_nxt;
    for (d, i) in DROP.iter().zip([2u32, 5, 6]) {
        d.store(base + i * mss, Relaxed);
    }
    p.filter = drop_listed;
    p.a.cong.set_cwnd(20);
    p.send_a(&pattern(12 * mss as usize));
    let t = p.now;
    p.run();
    assert_eq!(p.now, t, "no timeout");
    assert_eq!(p.b.rcvq_len(), 12 * mss as usize);
    let s = sends(&p);
    let again: Vec<u32> = s.iter().filter(|(_, n)| **n > 1).map(|(k, _)| *k).collect();
    assert_eq!(again, [base + 2 * mss, base + 5 * mss, base + 6 * mss]);
    assert!(s.values().all(|&n| n <= 2));
    assert_eq!(m.net.fold(LINUX_MIB_TCPSACKRECOVERY), 1);
    assert_eq!(m.net.fold(LINUX_MIB_TCPRENORECOVERY), 0);
    assert_eq!(m.net.fold(LINUX_MIB_TCPFASTRETRANS), 3);
    assert_eq!(m.net.fold(LINUX_MIB_TCPTIMEOUTS), 0);
    // SACK recovery ends as soon as high_seq is acked
    assert_eq!(p.a.ca_state, CaState::Open);
    assert_eq!(
        (
            p.a.packets_out,
            p.a.sacked_out,
            p.a.lost_out,
            p.a.retrans_out
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(p.a.cong.snd_cwnd(), p.a.cong.snd_ssthresh());
}

/// A reordered segment looks lost (no reordering seen yet: no RACK
/// window); its spurious retransmission comes back D-SACKed after the
/// cumulative ACK forgot it, and the reduction is undone (Linux
/// tcp_check_dsack's "dumb counting" of undo_retrans,
/// tcp_try_undo_dsack). The reordering itself is not seen: on the
/// test's frozen clock the original and the retransmission share one
/// timestamp (Linux tcp_try_undo_partial needs an earlier echo)
#[test]
fn dsack_undoes_spurious_retransmission() {
    use crate::net::mib::*;
    let (mut p, m) = sack_pair(1000);
    fn delay_third(_: &Pair, to_b: bool, s: &Seg, _: usize) -> Fate {
        static ONCE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
        if to_b
            && !s.data.is_empty()
            && s.data[0] == pattern(3000)[2 * 988]
            && !ONCE.swap(true, core::sync::atomic::Ordering::Relaxed)
        {
            Fate::Delay
        } else {
            Fate::Pass
        }
    }
    p.filter = delay_third;
    p.a.cong.set_cwnd(20);
    let data = pattern(10 * 988);
    p.send_a(&data);
    p.run();
    assert_eq!(p.b.rcvq_len(), data.len());
    assert!(m.net.fold(LINUX_MIB_TCPDSACKRECV) >= 1);
    assert!(p.a.dsack_dups >= 1);
    assert!(p.a.sack_ok & super::cb::DSACK_SEEN != 0);
    assert_eq!(m.net.fold(LINUX_MIB_TCPDSACKUNDO), 1);
    assert_eq!(m.net.fold(LINUX_MIB_TCPTIMEOUTS), 0);
}

/// A hole filled by its original, not the retransmission (the echo
/// predates the retransmission): reordering of the distance to the
/// highest SACK (Linux tcp_try_undo_partial -> tcp_check_sack_reordering,
/// TCPTSReorder)
#[test]
fn reordering_seen_by_timestamps() {
    use crate::net::mib::*;
    let (mut p, m) = sack_pair(1000);
    p.a.cong.set_cwnd(20);
    p.send_a(&pattern(8 * 988));
    let segs = take_to_b(&mut p);
    p.now = 100;
    // 3 is late, 7 lost; b SACKs 4..7
    let mut acks = Vec::new();
    for i in [0, 1, 2, 4, 5, 6] {
        acks.extend(feed_b(&mut p, &segs[i]));
    }
    for a in &acks {
        p.a.feed(&seg_in(a), p.now, &mut Out::default());
    }
    assert_eq!(p.a.ca_state, super::recovery::CaState::Recovery);
    assert_eq!(p.a.retrans_out, 1);
    assert_eq!(p.a.reordering, 3);
    // The original 3 arrives: a partial ACK echoing its old TSval
    let ack = feed_b(&mut p, &segs[3]);
    p.a.feed(&seg_in(&ack[0]), p.now, &mut Out::default());
    assert_eq!(p.a.reordering, 4);
    assert_eq!(p.a.reord_seen, 1);
    assert_eq!(m.net.fold(LINUX_MIB_TCPTSREORDER), 1);
}

/// SACKed small segments join the SACKed skb before them when its
/// buffer has room (Linux tcp_shift_skb_data / tcp_shifted_skb:
/// SACKMerged; the first one has no SACKed skb before it:
/// SACKShiftFallback), and the counts stay right through recovery
#[test]
fn sacked_skbs_merge() {
    use crate::net::mib::*;
    let (mut p, m) = sack_pair(1000);
    p.a.opts.nodelay = true;
    let mut segs = Vec::new();
    for i in 0..6u8 {
        p.send_a(&[i; 100]);
        segs.extend(take_to_b(&mut p));
    }
    assert_eq!((segs.len(), p.a.packets_out, p.a.rtx.len()), (6, 6, 6));
    let mut acks = Vec::new();
    for s in &segs[1..] {
        acks.extend(feed_b(&mut p, s));
    }
    let mut out = Out::default();
    for a in &acks {
        p.a.feed(&seg_in(a), p.now, &mut out);
    }
    assert_eq!(m.net.fold(LINUX_MIB_SACKSHIFTFALLBACK), 1);
    assert_eq!(m.net.fold(LINUX_MIB_SACKMERGED), 4);
    // One SACKed skb of five segments behind the lost one, the
    // truesize moved with the data (Linux skb_shift)
    assert_eq!(p.a.rtx.len(), 2);
    assert_eq!(p.a.wmem_queued, queued_truesize(&p.a));
    assert_eq!((p.a.packets_out, p.a.sacked_out), (6, 5));
    // The lost one went again; its ACK clears everything
    let w = wire(&out);
    assert_eq!(w.last().unwrap().seq, segs[0].seq);
    let ack = feed_b(&mut p, &segs[0]);
    p.a.feed(&seg_in(&ack[0]), p.now, &mut Out::default());
    assert_eq!(
        (
            p.a.packets_out,
            p.a.sacked_out,
            p.a.lost_out,
            p.a.retrans_out
        ),
        (0, 0, 0, 0)
    );
    assert!(p.a.rtx.is_empty());
    assert_eq!(p.a.wmem_queued, 0);
}

/// Small skbs lost together are merged as the head is retransmitted
/// (Linux tcp_retrans_try_collapse): the data take their truesize
/// along (skb_shift), the merged skbs' heads leave the queue
#[test]
fn retrans_collapse_moves_truesize() {
    let mut p = Pair::new(1000);
    p.a.opts.nodelay = true;
    p.filter = |_, to_b, s, _| {
        if to_b && !s.data.is_empty() {
            Fate::Drop
        } else {
            Fate::Pass
        }
    };
    for i in 0..3u8 {
        p.send_a(&[i; 100]);
    }
    assert_eq!(p.a.rtx.len(), 3);
    assert_eq!(p.a.wmem_queued, 3 * (HEAD_TRUESIZE + 100));
    // The loss probe, then the RTO
    for _ in 0..2 {
        let t = p.a.next_timer().expect("armed");
        p.now = t;
        let mut out = Out::default();
        p.a.on_timer(t, &mut out);
        assert_eq!(p.a.wmem_queued, queued_truesize(&p.a));
    }
    assert_eq!(p.a.rtx.len(), 1);
    assert_eq!(p.a.wmem_queued, HEAD_TRUESIZE + 300);
}

/// A lost tail has nothing after it to be SACKed: the loss probe
/// resends the last segment after 2 RTT and repairs it without a
/// timeout; an ACK beyond the probe's episode then reduces the window
/// once (Linux tcp_schedule_loss_probe, tcp_send_loss_probe,
/// tcp_process_tlp_ack: TCPLossProbes, TCPLossProbeRecovery)
#[test]
fn tail_loss_probe_repairs_lost_tail() {
    use super::recovery::CaState;
    use crate::net::mib::*;
    use core::sync::atomic::Ordering::Relaxed;
    static TAIL: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    fn drop_tail(_: &Pair, to_b: bool, s: &Seg, _: usize) -> Fate {
        if to_b && !s.data.is_empty() && TAIL.compare_exchange(s.seq, 0, Relaxed, Relaxed).is_ok() {
            Fate::Drop
        } else {
            Fate::Pass
        }
    }
    let (mut p, m) = sack_pair(1000);
    let mss = p.a.live.mss.get();
    TAIL.store(p.a.snd_nxt + 4 * mss, Relaxed);
    p.filter = drop_tail;
    p.send_a(&pattern(5 * mss as usize));
    p.run();
    assert_eq!(p.b.rcvq_len(), 4 * mss as usize);
    assert!(matches!(
        p.a.live.tmr.get(),
        Some((super::cb::Tmr::LossProbe, _))
    ));
    assert!(p.tick());
    p.run();
    assert_eq!(p.b.rcvq_len(), 5 * mss as usize);
    assert_eq!(m.net.fold(LINUX_MIB_TCPLOSSPROBES), 1);
    assert_eq!(m.net.fold(LINUX_MIB_TCPTIMEOUTS), 0);
    assert_eq!(p.a.tlp_high_seq, Some(p.a.snd_max));
    let cwnd = p.a.cong.snd_cwnd();
    p.send_a(&pattern(mss as usize));
    p.run();
    assert_eq!(m.net.fold(LINUX_MIB_TCPLOSSPROBERECOVERY), 1);
    assert_eq!(p.a.tlp_high_seq, None);
    assert!(p.a.cong.snd_cwnd() < cwnd);
    assert_ne!(p.a.ca_state, CaState::Loss);
}

/// A segment not yet past RTT + the reordering window waits on the
/// RACK reordering timer, which then marks it lost and starts recovery
/// (Linux tcp_rack_mark_lost, ICSK_TIME_REO_TIMEOUT,
/// tcp_rack_reo_timeout)
#[test]
fn rack_reordering_timer_marks_loss() {
    use super::cb::Tmr;
    use super::recovery::CaState;
    use crate::net::mib::*;
    let (mut p, m) = sack_pair(1000);
    // A 100 ms path: reordering window min_rtt/4 = 25 ms
    p.a.rtt_min.reset(0, 100_000);
    p.a.srtt_us = 100_000 << 3;
    p.now = 1000;
    p.a.cong.set_cwnd(20);
    p.send_a(&pattern(4 * 988));
    let segs = take_to_b(&mut p);
    p.now = 1100;
    let acks = feed_b(&mut p, &segs[1]);
    let mut out = Out::default();
    p.a.feed(&seg_in(&acks[0]), p.now, &mut out);
    assert!(wire(&out).is_empty());
    assert_eq!(p.a.live.tmr.get(), Some((Tmr::Reo, 1100 + 25 + 2)));
    assert_eq!(p.a.ca_state, CaState::Disorder);
    p.now = 1127;
    let mut out = Out::default();
    p.a.on_timer(p.now, &mut out);
    let w = wire(&out);
    assert_eq!(w.len(), 1);
    assert_eq!(w[0].seq, segs[0].seq);
    assert_eq!(p.a.ca_state, CaState::Recovery);
    assert_eq!(m.net.fold(LINUX_MIB_TCPSACKRECOVERY), 1);
    assert!(matches!(p.a.live.tmr.get(), Some((Tmr::Rtx, _))));
}

/// A pair without SACK (RACK needs a real RTT, which the simulated
/// wire lacks), timestamps off (`ts` 0) or on, MIBs counted at a
fn frto_pair(ts: u8) -> (Pair, alloc::sync::Arc<crate::net::mib::NetMib>) {
    let c = Cfg {
        ts,
        sack: false,
        ..cfg()
    };
    let mut p = Pair::with_cfgs(1000, 64 * 1024, c, c);
    let m = crate::net::mib::NetMib::new().unwrap();
    p.a.mib = Some(m.clone());
    (p, m)
}

/// A spurious timeout: b's ACKs for a window are held past the RTO,
/// then arrive after the resend of the head
fn spurious_rto(p: &mut Pair) {
    for s in held_acks(p) {
        let mut out = Out::default();
        p.a.feed(&seg_in(&s), p.now, &mut out);
        p.take(true, out);
    }
}

/// `spurious_rto` up to the ACKs it holds back
fn held_acks(p: &mut Pair) -> Vec<Seg> {
    p.filter = |_, to_b, _, _| if to_b { Fate::Pass } else { Fate::Drop };
    let n = p.log.len();
    p.send_a(&pattern(20 * 988));
    p.run();
    let held: Vec<Seg> = p.log[n..]
        .iter()
        .filter(|(_, to_b, _)| !*to_b)
        .map(|(_, _, s)| s.clone())
        .collect();
    assert!(!held.is_empty());
    // The loss probe, then the RTO resends the head only (cwnd 1,
    // CA_Loss)
    p.filter = |_, to_b, _, _| if to_b { Fate::Drop } else { Fate::Pass };
    for _ in 0..3 {
        if p.a.ca_state == super::recovery::CaState::Loss {
            break;
        }
        assert!(p.tick());
    }
    assert_eq!(p.a.ca_state, super::recovery::CaState::Loss);
    assert_eq!(p.a.cong.snd_cwnd(), 1);
    p.filter = pass;
    held
}

/// With timestamps the first ACK of the originals echoes a TSval from
/// before the resend (retrans_stamp): the timeout is undone at once
/// (Linux tcp_try_undo_loss via tcp_packet_delayed, RFC 3522)
#[test]
fn eifel_undoes_spurious_timeout() {
    use crate::net::mib::*;
    let (mut p, m) = frto_pair(1);
    let held = held_acks(&mut p);
    let mut out = Out::default();
    p.a.feed(&seg_in(&held[0]), p.now, &mut out);
    p.take(true, out);
    assert_eq!(m.net.fold(LINUX_MIB_TCPLOSSUNDO), 1);
    assert_eq!(m.net.fold(LINUX_MIB_TCPSPURIOUSRTOS), 0);
    assert!(p.a.cong.snd_cwnd() >= 10);
    assert_eq!(p.a.cong.snd_ssthresh(), super::cong::INFINITE_SSTHRESH);
}

/// Linux tcp_model_timeout's values (ms)
#[test]
fn model_timeout_values() {
    use super::timer::model_timeout;
    assert_eq!(model_timeout(2, 1000), 7 * 1000);
    assert_eq!(model_timeout(9, 200), 1023 * 200);
    assert_eq!(model_timeout(10, 200), 1023 * 200 + RTO_MAX);
    assert_eq!(model_timeout(15, 200), 1023 * 200 + 6 * RTO_MAX);
    // tcp_orphan_retries' 8
    assert_eq!(model_timeout(8, 200), 511 * 200);
}

/// F-RTO (RFC 5682): ACKs of never retransmitted data after a timeout
/// show it spurious: undone, TCPSpuriousRTOs (Linux tcp_process_loss
/// step 3.b, tcp_try_undo_loss)
#[test]
fn frto_undoes_spurious_timeout() {
    use crate::net::mib::*;
    let (mut p, m) = frto_pair(0);
    spurious_rto(&mut p);
    assert_eq!(m.net.fold(LINUX_MIB_TCPSPURIOUSRTOS), 1);
    assert_eq!(m.net.fold(LINUX_MIB_TCPLOSSUNDO), 1);
    assert_eq!(p.a.ca_state, super::recovery::CaState::Open);
    assert!(p.a.cong.snd_cwnd() >= 10);
    assert_eq!(p.a.cong.snd_ssthresh(), super::cong::INFINITE_SSTHRESH);
    p.run();
    assert_eq!(p.b.rcvq_len(), 20 * 988);
}

/// tcp_frto 0: the timeout stands
#[test]
fn frto_off_keeps_the_reduction() {
    use crate::net::mib::*;
    let (mut p, m) = frto_pair(0);
    p.a.cfg.frto = 0;
    spurious_rto(&mut p);
    assert_eq!(m.net.fold(LINUX_MIB_TCPSPURIOUSRTOS), 0);
    assert_eq!(m.net.fold(LINUX_MIB_TCPLOSSUNDO), 0);
    assert!(p.a.cong.snd_ssthresh() < super::cong::INFINITE_SSTHRESH);
}

/// An active open whose SYN timed out `n` times, then answered
fn syn_timeouts(n: usize) -> TcpCb {
    let mut p = Pair::bare();
    p.filter = drop_all;
    let mut out = Out::default();
    p.a.connect(open(1, 1460), 0, &mut out);
    p.take(true, out);
    for _ in 0..n {
        assert!(p.tick());
    }
    let synack = SegIn {
        seq: 5000,
        ack: 2,
        flags: flags::SYN | flags::ACK,
        wnd: 65535,
        mss: Some(1460),
        ..Default::default()
    };
    let mut out = Out::default();
    p.a.feed(&synack, p.now, &mut out);
    assert_eq!(p.a.state, TcpState::Established);
    p.a
}

/// A SYN timeout enters CA_Loss (Linux tcp_retransmit_timer's
/// tcp_enter_loss): ssthresh from the algorithm (reno here, the
/// options' default: half of 10), and after more than one SYN retransmission the transfer
/// starts from one packet (tcp_init_transfer)
#[test]
fn syn_timeouts_enter_loss() {
    use super::recovery::CaState;
    let a = syn_timeouts(2);
    assert_eq!(a.stats.total_retrans, 2);
    assert!(a.undo_marker.is_some());
    assert_eq!(a.cong.snd_ssthresh(), 5);
    assert_eq!(a.cong.snd_cwnd(), 1);
    // Without SACK, CA_Loss holds until data above the SYN is acked
    assert_eq!(a.ca_state, CaState::Loss);
    let a = syn_timeouts(1);
    assert_eq!(a.cong.snd_cwnd(), super::cong::INIT_CWND);
    let a = syn_timeouts(0);
    assert_eq!(a.ca_state, CaState::Open);
    assert!(a.cong.in_initial_slowstart());
}

/// The minimum RTT is windowed (Linux tcp_update_rtt_min over
/// tcp_min_rtt_wlen with lib/win_minmax.c); a suspected delayed ACK's
/// longer RTT is skipped
#[test]
fn min_rtt_windowed() {
    use super::recovery::flag;
    let mut a = TcpCb::new(
        Cfg {
            min_rtt_wlen: 1,
            ..cfg()
        },
        Default::default(),
    );
    assert_eq!(a.min_rtt(), u64::from(u32::MAX));
    a.tick(0);
    a.update_rtt_min(100_000, 0);
    a.tick(500);
    a.update_rtt_min(200_000, 0);
    assert_eq!(a.min_rtt(), 100_000);
    a.update_rtt_min(150_000, flag::ACK_MAYBE_DELAYED);
    a.tick(1500);
    a.update_rtt_min(300_000, 0);
    // The 1 s window passed: the second choice, from its second quarter
    assert_eq!(a.min_rtt(), 200_000);
    a.update_rtt_min(0, 0);
    assert_eq!(a.min_rtt(), 1000);
}

/// Linux tcp_rtt_estimator / tcp_set_rto, step by step (us)
#[test]
fn rtt_estimator_as_linux() {
    let mut a = TcpCb::new(cfg(), Default::default());
    a.snd_una = 0;
    a.snd_nxt = 1000;
    // First: srtt 8m, mdev 2m, rttvar max(mdev, TCP_RTO_MIN)
    a.rtt_estimator(100_000);
    a.set_rto();
    assert_eq!(
        (a.srtt_us, a.mdev_us, a.mdev_max_us, a.rttvar_us),
        (800_000, 200_000, 200_000, 200_000)
    );
    assert_eq!((a.rtt_seq, a.live.rto.get()), (1000, 300));
    // Falling: the error less mdev / 4 is 0, so mdev holds
    a.rtt_estimator(50_000);
    a.set_rto();
    assert_eq!(
        (a.srtt_us, a.mdev_us, a.rttvar_us),
        (750_000, 200_000, 200_000)
    );
    assert_eq!(a.live.rto.get(), 294);
    // Rising past the round's end: rttvar follows the new maximum, the
    // round restarts at TCP_RTO_MIN
    a.snd_una = 1001;
    a.snd_nxt = 2000;
    a.rtt_estimator(200_000);
    a.set_rto();
    assert_eq!(
        (a.srtt_us, a.mdev_us, a.rttvar_us),
        (856_250, 256_250, 256_250)
    );
    assert_eq!(
        (a.mdev_max_us, a.rtt_seq, a.live.rto.get()),
        (200_000, 2000, 364)
    );
}

/// Linux tcp_orphan_retries with net.ipv4.tcp_orphan_retries
#[test]
fn orphan_retries_sysctl() {
    let mut a = TcpCb::new(cfg(), Default::default());
    // 0 (the default): 8 while the RTO is below its maximum, else none
    assert_eq!((a.orphan_retries(true), a.orphan_retries(false)), (8, 0));
    a.cfg.orphan_retries = 3;
    assert_eq!((a.orphan_retries(true), a.orphan_retries(false)), (3, 3));
    // An ICMP error and the RTO at its maximum: none
    a.soft_err = Some(KernelError::HostUnreachable);
    assert_eq!((a.orphan_retries(true), a.orphan_retries(false)), (3, 0));
}

/// A loss probe with the congestion window full still sends one new
/// segment (Linux tcp_write_xmit with push_one 2: cwnd_quota 1)
#[test]
fn loss_probe_ignores_full_cwnd() {
    use crate::net::mib::*;
    let (mut p, m) = sack_pair(1000);
    let mss = p.a.live.mss.get();
    p.a.cong.set_cwnd(2);
    p.filter = drop_all;
    let una = p.a.snd_nxt;
    p.send_a(&pattern(4 * mss as usize));
    p.run();
    assert_eq!(p.a.packets_out, 2);
    assert!(matches!(
        p.a.live.tmr.get(),
        Some((super::cb::Tmr::LossProbe, _))
    ));
    let n = p.log.len();
    assert!(p.tick());
    let sent: Vec<u32> = p.log[n..]
        .iter()
        .filter(|l| l.1 && !l.2.data.is_empty())
        .map(|l| l.2.seq)
        .collect();
    assert_eq!(sent, [una + 2 * mss]);
    assert_eq!(p.a.packets_out, 3);
    assert!(!p.a.tlp_retrans);
    assert_eq!(p.a.tlp_high_seq, Some(p.a.snd_max));
    assert_eq!(m.net.fold(LINUX_MIB_TCPLOSSPROBES), 1);
}

/// The flight filling the congestion window after a transmit pass is
/// cwnd-limited, whether or not the pass sent anything (Linux
/// tcp_write_xmit: is_cwnd_limited |= in_flight >= cwnd, then
/// tcp_cwnd_validate on sent_pkts || is_cwnd_limited)
#[test]
fn full_flight_is_cwnd_limited() {
    let mut p = Pair::new(1000);
    let mss = p.a.live.mss.get() as usize;
    p.a.cong.set_cwnd(2);
    p.a.cong.set_ssthresh(2);
    p.filter = drop_all;
    // Exactly the window: nothing left queued, yet the window is full
    p.send_a(&pattern(2 * mss));
    assert_eq!(p.a.packets_out, 2);
    assert!(p.a.cong.cwnd_limited());
    // A pass that sends nothing still records it
    let mut q = Pair::new(1000);
    q.a.cong.set_cwnd(2);
    q.a.cong.set_ssthresh(2);
    q.filter = drop_all;
    q.send_a(&pattern(mss));
    assert!(!q.a.cong.cwnd_limited());
    q.a.cong.set_cwnd(1);
    q.a.cong.set_ssthresh(1);
    q.send_a(&pattern(mss));
    assert_eq!(q.a.packets_out, 1);
    assert!(q.a.cong.cwnd_limited());
}

/// An old ACK (below SND.UNA, no SACK blocks) still updates TS.Recent,
/// though not the window (Linux tcp_ack old_ack: tcp_replace_ts_recent
/// before the SACK check)
#[test]
fn old_ack_updates_ts_recent() {
    let mut p = Pair::new(1000);
    p.send_a(&pattern(5000));
    p.run();
    let wnd = p.a.snd_wnd;
    let tsv = p.a.ts_recent.wrapping_add(7);
    let old = SegIn {
        seq: p.a.rcv_nxt,
        ack: p.a.snd_una.wrapping_sub(500),
        flags: flags::ACK,
        wnd: 0,
        ts: Some((tsv, 0)),
        ..Default::default()
    };
    p.a.feed(&old, p.now, &mut Out::default());
    assert_eq!(p.a.ts_recent, tsv);
    assert_eq!(p.a.snd_wnd, wnd);
}

/// A duplicate ACK at SND.WL1 may only grow the window or close it
/// (Linux tcp_may_update_window: seq == wl1 needs nwin > snd_wnd or
/// nwin == 0); a smaller nonzero window there is ignored
#[test]
fn dup_ack_does_not_shrink_window() {
    let mut p = Pair::new(1000);
    p.send_a(&pattern(5000));
    p.run();
    let wnd = p.a.snd_wnd;
    assert!(wnd > 1 << p.a.snd_wscale);
    let dup = SegIn {
        seq: p.a.rcv_nxt,
        ack: p.a.snd_una,
        flags: flags::ACK,
        wnd: 1,
        ts: Some((p.a.ts_recent.wrapping_add(1), 0)),
        ..Default::default()
    };
    p.a.feed(&dup, p.now, &mut Out::default());
    assert_eq!(p.a.snd_wnd, wnd);
    // A zero window at WL1 is taken
    let zero = SegIn { wnd: 0, ..dup };
    p.a.feed(&zero, p.now, &mut Out::default());
    assert_eq!(p.a.snd_wnd, 0);
}

/// Any acceptable ACK, even a duplicate, clears the soft error (Linux
/// tcp_ack: sk_err_soft = 0); an old one does not
#[test]
fn ack_clears_soft_error() {
    let mut p = Pair::new(1000);
    p.send_a(&pattern(3000));
    p.run();
    let dup = SegIn {
        seq: p.a.rcv_nxt,
        ack: p.a.snd_una,
        flags: flags::ACK,
        wnd: (p.a.snd_wnd >> p.a.snd_wscale) as u16,
        ts: Some((p.a.ts_recent, 0)),
        ..Default::default()
    };
    let old = SegIn {
        ack: p.a.snd_una.wrapping_sub(500),
        ..dup
    };
    p.a.soft_err = Some(KernelError::HostUnreachable);
    p.a.feed(&old, p.now, &mut Out::default());
    assert_eq!(p.a.soft_err, Some(KernelError::HostUnreachable));
    p.a.feed(&dup, p.now, &mut Out::default());
    assert_eq!(p.a.soft_err, None);
}

/// A retransmission is data sent too (Linux __tcp_transmit_skb ->
/// tcp_event_data_sent): lsndtime follows it
#[test]
fn retransmission_is_data_sent() {
    let mut p = Pair::new(1000);
    p.filter = drop_all;
    p.now = 100;
    p.send_a(&pattern(2000));
    assert_eq!(p.a.lsndtime, 100);
    assert!(p.tick());
    assert!(p.now > 100);
    assert!(p.a.stats.total_retrans > 0 || p.a.tlp_high_seq.is_some());
    assert_eq!(p.a.lsndtime, p.now);
}

/// The handshake delivers one packet each way (Linux: the SYN acked
/// in tcp_clean_rtx_queue, the SYN-ACK in tcp_rcv_state_process
/// SYN_RECV), then every data packet acked counts (tp->delivered, as
/// tcpi_delivered reports it)
#[test]
fn delivered_counts_packets() {
    let mut p = Pair::new(1000);
    assert_eq!((p.a.delivered, p.b.delivered), (1, 1));
    let mss = p.a.live.mss.get() as usize;
    let data = pattern(3 * mss);
    assert_eq!(transfer(&mut p, &data, 100), data);
    assert_eq!(p.a.delivered, 4);
}

/// What is left of the RTO becomes timer ms rounded up (Linux
/// tcp_rearm_rto / tcp_schedule_loss_probe: usecs_to_jiffies)
#[test]
fn rto_delta_rounds_up() {
    use super::cb::Tmr;
    let (mut p, _) = sack_pair(1000);
    p.filter = drop_all;
    p.now = 100;
    p.send_a(&pattern(2000));
    let head = p.a.rtx.first().map(super::cb::skb_mstamp_us).unwrap();
    let rto = p.a.rto_cur();
    // Half a ms after the head went out
    p.a.tcp_mstamp = head + 500;
    p.a.live.tmr.set(Some((Tmr::LossProbe, 0)));
    p.a.rearm_rto(100);
    assert_eq!(p.a.live.tmr.get(), Some((Tmr::Rtx, 100 + rto)));
    // A probe due after the RTO is pulled in to it
    p.a.srtt_us = 8 * 1_000_000;
    assert!(p.a.schedule_loss_probe(100, false));
    assert_eq!(p.a.live.tmr.get(), Some((Tmr::LossProbe, 100 + rto)));
}

/// A simultaneous open delivers two packets each way (Linux: our SYN,
/// still on the retransmit queue, acked in tcp_ack's
/// tcp_clean_rtx_queue, TCPDelivered; then tcp_rcv_state_process
/// SYN_RECV's SYN-ACK delivery, not in the MIB)
#[test]
fn simultaneous_open_delivered() {
    use crate::net::mib::*;
    let mut p = crossed_syns();
    let m = crate::net::mib::NetMib::new().unwrap();
    p.a.mib = Some(m.clone());
    p.run();
    assert_eq!(p.a.state, TcpState::Established);
    assert_eq!(p.b.state, TcpState::Established);
    assert_eq!((p.a.delivered, p.b.delivered), (2, 2));
    assert_eq!(m.net.fold(LINUX_MIB_TCPDELIVERED), 1);
}
