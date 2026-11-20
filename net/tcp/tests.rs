//! Deterministic tests of the I/O-free control block: two control
//! blocks over a simulated network with a virtual clock, where a filter
//! may drop, duplicate or reorder segments.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::cb::{
    Cfg, MSS_DEFAULT, Open, Out, RCV_SHUTDOWN, RTO_MAX, TIMEWAIT_LEN, TcpCb, TcpState, flags, wake,
};
use super::timewait::{TwCb, TwStatus};
use crate::mm::page_alloc::Gfp;
use crate::net::skb::{Sacks, SkBuff};
use crate::util::error::KernelError;

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
    /// Its header (Linux TCP_SKB_CB) and an skb holding its payload
    fn skb(&self) -> Box<SkBuff> {
        let mut skb = SkBuff::alloc_tx(self.data.len(), Gfp::KERNEL).unwrap();
        skb.put_slice(self.data).unwrap();
        skb.set_tcp(super::cb::Seg {
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
        });
        skb.tcp_mut().set_len(self.data.len() as u32);
        skb
    }

    fn hdr(&self) -> super::cb::Seg {
        self.skb().tcp()
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
        let skb = s.skb();
        let h = skb.tcp();
        self.input(&h, skb, now, out);
        if let Some(skb) = out.req_ack.take() {
            self.req_full = true;
            let h = skb.tcp();
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
        .map(|skb| Seg {
            seq: skb.tcp().seq,
            ack: skb.tcp().ack,
            flags: skb.tcp().flags,
            wnd: skb.tcp().wnd,
            mss: skb.tcp().mss,
            ws: skb.tcp().ws,
            ts: skb.tcp().ts,
            sack_perm: skb.tcp().sack_perm,
            sack: skb.tcp().sack,
            data: skb.data().to_vec(),
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
    b.rcv_cap = cap;
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
        p.b.rcv_cap = cap;
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
    // RTT 0 measured in the handshake: RTO = 200 ms (RTO_MIN), doubling
    // up to 120 s; retries2 = 15 retransmissions
    assert_eq!(times.len(), 16);
    let gaps: Vec<u64> = times.windows(2).map(|w| w[1] - w[0]).collect();
    assert_eq!(&gaps[..6], &[200, 400, 800, 1600, 3200, 6400]);
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
    assert!(srtt > 0 && srtt <= 100, "srtt {}", srtt);
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
    // never past the buffer (twice that)
    assert!((4000..=8000).contains(&p.b.rcvq_len()));
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
    let mut p = Pair::with_cap(1000, 3000);
    let data = pattern(3000);
    p.send_a(&data);
    p.run();
    let rest = pattern(5000);
    p.send_a(&rest);
    p.run();
    p.filter = drop_window_updates;
    let first = p.read_b(10_000);
    p.run();
    // The update was lost; the persist timer finds the open window
    let ok = p.until(|p| p.b.rcvq_len() > 0, 50);
    assert!(ok, "probe should find the window");
    assert_eq!(first.len(), 3000);
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
    let mut p = Pair::new(1460);
    let mut out = Out::default();
    p.a.close(false, p.now, &mut out);
    p.take(true, out);
    p.run();
    assert_eq!(p.a.state, TcpState::FinWait2);
    let t = p.now;
    p.until(|p| p.a.state == TcpState::Closed, 10);
    assert_eq!(p.now - t, 60_000);
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
    p.a.live.cwnd.set(20_000);
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
    // Only skbs beyond the incoming segment go, highest first
    assert!(o.prune_after(120));
    assert_eq!(o.bytes(), 10);
    assert!(!o.prune_after(120));
    assert!(o.prune_after(100));
    assert!(o.is_empty() && !o.prune_after(100));
}

#[test]
fn rcv_nxt_only_over_accepted_bytes() {
    let mut p = Pair::with_cap(60_000, 10_000);
    // b offers 10000; a 30000-byte flood is cut at the window edge
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
    assert_eq!(p.b.rcv_wnd(), 10_000);
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
    // The timeout resends the SYN-ACK alone (Linux: the head of the
    // retransmit queue, still in FIN_WAIT_1), then the FIN once it is
    // acknowledged
    let n = p.log.len();
    assert!(p.tick());
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
    assert_eq!(p.a.stats.total_retrans, 1);
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
    assert_eq!(p.a.ca_state, super::recovery::CaState::Open);
    let n = p.log.len();
    assert!(p.tick());
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
fn ooo_pieces_bounded() {
    use super::cb::{OOO_MAX, Ooo};
    let mut o = Ooo::default();
    // Many tiny scattered segments: bounded pieces, charged overhead
    for i in 0..2000u32 {
        o.insert(piece(10 + i * 3, 1, 1), None);
    }
    assert_eq!(o.pieces(), OOO_MAX);
    assert_eq!(o.truesize(), OOO_MAX * (1 + super::cb::OOO_OVERHEAD));
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
    p.a.live.cwnd.set(1 << 20);
    p.filter = drop_all;
    p.send_a(&data[400_000..]);
    assert!(p.a.snd_max.wrapping_sub(p.a.snd_una) > 65535);
    // The locked buffer picks its own scale (Linux SOCK_RCVBUF_LOCK)
    let mut b = TcpCb::new(cfg(), Default::default());
    b.rcv_cap = 4096;
    b.rcv_locked = true;
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
    // SRTT 0 from the handshake, then a 100 ms sample: 100 / 8
    assert_eq!(p.a.rtt().0, 12);
    assert_eq!(p.a.stats.min_rtt, Some(0));
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
    // The retransmission's echo gives a sample of 50 ms: srtt8 100 + 38
    assert_eq!(p.a.rtt().0, 17);
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
    assert_eq!(p.a.cong.cwnd() as usize, 10 * mss);
    p.filter = drop_all;
    p.log.clear();
    p.send_a(&pattern(100_000));
    // The initial window: ten segments
    assert_eq!(p.log.len(), 10);
    // Slow start roughly doubles per round trip
    let mut p = Pair::new(1000);
    p.b.rcv_cap = 1 << 20;
    let mut rounds = Vec::new();
    p.send_a(&pattern(300_000));
    for _ in 0..3 {
        let before = p.a.snd_max;
        p.run();
        rounds.push(p.a.snd_max.wrapping_sub(before) as usize / mss);
        p.read_b(1 << 20);
    }
    assert!(rounds[1] >= 16, "rounds {:?}", rounds);
    // Congestion avoidance: about one segment per window
    let mut c = p.a.cong.dup();
    c.live.ssthresh.set(c.cwnd());
    let w = c.cwnd();
    c.on_sent(w, 0, 1, true);
    c.on_ack(w);
    assert_eq!(c.cwnd(), w + mss as u32);
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
    // Gave up about 5 s after the data first went out, not after 15
    // retransmissions
    let dt = p.now - t0;
    assert!((5000..=5300).contains(&dt), "gave up after {} ms", dt);
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
    let s = tw_seg(old, flags::SYN, Some((r.wrapping_add(1), 0)));
    assert_eq!(tw.rcv(&s, now, false, None), TwStatus::Syn);
    let s = tw_seg(next, flags::SYN, None);
    assert_eq!(tw.rcv(&s, now, false, None), TwStatus::Syn);
    // Not with ACK
    let s = tw_seg(next, flags::SYN | flags::ACK, None);
    assert_ne!(tw.rcv(&s, now, false, None), TwStatus::Syn);
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
    assert_eq!(m.net.fold(LINUX_MIB_TCPTIMEOUTS), 1);
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
    p.a.cong.set_snd_cwnd(20);
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
    // ssthresh: half the 8 packets out at the third duplicate (the
    // algorithm's ssthresh); recovery ends at it
    assert_eq!(p.a.cong.snd_ssthresh(), 4);
    assert_eq!(p.a.cong.snd_cwnd(), 4);
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

/// Drop the first transmission of data at the seqs `p.a` lists in
/// `DROP` (a filter's state lives in a static: filters are fn pointers)
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
    p.a.cong.set_snd_cwnd(20);
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
    p.a.cong.set_snd_cwnd(20);
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
    p.a.cong.set_snd_cwnd(20);
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
    // One SACKed skb of five segments behind the lost one
    assert_eq!(p.a.rtx.len(), 2);
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
}
