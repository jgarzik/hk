//! Deterministic tests of the I/O-free control block: two control
//! blocks over a simulated network with a virtual clock, where a filter
//! may drop, duplicate or reorder segments.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::cb::{
    Cfg, MSS_DEFAULT, Out, RCV_SHUTDOWN, RTO_MAX, Seg, SegIn, TIMEWAIT_LEN, TcpCb, TcpState, flags,
};
use crate::error::KernelError;

fn seg_in(s: &Seg) -> SegIn<'_> {
    SegIn {
        seq: s.seq,
        ack: s.ack,
        flags: s.flags,
        wnd: s.wnd,
        mss: s.mss,
        data: &s.data,
    }
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
    }
}

impl Pair {
    /// A connected pair (a active, b passive); `mss` both ways
    fn new(mss: u32) -> Self {
        Self::with_cap(mss, 64 * 1024)
    }

    /// Same, b's receive buffer `cap` bytes
    fn with_cap(mss: u32, cap: usize) -> Self {
        let mut p = Self::bare();
        let mut out = Out::default();
        p.a.connect(1000, mss, p.now, &mut out);
        p.take(true, out);
        let (_, syn) = p.wire.pop_front().unwrap();
        let mut out = Out::default();
        p.b = TcpCb::passive(
            cfg(),
            &seg_in(&syn),
            5000,
            mss,
            (cap, 64 * 1024),
            p.now,
            &mut out,
        );
        p.take(false, out);
        p.run();
        assert_eq!(p.a.state, TcpState::Established);
        assert_eq!(p.b.state, TcpState::Established);
        p
    }

    fn bare() -> Self {
        Self {
            a: TcpCb::new(cfg()),
            b: TcpCb::new(cfg()),
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
        for s in out.segs {
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
        let rest = Out {
            segs: Vec::new(),
            ..out
        };
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
            self.b.input(&seg_in(&s), self.now, &mut out);
        } else {
            self.a.input(&seg_in(&s), self.now, &mut out);
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
    assert_eq!((p.a.mss, p.b.mss), (1460, 1460));
    assert_eq!(p.a.snd_una, 1001);
    assert_eq!(p.b.rcv_nxt, 1001);
}

#[test]
fn mss_default_without_option() {
    let mut a = TcpCb::new(cfg());
    let mut out = Out::default();
    a.connect(1, 1460, 0, &mut out);
    let synack = SegIn {
        seq: 77,
        ack: 2,
        flags: flags::SYN | flags::ACK,
        wnd: 8000,
        mss: None,
        data: &[],
    };
    let mut out = Out::default();
    a.input(&synack, 5, &mut out);
    assert_eq!(a.state, TcpState::Established);
    assert_eq!(a.mss, MSS_DEFAULT);
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
    p.a.connect(1, 1460, 0, &mut out);
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
    p.a.connect(1, 1460, 0, &mut out);
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
    assert_eq!(p.b.rcvq_len(), 4000);
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
        for (_, to_b, s) in p.log.iter().filter(|l| !l.1) {
            let _ = to_b;
            let e = s.ack.wrapping_add(s.wnd as u32);
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
    // 2MSL later the entry ends
    let t = p.now;
    p.until(|p| p.a.state == TcpState::Closed, 10);
    assert_eq!(p.now - t, TIMEWAIT_LEN);
}

#[test]
fn time_wait_reacks_fin_and_restarts() {
    let mut p = Pair::new(1460);
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
    p.now += 30_000;
    p.log.clear();
    let mut out = Out::default();
    p.a.input(&seg_in(&fin), p.now, &mut out);
    assert_eq!(out.segs.len(), 1);
    assert!(out.segs[0].has(flags::ACK));
    assert_eq!(out.segs[0].ack, fin.seq.wrapping_add(1));
    assert_eq!(p.a.next_timer(), Some(p.now + TIMEWAIT_LEN));
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
    p.a.connect(100, 1460, 0, &mut o1);
    let mut o2 = Out::default();
    p.b.connect(900, 1460, 0, &mut o2);
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
        ack: 0,
        flags: flags::RST,
        wnd: 0,
        mss: None,
        data: &[],
    };
    // In window, not exact: challenge ACK
    let mut out = Out::default();
    p.a.input(&rst(nxt + 10), 0, &mut out);
    assert_eq!(p.a.state, TcpState::Established);
    assert_eq!(out.segs.len(), 1);
    assert!(out.segs[0].has(flags::ACK) && out.segs[0].ack == nxt);
    // Out of window: silently dropped
    let mut out = Out::default();
    p.a.input(&rst(nxt.wrapping_sub(100_000)), 0, &mut out);
    assert!(out.segs.is_empty() && p.a.state == TcpState::Established);
    // SYN on an established connection: challenge ACK
    let syn = SegIn {
        flags: flags::SYN,
        ..rst(nxt)
    };
    let mut out = Out::default();
    p.a.input(&syn, 0, &mut out);
    assert_eq!(p.a.state, TcpState::Established);
    assert!(out.segs[0].has(flags::ACK));
    // ACK of data never sent: ACK back, segment dropped
    let bad = SegIn {
        flags: flags::ACK,
        ack: p.a.snd_max.wrapping_add(1000),
        data: b"zz",
        ..rst(nxt)
    };
    let mut out = Out::default();
    p.a.input(&bad, 0, &mut out);
    assert_eq!(p.a.rcvq_len(), 0);
    assert!(out.segs[0].has(flags::ACK));
    // Exact: reset
    let mut out = Out::default();
    p.a.input(&rst(nxt), 0, &mut out);
    assert_eq!(p.a.state, TcpState::Closed);
    assert_eq!(out.err, Some(KernelError::ConnectionReset));
    assert!(out.done);
}

#[test]
fn syn_sent_refused_and_bad_ack() {
    let mut a = TcpCb::new(cfg());
    let mut out = Out::default();
    a.connect(500, 1460, 0, &mut out);
    // An ACK for something else: RST from its ACK, still SYN_SENT
    let bad = SegIn {
        seq: 9,
        ack: 77,
        flags: flags::ACK,
        wnd: 0,
        mss: None,
        data: &[],
    };
    let mut out = Out::default();
    a.input(&bad, 0, &mut out);
    assert_eq!(a.state, TcpState::SynSent);
    assert_eq!((out.segs[0].flags, out.segs[0].seq), (flags::RST, 77));
    // RST without ACK: ignored
    let mut out = Out::default();
    a.input(
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
    a.input(
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
        ack: 0,
        flags: flags::RST,
        wnd: 0,
        mss: None,
        data: &[],
    };
    let mut out = Out::default();
    p.a.input(&rst, 0, &mut out);
    assert_eq!(out.err, Some(KernelError::BrokenPipe));
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
    assert!(out.segs[0].has(flags::RST));
    p.take(false, out);
    p.run();
    assert_eq!(p.a.state, TcpState::Closed);
    assert_eq!(p.a_out.err, Some(KernelError::ConnectionReset));
}

#[test]
fn linger_zero_resets() {
    let mut p = Pair::new(1460);
    let mut out = Out::default();
    p.a.close(true, p.now, &mut out);
    assert!(out.segs[0].has(flags::RST));
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
    let mut a = TcpCb::new(cfg());
    let mut out = Out::default();
    a.connect(10, 1460, 0, &mut out);
    let syn = out.segs[0].clone();
    let mut out = Out::default();
    let mut b = TcpCb::passive(cfg(), &seg_in(&syn), 99, 1460, BUFS, 0, &mut out);
    let synack = out.segs[0].clone();
    let mut out = Out::default();
    b.input(&seg_in(&syn), 1, &mut out);
    assert_eq!(out.segs, [synack]);
    assert_eq!(b.state, TcpState::SynReceived);
}

#[test]
fn synack_retries_then_give_up() {
    let mut p = Pair::bare();
    let mut out = Out::default();
    p.a.connect(1, 1460, 0, &mut out);
    let syn = out.segs[0].clone();
    let mut out = Out::default();
    p.b = TcpCb::passive(cfg(), &seg_in(&syn), 2, 1460, BUFS, 0, &mut out);
    p.filter = drop_all;
    p.a = TcpCb::new(cfg());
    p.until(|p| p.b.state == TcpState::Closed, 20);
    let times: Vec<u64> = p.log.iter().filter(|l| !l.1).map(|l| l.0).collect();
    assert_eq!(times, [1000, 3000]);
    assert_eq!(p.now, 7000);
}

#[test]
fn ack_with_data_completes_handshake() {
    let mut a = TcpCb::new(cfg());
    let mut out = Out::default();
    a.connect(10, 1460, 0, &mut out);
    let syn = out.segs[0].clone();
    let mut out = Out::default();
    let mut b = TcpCb::passive(cfg(), &seg_in(&syn), 99, 1460, BUFS, 0, &mut out);
    let ack = SegIn {
        seq: 11,
        ack: 100,
        flags: flags::ACK | flags::PSH,
        wnd: 1000,
        mss: None,
        data: b"payload",
    };
    let mut out = Out::default();
    b.input(&ack, 1, &mut out);
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
    p.a.cong.cwnd = 20_000;
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
    assert_eq!(p.a.mss, 536);
    assert!(!out.segs.is_empty());
    assert!(out.segs.iter().all(|s| s.data.len() <= 536));
}

#[test]
fn ooo_intervals_merge() {
    use super::cb::Ooo;
    let mut o = Ooo::default();
    o.insert(100, 110, &[1; 10]);
    o.insert(100, 130, &[3; 10]);
    o.insert(100, 118, &[2; 14]);
    assert_eq!(o.bytes(), 30);
    assert_eq!(o.take(100), None);
    let d = o.take(110).unwrap();
    assert_eq!(d.len(), 30);
    assert!(o.is_empty());
    o.insert(100, 105, &[9; 10]);
    assert_eq!(o.take(108).unwrap().len(), 7);
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
        mss: None,
        data: &flood,
    };
    let (start, edge) = (p.b.rcv_nxt, p.b.rcv_nxt.wrapping_add(p.b.rcv_wnd()));
    assert_eq!(p.b.rcv_wnd(), 10_000);
    let mut out = Out::default();
    p.b.input(&big, p.now, &mut out);
    assert_eq!(p.b.rcv_nxt, edge);
    assert_eq!(p.b.rcvq_len(), edge.wrapping_sub(start) as usize);
    // Its ACK offers a zero window
    assert_eq!(out.segs.last().unwrap().wnd, 0);
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
            mss: None,
            data: &d,
        };
        let mut out = Out::default();
        b.input(&s, 0, &mut out);
        out
    };
    feed(&mut p.b, seg(100, 100, 0));
    feed(&mut p.b, seg(300, 100, 0));
    // A go-back-N retransmission covers both holes and both intervals
    feed(&mut p.b, seg(0, 400, 0));
    assert_eq!(p.b.rcvq_len(), 400);
    let out = feed(&mut p.b, seg(400, 0, flags::FIN));
    assert_eq!(p.b.state, TcpState::CloseWait);
    assert_eq!(out.segs.last().unwrap().ack, base.wrapping_add(401));
}

#[test]
fn shutdown_in_syn_received_sends_fin_later() {
    let mut p = Pair::bare();
    let mut o1 = Out::default();
    p.a.connect(100, 1460, 0, &mut o1);
    let mut o2 = Out::default();
    p.b.connect(900, 1460, 0, &mut o2);
    p.take(true, o1);
    p.take(false, o2);
    p.step();
    p.step();
    assert_eq!(p.a.state, TcpState::SynReceived);
    let mut out = Out::default();
    assert!(p.a.shutdown_wr(p.now, &mut out));
    p.take(true, out);
    p.run();
    assert_eq!(p.a.state, TcpState::FinWait2);
    assert_eq!(p.b.state, TcpState::CloseWait);
}
