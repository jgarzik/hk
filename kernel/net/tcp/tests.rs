//! Deterministic tests of the I/O-free control block: two control
//! blocks over a simulated network with a virtual clock, where a filter
//! may drop, duplicate or reorder segments.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::cb::{
    Cfg, MSS_DEFAULT, Open, Out, RCV_SHUTDOWN, RTO_MAX, Seg, SegIn, TIMEWAIT_LEN, TcpCb, TcpState,
    flags,
};
use crate::error::KernelError;

fn seg_in(s: &Seg) -> SegIn<'_> {
    SegIn {
        seq: s.seq,
        ack: s.ack,
        flags: s.flags,
        wnd: s.wnd,
        mss: s.mss,
        ws: s.ws,
        ts: s.ts,
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
    let mut b = TcpCb::new(cfg());
    b.rcv_cap = cap;
    b.passive(&seg_in(syn), open(iss, mss), now, out);
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
        p.a = TcpCb::new(ca);
        let mut out = Out::default();
        p.a.connect(open(1000, mss), p.now, &mut out);
        p.take(true, out);
        let (_, syn) = p.wire.pop_front().unwrap();
        let mut out = Out::default();
        p.b = TcpCb::new(cb);
        p.b.rcv_cap = cap;
        p.b.passive(&seg_in(&syn), open(5000, mss), p.now, &mut out);
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
    // Timestamps (12 option bytes) come off the MSS
    assert_eq!((p.a.mss, p.b.mss), (1448, 1448));
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
    let mut a = TcpCb::new(cfg());
    let mut out = Out::default();
    a.connect(open(1, 1460), 0, &mut out);
    let synack = SegIn {
        seq: 77,
        ack: 2,
        flags: flags::SYN | flags::ACK,
        wnd: 8000,
        mss: None,
        ws: None,
        ts: None,
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
        ack: 0,
        flags: flags::RST,
        wnd: 0,
        mss: None,
        ws: None,
        ts: None,
        data: &[],
    };
    // In window, not exact: challenge ACK (spaced past the 500 ms
    // per-connection rate limit)
    let mut out = Out::default();
    p.a.input(&rst(nxt + 10), 1000, &mut out);
    assert_eq!(p.a.state, TcpState::Established);
    assert_eq!(out.segs.len(), 1);
    assert!(out.segs[0].has(flags::ACK) && out.segs[0].ack == nxt);
    // Out of window: silently dropped
    let mut out = Out::default();
    p.a.input(&rst(nxt.wrapping_sub(100_000)), 2000, &mut out);
    assert!(out.segs.is_empty() && p.a.state == TcpState::Established);
    // SYN on an established connection: challenge ACK
    let syn = SegIn {
        flags: flags::SYN,
        ..rst(nxt)
    };
    let mut out = Out::default();
    p.a.input(&syn, 3000, &mut out);
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
    p.a.input(&bad, 4000, &mut out);
    assert_eq!(p.a.rcvq_len(), 0);
    assert!(out.segs[0].has(flags::ACK));
    // Exact: reset
    let mut out = Out::default();
    p.a.input(&rst(nxt), 5000, &mut out);
    assert_eq!(p.a.state, TcpState::Closed);
    assert_eq!(out.err, Some(KernelError::ConnectionReset));
    assert!(out.done);
}

#[test]
fn syn_sent_refused_and_bad_ack() {
    let mut a = TcpCb::new(cfg());
    let mut out = Out::default();
    a.connect(open(500, 1460), 0, &mut out);
    // An ACK for something else: RST from its ACK, still SYN_SENT
    let bad = SegIn {
        seq: 9,
        ack: 77,
        flags: flags::ACK,
        wnd: 0,
        mss: None,
        ws: None,
        ts: None,
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
        ws: None,
        ts: None,
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
    a.connect(open(10, 1460), 0, &mut out);
    let syn = out.segs[0].clone();
    let mut out = Out::default();
    let mut b = passive(&syn, 99, 1460, BUFS.0, 0, &mut out);
    let synack = out.segs[0].clone();
    let mut out = Out::default();
    b.input(&seg_in(&syn), 1, &mut out);
    // The same SYN-ACK, but a fresh TSval
    let again = Seg {
        ts: synack.ts,
        ..out.segs[0].clone()
    };
    assert_eq!(out.segs.len(), 1);
    assert_eq!(again, synack);
    assert_eq!(b.state, TcpState::SynReceived);
}

#[test]
fn synack_retries_then_give_up() {
    let mut p = Pair::bare();
    let mut out = Out::default();
    p.a.connect(open(1, 1460), 0, &mut out);
    let syn = out.segs[0].clone();
    let mut out = Out::default();
    p.b = passive(&syn, 2, 1460, BUFS.0, 0, &mut out);
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
    a.connect(open(10, 1460), 0, &mut out);
    let syn = out.segs[0].clone();
    let mut out = Out::default();
    let mut b = passive(&syn, 99, 1460, BUFS.0, 0, &mut out);
    let ack = SegIn {
        seq: 11,
        ack: 100,
        flags: flags::ACK | flags::PSH,
        wnd: 1000,
        mss: None,
        ws: None,
        ts: None,
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
    assert_eq!(p.a.mss, 524);
    assert!(!out.segs.is_empty());
    assert!(out.segs.iter().all(|s| s.data.len() <= 524));
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
    // Disjoint pieces, each byte stored once, delivered in order
    assert_eq!(o.take(110).unwrap(), [1u8; 10]);
    assert_eq!(o.take(120).unwrap(), [2u8; 10]);
    assert_eq!(o.take(130).unwrap(), [3u8; 10]);
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
        ws: None,
        ts: None,
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
            ws: None,
            ts: None,
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
    p.a.connect(open(100, 1460), 0, &mut o1);
    let mut o2 = Out::default();
    p.b.connect(open(900, 1460), 0, &mut o2);
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

#[test]
fn ooo_pieces_bounded() {
    use super::cb::{OOO_MAX, Ooo};
    let mut o = Ooo::default();
    // Many tiny scattered segments: bounded pieces, charged overhead
    for i in 0..20_000u32 {
        o.insert(0, 10 + i * 3, &[1]);
    }
    assert_eq!(o.pieces(), OOO_MAX);
    assert_eq!(o.truesize(), OOO_MAX * (1 + super::cb::OOO_OVERHEAD));
    // Adjacent tiny segments growing one range never re-copy held bytes
    let mut o = Ooo::default();
    for i in 0..200u32 {
        o.insert(0, 10 + i, &[i as u8]);
    }
    o.insert(0, 5, &[9; 300]);
    assert_eq!(o.bytes(), 300);
    let d = o.take(5).unwrap();
    assert_eq!(d.len(), 5);
    assert_eq!(o.take(10).unwrap(), [0u8]);
    // Rebasing keeps data
    let mut o = Ooo::default();
    o.insert(0, 100, &[3; 10]);
    o.insert(0x7000_0000, 0x7000_0010, &[4; 4]);
    assert_eq!(o.take(0x7000_0010).unwrap(), [4u8; 4]);
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
        assert_eq!(c.mss, 1460);
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
    p.a.cong.cwnd = 1 << 20;
    p.filter = drop_all;
    p.send_a(&data[400_000..]);
    assert!(p.a.snd_max.wrapping_sub(p.a.snd_una) > 65535);
    // The locked buffer picks its own scale (Linux SOCK_RCVBUF_LOCK)
    let mut b = TcpCb::new(cfg());
    b.rcv_cap = 4096;
    b.rcv_locked = true;
    let mut a = TcpCb::new(cfg());
    let mut out = Out::default();
    a.connect(open(1, 1460), 0, &mut out);
    let mut o2 = Out::default();
    b.passive(&seg_in(&out.segs[0]), open(2, 1460), 0, &mut o2);
    assert_eq!(b.rcv_wscale, 0);
    assert_eq!(o2.segs[0].ws, Some(0));
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
    p.b.input(&seg_in(&replay), p.now, &mut out);
    assert_eq!(p.b.rcvq_len(), 6);
    assert_eq!(out.segs.len(), 1);
    assert_eq!(out.segs[0].ack, p.b.rcv_nxt);
    // The same with a fresh TSval is accepted
    replay.ts = Some((old.ts.unwrap().0.wrapping_add(5000), 0));
    let mut out = Out::default();
    p.b.input(&seg_in(&replay), p.now, &mut out);
    assert_eq!(p.b.rcvq_len(), 10);
    // An old RST is still honoured (RFC 7323 5.3 / Linux)
    let rst = Seg {
        seq: p.b.rcv_nxt,
        flags: flags::RST,
        ts: old.ts,
        ..Default::default()
    };
    let mut out = Out::default();
    p.b.input(&seg_in(&rst), p.now, &mut out);
    assert_eq!(p.b.state, TcpState::Closed);
}

#[test]
fn ts_recent_follows_last_ack_sent() {
    // TS.Recent is taken only from segments at or before Last.ACK.sent:
    // with ACKs delayed it echoes the earliest unacknowledged segment
    let mut p = Pair::new(1000);
    p.b.dack.quick = 0;
    p.b.dack.ato = 40;
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
    assert!(p.b.dack.quick > 0);
    // Leave quickack mode: a lone small segment waits for the ATO
    p.b.dack.quick = 0;
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
    p.b.dack.quick = 0;
    p.log.clear();
    let mss = p.a.mss as usize;
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
    p.b.dack.quick = 0;
    p.send_a(&pattern(10));
    p.run();
    p.log.clear();
    let mut out = Out::default();
    p.b.send(b"reply");
    p.b.output(p.now, &mut out);
    assert_eq!(out.segs.len(), 1);
    assert_eq!(out.segs[0].ack, p.b.rcv_nxt);
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
    assert_eq!(out.segs.len(), 1);
    assert!(!p.b.dack.pending);
}

#[test]
fn nagle_coalesces_small_writes() {
    let mut p = Pair::new(1000);
    p.b.dack.quick = 0;
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
    let m = p.a.mss as usize;
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
    assert_eq!(out.segs.len(), 1);
    assert_eq!(out.segs[0].data.len(), 300);
    // MSG_MORE holds the tail of that send only
    p.take(true, out);
    p.run();
    p.log.clear();
    p.a.send(&pattern(m + 200));
    let mut out = Out::default();
    p.a.output_more(p.now, &mut out);
    let sent: Vec<usize> = out.segs.iter().map(|s| s.data.len()).collect();
    assert_eq!(sent, [m]);
}

#[test]
fn iw10_slow_start_growth() {
    let mut p = Pair::new(1000);
    let mss = p.a.mss as usize;
    assert_eq!(p.a.cong.cwnd as usize, 10 * mss);
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
    let mut c = p.a.cong.clone();
    c.ssthresh = c.cwnd;
    let w = c.cwnd;
    c.on_sent(w, 0, 1, true);
    c.on_ack(w, 2);
    assert_eq!(c.cwnd, w + mss as u32);
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
    assert_eq!((p.now, p.a.keep_at), (10_000, Some(16_000)));
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
    assert!(p.a.keep_at.is_none());
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
    let mut p = Pair::new(1460);
    let mut out = Out::default();
    p.a.close(false, p.now, &mut out);
    p.take(true, out);
    p.run();
    let mut out = Out::default();
    p.b.close(false, p.now, &mut out);
    p.take(false, out);
    p.run();
    assert_eq!(p.a.state, TcpState::TimeWait);
    let tw = p.a.tw_clone();
    let syn = |seq: u32, tsv: u32| SegIn {
        seq,
        flags: flags::SYN,
        ts: Some((tsv, 0)),
        ..Default::default()
    };
    let old = tw.rcv_nxt.wrapping_sub(10);
    assert!(!tw.tw_syn_ok(&syn(old, tw.ts_recent.wrapping_sub(1))));
    assert!(tw.tw_syn_ok(&syn(old, tw.ts_recent.wrapping_add(1))));
    assert!(tw.tw_syn_ok(&syn(tw.rcv_nxt.wrapping_add(1), 0)));
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
    p.b.input(&bogus, p.now, &mut Out::default());
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
    p.a.input(&old, p.now, &mut Out::default());
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
    q.a.input(&far, q.now, &mut out);
    assert!(q.a.snd_wnd > 0);
    assert_eq!(
        out.segs.len(),
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
        p.a.input(&stale, p.now, &mut out);
        n += out.segs.len();
    }
    assert_eq!(n, 1);
    let mut out = Out::default();
    p.a.input(&stale, p.now + 500, &mut out);
    assert_eq!(out.segs.len(), 1);
    // Challenge ACKs (in-window RST) share the limit
    let rst = SegIn {
        seq: p.a.rcv_nxt.wrapping_add(10),
        flags: flags::RST,
        ..Default::default()
    };
    let mut out = Out::default();
    p.a.input(&rst, p.now + 600, &mut out);
    assert!(out.segs.is_empty());
    assert_eq!(p.a.state, TcpState::Established);
}
