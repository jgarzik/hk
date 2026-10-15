//! TCP timers: RTO estimation (RFC 6298 with Karn's algorithm), the
//! retransmission / persist / TIME_WAIT / FIN_WAIT_2 expiry logic of the
//! control block (I/O-free), and the timer service that calls it.
//!
//! ## Timer service (thread context only)
//!
//! Connections and timewait entries register their earliest deadline in
//! `TIMERS` (a `spin::Mutex` leaf: deadline-ordered map of weak
//! handles). One `timer::Alarm` (ktimerd) is armed for the earliest
//! deadline; it only raises a flag and wakes `softnet/0` (decision 1:
//! protocol timers run in softnet), which calls [`run`]: due entries are
//! taken out under `TIMERS`, then each is processed under its own socket
//! lock with `TIMERS` dropped. Order: socket lock -> `TIMERS` ->
//! `Alarm.st` -> kernel `TIMERS` (IrqSpinlock).

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use spin::Mutex;

use super::cb::{ORPHAN_RETRIES, Out, RTO_FALLBACK, RTO_MAX, RTO_MIN, TcpCb, TcpState, Tmr};
use crate::error::KernelError;

impl TcpCb {
    /// Current timeout: the base RTO backed off, at most RTO_MAX
    pub(super) fn rto_cur(&self) -> u64 {
        (self.rto << self.backoff.min(16)).min(RTO_MAX)
    }

    /// (Re)start the retransmission timer
    pub(super) fn arm_rtx(&mut self, now: u64) {
        self.tmr = Some((Tmr::Rtx, now + self.rto_cur()));
    }

    /// RFC 6298 2.2/2.3 for a measured round trip `r` ms (srtt8 = 8 *
    /// SRTT, rttvar4 = 4 * RTTVAR); a valid sample ends the backoff
    pub(super) fn rtt_sample(&mut self, r: u64) {
        if self.srtt8 == 0 {
            self.srtt8 = (r * 8).max(1);
            self.rttvar4 = r * 2;
        } else {
            let srtt = (self.srtt8 / 8) as i64;
            let delta = r as i64 - srtt;
            self.srtt8 = (self.srtt8 as i64 + delta).max(1) as u64;
            let var = (self.rttvar4 / 4) as i64;
            self.rttvar4 = (self.rttvar4 as i64 + delta.abs() - var).max(0) as u64;
        }
        self.rto = (self.srtt8 / 8 + self.rttvar4.max(1)).clamp(RTO_MIN, RTO_MAX);
        self.backoff = 0;
    }

    /// RFC 6298 5.7: SYN retransmitted and no RTT measured
    pub(super) fn set_rto_fallback(&mut self) {
        if self.srtt8 == 0 {
            self.rto = RTO_FALLBACK;
        }
    }

    /// Smoothed RTT and its variance in ms (TCP_INFO)
    pub fn rtt(&self) -> (u64, u64) {
        (self.srtt8 / 8, self.rttvar4 / 4)
    }

    /// Retransmissions allowed before giving up (Linux tcp_write_timeout)
    fn retries(&self) -> u32 {
        match self.state {
            TcpState::SynSent => self.cfg.syn_retries,
            TcpState::SynReceived => self.cfg.synack_retries,
            _ if self.orphan => ORPHAN_RETRIES.min(self.cfg.retries2),
            _ => self.cfg.retries2,
        }
    }

    /// Give up: the last soft (ICMP) error, else ETIMEDOUT
    fn timed_out(&mut self, out: &mut Out) {
        let e = self.soft_err.take().unwrap_or(KernelError::TimedOut);
        self.fail(e, out);
    }

    /// A deadline passed (call at or after `next_timer()`)
    pub fn on_timer(&mut self, now: u64, out: &mut Out) {
        if self.wait_at.is_some_and(|t| t <= now) {
            self.wait_at = None;
            match self.state {
                TcpState::TimeWait => self.set_closed(out),
                // Orphan in FIN_WAIT_2 too long (Linux tcp_keepalive_timer)
                TcpState::FinWait2 => self.abort(out),
                _ => {}
            }
            return;
        }
        let Some((kind, at)) = self.tmr else {
            return;
        };
        if at > now {
            return;
        }
        self.tmr = None;
        match kind {
            Tmr::Rtx => self.rtx_timer(now, out),
            Tmr::Probe => self.probe_timer(now, out),
        }
    }

    /// Retransmission timeout (Linux tcp_retransmit_timer): back off,
    /// collapse the congestion window, resend from SND.UNA (go-back-N)
    fn rtx_timer(&mut self, now: u64, out: &mut Out) {
        let handshake = matches!(self.state, TcpState::SynSent | TcpState::SynReceived);
        if !handshake && self.snd_una == self.snd_max {
            return;
        }
        if self.backoff >= self.retries() {
            self.timed_out(out);
            return;
        }
        let flight = self.snd_max.wrapping_sub(self.snd_una);
        self.cong.on_rto(flight);
        self.rtt_seq = None;
        self.backoff += 1;
        if handshake {
            self.syn_rtx = true;
            let s = self.syn_seg();
            out.segs.push(s);
        } else {
            self.snd_nxt = self.snd_una;
            self.output(now, out);
        }
        self.arm_rtx(now);
    }

    /// Persist timer: probe the zero window, backing off (Linux
    /// tcp_probe_timer); a peer that never answers is given up on
    fn probe_timer(&mut self, now: u64, out: &mut Out) {
        if self.snd_wnd != 0 {
            self.output(now, out);
            return;
        }
        self.probes += 1;
        if self.probes > self.retries() {
            self.timed_out(out);
            return;
        }
        self.send_probe(out);
        self.backoff += 1;
        self.tmr = Some((Tmr::Probe, now + self.rto_cur()));
    }
}

// ============================================================================
// Timer service
// ============================================================================

/// Something with TCP deadlines (a connection or a timewait entry)
pub trait Expire: Send + Sync {
    /// Registration `id` is due: run due work at `now` (ms) and
    /// re-register (call [`fired`] first, under the owner's lock)
    fn expire(self: Arc<Self>, id: u64, now: u64);
}

/// Registered deadlines: (deadline ms, registration id) -> owner
static TIMERS: Mutex<BTreeMap<(u64, u64), Weak<dyn Expire>>> = Mutex::new(BTreeMap::new());

/// Registration ids
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Wakes softnet/0 to run [`run`]
static ALARM: crate::timer::Alarm = crate::timer::Alarm::new(alarm_fired);

fn alarm_fired(_: u64) {
    crate::net::dev::raise_timer();
}

/// Milliseconds on the monotonic clock
pub fn now_ms() -> u64 {
    crate::time::monotonic_ns() / 1_000_000
}

/// A registration slot owned by a connection (kept under its lock)
#[derive(Debug, Default)]
pub struct Slot(Option<(u64, u64)>);

/// Make `slot` match `want` (None = cancel) for owner `me`
pub fn rearm(slot: &mut Slot, want: Option<u64>, me: Weak<dyn Expire>) {
    if slot.0.map(|k| k.0) == want {
        return;
    }
    let mut t = TIMERS.lock();
    if let Some(k) = slot.0.take() {
        t.remove(&k);
    }
    let Some(at) = want else {
        return;
    };
    let k = (at, NEXT_ID.fetch_add(1, Ordering::Relaxed));
    t.insert(k, me);
    slot.0 = Some(k);
    let first = t.keys().next().map(|k| k.0) == Some(at);
    drop(t);
    if first {
        ALARM.arm(at.saturating_mul(1_000_000));
    }
}

/// Registration `id` fired (called under the owner's lock before it
/// runs its timers): forget it unless it was re-armed meanwhile
pub fn fired(slot: &mut Slot, id: u64) {
    if slot.0.is_some_and(|k| k.1 == id) {
        slot.0 = None;
    }
}

/// Run due TCP timers (softnet/0, thread context, no locks held)
pub fn run() {
    ALARM.fired();
    let now = now_ms();
    let due: Vec<((u64, u64), Weak<dyn Expire>)> = {
        let mut t = TIMERS.lock();
        let mut v = Vec::new();
        while let Some((&k, _)) = t.iter().next() {
            if k.0 > now || v.len() >= 256 {
                break;
            }
            let w = t.remove(&k).unwrap();
            v.push((k, w));
        }
        v
    };
    for (k, w) in due {
        if let Some(o) = w.upgrade() {
            o.expire(k.1, now);
        }
    }
    let next = TIMERS.lock().keys().next().map(|k| k.0);
    if let Some(at) = next {
        ALARM.arm(at.saturating_mul(1_000_000));
    }
}
