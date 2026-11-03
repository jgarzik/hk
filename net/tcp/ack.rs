//! Delayed ACKs (RFC 1122 4.2.3.2, RFC 5681 4.2; Linux icsk_ack,
//! tcp_event_data_recv, __tcp_ack_snd_check, tcp_send_delayed_ack,
//! tcp_delack_timer_handler), I/O-free
//!
//! In-order data is acknowledged at once when more than one full
//! segment is unacknowledged, in quickack mode (the start of a
//! connection and after idle gaps: up to 16 ACKs), or when out-of-order
//! data is held; otherwise the ACK waits up to the adaptive ATO (40 ms
//! minimum, at most 200 ms / 500 ms, bounded by the smoothed RTT) for a
//! data segment to piggyback on. Interactive ("pingpong") connections
//! delay ACKs even in quickack mode. Out-of-order segments, duplicates,
//! FINs and window-edge trims are acknowledged immediately (`ack_now`).

use super::cb::{Out, TcpCb, TcpState};

/// Linux TCP_ATO_MIN / TCP_DELACK_MIN / TCP_DELACK_MAX (ms)
pub const ATO_MIN: u64 = 40;
pub const DELACK_MAX: u64 = 200;
/// Linux TCP_MAX_QUICKACKS
pub const MAX_QUICKACKS: u32 = 16;
/// Smallest rcv_mss estimate (Linux TCP_MIN_MSS)
const MIN_MSS: u32 = 88;

/// Delayed ACK state (Linux inet_connection_sock.icsk_ack)
#[derive(Clone, Debug, Default)]
pub struct Dack {
    /// An ACK is owed for received data
    pub pending: bool,
    /// A segment shorter than `rcv_mss` arrived since the last ACK
    pub pushed: bool,
    /// ACKs left to send at once (quickack mode)
    pub quick: u32,
    /// Interactive: replies follow data, ACKs ride on them
    pub pingpong: bool,
    /// Adaptive delay (ms; 0 until data arrives)
    pub ato: u64,
    /// When data last arrived
    pub lrcvtime: u64,
    /// Estimated peer MSS
    pub rcv_mss: u32,
    /// Delayed ACK deadline
    pub at: Option<u64>,
}

impl Dack {
    /// Linux tcp_initialize_rcv_mss
    pub fn init(&mut self, mss: u32, rcv_wnd: u32) {
        self.rcv_mss = mss.min(rcv_wnd / 2).clamp(MIN_MSS, 536);
    }
}

impl TcpCb {
    /// Linux tcp_incr_quickack
    fn incr_quickack(&mut self, max: u32) {
        let q = (self.rcv_wnd() / (2 * self.dack.rcv_mss.max(1))).max(2);
        self.dack.quick = self.dack.quick.max(q.min(max));
    }

    /// Linux tcp_enter_quickack_mode
    pub(super) fn enter_quickack(&mut self) {
        self.incr_quickack(MAX_QUICKACKS);
        self.dack.pingpong = false;
        self.dack.ato = ATO_MIN;
    }

    fn in_quickack(&self) -> bool {
        self.dack.quick > 0 && !self.dack.pingpong
    }

    /// In-order data of `len` bytes arrived (Linux tcp_event_data_recv +
    /// tcp_measure_rcv_mss): owe an ACK, adapt the ATO
    pub(super) fn data_recv(&mut self, len: u32, now: u64) {
        self.dack.pending = true;
        if len >= self.dack.rcv_mss {
            self.dack.rcv_mss = len.min(self.adv_mss).max(MIN_MSS);
        } else {
            self.dack.pushed = true;
        }
        let d = &mut self.dack;
        if d.ato == 0 {
            // The first data: start in quickack mode
            d.ato = ATO_MIN;
            self.incr_quickack(MAX_QUICKACKS);
        } else {
            let m = now.saturating_sub(d.lrcvtime);
            if m <= ATO_MIN / 2 {
                d.ato = d.ato / 2 + ATO_MIN / 2;
            } else if m < d.ato {
                d.ato = (d.ato / 2 + m).min(self.rto);
            } else if m > self.rto {
                // A long gap: the sender restarts, ACK quickly
                self.incr_quickack(MAX_QUICKACKS);
            }
        }
        self.dack.lrcvtime = now;
        self.stats.last_data_recv = now;
    }

    /// An ACK went out (Linux tcp_event_ack_sent): nothing owed any more
    pub(super) fn ack_sent(&mut self) {
        if self.dack.quick > 0 && self.dack.pending {
            self.dack.quick -= 1;
            if self.dack.quick == 0 {
                self.dack.ato = ATO_MIN;
            }
        }
        self.dack.pending = false;
        self.dack.pushed = false;
        self.dack.at = None;
        self.ack_now = false;
    }

    /// New data went out at `now` (Linux tcp_event_data_sent): a reply
    /// within the ATO of the last data received makes the connection
    /// interactive
    pub(super) fn data_sent(&mut self, now: u64) {
        if self.dack.ato != 0 && now.saturating_sub(self.dack.lrcvtime) < self.dack.ato {
            self.dack.pingpong = true;
        }
    }

    /// After input, with no data segment carrying the ACK: send it now
    /// or arm the delayed ACK timer (Linux __tcp_ack_snd_check)
    pub(super) fn ack_snd_check(&mut self, now: u64, out: &mut Out) {
        if self.ack_now {
            self.send_ack(out);
            return;
        }
        if !self.dack.pending {
            return;
        }
        // More than a full segment unacknowledged, and the right edge
        // would advance by at least what arrived (else the reader's
        // tcp_cleanup_rbuf sends the ACK when it makes room)
        let unacked = self.rcv_nxt.wrapping_sub(self.rcv_wup);
        let last = self.rcv_adv.wrapping_sub(self.rcv_wup);
        if (unacked > self.dack.rcv_mss && self.window_now() >= last)
            || self.in_quickack()
            || !self.ooo.is_empty()
        {
            self.send_ack(out);
            return;
        }
        self.delay_ack(now, out);
    }

    /// Arm the delayed ACK timer (Linux tcp_send_delayed_ack)
    fn delay_ack(&mut self, now: u64, out: &mut Out) {
        let mut ato = self.dack.ato.max(ATO_MIN);
        if ato > ATO_MIN {
            let mut max = 500;
            if self.dack.pingpong || self.dack.pushed {
                max = DELACK_MAX;
            }
            if self.srtt8 != 0 {
                max = max.min((self.srtt8 / 8).max(ATO_MIN));
            }
            ato = ato.min(max);
        }
        let mut at = now + ato;
        if let Some(old) = self.dack.at {
            if old <= now + ato / 4 {
                self.send_ack(out);
                return;
            }
            at = at.min(old);
        }
        self.dack.at = Some(at);
    }

    /// The delayed ACK timer fired (Linux tcp_delack_timer_handler)
    pub(super) fn delack_timer(&mut self, out: &mut Out) {
        self.dack.at = None;
        if !self.dack.pending || !self.state.synced() {
            return;
        }
        if self.dack.pingpong {
            // Missed: leave interactive mode
            self.dack.pingpong = false;
            self.dack.ato = ATO_MIN;
        } else {
            self.dack.ato = (self.dack.ato << 1).min(self.rto);
        }
        self.send_ack(out);
    }

    /// TCP_QUICKACK (Linux __tcp_sock_set_quickack): nonzero leaves
    /// interactive mode and sends an owed ACK; zero (or an even value
    /// after the ACK) enters it
    pub fn set_quickack(&mut self, val: i32, out: &mut Out) {
        if val == 0 {
            self.dack.pingpong = true;
            return;
        }
        self.dack.pingpong = false;
        if matches!(self.state, TcpState::Established | TcpState::CloseWait) && self.dack.pending {
            self.send_ack(out);
            if val & 1 == 0 {
                self.dack.pingpong = true;
            }
        }
    }

    /// TCP_QUICKACK as read back: not interactive
    pub fn quickack(&self) -> bool {
        !self.dack.pingpong
    }
}
