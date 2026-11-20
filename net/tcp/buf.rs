//! Buffer size and advertised window tuning (Linux tcp_input.c's
//! "Buffer size and advertised window tuning": tcp_grow_window,
//! tcp_init_buffer_space, tcp_clamp_window; tcp_output.c
//! tcp_select_initial_window; include/net/tcp.h tcp_win_from_space,
//! tcp_space, tcp_adjust_rcv_ssthresh; tcp.c tcp_set_window_clamp)
//!
//! Receive memory is counted as Linux counts it: the truesize of the
//! skbs on the receive and out-of-order queues (sk_rmem_alloc) against
//! the receive buffer (sk_rcvbuf). The window a buffer allows is its
//! space scaled by the share of payload in truesize, measured on the
//! segments received (scaling_ratio, tcp_measure_rcv_mss). The window
//! offered grows from the initial one up to `rcv_ssthresh`, which
//! segments with little overhead raise towards `window_clamp`
//! (tcp_grow_window); memory pressure pulls it back.

use super::cb::{MAX_WINDOW, MAX_WSCALE, TcpCb, before};
use super::mem;
use crate::util::error::KernelError;

/// `TcpCb.userlocks` bits (Linux SOCK_SNDBUF_LOCK, SOCK_RCVBUF_LOCK)
pub const SNDBUF_LOCK: u8 = 1;
pub const RCVBUF_LOCK: u8 = 2;

/// Linux TCP_RMEM_TO_WIN_SCALE
const RMEM_TO_WIN_SCALE: u32 = 8;
/// Linux SKB_TRUESIZE(4096): the page plus Linux's aligned sk_buff
/// (256) and skb_shared_info (320)
const SKB_TRUESIZE_4K: u32 = 4096 + 256 + 320;
/// Linux TCP_DEFAULT_SCALING_RATIO: 1200 bytes of payload per
/// SKB_TRUESIZE(4096) until segments are measured
pub const DEFAULT_SCALING_RATIO: u8 = ((1200 << RMEM_TO_WIN_SCALE) / SKB_TRUESIZE_4K) as u8;
/// Linux SOCK_MIN_RCVBUF / 2: the least TCP_WINDOW_CLAMP
const MIN_WINDOW_CLAMP: u32 = crate::net::sock::MIN_RCVBUF / 2;
/// Linux tcp_grow_window's segments: shorter ones do not grow it
const GROW_MIN_LEN: u32 = 128;
/// Linux TCP_INIT_CWND
const INIT_CWND: u32 = super::cong::INIT_CWND;

/// Linux rcv_rtt_est: the RTT as the receiver sees it (a window's
/// worth of data from the sender, or a timestamp echo), 8 x us; the
/// sequence and time a measurement started
#[derive(Clone, Copy, Debug, Default)]
pub struct RcvRtt {
    pub rtt_us: u32,
    seq: u32,
    time: u64,
    /// The TSecr last sampled (Linux rcv_rtt_last_tsecr)
    last_tsecr: u32,
}

/// Linux rcvq_space: bytes the reader copied in the last receive RTT
/// (`space`), counted from `seq` (copied_seq) since `time` (us)
#[derive(Clone, Copy, Debug, Default)]
pub struct RcvqSpace {
    pub space: u32,
    seq: u32,
    time: u64,
}

impl TcpCb {
    /// Linux tcp_win_from_space: the window `space` bytes of buffer
    /// hold (negative for an overcommitted buffer)
    pub(super) fn win_from_space(&self, space: i64) -> i64 {
        (space * i64::from(self.scaling_ratio)) >> RMEM_TO_WIN_SCALE
    }

    /// Linux tcp_space_from_win: the buffer a window of `win` takes
    pub(super) fn space_from_win(&self, win: u64) -> u64 {
        (win << RMEM_TO_WIN_SCALE) / u64::from(self.scaling_ratio.max(1))
    }

    /// Truesize received and queued (Linux sk_rmem_alloc)
    pub(super) fn rmem_alloc(&self) -> usize {
        self.rcvq_truesize + self.ooo.truesize()
    }

    /// Linux tcp_space: the window the unused buffer holds; negative
    /// past the buffer. The socket's backlog is not counted (Linux
    /// subtracts sk_backlog.len; the control block does not see it)
    pub(super) fn space(&self) -> i64 {
        self.win_from_space(i64::from(self.rcvbuf) - self.rmem_alloc() as i64)
    }

    /// Linux tcp_full_space: the window the whole buffer holds
    pub(super) fn full_space(&self) -> u32 {
        self.win_from_space(i64::from(self.rcvbuf)).max(0) as u32
    }

    /// The window last offered, from RCV.WUP (Linux tp->rcv_wnd)
    pub(super) fn rcv_wnd_adv(&self) -> u32 {
        self.rcv_adv.wrapping_sub(self.rcv_wup)
    }

    /// Linux __tcp_adjust_rcv_ssthresh: no SO_RESERVE_MEM, nothing
    /// reserved to keep it up
    pub(super) fn adjust_rcv_ssthresh_to(&mut self, v: u32) {
        self.rcv_ssthresh = self.rcv_ssthresh.min(v);
    }

    /// Linux tcp_adjust_rcv_ssthresh: under memory pressure, four
    /// segments
    pub(super) fn adjust_rcv_ssthresh(&mut self) {
        self.adjust_rcv_ssthresh_to(4 * self.adv_mss);
    }

    /// Linux tcp_select_initial_window: the window of the SYN or
    /// SYN-ACK from `space` (whole segments of `mss` up to the 16-bit
    /// field) and our scale (enough for tcp_rmem[2] or net.core.rmem_max,
    /// within `window_clamp`), which then bounds the clamp; stored as
    /// the window offered from RCV.WUP (Linux tp->rcv_wnd), which
    /// `rcv_ssthresh` starts at
    pub(super) fn select_initial_window(&mut self, space: i64, mss: u32, wscale_ok: bool) {
        if self.window_clamp == 0 {
            self.window_clamp = MAX_WINDOW << MAX_WSCALE;
        }
        let mut space = (space.max(0) as u32).min(self.window_clamp);
        if space > mss {
            space -= space % mss;
        }
        let rcv_wnd = space.min(MAX_WINDOW);
        self.rcv_wscale = 0;
        if wscale_ok {
            let s = space
                .max(self.cfg.rmem_max)
                .max(crate::net::sock::BUF_MAX)
                .min(self.window_clamp)
                .max(1);
            let log = 31 - s.leading_zeros();
            self.rcv_wscale = log.saturating_sub(15).min(u32::from(MAX_WSCALE)) as u8;
        }
        self.window_clamp = self.window_clamp.min(MAX_WINDOW << self.rcv_wscale);
        self.rcv_wup = 0;
        self.rcv_adv = rcv_wnd;
        self.rcv_ssthresh = rcv_wnd;
    }

    /// The initial window of an opening connection (Linux
    /// tcp_connect_init, tcp_openreq_init_rwin): a fixed SO_RCVBUF
    /// bounds the clamp; our MSS less the timestamp option bytes
    /// rounds it
    pub(super) fn init_rwin(&mut self, ts: bool) {
        let full = self.full_space();
        if self.userlocks & RCVBUF_LOCK != 0 && (self.window_clamp > full || self.window_clamp == 0)
        {
            self.window_clamp = full;
        }
        let mss = self.adv_mss - if ts { super::cb::TS_LEN } else { 0 };
        self.select_initial_window(i64::from(full), mss, self.wscale_ok);
    }

    /// Linux tcp_init_buffer_space (from tcp_init_transfer): the clamp
    /// fits the buffer, less 1/2^tcp_app_win of it for the application
    /// and one segment held back; `rcv_ssthresh` within it
    pub(super) fn init_buffer_space(&mut self) {
        let app_win = u32::from(self.cfg.app_win);
        let advmss = self.adv_mss;
        let maxwin = self.full_space();
        if self.window_clamp >= maxwin {
            self.window_clamp = maxwin;
            if app_win != 0 && maxwin > 4 * advmss {
                let w = maxwin.checked_shr(app_win).unwrap_or(0);
                self.window_clamp = (maxwin - w).max(4 * advmss);
            }
        }
        if app_win != 0 && self.window_clamp > 2 * advmss && self.window_clamp + advmss > maxwin {
            self.window_clamp = (2 * advmss).max(maxwin.saturating_sub(advmss));
        }
        self.rcv_ssthresh = self.rcv_ssthresh.min(self.window_clamp);
        self.rcvq_space = RcvqSpace {
            space: self
                .rcv_ssthresh
                .min(self.rcv_wnd_adv())
                .min(INIT_CWND * advmss),
            seq: self.copied_seq,
            time: self.tcp_mstamp,
        };
    }

    /// Linux tcp_rcv_rtt_update: `sample` us into the estimate; a
    /// window-based one (`win_dep`) only lowers it
    fn rcv_rtt_update(&mut self, sample: u32, win_dep: bool) {
        let mut new = self.rcv_rtt.rtt_us;
        let m = i64::from(sample);
        if new != 0 {
            if !win_dep {
                new = (i64::from(new) + m - i64::from(new >> 3)) as u32;
            } else if ((m << 3) as u32) < new {
                new = (m << 3) as u32;
            }
        } else {
            new = (m << 3) as u32;
        }
        self.rcv_rtt.rtt_us = new;
    }

    /// Linux tcp_rcv_rtt_measure (tcp_event_data_recv): a window's
    /// worth of data since the last measurement took one RTT
    pub(super) fn rcv_rtt_measure(&mut self) {
        if self.rcv_rtt.time != 0 {
            if before(self.rcv_nxt, self.rcv_rtt.seq) {
                return;
            }
            let d = self.tcp_mstamp.saturating_sub(self.rcv_rtt.time).max(1);
            self.rcv_rtt_update(d.min(u64::from(u32::MAX)) as u32, true);
        }
        self.rcv_rtt.seq = self.rcv_nxt.wrapping_add(self.rcv_wnd_adv());
        self.rcv_rtt.time = self.tcp_mstamp;
    }

    /// Linux tcp_rcv_rtt_measure_ts (tcp_rcv_established, after
    /// tcp_ack): a segment of at least the MSS estimate echoing a new
    /// TSval samples the time since we sent it
    pub(super) fn rcv_rtt_measure_ts(&mut self, seq_len: u32) {
        let Some(tsecr) = self.rcv_tsecr else {
            return;
        };
        if tsecr == self.rcv_rtt.last_tsecr {
            return;
        }
        self.rcv_rtt.last_tsecr = tsecr;
        if seq_len >= self.dack.rcv_mss {
            // Linux tcp_rtt_tsopt_us: ms timestamps
            let delta = self.tsval().wrapping_sub(tsecr);
            if delta < i32::MAX as u32 / 1000 {
                self.rcv_rtt_update(delta.max(1) * 1000, false);
            }
        }
    }

    /// Linux tcp_rcv_space_adjust (after the reader copied): once per
    /// receive RTT, a reader that took more than last time gets a
    /// buffer for twice that plus sixteen segments, grown with the
    /// sender's rate (tcp_moderate_rcvbuf, no fixed SO_RCVBUF, at most
    /// tcp_rmem[2]); the clamp follows
    pub(super) fn rcv_space_adjust(&mut self) {
        self.tick(self.clock);
        let time = self.tcp_mstamp.saturating_sub(self.rcvq_space.time);
        let rtt = self.rcv_rtt.rtt_us;
        if time < u64::from(rtt >> 3) || rtt == 0 {
            return;
        }
        let copied = self.copied_seq.wrapping_sub(self.rcvq_space.seq);
        if copied > self.rcvq_space.space {
            if self.cfg.moderate_rcvbuf && self.userlocks & RCVBUF_LOCK == 0 {
                self.rcvbuf_grow(copied);
            }
            self.rcvq_space.space = copied;
        }
        self.rcvq_space.seq = self.copied_seq;
        self.rcvq_space.time = self.tcp_mstamp;
    }

    /// tcp_rcv_space_adjust's growth for `copied` bytes in an RTT
    fn rcvbuf_grow(&mut self, copied: u32) {
        let space = u64::from(self.rcvq_space.space.max(1));
        let mut rcvwin = (u64::from(copied) << 1) + 16 * u64::from(self.adv_mss);
        let grow = rcvwin * (u64::from(copied) - space) / space;
        rcvwin += grow << 1;
        let rcvbuf = self
            .space_from_win(rcvwin)
            .min(u64::from(self.cfg.rmem_max)) as u32;
        if rcvbuf > self.rcvbuf {
            self.rcvbuf = rcvbuf;
            self.window_clamp = self.win_from_space(i64::from(rcvbuf)).max(0) as u32;
        }
    }

    /// Linux tcp_grow_window: an in-order or out-of-order skb of `len`
    /// payload bytes and `truesize` arrived (`uncharged`: the
    /// out-of-order one, its truesize counted already, as if not yet);
    /// while the buffer has room,
    /// raise `rcv_ssthresh` when skbs of this overhead would fit the
    /// window it allows (hk's skbs are linear: truesize_adjust leaves
    /// truesize as is)
    pub(super) fn grow_window(&mut self, len: u32, truesize: u32, uncharged: bool) {
        // Linux grows an out-of-order skb's window before charging it
        // (skb_set_owner_r follows): its truesize is not counted yet
        let space = if uncharged {
            self.win_from_space(
                i64::from(self.rcvbuf) - self.rmem_alloc() as i64 + i64::from(truesize),
            )
        } else {
            self.space()
        };
        let room = i64::from(self.window_clamp).min(space) - i64::from(self.rcv_ssthresh);
        if room <= 0 {
            return;
        }
        if mem::under_pressure() {
            self.adjust_rcv_ssthresh();
            return;
        }
        let incr = if self.win_from_space(i64::from(truesize)) <= i64::from(len) {
            2 * self.adv_mss
        } else {
            self.grow_window_slow(len, truesize)
        };
        if incr != 0 {
            let incr = incr.max(2 * len);
            self.rcv_ssthresh += (room as u32).min(incr);
            self.live.quick.set(self.live.quick.get() | 1);
        }
    }

    /// Linux __tcp_grow_window: halving the window tcp_rmem[2] allows
    /// and the skb's share of it, the skb fits a smaller window than
    /// `rcv_ssthresh` reached: grow by two segments
    fn grow_window_slow(&self, len: u32, truesize: u32) -> u32 {
        let mut ts = self.win_from_space(i64::from(truesize)) >> 1;
        let mut window = self.win_from_space(i64::from(self.cfg.rmem_max)) >> 1;
        while i64::from(self.rcv_ssthresh) <= window {
            if ts <= i64::from(len) {
                return 2 * self.dack.rcv_mss;
            }
            ts >>= 1;
            window >>= 1;
        }
        0
    }

    /// Linux tcp_event_data_recv's tail: segments of at least 128
    /// bytes may grow the window
    pub(super) fn data_grow(&mut self, len: u32, truesize: u32) {
        if len >= GROW_MIN_LEN {
            self.grow_window(len, truesize, false);
        }
    }

    /// Linux tcp_clamp_window: the buffer is full; take more of
    /// tcp_rmem[2] while memory is plentiful (no fixed SO_RCVBUF), and
    /// still over: cut `rcv_ssthresh` to two segments
    pub(super) fn clamp_window(&mut self) {
        self.live.quick.set(0);
        let rmem2 = self.cfg.rmem_max;
        let rmem = self.rmem_alloc().min(u32::MAX as usize) as u32;
        if self.rcvbuf < rmem2
            && self.userlocks & RCVBUF_LOCK == 0
            && !mem::under_pressure()
            && mem::allocated() < mem::limit(0)
        {
            self.rcvbuf = rmem.min(rmem2);
        }
        if rmem > self.rcvbuf {
            self.rcv_ssthresh = self.window_clamp.min(2 * self.adv_mss);
        }
    }

    /// TCP_WINDOW_CLAMP (Linux tcp_set_window_clamp): 0 clears it on a
    /// closed socket only; a smaller clamp lowers `rcv_ssthresh`, a
    /// larger one lets it up to the window offered. Kept in `opts` too,
    /// for the next connection and a listener's children.
    pub fn set_window_clamp(&mut self, val: i32) -> Result<(), KernelError> {
        if val == 0 {
            if self.state != super::cb::TcpState::Closed {
                return Err(KernelError::InvalidArgument);
            }
            self.window_clamp = 0;
        } else {
            // Linux compares with an unsigned bound: a negative value
            // is taken as it is, a huge clamp
            let new = if val < 0 {
                val as u32
            } else {
                (val as u32).max(MIN_WINDOW_CLAMP)
            };
            let old = self.window_clamp;
            if new != old {
                self.window_clamp = new;
                if new < old {
                    self.adjust_rcv_ssthresh_to(new);
                } else {
                    let v = self.rcv_wnd_adv().min(new);
                    self.rcv_ssthresh = self.rcv_ssthresh.max(v);
                }
            }
        }
        self.opts.window_clamp = self.window_clamp;
        Ok(())
    }

    /// SO_RCVLOWAT's value for TCP (Linux tcp_set_rcvlowat): at most
    /// half the buffer (a fixed one, else tcp_rmem[2]); an unfixed
    /// buffer grows to hold it as window, which the clamp becomes
    pub fn set_rcvlowat(&mut self, val: i32) -> i32 {
        let locked = self.userlocks & RCVBUF_LOCK != 0;
        let cap = if locked {
            self.rcvbuf
        } else {
            self.cfg.rmem_max
        } >> 1;
        let val = val.min(cap.min(i32::MAX as u32) as i32);
        if !locked {
            let space = self.space_from_win(val.max(0) as u64);
            if space > u64::from(self.rcvbuf) {
                self.rcvbuf = space.min(u64::from(u32::MAX)) as u32;
                self.window_clamp = val as u32;
            }
        }
        val
    }

    /// TCP_WINDOW_CLAMP's value (Linux tp->window_clamp)
    pub fn window_clamp(&self) -> u32 {
        self.window_clamp
    }

    /// TCP_INFO tcpi_rcv_ssthresh
    pub(super) fn rcv_ssthresh(&self) -> u32 {
        self.rcv_ssthresh
    }
}
