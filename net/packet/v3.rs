//! TPACKET_V3 receive blocks (Linux af_packet.c prb_* and
//! tpacket_rcv's block path, the kernel block descriptor queue kbdq)
//!
//! A V3 receive ring hands whole blocks to user space: packets are
//! packed into the current block (struct tpacket3_hdr each, linked by
//! tp_next_offset), and the block is closed (TP_STATUS_USER in its
//! struct tpacket_block_desc) when the next packet does not fit, or
//! when the retire timer finds it unchanged with packets in it
//! (TP_STATUS_BLK_TMO). When the next block is still the user's, the
//! queue freezes (packets dropped, tp_freeze_q_cnt) until it is given
//! back.
//!
//! Locking: the block state (`Kbdq`) is under `PacketSock.rx` (Linux
//! sk_receive_queue.lock), as is arming the retire timer; a packet is
//! placed under it and copied after it, counted in its ring's
//! `fill` (Linux blk_fill_in_prog_lock readers) until copied; closing a
//! block waits under `rx` for those copies (they never take `rx`). The
//! retire timer (`Retire`, an `ArcTimer` in `ktimers/N`) holds only a
//! `Weak` to its socket; it is stopped (sync) after a ring is swapped
//! out, and finding no V3 ring it does not re-arm.

use alloc::sync::{Arc, Weak};
use core::sync::atomic::{Ordering, fence};

use crate::mm::shared::SharedRegion;
use crate::net::dev::Tap;
use crate::net::ethernet::ETH_HLEN;
use crate::net::socket::SOCK_DGRAM;
use crate::time::timer::ArcTimer;

use super::PacketSock;
use super::ring::{
    BLK_HDR_LEN, PgRing, Req, Room, TP_STATUS_KERNEL, TP_STATUS_LOSING, TP_STATUS_USER, TPACKET_V3,
    TPACKET3_SIZE, V3_ALIGNMENT, blk_plus_priv, tpacket_align,
};

/// Block retired by the timer (Linux TP_STATUS_BLK_TMO)
pub const TP_STATUS_BLK_TMO: u32 = 1 << 5;
/// tp_feature_req_word: fill tp_rxhash
const TP_FT_REQ_FILL_RXHASH: u32 = 0x1;
/// Linux DEFAULT_PRB_RETIRE_TOV (ms)
pub const DEFAULT_PRB_RETIRE_TOV: u32 = 8;
const NS_PER_MS: u64 = 1_000_000;

/// struct tpacket_block_desc offsets
const BD_VERSION: usize = 0;
const BD_O2PRIV: usize = 4;
const BD_STATUS: usize = 8;
const BD_NUM_PKTS: usize = 12;
const BD_O2FP: usize = 16;
const BD_LEN: usize = 20;
const BD_SEQ: usize = 24;
const BD_TS_FIRST: usize = 32;
const BD_TS_LAST: usize = 40;

/// Linux TOTAL_PKT_LEN_INCL_ALIGN
fn pkt_len_aligned(len: usize) -> usize {
    len.next_multiple_of(V3_ALIGNMENT as usize)
}

/// Linux prb_calc_retire_blk_tmo: 8 ms unless the link is 1 Gb/s or
/// faster, then the time to fill a block at line rate plus 1 ms.
/// `speed` in Mb/s, None when unknown (hk keeps no ethtool link
/// settings: every device is SPEED_UNKNOWN, as lo and virtio-net)
pub fn retire_tmo(speed: Option<u32>, blk_size: u32) -> u32 {
    let Some(speed) = speed.filter(|&s| s >= 1000) else {
        return DEFAULT_PRB_RETIRE_TOV;
    };
    let div = u64::from(speed / 1000);
    let mbits = u64::from(blk_size) * 8 / (1024 * 1024);
    (mbits / div + 1) as u32
}

/// The kernel block descriptor queue (Linux struct tpacket_kbdq_core)
pub struct Kbdq {
    feature_req_word: u32,
    /// The queue froze on a block still the user's (Linux
    /// reset_pending_on_curr_blk)
    frozen: bool,
    kactive_blk_num: u32,
    /// The block the timer saw last (Linux last_kactive_blk_num)
    last_kactive_blk_num: u32,
    blk_sizeof_priv: u32,
    knum_blocks: u32,
    kblk_size: usize,
    max_frame_len: usize,
    knxt_seq_num: u64,
    /// The last packet's offset in the current block (Linux prev)
    prev: usize,
    /// Where the next packet goes in the current block
    nxt_offset: usize,
    /// Retire timeout (Linux retire_blk_tov)
    tov_ms: u32,
}

/// The retire timer of a socket's V3 ring (Linux retire_blk_timer)
pub struct Retire {
    timer: ArcTimer<Retire>,
    sk: spin::Once<Weak<PacketSock>>,
}

impl Retire {
    pub fn new() -> Self {
        Self {
            timer: ArcTimer::new(retire_expired),
            sk: spin::Once::new(),
        }
    }

    /// Set the socket once it is in its `Arc`
    pub fn attach(&self, s: &Arc<PacketSock>) {
        self.sk.call_once(|| Arc::downgrade(s));
    }
}

impl Default for Retire {
    fn default() -> Self {
        Self::new()
    }
}

/// Block `n`
fn blk(ring: &PgRing, n: u32) -> &SharedRegion {
    ring.pg.block(n as usize)
}

fn blk_status(b: &SharedRegion) -> u32 {
    b.word(BD_STATUS).load(Ordering::Acquire)
}

fn now_ts() -> (u32, u32) {
    let ns = crate::net::dgram::now();
    (
        ns.div_euclid(1_000_000_000) as u32,
        ns.rem_euclid(1_000_000_000) as u32,
    )
}

impl Kbdq {
    /// Linux init_prb_bdqc (the first block opened by the caller)
    pub fn new(req: &Req) -> Self {
        let tov_ms = if req.retire_blk_tov != 0 {
            req.retire_blk_tov
        } else {
            retire_tmo(None, req.block_size)
        };
        Self {
            feature_req_word: req.feature_req_word,
            frozen: false,
            kactive_blk_num: 0,
            last_kactive_blk_num: 0,
            blk_sizeof_priv: req.sizeof_priv,
            knum_blocks: req.block_nr,
            kblk_size: req.block_size as usize,
            max_frame_len: (u64::from(req.block_size) - blk_plus_priv(u64::from(req.sizeof_priv)))
                as usize,
            knxt_seq_num: 1,
            prev: 0,
            nxt_offset: 0,
            tov_ms,
        }
    }

    fn plus_priv(&self) -> usize {
        blk_plus_priv(u64::from(self.blk_sizeof_priv)) as usize
    }

    fn next_blk(&self) -> u32 {
        if self.kactive_blk_num < self.knum_blocks - 1 {
            self.kactive_blk_num + 1
        } else {
            0
        }
    }
}

impl PacketSock {
    /// (Re)arm the retire timer and note the block it watches, `rx`
    /// held (Linux _prb_refresh_rx_retire_blk_timer)
    fn refresh_timer(&self, k: &mut Kbdq) {
        let at = crate::time::monotonic_ns() + u64::from(k.tov_ms) * NS_PER_MS;
        self.retire.timer.reset(&self.retire, at);
        k.last_kactive_blk_num = k.kactive_blk_num;
    }

    /// Linux prb_open_block: a fresh header (the private area kept),
    /// the queue thawed, the timer refreshed
    pub(super) fn open_block(&self, k: &mut Kbdq, ring: &PgRing) {
        let b = blk(ring, k.kactive_blk_num);
        fence(Ordering::SeqCst);
        b.write::<u64>(BD_SEQ, k.knxt_seq_num);
        k.knxt_seq_num += 1;
        b.write::<u32>(BD_NUM_PKTS, 0);
        let pp = k.plus_priv();
        b.write::<u32>(BD_LEN, pp as u32);
        let (sec, nsec) = now_ts();
        b.write::<u32>(BD_TS_FIRST, sec);
        b.write::<u32>(BD_TS_FIRST + 4, nsec);
        k.nxt_offset = pp;
        b.write::<u32>(BD_O2FP, pp as u32);
        b.write::<u32>(BD_O2PRIV, BLK_HDR_LEN as u32);
        b.write::<u32>(BD_VERSION, TPACKET_V3);
        k.prev = k.nxt_offset;
        k.frozen = false;
        fence(Ordering::SeqCst);
        self.refresh_timer(k);
    }

    /// Linux prb_close_block: the block handed to user space, the next
    /// one active
    fn close_block(&self, k: &mut Kbdq, ring: &PgRing, stat: u32) {
        let b = blk(ring, k.kactive_blk_num);
        let mut status = TP_STATUS_USER | stat;
        if self.drops.load(Ordering::Relaxed) != 0 {
            status |= TP_STATUS_LOSING;
        }
        b.write::<u32>(k.prev, 0);
        let (sec, nsec) = if b.read::<u32>(BD_NUM_PKTS) != 0 {
            (b.read::<u32>(k.prev + 4), b.read::<u32>(k.prev + 8))
        } else {
            now_ts()
        };
        b.write::<u32>(BD_TS_LAST, sec);
        b.write::<u32>(BD_TS_LAST + 4, nsec);
        fence(Ordering::SeqCst);
        b.word(BD_STATUS).store(status, Ordering::Release);
        fence(Ordering::SeqCst);
        self.sk.data_ready();
        k.kactive_blk_num = k.next_blk();
    }

    /// Wait for the packets being copied into the current block (Linux
    /// write_lock/unlock of blk_fill_in_prog_lock)
    fn wait_fill(ring: &PgRing) {
        while ring.fill.load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }
    }

    /// Linux prb_retire_current_block
    fn retire_current(&self, k: &mut Kbdq, ring: &PgRing, stat: u32) {
        let b = blk(ring, k.kactive_blk_num);
        if blk_status(b) == TP_STATUS_KERNEL {
            if stat & TP_STATUS_BLK_TMO == 0 {
                Self::wait_fill(ring);
            }
            self.close_block(k, ring, stat);
        }
    }

    /// Linux prb_dispatch_next_block: the next block opened, or the
    /// queue frozen when user space still has it
    fn dispatch_next(&self, k: &mut Kbdq, ring: &PgRing) -> Option<usize> {
        fence(Ordering::SeqCst);
        if blk_status(blk(ring, k.kactive_blk_num)) & TP_STATUS_USER != 0 {
            k.frozen = true;
            self.freeze_q_cnt.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        self.open_block(k, ring);
        Some(k.nxt_offset)
    }

    /// Linux prb_fill_curr_block + prb_run_all_ft_ops: the packet's
    /// header linked in, counted as being filled
    fn fill_curr_block(&self, k: &mut Kbdq, ring: &PgRing, curr: usize, len: usize, hash: u32) {
        let b = blk(ring, k.kactive_blk_num);
        let l = pkt_len_aligned(len);
        b.write::<u32>(curr, l as u32);
        k.prev = curr;
        k.nxt_offset += l;
        b.write::<u32>(BD_LEN, b.read::<u32>(BD_LEN).wrapping_add(l as u32));
        b.write::<u32>(BD_NUM_PKTS, b.read::<u32>(BD_NUM_PKTS).wrapping_add(1));
        ring.fill.fetch_add(1, Ordering::AcqRel);
        // hv1: tp_padding, no VLAN tag (tp_status AVAILABLE), rxhash
        b.write::<u16>(curr + 38, 0);
        b.write::<u32>(curr + 32, 0);
        b.write::<u16>(curr + 36, 0);
        b.write::<u32>(curr + 20, 0);
        let h = if k.feature_req_word & TP_FT_REQ_FILL_RXHASH != 0 {
            hash
        } else {
            0
        };
        b.write::<u32>(curr + 28, h);
    }

    /// Linux __packet_lookup_frame_in_block: where a packet of `len`
    /// bytes goes in the current block (closing it and opening the
    /// next if it does not fit), None when the queue is frozen
    fn frame_in_block(
        &self,
        k: &mut Kbdq,
        ring: &PgRing,
        len: usize,
        hash: u32,
    ) -> Option<(u32, usize)> {
        if k.frozen {
            if blk_status(blk(ring, k.kactive_blk_num)) & TP_STATUS_USER != 0 {
                return None;
            }
            self.open_block(k, ring);
        }
        fence(Ordering::SeqCst);
        let curr = k.nxt_offset;
        if curr + pkt_len_aligned(len) < k.kblk_size {
            self.fill_curr_block(k, ring, curr, len, hash);
            return Some((k.kactive_blk_num, curr));
        }
        self.retire_current(k, ring, 0);
        let curr = self.dispatch_next(k, ring)?;
        self.fill_curr_block(k, ring, curr, len, hash);
        Some((k.kactive_blk_num, curr))
    }

    /// Room in a V3 ring (Linux __tpacket_v3_has_room)
    pub(super) fn v3_room(&self) -> Room {
        let rx = self.rx.lock();
        let (Some(ring), Some(k)) = (&rx.ring, &rx.kbdq) else {
            return Room::None;
        };
        let free = |pow_off: u32| {
            let len = k.knum_blocks;
            let mut idx = k.kactive_blk_num;
            if pow_off != 0 {
                idx += len >> pow_off;
            }
            if idx >= len {
                idx -= len;
            }
            blk_status(blk(ring, idx)) == TP_STATUS_KERNEL
        };
        if free(2) {
            Room::Normal
        } else if free(0) {
            Room::Low
        } else {
            Room::None
        }
    }

    /// Linux packet_poll for V3: the block before the active one is not
    /// the kernel's
    pub(super) fn v3_readable(&self, ring: &PgRing, k: &Kbdq) -> bool {
        let prev = if k.kactive_blk_num != 0 {
            k.kactive_blk_num - 1
        } else {
            k.knum_blocks - 1
        };
        blk_status(blk(ring, prev)) != TP_STATUS_KERNEL
    }

    /// Linux tpacket_rcv, TPACKET_V3: the packet packed into the
    /// current block (no per-packet wakeup: closing a block wakes)
    pub(super) fn tpacket_rcv_v3(
        &self,
        t: &Tap<'_>,
        proto: u16,
        data: &[u8],
        snaplen: usize,
        status: u32,
    ) {
        let hdrlen = self.tp_hdrlen.load(Ordering::Acquire) as usize;
        let reserve = self.tp_reserve.load(Ordering::Acquire) as usize;
        let vnet = self.vnet_hdr_len();
        let (macoff, netoff) = if self.sk.stype == SOCK_DGRAM {
            let n = tpacket_align(hdrlen) + 16 + reserve;
            (n, n)
        } else {
            let n = tpacket_align(hdrlen + ETH_HLEN.max(16)) + reserve + vnet;
            (n - ETH_HLEN, n)
        };
        if netoff > usize::from(u16::MAX) {
            self.drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let hash = super::rcv::flow_hash(t.frame, false);
        let Some((ring, bn, off, mac, snaplen)) = self.v3_claim(macoff, snaplen, hash) else {
            self.drops.fetch_add(1, Ordering::Relaxed);
            self.sk.data_ready();
            return;
        };
        let b = blk(&ring, bn);
        // Linux: no header when the frame room fell short of macoff
        let macoff = mac;
        if vnet != 0 && macoff == netoff - ETH_HLEN {
            let h = super::vnet::from_frame(status, t.frame).bytes();
            b.copy_in(
                off + macoff - super::vnet::VNET_HDR_LEN,
                &h[..super::vnet::VNET_HDR_LEN],
            );
        }
        if snaplen > 0 {
            b.copy_in(off + macoff, &data[..snaplen]);
        }
        let (sec, nsec) = now_ts();
        let st = b.read::<u32>(off + 20) | status;
        b.write::<u32>(off + 20, st);
        b.write::<u32>(off + 16, data.len() as u32);
        b.write::<u32>(off + 12, snaplen as u32);
        b.write::<u16>(off + 24, macoff as u16);
        b.write::<u16>(off + 26, netoff as u16);
        b.write::<u32>(off + 4, sec);
        b.write::<u32>(off + 8, nsec);
        b.zero(off + 40, 8);
        super::ring::Frame { r: b, off }.put_sll(TPACKET3_SIZE, &self.rx_sll(t, proto));
        fence(Ordering::SeqCst);
        // Linux prb_clear_blk_fill_status
        ring.fill.fetch_sub(1, Ordering::AcqRel);
    }

    /// Place a packet under `rx`: (ring, block, offset, macoff,
    /// snaplen), the snap cut to the block's frame room (Linux
    /// tpacket_rcv's max_frame_len clamp), the packet counted
    fn v3_claim(
        &self,
        macoff: usize,
        snaplen: usize,
        hash: u32,
    ) -> Option<(Arc<PgRing>, u32, usize, usize, usize)> {
        let mut g = self.rx.lock();
        let rx = &mut *g;
        let ring = rx.ring.clone()?;
        let k = rx.kbdq.as_mut()?;
        let (mut macoff, mut snaplen) = (macoff, snaplen);
        if macoff + snaplen > k.max_frame_len {
            match k.max_frame_len.checked_sub(macoff) {
                Some(n) => snaplen = n,
                None => {
                    snaplen = 0;
                    macoff = k.max_frame_len;
                }
            }
        }
        let (bn, off) = self.frame_in_block(k, &ring, macoff + snaplen, hash)?;
        self.packets.fetch_add(1, Ordering::Relaxed);
        Some((ring, bn, off, macoff, snaplen))
    }

    /// The retire timer fired (Linux prb_retire_rx_blk_timer_expired,
    /// 6.8's timer_list version)
    fn retire_fire(&self) {
        let mut rx = self.rx.lock();
        let rx = &mut *rx;
        // The ring was swapped out (Linux delete_blk_timer): no re-arm
        let (Some(ring), Some(k)) = (rx.ring.clone(), rx.kbdq.as_mut()) else {
            return;
        };
        let b = blk(&ring, k.kactive_blk_num);
        if b.read::<u32>(BD_NUM_PKTS) != 0 {
            Self::wait_fill(&ring);
        }
        if k.last_kactive_blk_num == k.kactive_blk_num {
            if !k.frozen {
                if b.read::<u32>(BD_NUM_PKTS) != 0 {
                    self.retire_current(k, &ring, TP_STATUS_BLK_TMO);
                    if self.dispatch_next(k, &ring).is_some() {
                        return;
                    }
                }
            } else if blk_status(b) & TP_STATUS_USER == 0 {
                // User space caught up and the link went idle: open the
                // block, which thaws the queue and re-arms the timer
                self.open_block(k, &ring);
                return;
            }
        }
        self.refresh_timer(k);
    }
}

/// The timer callback: through the socket, if it is still there
fn retire_expired(r: Arc<Retire>) {
    if let Some(s) = r.sk.get().and_then(Weak::upgrade) {
        s.retire_fire();
    }
}

/// Stop a socket's retire timer after its V3 ring went (Linux
/// prb_shutdown_retire_blk_timer); thread context, may sleep
pub fn shutdown_timer(s: &PacketSock) {
    s.retire.timer.stop_sync();
}

/// New block state for a V3 receive ring: the first block opened
pub fn init(s: &PacketSock, k: &mut Kbdq, ring: &PgRing) {
    s.freeze_q_cnt.store(0, Ordering::Relaxed);
    s.open_block(k, ring);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retire_tmo_rules() {
        assert_eq!(retire_tmo(None, 1 << 20), 8);
        assert_eq!(retire_tmo(Some(100), 1 << 20), 8);
        // 1 MiB at 1 Gb/s: 8 Mbit, + 1 ms
        assert_eq!(retire_tmo(Some(1000), 1 << 20), 9);
        assert_eq!(retire_tmo(Some(10000), 1 << 20), 1);
        // A 2 GiB block: no 32-bit overflow (Linux (u64) cast)
        assert_eq!(retire_tmo(Some(1000), 0x8000_0000), 16385);
    }

    #[test]
    fn blk_priv() {
        assert_eq!(blk_plus_priv(0), 48);
        assert_eq!(blk_plus_priv(13), 64);
        assert_eq!(blk_plus_priv(u64::from(u32::MAX)), 48 + (1 << 32));
    }
}
