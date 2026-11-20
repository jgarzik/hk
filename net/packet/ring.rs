//! AF_PACKET mmap rings (Linux af_packet.c: packet_set_ring,
//! alloc_pg_vec, packet_mmap, tpacket_rcv, packet_poll)
//!
//! A ring is tp_block_nr blocks of tp_block_size bytes (`PgVec`), cut
//! into frames of tp_frame_size bytes (TPACKET_V1/V2). Each frame
//! starts with a header whose status word hands it between the kernel
//! and user space: the kernel fills a TP_STATUS_KERNEL frame and sets
//! it TP_STATUS_USER (receive), user space gives it back by writing
//! TP_STATUS_KERNEL. All of it is user-writable at any time: the
//! kernel reads and writes it only through the region's atomics and
//! volatile copies, and bounds every offset by the geometry it checked
//! at setup.
//!
//! Locking: the receive ring's state (`PacketSock.rx`: the ring, its
//! head and frame ownership map; Linux sk_receive_queue.lock) is a spin
//! leaf but for the copy queue (`rx` -> `rxq`); a frame is claimed
//! under it, filled after it (the ring kept by an `Arc`), and released
//! under it. A ring is swapped by `set_ring` under `sk_lock` and
//! `pg_vec_lock` (sleeping, Linux po->pg_vec_lock), with the socket
//! unhooked meanwhile; never while user space maps it (`mapped`, Linux
//! po->mapped, counted per VMA), except at the last close.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering, fence};

use crate::mm::PAGE_SIZE;
use crate::mm::shared::{PgVec, SharedRegion};
use crate::mm::vma::{VmHold, VmOps};
use crate::net::dev::Tap;
use crate::net::ethernet::{ETH_ALEN, ETH_HLEN};
use crate::net::socket::{AF_PACKET, SOCK_DGRAM};
use crate::util::error::KernelError;

use super::rcv::{PktCb, frame_skb};
use super::{PacketSock, Sll, pf};

/// enum tpacket_versions
pub const TPACKET_V1: u32 = 0;
pub const TPACKET_V2: u32 = 1;
pub const TPACKET_V3: u32 = 2;

/// Frame header status words (receive)
pub const TP_STATUS_KERNEL: u32 = 0;
pub const TP_STATUS_USER: u32 = 1 << 0;
pub const TP_STATUS_COPY: u32 = 1 << 1;
pub const TP_STATUS_LOSING: u32 = 1 << 2;
pub const TP_STATUS_CSUMNOTREADY: u32 = 1 << 3;
pub const TP_STATUS_CSUM_VALID: u32 = 1 << 7;

const TPACKET_ALIGNMENT: usize = 16;

/// sizeof(struct tpacket_hdr) (64-bit: an unsigned long status),
/// struct tpacket2_hdr, struct tpacket3_hdr
pub const TPACKET1_SIZE: usize = 32;
pub const TPACKET2_SIZE: usize = 32;
pub const TPACKET3_SIZE: usize = 48;

/// TPACKET_ALIGN(x)
pub const fn tpacket_align(x: usize) -> usize {
    (x + TPACKET_ALIGNMENT - 1) & !(TPACKET_ALIGNMENT - 1)
}

/// sizeof the version's frame header (getsockopt PACKET_HDRLEN)
pub fn hdr_size(version: u32) -> usize {
    match version {
        TPACKET_V1 => TPACKET1_SIZE,
        TPACKET_V2 => TPACKET2_SIZE,
        _ => TPACKET3_SIZE,
    }
}

/// TPACKET_HDRLEN / TPACKET2_HDRLEN / TPACKET3_HDRLEN: the header,
/// aligned, then a sockaddr_ll
pub fn tp_hdrlen(version: u32) -> u32 {
    (tpacket_align(hdr_size(version)) + super::SLL_LEN) as u32
}

/// V3 block layout alignment (Linux V3_ALIGNMENT)
pub const V3_ALIGNMENT: u64 = 8;
/// ALIGN(sizeof(struct tpacket_block_desc), V3_ALIGNMENT)
pub const BLK_HDR_LEN: u64 = 48;

/// Linux BLK_PLUS_PRIV: the block descriptor and the private area,
/// computed in 64 bits (the sizeof_priv check cannot wrap)
pub const fn blk_plus_priv(sizeof_priv: u64) -> u64 {
    BLK_HDR_LEN + sizeof_priv.next_multiple_of(V3_ALIGNMENT)
}

/// struct tpacket_req3 (tpacket_req is its first four words)
#[derive(Clone, Copy, Debug, Default)]
pub struct Req {
    pub block_size: u32,
    pub block_nr: u32,
    pub frame_size: u32,
    pub frame_nr: u32,
    pub retire_blk_tov: u32,
    pub sizeof_priv: u32,
    pub feature_req_word: u32,
}

impl Req {
    /// From the user's words (4 for tpacket_req, 7 for tpacket_req3)
    pub fn parse(b: &[u8]) -> Self {
        let w = |i: usize| {
            b.get(i * 4..i * 4 + 4)
                .map_or(0, |x| u32::from_ne_bytes([x[0], x[1], x[2], x[3]]))
        };
        Self {
            block_size: w(0),
            block_nr: w(1),
            frame_size: w(2),
            frame_nr: w(3),
            retire_blk_tov: w(4),
            sizeof_priv: w(5),
            feature_req_word: w(6),
        }
    }
}

/// Frames per block of a valid ring request, else EINVAL (Linux
/// packet_set_ring's sanity tests; the per-block frame count is checked
/// against overflow before the total, CVE-2017-7308's fix)
pub fn check_req(version: u32, hdrlen: u32, reserve: u32, r: &Req) -> Result<u32, KernelError> {
    let inval = Err(KernelError::InvalidArgument);
    if r.block_size as i32 <= 0 || !(r.block_size as usize).is_multiple_of(PAGE_SIZE as usize) {
        return inval;
    }
    // reserve <= INT_MAX (PACKET_RESERVE): no u32 overflow
    let min_frame = hdrlen + reserve;
    if version >= TPACKET_V3
        && u64::from(r.block_size) < blk_plus_priv(u64::from(r.sizeof_priv)) + u64::from(min_frame)
    {
        return inval;
    }
    if r.frame_size < min_frame || !(r.frame_size as usize).is_multiple_of(TPACKET_ALIGNMENT) {
        return inval;
    }
    let fpb = r.block_size / r.frame_size;
    if fpb == 0 || fpb > u32::MAX / r.block_nr || fpb * r.block_nr != r.frame_nr {
        return inval;
    }
    Ok(fpb)
}

/// A ring's memory and fixed geometry (Linux packet_ring_buffer's
/// pg_vec, frames_per_block, frame_size, frame_max)
pub struct PgRing {
    pub pg: PgVec,
    pub frames_per_block: u32,
    pub frame_size: u32,
    /// Last frame index (tp_frame_nr - 1)
    pub frame_max: u32,
    /// V3: packets being copied into the current block (Linux
    /// blk_fill_in_prog_lock's readers)
    pub fill: AtomicU32,
}

/// A frame of a ring: its block and offset in it
#[derive(Clone, Copy)]
pub struct Frame<'a> {
    pub r: &'a SharedRegion,
    pub off: usize,
}

impl PgRing {
    /// Frame `pos` (Linux packet_lookup_frame's address)
    pub fn frame(&self, pos: u32) -> Frame<'_> {
        let b = pos / self.frames_per_block;
        let i = pos % self.frames_per_block;
        Frame {
            r: self.pg.block(b as usize),
            off: (i * self.frame_size) as usize,
        }
    }
}

impl Frame<'_> {
    /// The status word, read once (Linux __packet_get_status: smp_rmb,
    /// READ_ONCE; V1's is an unsigned long, its high bits compared too)
    pub fn status(&self, version: u32) -> u64 {
        if version == TPACKET_V1 {
            self.r.word64(self.off).load(Ordering::Acquire)
        } else {
            let o = if version == TPACKET_V3 { 20 } else { 0 };
            u64::from(self.r.word(self.off + o).load(Ordering::Acquire))
        }
    }

    /// Hand the frame over (Linux __packet_set_status: WRITE_ONCE,
    /// smp_wmb): everything written before is visible first
    pub fn set_status(&self, version: u32, st: u32) {
        if version == TPACKET_V1 {
            self.r
                .word64(self.off)
                .store(u64::from(st), Ordering::Release);
        } else {
            let o = if version == TPACKET_V3 { 20 } else { 0 };
            self.r.word(self.off + o).store(st, Ordering::Release);
        }
        fence(Ordering::SeqCst);
    }

    pub fn get32(&self, o: usize) -> u32 {
        self.r.read::<u32>(self.off + o)
    }

    pub fn get16(&self, o: usize) -> u16 {
        self.r.read::<u16>(self.off + o)
    }

    pub fn put32(&self, o: usize, v: u32) {
        self.r.write::<u32>(self.off + o, v);
    }

    pub fn put16(&self, o: usize, v: u16) {
        self.r.write::<u16>(self.off + o, v);
    }

    /// The sockaddr_ll after a header of `hsize` bytes (Linux
    /// tpacket_rcv; the address bytes past the source's six kept as
    /// they are, dev_parse_header)
    pub fn put_sll(&self, hsize: usize, sll: &Sll) {
        let o = self.off + tpacket_align(hsize);
        self.r.write::<u16>(o, AF_PACKET);
        self.r.write::<u16>(o + 2, sll.protocol.to_be());
        self.r.write::<i32>(o + 4, sll.ifindex);
        self.r.write::<u16>(o + 8, sll.hatype);
        self.r.write::<u8>(o + 10, sll.pkttype);
        self.r.write::<u8>(o + 11, sll.halen);
        self.r.copy_in(o + 12, &sll.addr[..usize::from(sll.halen)]);
    }
}

/// The receive ring's state (Linux po->rx_ring under the receive
/// queue lock)
#[derive(Default)]
pub struct RxRing {
    pub ring: Option<Arc<PgRing>>,
    /// Next frame to fill (V1/V2)
    pub head: u32,
    /// Frames claimed and being filled (Linux rx_owner_map)
    pub owner_map: Vec<u64>,
    /// TPACKET_V3 block state (Linux prb_bdqc)
    pub kbdq: Option<super::v3::Kbdq>,
}

impl RxRing {
    fn owned(&self, i: u32) -> bool {
        self.owner_map[(i / 64) as usize] & (1 << (i % 64)) != 0
    }

    fn set_owned(&mut self, i: u32, on: bool) {
        let w = &mut self.owner_map[(i / 64) as usize];
        if on {
            *w |= 1 << (i % 64);
        } else {
            *w &= !(1 << (i % 64));
        }
    }

    /// Linux packet_increment_head
    fn increment_head(&mut self, frame_max: u32) {
        self.head = if self.head != frame_max {
            self.head + 1
        } else {
            0
        };
    }
}

/// The user mappings of a socket's rings (Linux po->mapped, counted
/// by packet_mm_open/close)
#[derive(Default)]
pub struct Mapped(AtomicUsize);

impl Mapped {
    pub fn get(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }
}

impl VmOps for Mapped {
    fn open(&self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }

    fn close(&self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Room in the receive ring (Linux __packet_rcv_has_room for
/// tpacket_rcv)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Room {
    None,
    Low,
    Normal,
}

/// Linux ROOM_POW_OFF
const ROOM_POW_OFF: u32 = 2;

impl PacketSock {
    pub(super) fn version(&self) -> u32 {
        self.tp_version.load(Ordering::Acquire)
    }

    /// A ring of either direction exists (Linux rx_ring.pg_vec ||
    /// tx_ring.pg_vec)
    pub(super) fn has_ring(&self) -> bool {
        self.rx.lock().ring.is_some() || self.tx.lock().ring.is_some()
    }

    /// Frame `idx` from the head free (Linux __tpacket_has_room)
    fn frame_free(&self, rx: &RxRing, ring: &PgRing, pow_off: u32) -> bool {
        let len = ring.frame_max + 1;
        let mut idx = rx.head;
        if pow_off != 0 {
            idx += len >> pow_off;
        }
        if idx >= len {
            idx -= len;
        }
        ring.frame(idx).status(self.version()) == u64::from(TP_STATUS_KERNEL)
    }

    /// Room in the ring (Linux __packet_rcv_has_room, tpacket_rcv part)
    pub(super) fn ring_room(&self) -> Room {
        if self.version() == TPACKET_V3 {
            return self.v3_room();
        }
        let rx = self.rx.lock();
        let Some(ring) = rx.ring.clone() else {
            return Room::None;
        };
        if self.frame_free(&rx, &ring, ROOM_POW_OFF) {
            Room::Normal
        } else if self.frame_free(&rx, &ring, 0) {
            Room::Low
        } else {
            Room::None
        }
    }

    /// A filled frame is waiting (Linux packet_poll: the frame before
    /// the head is not TP_STATUS_KERNEL)
    pub(super) fn ring_readable(&self) -> bool {
        let rx = self.rx.lock();
        let Some(ring) = &rx.ring else {
            return false;
        };
        if let Some(k) = &rx.kbdq {
            return self.v3_readable(ring, k);
        }
        let prev = if rx.head != 0 {
            rx.head - 1
        } else {
            ring.frame_max
        };
        ring.frame(prev).status(self.version()) != u64::from(TP_STATUS_KERNEL)
    }

    /// Linux tpacket_rcv: copy a tapped frame into the
    /// next free ring frame, or count a drop. `data` is what the socket
    /// sees (from the link header for SOCK_RAW, the network header for
    /// SOCK_DGRAM), `snaplen` its length after the filter.
    pub(super) fn tpacket_rcv(&self, t: &Tap<'_>, proto: u16, data: &[u8], snaplen: usize) {
        if self.ring_room() == Room::None {
            self.drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let version = self.version();
        let mut status = TP_STATUS_USER | super::rcv::csum_status(t);
        if version == TPACKET_V3 {
            return self.tpacket_rcv_v3(t, proto, data, snaplen, status);
        }
        let hdrlen = self.tp_hdrlen.load(Ordering::Acquire) as usize;
        let reserve = self.tp_reserve.load(Ordering::Acquire) as usize;
        let mut vnet = self.vnet_hdr_len();
        let (macoff, netoff) = if self.sk.stype == SOCK_DGRAM {
            let n = tpacket_align(hdrlen) + 16 + reserve;
            (n, n)
        } else {
            let maclen = ETH_HLEN;
            let n = tpacket_align(hdrlen + maclen.max(16)) + reserve + vnet;
            (n - maclen, n)
        };
        if netoff > usize::from(u16::MAX) {
            self.drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let mut snaplen = snaplen;
        let mut copy = None;
        let Some(ring) = self.rx.lock().ring.clone() else {
            self.drops.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let frame_size = ring.frame_size as usize;
        if macoff + snaplen > frame_size {
            // Linux: a whole copy for recvmsg while SO_RCVBUF allows
            if self.copy_thresh.load(Ordering::Acquire) != 0 && self.rxq.has_room(&self.sk) {
                let net_off = if self.sk.stype == SOCK_DGRAM {
                    0
                } else {
                    ETH_HLEN
                };
                let cb = PktCb::copy(proto, net_off);
                copy = frame_skb(data, cb, self.sk.drops.load(Ordering::Relaxed));
            }
            snaplen = frame_size.saturating_sub(macoff);
            if macoff > frame_size {
                vnet = 0;
            }
        }
        let mut rx = self.rx.lock();
        // The ring changes only with the socket unhooked and a grace
        // period waited: still this one
        if !rx.ring.as_ref().is_some_and(|r| Arc::ptr_eq(r, &ring)) {
            drop(rx);
            self.drop_n_account();
            return;
        }
        let slot = rx.head;
        let f = ring.frame(slot);
        if f.status(version) != u64::from(TP_STATUS_KERNEL) || rx.owned(slot) {
            drop(rx);
            self.drop_n_account();
            return;
        }
        rx.set_owned(slot, true);
        rx.increment_head(ring.frame_max);
        // Clear on read: LOSING until PACKET_STATISTICS is read
        if self.drops.load(Ordering::Relaxed) != 0 {
            status |= TP_STATUS_LOSING;
        }
        self.packets.fetch_add(1, Ordering::Relaxed);
        if let Some(c) = copy {
            status |= TP_STATUS_COPY;
            self.rxq.enqueue(&self.sk, c);
        }
        drop(rx);

        if vnet != 0 {
            let h = super::vnet::from_frame(status, t.frame).bytes();
            f.r.copy_in(
                f.off + macoff - super::vnet::VNET_HDR_LEN,
                &h[..super::vnet::VNET_HDR_LEN],
            );
        }
        if snaplen > 0 {
            f.r.copy_in(f.off + macoff, &data[..snaplen]);
        }
        let ns = crate::net::dgram::now();
        let (sec, nsec) = (ns.div_euclid(1_000_000_000), ns.rem_euclid(1_000_000_000));
        let len = data.len() as u32;
        if version == TPACKET_V1 {
            f.put32(8, len);
            f.put32(12, snaplen as u32);
            f.put16(16, macoff as u16);
            f.put16(18, netoff as u16);
            f.put32(20, sec as u32);
            f.put32(24, (nsec / 1000) as u32);
        } else {
            f.put32(4, len);
            f.put32(8, snaplen as u32);
            f.put16(12, macoff as u16);
            f.put16(14, netoff as u16);
            f.put32(16, sec as u32);
            f.put32(20, nsec as u32);
            // No VLAN tag offload: tp_vlan_tci, tp_vlan_tpid 0
            f.put32(24, 0);
            f.put32(28, 0);
        }
        f.put_sll(hdr_size(version), &self.rx_sll(t, proto));
        fence(Ordering::SeqCst);
        let mut rx = self.rx.lock();
        f.set_status(version, status);
        rx.set_owned(slot, false);
        drop(rx);
        self.sk.data_ready();
    }

    /// No frame for a packet (Linux tpacket_rcv's drop_n_account)
    fn drop_n_account(&self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
        self.sk.data_ready();
    }

    /// The sockaddr_ll of a tapped frame (Linux packet_rcv,
    /// tpacket_rcv: dev_parse_header's source address)
    pub(super) fn rx_sll(&self, t: &Tap<'_>, proto: u16) -> Sll {
        let mut sll = Sll {
            protocol: proto,
            ifindex: t.dev.ifindex() as i32,
            hatype: t.dev.link().dev_type,
            pkttype: t.pkt_type.num(),
            halen: ETH_ALEN as u8,
            addr: [0; 8],
        };
        sll.addr[..ETH_ALEN].copy_from_slice(&t.frame[6..12]);
        sll
    }
}

// ============================================================================
// Ring setup (Linux packet_set_ring)
// ============================================================================

/// Set up (`req.block_nr` != 0) or tear down a ring, `sk_lock` held
/// (Linux packet_set_ring: EBUSY while mapped or when a ring exists;
/// the socket unhooked across the swap)
pub fn set_ring(s: &PacketSock, req: &Req, closing: bool, tx: bool) -> Result<(), KernelError> {
    // Linux: busy while mapped or while TX frames are in flight
    // (packet_read_pending)
    let pending = || tx && s.tx_pending.load(Ordering::Acquire) != 0;
    if !closing && (s.mapped.get() != 0 || pending()) {
        return Err(KernelError::Busy);
    }
    let version = s.version();
    let mut new = RxRing::default();
    if req.block_nr != 0 {
        let exists = if tx {
            s.tx.lock().ring.is_some()
        } else {
            s.rx.lock().ring.is_some()
        };
        if exists {
            return Err(KernelError::Busy);
        }
        let hdrlen = tp_hdrlen(version);
        s.tp_hdrlen.store(hdrlen, Ordering::Release);
        let reserve = s.tp_reserve.load(Ordering::Acquire);
        let fpb = check_req(version, hdrlen, reserve, req)?;
        // Block transmit is not supported (Linux)
        if version == TPACKET_V3
            && tx
            && (req.retire_blk_tov != 0 || req.sizeof_priv != 0 || req.feature_req_word != 0)
        {
            return Err(KernelError::InvalidArgument);
        }
        let pg = PgVec::new(req.block_nr as usize, req.block_size as usize)?;
        if version == TPACKET_V3 && !tx {
            new.kbdq = Some(super::v3::Kbdq::new(req));
        } else if !tx {
            new.owner_map = crate::util::kmem::try_vec((req.frame_nr as usize).div_ceil(64), 0u64)?;
        }
        new.ring = Some(crate::util::kalloc::try_arc(PgRing {
            pg,
            frames_per_block: fpb,
            frame_size: req.frame_size,
            frame_max: req.frame_nr - 1,
            fill: AtomicU32::new(0),
        })?);
    } else if req.frame_nr != 0 {
        return Err(KernelError::InvalidArgument);
    }

    // Detach the socket from the network (Linux: po->num 0, unhooked)
    let (was_running, num) = {
        let g = s.bind_lock.lock();
        let was = s.flag(pf::RUNNING);
        let (num, ifindex) = s.bound();
        s.bind.store(super::pack(0, ifindex), Ordering::Release);
        let _g = s.unregister_hook(g, false);
        (was, num)
    };
    crate::sync::rcu::synchronize();

    let mut r = Ok(());
    let old = {
        let _pg = s.pg_vec_lock.lock();
        if (closing || s.mapped.get() == 0) && !(!closing && pending()) {
            if tx {
                let mut t = s.tx.lock();
                let old = t.ring.take();
                t.ring = new.ring.take();
                t.head = 0;
                drop(t);
                Some(RxRing {
                    ring: old,
                    ..RxRing::default()
                })
            } else {
                let mut rx = s.rx.lock();
                let old = core::mem::replace(&mut *rx, new);
                s.set_flag(pf::TPACKET, rx.ring.is_some());
                // Linux init_prb_bdqc: the first block opened, the
                // retire timer armed
                let st = &mut *rx;
                if let (Some(ring), Some(k)) = (&st.ring, st.kbdq.as_mut()) {
                    super::v3::init(s, k, ring);
                }
                drop(rx);
                s.rxq.clear();
                Some(old)
            }
        } else {
            r = Err(KernelError::Busy);
            None
        }
    };

    {
        let g = s.bind_lock.lock();
        let (_, ifindex) = s.bound();
        s.bind.store(super::pack(num, ifindex), Ordering::Release);
        // NETDEV_UNREGISTER may have unbound it meanwhile: no hook on a
        // dead device (Linux 42156f93d123)
        if was_running && ifindex != -1 {
            s.register_hook(&g);
        }
    }
    // A V3 ring's retire timer stops once the ring is out (Linux
    // prb_shutdown_retire_blk_timer); the old ring goes after the
    // unlock, pages still mapped stay until their mapping goes
    if old.as_ref().is_some_and(|o| o.kbdq.is_some()) {
        super::v3::shutdown_timer(s);
    }
    drop(old);
    r
}

/// Linux packet_mmap's size check and accounting: the mapping covers
/// both rings exactly, from offset 0 (checked by `mmap_offset`)
pub fn mmap_hold(s: &PacketSock, len: u64) -> Result<Option<VmHold>, KernelError> {
    let _pg = s.pg_vec_lock.lock();
    let rx = s.rx.lock().ring.as_ref().map_or(0, |r| r.pg.pages());
    let pages = rx + s.tx.lock().ring.as_ref().map_or(0, |r| r.pg.pages());
    let expected = pages as u64 * PAGE_SIZE;
    if expected == 0 || len != expected {
        return Err(KernelError::InvalidArgument);
    }
    s.mapped.open();
    Ok(Some(VmHold::new(s.mapped.clone())))
}

/// Page `idx` of the mapping: the receive ring's pages, then the
/// transmit ring's (Linux packet_mmap)
pub fn map_page(s: &PacketSock, idx: u64) -> Option<u64> {
    let mut idx = idx;
    if let Some(r) = s.rx.lock().ring.clone() {
        if idx < r.pg.pages() as u64 {
            return r.pg.map_page(idx);
        }
        idx -= r.pg.pages() as u64;
    }
    let r = s.tx.lock().ring.clone()?;
    r.pg.map_page(idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(bs: u32, bn: u32, fs: u32, fnr: u32) -> Req {
        Req {
            block_size: bs,
            block_nr: bn,
            frame_size: fs,
            frame_nr: fnr,
            ..Default::default()
        }
    }

    #[test]
    fn hdrlens() {
        assert_eq!(tp_hdrlen(TPACKET_V1), 52);
        assert_eq!(tp_hdrlen(TPACKET_V2), 52);
        assert_eq!(tp_hdrlen(TPACKET_V3), 68);
    }

    #[test]
    fn check_req_rules() {
        let h = tp_hdrlen(TPACKET_V2);
        assert_eq!(check_req(TPACKET_V2, h, 0, &req(4096, 4, 2048, 8)), Ok(2));
        let e = Err(KernelError::InvalidArgument);
        // block size not a page multiple, negative as int
        assert_eq!(check_req(TPACKET_V2, h, 0, &req(4000, 4, 2048, 8)), e);
        assert_eq!(
            check_req(TPACKET_V2, h, 0, &req(0x8000_0000, 1, 2048, 1 << 20)),
            e
        );
        // frame too small, misaligned, over the block
        assert_eq!(check_req(TPACKET_V2, h, 0, &req(4096, 1, 48, 85)), e);
        assert_eq!(check_req(TPACKET_V2, h, 0, &req(4096, 1, 2056, 1)), e);
        assert_eq!(check_req(TPACKET_V2, h, 0, &req(4096, 1, 8192, 0)), e);
        // reserve counts in the minimum frame
        assert_eq!(check_req(TPACKET_V2, h, 4050, &req(8192, 1, 4096, 2)), e);
        // frame count must match
        assert_eq!(check_req(TPACKET_V2, h, 0, &req(4096, 4, 2048, 9)), e);
        // fpb * block_nr wrapping to tp_frame_nr (CVE-2017-7308)
        assert_eq!(
            check_req(TPACKET_V2, h, 0, &req(1 << 30, 1 << 16, 16 << 0x4, 0)),
            e
        );
        assert_eq!(
            check_req(TPACKET_V2, h, 0, &req(4096, 0x8000_0001, 2048, 2)),
            e
        );
    }
}
