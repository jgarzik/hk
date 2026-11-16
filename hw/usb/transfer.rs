//! xHCI Transfer Ring
//!
//! Transfer Rings are used for data transfers on bulk, interrupt, and control endpoints.
//! Each active endpoint has its own Transfer Ring.
//!
//! Unlike the Command Ring which is shared across all devices, each endpoint
//! has a dedicated Transfer Ring for submitting transfer TRBs.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

use crate::hw::dma::{DmaBox, DmaDevice};
use crate::mm::frame_alloc::FRAME_SIZE;
use crate::mm::page_alloc::Gfp;

/// Transfer Request Block (TRB) - same structure as in xhci.rs
/// but with additional types for data transfers
#[derive(Debug, Clone, Copy, Default)]
#[repr(C, align(16))]
pub struct Trb {
    /// Parameter (data pointer or other info)
    pub parameter: u64,
    /// Status field (transfer length, etc.)
    pub status: u32,
    /// Control field (TRB type, cycle bit, flags)
    pub control: u32,
}

impl Trb {
    /// Create a new zeroed TRB
    pub const fn new() -> Self {
        Self {
            parameter: 0,
            status: 0,
            control: 0,
        }
    }

    /// Set TRB type (bits 15:10)
    pub fn set_type(&mut self, trb_type: u8) {
        self.control = (self.control & !0xFC00) | (u32::from(trb_type) << 10);
    }

    /// Get TRB type
    pub fn get_type(&self) -> u8 {
        ((self.control >> 10) & 0x3F) as u8
    }

    /// Set cycle bit (bit 0)
    pub fn set_cycle(&mut self, cycle: bool) {
        if cycle {
            self.control |= 1;
        } else {
            self.control &= !1;
        }
    }

    /// Get cycle bit
    pub fn get_cycle(&self) -> bool {
        (self.control & 1) != 0
    }

    /// Set Interrupt On Completion flag (bit 5)
    pub fn set_ioc(&mut self, ioc: bool) {
        if ioc {
            self.control |= 1 << 5;
        } else {
            self.control &= !(1 << 5);
        }
    }

    /// Set Immediate Data flag (bit 6) - data is in parameter field
    pub fn set_idt(&mut self, idt: bool) {
        if idt {
            self.control |= 1 << 6;
        } else {
            self.control &= !(1 << 6);
        }
    }

    /// Set Chain bit (bit 4) - TRB is part of a chain
    pub fn set_chain(&mut self, chain: bool) {
        if chain {
            self.control |= 1 << 4;
        } else {
            self.control &= !(1 << 4);
        }
    }

    /// Set transfer length in status field (bits 16:0)
    pub fn set_transfer_length(&mut self, len: u32) {
        self.status = (self.status & !0x1FFFF) | (len & 0x1FFFF);
    }

    /// Get transfer length from status field
    pub fn get_transfer_length(&self) -> u32 {
        self.status & 0x1FFFF
    }

    /// Get completion code from status field (bits 31:24)
    pub fn get_completion_code(&self) -> u8 {
        ((self.status >> 24) & 0xFF) as u8
    }

    /// Set TD Size field (bits 21:17) - number of remaining packets
    pub fn set_td_size(&mut self, td_size: u8) {
        self.status = (self.status & !(0x1F << 17)) | ((u32::from(td_size) & 0x1F) << 17);
    }

    /// Set Interrupter Target (bits 31:22)
    pub fn set_interrupter_target(&mut self, target: u16) {
        self.status = (self.status & !(0x3FF << 22)) | ((u32::from(target) & 0x3FF) << 22);
    }

    /// Create a Normal TRB for data transfer
    pub fn normal(data_ptr: u64, len: u32, ioc: bool, chain: bool) -> Self {
        let mut trb = Self::new();
        trb.parameter = data_ptr;
        trb.set_type(TrbType::NORMAL);
        trb.set_transfer_length(len);
        trb.set_ioc(ioc);
        trb.set_chain(chain);
        trb
    }

    /// Create a Link TRB
    pub fn link(target: u64, toggle_cycle: bool) -> Self {
        let mut trb = Self::new();
        trb.parameter = target;
        trb.set_type(TrbType::LINK);
        if toggle_cycle {
            trb.control |= 1 << 1; // Toggle Cycle bit
        }
        trb
    }

    /// Create a Setup Stage TRB for control transfers
    pub fn setup_stage(setup: &[u8; 8], transfer_type: u8) -> Self {
        let mut trb = Self::new();
        // Setup data goes in parameter field (8 bytes)
        trb.parameter = u64::from_le_bytes(*setup);
        trb.set_type(TrbType::SETUP_STAGE);
        trb.set_transfer_length(8);
        trb.set_idt(true); // Immediate Data
        // Transfer type: 0=No Data, 2=OUT Data, 3=IN Data
        trb.control |= u32::from(transfer_type) << 16;
        trb
    }

    /// Create a Data Stage TRB for control transfers
    pub fn data_stage(data_ptr: u64, len: u32, is_in: bool) -> Self {
        let mut trb = Self::new();
        trb.parameter = data_ptr;
        trb.set_type(TrbType::DATA_STAGE);
        trb.set_transfer_length(len);
        if is_in {
            // Direction IN, and an event on a short packet (Linux sets
            // TRB_ISP for IN data stages only)
            trb.control |= (1 << 16) | (1 << 2);
        }
        trb
    }

    /// Create a Status Stage TRB for control transfers
    pub fn status_stage(is_in: bool) -> Self {
        let mut trb = Self::new();
        trb.set_type(TrbType::STATUS_STAGE);
        trb.set_ioc(true); // Always want completion for status stage
        if is_in {
            trb.control |= 1 << 16; // Direction bit
        }
        trb
    }
}

/// TRB types
#[expect(non_snake_case)]
pub mod TrbType {
    /// Normal TRB - used for bulk/interrupt data transfers
    pub const NORMAL: u8 = 1;
    /// Setup Stage TRB - first TRB in control transfer
    pub const SETUP_STAGE: u8 = 2;
    /// Data Stage TRB - data phase of control transfer
    pub const DATA_STAGE: u8 = 3;
    /// Status Stage TRB - status phase of control transfer
    pub const STATUS_STAGE: u8 = 4;
    /// Isoch TRB - isochronous transfer
    pub const ISOCH: u8 = 5;
    /// Link TRB - chain to another ring segment
    pub const LINK: u8 = 6;
    /// Event Data TRB - for event data
    pub const EVENT_DATA: u8 = 7;
    /// No Op TRB
    pub const NO_OP: u8 = 8;

    // Command TRB types (for command ring, not transfer ring)
    /// Enable Slot Command
    pub const ENABLE_SLOT: u8 = 9;
    /// Disable Slot Command
    pub const DISABLE_SLOT: u8 = 10;
    /// Address Device Command
    pub const ADDRESS_DEVICE: u8 = 11;
    /// Configure Endpoint Command
    pub const CONFIGURE_ENDPOINT: u8 = 12;
    /// Evaluate Context Command
    pub const EVALUATE_CONTEXT: u8 = 13;
    /// Reset Endpoint Command
    pub const RESET_ENDPOINT: u8 = 14;
    /// Stop Endpoint Command
    pub const STOP_ENDPOINT: u8 = 15;
    /// Set TR Dequeue Pointer Command
    pub const SET_TR_DEQUEUE: u8 = 16;
    /// Reset Device Command
    pub const RESET_DEVICE: u8 = 17;

    // Event TRB types
    /// Transfer Event
    pub const TRANSFER_EVENT: u8 = 32;
    /// Command Completion Event
    pub const COMMAND_COMPLETION: u8 = 33;
    /// Port Status Change Event
    pub const PORT_STATUS_CHANGE: u8 = 34;
    /// Bandwidth Request Event
    pub const BANDWIDTH_REQUEST: u8 = 35;
    /// Doorbell Event
    pub const DOORBELL: u8 = 36;
    /// Host Controller Event
    pub const HOST_CONTROLLER: u8 = 37;
    /// Device Notification Event
    pub const DEVICE_NOTIFICATION: u8 = 38;
    /// MFINDEX Wrap Event
    pub const MFINDEX_WRAP: u8 = 39;
}

/// TRB completion codes
#[expect(non_snake_case)]
pub mod CompletionCode {
    pub const INVALID: u8 = 0;
    pub const SUCCESS: u8 = 1;
    pub const DATA_BUFFER_ERROR: u8 = 2;
    pub const BABBLE_DETECTED: u8 = 3;
    pub const USB_TRANSACTION_ERROR: u8 = 4;
    pub const TRB_ERROR: u8 = 5;
    pub const STALL_ERROR: u8 = 6;
    pub const RESOURCE_ERROR: u8 = 7;
    pub const BANDWIDTH_ERROR: u8 = 8;
    pub const NO_SLOTS_AVAILABLE: u8 = 9;
    pub const INVALID_STREAM_TYPE: u8 = 10;
    pub const SLOT_NOT_ENABLED: u8 = 11;
    pub const ENDPOINT_NOT_ENABLED: u8 = 12;
    pub const SHORT_PACKET: u8 = 13;
    pub const RING_UNDERRUN: u8 = 14;
    pub const RING_OVERRUN: u8 = 15;
    pub const VF_EVENT_RING_FULL: u8 = 16;
    pub const PARAMETER_ERROR: u8 = 17;
    pub const BANDWIDTH_OVERRUN: u8 = 18;
    pub const CONTEXT_STATE_ERROR: u8 = 19;
    pub const NO_PING_RESPONSE: u8 = 20;
    pub const EVENT_RING_FULL: u8 = 21;
    pub const INCOMPATIBLE_DEVICE: u8 = 22;
    pub const MISSED_SERVICE: u8 = 23;
    pub const COMMAND_RING_STOPPED: u8 = 24;
    pub const COMMAND_ABORTED: u8 = 25;
    pub const STOPPED: u8 = 26;
    pub const STOPPED_LENGTH_INVALID: u8 = 27;
    pub const STOPPED_SHORT_PACKET: u8 = 28;
    pub const MAX_EXIT_LATENCY_TOO_LARGE: u8 = 29;
}

/// Largest buffer a TRB may point at, and the boundary it must not
/// cross (xHCI 6.4.1: Linux TRB_MAX_BUFF_SIZE)
pub const TRB_MAX_BUFF_SIZE: u64 = 1 << 16;

/// The TD Size field of a TRB: packets left after this one (xHCI 1.0
/// 4.11.2.4), or KiB left including it before 1.0, at most 31 (Linux
/// xhci_td_remainder)
pub fn td_remainder(
    hci_version: u16,
    transferred: usize,
    trb_len: usize,
    total: usize,
    maxp: u16,
    more_trbs: bool,
) -> u8 {
    let r = if hci_version < 0x100 {
        (total - transferred) >> 10
    } else if !more_trbs || (transferred == 0 && trb_len == 0) || trb_len == total {
        0
    } else {
        let maxp = usize::from(maxp.max(1));
        total.div_ceil(maxp) - (transferred + trb_len) / maxp
    };
    r.min(31) as u8
}

/// The Normal TRBs of a bulk or interrupt TD of `len` bytes at device
/// address `addr` (Linux xhci_queue_bulk_tx): split at 64 KiB
/// boundaries, chained, interrupt on the last, an event on a short IN
/// packet (ISP); one zero-length TRB for no data
pub fn bulk_trbs(
    addr: u64,
    len: usize,
    is_in: bool,
    maxp: u16,
    hci_version: u16,
) -> Option<alloc::vec::Vec<Trb>> {
    let count = (len as u64 + (addr & (TRB_MAX_BUFF_SIZE - 1)))
        .div_ceil(TRB_MAX_BUFF_SIZE)
        .max(1);
    let mut trbs = alloc::vec::Vec::new();
    trbs.try_reserve_exact(count as usize).ok()?;
    let mut done = 0usize;
    loop {
        let at = addr + done as u64;
        let room = (TRB_MAX_BUFF_SIZE - (at & (TRB_MAX_BUFF_SIZE - 1))) as usize;
        let n = (len - done).min(room);
        let more = done + n < len;
        let mut t = Trb::normal(at, n as u32, !more, more);
        if is_in {
            t.control |= 1 << 2; // ISP
        }
        t.set_td_size(td_remainder(hci_version, done, n, len, maxp, more));
        trbs.push(t);
        done += n;
        if !more {
            return Some(trbs);
        }
    }
}

/// Where a TD sits on its ring: `n` TRBs from index `start`, wrapping
/// past the link TRB
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TdSpan {
    pub start: usize,
    pub n: usize,
}

/// A segment's memory: its DMA allocation, or (unit tests) leaked heap
enum RingMem {
    Dma(#[expect(dead_code, reason = "owns the DMA allocation")] DmaBox),
    #[cfg(test)]
    Heap,
}

/// One segment of a transfer ring (Linux struct xhci_segment): its
/// TRBs, then a Link TRB to the next segment
struct Segment {
    #[expect(dead_code, reason = "owns the TRBs' memory")]
    mem: RingMem,
    trbs: *mut Trb,
    dma: u64,
}

/// Where the ring grew (`TransferRing::expand`): indices from `at` on
/// moved up by `by`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingShift {
    at: usize,
    by: usize,
}

impl RingShift {
    /// Index `i` after the expansion
    pub fn apply(&self, i: usize) -> usize {
        if i >= self.at { i + self.by } else { i }
    }
}

/// Transfer Ring for bulk/interrupt/control endpoint transfers: a
/// circle of segments, each `seg` TRBs then a Link TRB to the next, the
/// last one's toggling the cycle state (Linux struct xhci_ring). TRBs
/// are numbered 0..size across the segments in ring order, Link TRBs
/// apart.
///
/// Producer side only: `enqueue` is where the next TRB goes, `dequeue`
/// the first TRB of the oldest TD not yet given back (Linux
/// ring->dequeue, moved past each finished TD and by Set TR Dequeue
/// Pointer); the TRBs from one to the other are the controller's.
/// Touched only under its owner's lock (xHCI: `Xhci.lock`).
pub struct TransferRing {
    segs: alloc::vec::Vec<Segment>,
    /// TRBs per segment, its Link TRB apart (Linux TRBS_PER_SEGMENT - 1)
    seg: usize,
    /// TRBs in the ring, Link TRBs apart
    size: usize,
    /// Enqueue pointer index
    enqueue: usize,
    /// Dequeue pointer index
    dequeue: usize,
    /// Producer Cycle State
    cycle: bool,
}

// SAFETY: each segment's `trbs` points into the memory it owns (`mem`),
// touched only through `&mut self` or under the owner's lock
unsafe impl Send for TransferRing {}
// SAFETY: as above
unsafe impl Sync for TransferRing {}

impl TransferRing {
    /// TRBs per segment: a page, its last TRB the Link TRB
    pub const SEG_TRBS: usize = FRAME_SIZE / 16 - 1;
    /// Segments of a new endpoint ring (Linux xhci_endpoint_init's 2)
    const INIT_SEGS: usize = 2;

    /// A new ring of two segments
    pub fn new<D: DmaDevice>(dev: &D) -> Option<Self> {
        let mut segs = alloc::vec::Vec::new();
        segs.try_reserve_exact(Self::INIT_SEGS).ok()?;
        for _ in 0..Self::INIT_SEGS {
            segs.push(Self::dma_seg(dev, Gfp::KERNEL, true)?);
        }
        Some(Self::init(segs, Self::SEG_TRBS))
    }

    /// A zeroed DMA segment, its TRBs' cycle bits set unless `pcs` (the
    /// ring's cycle state): none is the controller's yet (Linux
    /// xhci_link_rings' TRB_CYCLE fill)
    fn dma_seg<D: DmaDevice>(dev: &D, gfp: Gfp, pcs: bool) -> Option<Segment> {
        let dma = DmaBox::alloc_gfp(dev, FRAME_SIZE, gfp)?;
        let (trbs, base) = (dma.cpu_addr().cast::<Trb>(), dma.dma_addr().as_u64());
        let s = Segment {
            mem: RingMem::Dma(dma),
            trbs,
            dma: base,
        };
        // SAFETY: the fresh page the segment owns: SEG_TRBS + 1 TRBs
        unsafe { Self::fill_seg(&s, Self::SEG_TRBS, pcs) };
        Some(s)
    }

    /// Zero `seg + 1` TRBs of `s`, cycle bits set unless `pcs`
    ///
    /// # Safety
    /// `s.trbs` points at `seg + 1` TRBs its memory keeps allocated.
    unsafe fn fill_seg(s: &Segment, seg: usize, pcs: bool) {
        // SAFETY: the caller's `seg + 1` TRBs
        unsafe { core::ptr::write_bytes(s.trbs, 0, seg + 1) };
        if !pcs {
            for i in 0..=seg {
                // SAFETY: as above
                unsafe { write_volatile(&raw mut (*s.trbs.add(i)).control, 1) };
            }
        }
    }

    /// A ring of `segs` (each `seg` TRBs and a Link TRB), linked in
    /// order
    fn init(segs: alloc::vec::Vec<Segment>, seg: usize) -> Self {
        let r = Self {
            size: segs.len() * seg,
            segs,
            seg,
            enqueue: 0,
            dequeue: 0,
            cycle: true,
        };
        for k in 0..r.segs.len() {
            r.link_seg(k);
        }
        r
    }

    /// Point segment `k`'s Link TRB at the next segment, toggling the
    /// cycle state if `k` is the last; its cycle and chain bits kept
    /// (Linux xhci_set_link_trb, LINK_TOGGLE on the last segment)
    fn link_seg(&self, k: usize) {
        let n = self.segs.len();
        let old = self.raw(k, self.seg);
        let mut link = Trb::link(self.segs[(k + 1) % n].dma, k + 1 == n);
        link.control |= old.control & (1 | 1 << 4);
        self.raw_put(k, self.seg, link);
    }

    /// TRB `off` (0..=seg) of segment `k`
    fn raw(&self, k: usize, off: usize) -> Trb {
        assert!(off <= self.seg);
        // SAFETY: one of the segment's seg + 1 TRBs
        unsafe { read_volatile(self.segs[k].trbs.add(off)) }
    }

    /// Write TRB `off` (0..=seg) of segment `k`: the first three words,
    /// then the control word with its cycle bit (Linux queue_trb's
    /// wmb), so the controller never sees a valid TRB half written
    fn raw_put(&self, k: usize, off: usize, trb: Trb) {
        assert!(off <= self.seg);
        // SAFETY: one of the segment's seg + 1 TRBs
        let p = unsafe { self.segs[k].trbs.add(off) };
        // SAFETY: as above; fields of a 16-byte TRB
        unsafe {
            write_volatile(&raw mut (*p).parameter, trb.parameter);
            write_volatile(&raw mut (*p).status, trb.status);
            fence(Ordering::SeqCst);
            write_volatile(&raw mut (*p).control, trb.control);
        }
        fence(Ordering::SeqCst);
    }

    /// TRB `i` (0..size)
    fn get(&self, i: usize) -> Trb {
        self.raw(i / self.seg, i % self.seg)
    }

    /// Write TRB `i` (0..size)
    fn put(&self, i: usize, trb: Trb) {
        self.raw_put(i / self.seg, i % self.seg, trb);
    }

    /// Whether TRB `i` is the last of its segment (its Link TRB next)
    fn seg_end(&self, i: usize) -> bool {
        (i + 1).is_multiple_of(self.seg)
    }

    /// Device address of the ring's first TRB (the endpoint context's
    /// TR Dequeue Pointer)
    pub fn dma_addr(&self) -> u64 {
        self.segs[0].dma
    }

    /// Device address of TRB `i`
    pub fn dma_of(&self, i: usize) -> u64 {
        self.segs[i / self.seg].dma + ((i % self.seg) * 16) as u64
    }

    /// The transfer TRB at device address `dma` (not a Link TRB)
    pub fn index_of(&self, dma: u64) -> Option<usize> {
        self.segs.iter().enumerate().find_map(|(k, s)| {
            let off = dma.checked_sub(s.dma)?;
            let i = usize::try_from(off / 16).ok()?;
            (off % 16 == 0 && i < self.seg).then_some(k * self.seg + i)
        })
    }

    /// Segments to add before `n` more TRBs are queued (Linux
    /// xhci_ring_expansion_needed): a TD goes only into segments the
    /// dequeue is not in, its own segment apart, and one that would
    /// fill the enqueue segment needs the next free too (a full ring
    /// must differ from an empty one)
    pub fn segs_needed(&self, n: usize) -> usize {
        let used = self.enqueue % self.seg;
        let Some(past) = (used + n).checked_sub(self.seg) else {
            return 0;
        };
        let (deq_seg, nsegs) = (self.dequeue / self.seg, self.segs.len());
        let mut k = self.enqueue / self.seg;
        let mut need = 1 + past / self.seg;
        while need > 0 {
            k = (k + 1) % nsegs;
            if k == deq_seg {
                return need;
            }
            need -= 1;
        }
        0
    }

    /// Grow by `n` segments after the enqueue segment (Linux
    /// xhci_ring_expansion, xhci_link_rings), each allocated with `gfp`
    /// and its TRBs not yet the controller's: where indices moved, for
    /// the owner's TDs. None (ring unchanged) out of memory
    pub fn expand<D: DmaDevice>(&mut self, dev: &D, n: usize, gfp: Gfp) -> Option<RingShift> {
        let mut new = alloc::vec::Vec::new();
        new.try_reserve_exact(n).ok()?;
        self.segs.try_reserve(n).ok()?;
        for _ in 0..n {
            new.push(Self::dma_seg(dev, gfp, self.cycle)?);
        }
        Some(self.insert_segs(new))
    }

    /// Link `new` in after the enqueue segment (room for them reserved
    /// in `segs`); the dequeue (never in a segment after the enqueue's)
    /// moves with what follows
    fn insert_segs(&mut self, new: alloc::vec::Vec<Segment>) -> RingShift {
        let k = self.enqueue / self.seg;
        let shift = RingShift {
            at: (k + 1) * self.seg,
            by: new.len() * self.seg,
        };
        let n = new.len();
        for (j, s) in new.into_iter().enumerate() {
            self.segs.insert(k + 1 + j, s);
        }
        self.size = self.segs.len() * self.seg;
        // The enqueue segment's link points at the first new one (no
        // longer toggling if it was the last), the last new one's at
        // what followed (toggling if now the last)
        for j in k..=k + n {
            self.link_seg(j);
        }
        self.dequeue = shift.apply(self.dequeue);
        shift
    }

    /// Enqueue the TRBs of one TD (the caller made room:
    /// `segs_needed` 0). The first is written with the wrong cycle bit
    /// and given the right one last, so the controller never starts on
    /// a partial TD (Linux giveback_first_trb)
    pub fn enqueue_td(&mut self, trbs: &[Trb]) -> TdSpan {
        let start = self.enqueue;
        let cycle = self.cycle;
        for (i, trb) in trbs.iter().enumerate() {
            self.write(*trb, if i == 0 { !self.cycle } else { self.cycle });
        }
        if !trbs.is_empty() {
            let mut t = self.get(start);
            t.set_cycle(cycle);
            self.put(start, t);
        }
        TdSpan {
            start,
            n: trbs.len(),
        }
    }

    /// Write `trb` with cycle bit `cycle` at the enqueue position and
    /// advance it; past a segment's last TRB, its Link TRB is handed to
    /// the controller with the chain bit of the TRB before it (a TD
    /// that crosses stays one TD: xHCI 4.11.5.1, Linux inc_enq), and
    /// past the last segment's the cycle state toggles
    fn write(&mut self, mut trb: Trb, cycle: bool) {
        trb.set_cycle(cycle);
        let chain = trb.control & (1 << 4);
        let i = self.enqueue;
        self.put(i, trb);
        self.enqueue = (i + 1) % self.size;
        if self.seg_end(i) {
            let k = i / self.seg;
            let mut link = self.raw(k, self.seg);
            link.control = (link.control & !(1 << 4)) | chain;
            link.set_cycle(self.cycle);
            self.raw_put(k, self.seg, link);
            if k + 1 == self.segs.len() {
                self.cycle = !self.cycle;
            }
        }
    }

    /// Whether TRB `i` belongs to `td`
    pub fn td_contains(&self, td: TdSpan, i: usize) -> bool {
        (i + self.size - td.start) % self.size < td.n
    }

    /// The last TRB of `td`
    pub fn td_end(&self, td: TdSpan) -> usize {
        (td.start + td.n - 1) % self.size
    }

    /// The TRB after `td`
    pub fn td_next(&self, td: TdSpan) -> usize {
        (td.start + td.n) % self.size
    }

    /// TRB `i` as queued
    pub fn trb(&self, i: usize) -> Trb {
        self.get(i % self.size)
    }

    /// Bytes of `td`'s TRBs before TRB `stop` (Linux sum_trb_lengths)
    pub fn sum_trb_lengths(&self, td: TdSpan, stop: usize) -> usize {
        let mut sum = 0;
        let mut i = td.start;
        while i != stop && self.td_contains(td, i) {
            let t = self.get(i);
            if t.get_type() != TrbType::NO_OP {
                sum += t.get_transfer_length() as usize;
            }
            i = (i + 1) % self.size;
        }
        sum
    }

    /// Turn `td` into No-op TRBs, cycle bits kept, chains broken, so a
    /// stopped endpoint skips it once restarted (Linux td_to_noop); a
    /// TD that crossed a segment no longer chains through its Link TRB
    pub fn td_to_noop(&mut self, td: TdSpan) {
        for k in 0..td.n {
            let i = (td.start + k) % self.size;
            let mut t = Trb::new();
            t.set_type(TrbType::NO_OP);
            t.control |= self.get(i).control & 1;
            self.put(i, t);
            if self.seg_end(i) && k + 1 < td.n {
                let s = i / self.seg;
                let mut link = self.raw(s, self.seg);
                link.control &= !(1 << 4);
                self.raw_put(s, self.seg, link);
            }
        }
    }

    /// `td` given back: the ring's dequeue moves past it (Linux
    /// xhci_dequeue_td)
    pub fn dequeue_past(&mut self, td: TdSpan) {
        self.dequeue = self.td_next(td);
    }

    /// The controller's dequeue was set to TRB `i` (Set TR Dequeue
    /// Pointer completed)
    pub fn set_dequeue(&mut self, i: usize) {
        self.dequeue = i % self.size;
    }

    /// Where a Set TR Dequeue Pointer moves a stopped endpoint to skip
    /// `td`, and the cycle state the controller is to expect there
    /// (Linux xhci_move_deq_to_next_td): the TRB after it, the first of
    /// the next TD (its cycle bit as written) or, with none queued, the
    /// enqueue position (the ring's cycle state)
    pub fn deq_past_td(&self, td: TdSpan) -> (usize, bool) {
        let to = self.td_next(td);
        let cycle = if to == self.enqueue {
            self.cycle
        } else {
            self.get(to).get_cycle()
        };
        (to, cycle)
    }

    /// A heap segment of `seg` TRBs (never freed) at device address
    /// `base`, for unit tests
    #[cfg(test)]
    fn heap_seg(seg: usize, base: u64, pcs: bool) -> Segment {
        let mem = alloc::vec![Trb::new(); seg + 1].leak();
        let s = Segment {
            mem: RingMem::Heap,
            trbs: mem.as_mut_ptr(),
            dma: base,
        };
        // SAFETY: `seg + 1` leaked TRBs
        unsafe { Self::fill_seg(&s, seg, pcs) };
        s
    }

    /// A ring of `nsegs` heap segments of `seg` TRBs, segment `k` at
    /// device address `base + k * 0x1000`, for unit tests
    #[cfg(test)]
    pub fn for_test_segs(nsegs: usize, seg: usize, base: u64) -> Self {
        let segs = (0..nsegs)
            .map(|k| Self::heap_seg(seg, base + k as u64 * 0x1000, true))
            .collect();
        Self::init(segs, seg)
    }

    /// A one-segment ring of `size` TRBs, for unit tests
    #[cfg(test)]
    pub fn for_test(size: usize, base: u64) -> Self {
        Self::for_test_segs(1, size, base)
    }

    /// `expand` with heap segments at `base + j * 0x1000`
    #[cfg(test)]
    fn expand_test(&mut self, n: usize, base: u64) -> RingShift {
        let new = (0..n)
            .map(|j| Self::heap_seg(self.seg, base + j as u64 * 0x1000, self.cycle))
            .collect();
        self.segs.reserve(n);
        self.insert_segs(new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trb_n(chain: bool) -> Trb {
        Trb::normal(0x1000, 8, !chain, chain)
    }

    /// A chained TD that wraps keeps its chain across the Link TRB;
    /// turned into No-ops, it no longer chains through it
    #[test]
    fn wrap_chains_link() {
        let mut r = TransferRing::for_test(4, 0x10_0000);
        assert!(!r.raw(0, 4).get_cycle(), "link not the controller's yet");
        let td = r.enqueue_td(&[trb_n(false), trb_n(false)]);
        assert_eq!((td.start, td.n), (0, 2));
        r.dequeue_past(td);
        let td = r.enqueue_td(&[trb_n(true), trb_n(true), trb_n(false)]);
        assert_eq!((td.start, td.n), (2, 3));
        assert_ne!(r.raw(0, 4).control & (1 << 4), 0, "link chained");
        assert!(r.td_contains(td, 3) && r.td_contains(td, 0) && !r.td_contains(td, 1));
        assert_eq!(r.td_end(td), 0);
        // cycle: the first pass wrote 1, the TRB after the link 0
        assert!(r.get(2).get_cycle() && r.get(3).get_cycle() && !r.get(0).get_cycle());
        assert!(
            r.raw(0, 4).get_cycle(),
            "link handed over on the first pass"
        );
        r.td_to_noop(td);
        assert_eq!(r.raw(0, 4).control & (1 << 4), 0, "noop unchains the link");
        assert_eq!(r.get(3).get_type(), TrbType::NO_OP);
        assert!(r.get(3).get_cycle() && !r.get(0).get_cycle());
    }

    #[test]
    fn addresses() {
        let mut r = TransferRing::for_test_segs(2, 8, 0x2000);
        let td = r.enqueue_td(&[trb_n(false); 3]);
        assert_eq!(r.index_of(r.dma_of(2)), Some(2));
        assert_eq!(r.dma_of(9), 0x3000 + 16);
        assert_eq!(r.index_of(0x3000 + 16), Some(9));
        assert_eq!(r.index_of(0x2000 + 8 * 16), None, "a link TRB");
        assert_eq!(r.index_of(0x2004), None);
        assert_eq!(r.index_of(0x1ff0), None);
        assert_eq!(r.sum_trb_lengths(td, 2), 16);
        // links: segment 0 to 1, 1 back to 0 toggling
        assert_eq!(r.raw(0, 8).parameter, 0x3000);
        assert_eq!(
            (r.raw(1, 8).parameter, r.raw(1, 8).control & 2),
            (0x2000, 2)
        );
        assert_eq!(r.raw(0, 8).control & 2, 0);
    }

    /// Linux xhci_ring_expansion_needed: a TD may fill the rest of the
    /// enqueue segment only if the next is free of the dequeue
    #[test]
    fn segs_needed() {
        let mut r = TransferRing::for_test_segs(2, 4, 0x4000);
        assert_eq!(r.segs_needed(3), 0);
        // filling segment 0 needs segment 1, free
        assert_eq!(r.segs_needed(4), 0);
        // into segment 0 again, where the dequeue is
        assert_eq!(r.segs_needed(8), 1);
        assert_eq!(r.segs_needed(13), 2);
        let td = r.enqueue_td(&[trb_n(false); 4]);
        // enqueue at 4 (segment 1); the dequeue still in segment 0
        assert_eq!(r.segs_needed(3), 0);
        assert_eq!(r.segs_needed(4), 1);
        r.dequeue_past(td);
        assert_eq!(r.segs_needed(4), 0, "dequeue left segment 0");
    }

    /// Segments go in after the enqueue segment, links rewired, the
    /// toggle on the last; indices past them move; their TRBs are not
    /// the controller's until written
    #[test]
    fn expand_after_enqueue() {
        let mut r = TransferRing::for_test_segs(2, 4, 0x10_000);
        let a = r.enqueue_td(&[trb_n(false); 4]);
        r.dequeue_past(a);
        let b = r.enqueue_td(&[trb_n(false); 2]);
        // enqueue 6 (segment 1), dequeue 4: segment 1 is the last
        let sh = r.expand_test(1, 0x20_000);
        assert_eq!(sh.apply(3), 3);
        assert_eq!(sh.apply(8), 12, "past the enqueue segment");
        assert_eq!(r.size, 12);
        assert_eq!(r.raw(1, 4).parameter, 0x20_000, "enqueue seg links to new");
        assert_eq!(r.raw(1, 4).control & 2, 0, "toggle moved off");
        assert_eq!(
            (r.raw(2, 4).parameter, r.raw(2, 4).control & 2),
            (0x10_000, 2)
        );
        assert!(!r.raw(2, 0).get_cycle(), "new TRBs not the controller's");
        assert_eq!(r.dequeue, 4);
        // the TD crossing into the new segment is one TD
        let c = r.enqueue_td(&[trb_n(true), trb_n(true), trb_n(false)]);
        assert_eq!((c.start, c.n), (6, 3));
        assert_eq!(r.td_end(c), 8);
        assert!(r.get(8).get_cycle(), "still the first pass");
        r.dequeue_past(b);
        assert_eq!(r.deq_past_td(c), (9, true));
        // in the middle: what follows moves; the dequeue with it
        let mut m = TransferRing::for_test_segs(2, 4, 0x30_000);
        let d = m.enqueue_td(&[trb_n(false); 4]);
        m.dequeue_past(d);
        let e = m.enqueue_td(&[trb_n(false); 3]);
        m.dequeue_past(e);
        let f = m.enqueue_td(&[trb_n(false); 2]);
        // enqueue 1 (segment 0, second pass), dequeue 7 (segment 1)
        assert_eq!((m.enqueue, m.dequeue, m.cycle), (1, 7, false));
        let sh = m.expand_test(1, 0x40_000);
        assert_eq!(m.dequeue, 11);
        assert_eq!(sh.apply(f.start), 11, "the queued TD moved too");
        assert_eq!(m.raw(0, 4).parameter, 0x40_000);
        assert_eq!(m.raw(1, 4).parameter, 0x30_000 + 0x1000);
        assert!(m.raw(1, 0).get_cycle(), "filled for pcs 0");
        assert_eq!(m.raw(2, 4).control & 2, 2, "old last keeps the toggle");
    }

    /// The new dequeue is the TRB after the TD: the next TD's first,
    /// with its cycle bit, or the enqueue position with the ring's
    /// cycle state
    #[test]
    fn dequeue_past_td() {
        let mut r = TransferRing::for_test(4, 0x3000);
        let a = r.enqueue_td(&[trb_n(false)]);
        r.dequeue_past(a);
        let td = r.enqueue_td(&[trb_n(true), trb_n(false)]);
        assert_eq!((td.start, td.n), (1, 2));
        // nothing queued after it: the enqueue position, cycle 1
        assert_eq!(r.deq_past_td(td), (3, true));
        r.dequeue_past(td);
        let w = r.enqueue_td(&[trb_n(true), trb_n(false)]);
        assert_eq!((w.start, w.n), (3, 2));
        // past the Link TRB: the ring's toggled cycle state
        assert_eq!(r.deq_past_td(w), (1, false));
        // a TD queued after it: its first TRB's cycle bit
        let n = r.enqueue_td(&[trb_n(false)]);
        assert_eq!(n.start, 1);
        assert_eq!(r.deq_past_td(w), (1, false));
        assert_eq!(r.deq_past_td(td), (3, true));
    }

    /// TD Size (xHCI 1.0): packets after this TRB; 0 on the last
    #[test]
    fn remainder() {
        assert_eq!(td_remainder(0x100, 0, 512, 2048, 512, true), 3);
        assert_eq!(td_remainder(0x100, 1536, 512, 2048, 512, false), 0);
        assert_eq!(td_remainder(0x100, 0, 0, 0, 512, false), 0);
        assert_eq!(td_remainder(0x100, 0, 1 << 16, 1 << 24, 512, true), 31);
        // 0.96: KiB left, this TRB included
        assert_eq!(td_remainder(0x96, 0, 512, 4096, 512, true), 4);
    }

    /// Split at each 64 KiB boundary, chained, IOC on the last only
    #[test]
    fn bulk_split() {
        let t = bulk_trbs(0xf000, 0x12000, true, 512, 0x100).unwrap();
        let lens: alloc::vec::Vec<u32> = t.iter().map(Trb::get_transfer_length).collect();
        assert_eq!(lens, [0x1000, 0x10000, 0x1000]);
        let chain = |t: &Trb| t.control & (1 << 4) != 0;
        let ioc = |t: &Trb| t.control & (1 << 5) != 0;
        assert!(chain(&t[0]) && chain(&t[1]) && !chain(&t[2]));
        assert!(!ioc(&t[0]) && !ioc(&t[1]) && ioc(&t[2]));
        assert!(t.iter().all(|t| t.control & (1 << 2) != 0), "ISP on IN");
        assert_eq!(t[1].parameter, 0x10000);
        let z = bulk_trbs(0x1000, 0, false, 64, 0x100).unwrap();
        assert_eq!(z.len(), 1);
        assert_eq!(z[0].get_transfer_length(), 0);
        assert_eq!(z[0].control & (1 << 2), 0);
        // 128 KiB never overflows a TRB's 17-bit length
        assert_eq!(bulk_trbs(0, 0x20000, false, 512, 0x100).unwrap().len(), 2);
    }
}
