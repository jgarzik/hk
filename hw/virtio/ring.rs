//! Split virtqueue ring logic (virtio 1.2 section 2.7)
//!
//! Linux reference: drivers/virtio/virtio_ring.c (split ring, indirect
//! descriptors, event index).
//!
//! [`Vring`] works on raw ring memory the caller provides (coherent DMA
//! memory in the kernel, a heap buffer in host unit tests), so the index
//! math, free list and barrier placement are tested on the host.
//!
//! Memory layout (one allocation, little-endian fields):
//!
//! ```text
//! 0               descriptor table: num x {addr u64, len u32, flags u16, next u16}
//! avail           avail ring: flags u16, idx u16, ring[num] u16, (used_event u16)
//! used (64-al.)   used ring:  flags u16, idx u16, ring[num] {id u32, len u32}, (avail_event u16)
//! ```
//!
//! The free list and descriptor chains are tracked in a driver-private
//! shadow (`next`, Linux `desc_extra`): the driver never trusts link
//! fields in memory the device can write.
//!
//! Indirect descriptors (VIRTIO_RING_F_INDIRECT_DESC, spec 2.7.5.3): a
//! request's chain is written to a table of its own ([`set_chain`],
//! Linux alloc_indirect_split), which the caller allocates and DMA-maps;
//! one ring descriptor points at it ([`Vring::add_indirect`]), so a big
//! request takes one ring slot instead of one per buffer.
//!
//! Event index (VIRTIO_RING_F_EVENT_IDX, spec 2.7.7, 2.7.10): with it
//! negotiated ([`Vring::set_event_idx`]) the flags are hints the other
//! side ignores. The device publishes `avail_event` (after the used
//! ring): the driver notifies only when its new avail index passes it
//! since the last notification (Linux virtqueue_kick_prepare_split,
//! [`need_event`]). The driver publishes `used_event` (after the avail
//! ring): the device interrupts only when its used index passes it, so
//! the driver moves it to the next entry it will consume whenever it
//! wants interrupts (`get`, `enable_cb`).
#![expect(clippy::undocumented_unsafe_blocks)] // TODO(unsafe): SAFETY comments (doc/UNSAFE.md)

use alloc::vec;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

use crate::arch::barrier::{dma_rmb, dma_wmb};

/// Descriptor continues via `next`
const VRING_DESC_F_NEXT: u16 = 1;
/// Buffer is device-writable
const VRING_DESC_F_WRITE: u16 = 2;
/// Buffer is a table of descriptors
const VRING_DESC_F_INDIRECT: u16 = 4;
/// Driver: do not interrupt on used buffers (a hint)
const VRING_AVAIL_F_NO_INTERRUPT: u16 = 1;
/// Device: do not notify on available buffers (a hint)
const VRING_USED_F_NO_NOTIFY: u16 = 1;

/// Largest queue we use (also bounds memory per queue)
pub const VRING_MAX: u16 = 256;

/// One scatter-gather element: a DMA address and length
#[derive(Clone, Copy, Debug)]
pub struct Sg {
    pub addr: u64,
    pub len: u32,
}

/// Errors from [`Vring::add`]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VqError {
    /// Not enough free descriptors
    NoSpace,
    /// No buffers given
    Empty,
}

/// One descriptor (struct vring_desc), little-endian: in the ring, or
/// in an indirect table
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Desc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

impl Desc {
    /// The buffer it describes
    pub fn sg(&self) -> Sg {
        Sg {
            addr: u64::from_le(self.addr),
            len: u32::from_le(self.len),
        }
    }
}

/// Flags of descriptor `k` of a chain of `total`: device-writable if
/// `write`, linked to the next unless last
fn chain_flags(write: bool, k: usize, total: usize) -> u16 {
    let mut flags = if write { VRING_DESC_F_WRITE } else { 0 };
    if k + 1 < total {
        flags |= VRING_DESC_F_NEXT;
    }
    flags
}

/// Entry `k` of a chain written to `table`, which holds exactly the
/// chain (Linux alloc_indirect_split + virtqueue_add_desc_split): buffer
/// `sg`, device-writable if `write`, linked to entry k + 1 unless last.
/// The device-readable buffers must come first
pub fn set_chain(table: &mut [Desc], k: usize, sg: Sg, write: bool) {
    let flags = chain_flags(write, k, table.len());
    table[k] = Desc {
        addr: sg.addr.to_le(),
        len: sg.len.to_le(),
        flags: flags.to_le(),
        // Truncation only on the last entry, whose link is unused
        next: ((k + 1) as u16).to_le(),
    };
}

const _: () = assert!(core::mem::size_of::<Desc>() == 16);

/// Byte offsets of the three parts in one allocation
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub avail: usize,
    pub used: usize,
    pub size: usize,
}

impl Layout {
    /// Layout for `num` entries (a power of two)
    pub fn new(num: u16) -> Self {
        let n = num as usize;
        let avail = 16 * n;
        // used ring: 4-byte alignment required; a cache line keeps the
        // device-written part apart from the driver-written one
        let used = (avail + 6 + 2 * n).next_multiple_of(64);
        Self {
            avail,
            used,
            size: used + 6 + 8 * n,
        }
    }
}

/// Queue size to use for a device maximum `max` (0 = queue absent)
pub fn pick_size(max: u16) -> Option<u16> {
    if max == 0 {
        return None;
    }
    // Split rings may have any size up to 32768 in virtio 1.x, but the
    // index math below wants a power of two (all real devices use one)
    let n = max.min(VRING_MAX);
    Some(if n.is_power_of_two() {
        n
    } else {
        1 << (15 - n.leading_zeros())
    })
}

/// Split ring state (driver side)
pub struct Vring {
    num: u16,
    base: *mut u8,
    lay: Layout,
    /// Head of the free descriptor list
    free_head: u16,
    num_free: u16,
    /// Our copy of avail.idx (free-running)
    avail_idx: u16,
    /// Next used-ring entry to consume (free-running)
    last_used: u16,
    /// Shadow links: free list and chains
    next: Vec<u16>,
    /// Descriptors in the chain starting at each head (0 = not a head)
    chain: Vec<u16>,
    /// Caller's token per chain head
    tokens: Vec<usize>,
    /// The device returned an invalid used entry
    broken: bool,
    /// VIRTIO_RING_F_EVENT_IDX was negotiated
    event: bool,
    /// `avail_idx` when the device was last asked about a notification
    kicked: u16,
}

// The ring memory is owned by the queue; access is serialized by its owner
unsafe impl Send for Vring {}
unsafe impl Sync for Vring {}

impl Vring {
    /// Set up a ring of `num` (power of two) entries over zeroed memory at
    /// `base` of at least `Layout::new(num).size` bytes, 64-byte aligned
    ///
    /// # Safety
    /// `base` must stay valid and unaliased (except by the device) for the
    /// life of the ring.
    pub unsafe fn new(base: *mut u8, num: u16) -> Self {
        debug_assert!(num.is_power_of_two());
        let n = num as usize;
        let mut next = vec![0u16; n];
        for (i, l) in next.iter_mut().enumerate() {
            *l = (i + 1) as u16;
        }
        Self {
            num,
            base,
            lay: Layout::new(num),
            free_head: 0,
            num_free: num,
            avail_idx: 0,
            last_used: 0,
            next,
            chain: vec![0; n],
            tokens: vec![0; n],
            broken: false,
            event: false,
            kicked: 0,
        }
    }

    /// Use the event index (VIRTIO_RING_F_EVENT_IDX negotiated), before
    /// the first buffer
    pub fn set_event_idx(&mut self) {
        self.event = true;
    }

    pub fn num(&self) -> u16 {
        self.num
    }

    pub fn num_free(&self) -> u16 {
        self.num_free
    }

    pub fn is_broken(&self) -> bool {
        self.broken
    }

    fn desc(&self, i: u16) -> *mut Desc {
        unsafe { self.base.cast::<Desc>().add(i as usize) }
    }

    fn avail16(&self, i: usize) -> *mut u16 {
        unsafe { self.base.add(self.lay.avail).cast::<u16>().add(i) }
    }

    fn used16(&self, i: usize) -> *mut u16 {
        unsafe { self.base.add(self.lay.used).cast::<u16>().add(i) }
    }

    fn used_elem(&self, slot: u16) -> *const u32 {
        unsafe { (self.base.add(self.lay.used + 4) as *const u32).add(2 * slot as usize) }
    }

    /// Expose a chain of `out` (device-readable) then `inb`
    /// (device-writable) buffers; `token` comes back from [`Vring::get`]
    pub fn add(&mut self, out: &[Sg], inb: &[Sg], token: usize) -> Result<(), VqError> {
        let total = out.len() + inb.len();
        if total == 0 {
            return Err(VqError::Empty);
        }
        if total > self.num_free as usize {
            return Err(VqError::NoSpace);
        }
        let head = self.free_head;
        let mut i = head;
        for (k, sg) in out.iter().chain(inb).enumerate() {
            let flags = chain_flags(k >= out.len(), k, total);
            let d = self.desc(i);
            unsafe {
                write_volatile(&raw mut (*d).addr, sg.addr.to_le());
                write_volatile(&raw mut (*d).len, sg.len.to_le());
                write_volatile(&raw mut (*d).flags, flags.to_le());
                write_volatile(&raw mut (*d).next, self.next[i as usize].to_le());
            }
            i = self.next[i as usize];
        }
        self.free_head = i;
        self.publish(head, total as u16, token);
        Ok(())
    }

    /// Expose a chain written by [`set_chain`] as direct ring
    /// descriptors, for a device without indirect descriptors
    pub fn add_chain(&mut self, table: &[Desc], token: usize) -> Result<(), VqError> {
        let total = table.len();
        if total == 0 {
            return Err(VqError::Empty);
        }
        if total > self.num_free as usize {
            return Err(VqError::NoSpace);
        }
        let head = self.free_head;
        let mut i = head;
        for t in table {
            let d = self.desc(i);
            unsafe {
                write_volatile(&raw mut (*d).addr, t.addr);
                write_volatile(&raw mut (*d).len, t.len);
                write_volatile(&raw mut (*d).flags, t.flags);
                write_volatile(&raw mut (*d).next, self.next[i as usize].to_le());
            }
            i = self.next[i as usize];
        }
        self.free_head = i;
        self.publish(head, total as u16, token);
        Ok(())
    }

    /// Expose an indirect table of `n` descriptors at DMA address
    /// `table` (written by [`set_chain`], mapped for the device until
    /// `token` comes back from [`Vring::get`]): one ring descriptor
    pub fn add_indirect(&mut self, table: u64, n: u16, token: usize) -> Result<(), VqError> {
        if n == 0 {
            return Err(VqError::Empty);
        }
        if self.num_free == 0 {
            return Err(VqError::NoSpace);
        }
        let head = self.free_head;
        let d = self.desc(head);
        unsafe {
            write_volatile(&raw mut (*d).addr, table.to_le());
            write_volatile(&raw mut (*d).len, (u32::from(n) * 16).to_le());
            write_volatile(&raw mut (*d).flags, VRING_DESC_F_INDIRECT.to_le());
            write_volatile(&raw mut (*d).next, 0);
        }
        self.free_head = self.next[head as usize];
        self.publish(head, 1, token);
        Ok(())
    }

    /// Account the chain of `n` ring descriptors at `head` and make it
    /// available to the device
    fn publish(&mut self, head: u16, n: u16, token: usize) {
        self.num_free -= n;
        self.chain[head as usize] = n;
        self.tokens[head as usize] = token;

        // Publish the head in the avail ring, then the index that covers
        // it: the device must see the descriptors and the entry first
        let slot = (self.avail_idx & (self.num - 1)) as usize;
        unsafe { write_volatile(self.avail16(2 + slot), head.to_le()) };
        self.avail_idx = self.avail_idx.wrapping_add(1);
        dma_wmb();
        unsafe { write_volatile(self.avail16(1), self.avail_idx.to_le()) };
    }

    /// After [`Vring::add`]s: true if the device wants a notification
    /// for the buffers added since the last call (Linux
    /// virtqueue_kick_prepare_split)
    pub fn needs_notify(&mut self) -> bool {
        // The new avail.idx before the used ring's event or flags read
        fence(Ordering::SeqCst);
        let (old, new) = (self.kicked, self.avail_idx);
        self.kicked = new;
        if self.event {
            let ev = u16::from_le(unsafe { read_volatile(self.avail_event()) });
            return need_event(ev, new, old);
        }
        let f = u16::from_le(unsafe { read_volatile(self.used16(0)) });
        f & VRING_USED_F_NO_NOTIFY == 0
    }

    /// The device's avail_event, after the used ring (spec 2.7.8)
    fn avail_event(&self) -> *mut u16 {
        self.used16(2 + 4 * self.num as usize)
    }

    /// Our used_event, after the avail ring (spec 2.7.6)
    fn used_event(&self) -> *mut u16 {
        self.avail16(2 + self.num as usize)
    }

    /// Callbacks are wanted: the avail flags (our own; with the event
    /// index the device ignores them) lack NO_INTERRUPT
    fn cb_wanted(&self) -> bool {
        u16::from_le(unsafe { read_volatile(self.avail16(0)) }) & VRING_AVAIL_F_NO_INTERRUPT == 0
    }

    fn used_idx(&self) -> u16 {
        u16::from_le(unsafe { read_volatile(self.used16(1)) })
    }

    /// The device has returned buffers we have not consumed
    pub fn more_used(&self) -> bool {
        self.last_used != self.used_idx()
    }

    /// Next completed chain: (token, bytes the device wrote)
    pub fn get(&mut self) -> Option<(usize, u32)> {
        if self.broken || !self.more_used() {
            return None;
        }
        // used.idx before the entry it covers
        dma_rmb();
        let e = self.used_elem(self.last_used & (self.num - 1));
        let id = u32::from_le(unsafe { read_volatile(e) });
        let len = u32::from_le(unsafe { read_volatile(e.add(1)) });
        if id >= u32::from(self.num) || self.chain[id as usize] == 0 {
            // Linux BAD_RING: stop using the queue
            self.broken = true;
            return None;
        }
        self.last_used = self.last_used.wrapping_add(1);
        // The next interrupt for the entry after this one, if wanted
        // (Linux virtqueue_get_buf_ctx_split: virtio_store_mb)
        if self.event && self.cb_wanted() {
            unsafe { write_volatile(self.used_event(), self.last_used.to_le()) };
            fence(Ordering::SeqCst);
        }
        let token = self.tokens[id as usize];
        self.detach(id as u16);
        Some((token, len))
    }

    /// Return a completed chain's descriptors to the free list
    fn detach(&mut self, head: u16) {
        let n = self.chain[head as usize];
        self.chain[head as usize] = 0;
        let mut tail = head;
        for _ in 1..n {
            tail = self.next[tail as usize];
        }
        self.next[tail as usize] = self.free_head;
        self.free_head = head;
        self.num_free += n;
    }

    /// Ask the device not to interrupt for used buffers (a hint; callable
    /// from IRQ context through [`VringCb`])
    pub fn disable_cb(&self) {
        self.cb().disable();
    }

    /// Re-enable used-buffer interrupts; false if buffers are already
    /// pending (the caller must poll again: Linux virtqueue_enable_cb)
    pub fn enable_cb(&self) -> bool {
        unsafe { write_volatile(self.avail16(0), 0) };
        if self.event {
            // An interrupt for the next entry consumed (Linux
            // virtqueue_enable_cb_prepare_split)
            unsafe { write_volatile(self.used_event(), self.last_used.to_le()) };
        }
        // flags (and used_event) store before the used.idx load
        fence(Ordering::SeqCst);
        !self.more_used()
    }

    /// IRQ-safe handle on the interrupt-suppression flag
    pub fn cb(&self) -> VringCb {
        VringCb {
            avail_flags: self.avail16(0),
        }
    }
}

/// The other side asked for an event at index `event`: true if moving
/// an index from `old` to `new` passes it (spec 2.7.10, Linux
/// vring_need_event)
pub fn need_event(event: u16, new: u16, old: u16) -> bool {
    new.wrapping_sub(event).wrapping_sub(1) < new.wrapping_sub(old)
}

/// Lock-free handle that lets an ISR suppress further used-buffer
/// interrupts without the queue's lock (Linux virtqueue_disable_cb from
/// a vring interrupt)
#[derive(Clone, Copy)]
pub struct VringCb {
    avail_flags: *mut u16,
}

unsafe impl Send for VringCb {}
unsafe impl Sync for VringCb {}

impl VringCb {
    pub fn disable(&self) {
        unsafe { write_volatile(self.avail_flags, VRING_AVAIL_F_NO_INTERRUPT.to_le()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ring memory plus a minimal device model
    struct Fake {
        mem: Vec<u64>,
        ring: Vring,
        /// Device's next avail entry
        dev_avail: u16,
        /// Device's used.idx
        dev_used: u16,
    }

    impl Fake {
        fn new(num: u16) -> Self {
            let mut mem = vec![0u64; Layout::new(num).size.div_ceil(8)];
            let ring = unsafe { Vring::new(mem.as_mut_ptr() as *mut u8, num) };
            Self {
                mem,
                ring,
                dev_avail: 0,
                dev_used: 0,
            }
        }

        fn base(&self) -> *mut u8 {
            self.mem.as_ptr() as *mut u8
        }

        fn rd16(&self, off: usize) -> u16 {
            unsafe { read_volatile(self.base().add(off) as *const u16) }
        }

        fn wr16(&self, off: usize, v: u16) {
            unsafe { write_volatile(self.base().add(off) as *mut u16, v) }
        }

        /// Device: take the next available chain; (head, descriptors)
        fn pop(&mut self) -> Option<(u16, Vec<(u64, u32, u16)>)> {
            let lay = self.ring.lay;
            let num = self.ring.num;
            if self.rd16(lay.avail + 2) == self.dev_avail {
                return None;
            }
            let slot = (self.dev_avail & (num - 1)) as usize;
            let head = self.rd16(lay.avail + 4 + 2 * slot);
            self.dev_avail = self.dev_avail.wrapping_add(1);
            let mut v = Vec::new();
            let mut i = head;
            loop {
                let d = unsafe { &*(self.base() as *const Desc).add(i as usize) };
                v.push((d.addr, d.len, d.flags));
                assert!(v.len() <= num as usize, "descriptor loop");
                if d.flags & VRING_DESC_F_NEXT == 0 {
                    break;
                }
                i = d.next;
            }
            Some((head, v))
        }

        /// Device: complete chain `head` having written `len` bytes
        fn push(&mut self, head: u16, len: u32) {
            let lay = self.ring.lay;
            let slot = (self.dev_used & (self.ring.num - 1)) as usize;
            let e = unsafe { (self.base().add(lay.used + 4) as *mut u32).add(2 * slot) };
            unsafe {
                write_volatile(e, head as u32);
                write_volatile(e.add(1), len);
            }
            self.dev_used = self.dev_used.wrapping_add(1);
            self.wr16(lay.used + 2, self.dev_used);
        }
    }

    fn sg(addr: u64, len: u32) -> Sg {
        Sg { addr, len }
    }

    #[test]
    fn layout_and_size() {
        let l = Layout::new(256);
        assert_eq!(l.avail, 4096);
        assert_eq!(l.used % 64, 0);
        assert!(l.used >= l.avail + 6 + 512);
        assert_eq!(l.size, l.used + 6 + 8 * 256);
        assert_eq!(pick_size(0), None);
        assert_eq!(pick_size(1024), Some(256));
        assert_eq!(pick_size(128), Some(128));
        assert_eq!(pick_size(200), Some(128));
    }

    #[test]
    fn add_get_roundtrip_and_flags() {
        let mut f = Fake::new(8);
        f.ring
            .add(&[sg(0x1000, 12), sg(0x2000, 100)], &[sg(0x3000, 64)], 42)
            .unwrap();
        assert_eq!(f.ring.num_free(), 5);
        let (head, chain) = f.pop().unwrap();
        assert_eq!(
            chain,
            [
                (0x1000, 12, VRING_DESC_F_NEXT),
                (0x2000, 100, VRING_DESC_F_NEXT),
                (0x3000, 64, VRING_DESC_F_WRITE)
            ]
        );
        assert!(f.ring.get().is_none());
        f.push(head, 64);
        assert_eq!(f.ring.get(), Some((42, 64)));
        assert_eq!(f.ring.num_free(), 8);
        assert!(f.ring.get().is_none());
        assert_eq!(f.ring.add(&[], &[], 0), Err(VqError::Empty));
    }

    #[test]
    fn full_ring_and_free_list_reuse() {
        let mut f = Fake::new(4);
        for t in 0..4 {
            f.ring.add(&[sg(t as u64, 1)], &[], t).unwrap();
        }
        assert_eq!(f.ring.add(&[sg(9, 1)], &[], 9), Err(VqError::NoSpace));
        // Complete out of order: 2, 0
        let heads: Vec<u16> = (0..4).map(|_| f.pop().unwrap().0).collect();
        f.push(heads[2], 0);
        f.push(heads[0], 0);
        assert_eq!(f.ring.get().map(|g| g.0), Some(2));
        assert_eq!(f.ring.get().map(|g| g.0), Some(0));
        assert_eq!(f.ring.num_free(), 2);
        // A 2-descriptor chain fits in the two freed slots; a third does not
        f.ring.add(&[sg(1, 1)], &[sg(2, 2)], 7).unwrap();
        assert_eq!(f.ring.add(&[sg(1, 1)], &[], 8), Err(VqError::NoSpace));
        let (h, chain) = f.pop().unwrap();
        assert_eq!(chain.len(), 2);
        assert!(h == heads[2] || h == heads[0]);
    }

    #[test]
    fn index_wraparound() {
        // Far more than 2^16 operations: avail/used indices wrap
        let mut f = Fake::new(8);
        let mut want = 0usize;
        for round in 0..70_000usize {
            let n = 1 + round % 3;
            for k in 0..n {
                let t = round * 4 + k;
                f.ring.add(&[sg(t as u64, 1)], &[sg(0, 2)], t).unwrap();
            }
            for _ in 0..n {
                let (h, c) = f.pop().unwrap();
                assert_eq!(c.len(), 2);
                f.push(h, 2);
            }
            for _ in 0..n {
                let (t, len) = f.ring.get().unwrap();
                assert_eq!((t / 4, len), (round, 2));
                want += 1;
            }
            assert_eq!(f.ring.num_free(), 8);
        }
        assert!(want > 0x1_0000);
        assert_eq!(f.ring.avail_idx, f.dev_avail);
        assert_eq!(f.ring.last_used, f.dev_used);
    }

    /// A request's table: header out, data and status in
    fn table3() -> [Desc; 3] {
        let mut t = [Desc::default(); 3];
        set_chain(&mut t, 0, sg(0x10, 16), false);
        set_chain(&mut t, 1, sg(0x20, 512), true);
        set_chain(&mut t, 2, sg(0x30, 1), true);
        t
    }

    #[test]
    fn indirect_takes_one_slot() {
        let mut f = Fake::new(4);
        let t = table3();
        let e: Vec<(u64, u32, u16, u16)> =
            t.iter().map(|d| (d.addr, d.len, d.flags, d.next)).collect();
        let (n, w) = (VRING_DESC_F_NEXT, VRING_DESC_F_WRITE);
        assert_eq!(
            e,
            [(0x10, 16, n, 1), (0x20, 512, n | w, 2), (0x30, 1, w, 3)]
        );
        assert_eq!(t[2].sg().addr, 0x30);
        for k in 0..4 {
            f.ring.add_indirect(0x9000 + k, 3, k as usize).unwrap();
        }
        assert_eq!(f.ring.add_indirect(0x9000, 3, 9), Err(VqError::NoSpace));
        assert_eq!(f.ring.num_free(), 0);
        let (h, c) = f.pop().unwrap();
        assert_eq!(c, [(0x9000, 48, VRING_DESC_F_INDIRECT)]);
        f.push(h, 0);
        assert_eq!(f.ring.get(), Some((0, 0)));
        assert_eq!(f.ring.num_free(), 1);
        // The freed slot takes a direct chain of one
        f.ring.add(&[sg(5, 5)], &[], 5).unwrap();
        assert_eq!(f.ring.add_indirect(1, 0, 0), Err(VqError::Empty));
    }

    #[test]
    fn table_as_direct_chain() {
        let mut f = Fake::new(4);
        let t = table3();
        assert_eq!(f.ring.add_chain(&t[..0], 0), Err(VqError::Empty));
        f.ring.add_chain(&t, 7).unwrap();
        assert_eq!(f.ring.add_chain(&t, 8), Err(VqError::NoSpace));
        let (h, c) = f.pop().unwrap();
        let (n, w) = (VRING_DESC_F_NEXT, VRING_DESC_F_WRITE);
        assert_eq!(c, [(0x10, 16, n), (0x20, 512, n | w), (0x30, 1, w)]);
        f.push(h, 513);
        assert_eq!(f.ring.get(), Some((7, 513)));
        assert_eq!(f.ring.num_free(), 4);
    }

    #[test]
    fn need_event_window() {
        // Passing the event index from old to new (exclusive of old)
        assert!(need_event(5, 6, 5));
        assert!(need_event(5, 8, 2));
        assert!(!need_event(5, 5, 2));
        assert!(!need_event(5, 9, 6));
        assert!(!need_event(5, 5, 5));
        // Across the 16-bit wrap
        assert!(need_event(0xffff, 0x0001, 0xfffe));
        assert!(need_event(0, 1, 0xffff));
        assert!(!need_event(2, 1, 0xffff));
    }

    #[test]
    fn event_idx_suppression() {
        let mut f = Fake::new(8);
        f.ring.set_event_idx();
        let lay = f.ring.lay;
        let avail_event = lay.used + 4 + 8 * 8;
        let used_event = lay.avail + 4 + 2 * 8;
        // The device wants a kick once avail passes 0: the first add
        f.wr16(avail_event, 0);
        f.ring.add(&[sg(1, 1)], &[], 1).unwrap();
        assert!(f.ring.needs_notify());
        // Nothing new: no kick
        assert!(!f.ring.needs_notify());
        // The device asks again at 3: adds 2 and 3 cover only index 2
        f.wr16(avail_event, 3);
        f.ring.add(&[sg(2, 1)], &[], 2).unwrap();
        assert!(!f.ring.needs_notify());
        f.ring.add(&[sg(3, 1)], &[], 3).unwrap();
        f.ring.add(&[sg(4, 1)], &[], 4).unwrap();
        assert!(f.ring.needs_notify());
        // The flags no longer count
        f.wr16(lay.used, VRING_USED_F_NO_NOTIFY);
        f.wr16(avail_event, 4);
        f.ring.add(&[sg(5, 1)], &[], 5).unwrap();
        assert!(f.ring.needs_notify());
        // Consuming moves used_event to the next entry while callbacks
        // are on; disabled, it stays
        for _ in 0..5 {
            let (h, _) = f.pop().unwrap();
            f.push(h, 0);
        }
        assert!(f.ring.get().is_some());
        assert_eq!(f.rd16(used_event), 1);
        f.ring.disable_cb();
        assert!(f.ring.get().is_some());
        assert_eq!(f.rd16(used_event), 1);
        // Enabling asks for the next entry and reports what is pending
        assert!(!f.ring.enable_cb());
        assert_eq!(f.rd16(used_event), 2);
        while f.ring.get().is_some() {}
        assert_eq!(f.rd16(used_event), 5);
        assert!(f.ring.enable_cb());
    }

    #[test]
    fn bad_used_id_breaks_ring() {
        let mut f = Fake::new(4);
        f.ring.add(&[sg(1, 1)], &[], 1).unwrap();
        // Device returns a descriptor that is not a chain head
        f.push(3, 0);
        assert!(f.ring.get().is_none());
        assert!(f.ring.is_broken());
    }

    #[test]
    fn callbacks_and_notify_hints() {
        let mut f = Fake::new(4);
        let lay = f.ring.lay;
        f.ring.disable_cb();
        assert_eq!(f.rd16(lay.avail), VRING_AVAIL_F_NO_INTERRUPT);
        assert!(f.ring.enable_cb());
        assert_eq!(f.rd16(lay.avail), 0);
        f.ring.add(&[sg(1, 1)], &[], 1).unwrap();
        assert!(f.ring.needs_notify());
        f.wr16(lay.used, VRING_USED_F_NO_NOTIFY);
        assert!(!f.ring.needs_notify());
        let (h, _) = f.pop().unwrap();
        f.push(h, 0);
        // Pending used buffer: enabling reports it
        assert!(!f.ring.enable_cb());
        assert_eq!(f.ring.get(), Some((1, 0)));
        assert!(f.ring.enable_cb());
    }
}
