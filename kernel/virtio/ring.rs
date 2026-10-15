//! Split virtqueue ring logic (virtio 1.2 section 2.7)
//!
//! Linux reference: drivers/virtio/virtio_ring.c (split ring, no indirect
//! descriptors, no event index).
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

use alloc::vec;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

use crate::arch::barrier::{dma_rmb, dma_wmb};

/// Descriptor continues via `next`
const VRING_DESC_F_NEXT: u16 = 1;
/// Buffer is device-writable
const VRING_DESC_F_WRITE: u16 = 2;
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

#[repr(C)]
struct Desc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
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
        }
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
        unsafe { (self.base as *mut Desc).add(i as usize) }
    }

    fn avail16(&self, i: usize) -> *mut u16 {
        unsafe { (self.base.add(self.lay.avail) as *mut u16).add(i) }
    }

    fn used16(&self, i: usize) -> *mut u16 {
        unsafe { (self.base.add(self.lay.used) as *mut u16).add(i) }
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
            let mut flags = if k >= out.len() {
                VRING_DESC_F_WRITE
            } else {
                0
            };
            if k + 1 < total {
                flags |= VRING_DESC_F_NEXT;
            }
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
        self.num_free -= total as u16;
        self.chain[head as usize] = total as u16;
        self.tokens[head as usize] = token;

        // Publish the head in the avail ring, then the index that covers
        // it: the device must see the descriptors and the entry first
        let slot = (self.avail_idx & (self.num - 1)) as usize;
        unsafe { write_volatile(self.avail16(2 + slot), head.to_le()) };
        self.avail_idx = self.avail_idx.wrapping_add(1);
        dma_wmb();
        unsafe { write_volatile(self.avail16(1), self.avail_idx.to_le()) };
        Ok(())
    }

    /// After [`Vring::add`]s: true if the device wants a notification
    /// (Linux virtqueue_kick_prepare without event index)
    pub fn needs_notify(&self) -> bool {
        // The new avail.idx before the used.flags read
        fence(Ordering::SeqCst);
        let f = u16::from_le(unsafe { read_volatile(self.used16(0)) });
        f & VRING_USED_F_NO_NOTIFY == 0
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
        if id >= self.num as u32 || self.chain[id as usize] == 0 {
            // Linux BAD_RING: stop using the queue
            self.broken = true;
            return None;
        }
        self.last_used = self.last_used.wrapping_add(1);
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
        // flags store before the used.idx load
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
