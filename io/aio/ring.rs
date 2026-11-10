//! The completion ring an AIO context shares with user space (Linux
//! fs/aio.c aio_setup_ring, struct aio_ring)
//!
//! One `SharedRegion`: the 32-byte `struct aio_ring` header (id, nr,
//! head, tail, magic, compat and incompat features, header length),
//! then `nr` `struct io_event`s. It is mapped shared into the process
//! (an anonymous "[aio]" file's pages, whose address is the context id),
//! and libaio reads events straight from it: it checks the magic and
//! the incompat features, reads head and tail, copies events and stores
//! a new head. The kernel stores each event before the tail (Release),
//! reads the head with Acquire, and never trusts the head user space
//! wrote further than reducing it modulo `nr`.

use core::sync::atomic::Ordering;

use super::abi::*;
use crate::fs::file::{File, FileOps};
use crate::mm::PAGE_SIZE;
use crate::mm::shared::SharedRegion;
use crate::util::error::KernelError;

/// The ring's pages and the context they belong to (the "[aio]"
/// file's private object; Linux aio_inode_info)
pub struct AioRing {
    region: SharedRegion,
    /// Events the ring holds (the trusted copy of `nr`)
    nr: u32,
}

/// Events and pages of a ring for at least `nr_events` events (Linux
/// aio_setup_ring: two more for the head/tail overlap, then as many as
/// the whole pages hold); EINVAL past what a ring may hold
pub fn ring_size(nr_events: u32) -> Result<(u32, usize), KernelError> {
    let want = nr_events
        .checked_add(2)
        .ok_or(KernelError::InvalidArgument)? as usize;
    let bytes = RING_HEADER + EVENT_SIZE * want;
    let pages = bytes.div_ceil(PAGE_SIZE as usize);
    let nr = (pages * PAGE_SIZE as usize - RING_HEADER) / EVENT_SIZE;
    let nr = u32::try_from(nr).map_err(|_| KernelError::InvalidArgument)?;
    Ok((nr, pages))
}

impl AioRing {
    /// A zeroed ring of `nr` events over `pages` pages, its header set
    /// (id ~0 until the context has one); ENOMEM
    pub fn new(nr: u32, pages: usize) -> Result<Self, KernelError> {
        let region = SharedRegion::new(pages * PAGE_SIZE as usize)?;
        let r = Self { region, nr };
        r.set(RING_ID, !0);
        r.set(RING_NR, nr);
        r.set(RING_MAGIC, AIO_RING_MAGIC);
        r.set(RING_COMPAT, AIO_RING_COMPAT_FEATURES);
        r.set(RING_INCOMPAT, AIO_RING_INCOMPAT_FEATURES);
        r.set(RING_HEADER_LENGTH, RING_HEADER as u32);
        Ok(r)
    }

    fn set(&self, off: usize, v: u32) {
        self.region.word(off).store(v, Ordering::Release);
    }

    /// Its size in bytes (what is mapped)
    pub fn bytes(&self) -> u64 {
        (self.region.pages() as u64) * PAGE_SIZE
    }

    /// Events it holds
    pub fn nr(&self) -> u32 {
        self.nr
    }

    /// Record the context's table index (Linux ioctx_add_table: ring->id)
    pub fn set_id(&self, id: u32) {
        self.set(RING_ID, id);
    }

    /// The head user space (or the kernel) last stored, as it is
    pub fn head(&self) -> u32 {
        self.region.word(RING_HEAD).load(Ordering::Acquire)
    }

    /// Store a new head (events before it consumed)
    pub fn set_head(&self, head: u32) {
        self.set(RING_HEAD, head);
    }

    /// The tail, as the kernel stored it
    pub fn tail(&self) -> u32 {
        self.region.word(RING_TAIL).load(Ordering::Acquire)
    }

    /// Publish a new tail: the events before it are written
    pub fn set_tail(&self, tail: u32) {
        self.set(RING_TAIL, tail);
    }

    /// Store event slot `i` (< nr)
    pub fn write_event(&self, i: u32, ev: IoEvent) {
        self.region.write(RING_HEADER + i as usize * EVENT_SIZE, ev);
    }

    /// A copy of event slot `i` (< nr)
    pub fn read_event(&self, i: u32) -> IoEvent {
        self.region.read(RING_HEADER + i as usize * EVENT_SIZE)
    }
}

/// The "[aio]" file: its mappings are the ring's pages (Linux
/// aio_ring_fops, aio_ring_vm_ops)
pub struct AioRingOps;

pub static AIO_RING_FOPS: AioRingOps = AioRingOps;

impl FileOps for AioRingOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn mmap(&self, _file: &File, _shared: bool) -> Result<(), KernelError> {
        Ok(())
    }

    fn maps_driver_pages(&self, _file: &File) -> bool {
        true
    }

    /// Page `idx` of the ring; none past it
    // SAFETY: the ring's frames hold only the header and events shared
    // with user space, and each one handed out carries a reference that
    // keeps it allocated (`SharedRegion::map_page`)
    unsafe fn map_page(
        &self,
        file: &File,
        _off: u64,
        idx: u64,
    ) -> Option<Result<u64, KernelError>> {
        let r = file.private_ref::<AioRing>()?;
        r.region.map_page(idx).map(Ok)
    }

    /// The ring moved to `start` in `mm` (Linux aio_ring_mremap): the
    /// context id is its new address. Only a context of `mm`'s own
    /// table moves (a ring inherited by a fork child, or one whose
    /// context left the table, belongs to none there); EINVAL then, or
    /// if the context is dead or the move is not of the whole ring
    fn mremap(
        &self,
        file: &File,
        mm: &crate::mm::Mm,
        start: u64,
        len: u64,
    ) -> Result<(), KernelError> {
        let ring = file
            .private_ref::<AioRing>()
            .ok_or(KernelError::InvalidArgument)?;
        mm.ioctx().ring_moved(ring, start, len)
    }

    fn can_poll(&self, _file: &File) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_as_linux() {
        // A page holds the header and 127 events; two more than asked
        assert_eq!(ring_size(125).unwrap(), (127, 1));
        assert_eq!(ring_size(126).unwrap(), (255, 2));
        assert_eq!(ring_size(253).unwrap(), (255, 2));
        assert_eq!(ring_size(254).unwrap(), (383, 3));
        assert!(ring_size(u32::MAX).is_err());
    }
}
