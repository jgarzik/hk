//! Virtio block device driver (virtio 1.2 section 5.2)
//!
//! Linux reference: drivers/block/virtio_blk.c.
//!
//! ## Design
//!
//! - Features: SIZE_MAX, SEG_MAX, BLK_SIZE, TOPOLOGY (physical block
//!   size), FLUSH (volatile write cache), RO, MQ (one virtqueue per
//!   hardware queue, CPUs spread over them).
//! - Limits from the device (Linux virtblk_read_limits): SEG_MAX
//!   segments, SIZE_MAX bytes each (no limit without it), no sector
//!   limit of its own (the block layer's 4 MiB cap); one hardware queue
//!   per virtqueue, at most one per CPU; the queue depth fills the ring
//!   (half without indirect descriptors: Linux virtblk_probe).
//! - A blk-mq driver (`block::blk_mq`): each virtqueue is one hardware
//!   queue. A request is `[header] [data...] [status]`; headers and
//!   status bytes live in a per-queue coherent pool, one slot per tag.
//!   The chain is written to a table (Linux virtblk_req's sg table)
//!   allocated per request (Linux GFP_ATOMIC: in hardirq when restarted
//!   from a completion), or the queue's spare full-size table when the
//!   heap has none; with indirect descriptors the table goes to the
//!   device as one ring entry (Linux virtqueue_add_sgs), else as a
//!   chain. Data segments are the bio's, DMA-mapped in `queue_rq` and
//!   unmapped in `complete` from the table (the DMA API is lock-free).
//! - Interrupts: MSI-X when the transport has it, a vector per queue
//!   aimed at the first CPU blk-mq maps to that queue (Linux managed
//!   affinity, `util::group_cpus`), reaping that queue; else INTx, where
//!   an interrupt reaps every hardware queue (the ISR status does not
//!   say which queue fired). Completions restart dispatch of bios that
//!   waited for room.
//! - Disks: vda, vdb, ... on one dynamic major ("virtblk"), 16 minors
//!   each (Linux PART_BITS 4); the index is freed with the disk, after
//!   its last reference (Linux virtblk_free_disk).
//! - Remove (Linux virtblk_remove): `del_gendisk` fails new I/O and
//!   waits for the requests in flight; the queues are taken back from
//!   blk-mq, the IRQ freed, the device reset and the rings, header
//!   pools freed (`del_vqs`).
//!
//! ## Locking (doc/LOCKING.md 3.10, Block Device Subsystem)
//!
//! Each virtqueue and its slots are owned by the blk-mq hardware queue
//! (`IrqSpinlock`, leaf; Linux virtio_blk_vq.lock): `queue_rq` runs in
//! thread context or, restarting, in the IRQ handler; `complete` in the
//! IRQ handler or a polling submitter. Neither sleeps; `queue_rq`'s
//! table allocation is the heap's atomic one (IRQ-safe slab, falling
//! back to the spare).
#![expect(clippy::undocumented_unsafe_blocks)] // TODO(unsafe): SAFETY comments (doc/UNSAFE.md)

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::mem::MaybeUninit;

use spin::Once;

use crate::arch::phys_to_virt;
use crate::block::blk_mq::{BlkMq, MqOps, Queued};
use crate::block::blkdev::{
    BLK_DEF_MAX_SECTORS_CAP, Bio, BioList, BioOp, Disk, QueueLimits, RequestQueue, SECTOR_SHIFT,
    register_blkdev,
};
use crate::block::genhd::{add_disk, del_gendisk, disk_name};
use crate::hw::dma::{DmaAddr, DmaCoherent, DmaDirection, dma_map_single, dma_unmap_single};
use crate::hw::virtio::ring::{Desc, Sg, set_chain};
use crate::hw::virtio::{self, VirtioDevice, VirtioDriver, VirtioIrq, Virtqueue};
use crate::printkln;
use crate::util::error::KernelError;
use crate::util::group_cpus::first_cpu;
use crate::util::ida::Ida;
use crate::util::kalloc::{try_arc, try_box};
use crate::util::kmem::{KVec, try_vec};

/// Device-specific feature bits
mod feature {
    pub const SIZE_MAX: u32 = 1;
    pub const SEG_MAX: u32 = 2;
    pub const RO: u32 = 5;
    pub const BLK_SIZE: u32 = 6;
    pub const FLUSH: u32 = 9;
    pub const TOPOLOGY: u32 = 10;
    pub const MQ: u32 = 12;
}

/// struct virtio_blk_config offsets
mod cfg {
    pub const CAPACITY: u32 = 0;
    pub const SIZE_MAX: u32 = 8;
    pub const SEG_MAX: u32 = 12;
    pub const BLK_SIZE: u32 = 20;
    pub const PHYS_EXP: u32 = 24;
    pub const MIN_IO_SIZE: u32 = 26;
    pub const NUM_QUEUES: u32 = 34;
}

/// Request types and status (struct virtio_blk_outhdr, 5.2.6)
const T_IN: u32 = 0;
const T_OUT: u32 = 1;
const T_FLUSH: u32 = 4;
const S_OK: u8 = 0;
const S_UNSUPP: u8 = 2;

/// Per-tag pool slot: 16-byte header, then the status byte
const SLOT: usize = 32;
const PAGE: u32 = 4096;
/// Minors per disk (Linux PART_BITS = 4)
const VD_MINORS: u16 = 16;
/// Most data segments a device may ask for (Linux
/// VIRTIO_BLK_MAX_SG_ELEMS - 2: header and status take two)
const MAX_SG_ELEMS: u32 = 32768 - 2;

/// A started request: its bio and descriptor table
struct Slot {
    bio: Option<Box<Bio>>,
    /// `[header, data..., status]` with the data's DMA mappings (Linux
    /// virtblk_req's sg table, and the indirect table built from it)
    table: Vec<Desc>,
    /// Entries of `table` in use
    n: usize,
    /// DMA address of the mapped table (an indirect request)
    table_dma: Option<u64>,
}

/// One virtqueue: a blk-mq hardware queue (Linux virtio_blk_vq)
struct VbQueue {
    vdev: Arc<VirtioDevice>,
    vq: Virtqueue,
    pool: DmaCoherent,
    slots: Vec<Slot>,
    /// Free tags (capacity reserved: push/pop never allocate)
    free: Vec<u16>,
    /// A table of the most entries, used when the heap has none, so a
    /// queue with nothing in flight always makes progress (Linux relies
    /// on GFP_ATOMIC and a delayed queue rerun)
    spare: Option<Vec<Desc>>,
    /// Most data segments per request (max_segments)
    max_segs: usize,
}

fn dir(op: BioOp) -> DmaDirection {
    if op == BioOp::Read {
        DmaDirection::FromDevice
    } else {
        DmaDirection::ToDevice
    }
}

impl VbQueue {
    fn new(vdev: &Arc<VirtioDevice>, vq: Virtqueue, max_segs: usize) -> Result<Self, KernelError> {
        // Linux virtblk_probe: fill the ring, two descriptors per
        // request without indirect ones
        let tags = if vq.indirect() {
            vq.num()
        } else {
            vq.num() / 2
        };
        let pool = crate::hw::dma::dma_alloc_coherent(&**vdev, tags as usize * SLOT)
            .ok_or(KernelError::NoDevice)?;
        let mut slots = KVec::try_with_capacity(tags as usize)?;
        for _ in 0..tags {
            slots.try_push(Slot {
                bio: None,
                table: Vec::new(),
                n: 0,
                table_dma: None,
            })?;
        }
        let mut free = KVec::try_with_capacity(tags as usize)?;
        for t in (0..tags).rev() {
            free.try_push(t)?;
        }
        Ok(Self {
            vdev: vdev.clone(),
            vq,
            pool,
            slots: slots.into_vec(),
            free: free.into_vec(),
            spare: Some(try_vec(max_segs + 2, Desc::default())?),
            max_segs,
        })
    }

    fn hdr_dma(&self, t: u16) -> u64 {
        self.pool.dma_addr().0 + (t as usize * SLOT) as u64
    }

    fn status(&self, t: u16) -> *mut u8 {
        unsafe { self.pool.cpu_addr().add(t as usize * SLOT + 16) }
    }

    /// Fill the request header of tag `t`
    fn write_hdr(&self, t: u16, ty: u32, sector: u64) {
        let h = unsafe { self.pool.cpu_addr().add(t as usize * SLOT) };
        unsafe {
            core::ptr::write_volatile(h.cast::<u32>(), ty.to_le());
            core::ptr::write_volatile(h.add(4).cast::<u32>(), 0);
            core::ptr::write_volatile(h.add(8).cast::<u64>(), sector.to_le());
            core::ptr::write_volatile(self.status(t), 0xff);
        }
    }

    /// A table of at least `n` entries: from the heap (Linux GFP_ATOMIC:
    /// this may run in hardirq, small blocks only) or the spare
    fn get_table(&mut self, n: usize) -> Option<Vec<Desc>> {
        try_vec(n, Desc::default())
            .ok()
            .or_else(|| self.spare.take())
    }

    /// A finished request's table: back as the spare if that is out
    fn put_table(&mut self, t: Vec<Desc>) {
        if self.spare.is_none() && t.len() == self.max_segs + 2 {
            self.spare = Some(t);
        }
    }

    /// Write tag `t`'s chain `[header, data..., status]` to `table`
    /// (n + 2 entries for the request's n segments), DMA-mapping the data; false if a mapping failed
    /// (nothing left mapped)
    fn fill(&self, t: u16, bio: &Bio, table: &mut [Desc]) -> bool {
        let d = dir(bio.op);
        let write = bio.op == BioOp::Read;
        let hdr = Sg {
            addr: self.hdr_dma(t),
            len: 16,
        };
        set_chain(table, 0, hdr, false);
        for (k, seg) in bio.rq_segs().enumerate() {
            let p = unsafe { phys_to_virt(seg.frame).add(seg.offset) };
            // SAFETY: the bio's pages stay allocated until it completes,
            // and `unmap` runs at completion (or on the failure below)
            let Some(a) = (unsafe { dma_map_single(&*self.vdev, p, seg.len, d) }) else {
                self.unmap(&table[1..=k], bio.op);
                return false;
            };
            // A segment is at most max_segment_size (u32)
            let sg = Sg {
                addr: a.0,
                len: seg.len as u32,
            };
            set_chain(table, k + 1, sg, write);
        }
        let st = Sg {
            addr: self.hdr_dma(t) + 16,
            len: 1,
        };
        set_chain(table, table.len() - 1, st, true);
        true
    }

    /// Unmap the data entries `data` of a table
    fn unmap(&self, data: &[Desc], op: BioOp) {
        for e in data {
            let sg = e.sg();
            dma_unmap_single(&*self.vdev, DmaAddr(sg.addr), sg.len as usize, dir(op));
        }
    }

    /// Put a filled chain on the ring: one indirect descriptor when
    /// negotiated (the table mapped for the device), else the chain
    /// itself. Err: no room (nothing left mapped)
    fn add(&mut self, t: u16, table: &[Desc]) -> Result<Option<u64>, ()> {
        if !self.vq.indirect() {
            return self
                .vq
                .add_chain(table, t as usize)
                .map(|()| None)
                .map_err(|_| ());
        }
        let len = core::mem::size_of_val(table);
        // SAFETY: the table stays allocated, untouched by the CPU, until
        // its request completes and `complete` unmaps it (or the add
        // failure below)
        let a = unsafe {
            dma_map_single(
                &*self.vdev,
                table.as_ptr().cast(),
                len,
                DmaDirection::ToDevice,
            )
        }
        .ok_or(())?;
        // n + 2 <= MAX_SG_ELEMS + 2 fits u16
        if self
            .vq
            .add_indirect(a.0, table.len() as u16, t as usize)
            .is_err()
        {
            dma_unmap_single(&*self.vdev, a, len, DmaDirection::ToDevice);
            return Err(());
        }
        Ok(Some(a.0))
    }
}

impl MqOps for VbQueue {
    fn queue_rq(&mut self, bio: Box<Bio>) -> Queued {
        let n = bio.rq_nr_segs();
        if n > self.max_segs {
            return Queued::Failed(bio, KernelError::Io);
        }
        if !self.vq.indirect() && usize::from(self.vq.num_free()) < n + 2 {
            return Queued::Busy(bio);
        }
        let Some(t) = self.free.pop() else {
            return Queued::Busy(bio);
        };
        // Busy only with a request in flight (that has the spare), whose
        // completion reruns the queue
        let Some(mut table) = self.get_table(n + 2) else {
            self.free.push(t);
            return Queued::Busy(bio);
        };
        let ty = match bio.op {
            BioOp::Read => T_IN,
            BioOp::Write => T_OUT,
            BioOp::Flush => T_FLUSH,
        };
        self.write_hdr(t, ty, bio.sector);
        if !self.fill(t, &bio, &mut table[..n + 2]) {
            self.put_table(table);
            self.free.push(t);
            return Queued::Failed(bio, KernelError::Io);
        }
        let added = self.add(t, &table[..n + 2]);
        let Ok(table_dma) = added else {
            self.unmap(&table[1..=n], bio.op);
            self.put_table(table);
            self.free.push(t);
            return Queued::Busy(bio);
        };
        let s = &mut self.slots[t as usize];
        s.bio = Some(bio);
        s.table = table;
        s.n = n + 2;
        s.table_dma = table_dma;
        Queued::Started
    }

    fn commit(&mut self) {
        self.vq.kick();
    }

    fn complete(&mut self, done: &mut BioList) {
        while let Some((t, _)) = self.vq.get() {
            let t = t as u16;
            let s = &mut self.slots[t as usize];
            let Some(mut bio) = s.bio.take() else {
                continue;
            };
            let table = core::mem::take(&mut s.table);
            let (n, table_dma) = (s.n, s.table_dma.take());
            if let Some(a) = table_dma {
                let len = n * core::mem::size_of::<Desc>();
                dma_unmap_single(&*self.vdev, DmaAddr(a), len, DmaDirection::ToDevice);
            }
            self.unmap(&table[1..n - 1], bio.op);
            self.put_table(table);
            bio.status = match unsafe { core::ptr::read_volatile(self.status(t)) } {
                S_OK => Ok(()),
                S_UNSUPP => Err(KernelError::OperationNotSupported),
                _ => Err(KernelError::Io),
            };
            self.free.push(t);
            done.push(bio);
        }
    }

    fn depth(&self) -> usize {
        self.slots.len()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

/// A virtio-blk disk: interrupt side
struct VirtioBlk {
    vdev: Arc<VirtioDevice>,
    disk: Arc<Disk>,
}

impl VirtioIrq for VirtioBlk {
    /// Linux virtblk_done: one queue's completions (MSI-X), or every
    /// queue's (INTx)
    fn vq_interrupt(&self, vq: Option<u16>) {
        let Some(mq) = self.disk.queue.mq() else {
            return;
        };
        match vq {
            Some(q) => mq.complete(usize::from(q)),
            None => mq.poll(),
        }
    }

    /// Capacity changes are not followed (Linux virtblk_config_changed)
    fn config_changed(&self) {}
}

struct VirtioBlkDev(Arc<VirtioBlk>);

impl crate::base::Bound for VirtioBlkDev {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn shutdown(&self) {
        printkln!(
            "virtio-blk: {} irqs={}",
            self.0.disk.name,
            self.0.vdev.irqs()
        );
    }

    /// Linux virtblk_remove
    fn remove(&self) {
        let b = &self.0;
        // Nothing in flight, nothing more started
        del_gendisk(&b.disk);
        // Quiet before its IRQ goes (Linux: virtio_reset_device, then
        // del_vqs frees the IRQ); `stop` frees the rings
        let _ = b.vdev.reset();
        b.vdev.free_irq();
        let qs = b.disk.queue.mq().map_or(Vec::new(), |m| m.release());
        stop(&b.vdev, qs);
        printkln!("virtio-blk: {} removed", b.disk.name);
    }
}

/// Reset the device and free the queues' rings and header pools (Linux
/// virtio_reset_device + del_vqs); on a reset that does not complete the
/// memory is leaked
fn stop(vdev: &VirtioDevice, qs: Vec<Box<dyn MqOps>>) {
    let qs: Vec<VbQueue> = qs
        .into_iter()
        .filter_map(|q| q.into_any().downcast::<VbQueue>().ok())
        .map(|q| *q)
        .collect();
    let mut pools = Vec::with_capacity(qs.len());
    let vqs: Vec<Virtqueue> = qs
        .into_iter()
        .map(|q| {
            pools.push(q.pool);
            q.vq
        })
        .collect();
    if vdev.del_vqs(vqs).is_err() {
        printkln!("virtio-blk: {}: reset failed", vdev.bus_id());
        return;
    }
    for p in pools {
        // SAFETY: the device is reset (no DMA into the headers or status
        // bytes) and its queue, the pool's only user, is gone
        unsafe { crate::hw::dma::dma_free_coherent(vdev, p) };
    }
}

/// The virtio-blk driver (registered with `virtio::register_driver`)
pub struct VirtioBlkDriver;

pub static VIRTIO_BLK: VirtioBlkDriver = VirtioBlkDriver;

/// Dynamic major of all virtio disks
static MAJOR: Once<u16> = Once::new();
/// Disk indexes (vda = 0; Linux vd_index_ida)
static INDEX: Ida = Ida::new();

/// A disk's index, freed with the disk (Linux virtblk_free_disk)
struct VdIndex(u32);

impl Drop for VdIndex {
    fn drop(&mut self) {
        INDEX.free(self.0);
    }
}

/// Queue limits from the device (Linux virtblk_read_limits, then
/// blk_validate_limits); EINVAL for a segment size under a page (Linux
/// BLK_MIN_SEGMENT_SIZE). `ring`: the smallest ring, which bounds a
/// request's segments without indirect descriptors
fn limits(vdev: &VirtioDevice, ring: u16) -> Result<QueueLimits, KernelError> {
    let f = |b| vdev.has_feature(b);
    let lbs = match vdev.read_config(|d| d.cfg32(cfg::BLK_SIZE)) {
        n if f(feature::BLK_SIZE) && (512..=PAGE).contains(&n) && n.is_power_of_two() => n,
        _ => 512,
    };
    let pbs = if f(feature::TOPOLOGY) {
        lbs << vdev.read_config(|d| d.cfg8(cfg::PHYS_EXP)).min(12)
    } else {
        lbs
    };
    // Linux virtblk_probe: min_io_size in logical blocks
    let io_min = if f(feature::TOPOLOGY) {
        lbs.saturating_mul(u32::from(vdev.read_config(|d| d.cfg16(cfg::MIN_IO_SIZE))))
    } else {
        0
    };
    // At least one, at most what a request can carry
    let mut seg_max = if f(feature::SEG_MAX) {
        vdev.read_config(|d| d.cfg32(cfg::SEG_MAX))
            .clamp(1, MAX_SG_ELEMS)
    } else {
        1
    };
    if !vdev.has_feature(virtio::feature::RING_INDIRECT_DESC) {
        // Each request's chain must fit the ring
        seg_max = seg_max.min(u32::from(ring).saturating_sub(2).max(1));
    }
    // No limit but the device's (Linux virtio_max_dma_size: direct DMA)
    let size_max = if f(feature::SIZE_MAX) {
        vdev.read_config(|d| d.cfg32(cfg::SIZE_MAX))
    } else {
        u32::MAX
    };
    if size_max < PAGE {
        return Err(KernelError::InvalidArgument);
    }
    let lbs_sectors = lbs >> SECTOR_SHIFT;
    Ok(QueueLimits {
        logical_block_size: lbs,
        physical_block_size: pbs.min(PAGE),
        // Linux: max_hw_sectors UINT_MAX, max_sectors capped
        max_hw_sectors: u32::MAX / lbs_sectors * lbs_sectors,
        max_sectors: BLK_DEF_MAX_SECTORS_CAP / lbs_sectors * lbs_sectors,
        max_segments: seg_max,
        max_segment_size: size_max,
        rotational: true,
        io_min,
        ..QueueLimits::default()
    })
}

/// Request queues to set up: EINVAL if MQ reports none (Linux init_vq),
/// ENOENT if the transport has none (vp_find_vqs: no such queue)
fn nr_queues(vdev: &VirtioDevice) -> Result<u16, KernelError> {
    let n = if vdev.has_feature(feature::MQ) {
        vdev.read_config(|d| d.cfg16(cfg::NUM_QUEUES))
    } else {
        1
    };
    if n == 0 {
        return Err(KernelError::InvalidArgument);
    }
    // Linux blk_mq_num_possible_queues: at most one per CPU
    let cpus = u16::try_from(crate::cpu::nr_cpu_ids()).unwrap_or(u16::MAX);
    match n.min(vdev.num_queues()).min(cpus) {
        0 => Err(KernelError::NotFound),
        n => Ok(n),
    }
}

/// MSI-X vectors for `nq` queues, queue i's aimed at the first CPU of
/// the CPUs blk-mq maps to it (Linux virtio_find_vqs with an
/// irq_affinity: managed vectors spread by group_cpus_evenly, which
/// blk_mq_map_hw_queues then follows); INTx if there are none
fn vectors(vdev: &VirtioDevice, nq: u16) -> Result<(), KernelError> {
    let n = crate::cpu::nr_cpu_ids();
    let mut cpus = KVec::try_with_capacity(usize::from(nq))?;
    for i in 0..u32::from(nq) {
        cpus.try_push(first_cpu(i, n, u32::from(nq)))?;
    }
    vdev.alloc_vectors(&cpus).map(|_| ())
}

/// Virtqueues (Linux init_vq) and their hardware queues, within the
/// limits read once they are known (the ring sizes bound them)
fn setup_queues(vdev: &Arc<VirtioDevice>) -> Result<(BlkMq, QueueLimits), KernelError> {
    let mut vqs: Vec<Virtqueue> = Vec::new();
    let mut ring = u16::MAX;
    let r = (|| {
        let nq = nr_queues(vdev)?;
        vectors(vdev, nq)?;
        for i in 0..nq {
            let vq = vdev.setup_vq(i)?;
            ring = ring.min(vq.num());
            vqs.try_reserve(1).map_err(|_| KernelError::OutOfMemory)?;
            vqs.push(vq);
        }
        if ring < 3 {
            return Err(KernelError::NoDevice);
        }
        limits(vdev, ring)
    })();
    let lim = match r {
        Ok(l) => l,
        Err(e) => {
            let _ = vdev.del_vqs(vqs);
            return Err(e);
        }
    };
    let mut ops: Vec<Box<dyn MqOps>> = Vec::new();
    for vq in vqs {
        ops.push(try_box(VbQueue::new(vdev, vq, lim.max_segments as usize)?)?);
    }
    Ok((BlkMq::new(ops)?, lim))
}

fn new_disk(vdev: &Arc<VirtioDevice>) -> Result<Arc<Disk>, KernelError> {
    let major = *MAJOR
        .try_call_once(|| register_blkdev(0, "virtblk"))
        .map_err(|_| KernelError::Io)?;
    let index = VdIndex(INDEX.alloc());
    let i = index.0;
    if i as usize * VD_MINORS as usize > u16::MAX as usize - VD_MINORS as usize {
        return Err(KernelError::Io);
    }
    let private = try_box(index)?;
    let (mq, lim) = setup_queues(vdev)?;
    let nq = mq.nr_hw_queues();
    let wc = vdev.has_feature(feature::FLUSH);
    let cap = vdev.read_config(|d| d.cfg64(cfg::CAPACITY));
    let disk = Disk::new(
        major,
        i as u16 * VD_MINORS,
        VD_MINORS,
        disk_name("vd", i),
        cap,
        RequestQueue::new_mq(mq, lim, wc),
        vdev.has_feature(feature::RO),
    )?;
    disk.private.call_once(|| private);
    printkln!(
        "virtio-blk: {} {} sectors, {}/{} bytes, {} queues ({}){}{}",
        disk.name,
        cap,
        lim.logical_block_size,
        lim.physical_block_size,
        nq,
        if vdev.msix() { "MSI-X" } else { "INTx" },
        if wc { ", write cache" } else { "" },
        if disk.ro() { ", read-only" } else { "" },
    );
    Ok(disk)
}

impl VirtioDriver for VirtioBlkDriver {
    fn features(&self) -> u64 {
        [
            feature::SIZE_MAX,
            feature::SEG_MAX,
            feature::RO,
            feature::BLK_SIZE,
            feature::FLUSH,
            feature::TOPOLOGY,
            feature::MQ,
        ]
        .iter()
        .fold(0, |f, b| f | (1 << b))
    }

    fn probe(
        &self,
        dev: &Arc<crate::base::Device>,
        vdev: Arc<VirtioDevice>,
    ) -> Result<Box<dyn crate::base::Bound>, KernelError> {
        // The binding's memory first: nothing to undo should it fail
        let slot = try_box(MaybeUninit::<VirtioBlkDev>::uninit())?;
        // Vectors taken before the queues go with a failed setup
        let disk = new_disk(&vdev).inspect_err(|_| vdev.free_irq())?;
        // Undo the queues and the MSI-X vectors (Linux virtblk_probe's
        // out_free_vq: del_vqs resets, then frees the IRQs)
        let fail = |e| {
            let _ = vdev.reset();
            vdev.free_irq();
            stop(&vdev, disk.queue.mq().map_or(Vec::new(), |m| m.release()));
            e
        };
        let blk = try_arc(VirtioBlk {
            vdev: vdev.clone(),
            disk: disk.clone(),
        })
        .map_err(fail)?;
        if let Err(e) = vdev.request_irq(blk.clone() as Arc<dyn VirtioIrq>) {
            printkln!("virtio-blk: no IRQ ({:?})", e);
            return Err(fail(KernelError::NoDevice));
        }
        vdev.ready();
        if add_disk(disk.clone(), Some(dev)).is_err() {
            return Err(fail(KernelError::Io));
        }
        Ok(Box::write(slot, VirtioBlkDev(blk)))
    }
}

/// The virtio_blk driver on the virtio bus
pub static VIRTIO_BLK_DRIVER: crate::base::Driver = crate::base::Driver::new(
    "virtio_blk",
    &virtio::VIRTIO_BUS,
    None,
    &virtio::VirtioIds {
        ids: &[(virtio::id::BLOCK, virtio::VIRTIO_DEV_ANY_ID)],
        drv: &VIRTIO_BLK,
    },
    virtio::virtio_dev_probe,
);
