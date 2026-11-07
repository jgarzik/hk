//! Virtio block device driver (virtio 1.2 section 5.2)
//!
//! Linux reference: drivers/block/virtio_blk.c.
//!
//! ## Design
//!
//! - Features: SIZE_MAX, SEG_MAX, BLK_SIZE, TOPOLOGY (physical block
//!   size), FLUSH (volatile write cache), RO, MQ (one virtqueue per
//!   hardware queue, CPUs spread over them).
//! - A blk-mq driver (`block::blk_mq`): each virtqueue is one hardware
//!   queue. A request is `[header] [data...] [status]`; headers and
//!   status bytes live in a per-queue coherent pool, one slot per tag.
//!   Data segments are the bio's frames, DMA-mapped in `queue_rq` and
//!   unmapped in `complete` (the DMA API is lock-free).
//! - Interrupts (transport INTx): a queue interrupt reaps every hardware
//!   queue (the ISR status does not say which queue fired); completions
//!   restart dispatch of bios that waited for room.
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
//! IRQ handler or a polling submitter. Neither allocates nor sleeps.
#![expect(clippy::undocumented_unsafe_blocks)] // TODO(unsafe): SAFETY comments (doc/UNSAFE.md)

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::mem::MaybeUninit;

use spin::Once;

use crate::arch::phys_to_virt;
use crate::block::blk_mq::{BlkMq, MqOps, Queued};
use crate::block::blkdev::{Bio, BioList, BioOp, Disk, QueueLimits, RequestQueue, register_blkdev};
use crate::block::genhd::{add_disk, del_gendisk, disk_name};
use crate::hw::dma::{DmaAddr, DmaCoherent, DmaDirection, dma_map_single, dma_unmap_single};
use crate::hw::virtio::ring::Sg;
use crate::hw::virtio::{self, VirtioDevice, VirtioDriver, VirtioIrq, Virtqueue};
use crate::printkln;
use crate::util::error::KernelError;
use crate::util::ida::Ida;
use crate::util::kalloc::{try_arc, try_box};

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
    pub const NUM_QUEUES: u32 = 34;
}

/// Request types and status (struct virtio_blk_outhdr, 5.2.6)
const T_IN: u32 = 0;
const T_OUT: u32 = 1;
const T_FLUSH: u32 = 4;
const S_OK: u8 = 0;
const S_UNSUPP: u8 = 2;

/// Data segments per request (bounded further by SEG_MAX and the ring)
const MAX_SEGS: usize = 32;
/// Requests in flight per queue
const MAX_TAGS: u16 = 64;
/// Per-tag pool slot: 16-byte header, then the status byte
const SLOT: usize = 32;
/// Most hardware queues used
const MAX_QUEUES: u16 = 16;
const PAGE: u32 = 4096;
/// Minors per disk (Linux PART_BITS = 4)
const VD_MINORS: u16 = 16;

/// A started request: its bio and data mappings
struct Slot {
    bio: Option<Box<Bio>>,
    maps: [(u64, u32); MAX_SEGS],
    n: usize,
}

/// One virtqueue: a blk-mq hardware queue (Linux virtio_blk_vq)
struct VbQueue {
    vdev: Arc<VirtioDevice>,
    vq: Virtqueue,
    pool: DmaCoherent,
    slots: Vec<Slot>,
    /// Free tags (capacity reserved: push/pop never allocate)
    free: Vec<u16>,
}

fn dir(op: BioOp) -> DmaDirection {
    if op == BioOp::Read {
        DmaDirection::FromDevice
    } else {
        DmaDirection::ToDevice
    }
}

impl VbQueue {
    fn new(vdev: &Arc<VirtioDevice>, vq: Virtqueue) -> Result<Self, KernelError> {
        let tags = MAX_TAGS.min(vq.num());
        let pool = crate::hw::dma::dma_alloc_coherent(&**vdev, tags as usize * SLOT)
            .ok_or(KernelError::NoDevice)?;
        let slots = (0..tags)
            .map(|_| Slot {
                bio: None,
                maps: [(0, 0); MAX_SEGS],
                n: 0,
            })
            .collect();
        Ok(Self {
            vdev: vdev.clone(),
            vq,
            pool,
            slots,
            free: (0..tags).rev().collect(),
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

    /// DMA-map the bio's segments into slot `t`; false if one failed
    fn map(&mut self, t: u16, bio: &Bio) -> bool {
        let d = dir(bio.op);
        let s = &mut self.slots[t as usize];
        s.n = 0;
        for seg in &bio.segs {
            let p = unsafe { phys_to_virt(seg.frame).add(seg.offset) };
            // SAFETY: the bio's pages stay allocated until it completes,
            // and `unmap` runs at completion (or on the failure below)
            match unsafe { dma_map_single(&*self.vdev, p, seg.len, d) } {
                Some(a) => {
                    s.maps[s.n] = (a.0, seg.len as u32);
                    s.n += 1;
                }
                None => {
                    self.unmap(t, bio.op);
                    return false;
                }
            }
        }
        true
    }

    fn unmap(&mut self, t: u16, op: BioOp) {
        let s = &mut self.slots[t as usize];
        for &(a, len) in &s.maps[..s.n] {
            dma_unmap_single(&*self.vdev, DmaAddr(a), len as usize, dir(op));
        }
        s.n = 0;
    }

    /// Put tag `t`'s request on the ring
    fn add(&mut self, t: u16, op: BioOp) -> bool {
        let hdr = Sg {
            addr: self.hdr_dma(t),
            len: 16,
        };
        let st = Sg {
            addr: self.hdr_dma(t) + 16,
            len: 1,
        };
        let mut out = [hdr; MAX_SEGS + 1];
        let mut inb = [st; MAX_SEGS + 1];
        let (mut no, mut ni) = (1, 0);
        let s = &self.slots[t as usize];
        for &(addr, len) in &s.maps[..s.n] {
            let sg = Sg { addr, len };
            if op == BioOp::Read {
                inb[ni] = sg;
                ni += 1;
            } else {
                out[no] = sg;
                no += 1;
            }
        }
        inb[ni] = st;
        ni += 1;
        self.vq.add(&out[..no], &inb[..ni], t as usize).is_ok()
    }
}

impl MqOps for VbQueue {
    fn queue_rq(&mut self, bio: Box<Bio>) -> Queued {
        if bio.segs.len() > MAX_SEGS {
            return Queued::Failed(bio, KernelError::Io);
        }
        let Some(t) = self.free.pop() else {
            return Queued::Busy(bio);
        };
        let ty = match bio.op {
            BioOp::Read => T_IN,
            BioOp::Write => T_OUT,
            BioOp::Flush => T_FLUSH,
        };
        self.write_hdr(t, ty, bio.sector);
        if !self.map(t, &bio) {
            self.free.push(t);
            return Queued::Failed(bio, KernelError::Io);
        }
        if !self.add(t, bio.op) {
            self.unmap(t, bio.op);
            self.free.push(t);
            return Queued::Busy(bio);
        }
        self.slots[t as usize].bio = Some(bio);
        Queued::Started
    }

    fn commit(&mut self) {
        self.vq.kick();
    }

    fn complete(&mut self, done: &mut BioList) {
        while let Some((t, _)) = self.vq.get() {
            let t = t as u16;
            let Some(mut bio) = self.slots[t as usize].bio.take() else {
                continue;
            };
            self.unmap(t, bio.op);
            bio.status = match unsafe { core::ptr::read_volatile(self.status(t)) } {
                S_OK => Ok(()),
                S_UNSUPP => Err(KernelError::OperationNotSupported),
                _ => Err(KernelError::Io),
            };
            self.free.push(t);
            done.push(bio);
        }
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
    fn vq_interrupt(&self) {
        if let Some(mq) = self.disk.queue.mq() {
            mq.poll();
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

fn limits(vdev: &VirtioDevice, ring: u16) -> QueueLimits {
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
    let seg_max = if f(feature::SEG_MAX) {
        vdev.read_config(|d| d.cfg32(cfg::SEG_MAX)).max(1)
    } else {
        1
    };
    let size_max = if f(feature::SIZE_MAX) {
        vdev.read_config(|d| d.cfg32(cfg::SIZE_MAX))
            .clamp(lbs, PAGE)
    } else {
        PAGE
    };
    QueueLimits {
        logical_block_size: lbs,
        physical_block_size: pbs.min(PAGE),
        max_sectors: 128,
        max_segments: seg_max.min(MAX_SEGS as u32).min(u32::from(ring) - 2),
        max_segment_size: size_max,
        rotational: true,
    }
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
    match n.min(vdev.num_queues()).min(MAX_QUEUES) {
        0 => Err(KernelError::NotFound),
        n => Ok(n),
    }
}

/// Virtqueues and their hardware queues; also the smallest ring
fn setup_queues(vdev: &Arc<VirtioDevice>) -> Result<(BlkMq, u16), KernelError> {
    let mut ops: Vec<Box<dyn MqOps>> = Vec::new();
    let mut ring = u16::MAX;
    for i in 0..nr_queues(vdev)? {
        let vq = vdev.setup_vq(i)?;
        ring = ring.min(vq.num());
        ops.push(try_box(VbQueue::new(vdev, vq)?)?);
    }
    if ring < 3 {
        return Err(KernelError::NoDevice);
    }
    Ok((BlkMq::new(ops)?, ring))
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
    let (mq, ring) = setup_queues(vdev)?;
    let nq = mq.nr_hw_queues();
    let lim = limits(vdev, ring);
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
        "virtio-blk: {} {} sectors, {}/{} bytes, {} queues{}{}",
        disk.name,
        cap,
        lim.logical_block_size,
        lim.physical_block_size,
        nq,
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
        let disk = new_disk(&vdev)?;
        let blk = try_arc(VirtioBlk {
            vdev: vdev.clone(),
            disk: disk.clone(),
        })
        .inspect_err(|_| stop(&vdev, disk.queue.mq().map_or(Vec::new(), |m| m.release())))?;
        let fail = |e| {
            vdev.free_irq();
            stop(&vdev, disk.queue.mq().map_or(Vec::new(), |m| m.release()));
            e
        };
        if let Err(e) = vdev.request_irq(blk.clone() as Arc<dyn VirtioIrq>) {
            printkln!("virtio-blk: no IRQ ({})", e);
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
