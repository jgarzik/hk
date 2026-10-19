//! Virtio block device driver (virtio 1.2 section 5.2)
//!
//! Linux reference: drivers/block/virtio_blk.c.
//!
//! ## Design
//!
//! - Features: SIZE_MAX, SEG_MAX, BLK_SIZE, TOPOLOGY (physical block
//!   size), FLUSH (volatile write cache), RO, MQ (one virtqueue per
//!   hardware queue, CPUs spread over them).
//! - A blk-mq driver (`storage::blk_mq`): each virtqueue is one hardware
//!   queue. A request is `[header] [data...] [status]`; headers and
//!   status bytes live in a per-queue coherent pool, one slot per tag.
//!   Data segments are the bio's frames, DMA-mapped in `queue_rq` and
//!   unmapped in `complete` (the DMA API is lock-free).
//! - Interrupts (transport INTx): a queue interrupt reaps every hardware
//!   queue (the ISR status does not say which queue fired); completions
//!   restart dispatch of bios that waited for room.
//! - Disks: vda, vdb, ... on one dynamic major ("virtblk"), 16 minors
//!   each (Linux PART_BITS 4).
//!
//! ## Locking (doc/LOCKING.md 3.10, Block Device Subsystem)
//!
//! Each virtqueue and its slots are owned by the blk-mq hardware queue
//! (`IrqSpinlock`, leaf; Linux virtio_blk_vq.lock): `queue_rq` runs in
//! thread context or, restarting, in the IRQ handler; `complete` in the
//! IRQ handler or a polling submitter. Neither allocates nor sleeps.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU32, Ordering};

use spin::Once;

use crate::arch::phys_to_virt;
use crate::bus::driver::{Device, DriverError};
use crate::dma::{DmaAddr, DmaCoherent, DmaDirection, dma_map_single, dma_unmap_single};
use crate::error::KernelError;
use crate::printkln;
use crate::storage::blk_mq::{BlkMq, MqOps, Queued};
use crate::storage::blkdev::{
    Bio, BioList, BioOp, Disk, QueueLimits, RequestQueue, register_blkdev,
};
use crate::storage::genhd::{add_disk, disk_name};
use crate::virtio::ring::Sg;
use crate::virtio::{self, VirtioDevice, VirtioDriver, VirtioIrq, Virtqueue};

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
    fn new(vdev: &Arc<VirtioDevice>, vq: Virtqueue) -> Result<Self, DriverError> {
        let tags = MAX_TAGS.min(vq.num());
        let pool = crate::dma::dma_alloc_coherent(&**vdev, tags as usize * SLOT)
            .ok_or(DriverError::MissingResource)?;
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
        self.pool.dma_addr.0 + (t as usize * SLOT) as u64
    }

    fn status(&self, t: u16) -> *mut u8 {
        unsafe { self.pool.cpu_addr.add(t as usize * SLOT + 16) }
    }

    /// Fill the request header of tag `t`
    fn write_hdr(&self, t: u16, ty: u32, sector: u64) {
        let h = unsafe { self.pool.cpu_addr.add(t as usize * SLOT) };
        unsafe {
            core::ptr::write_volatile(h as *mut u32, ty.to_le());
            core::ptr::write_volatile(h.add(4) as *mut u32, 0);
            core::ptr::write_volatile(h.add(8) as *mut u64, sector.to_le());
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
            match dma_map_single(&*self.vdev, p, seg.len, d) {
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

impl Device for VirtioBlkDev {
    fn name(&self) -> &str {
        "virtio-blk"
    }

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
}

/// The virtio-blk driver (registered with `virtio::register_driver`)
pub struct VirtioBlkDriver;

pub static VIRTIO_BLK: VirtioBlkDriver = VirtioBlkDriver;

/// Dynamic major of all virtio disks
static MAJOR: Once<u16> = Once::new();
/// Next disk index (vda = 0)
static INDEX: AtomicU32 = AtomicU32::new(0);

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
        max_segments: seg_max.min(MAX_SEGS as u32).min(ring as u32 - 2),
        max_segment_size: size_max,
    }
}

fn nr_queues(vdev: &VirtioDevice) -> u16 {
    let n = if vdev.has_feature(feature::MQ) {
        vdev.read_config(|d| d.cfg16(cfg::NUM_QUEUES)).max(1)
    } else {
        1
    };
    n.min(vdev.num_queues()).min(MAX_QUEUES)
}

/// Virtqueues and their hardware queues; also the smallest ring
fn setup_queues(vdev: &Arc<VirtioDevice>) -> Result<(BlkMq, u16), DriverError> {
    let mut ops: Vec<Box<dyn MqOps>> = Vec::new();
    let mut ring = u16::MAX;
    for i in 0..nr_queues(vdev) {
        let vq = vdev.setup_vq(i)?;
        ring = ring.min(vq.num());
        ops.push(Box::new(VbQueue::new(vdev, vq)?));
    }
    if ring < 3 {
        return Err(DriverError::MissingResource);
    }
    Ok((BlkMq::new(ops), ring))
}

fn new_disk(vdev: &Arc<VirtioDevice>) -> Result<Arc<Disk>, DriverError> {
    let major = *MAJOR
        .try_call_once(|| register_blkdev(0, "virtblk"))
        .map_err(|_| DriverError::InitFailed)?;
    let index = INDEX.fetch_add(1, Ordering::Relaxed);
    if index as usize * VD_MINORS as usize > u16::MAX as usize - VD_MINORS as usize {
        return Err(DriverError::InitFailed);
    }
    let (mq, ring) = setup_queues(vdev)?;
    let nq = mq.nr_hw_queues();
    let lim = limits(vdev, ring);
    let wc = vdev.has_feature(feature::FLUSH);
    let cap = vdev.read_config(|d| d.cfg64(cfg::CAPACITY));
    let disk = Disk::new(
        major,
        index as u16 * VD_MINORS,
        VD_MINORS,
        disk_name("vd", index),
        cap,
        RequestQueue::new_mq(mq, lim, wc),
    );
    disk.set_ro(vdev.has_feature(feature::RO));
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
    fn name(&self) -> &'static str {
        "virtio-blk"
    }

    fn device_id(&self) -> u32 {
        virtio::id::BLOCK
    }

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

    fn probe(&self, vdev: Arc<VirtioDevice>) -> Result<Box<dyn Device>, DriverError> {
        let disk = new_disk(&vdev)?;
        let blk = Arc::new(VirtioBlk {
            vdev: vdev.clone(),
            disk: disk.clone(),
        });
        vdev.request_irq(blk.clone() as Arc<dyn VirtioIrq>)
            .map_err(|e| {
                printkln!("virtio-blk: no IRQ ({})", e);
                DriverError::MissingResource
            })?;
        vdev.ready();
        add_disk(disk).map_err(|_| DriverError::InitFailed)?;
        Ok(Box::new(VirtioBlkDev(blk)))
    }
}
