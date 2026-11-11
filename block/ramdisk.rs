//! RAM disk (Linux drivers/block/brd.c)
//!
//! A bio-based driver: the disk's pages are frames allocated on first
//! write and kept in a sparse map; reads of absent pages return zeros.
//! Bios run in the submitter's thread context.
//!
//! ## Locking
//!
//! `pages` (spin `Mutex` over an `XArray`, thread context, leaf; Linux
//! brd_pages xarray lock): held only to find or insert a frame, never
//! across a copy into user memory (copies use kernel bounce buffers).
//! Nothing allocates under it: a new page's frame is allocated and
//! zeroed before it is taken (Linux brd_insert_page), its index nodes
//! with it dropped (`xarray::store_nomem`); a frame that lost a race is
//! freed.
#![expect(clippy::undocumented_unsafe_blocks)] // TODO(unsafe): SAFETY comments (doc/UNSAFE.md)

use alloc::boxed::Box;
use alloc::format;
use alloc::sync::Arc;

use super::blkdev::{
    Bio, BioOp, BlockDevice, BlockDriver, Disk, QueueLimits, RequestQueue, SECTOR_SHIFT, bio_endio,
    major, register_blkdev,
};
use super::genhd::add_disk;
use crate::arch::phys_to_virt;
use crate::mm::xarray::XArray;
use crate::sync::spin::Mutex;
use crate::util::error::KernelError;
use crate::util::kalloc::try_arc;

const PAGE: u64 = 4096;

/// RAM disk storage
pub struct RamDisk {
    pages: Mutex<XArray>,
}

impl RamDisk {
    /// Frame of page `idx`; allocated (zeroed) if `alloc`
    fn page(&self, idx: u64, alloc: bool) -> Result<Option<u64>, KernelError> {
        let f = self.pages.lock().load(idx);
        if f != 0 {
            return Ok(Some(f));
        }
        if !alloc {
            return Ok(None);
        }
        // The frame first, with no lock held (Linux brd_insert_page)
        let f = crate::FRAME_ALLOCATOR
            .alloc()
            .ok_or(KernelError::OutOfMemory)?;
        // SAFETY: a fresh frame of PAGE bytes, mapped in the direct map,
        // not yet visible to anyone
        unsafe { core::ptr::write_bytes(phys_to_virt(f), 0, PAGE as usize) };
        let stored = crate::mm::xarray::store_nomem(
            || self.pages.lock(),
            idx,
            f,
            |t| match t.load(idx) {
                0 => Ok(()),
                other => Err(Some(other)),
            },
            None,
        );
        match stored {
            Ok(_) => Ok(Some(f)),
            // Another writer's page won (Linux __xa_cmpxchg): ours goes
            Err(won) => {
                crate::FRAME_ALLOCATOR.free(f);
                won.map(Some).ok_or(KernelError::OutOfMemory)
            }
        }
    }

    /// Copy `len` bytes between disk byte `pos` and kernel memory `mem`
    /// (`write`: from `mem` to the disk)
    fn copy(&self, write: bool, pos: u64, mem: *mut u8, len: usize) -> Result<(), KernelError> {
        let mut done = 0;
        while done < len {
            let at = pos + done as u64;
            let off = (at % PAGE) as usize;
            let n = (len - done).min(PAGE as usize - off);
            let m = unsafe { mem.add(done) };
            match self.page(at / PAGE, write)? {
                Some(f) => unsafe {
                    let d = phys_to_virt(f).add(off);
                    if write {
                        core::ptr::copy_nonoverlapping(m, d, n);
                    } else {
                        core::ptr::copy_nonoverlapping(d, m, n);
                    }
                },
                None => unsafe { core::ptr::write_bytes(m, 0, n) },
            }
            done += n;
        }
        Ok(())
    }

    fn do_bio(&self, bio: &Bio) -> Result<(), KernelError> {
        if bio.op == BioOp::Flush {
            return Ok(());
        }
        let mut pos = bio.sector << SECTOR_SHIFT;
        for s in &bio.segs {
            let mem = unsafe { phys_to_virt(s.frame).add(s.offset) };
            self.copy(bio.op == BioOp::Write, pos, mem, s.len)?;
            pos += s.len as u64;
        }
        Ok(())
    }
}

impl BlockDriver for RamDisk {
    fn submit_bio(&self, mut bio: Box<Bio>) {
        bio.status = self.do_bio(&bio);
        bio_endio(bio);
    }
}

/// Create RAM disk `rd<minor>` of `bytes` bytes holding `data`
fn create(minor: u16, bytes: u64, data: &[u8]) -> Result<Arc<BlockDevice>, KernelError> {
    register_blkdev(major::RAMDISK, "ramdisk")?;
    let rd = try_arc(RamDisk {
        pages: Mutex::new(XArray::new()),
    })?;
    rd.copy(true, 0, data.as_ptr().cast_mut(), data.len())?;
    // brd: no seek cost (Linux QUEUE_FLAG_NONROT), never waits
    // (BLK_FEAT_NOWAIT)
    let limits = QueueLimits {
        rotational: false,
        nowait: true,
        ..QueueLimits::default()
    };
    let q = RequestQueue::new_bio(rd, limits, false);
    let disk = Disk::new(
        major::RAMDISK,
        minor,
        1,
        format!("rd{}", minor),
        bytes >> SECTOR_SHIFT,
        q,
        false,
    )?;
    add_disk(disk, None)
}

/// Create an empty RAM disk of `capacity_mb` MiB
pub fn create_ramdisk(minor: u16, capacity_mb: u64) -> Result<Arc<BlockDevice>, KernelError> {
    create(minor, capacity_mb << 20, &[])
}

/// Create a RAM disk holding `data` (a filesystem image), its size
/// rounded up to a MiB
pub fn create_ramdisk_from_data(minor: u16, data: &[u8]) -> Result<Arc<BlockDevice>, KernelError> {
    create(minor, (data.len() as u64).next_multiple_of(1 << 20), data)
}
