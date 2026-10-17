//! RAM disk (Linux drivers/block/brd.c)
//!
//! A bio-based driver: the disk's pages are frames allocated on first
//! write and kept in a sparse map; reads of absent pages return zeros.
//! Bios run in the submitter's thread context.
//!
//! ## Locking
//!
//! `pages` (spin `Mutex`, thread context, leaf; Linux brd_pages
//! xarray lock): held only to find or insert a frame, never across a
//! copy into user memory (copies use kernel bounce buffers).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::sync::Arc;

use super::blkdev::{
    Bio, BioOp, BlockDevice, BlockDriver, Disk, QueueLimits, RequestQueue, SECTOR_SHIFT, bio_endio,
    major, register_blkdev,
};
use super::genhd::add_disk;
use crate::arch::phys_to_virt;
use crate::error::KernelError;
use crate::sync::spin::Mutex;

const PAGE: u64 = 4096;

/// RAM disk storage
pub struct RamDisk {
    pages: Mutex<BTreeMap<u64, u64>>,
}

impl RamDisk {
    /// Frame of page `idx`; allocated (zeroed) if `alloc`
    fn page(&self, idx: u64, alloc: bool) -> Result<Option<u64>, KernelError> {
        let mut p = self.pages.lock();
        if let Some(&f) = p.get(&idx) {
            return Ok(Some(f));
        }
        if !alloc {
            return Ok(None);
        }
        let f = crate::FRAME_ALLOCATOR
            .alloc()
            .ok_or(KernelError::OutOfMemory)?;
        unsafe { core::ptr::write_bytes(phys_to_virt(f), 0, PAGE as usize) };
        p.insert(idx, f);
        Ok(Some(f))
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
    let rd = Arc::new(RamDisk {
        pages: Mutex::new(BTreeMap::new()),
    });
    rd.copy(true, 0, data.as_ptr() as *mut u8, data.len())?;
    let q = RequestQueue::new_bio(rd, QueueLimits::default(), false);
    let disk = Disk::new(
        major::RAMDISK,
        minor,
        1,
        format!("rd{}", minor),
        bytes >> SECTOR_SHIFT,
        q,
    );
    add_disk(disk)
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
