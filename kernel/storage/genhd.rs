//! Disk registration, partitions and naming (Linux block/genhd.c,
//! block/partitions/core.c)
//!
//! `add_disk` registers the whole-disk block device, creates its
//! devtmpfs node and scans the partition table; `rescan` (BLKRRPART)
//! replaces the partitions; `/proc/partitions` lists every block device.
//! Partition scans and rescans run under the disk's `open_mutex`.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::Ordering;

use crate::error::KernelError;
use crate::fs::devtmpfs;

use super::blkdev::{
    BLKDEV_REGISTRY, BioOp, BlockDevice, Disk, bdev_rw, disk_bdevs, disk_release, register_bdev,
    unregister_bdev,
};
use super::part;

/// Name of disk `index` with `prefix`: vda..vdz, vdaa.. (Linux
/// sd_format_disk_name)
pub fn disk_name(prefix: &str, mut index: u32) -> String {
    let mut s = Vec::new();
    loop {
        s.push(b'a' + (index % 26) as u8);
        index /= 26;
        if index == 0 {
            break;
        }
        index -= 1;
    }
    s.reverse();
    let mut n = String::from(prefix);
    n.push_str(core::str::from_utf8(&s).unwrap_or(""));
    n
}

/// Name of partition `partno` of `disk`: vda1, but nvme0n1p1 after a
/// digit (Linux bdevname/disk_name)
pub fn part_name(disk: &str, partno: u16) -> String {
    if disk.ends_with(|c: char| c.is_ascii_digit()) {
        format!("{}p{}", disk, partno)
    } else {
        format!("{}{}", disk, partno)
    }
}

fn node_add(b: &BlockDevice) {
    devtmpfs::device_add(&b.name, b.dev, true, 0o660);
}

/// Register a disk and its partitions (Linux device_add_disk)
pub fn add_disk(disk: Arc<Disk>) -> Result<Arc<BlockDevice>, KernelError> {
    let whole = Arc::new(BlockDevice::new(
        disk.clone(),
        0,
        0,
        disk.capacity(),
        disk.name.clone(),
    ));
    register_bdev(whole.clone())?;
    node_add(&whole);
    if disk.minors > 1 {
        let _g = disk.open_mutex.lock();
        scan_partitions(&whole);
    }
    Ok(whole)
}

/// Read the partition table and add a block device per partition
/// (Linux blk_add_partitions); called with `open_mutex` held
fn scan_partitions(whole: &BlockDevice) {
    let disk = &whole.disk;
    let mut rd = |s: u64, b: &mut [u8; 512]| bdev_rw(whole, BioOp::Read, s, b);
    let parts = part::scan(&mut rd, whole.nr_sects(), disk.minors as usize);
    for (no, p) in parts {
        let b = Arc::new(BlockDevice::new(
            disk.clone(),
            no,
            p.start,
            p.size,
            part_name(&disk.name, no),
        ));
        if register_bdev(b.clone()).is_ok() {
            node_add(&b);
        }
    }
}

/// Remove block devices of `disk` with `partno >= from`
fn drop_bdevs(disk: &Arc<Disk>, from: u16) {
    for b in disk_bdevs(disk) {
        if b.partno >= from {
            unregister_bdev(b.dev);
            devtmpfs::device_del(&b.name);
        }
    }
}

/// A partition is held beyond the registry: an open file, a mounted
/// filesystem or active swap (each opens the device in Linux)
fn parts_held(disk: &Arc<Disk>) -> bool {
    disk.open_partitions.load(Ordering::Relaxed) != 0
        || BLKDEV_REGISTRY
            .read()
            .values()
            .any(|b| Arc::ptr_eq(&b.disk, disk) && b.partno != 0 && Arc::strong_count(b) > 1)
}

/// BLKRRPART: re-read the partition table (Linux disk_scan_partitions):
/// EINVAL on a partition or a disk without partitions, EBUSY while a
/// partition is in use
pub fn rescan(bdev: &BlockDevice) -> Result<(), KernelError> {
    let disk = &bdev.disk;
    if bdev.partno != 0 || disk.minors <= 1 {
        return Err(KernelError::InvalidArgument);
    }
    let _g = disk.open_mutex.lock();
    if parts_held(disk) {
        return Err(KernelError::Busy);
    }
    drop_bdevs(disk, 1);
    scan_partitions(bdev);
    Ok(())
}

/// Unregister a disk and its partitions (Linux del_gendisk)
pub fn del_gendisk(disk: &Arc<Disk>) {
    drop_bdevs(disk, 0);
    disk_release(disk);
}

/// /proc/partitions (Linux show_partition): every block device with a
/// non-zero size, in device number order
pub fn proc_partitions() -> Vec<u8> {
    let mut s = String::from("major minor  #blocks  name\n\n");
    for b in BLKDEV_REGISTRY.read().values() {
        if b.nr_sects() == 0 {
            continue;
        }
        let _ = writeln!(
            s,
            "{:4}  {:7} {:10} {}",
            b.dev.major,
            b.dev.minor,
            b.nr_sects() >> 1,
            b.name
        );
    }
    s.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(disk_name("vd", 0), "vda");
        assert_eq!(disk_name("vd", 25), "vdz");
        assert_eq!(disk_name("sd", 26), "sdaa");
        assert_eq!(disk_name("sd", 27), "sdab");
        assert_eq!(disk_name("sd", 26 + 26 * 26), "sdaaa");
        assert_eq!(part_name("vda", 3), "vda3");
        assert_eq!(part_name("nvme0n1", 1), "nvme0n1p1");
    }
}
