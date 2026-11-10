//! Disk registration, partitions and naming (Linux block/genhd.c,
//! block/partitions/core.c)
//!
//! `add_disk` registers the whole-disk block device as a block-class
//! device (its sysfs directory, /sys/block link, devtmpfs node and
//! uevent) and scans the partition table, each partition a device below
//! the disk; `rescan` (BLKRRPART) replaces the partitions;
//! `/proc/partitions` lists every block device. Partition scans and
//! rescans run under the disk's `open_mutex`.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;

use spin::Once;

use crate::base::{Class, Device, DeviceInfo, device_create};
use crate::fs::kernfs::{self, KNode};
use crate::util::error::KernelError;
use crate::util::kalloc::try_arc;

use super::blkdev::{
    BLKDEV_REGISTRY, BioOp, BlockDevice, Disk, bdev_rw_bytes, disk_bdevs, disk_release,
    register_bdev, unregister_bdev,
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

/// The block class (Linux block_class)
pub static BLOCK_CLASS: Class = Class::block("block", Some(block_uevent));

/// /sys/block (Linux block_depr)
static SYS_BLOCK: Once<Arc<KNode>> = Once::new();

/// Linux genhd_device_init: the class and /sys/block
pub fn genhd_init() {
    BLOCK_CLASS.register();
    SYS_BLOCK.call_once(|| crate::fs::kernfs::sysfs::top_dir(b"block"));
}

fn bdev_of(dev: &Device) -> Option<&BlockDevice> {
    dev.data::<BlockDevice>()
}

/// Linux part_uevent (PARTN) and disk_uevent (DISKSEQ)
fn block_uevent(dev: &Device, env: &mut Vec<Vec<u8>>) {
    let Some(b) = bdev_of(dev) else { return };
    if b.partno != 0 {
        env.push(format!("PARTN={}", b.partno).into_bytes());
    } else {
        env.push(format!("DISKSEQ={}", b.disk.seq).into_bytes());
    }
}

/// A text attribute of `dev` showing `f(bdev)`; it refers to the block
/// device weakly (a removed one's node may outlive it in the dcache,
/// as Linux's kernfs_node does its kobject)
fn battr(
    dev: &Arc<Device>,
    dir: &Arc<KNode>,
    name: &[u8],
    f: fn(&BlockDevice) -> String,
) -> Result<(), KernelError> {
    let b = dev.data_arc::<BlockDevice>().ok_or(KernelError::NoDevice)?;
    let b = Arc::downgrade(&b);
    dir.create_file(
        name,
        0o444,
        kernfs::show(move |o| {
            if let Some(b) = b.upgrade() {
                o.bytes(f(&b).as_bytes());
            }
        }),
    )?;
    Ok(())
}

/// An attribute: its name and its value from the block device
type BAttr = (&'static [u8], fn(&BlockDevice) -> String);

/// Attributes both disks and partitions have
const COMMON_ATTRS: [BAttr; 4] = [
    (b"size", |b| format!("{}\n", b.nr_sects())),
    (b"ro", |b| format!("{}\n", u8::from(b.ro()))),
    (b"alignment_offset", |_| String::from("0\n")),
    (b"discard_alignment", |_| String::from("0\n")),
];

/// A disk's attributes and queue/ (Linux disk_attrs, queue_attrs)
fn disk_attrs(dev: &Arc<Device>) -> Result<(), KernelError> {
    let d = dev.kobj();
    let attrs: [BAttr; 7] = [
        (b"removable", |_| String::from("0\n")),
        (b"hidden", |_| String::from("0\n")),
        (b"range", |b| format!("{}\n", b.disk.minors)),
        (b"ext_range", |b| format!("{}\n", b.disk.minors)),
        // GENHD_FL_NO_PART for a disk without partitions
        (b"capability", |b| {
            format!("{:x}\n", if b.disk.minors > 1 { 0 } else { 4 })
        }),
        (b"diskseq", |b| format!("{}\n", b.disk.seq)),
        (b"inflight", |_| String::from("       0        0\n")),
    ];
    for (n, f) in COMMON_ATTRS.into_iter().chain(attrs) {
        battr(dev, d, n, f)?;
    }
    let q = d.create_dir(b"queue", 0o755)?;
    let qattrs: [BAttr; 11] = [
        (b"logical_block_size", |b| {
            format!("{}\n", b.logical_block_size())
        }),
        (b"physical_block_size", |b| {
            format!("{}\n", b.physical_block_size())
        }),
        (b"hw_sector_size", |b| {
            format!("{}\n", b.logical_block_size())
        }),
        (b"minimum_io_size", |b| {
            format!("{}\n", b.physical_block_size())
        }),
        (b"optimal_io_size", |_| String::from("0\n")),
        (b"rotational", |b| {
            format!("{}\n", u8::from(b.disk.queue.limits.rotational))
        }),
        (b"max_sectors_kb", |b| {
            format!("{}\n", b.disk.queue.limits.max_sectors / 2)
        }),
        (b"max_hw_sectors_kb", |b| {
            format!("{}\n", b.disk.queue.limits.max_hw_sectors / 2)
        }),
        (b"max_segments", |b| {
            format!("{}\n", b.disk.queue.limits.max_segments)
        }),
        (b"max_segment_size", |b| {
            format!("{}\n", b.disk.queue.limits.max_segment_size)
        }),
        (b"read_ahead_kb", |_| String::from("128\n")),
    ];
    for (n, f) in qattrs {
        battr(dev, &q, n, f)?;
    }
    d.create_dir(b"holders", 0o755)?;
    d.create_dir(b"slaves", 0o755)?;
    Ok(())
}

/// A partition's attributes (Linux part_attrs)
fn part_attrs(dev: &Arc<Device>) -> Result<(), KernelError> {
    let d = dev.kobj();
    let attrs: [BAttr; 2] = [
        (b"partition", |b| format!("{}\n", b.partno)),
        (b"start", |b| format!("{}\n", b.start)),
    ];
    for (n, f) in COMMON_ATTRS.into_iter().chain(attrs) {
        battr(dev, d, n, f)?;
    }
    Ok(())
}

/// The block-class device of `b` below `parent` (Linux device_add of
/// the disk's or partition's struct device)
fn bdev_device_add(b: &Arc<BlockDevice>, parent: Option<&Arc<Device>>) {
    let disk = b.partno == 0;
    let r = device_create(DeviceInfo {
        parent,
        class: Some(&BLOCK_CLASS),
        devt: Some(b.dev),
        devtype: Some(if disk { "disk" } else { "partition" }),
        data: Some(b.clone()),
        attrs: Some(if disk { disk_attrs } else { part_attrs }),
        ..DeviceInfo::named(&b.name)
    });
    match r {
        Ok(d) => {
            if disk && let Some(sb) = SYS_BLOCK.get() {
                let _ = sb.create_link(b.name.as_bytes(), d.kobj());
            }
            b.kdev.call_once(|| Arc::downgrade(&d));
        }
        Err(e) => crate::printkln!("block: {}: {:?}", b.name, e),
    }
}

fn bdev_device_del(b: &BlockDevice) {
    if let Some(d) = b.kdev.get().and_then(|d| d.upgrade()) {
        if b.partno == 0
            && let Some(sb) = SYS_BLOCK.get()
        {
            sb.remove_child(b.name.as_bytes());
        }
        d.del();
    }
}

/// Register a disk below `parent` and its partitions (Linux
/// device_add_disk)
pub fn add_disk(
    disk: Arc<Disk>,
    parent: Option<&Arc<Device>>,
) -> Result<Arc<BlockDevice>, KernelError> {
    let whole = try_arc(BlockDevice::new(
        disk.clone(),
        0,
        0,
        disk.capacity(),
        disk.name.clone(),
    ))?;
    register_bdev(whole.clone())?;
    bdev_device_add(&whole, parent);
    if disk.minors > 1 {
        let _g = disk.open_mutex.lock();
        scan_partitions(&whole);
    }
    Ok(whole)
}

/// Read the partition table and add a block device per partition
/// (Linux blk_add_partitions); called with `open_mutex` held
fn scan_partitions(whole: &BlockDevice) {
    let parent = whole.kdev.get().and_then(|d| d.upgrade());
    let disk = &whole.disk;
    let mut rd = |s: u64, b: &mut [u8; 512]| bdev_rw_bytes(whole, BioOp::Read, s << 9, b);
    let parts = part::scan(&mut rd, whole.nr_sects(), disk.minors as usize);
    for (no, p) in parts {
        // A partition that cannot be had is skipped (Linux
        // blk_add_partition)
        let Ok(b) = try_arc(BlockDevice::new(
            disk.clone(),
            no,
            p.start,
            p.size,
            part_name(&disk.name, no),
        )) else {
            continue;
        };
        if register_bdev(b.clone()).is_ok() {
            bdev_device_add(&b, parent.as_ref());
        }
    }
}

/// Remove block devices of `disk` with `partno >= from`
fn drop_bdevs(disk: &Arc<Disk>, from: u16) {
    let mut gone: Vec<_> = disk_bdevs(disk)
        .into_iter()
        .filter(|b| b.partno >= from)
        .collect();
    // Partitions before their disk
    gone.sort_by_key(|b| core::cmp::Reverse(b.partno));
    for b in gone {
        unregister_bdev(b.dev);
        bdev_device_del(&b);
    }
}

/// BLKRRPART: re-read the partition table (Linux disk_scan_partitions):
/// EINVAL on a partition or a disk without partitions, EBUSY while a
/// partition is in use
pub fn rescan(bdev: &BlockDevice) -> Result<(), KernelError> {
    let disk = &bdev.disk;
    if bdev.partno != 0 || disk.minors <= 1 {
        return Err(KernelError::InvalidArgument);
    }
    let st = disk.open_mutex.lock();
    // A partition is open: a file, a mounted filesystem or active swap
    // (each opens the device, as in Linux)
    if st.open_partitions != 0 {
        return Err(KernelError::Busy);
    }
    drop_bdevs(disk, 1);
    scan_partitions(bdev);
    Ok(())
}

/// Unregister a disk and its partitions (Linux del_gendisk): new I/O
/// fails with EIO, open files get EIO, and the requests in flight
/// complete before it returns, so the driver may then stop the device
pub fn del_gendisk(disk: &Arc<Disk>) {
    {
        // Under open_mutex, like a rescan: an open in progress either
        // finished before or sees the device dead
        let _g = disk.open_mutex.lock();
        disk.queue.start_drain();
        drop_bdevs(disk, 0);
    }
    // Started requests complete before the bdi goes (Linux freezes the
    // queue before tearing the disk down)
    disk.queue.drain();
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
