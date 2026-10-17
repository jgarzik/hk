//! Disk registration and naming (Linux block/genhd.c)
//!
//! `add_disk` registers the whole-disk block device; `del_gendisk`
//! removes a disk's block devices.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::error::KernelError;

use super::blkdev::{BlockDevice, Disk, disk_bdevs, disk_release, register_bdev, unregister_bdev};

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

/// Register a disk (Linux device_add_disk)
pub fn add_disk(disk: Arc<Disk>) -> Result<Arc<BlockDevice>, KernelError> {
    let whole = Arc::new(BlockDevice::new(
        disk.clone(),
        0,
        0,
        disk.capacity(),
        disk.name.clone(),
    ));
    register_bdev(whole.clone())?;
    Ok(whole)
}

/// Remove block devices of `disk` with `partno >= from`
fn drop_bdevs(disk: &Arc<Disk>, from: u16) {
    for b in disk_bdevs(disk) {
        if b.partno >= from {
            unregister_bdev(b.dev);
        }
    }
}

/// Unregister a disk and its block devices (Linux del_gendisk)
pub fn del_gendisk(disk: &Arc<Disk>) {
    drop_bdevs(disk, 0);
    disk_release(disk);
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
    }
}
