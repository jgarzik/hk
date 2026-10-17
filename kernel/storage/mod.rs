//! Storage stack
//!
//! Block layer (bios, blk-mq-lite, disks, partitions), the SCSI command
//! layer and the disk drivers.

pub mod blk_mq;
pub mod blkdev;
pub mod genhd;
pub mod ramdisk;

// SCSI layer
#[allow(clippy::module_inception)]
pub mod scsi;
pub mod sd;

pub use blkdev::{
    BLKDEV_REGISTRY, Bio, BioOp, BioSeg, BlockDevice, BlockDriver, DevId, DevMajor, DevMinor, Disk,
    QueueLimits, RequestQueue, SECTOR_SIZE, get_blkdev, major, register_blkdev,
};
pub use ramdisk::{create_ramdisk, create_ramdisk_from_data};
pub use scsi::{Cdb, DataDirection, ScsiCommand, ScsiError, ScsiHost, ScsiResult};
pub use sd::{ScsiDisk, create_scsi_disk};
