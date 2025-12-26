//! Storage stack
//!
//! Block device framework, SCSI command layer, and disk drivers.

// Block device framework
pub mod blkdev;
pub mod ramdisk;

// SCSI layer
#[allow(clippy::module_inception)]
pub mod scsi;
pub mod sd;

// Re-export block device types
pub use blkdev::{
    BLKDEV_REGISTRY, Bio, BioFlags, BioOp, BioSeg, BlockDevice, BlockDeviceRegistry, BlockDriver,
    Disk, FifoScheduler, IoScheduler, QueueLimits, RequestQueue, SECTOR_SIZE,
    bytes_to_sectors, get_blkdev, major, register_blkdev, sectors_to_bytes, unregister_blkdev,
};
pub use blkdev::{DevId, DevMajor, DevMinor};

// Re-export ramdisk
pub use ramdisk::{RamDiskDriver, create_ramdisk, create_ramdisk_from_data};

// Re-export SCSI types
pub use scsi::{Cdb, DataDirection, ScsiCommand, ScsiError, ScsiHost, ScsiResult};
pub use sd::{ScsiDisk, create_scsi_disk};
