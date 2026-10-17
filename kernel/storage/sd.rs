//! SCSI Disk Driver (sd)
//!
//! A bio-based driver: bios become synchronous SCSI READ(10)/WRITE(10)/
//! SYNCHRONIZE CACHE commands in the submitter's thread context (the
//! USB transport sleeps and takes the controller mutex). Disks are
//! sda, sdb, ... on major 8 with 16 minors each (Linux sd).
//!
//! ## Device States (following Linux kernel scsi_device.h)
//!
//! SCSI devices have a state machine for hotplug support:
//! - `Running` - Device is operational
//! - `Cancel` - Device is being removed, no new commands accepted
//! - `Del` - Device deleted, final cleanup
//! - `Quiesce` - I/O paused (for error recovery)
//! - `Offline` - Device offline, I/O fails
//! - `TransportOffline` - Transport layer reports offline
//! - `Block` - Device blocked for I/O

use alloc::boxed::Box;
use alloc::sync::Arc;

use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use super::blkdev::{
    Bio, BioOp, BlockDevice, BlockDriver, DevId, Disk, QueueLimits, RequestQueue, SECTOR_SHIFT,
    bio_endio, disk_bdevs, get_blkdev, major, register_blkdev,
};
use super::genhd::{add_disk, del_gendisk, disk_name};

use crate::error::KernelError;

use super::scsi::{
    Cdb, ScsiCommand, ScsiError, ScsiHost, ScsiResult, inquiry, read_capacity, test_unit_ready,
};

/// SCSI device states (mirrors Linux kernel's enum scsi_device_state)
///
/// These states control device lifecycle and I/O acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ScsiDeviceState {
    /// Device has been created but not yet running
    Created = 0,
    /// Device is fully operational
    Running = 1,
    /// Device is being removed, no new commands accepted
    Cancel = 2,
    /// Device has been deleted, cleanup in progress
    Del = 3,
    /// Device is quiesced (I/O paused for error recovery)
    Quiesce = 4,
    /// Device is offline, all I/O fails
    Offline = 5,
    /// Transport layer reports device offline
    TransportOffline = 6,
    /// Device is blocked for I/O
    Block = 7,
}

impl ScsiDeviceState {
    /// Check if device accepts new I/O commands
    pub fn accepts_io(self) -> bool {
        matches!(self, ScsiDeviceState::Running)
    }

    /// Check if device is being removed
    pub fn is_removing(self) -> bool {
        matches!(self, ScsiDeviceState::Cancel | ScsiDeviceState::Del)
    }
}

impl From<u8> for ScsiDeviceState {
    fn from(val: u8) -> Self {
        match val {
            0 => ScsiDeviceState::Created,
            1 => ScsiDeviceState::Running,
            2 => ScsiDeviceState::Cancel,
            3 => ScsiDeviceState::Del,
            4 => ScsiDeviceState::Quiesce,
            5 => ScsiDeviceState::Offline,
            6 => ScsiDeviceState::TransportOffline,
            7 => ScsiDeviceState::Block,
            _ => ScsiDeviceState::Offline, // Default to offline for invalid values
        }
    }
}

/// SCSI Disk device state
pub struct ScsiDisk {
    /// SCSI host adapter for command execution
    host: Arc<dyn ScsiHost>,
    /// Target ID
    target: u8,
    /// Logical Unit Number
    lun: u8,
    /// Device state (atomic for lock-free access)
    state: AtomicU8,
    /// Disk capacity in sectors
    capacity_sectors: u64,
    /// Sector size in bytes (typically 512)
    sector_size: u32,
    /// Vendor identification
    #[allow(dead_code)]
    vendor: [u8; 8],
    /// Product identification
    #[allow(dead_code)]
    product: [u8; 16],
}

impl ScsiDisk {
    /// Probe a SCSI target and create disk if present
    pub fn probe(host: Arc<dyn ScsiHost>, target: u8, lun: u8) -> ScsiResult<Self> {
        crate::printkln!("SCSI: Probing target={} lun={}", target, lun);

        // Test if device is ready
        crate::printkln!("SCSI: Calling test_unit_ready");
        test_unit_ready(&host, target, lun)?;
        crate::printkln!("SCSI: test_unit_ready OK");

        // Get device identification
        let inq = inquiry(&host, target, lun)?;

        // Only handle disk devices
        if !inq.is_disk() {
            return Err(ScsiError::NotSupported);
        }

        // Get capacity
        let cap = read_capacity(&host, target, lun)?;

        // Device-reported geometry is untrusted (Linux sd_read_capacity):
        // 512..4096-byte power-of-two sectors only; READ(10) addresses
        // at most 2^32 blocks (last LBA 0xffffffff means "use READ
        // CAPACITY(16)", which is not issued)
        let sector_size = cap.block_length();
        if !(512..=4096).contains(&sector_size) || !sector_size.is_power_of_two() {
            crate::printkln!("SCSI: unsupported sector size {}", sector_size);
            return Err(ScsiError::NotSupported);
        }
        let capacity_sectors = cap.total_blocks().min(u32::MAX as u64);

        Ok(Self {
            host,
            target,
            lun,
            state: AtomicU8::new(ScsiDeviceState::Running as u8),
            capacity_sectors,
            sector_size,
            vendor: inq.vendor,
            product: inq.product,
        })
    }

    /// Get current device state
    pub fn state(&self) -> ScsiDeviceState {
        ScsiDeviceState::from(self.state.load(Ordering::Acquire))
    }

    /// Set device state (returns previous state)
    pub fn set_state(&self, new_state: ScsiDeviceState) -> ScsiDeviceState {
        let old = self.state.swap(new_state as u8, Ordering::AcqRel);
        ScsiDeviceState::from(old)
    }

    /// Transition to Cancel state (beginning of removal)
    ///
    /// Returns true if transition was successful.
    pub fn cancel(&self) -> bool {
        let current = self.state();
        if current == ScsiDeviceState::Running {
            self.set_state(ScsiDeviceState::Cancel);
            true
        } else {
            false
        }
    }

    /// Transition to Del state (final removal)
    pub fn mark_deleted(&self) {
        self.set_state(ScsiDeviceState::Del);
    }

    /// Mark device as offline (transport error)
    pub fn mark_offline(&self) {
        self.set_state(ScsiDeviceState::Offline);
    }

    /// Check if device accepts I/O
    pub fn accepts_io(&self) -> bool {
        self.state().accepts_io()
    }

    /// Get disk capacity in sectors
    pub fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    /// Get sector size
    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }

    /// Get capacity in bytes
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_sectors * self.sector_size as u64
    }

    /// Read sectors from disk
    ///
    /// Checks device state before issuing command - returns NoDevice if
    /// device is not in Running state.
    pub fn read_sectors(&self, lba: u64, count: u32, buf: &mut [u8]) -> ScsiResult<usize> {
        // Check device state (like Linux scsi_device_online())
        if !self.accepts_io() {
            return Err(ScsiError::NoDevice);
        }

        if lba > u32::MAX as u64 || count > u16::MAX as u32 {
            // Would need READ(16) for larger values
            return Err(ScsiError::IllegalRequest);
        }

        let expected_len = count as usize * self.sector_size as usize;
        if buf.len() < expected_len {
            return Err(ScsiError::IllegalRequest);
        }

        let cmd = ScsiCommand::read(
            Cdb::read_10(lba as u32, count as u16),
            buf.as_mut_ptr(),
            expected_len,
            30000, // 30 second timeout for I/O
        );

        self.host.execute(self.target, self.lun, &cmd)
    }

    /// Write sectors to disk
    ///
    /// Checks device state before issuing command - returns NoDevice if
    /// device is not in Running state.
    pub fn write_sectors(&self, lba: u64, count: u32, buf: &[u8]) -> ScsiResult<usize> {
        // Check device state
        if !self.accepts_io() {
            return Err(ScsiError::NoDevice);
        }

        if lba > u32::MAX as u64 || count > u16::MAX as u32 {
            return Err(ScsiError::IllegalRequest);
        }

        let expected_len = count as usize * self.sector_size as usize;
        if buf.len() < expected_len {
            return Err(ScsiError::IllegalRequest);
        }

        let cmd = ScsiCommand::write(
            Cdb::write_10(lba as u32, count as u16),
            buf.as_ptr() as *mut u8,
            expected_len,
            30000,
        );

        self.host.execute(self.target, self.lun, &cmd)
    }

    /// Flush disk cache
    ///
    /// Checks device state before issuing command.
    pub fn sync_cache(&self) -> ScsiResult<()> {
        if !self.accepts_io() {
            return Err(ScsiError::NoDevice);
        }

        let cmd = ScsiCommand::no_data(Cdb::synchronize_cache_10(), 60000); // 60 second timeout
        self.host.execute(self.target, self.lun, &cmd)?;
        Ok(())
    }
}

/// SCSI disk driver: the bio-based side of a [`ScsiDisk`]
pub struct ScsiDiskDriver {
    disk: Arc<ScsiDisk>,
}

impl ScsiDiskDriver {
    /// Run one bio; segments are consecutive on the disk
    fn do_bio(&self, bio: &Bio) -> Result<(), KernelError> {
        let ss = self.disk.sector_size() as u64;
        if bio.op == BioOp::Flush {
            return self.disk.sync_cache().map_err(|_| KernelError::Io);
        }
        let mut pos = bio.sector << SECTOR_SHIFT;
        for seg in &bio.segs {
            if !pos.is_multiple_of(ss) || !(seg.len as u64).is_multiple_of(ss) {
                return Err(KernelError::Io);
            }
            let (lba, n) = (pos / ss, (seg.len as u64 / ss) as u32);
            let p = unsafe { crate::arch::phys_to_virt(seg.frame).add(seg.offset) };
            let r = if bio.op == BioOp::Write {
                let buf = unsafe { core::slice::from_raw_parts(p as *const u8, seg.len) };
                self.disk.write_sectors(lba, n, buf)
            } else {
                let buf = unsafe { core::slice::from_raw_parts_mut(p, seg.len) };
                self.disk.read_sectors(lba, n, buf)
            };
            r.map_err(|_| KernelError::Io)?;
            pos += seg.len as u64;
        }
        Ok(())
    }
}

impl BlockDriver for ScsiDiskDriver {
    fn submit_bio(&self, mut bio: Box<Bio>) {
        bio.status = self.do_bio(&bio);
        bio_endio(bio);
    }
}

/// Minors per disk: the disk and 15 partitions (Linux SD_MINORS)
const SD_MINORS: u16 = 16;

/// Next disk index (sda = 0)
static SD_INDEX: AtomicU32 = AtomicU32::new(0);

/// Probe a SCSI target and add it as the next sdX disk
pub fn create_scsi_disk(
    host: Arc<dyn ScsiHost>,
    target: u8,
    lun: u8,
) -> Result<Arc<BlockDevice>, KernelError> {
    let scsi_disk =
        Arc::new(ScsiDisk::probe(host, target, lun).map_err(|_| KernelError::NotFound)?);
    let index = SD_INDEX.fetch_add(1, Ordering::Relaxed);
    if index >= 16 {
        return Err(KernelError::NoSpace);
    }
    register_blkdev(major::SCSI_DISK, "sd")?;
    let ss = scsi_disk.sector_size();
    let limits = QueueLimits {
        logical_block_size: ss,
        physical_block_size: ss,
        ..QueueLimits::default()
    };
    let q = RequestQueue::new_bio(
        Arc::new(ScsiDiskDriver {
            disk: scsi_disk.clone(),
        }),
        limits,
        true,
    );
    let name = disk_name("sd", index);
    let disk = Disk::new(
        major::SCSI_DISK,
        index as u16 * SD_MINORS,
        SD_MINORS,
        name.clone(),
        scsi_disk.capacity_bytes() >> SECTOR_SHIFT,
        q,
    );
    let bdev = add_disk(disk)?;
    crate::printkln!(
        "SCSI: {} ({} MB, {} byte sectors)",
        name,
        scsi_disk.capacity_bytes() / (1024 * 1024),
        ss
    );
    Ok(bdev)
}

/// Remove SCSI disk `index` (sda = 0) on hot unplug: its block devices
/// fail I/O from now on and its cached pages are dropped
pub fn unregister_scsi_disk(index: u16) -> Result<(), KernelError> {
    let dev = DevId::new(major::SCSI_DISK, index * SD_MINORS);
    let bdev = get_blkdev(dev).ok_or(KernelError::NotFound)?;
    // The disk and each partition: unregistered (open files see a dead
    // device, never a new one: indexes and minors are not reused) and
    // their cached pages dropped
    let all = disk_bdevs(&bdev.disk);
    del_gendisk(&bdev.disk);
    let mut freed = 0;
    for b in &all {
        freed += crate::invalidate_blkdev_pages(b.dev.major, b.dev.minor);
    }
    crate::printkln!("SCSI: {} removed ({} cached pages freed)", bdev.name, freed);
    Ok(())
}
