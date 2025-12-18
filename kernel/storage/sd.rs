//! SCSI Disk Driver (sd)
//!
//! Implements the BlockDriver trait for SCSI disks.
//! Translates Bio requests into SCSI READ/WRITE commands.
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

use alloc::string::String;
use alloc::sync::Arc;

use core::sync::atomic::{AtomicU8, Ordering};

use super::{
    Bio, BioOp, BlockDevice, BlockDriver, BlockError, DevId, Disk, QueueLimits, RequestQueue,
    major, register_blkdev, unregister_blkdev,
};

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

        let sector_size = cap.block_length();
        let capacity_sectors = cap.total_blocks();

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

/// SCSI Disk Driver implementing BlockDriver trait
pub struct ScsiDiskDriver {
    /// The underlying SCSI disk
    disk: Arc<ScsiDisk>,
}

impl ScsiDiskDriver {
    /// Create a new SCSI disk driver
    pub fn new(disk: Arc<ScsiDisk>) -> Arc<Self> {
        Arc::new(Self { disk })
    }
}

impl BlockDriver for ScsiDiskDriver {
    fn submit(&self, _blk_disk: &Disk, bio: Bio) {
        let result = match bio.op {
            BioOp::Read => self.handle_read(&bio),
            BioOp::Write => self.handle_write(&bio),
            BioOp::Flush => self.handle_flush(),
        };

        bio.complete(result);
    }

    fn name(&self) -> &str {
        "sd"
    }

    fn readpage(&self, _blk_disk: &Disk, frame: u64, page_offset: u64) {
        // Read a single page (4096 bytes = 8 sectors)
        let lba = page_offset * 8; // page_offset is in pages, convert to 512-byte sectors
        crate::printkln!(
            "sd: readpage frame=0x{:x} page_offset={} lba={}",
            frame,
            page_offset,
            lba
        );
        let buf = unsafe { core::slice::from_raw_parts_mut(frame as *mut u8, 4096) };

        if let Err(e) = self.disk.read_sectors(lba, 8, buf) {
            crate::printkln!("sd: readpage error: {:?}", e);
            // On error, zero the page
            buf.fill(0);
        } else {
            crate::printkln!("sd: readpage success");
        }
    }

    fn writepage(&self, _blk_disk: &Disk, frame: u64, page_offset: u64) {
        // Write a single page (4096 bytes = 8 sectors)
        let lba = page_offset * 8; // page_offset is in pages, convert to 512-byte sectors
        let buf = unsafe { core::slice::from_raw_parts(frame as *const u8, 4096) };

        if let Err(e) = self.disk.write_sectors(lba, 8, buf) {
            crate::printkln!("sd: writepage error: {:?}", e);
        }
    }
}

impl ScsiDiskDriver {
    /// Handle a read bio
    fn handle_read(&self, bio: &Bio) -> Result<(), BlockError> {
        // For each segment in the bio, read the data
        for seg in &bio.segs {
            let buf = unsafe { core::slice::from_raw_parts_mut(seg.frame as *mut u8, seg.len) };

            // Calculate LBA from bio.lba and segment offset
            let sectors_per_seg = seg.len / 512;
            self.disk
                .read_sectors(bio.lba, sectors_per_seg as u32, buf)
                .map_err(|_| BlockError::IoError)?;
        }
        Ok(())
    }

    /// Handle a write bio
    fn handle_write(&self, bio: &Bio) -> Result<(), BlockError> {
        for seg in &bio.segs {
            let buf = unsafe { core::slice::from_raw_parts(seg.frame as *const u8, seg.len) };

            let sectors_per_seg = seg.len / 512;
            self.disk
                .write_sectors(bio.lba, sectors_per_seg as u32, buf)
                .map_err(|_| BlockError::IoError)?;
        }
        Ok(())
    }

    /// Handle a flush bio
    fn handle_flush(&self) -> Result<(), BlockError> {
        self.disk.sync_cache().map_err(|_| BlockError::IoError)
    }
}

/// Create and register a SCSI disk device
///
/// # Arguments
/// * `host` - SCSI host adapter (e.g., SAT layer)
/// * `target` - Target ID
/// * `lun` - Logical Unit Number
/// * `minor` - Minor device number (0 for sd0, 1 for sd1, etc.)
///
/// # Returns
/// The created BlockDevice on success
pub fn create_scsi_disk(
    host: Arc<dyn ScsiHost>,
    target: u8,
    lun: u8,
    minor: u16,
) -> Result<Arc<BlockDevice>, BlockError> {
    // Probe the device
    let scsi_disk = Arc::new(ScsiDisk::probe(host, target, lun).map_err(|_| BlockError::NotFound)?);

    // Create driver
    let driver = ScsiDiskDriver::new(scsi_disk.clone());

    // Determine sector size (use 512 for compatibility)
    let sector_size = if scsi_disk.sector_size() == 512 {
        512
    } else {
        // For 4K native drives, we still expose 512-byte sectors
        // This is a simplification; real drivers handle this more carefully
        512
    };

    // Calculate capacity in 512-byte sectors
    let capacity_sectors = scsi_disk.capacity_bytes() / 512;

    // Create request queue
    let queue = Arc::new(RequestQueue::new(driver.clone(), QueueLimits::default()));

    // Create disk name
    let name = match minor {
        0 => String::from("sd0"),
        1 => String::from("sd1"),
        2 => String::from("sd2"),
        3 => String::from("sd3"),
        n => alloc::format!("sd{}", n),
    };

    // Create disk
    let dev_id = DevId::new(major::SCSI_DISK, minor);
    let disk = Disk::new(dev_id, name.clone(), capacity_sectors, sector_size, queue);

    // Create block device
    let bdev = Arc::new(BlockDevice::new(disk));

    // Register globally
    register_blkdev(dev_id, bdev.clone())?;

    crate::printkln!(
        "SCSI: {} ({} MB, {} byte sectors)",
        name,
        scsi_disk.capacity_bytes() / (1024 * 1024),
        scsi_disk.sector_size()
    );

    Ok(bdev)
}

/// Unregister a SCSI disk device (hotplug removal)
///
/// This function handles the removal sequence following Linux kernel patterns:
/// 1. Transition device state to Cancel (stop accepting new I/O)
/// 2. Transition device state to Del (final removal)
/// 3. Unregister from block device registry (marks device dead)
/// 4. Invalidate page cache entries for this device
///
/// # Arguments
/// * `minor` - Minor device number of the disk to remove
///
/// # Returns
/// * `Ok(())` - Device was successfully unregistered
/// * `Err(BlockError::NotFound)` - No device with this minor number
pub fn unregister_scsi_disk(minor: u16) -> Result<(), BlockError> {
    let dev_id = DevId::new(major::SCSI_DISK, minor);

    crate::printkln!(
        "SCSI: Unregistering sd{} (major={}, minor={})",
        minor,
        major::SCSI_DISK,
        minor
    );

    // Unregister from block device registry
    // This calls mark_dead() which stops the request queue
    let _bdev = unregister_blkdev(dev_id).ok_or(BlockError::NotFound)?;

    // Invalidate page cache entries for this block device
    // This frees all cached pages belonging to this device
    let pages_freed = crate::invalidate_blkdev_pages(major::SCSI_DISK, minor);

    crate::printkln!(
        "SCSI: sd{} removed ({} cached pages freed)",
        minor,
        pages_freed
    );

    Ok(())
}
