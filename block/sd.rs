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
#![expect(clippy::undocumented_unsafe_blocks)] // TODO(unsafe): SAFETY comments (doc/UNSAFE.md)

use alloc::boxed::Box;
use alloc::sync::Arc;

use crate::sync::spin::Mutex;

use super::blkdev::{
    Bio, BioOp, BlockDevice, BlockDriver, Disk, QueueLimits, RequestQueue, SECTOR_SHIFT, bio_endio,
    disk_bdevs, major, register_blkdev,
};
use super::genhd::{add_disk, del_gendisk, disk_name};

use crate::util::error::KernelError;
use crate::util::kalloc::try_arc;

use super::scsi::{
    Cdb, ScsiCommand, ScsiError, ScsiHost, ScsiResult, inquiry, read_capacity, test_unit_ready,
};

/// SCSI device states (mirrors Linux kernel's enum scsi_device_state)
///
/// These states control device lifecycle and I/O acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// A state change Linux scsi_device_set_state allows (a change to the
/// same state is always fine)
fn legal(from: ScsiDeviceState, to: ScsiDeviceState) -> bool {
    use ScsiDeviceState::*;
    from == to
        || match to {
            Running => matches!(from, Created | Offline | TransportOffline | Quiesce | Block),
            Offline | TransportOffline => matches!(from, Created | Running | Quiesce | Block),
            Cancel => matches!(
                from,
                Created | Running | Quiesce | Offline | TransportOffline
            ),
            Del => matches!(from, Created | Cancel | Offline | TransportOffline | Block),
            _ => false,
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
    /// Device state (Linux sdev_state under state_mutex): changed only
    /// by `set_state`'s legal transitions, read by each command (spin
    /// leaf, never held across I/O)
    state: Mutex<ScsiDeviceState>,
    /// Disk capacity in sectors
    capacity_sectors: u64,
    /// Sector size in bytes (typically 512)
    sector_size: u32,
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
        // 512..4096-byte power-of-two sectors only. Past 2^32 blocks
        // every command is 16-byte (Linux use_16_for_rw)
        let sector_size = cap.block_size;
        if !(512..=4096).contains(&sector_size) || !sector_size.is_power_of_two() {
            crate::printkln!("SCSI: unsupported sector size {}", sector_size);
            return Err(ScsiError::NotSupported);
        }
        let capacity_sectors = cap.blocks;
        // A size in bytes past 2^64 is too big to address (Linux
        // sd_read_capacity / sd_addressable_capacity: "Too big for this
        // kernel")
        if capacity_sectors
            .checked_mul(u64::from(sector_size))
            .is_none()
        {
            crate::printkln!("SCSI: capacity of {} blocks too big", capacity_sectors);
            return Err(ScsiError::NotSupported);
        }

        Ok(Self {
            host,
            target,
            lun,
            state: Mutex::new(ScsiDeviceState::Running),
            capacity_sectors,
            sector_size,
        })
    }

    /// Get current device state
    pub fn state(&self) -> ScsiDeviceState {
        *self.state.lock()
    }

    /// Change the state if Linux allows the transition
    /// (scsi_device_set_state); EINVAL otherwise
    pub fn set_state(&self, new: ScsiDeviceState) -> Result<(), KernelError> {
        let mut st = self.state.lock();
        let ok = legal(*st, new);
        if !ok {
            return Err(KernelError::InvalidArgument);
        }
        *st = new;
        Ok(())
    }

    /// Begin removal (Linux __scsi_remove_device: SDEV_CANCEL, else
    /// straight to SDEV_DEL where CANCEL is not allowed, e.g. from
    /// Block); false if neither is (it is already being removed)
    pub fn cancel(&self) -> bool {
        let mut st = self.state.lock();
        for to in [ScsiDeviceState::Cancel, ScsiDeviceState::Del] {
            if *st != to && legal(*st, to) {
                *st = to;
                return true;
            }
        }
        false
    }

    /// Finish removal (SDEV_DEL)
    pub fn mark_deleted(&self) {
        let _ = self.set_state(ScsiDeviceState::Del);
    }

    /// Check if device accepts I/O
    pub fn accepts_io(&self) -> bool {
        self.state().accepts_io()
    }

    /// Get disk capacity in sectors
    pub fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    /// Every command 16-byte: the disk passes READ(10)'s 32-bit LBA
    /// (Linux use_16_for_rw)
    fn use_16(&self) -> bool {
        self.capacity_sectors > u64::from(u32::MAX)
    }

    /// Get sector size
    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }

    /// Get capacity in bytes (probe refused a disk whose bytes overflow)
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_sectors
            .saturating_mul(u64::from(self.sector_size))
    }

    /// Run a read or write of `len` bytes: a transfer the device ended
    /// short (residue, no error status) is an I/O error, not success
    /// (Linux scsi_io_completion: only good_bytes complete)
    fn rw(&self, cmd: &ScsiCommand, len: usize) -> ScsiResult<usize> {
        let n = self.host.execute(self.target, self.lun, cmd)?;
        if n < len {
            return Err(ScsiError::IoError);
        }
        Ok(n)
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

        let expected_len = count as usize * self.sector_size as usize;
        if buf.len() < expected_len {
            return Err(ScsiError::IllegalRequest);
        }

        let cmd = ScsiCommand::read(
            Cdb::rw(false, lba, count, self.use_16()),
            buf.as_mut_ptr(),
            expected_len,
            30000, // 30 second timeout for I/O
        );

        self.rw(&cmd, expected_len)
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

        let expected_len = count as usize * self.sector_size as usize;
        if buf.len() < expected_len {
            return Err(ScsiError::IllegalRequest);
        }

        let cmd = ScsiCommand::write(
            Cdb::rw(true, lba, count, self.use_16()),
            buf.as_ptr().cast_mut(),
            expected_len,
            30000,
        );

        self.rw(&cmd, expected_len)
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
    /// Its disk index, free again with the driver's last reference
    _index: SdIndex,
}

impl ScsiDiskDriver {
    /// Run one bio; segments are consecutive on the disk
    fn do_bio(&self, bio: &Bio) -> Result<(), KernelError> {
        let ss = u64::from(self.disk.sector_size());
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
                let buf = unsafe { core::slice::from_raw_parts(p.cast_const(), seg.len) };
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

/// Disks on major 8 (its 256 minors)
const SD_MAX: u32 = 16;

/// Disk indexes in use (Linux sd_index_ida); an index is freed when the
/// disk's last reference drops, in any context
static SD_INDEX: crate::util::ida::Ida = crate::util::ida::Ida::new();

/// A disk index (sda = 0), free again when dropped (Linux
/// scsi_disk_release's ida_free): a removed disk's name is reused once
/// nothing holds it open
struct SdIndex(u32);

impl SdIndex {
    /// The lowest free index (Linux ida_alloc); ENOSPC past major 8's
    /// disks
    fn alloc() -> Result<Self, KernelError> {
        let i = SD_INDEX.alloc();
        if i >= SD_MAX {
            SD_INDEX.free(i);
            return Err(KernelError::NoSpace);
        }
        Ok(Self(i))
    }
}

impl Drop for SdIndex {
    fn drop(&mut self) {
        SD_INDEX.free(self.0);
    }
}

/// A disk `create_scsi_disk` added (Linux struct scsi_disk): its whole
/// block device and the SCSI device behind it
pub struct SdDisk {
    bdev: Arc<BlockDevice>,
    sdev: Arc<ScsiDisk>,
}

impl SdDisk {
    /// The whole-disk block device
    pub fn bdev(&self) -> &Arc<BlockDevice> {
        &self.bdev
    }

    /// Remove the disk (Linux __scsi_remove_device, sd_remove): no new
    /// commands (SDEV_CANCEL), then the disk and its partitions go
    /// (del_gendisk: sysfs, devtmpfs, cached pages; open files keep a
    /// dead device), then SDEV_DEL
    pub fn remove(&self) {
        // Already being removed: the other remover finishes it
        if !self.sdev.cancel() {
            return;
        }
        let all = disk_bdevs(&self.bdev.disk);
        let pages: u64 = all.iter().map(|b| b.bd_inode.i_data.nrpages()).sum();
        del_gendisk(&self.bdev.disk);
        self.sdev.mark_deleted();
        crate::printkln!(
            "SCSI: {} removed ({} cached pages freed)",
            self.bdev.name,
            pages
        );
    }
}

/// Probe a SCSI target and add it as the lowest free sdX disk
pub fn create_scsi_disk(
    host: Arc<dyn ScsiHost>,
    target: u8,
    lun: u8,
) -> Result<SdDisk, KernelError> {
    let scsi_disk = try_arc(ScsiDisk::probe(host, target, lun).map_err(|e| match e {
        ScsiError::NoMemory => KernelError::OutOfMemory,
        _ => KernelError::NotFound,
    })?)?;
    let index = SdIndex::alloc()?;
    let i = index.0;
    register_blkdev(major::SCSI_DISK, "sd")?;
    let ss = scsi_disk.sector_size();
    // DMA alignment of a sector (Linux libata's ata_scsi_dev_config,
    // usb-storage's 511)
    let limits = QueueLimits {
        logical_block_size: ss,
        physical_block_size: ss,
        dma_alignment: ss.saturating_sub(1),
        ..QueueLimits::default()
    };
    let q = RequestQueue::new_bio(
        try_arc(ScsiDiskDriver {
            disk: scsi_disk.clone(),
            _index: index,
        })?,
        limits,
        true,
    );
    let name = disk_name("sd", i);
    let disk = Disk::new(
        major::SCSI_DISK,
        i as u16 * SD_MINORS,
        SD_MINORS,
        name.clone(),
        scsi_disk.capacity_bytes() >> SECTOR_SHIFT,
        q,
        false,
    )?;
    let bdev = add_disk(disk, None)?;
    crate::printkln!(
        "SCSI: {} ({} MB, {} byte sectors)",
        name,
        scsi_disk.capacity_bytes() / (1024 * 1024),
        ss
    );
    Ok(SdDisk {
        bdev,
        sdev: scsi_disk,
    })
}

#[cfg(test)]
mod tests {
    use super::{ScsiDeviceState as S, legal};

    #[test]
    fn state_transitions() {
        assert!(legal(S::Running, S::Cancel));
        assert!(legal(S::Cancel, S::Del));
        assert!(!legal(S::Del, S::Running));
        assert!(!legal(S::Cancel, S::Running));
        assert!(!legal(S::Running, S::Del));
        assert!(legal(S::Offline, S::Running));
    }

    use super::*;

    /// 16-byte commands where READ(10) cannot address (Linux
    /// sd_setup_rw_cmnd), and READ CAPACITY(16)'s data
    #[test]
    fn cdbs() {
        use crate::block::scsi::{Cdb, capacity_16, opcode};
        let c = Cdb::rw(false, 5, 8, false);
        assert_eq!((c.len, c.bytes[0]), (10, opcode::READ_10));
        let c = Cdb::rw(true, 1 << 32, 8, false);
        assert_eq!((c.len, c.bytes[0]), (16, opcode::WRITE_16));
        assert_eq!(&c.bytes[2..10], &(1u64 << 32).to_be_bytes());
        assert_eq!(&c.bytes[10..14], &8u32.to_be_bytes());
        assert_eq!(Cdb::rw(false, 0, 0x1_0000, false).len, 16);
        assert_eq!(Cdb::rw(false, 0, 1, true).len, 16);
        let c = Cdb::read_capacity_16();
        assert_eq!((c.bytes[0], c.bytes[1], c.bytes[13]), (0x9e, 0x10, 32));
        let mut d = [0u8; 32];
        d[0..8].copy_from_slice(&0x1_2345_6789u64.to_be_bytes());
        d[8..12].copy_from_slice(&4096u32.to_be_bytes());
        let cap = capacity_16(&d);
        assert_eq!((cap.blocks, cap.block_size), (0x1_2345_678a, 4096));
    }

    #[test]
    fn index_reuse() {
        let a = SdIndex::alloc().unwrap();
        let b = SdIndex::alloc().unwrap();
        assert_eq!((a.0, b.0), (0, 1));
        drop(a);
        let c = SdIndex::alloc().unwrap();
        assert_eq!(c.0, 0);
        let rest: alloc::vec::Vec<_> = (2..SD_MAX).map(|_| SdIndex::alloc().unwrap()).collect();
        assert!(SdIndex::alloc().is_err());
        drop(rest);
        assert_eq!(SdIndex::alloc().unwrap().0, 2);
    }
}
