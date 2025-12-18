//! SCSI Command Definitions and Transport Abstraction
//!
//! Provides SCSI command structures, CDB builders, and the ScsiHost trait
//! that transport drivers (SAT, USB Mass Storage) implement.

use alloc::sync::Arc;

/// SCSI operation codes
pub mod opcode {
    /// Test Unit Ready - check if device is ready
    pub const TEST_UNIT_READY: u8 = 0x00;
    /// Inquiry - get device identification
    pub const INQUIRY: u8 = 0x12;
    /// Read Capacity (10) - get disk size
    pub const READ_CAPACITY_10: u8 = 0x25;
    /// Read (10) - read data
    pub const READ_10: u8 = 0x28;
    /// Write (10) - write data
    pub const WRITE_10: u8 = 0x2A;
    /// Synchronize Cache (10) - flush cache to media
    pub const SYNCHRONIZE_CACHE_10: u8 = 0x35;
}

/// SCSI device types (from INQUIRY response)
pub mod device_type {
    pub const DISK: u8 = 0x00;
    pub const TAPE: u8 = 0x01;
    pub const CDROM: u8 = 0x05;
}

/// SCSI sense keys for error reporting
pub mod sense_key {
    pub const NO_SENSE: u8 = 0x0;
    pub const RECOVERED_ERROR: u8 = 0x1;
    pub const NOT_READY: u8 = 0x2;
    pub const MEDIUM_ERROR: u8 = 0x3;
    pub const HARDWARE_ERROR: u8 = 0x4;
    pub const ILLEGAL_REQUEST: u8 = 0x5;
    pub const UNIT_ATTENTION: u8 = 0x6;
    pub const DATA_PROTECT: u8 = 0x7;
    pub const ABORTED_COMMAND: u8 = 0xB;
}

/// SCSI Command Descriptor Block (CDB)
///
/// Contains the raw command bytes sent to the device.
/// CDB length varies by command: 6, 10, 12, or 16 bytes.
#[derive(Debug, Clone)]
pub struct Cdb {
    /// Raw CDB bytes (max 16)
    pub bytes: [u8; 16],
    /// Actual CDB length
    pub len: usize,
}

impl Cdb {
    /// Create a 6-byte CDB (zeroed)
    pub fn new_6() -> Self {
        Self {
            bytes: [0; 16],
            len: 6,
        }
    }

    /// Create a 10-byte CDB (zeroed)
    pub fn new_10() -> Self {
        Self {
            bytes: [0; 16],
            len: 10,
        }
    }

    /// Build TEST UNIT READY CDB
    pub fn test_unit_ready() -> Self {
        let mut cdb = Self::new_6();
        cdb.bytes[0] = opcode::TEST_UNIT_READY;
        cdb
    }

    /// Build INQUIRY CDB
    ///
    /// # Arguments
    /// * `alloc_len` - Allocation length for response (typically 36 or 96)
    pub fn inquiry(alloc_len: u8) -> Self {
        let mut cdb = Self::new_6();
        cdb.bytes[0] = opcode::INQUIRY;
        cdb.bytes[4] = alloc_len;
        cdb
    }

    /// Build READ CAPACITY(10) CDB
    pub fn read_capacity_10() -> Self {
        let mut cdb = Self::new_10();
        cdb.bytes[0] = opcode::READ_CAPACITY_10;
        cdb
    }

    /// Build READ(10) CDB
    ///
    /// # Arguments
    /// * `lba` - Logical Block Address to start reading from
    /// * `transfer_length` - Number of blocks to read
    pub fn read_10(lba: u32, transfer_length: u16) -> Self {
        let mut cdb = Self::new_10();
        cdb.bytes[0] = opcode::READ_10;
        // LBA is bytes 2-5, big-endian
        cdb.bytes[2..6].copy_from_slice(&lba.to_be_bytes());
        // Transfer length is bytes 7-8, big-endian
        cdb.bytes[7..9].copy_from_slice(&transfer_length.to_be_bytes());
        cdb
    }

    /// Build WRITE(10) CDB
    ///
    /// # Arguments
    /// * `lba` - Logical Block Address to start writing to
    /// * `transfer_length` - Number of blocks to write
    pub fn write_10(lba: u32, transfer_length: u16) -> Self {
        let mut cdb = Self::new_10();
        cdb.bytes[0] = opcode::WRITE_10;
        // LBA is bytes 2-5, big-endian
        cdb.bytes[2..6].copy_from_slice(&lba.to_be_bytes());
        // Transfer length is bytes 7-8, big-endian
        cdb.bytes[7..9].copy_from_slice(&transfer_length.to_be_bytes());
        cdb
    }

    /// Build SYNCHRONIZE CACHE(10) CDB
    pub fn synchronize_cache_10() -> Self {
        let mut cdb = Self::new_10();
        cdb.bytes[0] = opcode::SYNCHRONIZE_CACHE_10;
        cdb
    }
}

/// Data transfer direction for SCSI commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataDirection {
    /// No data transfer
    None,
    /// Data transfer to device (write)
    ToDevice,
    /// Data transfer from device (read)
    FromDevice,
}

/// SCSI command with data transfer information
pub struct ScsiCommand {
    /// Command Descriptor Block
    pub cdb: Cdb,
    /// Data transfer direction
    pub direction: DataDirection,
    /// Data buffer pointer (for read/write operations)
    pub data: Option<*mut u8>,
    /// Data buffer length
    pub data_len: usize,
    /// Command timeout in milliseconds
    pub timeout_ms: u32,
}

// SAFETY: ScsiCommand is only used within controlled contexts
// where the data pointer validity is ensured by the caller
unsafe impl Send for ScsiCommand {}
unsafe impl Sync for ScsiCommand {}

impl ScsiCommand {
    /// Create a command with no data transfer
    pub fn no_data(cdb: Cdb, timeout_ms: u32) -> Self {
        Self {
            cdb,
            direction: DataDirection::None,
            data: None,
            data_len: 0,
            timeout_ms,
        }
    }

    /// Create a read command (data from device)
    pub fn read(cdb: Cdb, data: *mut u8, data_len: usize, timeout_ms: u32) -> Self {
        Self {
            cdb,
            direction: DataDirection::FromDevice,
            data: Some(data),
            data_len,
            timeout_ms,
        }
    }

    /// Create a write command (data to device)
    pub fn write(cdb: Cdb, data: *mut u8, data_len: usize, timeout_ms: u32) -> Self {
        Self {
            cdb,
            direction: DataDirection::ToDevice,
            data: Some(data),
            data_len,
            timeout_ms,
        }
    }
}

/// SCSI error types
#[derive(Debug, Clone)]
pub enum ScsiError {
    /// Generic I/O error
    IoError,
    /// Command timed out
    Timeout,
    /// Check Condition status with sense data
    CheckCondition { sense_key: u8, asc: u8, ascq: u8 },
    /// Device not ready
    NotReady,
    /// Medium error (bad sector, etc.)
    MediumError,
    /// Hardware error
    HardwareError,
    /// Illegal request (invalid command/parameter)
    IllegalRequest,
    /// Unit attention (media changed, etc.)
    UnitAttention,
    /// Command not supported by transport
    NotSupported,
    /// Device not present
    NoDevice,
}

/// Result type for SCSI operations
pub type ScsiResult<T> = Result<T, ScsiError>;

/// SCSI Host trait - transport abstraction
///
/// Implemented by transport drivers like SAT (SCSI-to-ATA Translation)
/// or USB Mass Storage to execute SCSI commands.
pub trait ScsiHost: Send + Sync {
    /// Execute a SCSI command
    ///
    /// # Arguments
    /// * `target` - Target ID (0-15 typically)
    /// * `lun` - Logical Unit Number
    /// * `cmd` - The SCSI command to execute
    ///
    /// # Returns
    /// Number of bytes transferred on success
    fn execute(&self, target: u8, lun: u8, cmd: &ScsiCommand) -> ScsiResult<usize>;

    /// Get host adapter name for debugging
    fn name(&self) -> &str;

    /// Get number of targets supported
    fn num_targets(&self) -> u8;
}

/// INQUIRY response data (standard 36 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct InquiryData {
    /// Peripheral device type and qualifier
    pub peripheral: u8,
    /// Removable media bit
    pub rmb: u8,
    /// Version
    pub version: u8,
    /// Response data format
    pub response_format: u8,
    /// Additional length
    pub additional_length: u8,
    /// Flags
    pub flags: [u8; 3],
    /// Vendor identification (8 bytes, ASCII)
    pub vendor: [u8; 8],
    /// Product identification (16 bytes, ASCII)
    pub product: [u8; 16],
    /// Product revision (4 bytes, ASCII)
    pub revision: [u8; 4],
}

impl InquiryData {
    /// Get peripheral device type
    pub fn device_type(&self) -> u8 {
        self.peripheral & 0x1F
    }

    /// Check if device is a disk
    pub fn is_disk(&self) -> bool {
        self.device_type() == device_type::DISK
    }

    /// Get vendor string (trimmed)
    pub fn vendor_str(&self) -> &[u8] {
        trim_ascii(&self.vendor)
    }

    /// Get product string (trimmed)
    pub fn product_str(&self) -> &[u8] {
        trim_ascii(&self.product)
    }
}

/// READ CAPACITY(10) response data
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ReadCapacityData {
    /// Returned Logical Block Address (last LBA)
    pub last_lba: [u8; 4],
    /// Block length in bytes
    pub block_length: [u8; 4],
}

impl ReadCapacityData {
    /// Get last LBA (big-endian)
    pub fn last_lba(&self) -> u32 {
        u32::from_be_bytes(self.last_lba)
    }

    /// Get block length (big-endian)
    pub fn block_length(&self) -> u32 {
        u32::from_be_bytes(self.block_length)
    }

    /// Get total capacity in blocks
    pub fn total_blocks(&self) -> u64 {
        self.last_lba() as u64 + 1
    }
}

/// Trim trailing spaces from ASCII string
fn trim_ascii(s: &[u8]) -> &[u8] {
    let end = s
        .iter()
        .rposition(|&c| c != b' ' && c != 0)
        .map_or(0, |i| i + 1);
    &s[..end]
}

/// Execute TEST UNIT READY and return success/failure
///
/// USB mass storage devices often need time to initialize after connection.
/// This function retries the TEST UNIT READY command multiple times with
/// delays between attempts, which is standard behavior for USB MSC devices.
pub fn test_unit_ready(host: &Arc<dyn ScsiHost>, target: u8, lun: u8) -> ScsiResult<()> {
    // USB mass storage devices may need several attempts to become ready
    const MAX_RETRIES: u32 = 5;
    const RETRY_DELAY_MS: u32 = 100;

    let cmd = ScsiCommand::no_data(Cdb::test_unit_ready(), 5000);

    for attempt in 0..MAX_RETRIES {
        match host.execute(target, lun, &cmd) {
            Ok(_) => return Ok(()),
            Err(e) => {
                if attempt + 1 < MAX_RETRIES {
                    // Wait before retrying
                    for _ in 0..RETRY_DELAY_MS {
                        for _ in 0..10000 {
                            core::hint::spin_loop();
                        }
                    }
                } else {
                    return Err(e);
                }
            }
        }
    }
    Ok(())
}

/// Execute INQUIRY and return response data
pub fn inquiry(host: &Arc<dyn ScsiHost>, target: u8, lun: u8) -> ScsiResult<InquiryData> {
    let mut data = InquiryData {
        peripheral: 0,
        rmb: 0,
        version: 0,
        response_format: 0,
        additional_length: 0,
        flags: [0; 3],
        vendor: [0; 8],
        product: [0; 16],
        revision: [0; 4],
    };

    let cmd = ScsiCommand::read(
        Cdb::inquiry(36),
        &mut data as *mut InquiryData as *mut u8,
        36,
        5000,
    );

    host.execute(target, lun, &cmd)?;
    Ok(data)
}

/// Execute READ CAPACITY(10) and return capacity data
pub fn read_capacity(
    host: &Arc<dyn ScsiHost>,
    target: u8,
    lun: u8,
) -> ScsiResult<ReadCapacityData> {
    let mut data = ReadCapacityData {
        last_lba: [0; 4],
        block_length: [0; 4],
    };

    let cmd = ScsiCommand::read(
        Cdb::read_capacity_10(),
        &mut data as *mut ReadCapacityData as *mut u8,
        8,
        5000,
    );

    host.execute(target, lun, &cmd)?;
    Ok(data)
}
