//! USB Mass Storage Class Driver
//!
//! Implements the Bulk-Only Transport (BOT) protocol for USB mass storage devices.
//! This driver implements the ScsiHost trait to integrate with the SCSI layer.

use alloc::boxed::Box;
use alloc::sync::Arc;

use crate::sync::spin::Mutex;
use core::any::Any;

use crate::block::{DataDirection, ScsiCommand, ScsiError, ScsiHost, ScsiResult};
use crate::printkln;
use crate::util::error::KernelError;

use super::{UsbDeviceId, UsbError, UsbIds, usb_bulk_in, usb_bulk_out};

/// CBW signature "USBC"
const CBW_SIGNATURE: u32 = 0x43425355;

/// CSW signature "USBS"
const CSW_SIGNATURE: u32 = 0x53425355;

/// Command Block Wrapper (CBW) - 31 bytes
/// Sent before each SCSI command in BOT protocol
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct Cbw {
    /// Signature - must be CBW_SIGNATURE
    signature: u32,
    /// Tag - echoed in CSW
    tag: u32,
    /// Data transfer length
    data_transfer_length: u32,
    /// Flags (bit 7: direction, 0=OUT, 1=IN)
    flags: u8,
    /// LUN (bits 3:0)
    lun: u8,
    /// CDB length (bits 4:0, valid 1-16)
    cb_length: u8,
    /// Command Block (CDB) - 16 bytes max
    cb: [u8; 16],
}

impl Cbw {
    const SIZE: usize = 31;

    fn new(tag: u32, data_len: u32, direction: DataDirection, lun: u8, cdb: &[u8]) -> Self {
        let flags = match direction {
            DataDirection::FromDevice => 0x80,
            DataDirection::ToDevice | DataDirection::None => 0x00,
        };

        let mut cb = [0u8; 16];
        let cdb_len = cdb.len().min(16);
        cb[..cdb_len].copy_from_slice(&cdb[..cdb_len]);

        Self {
            signature: CBW_SIGNATURE,
            tag,
            data_transfer_length: data_len,
            flags,
            lun,
            cb_length: cdb_len as u8,
            cb,
        }
    }

    fn as_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0..4].copy_from_slice(&self.signature.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.tag.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.data_transfer_length.to_le_bytes());
        bytes[12] = self.flags;
        bytes[13] = self.lun;
        bytes[14] = self.cb_length;
        bytes[15..31].copy_from_slice(&self.cb);
        bytes
    }
}

/// Command Status Wrapper (CSW) - 13 bytes
/// Received after each SCSI command in BOT protocol
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
struct Csw {
    /// Signature - must be CSW_SIGNATURE
    signature: u32,
    /// Tag - should match CBW tag
    tag: u32,
    /// Data residue - difference between requested and actual transfer
    data_residue: u32,
    /// Status: 0=Command Passed, 1=Command Failed, 2=Phase Error
    status: u8,
}

impl Csw {
    const SIZE: usize = 13;

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Self {
        Self {
            signature: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            tag: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            data_residue: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            status: bytes[12],
        }
    }

    fn is_valid(&self) -> bool {
        self.signature == CSW_SIGNATURE
    }

    fn is_success(&self) -> bool {
        self.status == 0
    }
}

/// CSW status values
#[allow(dead_code)]
mod csw_status {
    pub const PASSED: u8 = 0;
    pub const FAILED: u8 = 1;
    pub const PHASE_ERROR: u8 = 2;
}

/// USB Mass Storage device state (protected by Mutex)
struct UsbMscState {
    /// Current CBW tag (incremented for each command)
    tag: u32,
}

/// USB Mass Storage Device
///
/// Implements ScsiHost to allow the SCSI layer to send commands. Its
/// bulk endpoints were added to the controller when the configuration
/// was set.
pub struct UsbMscDevice {
    /// Mutable state under lock
    state: Mutex<UsbMscState>,
    /// USB device slot ID
    slot_id: u8,
    /// Bulk IN endpoint address
    bulk_in_ep: u8,
    /// Bulk OUT endpoint address
    bulk_out_ep: u8,
}

impl UsbMscDevice {
    fn new(slot_id: u8, bulk_in_ep: u8, bulk_out_ep: u8) -> Self {
        Self {
            state: Mutex::new(UsbMscState { tag: 1 }),
            slot_id,
            bulk_in_ep,
            bulk_out_ep,
        }
    }

    /// Execute a BOT transaction
    fn bot_transfer(
        &self,
        lun: u8,
        cdb: &[u8],
        direction: DataDirection,
        data: Option<&mut [u8]>,
    ) -> ScsiResult<usize> {
        // Get transfer parameters
        let data_len = data.as_ref().map(|d| d.len()).unwrap_or(0) as u32;

        // Get next tag and increment
        let tag = {
            let mut state = self.state.lock();
            let t = state.tag;
            state.tag = state.tag.wrapping_add(1);
            t
        };

        let slot_id = self.slot_id;
        let bulk_out = self.bulk_out_ep & 0x0F;
        let bulk_in = self.bulk_in_ep & 0x0F;

        // Phase 1: Send CBW (CBW and CSW buffers on the heap: the
        // controller DMAs them, never from a kernel stack; Linux
        // us->iobuf)
        let cbw = Cbw::new(tag, data_len, direction, lun, cdb);
        let cbw_bytes = Box::new(cbw.as_bytes());

        usb_bulk_out(slot_id, bulk_out, &cbw_bytes[..]).map_err(usb_to_scsi_error)?;

        // Phase 2: Data transfer (if any)
        let mut transferred = 0usize;
        if let Some(buf) = data {
            match direction {
                DataDirection::FromDevice => {
                    transferred = usb_bulk_in(slot_id, bulk_in, buf).map_err(usb_to_scsi_error)?;
                }
                DataDirection::ToDevice => {
                    transferred =
                        usb_bulk_out(slot_id, bulk_out, buf).map_err(usb_to_scsi_error)?;
                }
                DataDirection::None => {}
            }
        }

        // Phase 3: Receive CSW
        let mut csw_bytes = Box::new([0u8; Csw::SIZE]);
        usb_bulk_in(slot_id, bulk_in, &mut csw_bytes[..]).map_err(usb_to_scsi_error)?;

        let csw = Csw::from_bytes(&csw_bytes);

        // Validate CSW
        if !csw.is_valid() {
            printkln!("USB-MSC: Invalid CSW signature");
            return Err(ScsiError::IoError);
        }

        // Copy tag from packed struct before comparison
        let csw_tag = { csw.tag };
        if csw_tag != tag {
            printkln!(
                "USB-MSC: CSW tag mismatch (expected {}, got {})",
                tag,
                csw_tag
            );
            return Err(ScsiError::IoError);
        }

        if !csw.is_success() {
            // Command failed - this is common during device initialization
            return Err(ScsiError::CheckCondition {
                sense_key: 0,
                asc: 0,
                ascq: 0,
            });
        }

        Ok(transferred)
    }
}

impl ScsiHost for UsbMscDevice {
    fn execute(&self, _target: u8, lun: u8, cmd: &ScsiCommand) -> ScsiResult<usize> {
        // Prepare data buffer reference
        let data_ptr = cmd.data;
        let data_len = cmd.data_len;

        // Create a mutable slice for data transfer
        let data_buf: Option<&mut [u8]> = match cmd.direction {
            DataDirection::None => None,
            DataDirection::FromDevice | DataDirection::ToDevice => {
                if let Some(ptr) = data_ptr {
                    // SAFETY: Caller ensures pointer is valid for data_len bytes
                    Some(unsafe { core::slice::from_raw_parts_mut(ptr, data_len) })
                } else {
                    None
                }
            }
        };

        self.bot_transfer(lun, &cmd.cdb.bytes[..cmd.cdb.len], cmd.direction, data_buf)
    }

    fn name(&self) -> &str {
        "usb-msc"
    }

    fn num_targets(&self) -> u8 {
        1 // USB MSC devices typically have 1 target
    }
}

/// Convert USB error to SCSI error
fn usb_to_scsi_error(e: UsbError) -> ScsiError {
    match e {
        UsbError::Timeout => ScsiError::Timeout,
        UsbError::Stall => ScsiError::CheckCondition {
            sense_key: 0,
            asc: 0,
            ascq: 0,
        },
        UsbError::NoDevice => ScsiError::NoDevice,
        _ => ScsiError::IoError,
    }
}

/// Interfaces it drives (Linux usb-storage's usb_storage_usb_ids):
/// SCSI transparent command set over Bulk-Only Transport; the other
/// subclasses and the CB/CBI and UAS transports are not supported
/// (BUGS.md)
static STORAGE_IDS: [UsbDeviceId; 1] = [UsbDeviceId::interface_info(
    super::class::MASS_STORAGE,
    USB_SC_SCSI,
    USB_PR_BULK,
)];

/// bInterfaceSubClass: SCSI transparent command set
const USB_SC_SCSI: u8 = 0x06;
/// bInterfaceProtocol: Bulk-Only Transport
const USB_PR_BULK: u8 = 0x50;

/// The USB mass storage driver (Linux usb-storage): its SCSI disk is
/// scanned at probe
pub static USB_STORAGE_DRIVER: crate::base::Driver = crate::base::Driver::new(
    "usb-storage",
    &super::USB_BUS,
    Some("usb_storage"),
    &UsbIds::Interface(&STORAGE_IDS),
    usb_storage_probe,
);

fn usb_storage_probe(
    dev: &Arc<crate::base::Device>,
) -> Result<Box<dyn crate::base::Bound>, KernelError> {
    let (usb_dev, intf) = super::usb_intf(dev).ok_or(KernelError::NoDevice)?;
    let Some((bulk_in_ep, bulk_out_ep)) = intf.bulk_eps() else {
        printkln!("usb-storage {}: no bulk endpoints", dev.name());
        return Err(KernelError::NoDevice);
    };
    printkln!(
        "usb-storage {}: slot {}, bulk in {:#04x}, out {:#04x}",
        dev.name(),
        usb_dev.slot_id,
        bulk_in_ep,
        bulk_out_ep
    );
    let msc_dev = Arc::new(UsbMscDevice::new(usb_dev.slot_id, bulk_in_ep, bulk_out_ep));
    let _ = crate::block::create_scsi_disk(msc_dev.clone(), 0, 0);
    Ok(Box::new(UsbMscDeviceHandle {
        device: msc_dev,
        slot: usb_dev.slot_id,
    }))
}

/// Device handle returned from probe
///
/// This wraps the UsbMscDevice and provides access to the ScsiHost implementation.
pub struct UsbMscDeviceHandle {
    device: Arc<UsbMscDevice>,
    slot: u8,
}

impl UsbMscDeviceHandle {
    /// Get the SCSI host interface for this device
    pub fn scsi_host(&self) -> Arc<dyn ScsiHost> {
        self.device.clone()
    }
}

impl crate::base::Bound for UsbMscDeviceHandle {
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Unregister its SCSI disk (minor = slot id)
    fn remove(&self) {
        if let Err(e) = crate::block::sd::unregister_scsi_disk(self.slot as u16) {
            printkln!("USB-MSC: Failed to unregister SCSI disk: {:?}", e);
        }
    }
}
