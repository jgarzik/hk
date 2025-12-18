//! USB Mass Storage Class Driver
//!
//! Implements the Bulk-Only Transport (BOT) protocol for USB mass storage devices.
//! This driver implements the ScsiHost trait to integrate with the SCSI layer.

use alloc::boxed::Box;
use alloc::sync::Arc;

use core::any::Any;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::bus::bus::{BusContext, BusDevice, BusDriver};
use crate::bus::driver::{Device, DriverError};
use crate::downcast_bus_device;
use crate::printkln;
use crate::storage::{DataDirection, ScsiCommand, ScsiError, ScsiHost, ScsiResult};

use super::{UsbDevice, UsbError, usb_bulk_in, usb_bulk_out, usb_configure_endpoints};

/// USB Mass Storage class code
const USB_CLASS_MASS_STORAGE: u8 = 0x08;

/// USB Mass Storage subclass: SCSI transparent command set
const USB_SUBCLASS_SCSI: u8 = 0x06;

/// USB Mass Storage protocol: Bulk-Only Transport
const USB_PROTOCOL_BOT: u8 = 0x50;

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
/// Implements ScsiHost to allow the SCSI layer to send commands.
#[repr(C)]
pub struct UsbMscDevice {
    /// Mutable state under lock (place first for alignment)
    state: Mutex<UsbMscState>,
    /// Whether endpoints have been configured (atomic for lock-free check)
    configured: AtomicBool,
    /// USB device slot ID
    slot_id: u8,
    /// Bulk IN endpoint address
    bulk_in_ep: u8,
    /// Bulk OUT endpoint address
    bulk_out_ep: u8,
    /// Padding
    _pad: u8,
    /// Max packet size for bulk endpoints
    max_packet: u16,
}

impl UsbMscDevice {
    /// Create a new USB MSC device
    fn new(slot_id: u8, bulk_in_ep: u8, bulk_out_ep: u8, max_packet: u16) -> Self {
        crate::printkln!(
            "USB-MSC: Creating device slot={} in=0x{:02x} out=0x{:02x} pkt={}",
            slot_id,
            bulk_in_ep,
            bulk_out_ep,
            max_packet
        );
        let dev = Self {
            state: Mutex::new(UsbMscState { tag: 1 }),
            configured: AtomicBool::new(false),
            slot_id,
            bulk_in_ep,
            bulk_out_ep,
            _pad: 0,
            max_packet,
        };
        crate::printkln!(
            "USB-MSC: Created device slot={} in=0x{:02x} out=0x{:02x}",
            dev.slot_id,
            dev.bulk_in_ep,
            dev.bulk_out_ep
        );
        dev
    }

    /// Configure the bulk endpoints (must be called before transfers)
    #[allow(dead_code)]
    fn configure(&self) -> Result<(), UsbError> {
        // Check if already configured (lock-free)
        if self.configured.load(Ordering::Acquire) {
            return Ok(());
        }

        // Extract endpoint numbers (remove direction bit)
        let in_ep_num = self.bulk_in_ep & 0x0F;
        let out_ep_num = self.bulk_out_ep & 0x0F;

        crate::printkln!(
            "USB-MSC: Configuring endpoints IN={} OUT={} for slot {}",
            in_ep_num,
            out_ep_num,
            self.slot_id
        );

        usb_configure_endpoints(self.slot_id, in_ep_num, out_ep_num, self.max_packet)?;

        crate::printkln!("USB-MSC: Endpoints configured successfully");

        self.configured.store(true, Ordering::Release);
        Ok(())
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

        // Phase 1: Send CBW
        let cbw = Cbw::new(tag, data_len, direction, lun, cdb);
        let cbw_bytes = cbw.as_bytes();

        usb_bulk_out(slot_id, bulk_out, &cbw_bytes).map_err(usb_to_scsi_error)?;

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
        let mut csw_bytes = [0u8; Csw::SIZE];
        usb_bulk_in(slot_id, bulk_in, &mut csw_bytes).map_err(usb_to_scsi_error)?;

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

impl Device for UsbMscDevice {
    fn name(&self) -> &str {
        "usb-msc"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ScsiHost for UsbMscDevice {
    fn execute(&self, _target: u8, lun: u8, cmd: &ScsiCommand) -> ScsiResult<usize> {
        // Ensure endpoints are configured
        if !self.configured.load(Ordering::Acquire) {
            let in_ep_num = self.bulk_in_ep & 0x0F;
            let out_ep_num = self.bulk_out_ep & 0x0F;

            usb_configure_endpoints(self.slot_id, in_ep_num, out_ep_num, self.max_packet)
                .map_err(usb_to_scsi_error)?;

            self.configured.store(true, Ordering::Release);
        }

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

/// USB Mass Storage Bus Driver
///
/// Matches USB devices with class 0x08 (Mass Storage) and creates
/// UsbMscDevice instances for SCSI layer integration.
pub struct UsbMscBusDriver;

impl BusDriver for UsbMscBusDriver {
    fn name(&self) -> &str {
        "usb-msc"
    }

    /// Remove a USB MSC device (hotplug)
    ///
    /// Called when the USB device is disconnected. Performs cleanup:
    /// 1. Unregister associated SCSI disk from block device registry
    /// 2. Invalidate page cache entries
    fn remove(&self, device: &dyn BusDevice) -> Result<(), DriverError> {
        let usb_dev = downcast_bus_device!(device, UsbDevice).ok_or(DriverError::Unsupported)?;

        printkln!(
            "USB-MSC: Removing device slot {} (bus_id: {})",
            usb_dev.slot_id,
            BusDevice::bus_id(usb_dev)
        );

        // Unregister the SCSI disk associated with this device
        // Currently we use a simple mapping: slot_id -> minor number
        // A more robust implementation would track this mapping explicitly
        let minor = usb_dev.slot_id as u16;
        if let Err(e) = crate::storage::sd::unregister_scsi_disk(minor) {
            printkln!("USB-MSC: Failed to unregister SCSI disk: {:?}", e);
            // Continue with removal even if unregister fails
        }

        printkln!("USB-MSC: Device slot {} removed", usb_dev.slot_id);
        Ok(())
    }

    fn matches(&self, device: &dyn BusDevice) -> bool {
        if let Some(usb_dev) = downcast_bus_device!(device, UsbDevice) {
            // For QEMU usb-storage, the device class is typically set at interface level
            // Check device class or interface class
            if usb_dev.device_class == USB_CLASS_MASS_STORAGE {
                return true;
            }

            // Check interfaces
            for iface in &usb_dev.interfaces {
                if iface.class == USB_CLASS_MASS_STORAGE
                    && iface.subclass == USB_SUBCLASS_SCSI
                    && iface.protocol == USB_PROTOCOL_BOT
                {
                    return true;
                }
            }

            // For QEMU usb-storage without full enumeration, we might not have
            // interface info. Accept any device on USB bus for now.
            // Proper enumeration blocked on control transfer implementation
            return true;
        }
        false
    }

    fn probe(
        &self,
        device: &dyn BusDevice,
        _ctx: &mut BusContext,
    ) -> Result<Box<dyn Device>, DriverError> {
        let usb_dev = downcast_bus_device!(device, UsbDevice).ok_or(DriverError::Unsupported)?;

        printkln!(
            "USB-MSC: Probing device slot {} on port {}",
            usb_dev.slot_id,
            usb_dev.port
        );

        // Find bulk endpoints
        // For QEMU usb-storage, typical endpoints are:
        // - Bulk OUT: endpoint 2 (0x02)
        // - Bulk IN: endpoint 1 (0x81)
        // Since we don't have full enumeration yet, use defaults
        let (bulk_in_ep, bulk_out_ep) = find_bulk_endpoints(usb_dev).unwrap_or((0x81, 0x02));

        // Determine max packet size based on speed
        let max_packet = usb_dev.speed.default_max_packet_size();

        printkln!(
            "USB-MSC: Bulk IN=0x{:02x}, OUT=0x{:02x}, max_packet={}",
            bulk_in_ep,
            bulk_out_ep,
            max_packet
        );

        let msc_dev = Arc::new(UsbMscDevice::new(
            usb_dev.slot_id,
            bulk_in_ep,
            bulk_out_ep,
            max_packet,
        ));

        printkln!("USB-MSC: Device ready for SCSI layer");

        Ok(Box::new(UsbMscDeviceHandle { device: msc_dev }))
    }
}

/// Find bulk IN and OUT endpoints for MSC device
fn find_bulk_endpoints(usb_dev: &UsbDevice) -> Option<(u8, u8)> {
    // First try to find from interface info
    for iface in &usb_dev.interfaces {
        if iface.class == USB_CLASS_MASS_STORAGE {
            let mut bulk_in = None;
            let mut bulk_out = None;

            for ep in &iface.endpoints {
                if ep.ep_type == super::EndpointType::Bulk {
                    if (ep.address & 0x80) != 0 {
                        bulk_in = Some(ep.address);
                    } else {
                        bulk_out = Some(ep.address);
                    }
                }
            }

            if let (Some(i), Some(o)) = (bulk_in, bulk_out) {
                return Some((i, o));
            }
        }
    }

    None
}

/// Device handle returned from probe
///
/// This wraps the UsbMscDevice and provides access to the ScsiHost implementation.
pub struct UsbMscDeviceHandle {
    device: Arc<UsbMscDevice>,
}

impl UsbMscDeviceHandle {
    /// Get the SCSI host interface for this device
    pub fn scsi_host(&self) -> Arc<dyn ScsiHost> {
        self.device.clone()
    }
}

impl Device for UsbMscDeviceHandle {
    fn name(&self) -> &str {
        "usb-msc"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
