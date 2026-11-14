//! USB Subsystem
//!
//! The host controller (xHCI), the USB core on the device core
//! (`usbcore`: devices, interfaces, the generic driver; `driver`: id
//! matching and uevents; `config`: descriptor parsing) and the device
//! drivers (usb-storage, ftdi_sio).

use core::sync::atomic::{AtomicBool, Ordering};

use crate::printkln;

pub mod config;
pub mod context;
pub mod driver;
pub mod ext_caps;
pub mod msc;
pub mod pci_quirks;
pub mod serial;
pub mod transfer;
pub mod usbcore;
pub mod xhci;

// ============================================================================
// USB Protocol Tracing
// ============================================================================

/// USB protocol tracing flag (enable via kernel cmdline "usb_trace")
static USB_TRACE: AtomicBool = AtomicBool::new(false);

/// Enable USB protocol tracing
///
/// This enables detailed tracing of USB protocol operations across
/// all USB host controllers and drivers.
pub fn enable_usb_trace() {
    USB_TRACE.store(true, Ordering::Release);
    crate::trace::want_buffers();
    printkln!("USB: Protocol tracing enabled");
}

/// Check if USB tracing is enabled
#[inline]
pub fn usb_trace_enabled() -> bool {
    USB_TRACE.load(Ordering::Relaxed)
}

// Re-export USB host functions for use by USB drivers
pub use xhci::{usb_bulk_in, usb_bulk_out};

// Re-export USB serial driver for registration
pub use serial::{USB_SERIAL_DRIVER, UsbSerial};

pub use driver::{UsbDeviceId, UsbIds};
pub use usbcore::{USB_BUS, usb_dev, usb_init, usb_intf, usb_register_devices};

use alloc::vec::Vec;

/// USB speed classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UsbSpeed {
    /// Full speed (12 Mbps) - USB 1.1
    Full = 1,
    /// Low speed (1.5 Mbps) - USB 1.0
    Low = 2,
    /// High speed (480 Mbps) - USB 2.0
    High = 3,
    /// Super speed (5 Gbps) - USB 3.0
    Super = 4,
    /// Super speed+ (10 Gbps) - USB 3.1
    SuperPlus = 5,
}

impl UsbSpeed {
    /// Get speed from xHCI port speed ID
    pub fn from_xhci_speed(speed: u8) -> Option<Self> {
        match speed {
            1 => Some(UsbSpeed::Full),
            2 => Some(UsbSpeed::Low),
            3 => Some(UsbSpeed::High),
            4 => Some(UsbSpeed::Super),
            5 => Some(UsbSpeed::SuperPlus),
            _ => None,
        }
    }

    /// EP0's max packet size before the device descriptor is read
    /// (Linux xhci_setup_addressable_virt_dev)
    pub fn default_max_packet_size(&self) -> u16 {
        match self {
            UsbSpeed::Low => 8,
            UsbSpeed::Full | UsbSpeed::High => 64,
            UsbSpeed::Super | UsbSpeed::SuperPlus => 512,
        }
    }

    /// SuperSpeed or faster
    pub fn is_super(&self) -> bool {
        matches!(self, UsbSpeed::Super | UsbSpeed::SuperPlus)
    }
}

/// USB setup packet (for control transfers)
#[derive(Debug, Clone, Copy)]
pub struct SetupPacket {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

/// bmRequestType direction: device to host
pub const USB_DIR_IN: u8 = 0x80;

impl SetupPacket {
    /// A GET_DESCRIPTOR request (Linux usb_get_descriptor)
    pub fn get_descriptor(desc_type: u8, desc_index: u8, length: u16) -> Self {
        Self {
            request_type: USB_DIR_IN,
            request: 0x06,
            value: (u16::from(desc_type) << 8) | u16::from(desc_index),
            index: 0,
            length,
        }
    }

    /// A SET_CONFIGURATION request
    pub fn set_configuration(config: u8) -> Self {
        Self {
            request_type: 0x00,
            request: 0x09,
            value: u16::from(config),
            index: 0,
            length: 0,
        }
    }

    /// Device to host
    pub fn is_in(&self) -> bool {
        self.request_type & USB_DIR_IN != 0
    }

    /// The 8 bytes on the wire (little endian)
    pub fn bytes(&self) -> [u8; 8] {
        let [v0, v1] = self.value.to_le_bytes();
        let [i0, i1] = self.index.to_le_bytes();
        let [l0, l1] = self.length.to_le_bytes();
        [self.request_type, self.request, v0, v1, i0, i1, l0, l1]
    }
}

/// USB descriptor types
pub mod descriptor_type {
    pub const DEVICE: u8 = 0x01;
    pub const CONFIGURATION: u8 = 0x02;
    pub const STRING: u8 = 0x03;
    pub const INTERFACE: u8 = 0x04;
    pub const ENDPOINT: u8 = 0x05;
    pub const SS_ENDPOINT_COMP: u8 = 0x30;
}

/// USB class codes
pub mod class {
    pub const PER_INTERFACE: u8 = 0x00;
    pub const MASS_STORAGE: u8 = 0x08;
    pub const HUB: u8 = 0x09;
    pub const VENDOR_SPEC: u8 = 0xFF;
}

/// Endpoint transfer type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointType {
    Control,
    Isochronous,
    Bulk,
    Interrupt,
}

impl EndpointType {
    /// From bmAttributes bits 1:0
    pub fn from_attributes(a: u8) -> Self {
        match a & 3 {
            0 => Self::Control,
            1 => Self::Isochronous,
            2 => Self::Bulk,
            _ => Self::Interrupt,
        }
    }
}

/// An endpoint of an interface (its endpoint descriptor and, at
/// SuperSpeed, its companion)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbEndpoint {
    /// bEndpointAddress (bit 7: IN)
    pub address: u8,
    pub ep_type: EndpointType,
    /// wMaxPacketSize as sent (bits 12:11: high-bandwidth mult)
    pub max_packet_size: u16,
    /// bInterval
    pub interval: u8,
    /// bMaxBurst of the SuperSpeed companion (0 without one)
    pub max_burst: u8,
    /// wBytesPerInterval of the SuperSpeed companion
    pub bytes_per_interval: u16,
}

impl UsbEndpoint {
    pub fn is_in(&self) -> bool {
        self.address & 0x80 != 0
    }

    /// Max packet size (Linux usb_endpoint_maxp)
    pub fn maxp(&self) -> u16 {
        self.max_packet_size & 0x7ff
    }

    /// Extra transactions per microframe (Linux usb_endpoint_maxp_mult - 1)
    pub fn mult(&self) -> u8 {
        ((self.max_packet_size >> 11) & 3) as u8
    }
}

/// An interface setting (its interface descriptor and endpoints)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsbInterface {
    pub number: u8,
    pub alternate_setting: u8,
    /// bNumEndpoints
    pub num_endpoints: u8,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub endpoints: Vec<UsbEndpoint>,
}

impl UsbInterface {
    /// The first bulk IN and bulk OUT endpoint addresses
    pub fn bulk_eps(&self) -> Option<(u8, u8)> {
        let bulk = |want_in: bool| {
            self.endpoints
                .iter()
                .find(|e| e.ep_type == EndpointType::Bulk && e.is_in() == want_in)
                .map(|e| e.address)
        };
        Some((bulk(true)?, bulk(false)?))
    }
}

/// The active configuration's descriptor fields
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsbConfig {
    /// bConfigurationValue (0: unconfigured)
    pub value: u8,
    pub num_interfaces: u8,
    /// bmAttributes
    pub attributes: u8,
    /// bMaxPower (2 mA units, 8 mA at SuperSpeed)
    pub max_power: u8,
}

/// Represents a connected USB device
#[derive(Debug, Clone)]
pub struct UsbDevice {
    /// Device slot ID assigned by xHCI
    pub slot_id: u8,
    /// Device speed
    pub speed: UsbSpeed,
    /// Root hub port number
    pub port: u8,
    /// bcdUSB
    pub bcd_usb: u16,
    pub vendor_id: u16,
    pub product_id: u16,
    /// bcdDevice
    pub bcd_device: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    /// bMaxPacketSize0 as sent (an exponent at SuperSpeed)
    pub max_packet_size0: u8,
    pub num_configurations: u8,
    /// The active configuration
    pub config: UsbConfig,
    /// The active configuration's interface settings
    pub interfaces: Vec<UsbInterface>,
}

impl UsbDevice {
    /// A device not yet described (descriptors unread)
    pub fn new(slot_id: u8, port: u8, speed: UsbSpeed) -> Self {
        Self {
            slot_id,
            speed,
            port,
            bcd_usb: 0,
            vendor_id: 0,
            product_id: 0,
            bcd_device: 0,
            device_class: 0,
            device_subclass: 0,
            device_protocol: 0,
            max_packet_size0: 0,
            num_configurations: 0,
            config: UsbConfig::default(),
            interfaces: Vec::new(),
        }
    }
}

/// USB error types
#[derive(Debug)]
pub enum UsbError {
    /// Transfer timeout
    Timeout,
    /// Transfer stalled (endpoint error)
    Stall,
    /// Data buffer error
    BufferError,
    /// USB bus error
    BusError,
    /// Device not responding
    NoDevice,
    /// Out of resources (slots, memory)
    NoResources,
    /// Invalid parameter
    InvalidParam,
    /// Transfer failed with xHCI completion code
    TransferError(u8),
}

/// USB host controller trait
pub trait UsbController: Send {
    /// Reset the controller
    fn reset(&mut self) -> Result<(), UsbError>;

    /// Start the controller
    fn start(&mut self) -> Result<(), UsbError>;

    /// Enumerate connected devices
    fn enumerate_devices(&mut self) -> Result<Vec<UsbDevice>, UsbError>;

    /// Perform a control transfer: `data` is read (IN) or sent (OUT)
    fn control_transfer(
        &mut self,
        device: &UsbDevice,
        setup: &SetupPacket,
        data: Option<&mut [u8]>,
    ) -> Result<usize, UsbError>;

    /// Perform a bulk OUT transfer (host to device)
    fn bulk_out(
        &mut self,
        device: &UsbDevice,
        endpoint: u8,
        data: &[u8],
    ) -> Result<usize, UsbError>;

    /// Perform a bulk IN transfer (device to host)
    fn bulk_in(
        &mut self,
        device: &UsbDevice,
        endpoint: u8,
        data: &mut [u8],
    ) -> Result<usize, UsbError>;
}
