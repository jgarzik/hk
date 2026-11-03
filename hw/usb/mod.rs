//! USB Subsystem
//!
//! This module provides USB host controller support and device drivers.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::printkln;

pub mod context;
pub mod ext_caps;
pub mod msc;
pub mod pci_quirks;
pub mod serial;
pub mod transfer;
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
    printkln!("USB: Protocol tracing enabled");
}

/// Check if USB tracing is enabled
#[inline]
pub fn usb_trace_enabled() -> bool {
    USB_TRACE.load(Ordering::Relaxed)
}

// Re-export USB host functions for use by USB drivers
pub use xhci::{usb_bulk_in, usb_bulk_out, usb_configure_endpoints};

// Re-export USB serial driver for registration
pub use serial::{USB_SERIAL_DRIVER, UsbSerial};

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

    /// Get the maximum packet size for control endpoint 0
    pub fn default_max_packet_size(&self) -> u16 {
        match self {
            UsbSpeed::Low => 8,
            UsbSpeed::Full => 8,
            UsbSpeed::High => 64,
            UsbSpeed::Super | UsbSpeed::SuperPlus => 512,
        }
    }
}

/// USB device descriptor (standard format)
#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct UsbDeviceDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub usb_version: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub max_packet_size0: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub device_version: u16,
    pub manufacturer_index: u8,
    pub product_index: u8,
    pub serial_index: u8,
    pub num_configurations: u8,
}

/// USB configuration descriptor
#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct UsbConfigDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub total_length: u16,
    pub num_interfaces: u8,
    pub configuration_value: u8,
    pub configuration_index: u8,
    pub attributes: u8,
    pub max_power: u8,
}

/// USB interface descriptor
#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct UsbInterfaceDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub num_endpoints: u8,
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
    pub interface_index: u8,
}

/// USB endpoint descriptor
#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct UsbEndpointDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub endpoint_address: u8,
    pub attributes: u8,
    pub max_packet_size: u16,
    pub interval: u8,
}

impl UsbEndpointDescriptor {
    /// Get endpoint number (0-15)
    pub fn number(&self) -> u8 {
        self.endpoint_address & 0x0F
    }

    /// Check if endpoint is IN (device to host)
    pub fn is_in(&self) -> bool {
        (self.endpoint_address & 0x80) != 0
    }

    /// Get transfer type
    pub fn transfer_type(&self) -> EndpointType {
        match self.attributes & 0x03 {
            0 => EndpointType::Control,
            1 => EndpointType::Isochronous,
            2 => EndpointType::Bulk,
            3 => EndpointType::Interrupt,
            _ => unreachable!(),
        }
    }
}

/// Endpoint transfer type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointType {
    Control,
    Isochronous,
    Bulk,
    Interrupt,
}

/// USB setup packet (for control transfers)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct SetupPacket {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

impl SetupPacket {
    /// Create a GET_DESCRIPTOR request
    pub fn get_descriptor(desc_type: u8, desc_index: u8, length: u16) -> Self {
        Self {
            request_type: 0x80, // Device to host, standard, device
            request: 0x06,      // GET_DESCRIPTOR
            value: ((desc_type as u16) << 8) | (desc_index as u16),
            index: 0,
            length,
        }
    }

    /// Create a SET_ADDRESS request
    pub fn set_address(address: u8) -> Self {
        Self {
            request_type: 0x00, // Host to device, standard, device
            request: 0x05,      // SET_ADDRESS
            value: address as u16,
            index: 0,
            length: 0,
        }
    }

    /// Create a SET_CONFIGURATION request
    pub fn set_configuration(config: u8) -> Self {
        Self {
            request_type: 0x00, // Host to device, standard, device
            request: 0x09,      // SET_CONFIGURATION
            value: config as u16,
            index: 0,
            length: 0,
        }
    }

    /// Create a class-specific interface request
    pub fn class_interface(request: u8, value: u16, index: u16, length: u16) -> Self {
        Self {
            request_type: 0x21, // Host to device, class, interface
            request,
            value,
            index,
            length,
        }
    }
}

/// USB descriptor types
pub mod descriptor_type {
    pub const DEVICE: u8 = 0x01;
    pub const CONFIGURATION: u8 = 0x02;
    pub const STRING: u8 = 0x03;
    pub const INTERFACE: u8 = 0x04;
    pub const ENDPOINT: u8 = 0x05;
}

/// USB class codes
pub mod class {
    pub const INTERFACE_DEFINED: u8 = 0x00;
    pub const AUDIO: u8 = 0x01;
    pub const CDC: u8 = 0x02; // Communications Device Class
    pub const HID: u8 = 0x03;
    pub const MASS_STORAGE: u8 = 0x08;
    pub const HUB: u8 = 0x09;
    pub const CDC_DATA: u8 = 0x0A;
    pub const VENDOR_SPECIFIC: u8 = 0xFF;
}

/// CDC subclass codes
pub mod cdc_subclass {
    pub const ACM: u8 = 0x02; // Abstract Control Model (serial)
}

/// CDC protocol codes
pub mod cdc_protocol {
    pub const NONE: u8 = 0x00;
    pub const AT_COMMANDS: u8 = 0x01;
}

/// Represents a USB endpoint on a device
#[derive(Debug, Clone)]
pub struct UsbEndpoint {
    pub address: u8,
    pub ep_type: EndpointType,
    pub max_packet_size: u16,
    pub interval: u8,
}

/// Represents a USB interface on a device
#[derive(Debug, Clone)]
pub struct UsbInterface {
    pub number: u8,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub endpoints: Vec<UsbEndpoint>,
}

/// Represents a connected USB device
#[derive(Debug, Clone)]
pub struct UsbDevice {
    /// Device slot ID assigned by xHCI
    pub slot_id: u8,
    /// USB address (1-127)
    pub address: u8,
    /// Device speed
    pub speed: UsbSpeed,
    /// Root hub port number
    pub port: u8,
    /// Vendor ID
    pub vendor_id: u16,
    /// Product ID
    pub product_id: u16,
    /// Device class
    pub device_class: u8,
    /// Device subclass
    pub device_subclass: u8,
    /// Device protocol
    pub device_protocol: u8,
    /// Interfaces
    pub interfaces: Vec<UsbInterface>,
}

impl UsbDevice {
    /// Check if this is a CDC-ACM device (USB serial)
    pub fn is_cdc_acm(&self) -> bool {
        // Check device class or look through interfaces
        if self.device_class == class::CDC {
            return true;
        }

        // Check interfaces for CDC-ACM
        for iface in &self.interfaces {
            if iface.class == class::CDC && iface.subclass == cdc_subclass::ACM {
                return true;
            }
        }

        false
    }

    /// Find the CDC data interface (for bulk transfers)
    pub fn find_cdc_data_interface(&self) -> Option<&UsbInterface> {
        self.interfaces.iter().find(|i| i.class == class::CDC_DATA)
    }

    /// Find bulk IN and OUT endpoints from CDC data interface
    pub fn find_bulk_endpoints(&self) -> Option<(u8, u8)> {
        let data_iface = self.find_cdc_data_interface()?;
        let mut bulk_in = None;
        let mut bulk_out = None;

        for ep in &data_iface.endpoints {
            if ep.ep_type == EndpointType::Bulk {
                if (ep.address & 0x80) != 0 {
                    bulk_in = Some(ep.address);
                } else {
                    bulk_out = Some(ep.address);
                }
            }
        }

        match (bulk_in, bulk_out) {
            (Some(i), Some(o)) => Some((i, o)),
            _ => None,
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

    /// Perform a control transfer
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

// ============================================================================
// USB on the device core (Linux drivers/usb/core/usb.c, driver.c, hub.c)
// ============================================================================

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;

use crate::base::bus::BusType;
use crate::base::{Device, DeviceInfo, Driver, device_create};
use crate::fs::kernfs;
use crate::util::error::KernelError;

pub static USB_BUS: BusType = BusType::new("usb", usb_match, Some(usb_uevent));

/// Linux usb_init: the bus
pub fn usb_init() {
    USB_BUS.register();
}

/// A USB driver's match (by the device's properties)
pub struct UsbIds(pub fn(&UsbDevice) -> bool);

/// A USB device's data: the device, its bus number and address
pub struct UsbDevNode {
    pub dev: UsbDevice,
    pub busnum: u8,
    pub devnum: u8,
}

/// The USB device behind `dev`
pub fn usb_dev(dev: &Device) -> Option<&UsbDevice> {
    dev.data::<UsbDevNode>().map(|n| &n.dev)
}

fn usb_match(dev: &Device, drv: &'static Driver) -> bool {
    let (Some(u), Some(UsbIds(m))) = (usb_dev(dev), drv.ids.downcast_ref::<UsbIds>()) else {
        return false;
    };
    m(u)
}

/// Linux usb_dev_uevent
fn usb_uevent(dev: &Device, env: &mut Vec<Vec<u8>>) {
    let Some(n) = dev.data::<UsbDevNode>() else {
        return;
    };
    env.push(format!("BUSNUM={:03}", n.busnum).into_bytes());
    env.push(format!("DEVNUM={:03}", n.devnum).into_bytes());
}

/// Linux speed_show: Mbit/s
fn speed_mbps(s: UsbSpeed) -> &'static str {
    match s {
        UsbSpeed::Low => "1.5",
        UsbSpeed::Full => "12",
        UsbSpeed::High => "480",
        UsbSpeed::Super => "5000",
        UsbSpeed::SuperPlus => "10000",
    }
}

/// A USB device's attributes (Linux usb_dev_attrs subset)
fn usb_attrs(dev: &Arc<Device>) -> Result<(), KernelError> {
    let Some(n) = dev.data::<UsbDevNode>() else {
        return Ok(());
    };
    let devpath = match dev.name().split_once('-') {
        Some((_, p)) => String::from(p),
        None => String::from("0"),
    };
    let text: [(&[u8], String); 4] = [
        (b"busnum", format!("{}\n", n.busnum)),
        (b"devnum", format!("{}\n", n.devnum)),
        (b"speed", format!("{}\n", speed_mbps(n.dev.speed))),
        (b"devpath", format!("{}\n", devpath)),
    ];
    for (name, v) in text {
        dev.create_file(name, 0o444, kernfs::show(move |o| o.bytes(v.as_bytes())))?;
    }
    Ok(())
}

/// Register the root hub `usbN` below the host controller and each
/// device on its ports as `N-<port>` (Linux usb_add_hcd, usb_new_device)
pub fn usb_register_devices(hcd: &Arc<Device>, devs: Vec<UsbDevice>) -> Vec<Arc<Device>> {
    let busnum = 1;
    let mut out = Vec::new();
    let Ok(root) = device_create(DeviceInfo {
        parent: Some(hcd),
        devtype: Some("usb_device"),
        ..DeviceInfo::named(&format!("usb{}", busnum))
    }) else {
        return out;
    };
    for d in devs {
        let name = format!("{}-{}", busnum, d.port);
        let devnum = d.address;
        let r = device_create(DeviceInfo {
            parent: Some(&root),
            bus: Some(&USB_BUS),
            devtype: Some("usb_device"),
            data: Some(Arc::new(UsbDevNode {
                dev: d,
                busnum,
                devnum,
            })),
            attrs: Some(usb_attrs),
            ..DeviceInfo::named(&name)
        });
        if let Ok(dev) = r {
            out.push(dev);
        }
    }
    out.push(root);
    out
}
