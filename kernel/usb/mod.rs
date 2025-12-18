//! USB Subsystem
//!
//! This module provides USB host controller support and device drivers.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::printkln;

pub mod context;
pub mod msc;
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
pub use serial::{UsbSerial, UsbSerialBusDriver, UsbSerialDriver};

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
pub trait UsbController: crate::bus::driver::Device {
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
// USB Bus Implementation (Bus/Driver Model)
// ============================================================================

use alloc::boxed::Box;
use alloc::string::String;
use core::any::Any;

use crate::bus::driver::Device;
use crate::bus::{Bus, BusContext, BusDevice, BusDriver};

/// Implement BusDevice for UsbDevice to participate in bus/driver model
impl BusDevice for UsbDevice {
    fn name(&self) -> &str {
        "usb-device"
    }

    fn bus_id(&self) -> String {
        use alloc::format;
        format!("usb:{:x}:{}", self.slot_id, self.port)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// USB bus implementing the Bus trait for the bus/driver model
///
/// The USB bus is created by the xHCI driver when it detects a USB host controller
/// on the PCI bus. It contains the list of detected USB devices and matches them
/// against registered USB drivers (like USB-Serial).
pub struct UsbBus {
    /// Discovered USB devices
    devices: Vec<UsbDevice>,
    /// Registered USB drivers
    drivers: Vec<Box<dyn BusDriver>>,
    /// Probed devices (devices that have been matched to drivers)
    probed_devices: Vec<Box<dyn Device>>,
}

impl UsbBus {
    /// Create a new USB bus with discovered devices
    pub fn new(devices: Vec<UsbDevice>) -> Self {
        Self {
            devices,
            drivers: Vec::new(),
            probed_devices: Vec::new(),
        }
    }
}

impl Bus for UsbBus {
    fn name(&self) -> &str {
        "usb"
    }

    fn register_driver(&mut self, driver: Box<dyn BusDriver>) {
        printkln!("USB: Registered driver '{}'", driver.name());
        self.drivers.push(driver);
    }

    fn enumerate(&mut self, ctx: &mut BusContext) {
        printkln!("USB: Enumerating {} device(s)...", self.devices.len());

        // Match devices to drivers and probe
        for device in &self.devices {
            printkln!(
                "USB: Device at {} - speed={:?}, class={:02x}:{:02x}:{:02x}",
                BusDevice::bus_id(device),
                device.speed,
                device.device_class,
                device.device_subclass,
                device.device_protocol
            );

            for driver in &self.drivers {
                if driver.matches(device) {
                    printkln!(
                        "USB: Driver '{}' matched device at {}",
                        driver.name(),
                        BusDevice::bus_id(device)
                    );

                    match driver.probe(device, ctx) {
                        Ok(dev_instance) => {
                            printkln!("USB: Successfully probed '{}'", dev_instance.name());
                            self.probed_devices.push(dev_instance);
                        }
                        Err(e) => {
                            printkln!("USB: Failed to probe: {:?}", e);
                        }
                    }

                    // Only match first driver per device
                    break;
                }
            }
        }
    }

    fn is_root(&self) -> bool {
        false // USB is not a root bus - it's created by xHCI
    }

    fn probed_devices(&self) -> &[Box<dyn Device>] {
        &self.probed_devices
    }

    /// Remove a USB device from this bus (hotplug support)
    ///
    /// Following Linux kernel USB hotplug patterns:
    /// 1. Find the device by bus_id
    /// 2. Find and call driver.remove()
    /// 3. Remove from probed_devices
    /// 4. Remove from devices list
    fn remove_device(&mut self, bus_id: &str) -> Result<(), crate::bus::driver::DriverError> {
        use crate::bus::driver::DriverError;

        printkln!("USB: Removing device {}", bus_id);

        // Find the device index
        let device_idx = self
            .devices
            .iter()
            .position(|d| BusDevice::bus_id(d) == bus_id);

        let device_idx = match device_idx {
            Some(idx) => idx,
            None => {
                printkln!("USB: Device {} not found", bus_id);
                return Err(DriverError::MissingResource);
            }
        };

        // Get reference to device for driver matching
        let device = &self.devices[device_idx];

        // Find matching driver and call remove()
        for driver in &self.drivers {
            if driver.matches(device) {
                printkln!(
                    "USB: Calling driver '{}' remove for {}",
                    driver.name(),
                    bus_id
                );

                // Call driver's remove callback
                if let Err(e) = driver.remove(device) {
                    printkln!("USB: Driver remove failed: {:?}", e);
                    return Err(e);
                }

                break;
            }
        }

        // Remove from probed_devices list
        self.probed_devices.retain(|dev| {
            if let Some(dev_bus_id) = dev.bus_id() {
                dev_bus_id != bus_id
            } else {
                true // Keep devices without bus_id tracking
            }
        });

        // Remove from devices list
        self.devices.remove(device_idx);

        printkln!("USB: Device {} removed successfully", bus_id);
        Ok(())
    }
}
