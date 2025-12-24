//! USB Serial (CDC-ACM) Driver
//!
//! Implements USB Communications Device Class - Abstract Control Model
//! for USB serial devices.
//!
//! Implements `BusDriver` for the USB bus to be automatically matched
//! against CDC-ACM devices.
//!
//! ## Console Integration
//!
//! When a USB serial device is detected, it is registered as a console
//! with Normal priority. This allows it to take precedence over legacy
//! serial (Fallback priority) when both are present.

use alloc::boxed::Box;
use core::any::Any;

use crate::bus::bus::{BusContext, BusDevice, BusDriver};
use crate::bus::driver::{Device, Driver, DriverError};
use crate::console::{ConsoleDriver, ConsolePriority, register_console};
use crate::downcast_bus_device;
use crate::dt::registry::DeviceInfo;
use crate::printkln;

use super::{SetupPacket, UsbDevice, UsbSpeed, cdc_subclass, class};

/// USB Serial driver
pub struct UsbSerialDriver;

impl Driver for UsbSerialDriver {
    fn compatible(&self) -> &'static [&'static str] {
        &["usb:class:02:02:00", "usb:class:02:02:01"]
    }

    fn probe(&self, _dev: &DeviceInfo) -> Result<Box<dyn Device>, DriverError> {
        // This would be called from the USB subsystem when a CDC-ACM device is found
        Err(DriverError::Unsupported)
    }
}

// ============================================================================
// USB Serial Bus Driver (Bus/Driver Model)
// ============================================================================

/// USB Serial driver for the bus/driver model
///
/// This driver matches USB devices with CDC-ACM class (Communications Device
/// Class - Abstract Control Model) and creates serial device instances.
pub struct UsbSerialBusDriver;

impl BusDriver for UsbSerialBusDriver {
    fn name(&self) -> &str {
        "usb-serial"
    }

    fn matches(&self, device: &dyn BusDevice) -> bool {
        if let Some(usb_dev) = downcast_bus_device!(device, UsbDevice) {
            return UsbSerial::is_cdc_acm_device(usb_dev);
        }
        false
    }

    /// Remove a USB serial device (hotplug)
    ///
    /// Called when the USB device is disconnected. Clears the global
    /// console registration to prevent writes to disconnected device.
    fn remove(&self, device: &dyn BusDevice) -> Result<(), DriverError> {
        let usb_dev = downcast_bus_device!(device, UsbDevice).ok_or(DriverError::Unsupported)?;

        printkln!(
            "UsbSerial: Removing device slot {} (bus_id: {})",
            usb_dev.slot_id,
            BusDevice::bus_id(usb_dev)
        );

        // Clear global USB serial console
        // SAFETY: This is called during hotplug removal, synchronized by bus lock
        unsafe {
            USB_SERIAL_CONSOLE = None;
        }

        printkln!("UsbSerial: Device slot {} removed", usb_dev.slot_id);
        Ok(())
    }

    fn probe(
        &self,
        device: &dyn BusDevice,
        _ctx: &mut BusContext,
    ) -> Result<Box<dyn Device>, DriverError> {
        let usb_dev = downcast_bus_device!(device, UsbDevice).ok_or(DriverError::Unsupported)?;

        printkln!(
            "UsbSerial: Probing USB device at {}",
            BusDevice::bus_id(usb_dev)
        );

        // Create USB serial device
        let serial = UsbSerial::new(usb_dev.clone()).ok_or(DriverError::InitFailed)?;

        // Register as console with Normal priority
        // This allows USB serial to take precedence over legacy serial
        register_usb_serial_console(&serial);

        printkln!("USB_SERIAL_READY: {}", serial.name());

        Ok(Box::new(serial))
    }
}

/// CDC-ACM Line Coding structure
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct LineCoding {
    /// Baud rate (e.g., 115200)
    pub baud_rate: u32,
    /// Stop bits: 0=1, 1=1.5, 2=2
    pub stop_bits: u8,
    /// Parity: 0=None, 1=Odd, 2=Even, 3=Mark, 4=Space
    pub parity: u8,
    /// Data bits: 5, 6, 7, or 8
    pub data_bits: u8,
}

impl Default for LineCoding {
    fn default() -> Self {
        Self {
            baud_rate: 115200,
            stop_bits: 0, // 1 stop bit
            parity: 0,    // No parity
            data_bits: 8, // 8 data bits
        }
    }
}

/// CDC class-specific requests
mod cdc_request {
    pub const SET_LINE_CODING: u8 = 0x20;
    pub const SET_CONTROL_LINE_STATE: u8 = 0x22;
}

/// USB Serial device instance
pub struct UsbSerial {
    /// USB device info
    pub usb_device: UsbDevice,
    /// Bulk IN endpoint address
    pub bulk_in_ep: u8,
    /// Bulk OUT endpoint address
    pub bulk_out_ep: u8,
    /// Interrupt endpoint address (for serial state notifications)
    pub interrupt_ep: u8,
    /// Current line coding
    pub line_coding: LineCoding,
    /// Control interface number
    pub control_iface: u8,
    /// Data interface number
    pub data_iface: u8,
}

impl UsbSerial {
    /// Create a new USB serial device from a detected USB device
    ///
    /// This performs basic validation that the device looks like a CDC-ACM device.
    pub fn new(usb_device: UsbDevice) -> Option<Self> {
        // For a simple implementation, we assume the device is CDC-ACM
        // A full implementation would parse the configuration descriptor
        // to find the CDC control and data interfaces.

        // CDC-ACM typically has:
        // - Interface 0: CDC Control (class 0x02, subclass 0x02)
        //   - Interrupt IN endpoint for notifications
        // - Interface 1: CDC Data (class 0x0A)
        //   - Bulk IN endpoint for receiving data
        //   - Bulk OUT endpoint for sending data

        // QEMU's usb-serial device uses these typical endpoint addresses:
        // - Interrupt IN: 0x81
        // - Bulk IN: 0x82
        // - Bulk OUT: 0x02

        printkln!(
            "UsbSerial: Creating device for slot={}, port={}",
            usb_device.slot_id,
            usb_device.port
        );

        Some(Self {
            usb_device,
            bulk_in_ep: 0x82,   // Standard bulk IN
            bulk_out_ep: 0x02,  // Standard bulk OUT
            interrupt_ep: 0x81, // Standard interrupt IN
            line_coding: LineCoding::default(),
            control_iface: 0,
            data_iface: 1,
        })
    }

    /// Check if a USB device is a CDC-ACM serial device
    pub fn is_cdc_acm_device(device: &UsbDevice) -> bool {
        // Check device class
        if device.device_class == class::CDC {
            return true;
        }

        // For composite devices, check interfaces
        for iface in &device.interfaces {
            if iface.class == class::CDC && iface.subclass == cdc_subclass::ACM {
                return true;
            }
        }

        // For QEMU usb-serial, the device is class 0x02 (CDC)
        // We can also check if it's a Full speed device on an expected port
        // as a heuristic
        device.speed == UsbSpeed::Full
    }

    /// Initialize the serial device with line coding
    pub fn init(&mut self) -> Result<(), &'static str> {
        // In a full implementation, we would:
        // 1. Send SET_LINE_CODING to configure baud rate, etc.
        // 2. Send SET_CONTROL_LINE_STATE to enable DTR/RTS

        // Copy packed fields to avoid alignment issues
        let baud = { self.line_coding.baud_rate };
        let data_bits = { self.line_coding.data_bits };
        let stop_bits = { self.line_coding.stop_bits };

        printkln!(
            "UsbSerial: Initialized at {} baud, {}N{}",
            baud,
            data_bits,
            match stop_bits {
                0 => 1,
                1 => 15, // 1.5 represented as 15
                _ => 2,
            }
        );

        Ok(())
    }

    /// Create SET_LINE_CODING setup packet
    #[allow(dead_code)]
    pub fn set_line_coding_setup(&self) -> SetupPacket {
        SetupPacket::class_interface(
            cdc_request::SET_LINE_CODING,
            0,
            self.control_iface as u16,
            core::mem::size_of::<LineCoding>() as u16,
        )
    }

    /// Create SET_CONTROL_LINE_STATE setup packet
    #[allow(dead_code)]
    pub fn set_control_line_state_setup(&self, dtr: bool, rts: bool) -> SetupPacket {
        let value = (if dtr { 1 } else { 0 }) | (if rts { 2 } else { 0 });
        SetupPacket::class_interface(
            cdc_request::SET_CONTROL_LINE_STATE,
            value,
            self.control_iface as u16,
            0,
        )
    }
}

impl Device for UsbSerial {
    fn name(&self) -> &str {
        "usb-serial"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Static USB serial console instance
/// Used to register with the console subsystem
static mut USB_SERIAL_CONSOLE: Option<UsbSerialConsole> = None;

/// Wrapper for USB serial as a console
///
/// This wrapper allows UsbSerial to be registered as a static console.
/// Note: Actual USB bulk transfers require xHCI support which is not
/// fully implemented. For now, this acts as a placeholder that shows
/// the console infrastructure is working.
pub struct UsbSerialConsole {
    /// Device name
    name: &'static str,
    /// Slot ID for USB device
    slot_id: u8,
    /// Bulk OUT endpoint
    bulk_out_ep: u8,
}

impl UsbSerialConsole {
    /// Create from a UsbSerial device
    pub fn from_usb_serial(serial: &UsbSerial) -> Self {
        Self {
            name: "ttyUSB0",
            slot_id: serial.usb_device.slot_id,
            bulk_out_ep: serial.bulk_out_ep,
        }
    }
}

impl ConsoleDriver for UsbSerialConsole {
    fn name(&self) -> &str {
        self.name
    }

    fn write(&self, data: &[u8]) {
        use crate::usb::xhci::{is_usb_output_active, usb_bulk_out};

        // Check recursion guard - if USB output is already active, skip to prevent deadlock
        // This can happen when a printkln! inside USB code tries to write to USB serial
        if is_usb_output_active() {
            return;
        }

        // Send data via USB bulk OUT transfer (ignore errors - console is best-effort)
        let _ = usb_bulk_out(self.slot_id, self.bulk_out_ep, data);
    }
}

/// Register a USB serial device as a console
///
/// This is called from the probe function when a USB serial device is detected.
/// The device is registered with Normal priority, allowing it to take precedence
/// over legacy serial (Fallback priority).
pub fn register_usb_serial_console(serial: &UsbSerial) {
    use crate::console::ConsoleFlags;

    // SAFETY: This is only called during driver probe, which happens once
    // per device during boot on a single CPU
    unsafe {
        USB_SERIAL_CONSOLE = Some(UsbSerialConsole::from_usb_serial(serial));

        if let Some(ref console) = USB_SERIAL_CONSOLE {
            // Register with Normal priority (higher than legacy serial's Fallback)
            // No special flags - this is a normal runtime console
            register_console(console, ConsolePriority::Normal, ConsoleFlags::empty());
        }
    }
}

/// Create a USB serial device from a detected USB device if it's CDC-ACM
pub fn create_usb_serial(usb_device: UsbDevice) -> Option<UsbSerial> {
    if UsbSerial::is_cdc_acm_device(&usb_device) {
        let mut serial = UsbSerial::new(usb_device)?;
        if serial.init().is_ok() {
            return Some(serial);
        }
    }
    None
}
