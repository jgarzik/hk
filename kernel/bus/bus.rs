//! Bus/Driver Model
//!
//! Provides a layered bus abstraction following the Linux kernel model.
//! Each bus type (PCI, USB) can enumerate devices and match them against
//! registered drivers. Drivers can create child buses when probed.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use core::any::Any;

use crate::arch::FrameAlloc;
use crate::printkln;

use super::driver::{Device, DriverError};

/// A device on a bus that can be matched against drivers
pub trait BusDevice: Send + Sync + Any {
    /// Human-readable device name
    fn name(&self) -> &str;

    /// Unique identifier on this bus (e.g., "0000:00:04.0" for PCI)
    fn bus_id(&self) -> String;

    /// For downcasting support
    fn as_any(&self) -> &dyn Any;

    /// For downcasting support (mutable)
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Context passed to drivers during probe
///
/// Allows drivers to:
/// - Allocate physical memory frames
/// - Register child buses they create
/// - Register pending drivers for child buses
pub struct BusContext<'a> {
    /// Frame allocator for memory allocation
    pub frame_alloc: &'a mut dyn FrameAllocWrapper,

    /// Buses created during this probe (collected by BusManager)
    pub new_buses: Vec<(&'static str, Box<dyn Bus>)>,

    /// Drivers pending for buses that don't exist yet
    pub pending_drivers: &'a mut Vec<(&'static str, Box<dyn BusDriver>)>,
}

/// Wrapper trait to work around dyn FrameAlloc limitations
pub trait FrameAllocWrapper {
    fn alloc_frame(&mut self) -> Option<u64>;
    fn free_frame(&mut self, frame: u64);
}

impl<T: FrameAlloc<PhysAddr = u64>> FrameAllocWrapper for T {
    fn alloc_frame(&mut self) -> Option<u64> {
        FrameAlloc::alloc_frame(self)
    }

    fn free_frame(&mut self, frame: u64) {
        FrameAlloc::free_frame(self, frame);
    }
}

/// A driver for devices on a specific bus type
pub trait BusDriver: Send + Sync {
    /// Human-readable driver name
    fn name(&self) -> &str;

    /// Check if this driver can handle the given device
    fn matches(&self, device: &dyn BusDevice) -> bool;

    /// Probe and initialize a device
    ///
    /// Called when `matches()` returns true. The driver should:
    /// 1. Take ownership of the device
    /// 2. Initialize it
    /// 3. Optionally create child buses via `ctx.new_buses`
    fn probe(
        &self,
        device: &dyn BusDevice,
        ctx: &mut BusContext,
    ) -> Result<Box<dyn Device>, DriverError>;

    /// Remove/unbind a device from this driver (hotplug support)
    ///
    /// Called when a device is being disconnected or driver is being unloaded.
    /// The driver should:
    /// 1. Stop all pending transfers/operations
    /// 2. Unregister IRQ handlers
    /// 3. Free DMA allocations
    /// 4. Unmap MMIO regions
    ///
    /// Default implementation does nothing (for backward compatibility).
    fn remove(&self, _device: &dyn BusDevice) -> Result<(), DriverError> {
        Ok(())
    }
}

/// A bus that discovers devices and matches them to drivers
pub trait Bus: Send + Sync {
    /// Bus type name (e.g., "pci", "usb")
    fn name(&self) -> &str;

    /// Register a driver with this bus
    fn register_driver(&mut self, driver: Box<dyn BusDriver>);

    /// Enumerate devices on this bus and probe matching drivers
    ///
    /// This is where the magic happens:
    /// 1. Scan for devices (hardware-specific)
    /// 2. For each device, find a matching driver
    /// 3. Call driver.probe() which may create child buses
    fn enumerate(&mut self, ctx: &mut BusContext);

    /// Check if this bus is a "root" bus (should be enumerated first)
    fn is_root(&self) -> bool {
        false
    }

    /// Get all probed devices on this bus
    fn probed_devices(&self) -> &[Box<dyn Device>] {
        &[]
    }

    /// Remove a device from this bus (hotplug support)
    ///
    /// Called when a device is physically disconnected or being force-removed.
    /// The bus implementation should:
    /// 1. Find the driver bound to this device
    /// 2. Call driver.remove()
    /// 3. Remove device from internal tracking structures
    ///
    /// Default: returns Unsupported (bus doesn't support hotplug)
    fn remove_device(&mut self, _bus_id: &str) -> Result<(), DriverError> {
        Err(DriverError::Unsupported)
    }
}

/// Central registry for all buses in the system
pub struct BusManager {
    /// All registered buses, indexed by name
    buses: BTreeMap<String, Box<dyn Bus>>,

    /// Drivers waiting for buses that don't exist yet
    pending_drivers: Vec<(&'static str, Box<dyn BusDriver>)>,

    /// Order in which root buses should be enumerated
    root_buses: Vec<String>,
}

impl BusManager {
    /// Create a new empty bus manager
    pub fn new() -> Self {
        Self {
            buses: BTreeMap::new(),
            pending_drivers: Vec::new(),
            root_buses: Vec::new(),
        }
    }

    /// Register a bus
    ///
    /// If `is_root` is true, it will be enumerated during `enumerate_all()`
    pub fn register_bus(&mut self, name: &'static str, mut bus: Box<dyn Bus>) {
        printkln!("BusManager: Registering bus '{}'", name);

        // Apply any pending drivers for this bus
        let mut remaining = Vec::new();
        for (bus_name, driver) in self.pending_drivers.drain(..) {
            if bus_name == name {
                printkln!(
                    "BusManager: Adding pending driver '{}' to bus '{}'",
                    driver.name(),
                    name
                );
                bus.register_driver(driver);
            } else {
                remaining.push((bus_name, driver));
            }
        }
        self.pending_drivers = remaining;

        if bus.is_root() {
            self.root_buses.push(name.to_string());
        }

        self.buses.insert(name.to_string(), bus);
    }

    /// Register a driver for a specific bus type
    ///
    /// If the bus doesn't exist yet, the driver is queued and will be
    /// added when the bus is registered.
    pub fn register_driver(&mut self, bus_name: &'static str, driver: Box<dyn BusDriver>) {
        if let Some(bus) = self.buses.get_mut(bus_name) {
            printkln!(
                "BusManager: Registering driver '{}' on bus '{}'",
                driver.name(),
                bus_name
            );
            bus.register_driver(driver);
        } else {
            printkln!(
                "BusManager: Queuing driver '{}' for future bus '{}'",
                driver.name(),
                bus_name
            );
            self.pending_drivers.push((bus_name, driver));
        }
    }

    /// Get a mutable reference to a bus by name
    pub fn get_bus_mut(&mut self, name: &str) -> Option<&mut Box<dyn Bus>> {
        self.buses.get_mut(name)
    }

    /// Enumerate all root buses
    ///
    /// This kicks off the device discovery cascade:
    /// 1. Enumerate each root bus (e.g., PCI)
    /// 2. Matching drivers are probed
    /// 3. Drivers may create child buses (e.g., USB)
    /// 4. Child buses are enumerated
    /// 5. Continue until all buses are processed
    pub fn enumerate_all<FA: FrameAlloc<PhysAddr = u64>>(&mut self, frame_alloc: &mut FA) {
        printkln!(
            "BusManager: Starting enumeration of {} root buses",
            self.root_buses.len()
        );

        // Enumerate root buses first
        let root_names: Vec<String> = self.root_buses.clone();
        for bus_name in root_names {
            self.enumerate_bus(&bus_name, frame_alloc);
        }
    }

    /// Enumerate a specific bus and process any new buses it creates
    fn enumerate_bus<FA: FrameAlloc<PhysAddr = u64>>(&mut self, name: &str, frame_alloc: &mut FA) {
        // Take the bus out temporarily to avoid borrow issues
        let mut bus = match self.buses.remove(name) {
            Some(b) => b,
            None => return,
        };

        printkln!("BusManager: Enumerating bus '{}'", name);

        // Create context for this enumeration
        let mut ctx = BusContext {
            frame_alloc,
            new_buses: Vec::new(),
            pending_drivers: &mut self.pending_drivers,
        };

        // Enumerate the bus
        bus.enumerate(&mut ctx);

        // Put the bus back
        self.buses.insert(name.to_string(), bus);

        // Process any new buses created during enumeration
        let new_buses: Vec<_> = ctx.new_buses.drain(..).collect();
        for (new_name, new_bus) in new_buses {
            self.register_bus(new_name, new_bus);
            // Recursively enumerate the new bus
            self.enumerate_bus(new_name, frame_alloc);
        }
    }

    /// Find the first device of a specific type across all buses
    ///
    /// Uses downcasting to find a device matching the requested type.
    /// Returns a reference to the device if found.
    pub fn find_device<T: 'static>(&self) -> Option<&T> {
        for bus in self.buses.values() {
            for device in bus.probed_devices() {
                if let Some(typed) = device.as_any().downcast_ref::<T>() {
                    return Some(typed);
                }
            }
        }
        None
    }

    /// Remove a device from a specific bus (hotplug support)
    ///
    /// Delegates to the bus's `remove_device()` implementation.
    pub fn remove_device(&mut self, bus_name: &str, bus_id: &str) -> Result<(), DriverError> {
        if let Some(bus) = self.buses.get_mut(bus_name) {
            bus.remove_device(bus_id)
        } else {
            Err(DriverError::MissingResource)
        }
    }
}

impl Default for BusManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper macro for downcasting BusDevice to concrete types
#[macro_export]
macro_rules! downcast_bus_device {
    ($device:expr, $type:ty) => {
        $device.as_any().downcast_ref::<$type>()
    };
}
