//! Device registry

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// Information about a device discovered from the device tree
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// Device name (from node name)
    pub name: String,
    /// Compatible string
    pub compatible: String,
    /// Base address (from reg property)
    pub base_addr: Option<u64>,
    /// Size (from reg property)
    pub size: Option<u64>,
    /// Interrupt numbers
    pub interrupts: Option<Vec<u32>>,
    /// Clock frequency (from clock-frequency property)
    pub clock_frequency: Option<u32>,
}

/// Registry of all discovered devices
pub struct DeviceRegistry {
    /// Devices indexed by path
    devices: BTreeMap<String, DeviceInfo>,
}

impl DeviceRegistry {
    /// Create an empty registry
    pub fn new() -> Self {
        Self {
            devices: BTreeMap::new(),
        }
    }

    /// Add a device to the registry
    pub fn add(&mut self, path: String, info: DeviceInfo) {
        self.devices.insert(path, info);
    }

    /// Find a device by compatible string
    pub fn find_by_compatible(&self, compatible: &str) -> Option<&DeviceInfo> {
        self.devices.values().find(|d| d.compatible == compatible)
    }

    /// Find a device by path
    pub fn find_by_path(&self, path: &str) -> Option<&DeviceInfo> {
        self.devices.get(path)
    }

    /// Iterate over all devices
    pub fn iter(&self) -> impl Iterator<Item = (&String, &DeviceInfo)> {
        self.devices.iter()
    }
}

impl Default for DeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}
