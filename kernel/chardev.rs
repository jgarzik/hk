//! Character Device Framework
//!
//! This module provides the character device abstraction layer following
//! Linux conventions with major/minor device numbers.
//!
//! ## Architecture (per tty.txt)
//!
//! ```text
//! Lowest layer: chrdev framework (VFS integration, read/write/ioctl).
//! Middle:       tty framework (interactive terminals implemented as chrdevs).
//! Top:          console framework (kernel log + active console(s)).
//! ```

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use spin::RwLock;

/// Major device number type
pub type DevMajor = u16;

/// Minor device number type
pub type DevMinor = u16;

/// Device ID combining major and minor numbers
///
/// Following Linux conventions:
/// - major = which driver (or device class)
/// - minor = which instance handled by that driver
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DevId {
    pub major: DevMajor,
    pub minor: DevMinor,
}

impl DevId {
    /// Create a new device ID
    pub const fn new(major: DevMajor, minor: DevMinor) -> Self {
        Self { major, minor }
    }

    /// Create a null device ID (0, 0)
    pub const fn null() -> Self {
        Self { major: 0, minor: 0 }
    }

    /// Check if this is the null device
    pub const fn is_null(&self) -> bool {
        self.major == 0 && self.minor == 0
    }

    /// Encode as a single u32 (Linux dev_t style: 12-bit major, 20-bit minor)
    pub const fn encode(&self) -> u32 {
        ((self.major as u32) << 20) | (self.minor as u32 & 0xFFFFF)
    }

    /// Decode from a single u32
    pub const fn decode(dev: u32) -> Self {
        Self {
            major: ((dev >> 20) & 0xFFF) as u16,
            minor: (dev & 0xFFFFF) as u16,
        }
    }
}

/// Well-known major device numbers (following Linux conventions)
pub mod major {
    use super::DevMajor;

    /// Unnamed/null device
    pub const UNNAMED: DevMajor = 0;
    /// Memory devices (/dev/null, /dev/zero, /dev/random)
    pub const MEM: DevMajor = 1;
    /// TTY devices (ttyS*)
    pub const TTY: DevMajor = 4;
    /// Serial ports (ttyS*)
    pub const TTYS: DevMajor = 4;
    /// TTY special devices (/dev/tty, /dev/console, /dev/ptmx)
    pub const TTYAUX: DevMajor = 5;
    /// USB serial ports (ttyUSB*)
    pub const TTYUSB: DevMajor = 188;
    /// Block device placeholder (for future)
    pub const BLOCK: DevMajor = 0;
}

/// Device type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// No device (regular file, directory, etc.)
    None,
    /// Character device
    Char,
    /// Block device (placeholder for future)
    Block,
}

impl DeviceType {
    /// Check if this is a device type (char or block)
    pub const fn is_device(&self) -> bool {
        matches!(self, DeviceType::Char | DeviceType::Block)
    }
}

/// Error type for device operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceError {
    /// Device not ready
    NotReady,
    /// Operation would block
    WouldBlock,
    /// Operation not supported
    NotSupported,
    /// I/O error
    IoError,
    /// Invalid argument
    InvalidArg,
    /// Device not found
    NotFound,
    /// No such ioctl
    NotTty,
}

/// Character device trait
///
/// Implementations provide read/write/ioctl operations for character devices.
/// This is the lowest layer of the device model.
pub trait CharDevice: Send + Sync {
    /// Device name for identification
    fn name(&self) -> &str;

    /// Open the device
    fn open(&self, _flags: u32) -> Result<(), DeviceError> {
        Ok(())
    }

    /// Close the device
    fn close(&self) {}

    /// Read bytes from the device
    fn read(&self, buf: &mut [u8]) -> Result<usize, DeviceError>;

    /// Write bytes to the device
    fn write(&self, buf: &[u8]) -> Result<usize, DeviceError>;

    /// Device-specific control operations
    fn ioctl(&self, _cmd: u32, _arg: u64) -> Result<i64, DeviceError> {
        Err(DeviceError::NotTty)
    }

    /// Check if data is available for reading (non-blocking)
    fn poll_read(&self) -> bool {
        true // Default: always ready
    }

    /// Check if device is ready for writing (non-blocking)
    fn poll_write(&self) -> bool {
        true // Default: always ready
    }
}

/// Global character device registry
///
/// Maps DevId to character device instances.
pub struct CharDeviceRegistry {
    devices: BTreeMap<DevId, Arc<dyn CharDevice>>,
}

impl CharDeviceRegistry {
    /// Create a new empty registry
    pub const fn new() -> Self {
        Self {
            devices: BTreeMap::new(),
        }
    }

    /// Register a character device
    pub fn register(&mut self, id: DevId, device: Arc<dyn CharDevice>) -> Result<(), DeviceError> {
        if self.devices.contains_key(&id) {
            return Err(DeviceError::InvalidArg);
        }
        self.devices.insert(id, device);
        Ok(())
    }

    /// Unregister a character device
    pub fn unregister(&mut self, id: DevId) -> Option<Arc<dyn CharDevice>> {
        self.devices.remove(&id)
    }

    /// Look up a character device by ID
    pub fn get(&self, id: DevId) -> Option<Arc<dyn CharDevice>> {
        self.devices.get(&id).cloned()
    }

    /// Check if a device is registered
    pub fn contains(&self, id: DevId) -> bool {
        self.devices.contains_key(&id)
    }

    /// Get number of registered devices
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }
}

impl Default for CharDeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Global character device registry instance
pub static CHARDEV_REGISTRY: RwLock<CharDeviceRegistry> = RwLock::new(CharDeviceRegistry::new());

/// Register a character device globally
pub fn register_chardev(id: DevId, device: Arc<dyn CharDevice>) -> Result<(), DeviceError> {
    CHARDEV_REGISTRY.write().register(id, device)
}

/// Unregister a character device globally
pub fn unregister_chardev(id: DevId) -> Option<Arc<dyn CharDevice>> {
    CHARDEV_REGISTRY.write().unregister(id)
}

/// Look up a character device by ID
pub fn get_chardev(id: DevId) -> Option<Arc<dyn CharDevice>> {
    CHARDEV_REGISTRY.read().get(id)
}

/// Null character device - discards writes, returns EOF on read
pub struct NullCharDevice;

impl CharDevice for NullCharDevice {
    fn name(&self) -> &str {
        "null"
    }

    fn read(&self, _buf: &mut [u8]) -> Result<usize, DeviceError> {
        Ok(0) // EOF
    }

    fn write(&self, buf: &[u8]) -> Result<usize, DeviceError> {
        Ok(buf.len()) // Discard
    }
}

/// Zero character device - returns zeros on read, discards writes
pub struct ZeroCharDevice;

impl CharDevice for ZeroCharDevice {
    fn name(&self) -> &str {
        "zero"
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, DeviceError> {
        buf.fill(0);
        Ok(buf.len())
    }

    fn write(&self, buf: &[u8]) -> Result<usize, DeviceError> {
        Ok(buf.len()) // Discard
    }
}

/// Static null device instance
pub static NULL_CHARDEV: NullCharDevice = NullCharDevice;

/// Static zero device instance
pub static ZERO_CHARDEV: ZeroCharDevice = ZeroCharDevice;

/// Register built-in character devices (null, zero)
///
/// This must be called after the heap allocator is available.
/// Creates entries for /dev/null (1,3) and /dev/zero (1,5).
pub fn register_builtin_chardevs() {
    // /dev/null = major 1 (MEM), minor 3 (Linux convention)
    let null_dev = Arc::new(NullCharDevice);
    let _ = register_chardev(DevId::new(major::MEM, 3), null_dev);

    // /dev/zero = major 1 (MEM), minor 5 (Linux convention)
    let zero_dev = Arc::new(ZeroCharDevice);
    let _ = register_chardev(DevId::new(major::MEM, 5), zero_dev);
}
