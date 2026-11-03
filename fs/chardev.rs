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

use crate::fs::File;
use crate::io::poll::{POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM, PollTable};
use crate::sync::spin::RwLock;
use crate::util::error::KernelError;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;

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

    /// Encode as a user dev_t (st_rdev; Linux new_encode_dev)
    pub const fn to_user(&self) -> u64 {
        let (ma, mi) = (self.major as u64, self.minor as u64);
        (mi & 0xff) | (ma << 8) | ((mi & !0xff) << 12)
    }

    /// Decode a user dev_t (Linux new_decode_dev / huge_decode_dev)
    pub const fn from_user(dev: u64) -> Self {
        Self {
            major: (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as u16,
            minor: ((dev & 0xff) | ((dev >> 12) & !0xff)) as u16,
        }
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

/// Character device trait (Linux file_operations of a cdev)
///
/// Implementations provide the file operations of a character device;
/// `CharDevFileOps` routes the VFS ones here. Errors are the errno the
/// syscall returns.
pub trait CharDevice: Send + Sync {
    /// Device name for identification
    fn name(&self) -> &str;

    /// Open (Linux f_op->open): `file` carries the open flags and may
    /// take per-open state in `file.private`
    fn open(&self, _file: &File) -> Result<(), KernelError> {
        Ok(())
    }

    /// Last close of `file` (Linux f_op->release)
    fn release(&self, _file: &File) {}

    /// Read bytes from the device (`file`'s O_NONBLOCK says whether it
    /// may sleep)
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, KernelError>;

    /// Write bytes to the device
    fn write(&self, file: &File, buf: &[u8]) -> Result<usize, KernelError>;

    /// The device can be mapped (Linux: its fops have mmap)
    fn mmap_ok(&self) -> bool {
        false
    }

    /// Device-specific control operations
    fn ioctl(&self, _file: &File, _cmd: u32, _arg: u64) -> Result<i64, KernelError> {
        Err(KernelError::NotTty)
    }

    /// File operations of its own (Linux chrdev_open installs the
    /// cdev's fops): None uses the generic ones over the methods here
    fn fops(&self) -> Option<&'static dyn crate::fs::FileOps> {
        None
    }

    /// Ready events (Linux f_op->poll): register on the device's wait
    /// queues through `pt`, then return the mask. Default: always ready
    fn poll(&self, _file: &File, _pt: Option<&mut PollTable>) -> u16 {
        POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM
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
    pub fn register(&mut self, id: DevId, device: Arc<dyn CharDevice>) -> Result<(), KernelError> {
        if self.devices.contains_key(&id) {
            return Err(KernelError::InvalidArgument);
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
pub fn register_chardev(id: DevId, device: Arc<dyn CharDevice>) -> Result<(), KernelError> {
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

    fn read(&self, _file: &File, _buf: &mut [u8]) -> Result<usize, KernelError> {
        Ok(0) // EOF
    }

    fn write(&self, _file: &File, buf: &[u8]) -> Result<usize, KernelError> {
        Ok(buf.len()) // Discard
    }
}

/// Zero character device - returns zeros on read, discards writes
pub struct ZeroCharDevice;

impl CharDevice for ZeroCharDevice {
    fn name(&self) -> &str {
        "zero"
    }

    /// Linux mmap_zero: private zero pages
    fn mmap_ok(&self) -> bool {
        true
    }

    fn read(&self, _file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
        buf.fill(0);
        Ok(buf.len())
    }

    fn write(&self, _file: &File, buf: &[u8]) -> Result<usize, KernelError> {
        Ok(buf.len()) // Discard
    }
}

/// /dev/full (Linux drivers/char/mem.c): reads zeros, every write fails
/// with ENOSPC
pub struct FullCharDevice;

impl CharDevice for FullCharDevice {
    fn name(&self) -> &str {
        "full"
    }

    fn read(&self, _file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
        buf.fill(0);
        Ok(buf.len())
    }

    fn write(&self, _file: &File, _buf: &[u8]) -> Result<usize, KernelError> {
        Err(KernelError::NoSpace)
    }
}

/// /dev/random and /dev/urandom (Linux random_fops/urandom_fops): reads
/// come from the CRNG, which is ready from boot, so neither blocks (as
/// on Linux once the CRNG is initialized); writes are mixed into it
pub struct RandomCharDevice(&'static str);

impl CharDevice for RandomCharDevice {
    fn name(&self) -> &str {
        self.0
    }

    fn read(&self, _file: &File, buf: &mut [u8]) -> Result<usize, KernelError> {
        let n = crate::random::stream(buf.len(), |off, b| {
            buf[off..off + b.len()].copy_from_slice(b);
            true
        });
        Ok(n)
    }

    fn write(&self, _file: &File, buf: &[u8]) -> Result<usize, KernelError> {
        crate::random::add_device_randomness(buf);
        Ok(buf.len())
    }
}

/// Static null device instance
pub static NULL_CHARDEV: NullCharDevice = NullCharDevice;

/// Static zero device instance
pub static ZERO_CHARDEV: ZeroCharDevice = ZeroCharDevice;

/// Register built-in character devices (null, zero, full, random,
/// urandom)
///
/// This must be called after the heap allocator is available.
pub fn register_builtin_chardevs() {
    // /dev/null = major 1 (MEM), minor 3 (Linux convention)
    let null_dev = Arc::new(NullCharDevice);
    let _ = register_chardev(DevId::new(major::MEM, 3), null_dev);

    // /dev/zero = major 1 (MEM), minor 5 (Linux convention)
    let zero_dev = Arc::new(ZeroCharDevice);
    let _ = register_chardev(DevId::new(major::MEM, 5), zero_dev);

    // /dev/full (1,7), /dev/random (1,8), /dev/urandom (1,9)
    let _ = register_chardev(DevId::new(major::MEM, 7), Arc::new(FullCharDevice));
    let random = Arc::new(RandomCharDevice("random"));
    let _ = register_chardev(DevId::new(major::MEM, 8), random);
    let urandom = Arc::new(RandomCharDevice("urandom"));
    let _ = register_chardev(DevId::new(major::MEM, 9), urandom);
    // /dev/kmsg (1,11)
    let kmsg = Arc::new(crate::kmsg::KmsgCharDevice);
    let _ = register_chardev(DevId::new(major::MEM, 11), kmsg);
}
