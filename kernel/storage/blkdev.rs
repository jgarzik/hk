//! Block Device Framework
//!
//! Block device abstraction following Linux conventions with:
//! - Bio-based I/O requests
//! - RequestQueue with pluggable schedulers
//! - BlockDeviceRegistry for major/minor mapping
//!
//! ## Architecture
//!
//! ```text
//! VFS → BlockFileOps → Page Cache → Bio → RequestQueue → BlockDriver
//! ```
//!
//! Block devices are page-cache-fronted. For RAM disk, the page cache
//! pages ARE the storage (zero-copy design).

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use spin::{Mutex, RwLock};

// Re-use DevId from chardev
pub use crate::chardev::{DevId, DevMajor, DevMinor};

/// Well-known block device major numbers (Linux compatible)
pub mod major {
    use super::DevMajor;

    /// RAM disk devices (rd0, rd1, ...)
    pub const RAMDISK: DevMajor = 1;
    /// SCSI/SATA disks (future)
    pub const SCSI_DISK: DevMajor = 8;
    /// NVMe disks (future)
    pub const NVME: DevMajor = 259;
}

/// Block I/O operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BioOp {
    /// Read data from device
    Read,
    /// Write data to device
    Write,
    /// Flush volatile cache to stable storage
    Flush,
}

/// Block I/O flags
#[derive(Debug, Clone, Copy, Default)]
pub struct BioFlags {
    /// Force unit access - write is durable on completion
    pub fua: bool,
    /// Synchronous I/O - caller wants ordering guarantee
    pub sync: bool,
}

/// A single segment in a bio (scatter/gather)
///
/// Each segment references a contiguous region within a physical frame.
pub struct BioSeg {
    /// Physical frame address
    pub frame: u64,
    /// Offset within the frame
    pub offset: usize,
    /// Length of this segment in bytes
    pub len: usize,
}

/// Block device error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockError {
    /// I/O error during read/write
    IoError,
    /// Request out of range
    OutOfRange,
    /// Device not ready
    NotReady,
    /// Invalid argument
    InvalidArg,
    /// Device not found
    NotFound,
    /// Operation not supported
    NotSupported,
    /// Device already registered
    AlreadyExists,
}

/// Bio completion callback type
pub type BioComplete = Box<dyn FnOnce(Result<(), BlockError>) + Send + 'static>;

/// Block I/O request
///
/// Represents a single contiguous logical range with scatter/gather memory.
/// This is the core I/O abstraction passed through the block layer.
pub struct Bio {
    /// Operation type
    pub op: BioOp,
    /// Starting logical block address (in 512-byte sectors)
    pub lba: u64,
    /// Number of 512-byte sectors
    pub len_sectors: u32,
    /// Memory segments for data (scatter/gather)
    pub segs: Vec<BioSeg>,
    /// I/O flags
    pub flags: BioFlags,
    /// Completion callback (called when I/O finishes)
    pub complete: Option<BioComplete>,
}

impl Bio {
    /// Create a new read bio
    pub fn new_read(lba: u64, len_sectors: u32, segs: Vec<BioSeg>) -> Self {
        Self {
            op: BioOp::Read,
            lba,
            len_sectors,
            segs,
            flags: BioFlags::default(),
            complete: None,
        }
    }

    /// Create a new write bio
    pub fn new_write(lba: u64, len_sectors: u32, segs: Vec<BioSeg>) -> Self {
        Self {
            op: BioOp::Write,
            lba,
            len_sectors,
            segs,
            flags: BioFlags::default(),
            complete: None,
        }
    }

    /// Create a flush bio
    pub fn new_flush() -> Self {
        Self {
            op: BioOp::Flush,
            lba: 0,
            len_sectors: 0,
            segs: Vec::new(),
            flags: BioFlags::default(),
            complete: None,
        }
    }

    /// Set completion callback
    pub fn with_complete(mut self, complete: BioComplete) -> Self {
        self.complete = Some(complete);
        self
    }

    /// Set FUA flag
    pub fn with_fua(mut self) -> Self {
        self.flags.fua = true;
        self
    }

    /// Set sync flag
    pub fn with_sync(mut self) -> Self {
        self.flags.sync = true;
        self
    }

    /// Call the completion callback with the result
    pub fn complete(self, result: Result<(), BlockError>) {
        if let Some(complete) = self.complete {
            complete(result);
        }
    }

    /// Total bytes in this bio
    pub fn total_bytes(&self) -> usize {
        self.segs.iter().map(|s| s.len).sum()
    }
}

/// Queue limits and constraints
#[derive(Debug, Clone, Copy)]
pub struct QueueLimits {
    /// Maximum sectors per request
    pub max_sectors: u32,
    /// Maximum segments per request
    pub max_segments: u32,
    /// Logical block size (bytes, typically 512)
    pub logical_block_size: u32,
}

impl Default for QueueLimits {
    fn default() -> Self {
        Self {
            max_sectors: 256, // 128KB
            max_segments: 64,
            logical_block_size: 512,
        }
    }
}

/// I/O scheduler trait (pluggable elevator)
///
/// Schedulers determine the order in which bios are dispatched to drivers.
/// Note: Sync is not required since schedulers are always accessed through a Mutex.
pub trait IoScheduler: Send {
    /// Insert a bio into the scheduler
    fn insert(&mut self, bio: Bio);

    /// Dispatch the next bio for processing
    fn dispatch(&mut self) -> Option<Bio>;

    /// Check if scheduler has pending work
    fn has_pending(&self) -> bool;

    /// Scheduler name for debugging
    fn name(&self) -> &'static str;
}

/// Simple FIFO scheduler (MVP)
///
/// Dispatches bios in the order they were submitted.
pub struct FifoScheduler {
    queue: VecDeque<Bio>,
}

impl FifoScheduler {
    /// Create a new FIFO scheduler
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }
}

impl Default for FifoScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl IoScheduler for FifoScheduler {
    fn insert(&mut self, bio: Bio) {
        self.queue.push_back(bio);
    }

    fn dispatch(&mut self) -> Option<Bio> {
        self.queue.pop_front()
    }

    fn has_pending(&self) -> bool {
        !self.queue.is_empty()
    }

    fn name(&self) -> &'static str {
        "fifo"
    }
}

/// Block driver trait - implemented by device drivers
///
/// Drivers receive bios from the request queue and perform the actual I/O.
/// For RAM disk, this is a no-op since page cache IS the storage.
pub trait BlockDriver: Send + Sync {
    /// Process a bio request
    ///
    /// The driver is responsible for calling the bio's completion callback
    /// when the I/O completes (synchronously or asynchronously).
    fn submit(&self, disk: &Disk, bio: Bio);

    /// Get driver name
    fn name(&self) -> &str;

    /// Read a page from the device (for page cache miss)
    ///
    /// Called when page cache needs to populate a page.
    /// Default implementation zeros the page (sparse allocation).
    fn readpage(&self, _disk: &Disk, buf: &mut [u8], _page_offset: u64) {
        // Default: zero the page (sparse read returns zeros)
        buf.fill(0);
    }

    /// Write a page to the device (for dirty page writeback)
    ///
    /// Called when page cache needs to flush a dirty page.
    /// Default implementation is a no-op (RAM disk doesn't need writeback).
    fn writepage(&self, _disk: &Disk, _buf: &[u8], _page_offset: u64) {
        // Default: no-op (RAM disk keeps data in page cache)
    }
}

/// Request queue for block device I/O
///
/// Manages bio submission, scheduling, and dispatch to drivers.
pub struct RequestQueue {
    /// Queue limits
    pub limits: QueueLimits,
    /// I/O scheduler (protected by mutex)
    sched: Mutex<Box<dyn IoScheduler>>,
    /// Number of in-flight requests
    in_flight: AtomicUsize,
    /// Queue stopped flag
    stopped: AtomicBool,
    /// Block driver handling this queue
    driver: Arc<dyn BlockDriver>,
    /// Back-reference to disk (for submit)
    disk: RwLock<Option<Arc<Disk>>>,
}

impl RequestQueue {
    /// Create a new request queue
    pub fn new(driver: Arc<dyn BlockDriver>, limits: QueueLimits) -> Self {
        Self {
            limits,
            sched: Mutex::new(Box::new(FifoScheduler::new())),
            in_flight: AtomicUsize::new(0),
            stopped: AtomicBool::new(false),
            driver,
            disk: RwLock::new(None),
        }
    }

    /// Set the disk back-reference
    pub fn set_disk(&self, disk: Arc<Disk>) {
        *self.disk.write() = Some(disk);
    }

    /// Get the driver
    pub fn driver(&self) -> &Arc<dyn BlockDriver> {
        &self.driver
    }

    /// Submit a bio to the queue
    pub fn submit_bio(&self, bio: Bio) -> Result<(), BlockError> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(BlockError::NotReady);
        }

        // Validate against limits
        if bio.len_sectors > self.limits.max_sectors {
            return Err(BlockError::InvalidArg);
        }
        if bio.segs.len() > self.limits.max_segments as usize {
            return Err(BlockError::InvalidArg);
        }

        // For MVP: synchronous processing
        // Insert into scheduler and immediately dispatch
        {
            let mut sched = self.sched.lock();
            sched.insert(bio);
        }

        self.process_queue();
        Ok(())
    }

    /// Process pending requests in the queue
    fn process_queue(&self) {
        loop {
            let bio = {
                let mut sched = self.sched.lock();
                sched.dispatch()
            };

            match bio {
                Some(b) => {
                    self.in_flight.fetch_add(1, Ordering::Relaxed);
                    let disk = self.disk.read().clone();
                    if let Some(d) = disk {
                        self.driver.submit(&d, b);
                    } else {
                        // No disk attached, complete with error
                        b.complete(Err(BlockError::NotReady));
                    }
                    self.in_flight.fetch_sub(1, Ordering::Relaxed);
                }
                None => break,
            }
        }
    }

    /// Stop the queue (for device removal)
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
    }

    /// Start the queue
    pub fn start(&self) {
        self.stopped.store(false, Ordering::Release);
    }

    /// Check if queue is stopped
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    /// Get number of in-flight requests
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }
}

/// Disk geometry and identity (like Linux gendisk)
///
/// Represents a physical or virtual disk with its properties.
pub struct Disk {
    /// Device ID (major/minor)
    pub id: DevId,
    /// Disk name (e.g., "rd0", "sda")
    pub name: String,
    /// Capacity in 512-byte sectors
    capacity_sectors: AtomicU64,
    /// Logical block size in bytes (typically 512)
    pub logical_block_size: u32,
    /// Request queue
    pub queue: Arc<RequestQueue>,
}

impl Disk {
    /// Create a new disk
    pub fn new(
        id: DevId,
        name: String,
        capacity_sectors: u64,
        logical_block_size: u32,
        queue: Arc<RequestQueue>,
    ) -> Arc<Self> {
        let disk = Arc::new(Self {
            id,
            name,
            capacity_sectors: AtomicU64::new(capacity_sectors),
            logical_block_size,
            queue: queue.clone(),
        });
        queue.set_disk(disk.clone());
        disk
    }

    /// Get capacity in 512-byte sectors
    pub fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors.load(Ordering::Relaxed)
    }

    /// Get capacity in bytes
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_sectors() * 512
    }

    /// Set capacity (for resizable devices)
    pub fn set_capacity_sectors(&self, sectors: u64) {
        self.capacity_sectors.store(sectors, Ordering::Relaxed);
    }

    /// Validate that an I/O range is within disk bounds
    pub fn validate_range(&self, lba: u64, sectors: u32) -> bool {
        let end = lba.saturating_add(sectors as u64);
        end <= self.capacity_sectors()
    }
}

/// Open block device handle (like Linux block_device/bdev)
///
/// Represents an open reference to a disk, tracking open count.
pub struct BlockDevice {
    /// The underlying disk
    pub disk: Arc<Disk>,
    /// Open count
    open_count: AtomicUsize,
    /// Device is dead (removed/disconnected) - all I/O will fail
    dead: AtomicBool,
}

impl BlockDevice {
    /// Create a new block device handle
    pub fn new(disk: Arc<Disk>) -> Self {
        Self {
            disk,
            open_count: AtomicUsize::new(0),
            dead: AtomicBool::new(false),
        }
    }

    /// Mark this device as dead (hotplug removal)
    ///
    /// Stops the request queue and marks the device as dead.
    /// All subsequent I/O operations will fail with NotReady.
    pub fn mark_dead(&self) {
        self.dead.store(true, Ordering::Release);
        self.disk.queue.stop();
    }

    /// Check if device is dead (removed/disconnected)
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }

    /// Open the block device (increment open count)
    pub fn open(&self) -> Result<(), BlockError> {
        self.open_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Close the block device (decrement open count)
    pub fn close(&self) {
        self.open_count.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get open count
    pub fn open_count(&self) -> usize {
        self.open_count.load(Ordering::Relaxed)
    }

    /// Get capacity in bytes
    pub fn capacity(&self) -> u64 {
        self.disk.capacity_bytes()
    }

    /// Get logical block size
    pub fn block_size(&self) -> u32 {
        self.disk.logical_block_size
    }

    /// Get device ID
    pub fn dev_id(&self) -> DevId {
        self.disk.id
    }

    /// Submit a bio to this block device
    pub fn submit_bio(&self, bio: Bio) -> Result<(), BlockError> {
        // Check if device is dead (hotplug removed)
        if self.is_dead() {
            return Err(BlockError::NotReady);
        }
        // Validate range for non-flush operations
        if bio.op != BioOp::Flush && !self.disk.validate_range(bio.lba, bio.len_sectors) {
            return Err(BlockError::OutOfRange);
        }
        self.disk.queue.submit_bio(bio)
    }
}

/// Global block device registry
///
/// Maps DevId to BlockDevice instances.
pub struct BlockDeviceRegistry {
    /// Registered block devices by DevId
    devices: BTreeMap<DevId, Arc<BlockDevice>>,
}

impl BlockDeviceRegistry {
    /// Create a new empty registry
    pub const fn new() -> Self {
        Self {
            devices: BTreeMap::new(),
        }
    }

    /// Register a block device
    pub fn register(&mut self, id: DevId, device: Arc<BlockDevice>) -> Result<(), BlockError> {
        if self.devices.contains_key(&id) {
            return Err(BlockError::AlreadyExists);
        }
        self.devices.insert(id, device);
        Ok(())
    }

    /// Unregister a block device
    pub fn unregister(&mut self, id: DevId) -> Option<Arc<BlockDevice>> {
        self.devices.remove(&id)
    }

    /// Look up a block device by ID
    pub fn get(&self, id: DevId) -> Option<Arc<BlockDevice>> {
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

    /// Iterate over all registered devices
    pub fn iter(&self) -> impl Iterator<Item = (&DevId, &Arc<BlockDevice>)> {
        self.devices.iter()
    }
}

impl Default for BlockDeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Global block device registry instance
pub static BLKDEV_REGISTRY: RwLock<BlockDeviceRegistry> = RwLock::new(BlockDeviceRegistry::new());

/// Register a block device globally
pub fn register_blkdev(id: DevId, device: Arc<BlockDevice>) -> Result<(), BlockError> {
    BLKDEV_REGISTRY.write().register(id, device)
}

/// Unregister a block device globally (hotplug removal)
///
/// Marks the device as dead and removes it from the registry.
/// The device may still exist if there are open references, but
/// all I/O operations will fail.
pub fn unregister_blkdev(id: DevId) -> Option<Arc<BlockDevice>> {
    let mut registry = BLKDEV_REGISTRY.write();
    if let Some(device) = registry.devices.get(&id) {
        // Mark device as dead before removing from registry
        device.mark_dead();
    }
    registry.unregister(id)
}

/// Look up a block device by ID
pub fn get_blkdev(id: DevId) -> Option<Arc<BlockDevice>> {
    BLKDEV_REGISTRY.read().get(id)
}

/// Sector size constant (512 bytes, Linux convention)
pub const SECTOR_SIZE: u64 = 512;

/// Bytes to sectors (rounded up)
pub fn bytes_to_sectors(bytes: u64) -> u64 {
    bytes.div_ceil(SECTOR_SIZE)
}

/// Sectors to bytes
pub fn sectors_to_bytes(sectors: u64) -> u64 {
    sectors * SECTOR_SIZE
}
