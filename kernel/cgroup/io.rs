//! IO controller - block I/O bandwidth limits and accounting
//!
//! The IO controller provides:
//! - Per-device bandwidth limits via io.max
//! - Per-device statistics via io.stat
//!
//! # Control Files
//!
//! - `io.max`: Per-device limits ("$MAJ:$MIN rbps=$N wbps=$N riops=$N wiops=$N")
//! - `io.stat`: Per-device I/O statistics

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

use crate::error::KernelError;
use crate::task::Pid;

use super::subsys::{CgroupSubsysOps, ControlFile, ControllerType, CssPrivate};
use super::CgroupSubsysState;

/// Device ID (major:minor encoded as u64)
pub type DevId = u64;

/// Encode major:minor into DevId
pub fn make_dev(major: u32, minor: u32) -> DevId {
    ((major as u64) << 32) | (minor as u64)
}

/// Decode DevId into major:minor
pub fn dev_major_minor(dev: DevId) -> (u32, u32) {
    ((dev >> 32) as u32, dev as u32)
}

/// Per-device IO limits and statistics
pub struct DeviceIoState {
    /// Read bytes per second limit (0 = unlimited)
    pub rbps: AtomicU64,
    /// Write bytes per second limit (0 = unlimited)
    pub wbps: AtomicU64,
    /// Read IOPS limit (0 = unlimited)
    pub riops: AtomicU64,
    /// Write IOPS limit (0 = unlimited)
    pub wiops: AtomicU64,

    /// Statistics: total bytes read
    pub rbytes: AtomicU64,
    /// Statistics: total bytes written
    pub wbytes: AtomicU64,
    /// Statistics: read IOs completed
    pub rios: AtomicU64,
    /// Statistics: write IOs completed
    pub wios: AtomicU64,

    /// Token bucket: available read bytes
    pub read_tokens: AtomicU64,
    /// Token bucket: available write bytes
    pub write_tokens: AtomicU64,
    /// Last refill timestamp (microseconds)
    pub last_refill: AtomicU64,
}

impl DeviceIoState {
    /// Create new device IO state
    pub fn new() -> Self {
        Self {
            rbps: AtomicU64::new(0),
            wbps: AtomicU64::new(0),
            riops: AtomicU64::new(0),
            wiops: AtomicU64::new(0),
            rbytes: AtomicU64::new(0),
            wbytes: AtomicU64::new(0),
            rios: AtomicU64::new(0),
            wios: AtomicU64::new(0),
            read_tokens: AtomicU64::new(0),
            write_tokens: AtomicU64::new(0),
            last_refill: AtomicU64::new(0),
        }
    }

    /// Check if any limits are set
    pub fn has_limits(&self) -> bool {
        self.rbps.load(Ordering::Relaxed) > 0
            || self.wbps.load(Ordering::Relaxed) > 0
            || self.riops.load(Ordering::Relaxed) > 0
            || self.wiops.load(Ordering::Relaxed) > 0
    }
}

impl Default for DeviceIoState {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-cgroup IO state
pub struct IoState {
    /// Per-device limits and stats
    devices: RwLock<BTreeMap<DevId, Arc<DeviceIoState>>>,

    /// Parent for hierarchy
    parent: Option<Arc<IoState>>,
}

impl IoState {
    /// Create a new IO state
    pub fn new(parent: Option<Arc<IoState>>) -> Self {
        Self {
            devices: RwLock::new(BTreeMap::new()),
            parent,
        }
    }

    /// Get or create device state
    pub fn get_device(&self, dev: DevId) -> Arc<DeviceIoState> {
        {
            let devices = self.devices.read();
            if let Some(state) = devices.get(&dev) {
                return state.clone();
            }
        }

        let mut devices = self.devices.write();
        devices
            .entry(dev)
            .or_insert_with(|| Arc::new(DeviceIoState::new()))
            .clone()
    }

    /// Get all devices
    pub fn devices(&self) -> Vec<(DevId, Arc<DeviceIoState>)> {
        self.devices
            .read()
            .iter()
            .map(|(&k, v)| (k, v.clone()))
            .collect()
    }

    /// Try to acquire bandwidth for an IO operation
    ///
    /// Returns true if allowed, false if should be throttled.
    pub fn try_acquire(&self, dev: DevId, bytes: u64, is_write: bool, now_usec: u64) -> bool {
        let device = self.get_device(dev);

        let bps_limit = if is_write {
            device.wbps.load(Ordering::Relaxed)
        } else {
            device.rbps.load(Ordering::Relaxed)
        };

        if bps_limit == 0 {
            // No limit, always allow
            return true;
        }

        // Refill tokens based on time elapsed
        let last = device.last_refill.load(Ordering::Relaxed);
        let elapsed_usec = now_usec.saturating_sub(last);
        if elapsed_usec > 0 {
            // Refill: tokens = bps * elapsed_sec
            let refill = (bps_limit * elapsed_usec) / 1_000_000;
            if is_write {
                device.write_tokens.fetch_add(refill, Ordering::Relaxed);
            } else {
                device.read_tokens.fetch_add(refill, Ordering::Relaxed);
            }
            device.last_refill.store(now_usec, Ordering::Relaxed);
        }

        // Try to consume tokens
        let tokens = if is_write {
            &device.write_tokens
        } else {
            &device.read_tokens
        };

        let available = tokens.load(Ordering::Relaxed);
        if available >= bytes {
            tokens.fetch_sub(bytes, Ordering::Relaxed);
            return true;
        }

        false
    }

    /// Record completed IO
    pub fn record_io(&self, dev: DevId, bytes: u64, is_write: bool) {
        let device = self.get_device(dev);
        if is_write {
            device.wbytes.fetch_add(bytes, Ordering::Relaxed);
            device.wios.fetch_add(1, Ordering::Relaxed);
        } else {
            device.rbytes.fetch_add(bytes, Ordering::Relaxed);
            device.rios.fetch_add(1, Ordering::Relaxed);
        }

        if let Some(ref parent) = self.parent {
            parent.record_io(dev, bytes, is_write);
        }
    }

    /// Set limits for a device
    pub fn set_limits(
        &self,
        dev: DevId,
        rbps: Option<u64>,
        wbps: Option<u64>,
        riops: Option<u64>,
        wiops: Option<u64>,
    ) {
        let device = self.get_device(dev);
        if let Some(v) = rbps {
            device.rbps.store(v, Ordering::Relaxed);
        }
        if let Some(v) = wbps {
            device.wbps.store(v, Ordering::Relaxed);
        }
        if let Some(v) = riops {
            device.riops.store(v, Ordering::Relaxed);
        }
        if let Some(v) = wiops {
            device.wiops.store(v, Ordering::Relaxed);
        }
    }
}

impl CssPrivate for IoState {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }
}

/// IO controller implementation
pub struct IoController;

impl CgroupSubsysOps for IoController {
    fn controller_type(&self) -> ControllerType {
        ControllerType::Io
    }

    fn css_alloc(
        &self,
        parent_css: Option<&Arc<CgroupSubsysState>>,
    ) -> Result<Arc<dyn CssPrivate>, KernelError> {
        let parent_state = parent_css.and_then(|css| css.private_as::<IoState>());
        Ok(Arc::new(IoState::new(parent_state)))
    }

    fn css_free(&self, _css: &CgroupSubsysState) {
        // Nothing to clean up
    }

    fn control_files(&self) -> &'static [ControlFile] {
        &IO_FILES
    }
}

/// Static IO controller instance
pub static IO_CONTROLLER: IoController = IoController;

/// Control files for IO controller
static IO_FILES: [ControlFile; 2] = [
    ControlFile {
        name: "io.max",
        mode: 0o644,
        read: Some(io_max_read),
        write: Some(io_max_write),
    },
    ControlFile {
        name: "io.stat",
        mode: 0o444,
        read: Some(io_stat_read),
        write: None,
    },
];

/// Read io.max
fn io_max_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    if let Some(state) = css.private_as::<IoState>() {
        let mut content = String::new();

        for (dev, device) in state.devices() {
            let (major, minor) = dev_major_minor(dev);
            if device.has_limits() {
                let rbps = device.rbps.load(Ordering::Relaxed);
                let wbps = device.wbps.load(Ordering::Relaxed);
                let riops = device.riops.load(Ordering::Relaxed);
                let wiops = device.wiops.load(Ordering::Relaxed);

                content.push_str(&format!("{}:{}", major, minor));
                if rbps > 0 {
                    content.push_str(&format!(" rbps={}", rbps));
                }
                if wbps > 0 {
                    content.push_str(&format!(" wbps={}", wbps));
                }
                if riops > 0 {
                    content.push_str(&format!(" riops={}", riops));
                }
                if wiops > 0 {
                    content.push_str(&format!(" wiops={}", wiops));
                }
                content.push('\n');
            }
        }

        Ok(content.into_bytes())
    } else {
        Err(KernelError::Io)
    }
}

/// Write io.max
/// Format: "MAJ:MIN rbps=N wbps=N riops=N wiops=N"
fn io_max_write(css: &CgroupSubsysState, data: &[u8]) -> Result<(), KernelError> {
    if let Some(state) = css.private_as::<IoState>() {
        let s = core::str::from_utf8(data).map_err(|_| KernelError::InvalidArgument)?;

        for line in s.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let mut parts = line.split_whitespace();
            let dev_str = parts.next().ok_or(KernelError::InvalidArgument)?;

            // Parse MAJ:MIN
            let mut dev_parts = dev_str.split(':');
            let major: u32 = dev_parts
                .next()
                .ok_or(KernelError::InvalidArgument)?
                .parse()
                .map_err(|_| KernelError::InvalidArgument)?;
            let minor: u32 = dev_parts
                .next()
                .ok_or(KernelError::InvalidArgument)?
                .parse()
                .map_err(|_| KernelError::InvalidArgument)?;

            let dev = make_dev(major, minor);

            let mut rbps = None;
            let mut wbps = None;
            let mut riops = None;
            let mut wiops = None;

            for param in parts {
                if let Some(val) = param.strip_prefix("rbps=") {
                    rbps = Some(parse_io_value(val)?);
                } else if let Some(val) = param.strip_prefix("wbps=") {
                    wbps = Some(parse_io_value(val)?);
                } else if let Some(val) = param.strip_prefix("riops=") {
                    riops = Some(parse_io_value(val)?);
                } else if let Some(val) = param.strip_prefix("wiops=") {
                    wiops = Some(parse_io_value(val)?);
                }
            }

            state.set_limits(dev, rbps, wbps, riops, wiops);
        }

        Ok(())
    } else {
        Err(KernelError::Io)
    }
}

/// Parse IO value (number or "max" for unlimited/0)
fn parse_io_value(s: &str) -> Result<u64, KernelError> {
    if s == "max" {
        Ok(0) // 0 means unlimited for IO limits
    } else {
        s.parse().map_err(|_| KernelError::InvalidArgument)
    }
}

/// Read io.stat
fn io_stat_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    if let Some(state) = css.private_as::<IoState>() {
        let mut content = String::new();

        for (dev, device) in state.devices() {
            let (major, minor) = dev_major_minor(dev);
            let rbytes = device.rbytes.load(Ordering::Relaxed);
            let wbytes = device.wbytes.load(Ordering::Relaxed);
            let rios = device.rios.load(Ordering::Relaxed);
            let wios = device.wios.load(Ordering::Relaxed);

            content.push_str(&format!(
                "{}:{} rbytes={} wbytes={} rios={} wios={}\n",
                major, minor, rbytes, wbytes, rios, wios
            ));
        }

        Ok(content.into_bytes())
    } else {
        Err(KernelError::Io)
    }
}

/// Try to acquire IO bandwidth for a task
pub fn try_acquire_io(pid: Pid, dev: DevId, bytes: u64, is_write: bool, now_usec: u64) -> bool {
    if let Some(cgroup) = super::get_task_cgroup(pid) {
        if let Some(css) = cgroup.css(ControllerType::Io) {
            if let Some(state) = css.private_as::<IoState>() {
                return state.try_acquire(dev, bytes, is_write, now_usec);
            }
        }
    }
    true // No limits if not in a cgroup
}

/// Record IO for a task
pub fn record_io(pid: Pid, dev: DevId, bytes: u64, is_write: bool) {
    if let Some(cgroup) = super::get_task_cgroup(pid) {
        if let Some(css) = cgroup.css(ControllerType::Io) {
            if let Some(state) = css.private_as::<IoState>() {
                state.record_io(dev, bytes, is_write);
            }
        }
    }
}
