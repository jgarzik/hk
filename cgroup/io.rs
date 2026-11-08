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

use crate::sync::spin::Mutex;
use crate::util::kalloc::try_arc;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use crate::util::error::KernelError;

use super::CgroupSubsysState;
use super::subsys::{CgroupSubsysOps, ControlFile, ControllerType, CssPrivate};

/// Device ID (major:minor encoded as u64)
pub type DevId = u64;

/// Encode major:minor into DevId
pub fn make_dev(major: u32, minor: u32) -> DevId {
    (u64::from(major) << 32) | u64::from(minor)
}

/// Decode DevId into major:minor
pub fn dev_major_minor(dev: DevId) -> (u32, u32) {
    ((dev >> 32) as u32, dev as u32)
}

/// One device's io.max limits (0 = unlimited)
#[derive(Clone, Copy, Default)]
pub struct IoMax {
    pub rbps: u64,
    pub wbps: u64,
    pub riops: u64,
    pub wiops: u64,
}

impl IoMax {
    fn has_limits(&self) -> bool {
        self.rbps | self.wbps | self.riops | self.wiops != 0
    }
}

/// Per-cgroup IO state: io.max per device, values under one lock, so a
/// write's limits land together (thread context only). No IO is
/// throttled or accounted yet (BUGS "cgroup controller application");
/// when it is, the token bucket lives under the queue's lock, as Linux
/// blk-throttle under queue_lock.
#[derive(Default)]
pub struct IoState {
    devices: Mutex<BTreeMap<DevId, IoMax>>,
}

impl IoState {
    /// The devices with limits, in device order
    pub fn limits(&self) -> Vec<(DevId, IoMax)> {
        self.devices
            .lock()
            .iter()
            .filter(|(_, m)| m.has_limits())
            .map(|(&d, &m)| (d, m))
            .collect()
    }

    /// Set limits for a device (None keeps a value), all in one hold
    pub fn set_limits(
        &self,
        dev: DevId,
        rbps: Option<u64>,
        wbps: Option<u64>,
        riops: Option<u64>,
        wiops: Option<u64>,
    ) {
        let mut devices = self.devices.lock();
        let m = devices.entry(dev).or_default();
        m.rbps = rbps.unwrap_or(m.rbps);
        m.wbps = wbps.unwrap_or(m.wbps);
        m.riops = riops.unwrap_or(m.riops);
        m.wiops = wiops.unwrap_or(m.wiops);
        if !m.has_limits() {
            devices.remove(&dev);
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
        let _ = parent_css;
        Ok(try_arc(IoState::default())?)
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

        for (dev, m) in state.limits() {
            let (major, minor) = dev_major_minor(dev);
            content.push_str(&format!("{}:{}", major, minor));
            if m.rbps > 0 {
                content.push_str(&format!(" rbps={}", m.rbps));
            }
            if m.wbps > 0 {
                content.push_str(&format!(" wbps={}", m.wbps));
            }
            if m.riops > 0 {
                content.push_str(&format!(" riops={}", m.riops));
            }
            if m.wiops > 0 {
                content.push_str(&format!(" wiops={}", m.wiops));
            }
            content.push('\n');
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

/// Read io.stat: a line per device with IO accounted (Linux); none is
/// accounted yet
fn io_stat_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    css.private_as::<IoState>().ok_or(KernelError::Io)?;
    Ok(Vec::new())
}
