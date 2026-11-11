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
use crate::util::rbtree::{RbTree, RbTreeNodeReservation};
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

/// Per-cgroup IO state: io.max per device (Linux the blkg's
/// throtl_grp), values under one lock, so a write's limits land
/// together (a spin leaf, thread context only; nothing allocates under
/// it). No IO is throttled or accounted yet (BUGS "cgroup controller
/// application"); when it is, the token bucket lives under the queue's
/// lock, as Linux blk-throttle under queue_lock.
pub struct IoState {
    /// The devices with limits, by device (an entry without limits is
    /// removed)
    devices: Mutex<RbTree<DevId, IoMax>>,
}

impl Default for IoState {
    fn default() -> Self {
        Self {
            devices: Mutex::new(RbTree::new()),
        }
    }
}

/// One io.max line's values (None keeps a value)
#[derive(Clone, Copy, Default)]
pub struct IoMaxSet {
    pub rbps: Option<u64>,
    pub wbps: Option<u64>,
    pub riops: Option<u64>,
    pub wiops: Option<u64>,
}

impl IoMax {
    fn apply(&mut self, s: IoMaxSet) {
        self.rbps = s.rbps.unwrap_or(self.rbps);
        self.wbps = s.wbps.unwrap_or(self.wbps);
        self.riops = s.riops.unwrap_or(self.riops);
        self.wiops = s.wiops.unwrap_or(self.wiops);
    }
}

impl IoState {
    /// The devices with limits, in device order: the copy is sized
    /// before the lock is taken, and made again if the map grew
    /// meanwhile; ENOMEM
    pub fn limits(&self) -> Result<Vec<(DevId, IoMax)>, KernelError> {
        let mut n = self.devices.lock().len();
        loop {
            let mut v = Vec::new();
            v.try_reserve_exact(n)
                .map_err(|_| KernelError::OutOfMemory)?;
            let devices = self.devices.lock();
            if devices.len() <= n {
                v.extend(devices.iter().map(|(&d, &m)| (d, m)));
                return Ok(v);
            }
            n = devices.len();
        }
    }

    /// Set limits for a device, all in one hold (Linux blkg_conf_prep,
    /// then tg_set_limit): a device with none yet needs a node, made
    /// with the lock dropped and the lookup repeated; the node of a
    /// device left without limits is freed after the unlock. ENOMEM.
    pub fn set_limits(&self, dev: DevId, set: IoMaxSet) -> Result<(), KernelError> {
        let mut spare = None;
        loop {
            let mut devices = self.devices.lock();
            if let Some(m) = devices.get_mut(&dev) {
                m.apply(set);
                let gone = if m.has_limits() {
                    None
                } else {
                    devices.remove_node(&dev)
                };
                drop(devices);
                drop(gone);
                return Ok(());
            }
            let mut m = IoMax::default();
            m.apply(set);
            if !m.has_limits() {
                return Ok(());
            }
            if let Some(node) = spare.take() {
                // Absent (looked up above): nothing is replaced
                let old = devices.insert(RbTreeNodeReservation::into_node(node, dev, m));
                drop(devices);
                drop(old);
                return Ok(());
            }
            drop(devices);
            spare = Some(RbTreeNodeReservation::new()?);
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

        for (dev, m) in state.limits()? {
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

            let mut set = IoMaxSet::default();
            for param in parts {
                if let Some(val) = param.strip_prefix("rbps=") {
                    set.rbps = Some(parse_io_value(val)?);
                } else if let Some(val) = param.strip_prefix("wbps=") {
                    set.wbps = Some(parse_io_value(val)?);
                } else if let Some(val) = param.strip_prefix("riops=") {
                    set.riops = Some(parse_io_value(val)?);
                } else if let Some(val) = param.strip_prefix("wiops=") {
                    set.wiops = Some(parse_io_value(val)?);
                }
            }

            state.set_limits(dev, set)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn set(rbps: Option<u64>, wiops: Option<u64>) -> IoMaxSet {
        IoMaxSet {
            rbps,
            wiops,
            ..IoMaxSet::default()
        }
    }

    /// A device appears with its first limit, keeps values a later line
    /// leaves out, and goes when all are "max"; listed in device order
    #[test]
    fn limits_merge_and_clear() {
        let st = IoState::default();
        st.set_limits(make_dev(8, 16), set(Some(100), None))
            .unwrap();
        st.set_limits(make_dev(8, 0), set(None, Some(5))).unwrap();
        st.set_limits(make_dev(8, 0), set(Some(7), None)).unwrap();
        let l = st.limits().unwrap();
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].0, make_dev(8, 0));
        assert_eq!((l[0].1.rbps, l[0].1.wiops), (7, 5));
        st.set_limits(make_dev(8, 0), set(Some(0), Some(0)))
            .unwrap();
        st.set_limits(make_dev(9, 0), set(Some(0), None)).unwrap();
        let l = st.limits().unwrap();
        assert_eq!(l.len(), 1);
        assert_eq!((l[0].0, l[0].1.rbps), (make_dev(8, 16), 100));
    }
}
