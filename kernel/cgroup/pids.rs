//! Pids controller - limits number of tasks in a cgroup
//!
//! The pids controller allows limiting the number of tasks (processes/threads)
//! that can exist in a cgroup hierarchy. This prevents fork bombs and provides
//! process isolation.
//!
//! # Control Files
//!
//! - `pids.max`: Read/write limit (or "max" for unlimited)
//! - `pids.current`: Read-only current task count
//! - `pids.events`: Read-only event counter ("max N")

use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::error::KernelError;
use crate::task::Pid;

use super::subsys::{CgroupSubsysOps, ControlFile, ControllerType, CssPrivate};
use super::CgroupSubsysState;

/// Sentinel value for unlimited pids
pub const PIDS_MAX_UNLIMITED: u64 = u64::MAX;

/// Per-cgroup pids state
pub struct PidsState {
    /// Maximum number of tasks (pids.max)
    /// u64::MAX means unlimited ("max" in interface)
    max: AtomicU64,

    /// Current task count (pids.current)
    current: AtomicU64,

    /// Number of times fork was denied due to limit (pids.events)
    events_max: AtomicU64,

    /// Parent pids state (for hierarchical limits)
    parent: Option<Arc<PidsState>>,
}

impl PidsState {
    /// Create a new pids state
    pub fn new(parent: Option<Arc<PidsState>>) -> Self {
        Self {
            max: AtomicU64::new(PIDS_MAX_UNLIMITED),
            current: AtomicU64::new(0),
            events_max: AtomicU64::new(0),
            parent,
        }
    }

    /// Check if we can add a task (walk hierarchy)
    pub fn can_charge(&self) -> bool {
        let current = self.current.load(Ordering::Relaxed);
        let max = self.max.load(Ordering::Relaxed);

        if max != PIDS_MAX_UNLIMITED && current >= max {
            return false;
        }

        // Check parent hierarchy
        if let Some(ref parent) = self.parent {
            return parent.can_charge();
        }

        true
    }

    /// Charge a new task (increment counter up the hierarchy)
    pub fn charge(&self) {
        self.current.fetch_add(1, Ordering::Relaxed);
        if let Some(ref parent) = self.parent {
            parent.charge();
        }
    }

    /// Uncharge a task (decrement counter up the hierarchy)
    pub fn uncharge(&self) {
        self.current.fetch_sub(1, Ordering::Relaxed);
        if let Some(ref parent) = self.parent {
            parent.uncharge();
        }
    }

    /// Record a max hit event
    pub fn record_max_event(&self) {
        self.events_max.fetch_add(1, Ordering::Relaxed);
        if let Some(ref parent) = self.parent {
            parent.record_max_event();
        }
    }

    /// Get current count
    pub fn current(&self) -> u64 {
        self.current.load(Ordering::Relaxed)
    }

    /// Get max limit
    pub fn max(&self) -> u64 {
        self.max.load(Ordering::Relaxed)
    }

    /// Set max limit
    pub fn set_max(&self, max: u64) {
        self.max.store(max, Ordering::Relaxed);
    }

    /// Get events count
    pub fn events_max_count(&self) -> u64 {
        self.events_max.load(Ordering::Relaxed)
    }
}

impl CssPrivate for PidsState {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }
}

/// Pids controller implementation
pub struct PidsController;

impl CgroupSubsysOps for PidsController {
    fn controller_type(&self) -> ControllerType {
        ControllerType::Pids
    }

    fn css_alloc(
        &self,
        parent_css: Option<&Arc<CgroupSubsysState>>,
    ) -> Result<Arc<dyn CssPrivate>, KernelError> {
        let parent_state = parent_css.and_then(|css| css.private_as::<PidsState>());
        Ok(Arc::new(PidsState::new(parent_state)))
    }

    fn css_free(&self, _css: &CgroupSubsysState) {
        // Nothing to clean up
    }

    fn attach(&self, css: &CgroupSubsysState, _pid: Pid) -> Result<(), KernelError> {
        if let Some(state) = css.private_as::<PidsState>() {
            state.charge();
        }
        Ok(())
    }

    fn detach(&self, css: &CgroupSubsysState, _pid: Pid) {
        if let Some(state) = css.private_as::<PidsState>() {
            state.uncharge();
        }
    }

    fn can_fork(&self, css: &CgroupSubsysState) -> Result<(), KernelError> {
        if let Some(state) = css.private_as::<PidsState>() {
            if state.can_charge() {
                return Ok(());
            }
            state.record_max_event();
            return Err(KernelError::WouldBlock); // EAGAIN
        }
        Ok(())
    }

    fn fork(&self, css: &CgroupSubsysState, _child_pid: Pid) -> Result<(), KernelError> {
        if let Some(state) = css.private_as::<PidsState>() {
            state.charge();
        }
        Ok(())
    }

    fn exit(&self, css: &CgroupSubsysState, _pid: Pid) {
        if let Some(state) = css.private_as::<PidsState>() {
            state.uncharge();
        }
    }

    fn control_files(&self) -> &'static [ControlFile] {
        &PIDS_FILES
    }
}

/// Static pids controller instance
pub static PIDS_CONTROLLER: PidsController = PidsController;

/// Control files for pids controller
static PIDS_FILES: [ControlFile; 3] = [
    ControlFile {
        name: "pids.max",
        mode: 0o644,
        read: Some(pids_max_read),
        write: Some(pids_max_write),
    },
    ControlFile {
        name: "pids.current",
        mode: 0o444,
        read: Some(pids_current_read),
        write: None,
    },
    ControlFile {
        name: "pids.events",
        mode: 0o444,
        read: Some(pids_events_read),
        write: None,
    },
];

/// Read pids.max
fn pids_max_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    if let Some(state) = css.private_as::<PidsState>() {
        let max = state.max();
        let content = if max == PIDS_MAX_UNLIMITED {
            format!("max\n")
        } else {
            format!("{}\n", max)
        };
        Ok(content.into_bytes())
    } else {
        Err(KernelError::Io)
    }
}

/// Write pids.max
fn pids_max_write(css: &CgroupSubsysState, data: &[u8]) -> Result<(), KernelError> {
    if let Some(state) = css.private_as::<PidsState>() {
        let s = core::str::from_utf8(data).map_err(|_| KernelError::InvalidArgument)?;
        let trimmed = s.trim();

        let max = if trimmed == "max" {
            PIDS_MAX_UNLIMITED
        } else {
            trimmed
                .parse()
                .map_err(|_| KernelError::InvalidArgument)?
        };

        state.set_max(max);
        Ok(())
    } else {
        Err(KernelError::Io)
    }
}

/// Read pids.current
fn pids_current_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    if let Some(state) = css.private_as::<PidsState>() {
        let content = format!("{}\n", state.current());
        Ok(content.into_bytes())
    } else {
        Err(KernelError::Io)
    }
}

/// Read pids.events
fn pids_events_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    if let Some(state) = css.private_as::<PidsState>() {
        let content = format!("max {}\n", state.events_max_count());
        Ok(content.into_bytes())
    } else {
        Err(KernelError::Io)
    }
}
