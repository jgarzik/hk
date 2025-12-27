//! Freezer controller - freeze/thaw task execution
//!
//! The freezer controller allows stopping and resuming execution of all tasks
//! in a cgroup. This is useful for checkpointing, debugging, and container
//! migration.
//!
//! # Control Files
//!
//! - `cgroup.freeze`: Write 1 to freeze, 0 to thaw
//! - `cgroup.events`: Shows frozen task count

use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::error::KernelError;
use crate::task::Pid;

use super::subsys::{CgroupSubsysOps, ControlFile, ControllerType, CssPrivate};
use super::CgroupSubsysState;

/// Per-cgroup freezer state
pub struct FreezerState {
    /// Whether this cgroup is frozen
    frozen: AtomicBool,

    /// Count of frozen tasks
    frozen_count: AtomicU64,

    /// Parent freezer state (inherits frozen state)
    parent: Option<Arc<FreezerState>>,
}

impl FreezerState {
    /// Create a new freezer state
    pub fn new(parent: Option<Arc<FreezerState>>) -> Self {
        Self {
            frozen: AtomicBool::new(false),
            frozen_count: AtomicU64::new(0),
            parent,
        }
    }

    /// Check if effectively frozen (self or any ancestor)
    pub fn is_frozen(&self) -> bool {
        if self.frozen.load(Ordering::Acquire) {
            return true;
        }
        if let Some(ref parent) = self.parent {
            return parent.is_frozen();
        }
        false
    }

    /// Get self-frozen state (not considering ancestors)
    pub fn self_frozen(&self) -> bool {
        self.frozen.load(Ordering::Acquire)
    }

    /// Set frozen state
    pub fn set_frozen(&self, freeze: bool) {
        self.frozen.store(freeze, Ordering::Release);
    }

    /// Increment frozen count
    pub fn inc_frozen(&self) {
        self.frozen_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement frozen count
    pub fn dec_frozen(&self) {
        self.frozen_count.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get frozen count
    pub fn frozen_count(&self) -> u64 {
        self.frozen_count.load(Ordering::Relaxed)
    }
}

impl CssPrivate for FreezerState {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }
}

/// Freezer controller implementation
pub struct FreezerController;

impl CgroupSubsysOps for FreezerController {
    fn controller_type(&self) -> ControllerType {
        ControllerType::Freezer
    }

    fn css_alloc(
        &self,
        parent_css: Option<&Arc<CgroupSubsysState>>,
    ) -> Result<Arc<dyn CssPrivate>, KernelError> {
        let parent_state = parent_css.and_then(|css| css.private_as::<FreezerState>());
        Ok(Arc::new(FreezerState::new(parent_state)))
    }

    fn css_free(&self, _css: &CgroupSubsysState) {
        // Nothing to clean up
    }

    fn control_files(&self) -> &'static [ControlFile] {
        &FREEZER_FILES
    }
}

/// Static freezer controller instance
pub static FREEZER_CONTROLLER: FreezerController = FreezerController;

/// Control files for freezer controller
static FREEZER_FILES: [ControlFile; 2] = [
    ControlFile {
        name: "cgroup.freeze",
        mode: 0o644,
        read: Some(freeze_read),
        write: Some(freeze_write),
    },
    ControlFile {
        name: "cgroup.events",
        mode: 0o444,
        read: Some(events_read),
        write: None,
    },
];

/// Read cgroup.freeze
fn freeze_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    if let Some(state) = css.private_as::<FreezerState>() {
        let val = if state.self_frozen() { 1 } else { 0 };
        let content = format!("{}\n", val);
        Ok(content.into_bytes())
    } else {
        Err(KernelError::Io)
    }
}

/// Write cgroup.freeze
fn freeze_write(css: &CgroupSubsysState, data: &[u8]) -> Result<(), KernelError> {
    if let Some(state) = css.private_as::<FreezerState>() {
        let s = core::str::from_utf8(data).map_err(|_| KernelError::InvalidArgument)?;
        let trimmed = s.trim();

        let freeze = match trimmed {
            "0" => false,
            "1" => true,
            _ => return Err(KernelError::InvalidArgument),
        };

        let was_frozen = state.self_frozen();
        state.set_frozen(freeze);

        // Also set the frozen flag on the cgroup itself
        if let Some(cgroup) = css.cgroup() {
            cgroup.set_frozen(freeze);

            // Update frozen count based on tasks in this cgroup
            if freeze && !was_frozen {
                let count = cgroup.nr_tasks() as u64;
                for _ in 0..count {
                    state.inc_frozen();
                }
            } else if !freeze && was_frozen {
                let count = state.frozen_count();
                for _ in 0..count {
                    state.dec_frozen();
                }
            }
        }

        Ok(())
    } else {
        Err(KernelError::Io)
    }
}

/// Read cgroup.events (freezer events)
fn events_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    if let Some(state) = css.private_as::<FreezerState>() {
        let content = format!("frozen {}\n", state.frozen_count());
        Ok(content.into_bytes())
    } else {
        Err(KernelError::Io)
    }
}

/// Check if a task should be frozen (called from scheduler)
pub fn task_frozen(pid: Pid) -> bool {
    if let Some(cgroup) = super::get_task_cgroup(pid) {
        return cgroup.is_frozen();
    }
    false
}
