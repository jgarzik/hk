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

use crate::util::kalloc::try_arc;
use alloc::format;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::task::Pid;
use crate::util::error::KernelError;

use super::CgroupSubsysState;
use super::subsys::{CgroupSubsysOps, ControlFile, ControllerType, CssPrivate};

/// Sentinel value for unlimited pids
pub const PIDS_MAX_UNLIMITED: u64 = u64::MAX;

/// Per-cgroup pids state
pub struct PidsState {
    /// Maximum number of tasks (pids.max)
    /// u64::MAX means unlimited ("max" in interface)
    max: AtomicU64,

    /// Current task count (pids.current)
    current: AtomicU64,

    /// Forks refused by this level or a descendant's limit
    /// (pids.events "max", Linux events[PIDCG_MAX])
    events_max: AtomicU64,

    /// Forks refused by this level's own limit (pids.events.local
    /// "max", Linux events_local[PIDCG_MAX])
    events_local_max: AtomicU64,

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
            events_local_max: AtomicU64::new(0),
            parent,
        }
    }

    /// Charge a new task up to the root, which is never charged, or
    /// refuse it (Linux pids_try_charge): each level adds first and
    /// compares after, so concurrent forks cannot all pass a limit
    /// they share. A level over its max undoes the levels charged, from
    /// this one up to and including it (no list kept, as Linux), and is
    /// returned.
    pub fn try_charge(&self) -> Result<(), &PidsState> {
        let mut p = self;
        while let Some(parent) = p.parent.as_deref() {
            let new = p.current.fetch_add(1, Ordering::Relaxed) + 1;
            let max = p.max.load(Ordering::Relaxed);
            if max != PIDS_MAX_UNLIMITED && new > max {
                let mut q = self;
                loop {
                    q.current.fetch_sub(1, Ordering::Relaxed);
                    if core::ptr::eq(q, p) {
                        break;
                    }
                    q = q.parent.as_deref().unwrap_or(p);
                }
                return Err(p);
            }
            p = parent;
        }
        Ok(())
    }

    /// Charge a task without a limit check, up to the root (Linux
    /// pids_charge: a migration is always admitted)
    pub fn charge(&self) {
        let mut p = self;
        while let Some(parent) = p.parent.as_deref() {
            p.current.fetch_add(1, Ordering::Relaxed);
            p = parent;
        }
    }

    /// Uncharge a task up to the root (Linux pids_uncharge)
    pub fn uncharge(&self) {
        let mut p = self;
        while let Some(parent) = p.parent.as_deref() {
            p.current.fetch_sub(1, Ordering::Relaxed);
            p = parent;
        }
    }

    /// A fork was refused by this level's limit (Linux pids_event,
    /// default hierarchy without pids_localevents): counted locally
    /// here, and hierarchically here and in every ancestor but the root
    pub fn record_max_event(&self) {
        self.events_local_max.fetch_add(1, Ordering::Relaxed);
        let mut p = self;
        while let Some(parent) = p.parent.as_deref() {
            p.events_max.fetch_add(1, Ordering::Relaxed);
            p = parent;
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
        Ok(try_arc(PidsState::new(parent_state))?)
    }

    fn css_free(&self, _css: &CgroupSubsysState) {
        // Nothing to clean up
    }

    /// Linux pids_attach: the charge moves unconditionally (a migration
    /// may exceed pids.max)
    fn attach(&self, css: &CgroupSubsysState, _pid: Pid) {
        if let Some(state) = css.private_as::<PidsState>() {
            state.charge();
        }
    }

    fn detach(&self, css: &CgroupSubsysState, _pid: Pid) {
        if let Some(state) = css.private_as::<PidsState>() {
            state.uncharge();
        }
    }

    /// Linux pids_can_fork: try-charge the target, EAGAIN past a limit
    fn can_fork(&self, css: &CgroupSubsysState) -> Result<(), KernelError> {
        if let Some(state) = css.private_as::<PidsState>() {
            return state.try_charge().map_err(|over| {
                over.record_max_event();
                KernelError::WouldBlock // EAGAIN
            });
        }
        Ok(())
    }

    /// Linux pids_cancel_fork
    fn cancel_fork(&self, css: &CgroupSubsysState) {
        if let Some(state) = css.private_as::<PidsState>() {
            state.uncharge();
        }
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
static PIDS_FILES: [ControlFile; 4] = [
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
    ControlFile {
        name: "pids.events.local",
        mode: 0o444,
        read: Some(pids_events_local_read),
        write: None,
    },
];

/// Read pids.max
fn pids_max_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    if let Some(state) = css.private_as::<PidsState>() {
        let max = state.max();
        let content = if max == PIDS_MAX_UNLIMITED {
            "max\n".to_string()
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
            trimmed.parse().map_err(|_| KernelError::InvalidArgument)?
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

/// Read pids.events.local
fn pids_events_local_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    let state = css.private_as::<PidsState>().ok_or(KernelError::Io)?;
    let n = state.events_local_max.load(Ordering::Relaxed);
    Ok(format!("max {}\n", n).into_bytes())
}
