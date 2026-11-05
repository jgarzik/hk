//! Freezer controller - freeze/thaw task execution
//!
//! The freezer controller allows stopping and resuming execution of all tasks
//! in a cgroup. This is useful for checkpointing, debugging, and container
//! migration.
//!
//! # Control Files
//!
//! - `cgroup.freeze`: Write 1 to freeze, 0 to thaw
//! - `cgroup.events` (core): shows whether it is frozen

use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use crate::util::error::KernelError;

use super::CgroupSubsysState;
use super::subsys::{CgroupSubsysOps, ControlFile, ControllerType, CssPrivate};

/// Per-cgroup freezer state: none of its own. The one frozen flag is
/// the cgroup's (`Cgroup::frozen`, set by cgroup.freeze under
/// CGROUP_MUTEX); no task is stopped by it yet (BUGS "cgroup
/// controller application")
#[derive(Default)]
pub struct FreezerState;

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
        let _ = parent_css;
        Ok(Arc::new(FreezerState))
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

/// Control files for freezer controller (cgroup.events is the core
/// file, which reports the frozen state)
static FREEZER_FILES: [ControlFile; 1] = [ControlFile {
    name: "cgroup.freeze",
    mode: 0o644,
    read: Some(freeze_read),
    write: Some(freeze_write),
}];

/// Read cgroup.freeze: this cgroup's own setting (Linux
/// cgrp->freezer.freeze, ancestors aside)
fn freeze_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    let cgroup = css.cgroup().ok_or(KernelError::Io)?;
    Ok(format!("{}\n", cgroup.self_frozen() as u8).into_bytes())
}

/// Write cgroup.freeze ("0" or "1"); the cgroupfs write holds
/// CGROUP_MUTEX, as Linux cgroup_freeze_write under cgroup_mutex
fn freeze_write(css: &CgroupSubsysState, data: &[u8]) -> Result<(), KernelError> {
    let s = core::str::from_utf8(data).map_err(|_| KernelError::InvalidArgument)?;
    let freeze = match s.trim() {
        "0" => false,
        "1" => true,
        _ => return Err(KernelError::InvalidArgument),
    };
    css.cgroup().ok_or(KernelError::Io)?.set_frozen(freeze);
    Ok(())
}
