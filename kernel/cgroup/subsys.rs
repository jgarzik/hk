//! Cgroup subsystem (controller) traits and types
//!
//! This module defines the interface that all cgroup controllers must implement.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use crate::error::KernelError;
use crate::task::Pid;

use super::CgroupSubsysState;

/// Controller type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ControllerType {
    Pids = 0,
    Freezer = 1,
    Cpu = 2,
    Memory = 3,
    Io = 4,
}

impl ControllerType {
    /// Get the controller name for cgroupfs
    pub fn name(&self) -> &'static str {
        match self {
            ControllerType::Pids => "pids",
            ControllerType::Freezer => "freezer",
            ControllerType::Cpu => "cpu",
            ControllerType::Memory => "memory",
            ControllerType::Io => "io",
        }
    }

    /// Parse controller name
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "pids" => Some(ControllerType::Pids),
            "freezer" => Some(ControllerType::Freezer),
            "cpu" => Some(ControllerType::Cpu),
            "memory" => Some(ControllerType::Memory),
            "io" => Some(ControllerType::Io),
            _ => None,
        }
    }

    /// Get all controller types
    pub fn all() -> &'static [ControllerType] {
        &[
            ControllerType::Pids,
            ControllerType::Freezer,
            ControllerType::Cpu,
            ControllerType::Memory,
            ControllerType::Io,
        ]
    }
}

/// Trait for controller-specific CSS private data
///
/// Each controller stores its per-cgroup state in a struct implementing this trait.
pub trait CssPrivate: Send + Sync + Any {
    /// Downcast to Any for type checking
    fn as_any(&self) -> &dyn Any;

    /// Downcast Arc to concrete type
    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync>;
}

/// Cgroup subsystem (controller) operations
///
/// Each resource controller implements this trait to provide its specific behavior.
pub trait CgroupSubsysOps: Send + Sync {
    /// Controller type
    fn controller_type(&self) -> ControllerType;

    /// Controller name (for cgroupfs)
    fn name(&self) -> &'static str {
        self.controller_type().name()
    }

    /// Allocate CSS private data for a new cgroup
    ///
    /// Called when a cgroup enables this controller.
    /// `parent_css` is the parent's CSS (None for root cgroup).
    fn css_alloc(
        &self,
        parent_css: Option<&Arc<CgroupSubsysState>>,
    ) -> Result<Arc<dyn CssPrivate>, KernelError>;

    /// Free CSS private data
    ///
    /// Called when controller is disabled or cgroup is removed.
    fn css_free(&self, css: &CgroupSubsysState);

    /// Check if a task can be attached to this cgroup
    ///
    /// Called before task migration. Return Err to reject.
    fn can_attach(&self, _css: &CgroupSubsysState, _pid: Pid) -> Result<(), KernelError> {
        Ok(())
    }

    /// Called when a task is attached to a cgroup
    fn attach(&self, _css: &CgroupSubsysState, _pid: Pid) -> Result<(), KernelError> {
        Ok(())
    }

    /// Called when a task is detached from a cgroup
    fn detach(&self, _css: &CgroupSubsysState, _pid: Pid) {}

    /// Check if a task can fork
    ///
    /// Returns Err(EAGAIN) if resource limit would be exceeded.
    fn can_fork(&self, _css: &CgroupSubsysState) -> Result<(), KernelError> {
        Ok(())
    }

    /// Called after successful fork
    fn fork(&self, _css: &CgroupSubsysState, _child_pid: Pid) -> Result<(), KernelError> {
        Ok(())
    }

    /// Called when a task exits
    fn exit(&self, _css: &CgroupSubsysState, _pid: Pid) {}

    /// Get control files exposed by this controller
    fn control_files(&self) -> &'static [ControlFile];
}

/// Control file descriptor for cgroupfs
///
/// Defines a readable/writable control file in the cgroup directory.
pub struct ControlFile {
    /// Filename (e.g., "pids.max", "cpu.weight")
    pub name: &'static str,

    /// File mode (typically 0o644 for writable, 0o444 for read-only)
    pub mode: u16,

    /// Read callback: generate file content
    pub read: Option<fn(&CgroupSubsysState) -> Result<Vec<u8>, KernelError>>,

    /// Write callback: handle file write
    pub write: Option<fn(&CgroupSubsysState, &[u8]) -> Result<(), KernelError>>,
}

impl ControlFile {
    /// Create a read-only control file
    pub const fn read_only(
        name: &'static str,
        read: fn(&CgroupSubsysState) -> Result<Vec<u8>, KernelError>,
    ) -> Self {
        Self {
            name,
            mode: 0o444,
            read: Some(read),
            write: None,
        }
    }

    /// Create a read-write control file
    pub const fn read_write(
        name: &'static str,
        read: fn(&CgroupSubsysState) -> Result<Vec<u8>, KernelError>,
        write: fn(&CgroupSubsysState, &[u8]) -> Result<(), KernelError>,
    ) -> Self {
        Self {
            name,
            mode: 0o644,
            read: Some(read),
            write: Some(write),
        }
    }

    /// Create a write-only control file
    pub const fn write_only(
        name: &'static str,
        write: fn(&CgroupSubsysState, &[u8]) -> Result<(), KernelError>,
    ) -> Self {
        Self {
            name,
            mode: 0o200,
            read: None,
            write: Some(write),
        }
    }
}

/// Cgroup subsystem definition
///
/// Static structure defining a controller's metadata.
pub struct CgroupSubsys {
    /// Controller type
    pub controller: ControllerType,

    /// Controller name
    pub name: &'static str,

    /// Controller operations
    pub ops: &'static dyn CgroupSubsysOps,
}
