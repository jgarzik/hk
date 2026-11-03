//! Memory controller - memory usage limits and accounting
//!
//! The memory controller provides:
//! - Hard limit via memory.max
//! - Usage tracking via memory.current
//! - Detailed statistics via memory.stat
//!
//! # Control Files
//!
//! - `memory.max`: Hard limit in bytes (or "max" for unlimited)
//! - `memory.current`: Current usage in bytes
//! - `memory.stat`: Detailed breakdown (anon, file, kernel)
//! - `memory.events`: OOM and limit events

use alloc::format;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::error::KernelError;
use crate::task::Pid;

use super::CgroupSubsysState;
use super::subsys::{CgroupSubsysOps, ControlFile, ControllerType, CssPrivate};

/// Unlimited memory
pub const MEMORY_MAX_UNLIMITED: u64 = u64::MAX;

/// Memory type for charging
#[derive(Clone, Copy, Debug)]
pub enum MemType {
    /// Anonymous memory (heap, stack)
    Anon,
    /// File-backed memory (page cache)
    File,
    /// Kernel memory (slab, stack)
    Kernel,
    /// Shared memory
    Shmem,
}

/// Per-cgroup memory state
pub struct MemoryState {
    /// memory.max: hard limit in bytes (u64::MAX = "max")
    max: AtomicU64,

    /// memory.current: current usage in bytes
    current: AtomicU64,

    /// Detailed statistics
    anon: AtomicU64,
    file: AtomicU64,
    kernel: AtomicU64,
    shmem: AtomicU64,

    /// Events
    events_max: AtomicU64,
    events_oom: AtomicU64,
    events_oom_kill: AtomicU64,

    /// Parent for hierarchy
    parent: Option<Arc<MemoryState>>,
}

impl MemoryState {
    /// Create a new memory state
    pub fn new(parent: Option<Arc<MemoryState>>) -> Self {
        Self {
            max: AtomicU64::new(MEMORY_MAX_UNLIMITED),
            current: AtomicU64::new(0),
            anon: AtomicU64::new(0),
            file: AtomicU64::new(0),
            kernel: AtomicU64::new(0),
            shmem: AtomicU64::new(0),
            events_max: AtomicU64::new(0),
            events_oom: AtomicU64::new(0),
            events_oom_kill: AtomicU64::new(0),
            parent,
        }
    }

    /// Get max limit
    pub fn max(&self) -> u64 {
        self.max.load(Ordering::Relaxed)
    }

    /// Set max limit
    pub fn set_max(&self, max: u64) {
        self.max.store(max, Ordering::Relaxed);
    }

    /// Get current usage
    pub fn current(&self) -> u64 {
        self.current.load(Ordering::Relaxed)
    }

    /// Try to charge memory allocation
    ///
    /// Returns Ok(()) if charge succeeded, Err if over limit.
    pub fn try_charge(&self, bytes: u64, mem_type: MemType) -> Result<(), KernelError> {
        // Check against max (walk hierarchy)
        let max = self.max.load(Ordering::Relaxed);
        let current = self.current.load(Ordering::Relaxed);

        if max != MEMORY_MAX_UNLIMITED && current + bytes > max {
            self.events_max.fetch_add(1, Ordering::Relaxed);
            return Err(KernelError::OutOfMemory);
        }

        // Check parent hierarchy
        if let Some(ref parent) = self.parent {
            parent.try_charge(bytes, mem_type)?;
        }

        // Commit the charge
        self.current.fetch_add(bytes, Ordering::Relaxed);
        match mem_type {
            MemType::Anon => {
                self.anon.fetch_add(bytes, Ordering::Relaxed);
            }
            MemType::File => {
                self.file.fetch_add(bytes, Ordering::Relaxed);
            }
            MemType::Kernel => {
                self.kernel.fetch_add(bytes, Ordering::Relaxed);
            }
            MemType::Shmem => {
                self.shmem.fetch_add(bytes, Ordering::Relaxed);
            }
        }

        Ok(())
    }

    /// Uncharge memory on free
    pub fn uncharge(&self, bytes: u64, mem_type: MemType) {
        self.current.fetch_sub(bytes, Ordering::Relaxed);
        match mem_type {
            MemType::Anon => {
                self.anon.fetch_sub(bytes, Ordering::Relaxed);
            }
            MemType::File => {
                self.file.fetch_sub(bytes, Ordering::Relaxed);
            }
            MemType::Kernel => {
                self.kernel.fetch_sub(bytes, Ordering::Relaxed);
            }
            MemType::Shmem => {
                self.shmem.fetch_sub(bytes, Ordering::Relaxed);
            }
        }

        if let Some(ref parent) = self.parent {
            parent.uncharge(bytes, mem_type);
        }
    }

    /// Record OOM event
    pub fn record_oom(&self) {
        self.events_oom.fetch_add(1, Ordering::Relaxed);
    }

    /// Record OOM kill
    pub fn record_oom_kill(&self) {
        self.events_oom_kill.fetch_add(1, Ordering::Relaxed);
    }

    /// Get stats
    pub fn anon(&self) -> u64 {
        self.anon.load(Ordering::Relaxed)
    }

    pub fn file(&self) -> u64 {
        self.file.load(Ordering::Relaxed)
    }

    pub fn kernel(&self) -> u64 {
        self.kernel.load(Ordering::Relaxed)
    }

    pub fn shmem(&self) -> u64 {
        self.shmem.load(Ordering::Relaxed)
    }

    pub fn events_max_count(&self) -> u64 {
        self.events_max.load(Ordering::Relaxed)
    }

    pub fn events_oom_count(&self) -> u64 {
        self.events_oom.load(Ordering::Relaxed)
    }

    pub fn events_oom_kill_count(&self) -> u64 {
        self.events_oom_kill.load(Ordering::Relaxed)
    }
}

impl CssPrivate for MemoryState {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }
}

/// Memory controller implementation
pub struct MemoryController;

impl CgroupSubsysOps for MemoryController {
    fn controller_type(&self) -> ControllerType {
        ControllerType::Memory
    }

    fn css_alloc(
        &self,
        parent_css: Option<&Arc<CgroupSubsysState>>,
    ) -> Result<Arc<dyn CssPrivate>, KernelError> {
        let parent_state = parent_css.and_then(|css| css.private_as::<MemoryState>());
        Ok(Arc::new(MemoryState::new(parent_state)))
    }

    fn css_free(&self, _css: &CgroupSubsysState) {
        // Nothing to clean up
    }

    fn control_files(&self) -> &'static [ControlFile] {
        &MEMORY_FILES
    }
}

/// Static memory controller instance
pub static MEMORY_CONTROLLER: MemoryController = MemoryController;

/// Control files for memory controller
static MEMORY_FILES: [ControlFile; 4] = [
    ControlFile {
        name: "memory.max",
        mode: 0o644,
        read: Some(memory_max_read),
        write: Some(memory_max_write),
    },
    ControlFile {
        name: "memory.current",
        mode: 0o444,
        read: Some(memory_current_read),
        write: None,
    },
    ControlFile {
        name: "memory.stat",
        mode: 0o444,
        read: Some(memory_stat_read),
        write: None,
    },
    ControlFile {
        name: "memory.events",
        mode: 0o444,
        read: Some(memory_events_read),
        write: None,
    },
];

/// Read memory.max
fn memory_max_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    if let Some(state) = css.private_as::<MemoryState>() {
        let max = state.max();
        let content = if max == MEMORY_MAX_UNLIMITED {
            "max\n".to_string()
        } else {
            format!("{}\n", max)
        };
        Ok(content.into_bytes())
    } else {
        Err(KernelError::Io)
    }
}

/// Write memory.max
fn memory_max_write(css: &CgroupSubsysState, data: &[u8]) -> Result<(), KernelError> {
    if let Some(state) = css.private_as::<MemoryState>() {
        let s = core::str::from_utf8(data).map_err(|_| KernelError::InvalidArgument)?;
        let trimmed = s.trim();

        let max = if trimmed == "max" {
            MEMORY_MAX_UNLIMITED
        } else {
            // Support K, M, G suffixes
            parse_memory_size(trimmed)?
        };

        state.set_max(max);
        Ok(())
    } else {
        Err(KernelError::Io)
    }
}

/// Parse memory size with optional K/M/G suffix
fn parse_memory_size(s: &str) -> Result<u64, KernelError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(KernelError::InvalidArgument);
    }

    let (num_str, multiplier) = if s.ends_with('K') || s.ends_with('k') {
        (&s[..s.len() - 1], 1024u64)
    } else if s.ends_with('M') || s.ends_with('m') {
        (&s[..s.len() - 1], 1024 * 1024)
    } else if s.ends_with('G') || s.ends_with('g') {
        (&s[..s.len() - 1], 1024 * 1024 * 1024)
    } else {
        (s, 1)
    };

    let value: u64 = num_str.parse().map_err(|_| KernelError::InvalidArgument)?;

    value
        .checked_mul(multiplier)
        .ok_or(KernelError::InvalidArgument)
}

/// Read memory.current
fn memory_current_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    if let Some(state) = css.private_as::<MemoryState>() {
        let content = format!("{}\n", state.current());
        Ok(content.into_bytes())
    } else {
        Err(KernelError::Io)
    }
}

/// Read memory.stat
fn memory_stat_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    if let Some(state) = css.private_as::<MemoryState>() {
        let content = format!(
            "anon {}\n\
             file {}\n\
             kernel {}\n\
             shmem {}\n",
            state.anon(),
            state.file(),
            state.kernel(),
            state.shmem(),
        );
        Ok(content.into_bytes())
    } else {
        Err(KernelError::Io)
    }
}

/// Read memory.events
fn memory_events_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    if let Some(state) = css.private_as::<MemoryState>() {
        let content = format!(
            "max {}\n\
             oom {}\n\
             oom_kill {}\n",
            state.events_max_count(),
            state.events_oom_count(),
            state.events_oom_kill_count(),
        );
        Ok(content.into_bytes())
    } else {
        Err(KernelError::Io)
    }
}

/// Try to charge memory for a task's cgroup
pub fn try_charge_memory(pid: Pid, bytes: u64, mem_type: MemType) -> Result<(), KernelError> {
    if let Some(cgroup) = super::get_task_cgroup(pid)
        && let Some(css) = cgroup.css(ControllerType::Memory)
        && let Some(state) = css.private_as::<MemoryState>()
    {
        return state.try_charge(bytes, mem_type);
    }
    Ok(())
}

/// Uncharge memory for a task's cgroup
pub fn uncharge_memory(pid: Pid, bytes: u64, mem_type: MemType) {
    if let Some(cgroup) = super::get_task_cgroup(pid)
        && let Some(css) = cgroup.css(ControllerType::Memory)
        && let Some(state) = css.private_as::<MemoryState>()
    {
        state.uncharge(bytes, mem_type);
    }
}
