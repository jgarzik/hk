//! CPU controller - CPU bandwidth limits and weights
//!
//! The CPU controller provides:
//! - Bandwidth limiting via cpu.max (quota/period)
//! - Weighted fair scheduling via cpu.weight
//! - Usage statistics via cpu.stat
//!
//! # Control Files
//!
//! - `cpu.max`: Bandwidth limit ("$QUOTA $PERIOD" in microseconds, or "max $PERIOD")
//! - `cpu.weight`: Relative weight 1-10000 (default 100)
//! - `cpu.stat`: Usage statistics

use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::error::KernelError;
use crate::task::Pid;

use super::subsys::{CgroupSubsysOps, ControlFile, ControllerType, CssPrivate};
use super::CgroupSubsysState;

/// Default CPU weight
pub const CPU_WEIGHT_DEFAULT: u64 = 100;
/// Minimum CPU weight
pub const CPU_WEIGHT_MIN: u64 = 1;
/// Maximum CPU weight
pub const CPU_WEIGHT_MAX: u64 = 10000;

/// Unlimited quota (no bandwidth limit)
pub const CPU_QUOTA_UNLIMITED: u64 = u64::MAX;
/// Default period (100ms in microseconds)
pub const CPU_PERIOD_DEFAULT: u64 = 100_000;

/// Per-cgroup CPU state
pub struct CpuState {
    /// cpu.weight: relative weight for fair scheduling (1-10000)
    weight: AtomicU64,

    /// cpu.max quota: maximum microseconds per period (u64::MAX = "max")
    quota: AtomicU64,

    /// cpu.max period: period in microseconds
    period: AtomicU64,

    /// cpu.stat: total CPU time used (microseconds)
    usage_usec: AtomicU64,

    /// cpu.stat: user mode time (microseconds)
    user_usec: AtomicU64,

    /// cpu.stat: system mode time (microseconds)
    system_usec: AtomicU64,

    /// cpu.stat: number of periods elapsed
    nr_periods: AtomicU64,

    /// cpu.stat: number of times throttled
    nr_throttled: AtomicU64,

    /// cpu.stat: time spent throttled (microseconds)
    throttled_usec: AtomicU64,

    /// Bandwidth tracking: timestamp when current period started
    period_start: AtomicU64,

    /// Bandwidth tracking: microseconds used in current period
    period_used: AtomicU64,

    /// Currently throttled?
    throttled: AtomicBool,

    /// Parent state for hierarchy
    parent: Option<Arc<CpuState>>,
}

impl CpuState {
    /// Create a new CPU state
    pub fn new(parent: Option<Arc<CpuState>>) -> Self {
        Self {
            weight: AtomicU64::new(CPU_WEIGHT_DEFAULT),
            quota: AtomicU64::new(CPU_QUOTA_UNLIMITED),
            period: AtomicU64::new(CPU_PERIOD_DEFAULT),
            usage_usec: AtomicU64::new(0),
            user_usec: AtomicU64::new(0),
            system_usec: AtomicU64::new(0),
            nr_periods: AtomicU64::new(0),
            nr_throttled: AtomicU64::new(0),
            throttled_usec: AtomicU64::new(0),
            period_start: AtomicU64::new(0),
            period_used: AtomicU64::new(0),
            throttled: AtomicBool::new(false),
            parent,
        }
    }

    /// Get weight
    pub fn weight(&self) -> u64 {
        self.weight.load(Ordering::Relaxed)
    }

    /// Set weight
    pub fn set_weight(&self, weight: u64) {
        let clamped = weight.clamp(CPU_WEIGHT_MIN, CPU_WEIGHT_MAX);
        self.weight.store(clamped, Ordering::Relaxed);
    }

    /// Get quota
    pub fn quota(&self) -> u64 {
        self.quota.load(Ordering::Relaxed)
    }

    /// Get period
    pub fn period(&self) -> u64 {
        self.period.load(Ordering::Relaxed)
    }

    /// Set bandwidth limit
    pub fn set_max(&self, quota: u64, period: u64) {
        self.quota.store(quota, Ordering::Relaxed);
        self.period.store(period, Ordering::Relaxed);
    }

    /// Check if throttled
    pub fn is_throttled(&self) -> bool {
        self.throttled.load(Ordering::Acquire)
    }

    /// Charge CPU usage and check for throttling
    ///
    /// Called from timer interrupt or context switch.
    /// Returns true if task should continue running, false if throttled.
    pub fn charge_usage(&self, usec: u64, is_user: bool) -> bool {
        // Update usage stats
        self.usage_usec.fetch_add(usec, Ordering::Relaxed);
        if is_user {
            self.user_usec.fetch_add(usec, Ordering::Relaxed);
        } else {
            self.system_usec.fetch_add(usec, Ordering::Relaxed);
        }

        // Bandwidth enforcement
        let quota = self.quota.load(Ordering::Relaxed);
        if quota != CPU_QUOTA_UNLIMITED {
            let used = self.period_used.fetch_add(usec, Ordering::Relaxed) + usec;
            if used >= quota && !self.throttled.load(Ordering::Acquire) {
                self.throttled.store(true, Ordering::Release);
                self.nr_throttled.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }

        // Propagate to parent
        if let Some(ref parent) = self.parent {
            return parent.charge_usage(usec, is_user);
        }

        !self.is_throttled()
    }

    /// Called on period boundary to refill bandwidth
    pub fn period_tick(&self, now_usec: u64) {
        let period = self.period.load(Ordering::Relaxed);
        let period_start = self.period_start.load(Ordering::Relaxed);

        if now_usec - period_start >= period {
            self.nr_periods.fetch_add(1, Ordering::Relaxed);
            self.period_start.store(now_usec, Ordering::Relaxed);

            // Track time spent throttled
            if self.throttled.load(Ordering::Acquire) {
                let throttled_time = now_usec - period_start - self.period_used.load(Ordering::Relaxed);
                self.throttled_usec.fetch_add(throttled_time, Ordering::Relaxed);
            }

            self.period_used.store(0, Ordering::Relaxed);
            self.throttled.store(false, Ordering::Release);
        }
    }

    /// Get usage statistics
    pub fn usage_usec(&self) -> u64 {
        self.usage_usec.load(Ordering::Relaxed)
    }

    pub fn user_usec(&self) -> u64 {
        self.user_usec.load(Ordering::Relaxed)
    }

    pub fn system_usec(&self) -> u64 {
        self.system_usec.load(Ordering::Relaxed)
    }

    pub fn nr_periods(&self) -> u64 {
        self.nr_periods.load(Ordering::Relaxed)
    }

    pub fn nr_throttled(&self) -> u64 {
        self.nr_throttled.load(Ordering::Relaxed)
    }

    pub fn throttled_usec(&self) -> u64 {
        self.throttled_usec.load(Ordering::Relaxed)
    }
}

impl CssPrivate for CpuState {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }
}

/// CPU controller implementation
pub struct CpuController;

impl CgroupSubsysOps for CpuController {
    fn controller_type(&self) -> ControllerType {
        ControllerType::Cpu
    }

    fn css_alloc(
        &self,
        parent_css: Option<&Arc<CgroupSubsysState>>,
    ) -> Result<Arc<dyn CssPrivate>, KernelError> {
        let parent_state = parent_css.and_then(|css| css.private_as::<CpuState>());
        Ok(Arc::new(CpuState::new(parent_state)))
    }

    fn css_free(&self, _css: &CgroupSubsysState) {
        // Nothing to clean up
    }

    fn control_files(&self) -> &'static [ControlFile] {
        &CPU_FILES
    }
}

/// Static CPU controller instance
pub static CPU_CONTROLLER: CpuController = CpuController;

/// Control files for CPU controller
static CPU_FILES: [ControlFile; 3] = [
    ControlFile {
        name: "cpu.max",
        mode: 0o644,
        read: Some(cpu_max_read),
        write: Some(cpu_max_write),
    },
    ControlFile {
        name: "cpu.weight",
        mode: 0o644,
        read: Some(cpu_weight_read),
        write: Some(cpu_weight_write),
    },
    ControlFile {
        name: "cpu.stat",
        mode: 0o444,
        read: Some(cpu_stat_read),
        write: None,
    },
];

/// Read cpu.max
fn cpu_max_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    if let Some(state) = css.private_as::<CpuState>() {
        let quota = state.quota();
        let period = state.period();
        let content = if quota == CPU_QUOTA_UNLIMITED {
            format!("max {}\n", period)
        } else {
            format!("{} {}\n", quota, period)
        };
        Ok(content.into_bytes())
    } else {
        Err(KernelError::Io)
    }
}

/// Write cpu.max
fn cpu_max_write(css: &CgroupSubsysState, data: &[u8]) -> Result<(), KernelError> {
    if let Some(state) = css.private_as::<CpuState>() {
        let s = core::str::from_utf8(data).map_err(|_| KernelError::InvalidArgument)?;
        let trimmed = s.trim();

        let mut parts = trimmed.split_whitespace();
        let quota_str = parts.next().ok_or(KernelError::InvalidArgument)?;
        let period_str = parts.next();

        let quota = if quota_str == "max" {
            CPU_QUOTA_UNLIMITED
        } else {
            quota_str
                .parse()
                .map_err(|_| KernelError::InvalidArgument)?
        };

        let period = if let Some(p) = period_str {
            p.parse().map_err(|_| KernelError::InvalidArgument)?
        } else {
            state.period()
        };

        state.set_max(quota, period);
        Ok(())
    } else {
        Err(KernelError::Io)
    }
}

/// Read cpu.weight
fn cpu_weight_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    if let Some(state) = css.private_as::<CpuState>() {
        let content = format!("{}\n", state.weight());
        Ok(content.into_bytes())
    } else {
        Err(KernelError::Io)
    }
}

/// Write cpu.weight
fn cpu_weight_write(css: &CgroupSubsysState, data: &[u8]) -> Result<(), KernelError> {
    if let Some(state) = css.private_as::<CpuState>() {
        let s = core::str::from_utf8(data).map_err(|_| KernelError::InvalidArgument)?;
        let weight: u64 = s
            .trim()
            .parse()
            .map_err(|_| KernelError::InvalidArgument)?;

        if weight < CPU_WEIGHT_MIN || weight > CPU_WEIGHT_MAX {
            return Err(KernelError::InvalidArgument);
        }

        state.set_weight(weight);
        Ok(())
    } else {
        Err(KernelError::Io)
    }
}

/// Read cpu.stat
fn cpu_stat_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    if let Some(state) = css.private_as::<CpuState>() {
        let content = format!(
            "usage_usec {}\n\
             user_usec {}\n\
             system_usec {}\n\
             nr_periods {}\n\
             nr_throttled {}\n\
             throttled_usec {}\n",
            state.usage_usec(),
            state.user_usec(),
            state.system_usec(),
            state.nr_periods(),
            state.nr_throttled(),
            state.throttled_usec(),
        );
        Ok(content.into_bytes())
    } else {
        Err(KernelError::Io)
    }
}

/// Check if a task is CPU throttled
pub fn task_cpu_throttled(pid: Pid) -> bool {
    if let Some(cgroup) = super::get_task_cgroup(pid) {
        if let Some(css) = cgroup.css(ControllerType::Cpu) {
            if let Some(state) = css.private_as::<CpuState>() {
                return state.is_throttled();
            }
        }
    }
    false
}

/// Charge CPU time for a task
pub fn charge_cpu_time(pid: Pid, usec: u64, is_user: bool) {
    if let Some(cgroup) = super::get_task_cgroup(pid) {
        if let Some(css) = cgroup.css(ControllerType::Cpu) {
            if let Some(state) = css.private_as::<CpuState>() {
                state.charge_usage(usec, is_user);
            }
        }
    }
}
