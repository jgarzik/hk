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

use crate::util::kalloc::try_arc;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use crate::util::error::KernelError;

use super::CgroupSubsysState;
use super::subsys::{CgroupSubsysOps, ControlFile, ControllerType, CssPrivate};

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
/// Linux min_bw_quota_period_us / max_bw_quota_period_us (1 ms, 1 s)
const CPU_PERIOD_MIN: u64 = 1_000;
const CPU_PERIOD_MAX: u64 = 1_000_000;
/// Linux max_bw_runtime_us (MAX_BW: 2^44 - 1 us)
const CPU_QUOTA_MAX: u64 = (1 << 44) - 1;

/// cpu.weight and cpu.max: what a write sets together and a read sees
/// together (Linux keeps quota and period under cfs_b->lock)
#[derive(Clone, Copy)]
struct CpuBw {
    /// Relative weight for fair scheduling (1-10000)
    weight: u64,
    /// Maximum microseconds per period (u64::MAX = "max")
    quota: u64,
    /// Period in microseconds
    period: u64,
}

/// Per-cgroup CPU state: the interface values under one lock, so a
/// cpu.max write never tears against a read (thread context only; no
/// bandwidth is enforced yet, see BUGS "cgroup controller application")
pub struct CpuState {
    bw: spin::Mutex<CpuBw>,
}

impl CpuState {
    /// Create a new CPU state
    pub fn new() -> Self {
        Self {
            bw: spin::Mutex::new(CpuBw {
                weight: CPU_WEIGHT_DEFAULT,
                quota: CPU_QUOTA_UNLIMITED,
                period: CPU_PERIOD_DEFAULT,
            }),
        }
    }

    /// Get weight
    pub fn weight(&self) -> u64 {
        self.bw.lock().weight
    }

    /// Set weight
    pub fn set_weight(&self, weight: u64) {
        self.bw.lock().weight = weight.clamp(CPU_WEIGHT_MIN, CPU_WEIGHT_MAX);
    }

    /// cpu.max: (quota, period), read together
    pub fn max(&self) -> (u64, u64) {
        let b = *self.bw.lock();
        (b.quota, b.period)
    }

    /// Set the bandwidth limit; `period` None keeps the current one.
    /// Linux tg_set_bandwidth's bounds, checked in the same hold as the
    /// store (the kept period is the one in it): a period from 1 ms to
    /// 1 s, a quota ("max" aside) from 1 ms to MAX_BW, else EINVAL
    pub fn set_max(&self, quota: u64, period: Option<u64>) -> Result<(), KernelError> {
        let mut b = self.bw.lock();
        let p = period.unwrap_or(b.period);
        if !(CPU_PERIOD_MIN..=CPU_PERIOD_MAX).contains(&p)
            || (quota != CPU_QUOTA_UNLIMITED && !(CPU_PERIOD_MIN..=CPU_QUOTA_MAX).contains(&quota))
        {
            return Err(KernelError::InvalidArgument);
        }
        b.quota = quota;
        b.period = p;
        Ok(())
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
        let _ = parent_css;
        Ok(try_arc(CpuState::new())?)
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
        let (quota, period) = state.max();
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

        let period = match period_str {
            Some(p) => Some(p.parse().map_err(|_| KernelError::InvalidArgument)?),
            None => None,
        };

        state.set_max(quota, period)
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
        let weight: u64 = s.trim().parse().map_err(|_| KernelError::InvalidArgument)?;

        if !(CPU_WEIGHT_MIN..=CPU_WEIGHT_MAX).contains(&weight) {
            return Err(KernelError::InvalidArgument);
        }

        state.set_weight(weight);
        Ok(())
    } else {
        Err(KernelError::Io)
    }
}

/// Read cpu.stat: no CPU time is charged to cgroups yet, so every
/// counter is 0
fn cpu_stat_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    if css.private_as::<CpuState>().is_none() {
        return Err(KernelError::Io);
    }
    Ok(b"usage_usec 0\n\
         user_usec 0\n\
         system_usec 0\n\
         nr_periods 0\n\
         nr_throttled 0\n\
         throttled_usec 0\n"
        .to_vec())
}
