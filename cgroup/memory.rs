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

use crate::util::kalloc::try_arc;
use alloc::format;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::util::error::KernelError;

use super::CgroupSubsysState;
use super::subsys::{CgroupSubsysOps, ControlFile, ControllerType, CssPrivate};

/// Unlimited memory
pub const MEMORY_MAX_UNLIMITED: u64 = u64::MAX;

/// Per-cgroup memory state: memory.max, one word (Linux page_counter
/// max, read and written with READ_ONCE/WRITE_ONCE). Nothing is charged
/// to cgroups yet (BUGS "cgroup controller application"); when it is, it
/// is Linux page_counter_try_charge: add, check, roll back.
pub struct MemoryState {
    /// Hard limit in bytes (u64::MAX = "max")
    max: AtomicU64,
}

impl MemoryState {
    /// Create a new memory state
    pub fn new() -> Self {
        Self {
            max: AtomicU64::new(MEMORY_MAX_UNLIMITED),
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
        let _ = parent_css;
        Ok(try_arc(MemoryState::new())?)
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

/// Most pages a limit holds (Linux PAGE_COUNTER_MAX on 64-bit)
const PAGE_COUNTER_MAX: u64 = i64::MAX as u64 / 4096;

/// A size as Linux memparse: a base-0 number (0x hex, leading 0 octal)
/// and an optional K/M/G/T/P/E suffix; overflow saturates
fn memparse(s: &str) -> Option<u64> {
    let digits_end = |t: &str, radix: u32| t.find(|c: char| !c.is_digit(radix)).unwrap_or(t.len());
    let (radix, body) = if let Some(h) = s.strip_prefix("0x").or(s.strip_prefix("0X")) {
        (16, h)
    } else if s.len() > 1 && s.starts_with('0') {
        (8, &s[1..])
    } else {
        (10, s)
    };
    let n = digits_end(body, radix);
    if n == 0 && radix == 10 {
        return None;
    }
    let v = if n == 0 {
        0
    } else {
        u64::from_str_radix(&body[..n], radix).unwrap_or(u64::MAX)
    };
    let shl = match &body[n..] {
        "" => 0,
        "K" | "k" => 10,
        "M" | "m" => 20,
        "G" | "g" => 30,
        "T" | "t" => 40,
        "P" | "p" => 50,
        "E" | "e" => 60,
        _ => return None,
    };
    Some(
        v.checked_shl(shl)
            .filter(|r| r >> shl == v)
            .unwrap_or(u64::MAX),
    )
}

/// memory.max's limit in bytes (Linux page_counter_memparse): whole
/// pages, and the page counter's maximum is "max"
fn parse_memory_size(s: &str) -> Result<u64, KernelError> {
    let bytes = memparse(s.trim()).ok_or(KernelError::InvalidArgument)?;
    let pages = (bytes / 4096).min(PAGE_COUNTER_MAX);
    Ok(if pages == PAGE_COUNTER_MAX {
        MEMORY_MAX_UNLIMITED
    } else {
        pages * 4096
    })
}

/// Read memory.current (no usage is charged yet)
fn memory_current_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    css.private_as::<MemoryState>().ok_or(KernelError::Io)?;
    Ok(b"0\n".to_vec())
}

/// Read memory.stat (no usage is charged yet)
fn memory_stat_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    css.private_as::<MemoryState>().ok_or(KernelError::Io)?;
    Ok(b"anon 0\nfile 0\nkernel 0\nshmem 0\n".to_vec())
}

/// Read memory.events (no limit is enforced yet)
fn memory_events_read(css: &CgroupSubsysState) -> Result<Vec<u8>, KernelError> {
    css.private_as::<MemoryState>().ok_or(KernelError::Io)?;
    Ok(b"max 0\noom 0\noom_kill 0\n".to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memparse_sizes() {
        assert_eq!(memparse("4096"), Some(4096));
        assert_eq!(memparse("0x1000"), Some(4096));
        assert_eq!(memparse("010"), Some(8));
        assert_eq!(memparse("1k"), Some(1024));
        assert_eq!(memparse("2T"), Some(2 << 40));
        assert_eq!(memparse("3p"), Some(3 << 50));
        assert_eq!(memparse("1E"), Some(1 << 60));
        assert_eq!(memparse("99E"), Some(u64::MAX));
        assert_eq!(memparse(""), None);
        assert_eq!(memparse("-1"), None);
        assert_eq!(memparse("1X"), None);
        assert_eq!(memparse("1KB"), None);
        // Whole pages; the counter's maximum reads back as max
        assert_eq!(parse_memory_size("4097"), Ok(4096));
        assert_eq!(parse_memory_size("100"), Ok(0));
        assert_eq!(parse_memory_size("1E"), Ok(1 << 60));
        assert_eq!(parse_memory_size("10E"), Ok(MEMORY_MAX_UNLIMITED));
    }
}
