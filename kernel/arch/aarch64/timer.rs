//! ARM Generic Timer Driver
//!
//! Implements the ARM Generic Timer for timekeeping and preemption.
//!
//! Relevant system registers:
//! - CNTFRQ_EL0: Counter frequency (read-only)
//! - CNTPCT_EL0: Physical counter value
//! - CNTP_CTL_EL0: Physical timer control
//! - CNTP_TVAL_EL0: Physical timer value (countdown)
//! - CNTP_CVAL_EL0: Physical timer compare value (absolute)

use crate::printkln;
use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

// CNTP_CTL_EL0 bits
const CNTP_CTL_ENABLE: u64 = 1 << 0;

/// Timer frequency in Hz (cached from CNTFRQ_EL0)
static TIMER_FREQ: AtomicU64 = AtomicU64::new(0);

/// Timer ticks per millisecond
static TICKS_PER_MS: AtomicU64 = AtomicU64::new(0);

/// Timer interval in milliseconds
static TIMER_INTERVAL_MS: AtomicU64 = AtomicU64::new(10);

/// Timer tick counter
static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);

/// Preemption callback (set by scheduler)
static mut TIMER_CALLBACK: Option<fn()> = None;

/// Read the counter frequency from CNTFRQ_EL0
#[inline]
pub fn read_frequency() -> u64 {
    let freq: u64;
    unsafe {
        asm!(
            "mrs {}, cntfrq_el0",
            out(reg) freq,
            options(nostack, nomem, preserves_flags)
        );
    }
    freq
}

/// Write CNTP_CTL_EL0
#[inline]
fn write_ctl(val: u64) {
    unsafe {
        asm!(
            "msr cntp_ctl_el0, {}",
            in(reg) val,
            options(nostack, nomem, preserves_flags)
        );
    }
}

/// Write CNTP_TVAL_EL0 (countdown timer value)
#[inline]
fn write_tval(val: u64) {
    unsafe {
        asm!(
            "msr cntp_tval_el0, {}",
            in(reg) val,
            options(nostack, nomem, preserves_flags)
        );
    }
}

/// Initialize the ARM Generic Timer
///
/// This sets up the timer frequency and enables the timer interrupt.
pub fn init() {
    // Read and cache the timer frequency
    let freq = read_frequency();
    TIMER_FREQ.store(freq, Ordering::Relaxed);

    // Calculate ticks per millisecond
    let ticks_per_ms = freq / 1000;
    TICKS_PER_MS.store(ticks_per_ms, Ordering::Relaxed);

    printkln!("Timer: frequency {} Hz ({} ticks/ms)", freq, ticks_per_ms);

    // Disable timer initially
    write_ctl(0);
}

/// Start the periodic timer with the specified interval
pub fn start(interval_ms: u32) {
    let ticks_per_ms = TICKS_PER_MS.load(Ordering::Relaxed);
    let tval = ticks_per_ms * interval_ms as u64;

    TIMER_INTERVAL_MS.store(interval_ms as u64, Ordering::Relaxed);

    // Set countdown value
    write_tval(tval);

    // Enable timer, unmask interrupt
    write_ctl(CNTP_CTL_ENABLE);

    // Enable the timer PPI in the GIC
    super::gic::enable_ppi(super::gic::TIMER_PPI);

    printkln!("Timer: started with {}ms interval", interval_ms);
}

/// Handle timer interrupt
///
/// Called from the IRQ handler when the timer fires.
pub fn handle_timer_irq() {
    // Increment tick counter
    let _ticks = TIMER_TICKS.fetch_add(1, Ordering::Relaxed) + 1;

    // Reload timer for next interval
    let ticks_per_ms = TICKS_PER_MS.load(Ordering::Relaxed);
    let interval = TIMER_INTERVAL_MS.load(Ordering::Relaxed);
    write_tval(ticks_per_ms * interval);

    // Update global timekeeper (only on CPU 0 to avoid contention)
    if super::percpu::try_current_cpu()
        .map(|p| p.cpu_id == 0)
        .unwrap_or(false)
    {
        crate::time::TIMEKEEPER.update(crate::time::TIMEKEEPER.get_read_cycles());
    }

    // Call scheduler timer tick to update tick counter
    crate::task::percpu::timer_tick();

    // Check for expired delayed work items (workqueue-based periodic tasks)
    crate::workqueue::timer_tick();

    // Wake any sleeping tasks whose wake time has arrived
    crate::task::percpu::wake_sleepers();

    // Call preemption callback if registered
    unsafe {
        if let Some(callback) = TIMER_CALLBACK {
            callback();
        }
    }
}
