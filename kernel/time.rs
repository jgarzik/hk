//! Kernel timekeeping
//!
//! Provides the core timekeeping infrastructure using TSC for high-precision
//! time measurements and a seqlock-protected timekeeper for safe concurrent access.
//!
//! # Architecture
//!
//! The timekeeper maintains:
//! - `mono_base_ns`: Monotonic time (never goes backward, starts at 0 at boot)
//! - `realtime_offset_ns`: Offset to convert monotonic to wall-clock time
//!
//! Time is read by:
//! 1. Reading current TSC cycles
//! 2. Computing delta from last update
//! 3. Converting cycles to nanoseconds using mult/shift
//! 4. Adding to base time
//!
//! The seqlock ensures readers get consistent snapshots without blocking.

use ::core::sync::atomic::{AtomicI32, AtomicI64, AtomicPtr, AtomicU32, AtomicU64, Ordering};

/// Filesystem timestamp (seconds + nanoseconds since Unix epoch)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timespec {
    /// Seconds since Unix epoch (1970-01-01 00:00:00 UTC)
    pub sec: i64,
    /// Nanoseconds (0-999999999)
    pub nsec: u32,
}

impl Timespec {
    /// Zero timestamp (Unix epoch)
    pub const ZERO: Self = Self { sec: 0, nsec: 0 };

    /// Create timestamp from seconds only
    pub const fn from_secs(sec: i64) -> Self {
        Self { sec, nsec: 0 }
    }

    /// Create timestamp from nanoseconds
    pub fn from_nanos(ns: i128) -> Self {
        let sec = (ns / 1_000_000_000) as i64;
        let nsec = (ns % 1_000_000_000) as u32;
        Self { sec, nsec }
    }

    /// Convert to total nanoseconds
    pub fn to_nanos(&self) -> i128 {
        self.sec as i128 * 1_000_000_000 + self.nsec as i128
    }
}

/// Clock identifiers (Linux-compatible)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockId {
    /// CLOCK_REALTIME - Wall clock time, can jump forward/backward
    Realtime,
    /// CLOCK_MONOTONIC - Never goes backward, unaffected by time adjustments
    Monotonic,
}

/// Placeholder function for uninitialized TSC reader
fn null_read_tsc() -> u64 {
    0
}

// ============================================================================
// NTP state for adjtimex syscall
// ============================================================================

/// NTP-related status flags (from Linux)
pub const STA_PLL: i32 = 0x0001;
pub const STA_PPSFREQ: i32 = 0x0002;
pub const STA_PPSTIME: i32 = 0x0004;
pub const STA_FLL: i32 = 0x0008;
pub const STA_INS: i32 = 0x0010;
pub const STA_DEL: i32 = 0x0020;
pub const STA_UNSYNC: i32 = 0x0040;
pub const STA_FREQHOLD: i32 = 0x0080;
pub const STA_NANO: i32 = 0x2000;

/// Extended timekeeper state for NTP/adjtimex support
pub struct NtpState {
    /// Maximum error (microseconds)
    pub maxerror: AtomicI64,
    /// Estimated error (microseconds)
    pub esterror: AtomicI64,
    /// Clock status flags (STA_*)
    pub status: AtomicI32,
    /// TAI offset (seconds)
    pub tai_offset: AtomicI32,
    /// PLL time constant
    pub constant: AtomicI64,
    /// Tick value (usec per tick, nominally 10000 for 100Hz)
    pub tick: AtomicI64,
}

impl NtpState {
    /// Create a new NtpState with default values
    pub const fn new() -> Self {
        Self {
            maxerror: AtomicI64::new(500_000),  // 0.5 sec default
            esterror: AtomicI64::new(500_000),  // 0.5 sec default
            status: AtomicI32::new(STA_UNSYNC), // Initially unsynchronized
            tai_offset: AtomicI32::new(0),
            constant: AtomicI64::new(2),
            tick: AtomicI64::new(10000), // 10ms in usec (100Hz)
        }
    }
}

/// Global NTP state
pub static NTP_STATE: NtpState = NtpState::new();

/// Global timekeeper with seqlock protection
///
/// Uses a seqlock pattern for lock-free reads:
/// - Writers increment seq to odd before updating, even after
/// - Readers check seq before and after reading; retry if odd or changed
pub struct TimeKeeper {
    /// Seqlock sequence counter (odd = write in progress)
    seq: AtomicU32,

    /// TSC cycle count at last update
    cycle_base: AtomicU64,

    /// Monotonic time base in nanoseconds (at cycle_base)
    mono_base_ns: AtomicU64,

    /// Realtime offset from monotonic in nanoseconds
    /// realtime = monotonic + offset
    realtime_offset_ns: AtomicI64,

    /// Cycles to nanoseconds multiplier
    /// ns = (cycles * mult) >> shift
    mult: AtomicU64,

    /// Cycles to nanoseconds shift
    shift: AtomicU32,

    /// TSC frequency in Hz (for reference)
    tsc_freq_hz: AtomicU64,

    /// Whether the timekeeper has been initialized
    initialized: AtomicU32,

    /// Stored function pointer for reading cycles (set during init)
    read_cycles_fn: AtomicPtr<()>,
}

impl Default for TimeKeeper {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeKeeper {
    /// Create a new uninitialized timekeeper
    pub const fn new() -> Self {
        Self {
            seq: AtomicU32::new(0),
            cycle_base: AtomicU64::new(0),
            mono_base_ns: AtomicU64::new(0),
            realtime_offset_ns: AtomicI64::new(0),
            mult: AtomicU64::new(0),
            shift: AtomicU32::new(0),
            tsc_freq_hz: AtomicU64::new(0),
            initialized: AtomicU32::new(0),
            read_cycles_fn: AtomicPtr::new(null_read_tsc as *mut ()),
        }
    }

    /// Get the stored read_cycles function
    ///
    /// This returns the function pointer that was passed to `init()`.
    /// Useful for code that needs to call `read()` but doesn't have
    /// direct access to architecture-specific modules.
    pub fn get_read_cycles(&self) -> fn() -> u64 {
        let ptr = self.read_cycles_fn.load(Ordering::Relaxed);
        unsafe { ::core::mem::transmute(ptr) }
    }

    /// Initialize the timekeeper with RTC time and TSC frequency
    ///
    /// # Arguments
    /// * `rtc_time_secs` - Wall-clock time from RTC (seconds since Unix epoch)
    /// * `tsc_freq_hz` - TSC frequency in Hz (from calibration)
    /// * `read_tsc` - Function to read the current TSC value
    pub fn init(&self, rtc_time_secs: i64, tsc_freq_hz: u64, read_tsc: fn() -> u64) {
        // Store the read_tsc function for later use
        self.read_cycles_fn
            .store(read_tsc as *mut (), Ordering::Relaxed);

        // Calculate mult/shift for cycles->ns conversion
        // We want: ns = cycles * 1_000_000_000 / freq
        // Using fixed-point: ns = (cycles * mult) >> shift
        // Choose shift=32 for good precision
        let shift = 32u32;
        let mult = ((1_000_000_000u128) << shift) / tsc_freq_hz as u128;

        let now_cycles = read_tsc();

        // Realtime offset = RTC time in nanoseconds
        // At init: monotonic = 0, realtime = rtc_time
        // So offset = rtc_time_ns - 0 = rtc_time_ns
        let realtime_offset = rtc_time_secs * 1_000_000_000;

        // Begin write sequence
        self.seq.fetch_add(1, Ordering::Release);

        self.cycle_base.store(now_cycles, Ordering::Relaxed);
        self.mono_base_ns.store(0, Ordering::Relaxed);
        self.realtime_offset_ns
            .store(realtime_offset, Ordering::Relaxed);
        self.mult.store(mult as u64, Ordering::Relaxed);
        self.shift.store(shift, Ordering::Relaxed);
        self.tsc_freq_hz.store(tsc_freq_hz, Ordering::Relaxed);
        self.initialized.store(1, Ordering::Relaxed);

        // End write sequence
        self.seq.fetch_add(1, Ordering::Release);
    }

    /// Check if the timekeeper has been initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Relaxed) != 0
    }

    /// Called from timer interrupt to update base values
    ///
    /// This keeps the cycle_base reasonably fresh so that delta calculations
    /// don't overflow for very long uptimes.
    pub fn update(&self, read_tsc: fn() -> u64) {
        if !self.is_initialized() {
            return;
        }

        // Begin write (make seq odd)
        self.seq.fetch_add(1, Ordering::Relaxed);
        ::core::sync::atomic::fence(Ordering::Release);

        let now_cycles = read_tsc();
        let cycle_base = self.cycle_base.load(Ordering::Relaxed);
        let mono_base = self.mono_base_ns.load(Ordering::Relaxed);
        let mult = self.mult.load(Ordering::Relaxed);
        let shift = self.shift.load(Ordering::Relaxed);

        let delta_cycles = now_cycles.wrapping_sub(cycle_base);
        let delta_ns = ((delta_cycles as u128 * mult as u128) >> shift) as u64;

        self.cycle_base.store(now_cycles, Ordering::Relaxed);
        self.mono_base_ns
            .store(mono_base.wrapping_add(delta_ns), Ordering::Relaxed);

        // End write (make seq even)
        ::core::sync::atomic::fence(Ordering::Release);
        self.seq.fetch_add(1, Ordering::Relaxed);
    }

    /// Read time for a given clock (seqlock reader)
    ///
    /// This is lock-free but may retry if a write is in progress.
    pub fn read(&self, clock_id: ClockId, read_tsc: fn() -> u64) -> Timespec {
        if !self.is_initialized() {
            return Timespec::ZERO;
        }

        loop {
            // Read sequence number
            let seq1 = self.seq.load(Ordering::Acquire);

            // If odd, writer is active - retry
            if seq1 & 1 != 0 {
                ::core::hint::spin_loop();
                continue;
            }

            // Read all values
            let cycle_base = self.cycle_base.load(Ordering::Relaxed);
            let mono_base = self.mono_base_ns.load(Ordering::Relaxed);
            let realtime_offset = self.realtime_offset_ns.load(Ordering::Relaxed);
            let mult = self.mult.load(Ordering::Relaxed);
            let shift = self.shift.load(Ordering::Relaxed);

            // Read current TSC
            let now_cycles = read_tsc();

            // Check sequence didn't change
            let seq2 = self.seq.load(Ordering::Acquire);
            if seq1 != seq2 {
                ::core::hint::spin_loop();
                continue;
            }

            // Calculate current time
            let delta_cycles = now_cycles.wrapping_sub(cycle_base);
            let delta_ns = ((delta_cycles as u128 * mult as u128) >> shift) as u64;
            let mono_ns = mono_base.wrapping_add(delta_ns);

            let ns = match clock_id {
                ClockId::Monotonic => mono_ns as i128,
                ClockId::Realtime => mono_ns as i128 + realtime_offset as i128,
            };

            return Timespec::from_nanos(ns);
        }
    }

    /// Get current wall-clock time using the stored read_cycles function
    ///
    /// This is a convenience method for code that doesn't have access to
    /// architecture-specific modules (like the filesystem layer).
    pub fn current_time(&self) -> Timespec {
        self.read(ClockId::Realtime, self.get_read_cycles())
    }

    /// Set the realtime clock to a new value
    ///
    /// This updates the realtime offset so that CLOCK_REALTIME returns the
    /// specified time. CLOCK_MONOTONIC is unaffected.
    ///
    /// # Arguments
    /// * `new_time` - The new wall-clock time to set
    ///
    /// # Returns
    /// `true` if successful, `false` if timekeeper is not initialized
    pub fn set_realtime(&self, new_time: Timespec) -> bool {
        if !self.is_initialized() {
            return false;
        }

        let read_tsc = self.get_read_cycles();

        // Begin write (make seq odd)
        self.seq.fetch_add(1, Ordering::Relaxed);
        ::core::sync::atomic::fence(Ordering::Release);

        // Read current monotonic time
        let now_cycles = read_tsc();
        let cycle_base = self.cycle_base.load(Ordering::Relaxed);
        let mono_base = self.mono_base_ns.load(Ordering::Relaxed);
        let mult = self.mult.load(Ordering::Relaxed);
        let shift = self.shift.load(Ordering::Relaxed);

        let delta_cycles = now_cycles.wrapping_sub(cycle_base);
        let delta_ns = ((delta_cycles as u128 * mult as u128) >> shift) as u64;
        let mono_ns = mono_base.wrapping_add(delta_ns);

        // Calculate new offset: realtime = monotonic + offset
        // So offset = realtime - monotonic
        let new_time_ns = new_time.to_nanos();
        let new_offset = new_time_ns - mono_ns as i128;

        // Store new offset
        self.realtime_offset_ns
            .store(new_offset as i64, Ordering::Relaxed);

        // End write (make seq even)
        ::core::sync::atomic::fence(Ordering::Release);
        self.seq.fetch_add(1, Ordering::Relaxed);

        true
    }
}

/// Global timekeeper instance
pub static TIMEKEEPER: TimeKeeper = TimeKeeper::new();

/// Get current monotonic time in milliseconds (simple tick count)
///
/// This provides a simple monotonic tick suitable for timeouts and
/// timestamp comparisons. Returns 0 if timekeeper is not initialized.
pub fn current_ticks() -> u64 {
    let ts = TIMEKEEPER.current_time();
    // Convert to milliseconds
    ts.sec as u64 * 1000 + ts.nsec as u64 / 1_000_000
}

/// Get current monotonic time in nanoseconds
///
/// Returns the current monotonic clock time since boot in nanoseconds.
/// Suitable for process start times and precise timing measurements.
pub fn monotonic_ns() -> u64 {
    let ts = TIMEKEEPER.read(ClockId::Monotonic, TIMEKEEPER.get_read_cycles());
    ts.sec as u64 * 1_000_000_000 + ts.nsec as u64
}
