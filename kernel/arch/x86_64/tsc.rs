//! TSC (Time Stamp Counter) clocksource
//!
//! The TSC is a 64-bit register present in all x86-64 processors that counts
//! CPU cycles. On modern processors with invariant TSC, it runs at a constant
//! rate regardless of CPU frequency changes, making it ideal for timekeeping.

use super::io;
use crate::printkln;

/// TSC clocksource implementation
pub struct TscClockSource {
    /// Calibrated TSC frequency in Hz
    frequency_hz: u64,
    /// Whether this TSC has invariant flag (reliable across power states)
    #[allow(dead_code)] // Used via TimekeeperOps trait (future API)
    invariant: bool,
}

impl TscClockSource {
    /// Detect TSC capabilities and calibrate frequency
    ///
    /// Always succeeds on x86-64 (TSC is mandatory). Logs a warning if
    /// invariant TSC is not available (may drift with CPU power states).
    pub fn new() -> Option<Self> {
        let invariant = has_invariant_tsc();

        if !invariant {
            printkln!("TSC: Warning - invariant TSC not detected, clock may drift");
        }

        // Calibrate TSC frequency against PIT
        let frequency_hz = calibrate_tsc_frequency();

        Some(Self {
            frequency_hz,
            invariant,
        })
    }

    /// Returns true if this TSC has the invariant flag
    #[allow(dead_code)] // Used via TimekeeperOps::clock_is_reliable
    pub fn is_invariant(&self) -> bool {
        self.invariant
    }

    /// Get the calibrated TSC frequency in Hz
    pub fn frequency_hz(&self) -> u64 {
        self.frequency_hz
    }

    /// Read the current TSC value
    #[inline]
    pub fn read_tsc() -> u64 {
        let low: u32;
        let high: u32;
        unsafe {
            ::core::arch::asm!(
                "rdtsc",
                out("eax") low,
                out("edx") high,
                options(nomem, nostack, preserves_flags)
            );
        }
        ((high as u64) << 32) | (low as u64)
    }
}

/// Check CPUID for invariant TSC (constant rate across power states)
///
/// Invariant TSC is indicated by CPUID leaf 0x80000007, EDX bit 8
fn has_invariant_tsc() -> bool {
    // First check if extended CPUID is supported
    let max_extended: u32;
    let ebx_out: u32;
    unsafe {
        ::core::arch::asm!(
            "push rbx",      // Save rbx (LLVM uses it)
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",       // Restore rbx
            inout("eax") 0x80000000u32 => max_extended,
            ebx_out = out(reg) ebx_out,
            out("ecx") _,
            out("edx") _,
            options(nomem, nostack, preserves_flags)
        );
    }
    let _ = ebx_out; // suppress unused warning

    if max_extended < 0x80000007 {
        return false;
    }

    // Check for invariant TSC
    let edx: u32;
    let ebx_out2: u32;
    unsafe {
        ::core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inout("eax") 0x80000007u32 => _,
            ebx_out = out(reg) ebx_out2,
            out("ecx") _,
            out("edx") edx,
            options(nomem, nostack, preserves_flags)
        );
    }
    let _ = ebx_out2;

    // Bit 8 = Invariant TSC
    edx & (1 << 8) != 0
}

/// Calibrate TSC frequency using PIT channel 2
///
/// Measures TSC ticks over a known PIT interval to determine frequency.
fn calibrate_tsc_frequency() -> u64 {
    const CALIBRATION_MS: u64 = 10;
    const PIT_FREQ: u64 = 1193182; // PIT frequency in Hz

    let pit_count = ((PIT_FREQ * CALIBRATION_MS) / 1000) as u16;

    // Set up PIT channel 2 for one-shot countdown
    // Enable speaker gate (bit 0) for PIT channel 2, disable speaker (bit 1)
    let gate = io::inb(0x61);
    io::outb(0x61, (gate & 0xFC) | 0x01);

    // Configure PIT channel 2: mode 0 (interrupt on terminal count)
    // 0xB0 = Channel 2 (bits 7-6), lobyte/hibyte (bits 5-4), mode 0 (bits 3-1), binary (bit 0)
    io::outb(0x43, 0xB0);

    // Load count (low byte first, then high byte)
    io::outb(0x42, (pit_count & 0xFF) as u8);
    io::outb(0x42, ((pit_count >> 8) & 0xFF) as u8);

    // Read starting TSC
    let tsc_start = TscClockSource::read_tsc();

    // Wait for PIT to count down (poll OUT pin via port 0x61 bit 5)
    while (io::inb(0x61) & 0x20) == 0 {
        core::hint::spin_loop();
    }

    // Read ending TSC
    let tsc_end = TscClockSource::read_tsc();

    // Restore speaker gate
    io::outb(0x61, gate);

    // Calculate frequency
    let tsc_elapsed = tsc_end - tsc_start;
    (tsc_elapsed * 1000) / CALIBRATION_MS
}

/// Global function to read TSC (for use when TscClockSource isn't available)
#[inline]
pub fn read_tsc() -> u64 {
    TscClockSource::read_tsc()
}
