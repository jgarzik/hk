//! ARM PL031 Real-Time Clock (RTC) driver
//!
//! The PL031 is a simple RTC that stores time as seconds since the Unix epoch.
//! On QEMU virt, it's located at 0x0901_0000.
//!
//! Register map:
//! - RTCDR (0x000): Data Register - read returns current time in seconds
//! - RTCMR (0x004): Match Register - for alarms (not used)
//! - RTCLR (0x008): Load Register - write to set time
//! - RTCCR (0x00C): Control Register - bit 0 enables the RTC
//! - RTCIMSC (0x010): Interrupt Mask Set/Clear
//! - RTCRIS (0x014): Raw Interrupt Status
//! - RTCMIS (0x018): Masked Interrupt Status
//! - RTCICR (0x01C): Interrupt Clear Register

use core::ptr;

/// PL031 base address on QEMU virt platform
const PL031_BASE: usize = 0x0901_0000;

/// Register offsets
const RTCDR: usize = 0x000; // Data Register (read-only current time)
const RTCLR: usize = 0x008; // Load Register (write to set time)
const RTCCR: usize = 0x00C; // Control Register

/// Read the current time from the PL031 RTC
///
/// Returns seconds since Unix epoch (1970-01-01 00:00:00 UTC)
pub fn read_rtc() -> i64 {
    // The PL031 data register directly contains Unix time in seconds
    let time = unsafe { ptr::read_volatile((PL031_BASE + RTCDR) as *const u32) };
    time as i64
}

/// Initialize the PL031 RTC
///
/// Ensures the RTC is enabled. The RTC should already be running from QEMU,
/// but we enable it explicitly to be safe.
pub fn init() {
    unsafe {
        // Read current control register
        let ctrl = ptr::read_volatile((PL031_BASE + RTCCR) as *const u32);
        // Enable RTC if not already enabled (bit 0)
        if ctrl & 1 == 0 {
            ptr::write_volatile((PL031_BASE + RTCCR) as *mut u32, ctrl | 1);
        }
    }
}

/// Set the RTC time (optional - typically set by firmware/hypervisor)
#[allow(dead_code)]
pub fn set_rtc(seconds_since_epoch: u32) {
    unsafe {
        ptr::write_volatile((PL031_BASE + RTCLR) as *mut u32, seconds_since_epoch);
    }
}
