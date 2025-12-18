//! x86-64 power management via ACPI
//!
//! Implements system shutdown and reboot using standard ACPI mechanisms.
//! This works on real x86-64 hardware as well as virtual machines (QEMU, etc.).

use core::arch::asm;
use core::sync::atomic::{AtomicU8, AtomicU16, Ordering};

use super::io::{inb, outb, outw};

/// ACPI SLP_EN bit - enables transition to sleep state
const SLP_EN: u16 = 1 << 13;

/// Power management registers from FADT
/// Using atomics for safe initialization from boot code
static PM1A_CNT_BLK: AtomicU16 = AtomicU16::new(0);
static PM1B_CNT_BLK: AtomicU16 = AtomicU16::new(0);
static SLP_TYPA: AtomicU8 = AtomicU8::new(0); // Default S5 sleep type (0 for QEMU)

/// Initialize power management with values from ACPI FADT
///
/// Called during boot after ACPI tables are parsed.
pub fn init(pm1a: u16, pm1b: Option<u16>, slp_typa: u8) {
    PM1A_CNT_BLK.store(pm1a, Ordering::SeqCst);
    PM1B_CNT_BLK.store(pm1b.unwrap_or(0), Ordering::SeqCst);
    SLP_TYPA.store(slp_typa, Ordering::SeqCst);
}

/// Shutdown the system using ACPI S5 (soft-off)
///
/// Writes to the PM1a (and optionally PM1b) control registers to trigger
/// the S5 sleep state, which powers off the system.
///
/// # Panics
/// This function never returns. If ACPI shutdown fails, it falls back to halt.
pub fn shutdown() -> ! {
    let pm1a = PM1A_CNT_BLK.load(Ordering::SeqCst);
    let pm1b = PM1B_CNT_BLK.load(Ordering::SeqCst);
    let slp_typ = SLP_TYPA.load(Ordering::SeqCst);

    if pm1a != 0 {
        // Build the value: SLP_TYPa in bits 10-12, SLP_EN in bit 13
        let val = ((slp_typ as u16) << 10) | SLP_EN;

        // Write to PM1a control block
        outw(pm1a, val);

        // Write to PM1b if present
        if pm1b != 0 {
            outw(pm1b, val);
        }
    }

    // If we get here, ACPI shutdown didn't work - fall back to halt
    halt()
}

/// Reboot the system
///
/// Uses the keyboard controller reset method (pulse CPU reset line).
/// This is the standard way to reboot x86 systems.
pub fn reboot() -> ! {
    // Wait for keyboard controller to be ready
    // Clear any pending data
    while (inb(0x64) & 0x02) != 0 {
        core::hint::spin_loop();
    }

    // Send reset command (0xFE) to keyboard controller command port
    outb(0x64, 0xFE);

    // If keyboard reset didn't work, fall back to halt
    halt()
}

/// Halt the system
///
/// Disables interrupts and enters an infinite halt loop.
/// The system will remain powered on but idle.
pub fn halt() -> ! {
    loop {
        unsafe {
            asm!("cli; hlt", options(nomem, nostack));
        }
    }
}
