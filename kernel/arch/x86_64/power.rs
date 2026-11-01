//! x86-64 power management via ACPI
//!
//! Power-off enters ACPI S5 through the FADT's fixed hardware
//! (`crate::acpi::hw`); reboot pulses the keyboard controller's reset
//! line. Works on real hardware and on QEMU.
//!
//! Locking: `POWER` is a `spin::Once`, set at boot before any caller
//! can power off and read-only after.

use core::arch::asm;

use super::io::{inb, inw, outb, outw};
use crate::acpi::aml::SleepType;
use crate::acpi::hw::{self, PmRegs, PortIo};
use crate::arch::PowerInfo;
use crate::delay::Monotonic;
use crate::printkln;

/// The FADT's registers and the S5 sleep type, once parsed
struct Power {
    pm: PmRegs,
    s5: SleepType,
}

static POWER: spin::Once<Power> = spin::Once::new();

/// The CPU's I/O ports
struct Ports;

impl PortIo for Ports {
    fn inb(&mut self, port: u16) -> u8 {
        inb(port)
    }
    fn outb(&mut self, port: u16, val: u8) {
        outb(port, val)
    }
    fn inw(&mut self, port: u16) -> u16 {
        inw(port)
    }
    fn outw(&mut self, port: u16, val: u16) {
        outw(port, val)
    }
}

/// Record the ACPI power management info (boot, after table parsing)
pub fn init(info: &PowerInfo) {
    POWER.call_once(|| Power {
        pm: info.pm,
        s5: info.s5,
    });
}

/// Put the fixed hardware in ACPI mode, then disable every fixed event
/// and GPE (Linux acpi_enable_subsystem): no SCI handler exists yet, so
/// IRQ 9 stays masked and nothing may raise an SCI
pub fn enable() {
    let Some(p) = POWER.get().filter(|p| p.pm.pm1a_cnt != 0) else {
        return;
    };
    if hw::acpi_mode(&mut Ports, &p.pm) {
        printkln!("ACPI: already in ACPI mode");
    } else if hw::acpi_enable(&mut Ports, &p.pm, &mut Monotonic::new()).is_ok() {
        printkln!("ACPI: enabled ACPI mode");
    } else {
        printkln!(
            "ACPI: timeout entering ACPI mode (SMI_CMD {:#x})",
            p.pm.smi_cmd
        );
        return;
    }
    hw::disable_events(&mut Ports, &p.pm);
}

/// Power off through ACPI S5 (Linux acpi_power_off ->
/// acpi_enter_sleep_state(ACPI_STATE_S5)); halts if the machine stays on
pub fn shutdown() -> ! {
    if let Some(p) = POWER.get().filter(|p| p.pm.pm1a_cnt != 0) {
        hw::enter_s5(&mut Ports, &p.pm, p.s5);
        // Linux acpi_hw_legacy_sleep: wait ten seconds for chipsets that
        // poll PM1 control slowly, then set SLP_EN again
        crate::delay::mdelay(10_000);
        printkln!("ACPI: still on 10 s after S5, retrying");
        hw::sleep_retry(&mut Ports, &p.pm, p.s5);
        crate::delay::mdelay(1000);
        printkln!("ACPI: power-off failed, halting");
    }
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
