//! x86-64 power management via ACPI
//!
//! Power-off enters ACPI S5 through the FADT's fixed hardware
//! (`crate::acpi::hw`); reboot tries the FADT reset register, the
//! keyboard controller and port 0xCF9. Works on real hardware and on
//! QEMU.
//!
//! Locking: `POWER` is a `spin::Once`, set at boot before any caller
//! can power off and read-only after.

use core::arch::asm;

use super::io::{inb, inw, outb, outw};
use super::ioremap::ioremap;
use crate::acpi::aml::SleepType;
use crate::acpi::hw::{self, PmRegs, PortIo, ResetReg, Space};
use crate::arch::PowerInfo;
use crate::delay::Monotonic;
use crate::printkln;

/// The FADT's registers, the S5 sleep type and the reset register,
/// once parsed
struct Power {
    pm: PmRegs,
    s5: SleepType,
    reset: Option<Reset>,
}

/// The FADT reset register, ready to write: a port, or a mapped
/// address (as usize, so `Power` is Sync), and the reset value
#[derive(Clone, Copy)]
enum Reset {
    Io(u16, u8),
    Mem(usize, u8),
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
        reset: info.reset.and_then(reset_map),
    });
}

/// Ready the reset register: memory space is mapped now, since reboot
/// may run where mapping is unwise
fn reset_map(r: ResetReg) -> Option<Reset> {
    match r.space {
        Space::Io => Some(Reset::Io(r.addr as u16, r.value)),
        Space::Mem => ioremap(r.addr, 1)
            .ok()
            .map(|virt| Reset::Mem(virt as usize, r.value)),
    }
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

/// Restart: the ACPI reset register, then the keyboard controller,
/// twice, then the PCH reset control port (Linux
/// native_machine_emergency_restart's BOOT_ACPI -> BOOT_KBD order, with
/// CF9 last); halts if all fail
pub fn reboot() -> ! {
    for _ in 0..2 {
        acpi_reset();
        kbd_reset();
    }
    cf9_reset();
    printkln!("reboot: still running, halting");
    halt()
}

/// Write RESET_VALUE to the FADT reset register (Linux acpi_reboot),
/// then give the platform 15 ms to act on it
fn acpi_reset() {
    let Some(reset) = POWER.get().and_then(|p| p.reset) else {
        return;
    };
    match reset {
        Reset::Io(port, val) => outb(port, val),
        // SAFETY: mapped by init for this register
        Reset::Mem(virt, val) => unsafe { core::ptr::write_volatile(virt as *mut u8, val) },
    }
    crate::delay::mdelay(15);
}

/// 8042 status and command port
const KBD_PORT: u16 = 0x64;
/// 8042 status: input buffer full
const KBD_IBF: u8 = 1 << 1;
/// 8042 command: pulse the reset line low
const KBD_RESET: u8 = 0xfe;

/// Pulse the reset line through the keyboard controller, ten times
/// (Linux BOOT_KBD)
fn kbd_reset() {
    for _ in 0..10 {
        kb_wait();
        crate::delay::udelay(50);
        outb(KBD_PORT, KBD_RESET);
        crate::delay::udelay(50);
    }
}

/// Wait, bounded, for the 8042 input buffer to drain (Linux kb_wait)
fn kb_wait() {
    for _ in 0..0x10000 {
        if inb(KBD_PORT) & KBD_IBF == 0 {
            break;
        }
        crate::delay::udelay(2);
    }
}

/// PCH reset control register
const RST_CNT: u16 = 0xcf9;
/// RST_CNT: SYS_RST (hard reset) and RST_CPU (do it)
const RST_SYS: u8 = 1 << 1;
const RST_CPU: u8 = 1 << 2;

/// Hard reset through port 0xCF9 (Linux BOOT_CF9_SAFE)
fn cf9_reset() {
    let code = RST_SYS | RST_CPU;
    let cf9 = inb(RST_CNT) & !code;
    outb(RST_CNT, cf9 | RST_SYS);
    crate::delay::udelay(50);
    outb(RST_CNT, cf9 | code);
    crate::delay::udelay(50);
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
