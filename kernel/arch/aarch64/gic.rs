//! GICv3 Interrupt Controller Driver
//!
//! Support for ARM Generic Interrupt Controller v3 on QEMU virt platform.
//!
//! QEMU virt addresses:
//! - Distributor (GICD): 0x0800_0000
//! - Redistributor (GICR): 0x080A_0000 + (cpu_id * 0x20000)

use crate::printkln;
use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};

// QEMU virt GICv3 base addresses
const GICD_BASE: u64 = 0x0800_0000;
const GICR_BASE: u64 = 0x080A_0000;

// Redistributor stride per CPU (RD_base + SGI_base = 0x20000)
const GICR_STRIDE: u64 = 0x20000;

// Distributor registers (GICD)
const GICD_CTLR: u64 = GICD_BASE;
const GICD_TYPER: u64 = GICD_BASE + 0x0004;
const GICD_IPRIORITYR: u64 = GICD_BASE + 0x0400; // +n for interrupt n

// GICD_CTLR bits
const GICD_CTLR_ENABLE_G0: u32 = 1 << 0;
const GICD_CTLR_ENABLE_G1NS: u32 = 1 << 1;
const GICD_CTLR_ARE_NS: u32 = 1 << 4;

// Redistributor registers (GICR) - offsets from per-CPU base
const GICR_WAKER: u64 = 0x0014;

// SGI/PPI registers - offset 0x10000 from redistributor base
const GICR_SGI_BASE: u64 = 0x10000;
const GICR_IGROUPR0: u64 = GICR_SGI_BASE + 0x0080;
const GICR_ISENABLER0: u64 = GICR_SGI_BASE + 0x0100;
const GICR_IPRIORITYR: u64 = GICR_SGI_BASE + 0x0400;

// GICR_WAKER bits
const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
const GICR_WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;

// Physical timer PPI number
pub const TIMER_PPI: u32 = 30;

/// Get the redistributor base address for the current CPU
fn gicr_base() -> u64 {
    let cpu_id = super::cpu::cpu_id() as u64;
    GICR_BASE + (cpu_id * GICR_STRIDE)
}

/// Read a 32-bit value from a GIC register
#[inline]
unsafe fn read32(addr: u64) -> u32 {
    unsafe { read_volatile(addr as *const u32) }
}

/// Write a 32-bit value to a GIC register
#[inline]
unsafe fn write32(addr: u64, val: u32) {
    unsafe { write_volatile(addr as *mut u32, val) }
}

/// Initialize the GIC for the current CPU
///
/// This must be called on each CPU.
pub fn init() {
    unsafe {
        init_cpu_interface();
        init_redistributor();

        // On CPU 0, also initialize the distributor
        if super::cpu::cpu_id() == 0 {
            init_distributor();
        }
    }
}

/// Initialize the GIC CPU interface (ICC_* system registers)
unsafe fn init_cpu_interface() {
    // Enable system register access (ICC_SRE_EL1.SRE = 1)
    // Also set DFB and DIB to disable IRQ/FIQ bypass
    unsafe {
        asm!(
            "mrs {tmp}, icc_sre_el1",
            "orr {tmp}, {tmp}, #0x7",  // SRE | DFB | DIB
            "msr icc_sre_el1, {tmp}",
            "isb",
            tmp = out(reg) _,
            options(nostack, preserves_flags)
        );
    }

    // Set priority mask to accept all priorities (lowest priority = 0xFF)
    unsafe {
        asm!(
            "mov {tmp}, #0xFF",
            "msr icc_pmr_el1, {tmp}",
            tmp = out(reg) _,
            options(nostack, preserves_flags)
        );
    }

    // Set binary point to 0 (all bits for priority, none for subpriority)
    unsafe {
        asm!("msr icc_bpr1_el1, xzr", options(nostack, preserves_flags));
    }

    // Enable Group 1 interrupts (ICC_IGRPEN1_EL1 = 1)
    unsafe {
        asm!(
            "mov {tmp}, #1",
            "msr icc_igrpen1_el1, {tmp}",
            "isb",
            tmp = out(reg) _,
            options(nostack, preserves_flags)
        );
    }
}

/// Initialize the redistributor for the current CPU
unsafe fn init_redistributor() {
    let base = gicr_base();

    // Wake up the redistributor
    unsafe {
        let waker = read32(base + GICR_WAKER);
        write32(base + GICR_WAKER, waker & !GICR_WAKER_PROCESSOR_SLEEP);

        // Wait for it to wake (ChildrenAsleep should clear)
        let mut timeout = 1000000;
        while (read32(base + GICR_WAKER) & GICR_WAKER_CHILDREN_ASLEEP) != 0 {
            timeout -= 1;
            if timeout == 0 {
                printkln!("GIC: Redistributor wake timeout");
                break;
            }
        }

        // Set all PPIs to Group 1 (non-secure)
        write32(base + GICR_IGROUPR0, 0xFFFF_FFFF);

        // Set default priority for all SGIs/PPIs (0x80 = middle priority)
        for i in 0..8 {
            write32(base + GICR_IPRIORITYR + (i * 4), 0x8080_8080);
        }
    }
}

/// Initialize the GIC distributor (CPU 0 only)
unsafe fn init_distributor() {
    unsafe {
        // Disable distributor while configuring
        write32(GICD_CTLR, 0);

        // Read GICD_TYPER to find out how many interrupts are supported
        let typer = read32(GICD_TYPER);
        let it_lines = ((typer & 0x1F) + 1) * 32;
        printkln!("GIC: {} interrupt lines", it_lines);

        // Set all SPIs to Group 1, priority 0x80
        // SPIs start at interrupt 32
        for i in 1..(it_lines / 32) {
            // Group (offset 0x80): set all to Group 1
            write32(GICD_BASE + 0x0080 + (i * 4) as u64, 0xFFFF_FFFF);

            // Priority (offset 0x400): each byte is one interrupt
            for j in 0..8 {
                write32(GICD_IPRIORITYR + (i * 32 + j * 4) as u64, 0x8080_8080);
            }
        }

        // Enable distributor with Group 1 and affinity routing
        write32(
            GICD_CTLR,
            GICD_CTLR_ENABLE_G0 | GICD_CTLR_ENABLE_G1NS | GICD_CTLR_ARE_NS,
        );
    }

    printkln!("GIC distributor initialized");
}

/// Enable a specific PPI/SGI interrupt (0-31)
pub fn enable_ppi(intid: u32) {
    assert!(intid < 32, "PPI/SGI must be < 32");
    let base = gicr_base();
    unsafe {
        write32(base + GICR_ISENABLER0, 1 << intid);
    }
}

/// Acknowledge an interrupt (read ICC_IAR1_EL1)
///
/// Returns the interrupt ID (INTID). Returns 1020-1023 for spurious interrupts.
pub fn acknowledge_interrupt() -> u32 {
    let intid: u64;
    unsafe {
        asm!(
            "mrs {}, icc_iar1_el1",
            // DSB SY ensures the interrupt state change is visible
            // (per ARM GICv3 spec 4.1.1)
            "dsb sy",
            out(reg) intid,
            options(nostack)
        );
    }
    intid as u32
}

/// Signal end of interrupt (write ICC_EOIR1_EL1)
pub fn end_interrupt(intid: u32) {
    unsafe {
        asm!(
            "msr icc_eoir1_el1, {}",
            // ISB ensures EOI completes before further processing
            "isb",
            in(reg) intid as u64,
            options(nostack)
        );
    }
}
