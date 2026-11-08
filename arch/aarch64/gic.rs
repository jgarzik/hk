//! GICv3 Interrupt Controller Driver
//!
//! Support for ARM Generic Interrupt Controller v3 on QEMU virt platform.
//!
//! QEMU virt addresses:
//! - Distributor (GICD): 0x0800_0000
//! - Redistributor (GICR): 0x080A_0000 + (cpu_id * 0x20000)

use crate::printkln;
use core::arch::asm;
use core::ptr::NonNull;

use crate::hw::mmio::IoMem;

// QEMU virt GICv3 base addresses
const GICD_BASE: u64 = super::paging::io_va(0x0800_0000);
const GICR_BASE: u64 = super::paging::io_va(0x080A_0000);

// Redistributor stride per CPU (RD_base + SGI_base = 0x20000)
const GICR_STRIDE: u64 = 0x20000;

// Distributor registers (GICD)
const GICD_CTLR: u64 = GICD_BASE;
const GICD_TYPER: u64 = GICD_BASE + 0x0004;
const GICD_IPRIORITYR: u64 = GICD_BASE + 0x0400; // +n for interrupt n
const GICD_ISENABLER: u64 = GICD_BASE + 0x0100; // +4*(n/32)
const GICD_ICENABLER: u64 = GICD_BASE + 0x0180; // +4*(n/32)
const GICD_ICFGR: u64 = GICD_BASE + 0x0C00; // +4*(n/16), 2 bits per INTID
const GICD_IROUTER: u64 = GICD_BASE + 0x6000; // +8*n (n >= 32)
const GICD_CTLR_RWP: u32 = 1 << 31;

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
    let cpu_id = u64::from(super::cpu::cpu_id());
    GICR_BASE + (cpu_id * GICR_STRIDE)
}

/// Distributor window: 64KB of registers
const GICD_LEN: usize = 0x1_0000;
/// Redistributor windows: one per CPU, back to back, in QEMU virt's
/// redistributor region [0x080A0000, 0x09000000) (the UART follows it)
const GICR_LEN: usize = 0x0900_0000 - 0x080A_0000;

/// The distributor and redistributor register windows, in the device
/// block the boot page tables map for good (`kmap::map_io`)
static GICD: IoMem =
    // SAFETY: QEMU virt's GICv3 distributor, inside the always-mapped
    // device window
    unsafe { IoMem::new(NonNull::new(GICD_BASE as *mut u8).unwrap(), GICD_LEN) };
static GICR: IoMem =
    // SAFETY: as above, its redistributor frames
    unsafe { IoMem::new(NonNull::new(GICR_BASE as *mut u8).unwrap(), GICR_LEN) };

/// The window holding GIC register address `addr`, and the offset in it
fn window(addr: u64) -> (&'static IoMem, usize) {
    match addr {
        a if (GICD_BASE..GICD_BASE + GICD_LEN as u64).contains(&a) => {
            (&GICD, (a - GICD_BASE) as usize)
        }
        // Below GICR_BASE wraps to a huge offset: the window panics
        a => (&GICR, a.wrapping_sub(GICR_BASE) as usize),
    }
}

/// Read a 32-bit GIC register (an address in its windows; panics outside)
#[inline]
fn read32(addr: u64) -> u32 {
    let (w, off) = window(addr);
    w.read32(off)
}

/// Write a 32-bit GIC register (as `read32`)
#[inline]
fn write32(addr: u64, val: u32) {
    let (w, off) = window(addr);
    w.write32(off, val)
}

/// Write an 8-bit GIC register (as `read32`)
fn write8(addr: u64, val: u8) {
    let (w, off) = window(addr);
    w.write8(off, val)
}

/// Write a 64-bit GIC register (as `read32`)
fn write64(addr: u64, val: u64) {
    let (w, off) = window(addr);
    w.write64(off, val)
}

/// Initialize the GIC for the current CPU
///
/// This must be called on each CPU.
pub fn init() {
    // SAFETY: init() runs once per CPU as it comes up, interrupts masked;
    // the distributor only on CPU 0, before the APs
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
///
/// # Safety
/// On the CPU being brought up, interrupts masked, once.
unsafe fn init_cpu_interface() {
    // Enable system register access (ICC_SRE_EL1.SRE = 1)
    // Also set DFB and DIB to disable IRQ/FIQ bypass
    // SAFETY: this CPU's GIC CPU-interface registers, at bring-up
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
    // SAFETY: this CPU's GIC CPU-interface registers, at bring-up
    unsafe {
        asm!(
            "mov {tmp}, #0xFF",
            "msr icc_pmr_el1, {tmp}",
            tmp = out(reg) _,
            options(nostack, preserves_flags)
        );
    }

    // Set binary point to 0 (all bits for priority, none for subpriority)
    // SAFETY: this CPU's GIC CPU-interface registers, at bring-up
    unsafe {
        asm!("msr icc_bpr1_el1, xzr", options(nostack, preserves_flags));
    }

    // Enable Group 1 interrupts (ICC_IGRPEN1_EL1 = 1)
    // SAFETY: this CPU's GIC CPU-interface registers, at bring-up
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
///
/// # Safety
/// On the CPU being brought up, its redistributor mapped, once.
unsafe fn init_redistributor() {
    let base = gicr_base();

    // Wake up the redistributor
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

    // The IPI SGIs (ipi.rs)
    write32(
        base + GICR_ISENABLER0,
        (1 << super::ipi::SGI_RESCHEDULE) | (1 << super::ipi::SGI_CALL_FUNCTION),
    );
}

/// Send SGI `intid` to the CPU with affinity `mpidr` (ICC_SGI1R_EL1,
/// Linux gic_send_sgi). Any context.
pub fn send_sgi(mpidr: u64, intid: u32) {
    let aff = |n: u32| (mpidr >> (n * 8 + if n == 3 { 8 } else { 0 })) & 0xff;
    let aff0 = aff(0);
    let val = (aff(3) << 48)
        | (aff(2) << 32)
        | ((u64::from(intid) & 0xf) << 24)
        | (aff(1) << 16)
        | ((aff0 >> 4) << 44)
        | (1 << (aff0 & 0xf));
    // SAFETY: earlier stores (the queued call) are visible to the
    // target before the SGI (Linux gic_ipi_send_mask: dsb ishst)
    unsafe {
        asm!(
            "dsb ishst",
            "msr icc_sgi1r_el1, {}",
            "isb",
            in(reg) val,
            options(nostack)
        )
    };
}

/// Initialize the GIC distributor (CPU 0 only)
///
/// # Safety
/// Once, on CPU 0, the distributor mapped, before other CPUs use it.
unsafe fn init_distributor() {
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
        write32(GICD_BASE + 0x0080 + u64::from(i * 4), 0xFFFF_FFFF);

        // Priority (offset 0x400): each byte is one interrupt
        for j in 0..8 {
            write32(GICD_IPRIORITYR + u64::from(i * 32 + j * 4), 0x8080_8080);
        }
    }

    // Enable distributor with Group 1 and affinity routing
    write32(
        GICD_CTLR,
        GICD_CTLR_ENABLE_G0 | GICD_CTLR_ENABLE_G1NS | GICD_CTLR_ARE_NS,
    );

    printkln!("GIC distributor initialized");
}

/// Wait for a distributor register write to take effect (GICD_CTLR.RWP)
///
/// # Safety
/// The distributor is mapped.
unsafe fn gicd_wait_rwp() {
    let mut timeout = 1_000_000;
    while read32(GICD_CTLR) & GICD_CTLR_RWP != 0 && timeout > 0 {
        timeout -= 1;
    }
}

/// Configure and enable an SPI (INTID 32..1019)
///
/// Sets level trigger, priority 0x80 and Group 1 (init already did
/// those two for all SPIs), routes it to CPU 0 (whose tick and threads
/// handle device interrupts for now) and unmasks it at the distributor.
/// Safe to call again for an already enabled SPI. Process context.
pub fn enable_spi(intid: u32) {
    if !(32..1020).contains(&intid) {
        return;
    }
    let n = u64::from(intid);
    {
        // Level trigger: clear bit 1 of the 2-bit field (1 = edge)
        let cfg_reg = GICD_ICFGR + (n / 16) * 4;
        let shift = (n % 16) * 2 + 1;
        write32(cfg_reg, read32(cfg_reg) & !(1 << shift));

        // Priority (byte-addressed)
        write8(GICD_IPRIORITYR + n, 0x80);

        // Route to CPU 0 by affinity (ARE is enabled; IRM = 0)
        let mpidr = super::percpu::get_percpu(0).mpidr() & 0xFF_00FF_FFFF;
        write64(GICD_IROUTER + n * 8, mpidr);

        // Unmask
        write32(GICD_ISENABLER + (n / 32) * 4, 1 << (n % 32));
        // SAFETY: the distributor is up (enable_spi runs after init)
        unsafe { gicd_wait_rwp() };
    }
}

/// Mask an SPI at the distributor (any context)
pub fn disable_spi(intid: u32) {
    if !(32..1020).contains(&intid) {
        return;
    }
    let n = u64::from(intid);
    write32(GICD_ICENABLER + (n / 32) * 4, 1 << (n % 32));
    // SAFETY: as in enable_spi
    unsafe { gicd_wait_rwp() };
}

/// Enable a specific PPI/SGI interrupt (0-31)
pub fn enable_ppi(intid: u32) {
    assert!(intid < 32, "PPI/SGI must be < 32");
    let base = gicr_base();
    write32(base + GICR_ISENABLER0, 1 << intid);
}

/// Acknowledge an interrupt (read ICC_IAR1_EL1)
///
/// Returns the interrupt ID (INTID). Returns 1020-1023 for spurious interrupts.
pub fn acknowledge_interrupt() -> u32 {
    let intid: u64;
    // SAFETY: reads this CPU's acknowledge register (the interrupt path)
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
    // SAFETY: ends the interrupt this CPU acknowledged
    unsafe {
        asm!(
            "msr icc_eoir1_el1, {}",
            // ISB ensures EOI completes before further processing
            "isb",
            in(reg) u64::from(intid),
            options(nostack)
        );
    }
}
