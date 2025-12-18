//! Local APIC (Advanced Programmable Interrupt Controller) driver
//!
//! Each CPU has its own Local APIC for handling interrupts and IPIs.
//! This module provides functions to:
//! - Enable/configure the Local APIC
//! - Send Inter-Processor Interrupts (IPIs)
//! - Handle the APIC timer

use ::core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// LAPIC register offsets (from base address)
const LAPIC_ID: u32 = 0x020; // Local APIC ID
const LAPIC_VERSION: u32 = 0x030; // Local APIC Version
const LAPIC_TPR: u32 = 0x080; // Task Priority Register
const LAPIC_EOI: u32 = 0x0B0; // End of Interrupt
const LAPIC_SVR: u32 = 0x0F0; // Spurious Interrupt Vector Register
const LAPIC_ESR: u32 = 0x280; // Error Status Register
const LAPIC_ICR_LOW: u32 = 0x300; // Interrupt Command Register (bits 0-31)
const LAPIC_ICR_HIGH: u32 = 0x310; // Interrupt Command Register (bits 32-63)
const LAPIC_TIMER_LVT: u32 = 0x320; // Timer Local Vector Table entry
const LAPIC_THERMAL_LVT: u32 = 0x330;
const LAPIC_PERF_LVT: u32 = 0x340;
const LAPIC_LINT0_LVT: u32 = 0x350;
const LAPIC_LINT1_LVT: u32 = 0x360;
const LAPIC_TIMER_INIT: u32 = 0x380; // Timer Initial Count
const LAPIC_TIMER_CURRENT: u32 = 0x390; // Timer Current Count
const LAPIC_TIMER_DIV: u32 = 0x3E0; // Timer Divide Configuration

// SVR bits
const SVR_ENABLE: u32 = 0x100; // APIC Software Enable
const SVR_SPURIOUS_VECTOR: u32 = 0xFF; // Spurious interrupt vector

// ICR delivery modes
const ICR_INIT: u32 = 0x00500;
const ICR_STARTUP: u32 = 0x00600;

// ICR level/trigger
const ICR_LEVEL_ASSERT: u32 = 0x04000;
const ICR_LEVEL_DEASSERT: u32 = 0x00000;
const ICR_TRIGGER_LEVEL: u32 = 0x08000;

// ICR destination shorthand
const ICR_DEST_FIELD: u32 = 0x00000; // Use destination field

// ICR delivery status
const ICR_DELIVERY_PENDING: u32 = 0x1000;

// Timer LVT bits
const TIMER_PERIODIC: u32 = 0x20000;
const TIMER_MASKED: u32 = 0x10000;

// Timer divide values
const TIMER_DIV_16: u32 = 0x3;

/// Global LAPIC base address (set during initialization)
static LAPIC_BASE: AtomicU64 = AtomicU64::new(0);

/// Calibrated LAPIC timer ticks per millisecond (set by BSP, copied by APs)
static LAPIC_TICKS_PER_MS: AtomicU32 = AtomicU32::new(0);

/// Local APIC interface
pub struct LocalApic {
    base: u64,
}

impl LocalApic {
    /// Create a new LocalApic instance with the given MMIO base address
    ///
    /// # Safety
    /// The base address must be a valid, mapped LAPIC MMIO region.
    pub unsafe fn new(base: u64) -> Self {
        LAPIC_BASE.store(base, Ordering::SeqCst);
        Self { base }
    }

    /// Get a LocalApic instance using the stored global base
    ///
    /// # Panics
    /// Panics if the LAPIC has not been initialized.
    pub fn get() -> Self {
        let base = LAPIC_BASE.load(Ordering::SeqCst);
        assert!(base != 0, "LAPIC not initialized");
        Self { base }
    }

    /// Read a 32-bit LAPIC register
    #[inline]
    fn read(&self, offset: u32) -> u32 {
        unsafe {
            let addr = (self.base + offset as u64) as *const u32;
            core::ptr::read_volatile(addr)
        }
    }

    /// Write a 32-bit LAPIC register
    #[inline]
    fn write(&self, offset: u32, value: u32) {
        unsafe {
            let addr = (self.base + offset as u64) as *mut u32;
            core::ptr::write_volatile(addr, value);
        }
    }

    /// Get this CPU's APIC ID
    pub fn id(&self) -> u8 {
        ((self.read(LAPIC_ID) >> 24) & 0xFF) as u8
    }

    /// Get the LAPIC version
    pub fn version(&self) -> u32 {
        self.read(LAPIC_VERSION)
    }

    /// Enable the Local APIC
    pub fn enable(&self) {
        // Set spurious vector and enable APIC
        let svr = SVR_ENABLE | SVR_SPURIOUS_VECTOR;
        self.write(LAPIC_SVR, svr);

        // Clear error status (write twice as per Intel manual)
        self.write(LAPIC_ESR, 0);
        self.write(LAPIC_ESR, 0);

        // Set task priority to 0 (accept all interrupts)
        self.write(LAPIC_TPR, 0);

        // Mask LINT0 and LINT1
        self.write(LAPIC_LINT0_LVT, TIMER_MASKED);
        self.write(LAPIC_LINT1_LVT, TIMER_MASKED);

        // Disable performance counter and thermal interrupts
        if (self.version() >> 16) >= 4 {
            self.write(LAPIC_PERF_LVT, TIMER_MASKED);
        }
        self.write(LAPIC_THERMAL_LVT, TIMER_MASKED);

        // Clear any pending errors
        self.write(LAPIC_ESR, 0);
    }

    /// Wait for IPI delivery to complete
    fn wait_for_ipi(&self) {
        // Poll the delivery status bit
        while (self.read(LAPIC_ICR_LOW) & ICR_DELIVERY_PENDING) != 0 {
            core::hint::spin_loop();
        }
    }

    /// Send an INIT IPI to another processor
    pub fn send_init(&self, apic_id: u8) {
        // Set destination APIC ID in high register
        self.write(LAPIC_ICR_HIGH, (apic_id as u32) << 24);

        // Send INIT IPI (level triggered, assert)
        self.write(
            LAPIC_ICR_LOW,
            ICR_INIT | ICR_LEVEL_ASSERT | ICR_TRIGGER_LEVEL | ICR_DEST_FIELD,
        );

        self.wait_for_ipi();

        // Deassert INIT
        self.write(LAPIC_ICR_HIGH, (apic_id as u32) << 24);
        self.write(
            LAPIC_ICR_LOW,
            ICR_INIT | ICR_LEVEL_DEASSERT | ICR_TRIGGER_LEVEL | ICR_DEST_FIELD,
        );

        self.wait_for_ipi();
    }

    /// Send a Startup IPI (SIPI) to another processor
    ///
    /// The vector specifies the page number (vector * 0x1000 = startup address).
    /// For example, vector 0x08 means the AP starts at physical address 0x8000.
    pub fn send_sipi(&self, apic_id: u8, vector: u8) {
        self.write(LAPIC_ICR_HIGH, (apic_id as u32) << 24);
        self.write(
            LAPIC_ICR_LOW,
            ICR_STARTUP | ICR_DEST_FIELD | (vector as u32),
        );
        self.wait_for_ipi();
    }

    /// Configure and start the APIC timer in periodic mode
    ///
    /// # Arguments
    /// * `vector` - Interrupt vector for timer
    /// * `initial_count` - Initial countdown value
    /// * `divider` - Clock divider (use TIMER_DIV_* constants)
    pub fn start_timer_periodic(&self, vector: u8, initial_count: u32, divider: u32) {
        // Set divider
        self.write(LAPIC_TIMER_DIV, divider);

        // Set timer LVT entry (periodic mode, not masked)
        self.write(LAPIC_TIMER_LVT, TIMER_PERIODIC | (vector as u32));

        // Set initial count (starts the timer)
        self.write(LAPIC_TIMER_INIT, initial_count);
    }

    /// Get the current timer count
    pub fn timer_current(&self) -> u32 {
        self.read(LAPIC_TIMER_CURRENT)
    }

    /// Calibrate the LAPIC timer against the PIT
    ///
    /// Returns the number of LAPIC timer ticks per millisecond.
    pub fn calibrate_timer(&self) -> u32 {
        // Use PIT channel 2 for calibration (one-shot mode)
        // We'll measure how many LAPIC ticks occur in 10ms

        const CALIBRATION_MS: u32 = 10;
        const PIT_FREQ: u32 = 1193182; // PIT frequency in Hz
        let pit_count = (PIT_FREQ * CALIBRATION_MS) / 1000;

        // Set LAPIC timer to max count with divider 16
        self.write(LAPIC_TIMER_DIV, TIMER_DIV_16);
        self.write(LAPIC_TIMER_LVT, TIMER_MASKED); // Mask during calibration
        self.write(LAPIC_TIMER_INIT, 0xFFFFFFFF);

        // Set up PIT channel 2 for one-shot countdown
        // Channel 2, mode 0, binary, low/high byte
        // Enable speaker gate (bit 0) for PIT channel 2, disable speaker (bit 1)
        let gate = super::io::inb(0x61);
        super::io::outb(0x61, (gate & 0xFC) | 0x01);

        // Configure PIT channel 2: mode 0 (interrupt on terminal count)
        super::io::outb(0x43, 0xB0); // Channel 2, lobyte/hibyte, mode 0, binary

        // Load count
        super::io::outb(0x42, (pit_count & 0xFF) as u8);
        super::io::outb(0x42, ((pit_count >> 8) & 0xFF) as u8);

        // Wait for PIT to count down (poll OUT pin via port 0x61 bit 5)
        while (super::io::inb(0x61) & 0x20) == 0 {
            core::hint::spin_loop();
        }

        // Read how many LAPIC ticks elapsed
        let elapsed = 0xFFFFFFFF - self.timer_current();

        // Stop the timer
        self.write(LAPIC_TIMER_INIT, 0);

        // Calculate ticks per millisecond
        // Note: We used divider 16, so actual frequency is base_freq / 16
        elapsed / CALIBRATION_MS
    }
}

/// Global function to send EOI (for use from interrupt handlers)
#[inline]
pub fn eoi() {
    let base = LAPIC_BASE.load(Ordering::Relaxed);
    if base != 0 {
        unsafe {
            let addr = (base + LAPIC_EOI as u64) as *mut u32;
            core::ptr::write_volatile(addr, 0);
        }
    }
}

/// Get the current CPU's APIC ID
pub fn current_apic_id() -> u8 {
    let base = LAPIC_BASE.load(Ordering::Relaxed);
    if base != 0 {
        unsafe {
            let addr = (base + LAPIC_ID as u64) as *const u32;
            ((core::ptr::read_volatile(addr) >> 24) & 0xFF) as u8
        }
    } else {
        0
    }
}

/// Calibrate LAPIC timer and start periodic interrupts on BSP
///
/// This must be called on the BSP during boot. APs will use the
/// stored calibration value.
///
/// Returns the ticks per millisecond.
pub fn calibrate_and_start_timer(vector: u8, interval_ms: u32) -> u32 {
    let lapic = LocalApic::get();

    // Calibrate timer against PIT
    let ticks_per_ms = lapic.calibrate_timer();

    // Store calibration for APs
    LAPIC_TICKS_PER_MS.store(ticks_per_ms, Ordering::SeqCst);

    // Calculate initial count for desired interval
    let initial_count = ticks_per_ms * interval_ms;

    // Start periodic timer with divider 16 (same as calibration)
    lapic.start_timer_periodic(vector, initial_count, TIMER_DIV_16);

    ticks_per_ms
}

/// Start LAPIC timer on an AP using BSP's calibration
///
/// Must be called after BSP has calibrated the timer.
pub fn start_timer_on_ap(vector: u8, interval_ms: u32) {
    let ticks_per_ms = LAPIC_TICKS_PER_MS.load(Ordering::SeqCst);
    assert!(ticks_per_ms > 0, "LAPIC timer not calibrated");

    let lapic = LocalApic::get();
    let initial_count = ticks_per_ms * interval_ms;
    lapic.start_timer_periodic(vector, initial_count, TIMER_DIV_16);
}
