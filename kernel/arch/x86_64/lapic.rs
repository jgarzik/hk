//! Local APIC (Advanced Programmable Interrupt Controller) driver
//!
//! Each CPU has its own Local APIC for handling interrupts and IPIs.
//! This module provides functions to:
//! - Enable/configure the Local APIC
//! - Send Inter-Processor Interrupts (IPIs)
//! - Handle the APIC timer

use ::core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

// LAPIC register offsets (from base address)
const LAPIC_ID: u32 = 0x020; // Local APIC ID
const LAPIC_VERSION: u32 = 0x030; // Local APIC Version
const LAPIC_TPR: u32 = 0x080; // Task Priority Register
const LAPIC_EOI: u32 = 0x0B0; // End of Interrupt
const LAPIC_SVR: u32 = 0x0F0; // Spurious Interrupt Vector Register
const LAPIC_ESR: u32 = 0x280; // Error Status Register
const LAPIC_CMCI_LVT: u32 = 0x2F0; // Corrected machine-check interrupt
const LAPIC_ICR_LOW: u32 = 0x300; // Interrupt Command Register (bits 0-31)
const LAPIC_ICR_HIGH: u32 = 0x310; // Interrupt Command Register (bits 32-63)
const LAPIC_TIMER_LVT: u32 = 0x320; // Timer Local Vector Table entry
const LAPIC_THERMAL_LVT: u32 = 0x330;
const LAPIC_PERF_LVT: u32 = 0x340;
const LAPIC_LINT0_LVT: u32 = 0x350;
const LAPIC_LINT1_LVT: u32 = 0x360;
const LAPIC_ERROR_LVT: u32 = 0x370;
const LAPIC_ISR: u32 = 0x100; // In-Service Register (8 x 32 bits, 0x10 apart)
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
const TIMER_MASKED: u32 = 0x10000;

// Timer divide values
const TIMER_DIV_16: u32 = 0x3;

/// Global LAPIC base address (set during initialization)
static LAPIC_BASE: AtomicU64 = AtomicU64::new(0);

/// The LAPICs run in x2APIC mode (IA32_APIC_BASE.EXTD, as firmware left
/// them; the same on every CPU): IPIs go through the ICR MSR
static X2APIC: AtomicBool = AtomicBool::new(false);

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
        X2APIC.store(
            rdmsr(IA32_APIC_BASE) & APIC_BASE_EXTD != 0,
            Ordering::Relaxed,
        );
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

    /// BSP only: let the 8259 PIC reach this CPU through LINT0 (ExtINT)
    /// and NMIs through LINT1 (Intel MP spec "virtual wire" mode, Linux
    /// setup_local_APIC). Without it, every PIC-routed device IRQ (PCI
    /// INTx on QEMU `pc`) is silently lost once the LAPIC is enabled.
    pub fn enable_pic_virtual_wire(&self) {
        const APIC_DM_EXTINT: u32 = 0x700;
        const APIC_DM_NMI: u32 = 0x400;
        self.write(LAPIC_LINT0_LVT, APIC_DM_EXTINT);
        self.write(LAPIC_LINT1_LVT, APIC_DM_NMI);
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

        // Disable performance counter, thermal and corrected
        // machine-check interrupts: firmware may leave them unmasked on
        // the BSP, on vectors nothing handles (Linux clear_local_APIC)
        let maxlvt = self.maxlvt();
        if maxlvt >= 4 {
            self.write(LAPIC_PERF_LVT, TIMER_MASKED);
        }
        if maxlvt >= 5 {
            self.write(LAPIC_THERMAL_LVT, TIMER_MASKED);
        }
        if maxlvt >= 6 {
            self.write(LAPIC_CMCI_LVT, TIMER_MASKED);
        }

        // APIC errors raise ERROR_APIC_VECTOR (Linux setup_local_APIC
        // and lapic_setup_esr): clear the ESR, then unmask
        self.write(LAPIC_ESR, 0);
        self.write(LAPIC_ERROR_LVT, ERROR_APIC_VECTOR as u32);
        self.write(LAPIC_ESR, 0);
    }

    /// Index of the highest LVT entry (Linux lapic_get_maxlvt)
    fn maxlvt(&self) -> u32 {
        (self.version() >> 16) & 0xFF
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

    /// Configure and start the APIC timer in one-shot mode (the clock
    /// event device: `set_next_event` re-arms it)
    ///
    /// # Arguments
    /// * `vector` - Interrupt vector for timer
    /// * `initial_count` - Initial countdown value
    /// * `divider` - Clock divider (use TIMER_DIV_* constants)
    pub fn start_timer_oneshot(&self, vector: u8, initial_count: u32, divider: u32) {
        // Set divider
        self.write(LAPIC_TIMER_DIV, divider);

        // Set timer LVT entry (one-shot mode: mode bits 0, not masked)
        self.write(LAPIC_TIMER_LVT, vector as u32);

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

/// IA32_APIC_BASE MSR and its x2APIC-enable bit
const IA32_APIC_BASE: u32 = 0x1b;
const APIC_BASE_EXTD: u64 = 1 << 10;
/// x2APIC ICR MSR
const X2APIC_ICR: u32 = 0x830;

fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: reads an architectural MSR
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nostack))
    };
    ((hi as u64) << 32) | lo as u64
}

/// Send the fixed IPI `vector` to the CPU with APIC id `apic_id`
/// (physical destination; Linux __default_send_IPI_dest_field,
/// x2apic_send_IPI). Any context: the ICR is written with interrupts
/// off, so an interrupt handler's IPI cannot interleave with ours.
pub fn send_ipi(apic_id: u32, vector: u8) {
    let irq = super::spinlock::local_irq_save();
    if X2APIC.load(Ordering::Relaxed) {
        // WRMSR to the ICR is not serializing: earlier stores (the
        // queued call) first (Linux weak_wrmsr_fence)
        let icr = ((apic_id as u64) << 32) | vector as u64;
        // SAFETY: writes the x2APIC ICR
        unsafe {
            core::arch::asm!(
                "mfence",
                "lfence",
                "wrmsr",
                in("ecx") X2APIC_ICR,
                in("eax") icr as u32,
                in("edx") (icr >> 32) as u32,
                options(nostack)
            )
        };
    } else {
        let lapic = LocalApic::get();
        // The previous IPI must have left (Linux __xapic_wait_icr_idle);
        // MMIO stores keep program order with the queue store
        lapic.wait_for_ipi();
        lapic.write(LAPIC_ICR_HIGH, apic_id << 24);
        lapic.write(LAPIC_ICR_LOW, ICR_DEST_FIELD | vector as u32);
    }
    super::spinlock::local_irq_restore(irq);
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

/// Vector of the LVT Error entry (Linux ERROR_APIC_VECTOR)
pub const ERROR_APIC_VECTOR: u8 = 0xfe;

/// Vector the LAPIC delivers for a spurious interrupt (SVR; Linux
/// SPURIOUS_APIC_VECTOR)
pub const SPURIOUS_APIC_VECTOR: u8 = SVR_SPURIOUS_VECTOR as u8;

/// Latch and read this CPU's Error Status Register (the write latches
/// the errors seen since the last one); 0 before the LAPIC is mapped
pub fn read_esr() -> u32 {
    if LAPIC_BASE.load(Ordering::Relaxed) == 0 {
        return 0;
    }
    let lapic = LocalApic::get();
    lapic.write(LAPIC_ESR, 0);
    lapic.read(LAPIC_ESR)
}

/// `vector` is in service on this CPU (its ISR bit is set); false
/// before the LAPIC is mapped (a stray vector then is only reported)
pub fn in_service(vector: u8) -> bool {
    if LAPIC_BASE.load(Ordering::Relaxed) == 0 {
        return false;
    }
    let reg = LAPIC_ISR + ((vector as u32) >> 5) * 0x10;
    LocalApic::get().read(reg) & (1 << (vector & 0x1f)) != 0
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

    // Start the one-shot timer with divider 16 (same as calibration)
    lapic.start_timer_oneshot(vector, initial_count, TIMER_DIV_16);

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
    lapic.start_timer_oneshot(vector, initial_count, TIMER_DIV_16);
}

/// Program this CPU's timer interrupt `delta_ns` from now (the clock
/// event device, Linux lapic_next_event; interrupts off)
pub fn set_next_event(delta_ns: u64) {
    let per_ms = LAPIC_TICKS_PER_MS.load(Ordering::Relaxed) as u64;
    let count = (delta_ns as u128 * per_ms as u128 / 1_000_000).clamp(1, u32::MAX as u128);
    LocalApic::get().write(LAPIC_TIMER_INIT, count as u32);
}
