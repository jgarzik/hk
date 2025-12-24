//! AArch64 SMP initialization
//!
//! Uses PSCI CPU_ON to bring up Application Processors.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::{cpu, exceptions, gic, percpu, power, timer};
use crate::arch::{AcpiInfo, FrameAlloc};
use crate::printkln;

/// Stack size per AP (16KB)
const AP_STACK_SIZE: usize = 16 * 1024;

/// Page size
const PAGE_SIZE: usize = 4096;

/// Data passed to AP during startup
///
/// This structure MUST match the layout expected by ap_entry_point in boot.S
#[repr(C)]
pub struct ApBootData {
    /// Stack top for this AP
    pub stack_top: u64,
    /// Page table base (TTBR0/TTBR1 value)
    pub ttbr0: u64,
    /// Virtual address of Rust entry point
    pub entry_point: u64,
    /// MPIDR of this CPU
    pub mpidr: u64,
    /// Logical CPU ID
    pub cpu_id: u32,
    /// Padding for alignment
    _pad: u32,
}

impl ApBootData {
    const fn zeroed() -> Self {
        Self {
            stack_top: 0,
            ttbr0: 0,
            entry_point: 0,
            mpidr: 0,
            cpu_id: 0,
            _pad: 0,
        }
    }
}

/// Static boot data for each AP (must be in identity-mapped memory)
static mut AP_BOOT_DATA: [ApBootData; percpu::MAX_CPUS] =
    [const { ApBootData::zeroed() }; percpu::MAX_CPUS];

/// Flag set by AP when ready
static AP_READY: AtomicU32 = AtomicU32::new(0);

/// Flag to enable AP scheduling
static SCHEDULING_ENABLED: AtomicBool = AtomicBool::new(false);

// External symbol for AP entry point in boot.S
unsafe extern "C" {
    fn ap_entry_point();
}

/// Initialize SMP - bring up all APs
pub fn init<FA: FrameAlloc<PhysAddr = u64>>(acpi: &AcpiInfo, frame_alloc: &mut FA) -> usize {
    let bsp_mpidr = cpu::read_mpidr();
    let bsp_cpu_id = (bsp_mpidr & 0xFF) as u32;

    // Get BSP kernel stack (from current SP, rounded to stack top)
    let bsp_stack: u64;
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) bsp_stack);
    }
    // Round up to nearest 16KB boundary (stack grows down, so find top)
    let bsp_stack_top = (bsp_stack + AP_STACK_SIZE as u64 - 1) & !(AP_STACK_SIZE as u64 - 1);

    // Initialize BSP per-CPU data
    percpu::init_bsp(bsp_mpidr, bsp_stack_top);

    // Get current page table base
    let ttbr0: u64;
    unsafe {
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr0);
    }

    // Test PSCI is working
    let psci_ver = power::psci_version();
    if psci_ver == 0 || psci_ver == 0xFFFF_FFFF {
        printkln!("SMP: PSCI not available");
        return 1; // Only BSP
    }

    // Start each AP
    let mut cpu_id = 1u32;
    for cpu_info in &acpi.cpus {
        if cpu_info.hw_cpu_id == bsp_cpu_id {
            continue; // Skip BSP
        }

        if !cpu_info.enabled {
            continue;
        }

        if cpu_id as usize >= percpu::MAX_CPUS {
            printkln!("SMP: Maximum CPU count reached");
            break;
        }

        // Allocate stack for this AP
        let stack_base = match allocate_ap_stack(frame_alloc) {
            Some(base) => base,
            None => {
                printkln!(
                    "SMP: Failed to allocate stack for CPU {}",
                    cpu_info.hw_cpu_id
                );
                continue;
            }
        };
        let stack_top = stack_base + AP_STACK_SIZE as u64;

        // Build MPIDR for target CPU
        // QEMU virt uses Aff0 for CPU ID within cluster
        let target_mpidr = cpu_info.hw_cpu_id as u64;

        // Set up boot data for this AP
        unsafe {
            let boot_data = &mut AP_BOOT_DATA[cpu_id as usize];
            boot_data.stack_top = stack_top;
            boot_data.ttbr0 = ttbr0;
            boot_data.entry_point = ap_rust_entry as *const () as u64;
            boot_data.mpidr = target_mpidr;
            boot_data.cpu_id = cpu_id;

            // Ensure writes are visible to AP
            core::arch::asm!("dsb sy", "isb");
        }

        // Clear ready flag
        AP_READY.store(0, Ordering::SeqCst);

        // Physical address of AP entry point and boot data
        // Since we use identity mapping, virt == phys for kernel addresses
        let entry_phys = ap_entry_point as *const () as u64;
        let context_phys = unsafe { &AP_BOOT_DATA[cpu_id as usize] as *const _ as u64 };

        // Call PSCI CPU_ON
        let result = power::psci_cpu_on(target_mpidr, entry_phys, context_phys);

        if result == power::psci::SUCCESS {
            // Wait for AP to signal ready (5 seconds to account for slow boot)
            if wait_for_ap(5000) {
                cpu_id += 1;
            } else {
                printkln!("SMP: Timeout waiting for CPU {}", cpu_info.hw_cpu_id);
            }
        } else if result == power::psci::ALREADY_ON {
            printkln!("SMP: CPU {} already on", cpu_info.hw_cpu_id);
        } else {
            printkln!(
                "SMP: PSCI CPU_ON failed for CPU {}: {}",
                cpu_info.hw_cpu_id,
                result
            );
        }
    }

    let total = percpu::online_cpu_count() as usize;
    // Use direct serial for boot-critical message (printkln may be buffered)
    use core::fmt::Write;
    let mut writer = super::serial::BootWriter;
    let _ = write!(writer, "SMP: {} CPUs online\r\n", total);
    total
}

/// Allocate stack for an AP
fn allocate_ap_stack<FA: FrameAlloc<PhysAddr = u64>>(frame_alloc: &mut FA) -> Option<u64> {
    let pages = AP_STACK_SIZE / PAGE_SIZE;
    let mut base: Option<u64> = None;

    for i in 0..pages {
        let frame = frame_alloc.alloc_frame()?;
        if i == 0 {
            base = Some(frame);
        }
        // Zero the frame
        unsafe {
            core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE);
        }
    }

    base
}

/// Wait for an AP to signal ready using spin loop
///
/// Uses raw counter since timer::time_ms() may not work before timer::init()
fn wait_for_ap(timeout_ms: u32) -> bool {
    // Read counter frequency directly from CNTFRQ_EL0
    let freq: u64;
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq);
    }

    // Calculate timeout in counter ticks
    let ticks_per_ms = freq / 1000;
    let timeout_ticks = ticks_per_ms * timeout_ms as u64;

    // Read starting counter value
    let start: u64;
    unsafe {
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) start);
    }

    loop {
        // Check if AP is ready (use SeqCst to match AP's store)
        if AP_READY.load(Ordering::SeqCst) != 0 {
            return true;
        }

        // Check for timeout
        let now: u64;
        unsafe {
            core::arch::asm!("mrs {}, cntpct_el0", out(reg) now);
        }
        if now.wrapping_sub(start) >= timeout_ticks {
            return false;
        }

        // Wait for event (AP sends SEV after setting AP_READY)
        unsafe {
            core::arch::asm!("wfe", options(nomem, nostack));
        }
    }
}

/// Enable AP scheduling
pub fn enable_ap_scheduling() {
    SCHEDULING_ENABLED.store(true, Ordering::Release);
}

/// Rust entry point for APs
///
/// Called from assembly after MMU is enabled.
#[unsafe(no_mangle)]
extern "C" fn ap_rust_entry(boot_data: *const ApBootData) -> ! {
    let boot_data = unsafe { &*boot_data };

    // Initialize per-CPU data
    let cpu_id = percpu::init_ap(boot_data.mpidr, boot_data.stack_top);

    // Initialize exception vectors for this CPU
    exceptions::init();

    // Initialize GIC for this CPU (redistributor + CPU interface)
    gic::init();

    // Signal ready to BSP
    AP_READY.store(1, Ordering::SeqCst);
    // Ensure the store is visible to other CPUs
    unsafe {
        core::arch::asm!("dsb sy", "sev", options(nomem, nostack));
    }

    // Wait for BSP to finish initialization and enable scheduling
    while !SCHEDULING_ENABLED.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }

    // Start timer on this AP
    timer::start(10); // 10ms interval

    // Enable interrupts
    cpu::enable_interrupts();

    // Enter idle loop
    printkln!("SMP: CPU {} entering idle loop", cpu_id);
    ap_idle_loop()
}

/// AP idle loop
fn ap_idle_loop() -> ! {
    loop {
        // Check for reschedule request
        if percpu::try_current_cpu()
            .map(|p| p.needs_reschedule.load(Ordering::Relaxed))
            .unwrap_or(false)
        {
            crate::task::percpu::try_schedule();
        }

        // Wait for next interrupt
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack));
        }
    }
}
