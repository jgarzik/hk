//! SMP (Symmetric Multi-Processing) initialization
//!
//! This module handles bringing up Application Processors (APs) on an SMP system.
//! The Bootstrap Processor (BSP) uses INIT-SIPI-SIPI to wake each AP, which then
//! executes a trampoline to transition from real mode to long mode.

use ::core::sync::atomic::{AtomicU32, Ordering};

use super::acpi::AcpiInfo;
use super::cpu;
use super::lapic::LocalApic;
use super::percpu::{self, MAX_CPUS};
use crate::arch::FrameAlloc;
use crate::printkln;

/// Trampoline code location in low memory (must be below 1MB for real mode)
/// We use 0x8000 (32KB) which is safe conventional memory
const TRAMPOLINE_ADDR: u64 = 0x8000;

/// SIPI vector (address / 0x1000)
const SIPI_VECTOR: u8 = (TRAMPOLINE_ADDR / 0x1000) as u8;

/// Stack size for each AP (16KB)
const AP_STACK_SIZE: usize = 16 * 1024;

/// Page size
const PAGE_SIZE: usize = 4096;

// External symbols from trampoline.S (linked via linker script)
unsafe extern "C" {
    static __trampoline_start: u8;
    static __trampoline_end: u8;
    static mut __ap_data_pml4: u64;
    static mut __ap_data_entry: u64;
    static mut __ap_data_stack: u64;
    static mut __ap_data_cpu_id: u32;
    static mut __ap_data_apic_id: u32;
}

/// Flag set by AP when it's ready
static AP_READY: AtomicU32 = AtomicU32::new(0);

/// Initialize SMP - bring up all APs
///
/// Returns the total number of CPUs online (including BSP).
/// Note: Caller must have already initialized LAPIC via LocalApic::new()
pub fn init<F: FrameAlloc<PhysAddr = u64>>(acpi: &AcpiInfo, frame_alloc: &mut F) -> usize {
    // Use existing LAPIC instance (already mapped via ioremap in main.rs)
    let lapic = LocalApic::get();
    let bsp_apic_id = lapic.id() as u32;

    // Initialize BSP per-CPU data
    // Note: percpu uses u8 APIC ID for xAPIC compatibility
    let bsp_stack = cpu::get_kernel_stack();
    percpu::init_bsp(bsp_apic_id as u8, bsp_stack);
    printkln!("SMP_CPU_ONLINE: cpu=0 apic={}", bsp_apic_id);

    // Enable LAPIC on BSP
    lapic.enable();

    // Save kernel's GDT and IDT for APs to use
    cpu::save_kernel_gdt_for_aps();
    cpu::save_kernel_idt_for_aps();

    // Get current CR3 for APs to use (they share the same page table)
    let cr3 = cpu::read_cr3();

    // Copy trampoline code to low memory
    copy_trampoline();

    // Start each AP
    let mut cpu_id = 1u32;
    for cpu_info in &acpi.cpus {
        if cpu_info.apic_id == bsp_apic_id {
            continue; // Skip BSP
        }

        if !cpu_info.enabled {
            continue;
        }

        if cpu_id as usize >= MAX_CPUS {
            printkln!("SMP: Maximum CPU count reached");
            break;
        }

        // Allocate stack for this AP
        let stack_base = allocate_ap_stack(frame_alloc);
        if stack_base == 0 {
            printkln!(
                "SMP: Failed to allocate stack for APIC {}",
                cpu_info.apic_id
            );
            continue;
        }
        let stack_top = stack_base + AP_STACK_SIZE as u64;

        // Set up trampoline data for this AP
        unsafe {
            let start = &raw const __trampoline_start as usize;
            let pml4_offset = &raw const __ap_data_pml4 as usize - start;
            let entry_offset = &raw const __ap_data_entry as usize - start;
            let stack_offset = &raw const __ap_data_stack as usize - start;
            let cpu_id_offset = &raw const __ap_data_cpu_id as usize - start;
            let apic_id_offset = &raw const __ap_data_apic_id as usize - start;

            let pml4_ptr = (TRAMPOLINE_ADDR + pml4_offset as u64) as *mut u64;
            let entry_ptr = (TRAMPOLINE_ADDR + entry_offset as u64) as *mut u64;
            let stack_ptr = (TRAMPOLINE_ADDR + stack_offset as u64) as *mut u64;
            let cpu_id_ptr = (TRAMPOLINE_ADDR + cpu_id_offset as u64) as *mut u32;
            let apic_id_ptr = (TRAMPOLINE_ADDR + apic_id_offset as u64) as *mut u32;

            core::ptr::write_volatile(pml4_ptr, cr3);
            core::ptr::write_volatile(entry_ptr, ap_entry as *const () as u64);
            core::ptr::write_volatile(stack_ptr, stack_top);
            core::ptr::write_volatile(cpu_id_ptr, cpu_id);
            core::ptr::write_volatile(apic_id_ptr, cpu_info.apic_id);
        }

        // Clear ready flag and start AP
        AP_READY.store(0, Ordering::SeqCst);

        if start_ap(&lapic, cpu_info.apic_id) {
            printkln!("SMP_CPU_ONLINE: cpu={} apic={}", cpu_id, cpu_info.apic_id);
            cpu_id += 1;
        } else {
            printkln!("SMP: Failed to start APIC {}", cpu_info.apic_id);
        }
    }

    let total = percpu::online_cpu_count() as usize;
    printkln!("SMP_INIT_COMPLETE: {} CPUs online", total);
    total
}

/// Allocate a stack for an AP
fn allocate_ap_stack<F: FrameAlloc<PhysAddr = u64>>(frame_alloc: &mut F) -> u64 {
    let pages = AP_STACK_SIZE / PAGE_SIZE;
    let mut base: Option<u64> = None;

    for i in 0..pages {
        let frame = match frame_alloc.alloc_frame() {
            Some(f) => f,
            None => return 0,
        };
        if i == 0 {
            base = Some(frame);
        }
        // Zero the frame
        unsafe {
            core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE);
        }
    }

    base.unwrap_or(0)
}

/// Start an AP using INIT-SIPI-SIPI sequence
///
/// Note: The LAPIC IPI functions currently only support xAPIC mode (8-bit APIC IDs).
/// For X2APIC systems with APIC IDs > 255, this will fail. Full X2APIC support
/// would require using MSRs instead of MMIO for IPI delivery.
fn start_ap(lapic: &LocalApic, apic_id: u32) -> bool {
    // xAPIC mode only supports 8-bit APIC IDs
    if apic_id > 255 {
        crate::printkln!(
            "SMP: Cannot start AP with APIC ID {} > 255 (X2APIC mode not supported)",
            apic_id
        );
        return false;
    }
    let apic_id_u8 = apic_id as u8;

    // Send INIT IPI
    lapic.send_init(apic_id_u8);

    // Wait 10ms
    delay_ms(10);

    // Send first SIPI
    lapic.send_sipi(apic_id_u8, SIPI_VECTOR);

    // Wait up to 200ms for AP to respond
    if wait_for_ap(200) {
        return true;
    }

    // Send second SIPI (required by some older CPUs)
    lapic.send_sipi(apic_id_u8, SIPI_VECTOR);

    // Wait up to 1 second for AP
    wait_for_ap(1000)
}

/// Wait for an AP to signal ready
fn wait_for_ap(timeout_ms: u32) -> bool {
    let deadline = get_ticks() + timeout_ms as u64;

    while get_ticks() < deadline {
        if AP_READY.load(Ordering::Acquire) != 0 {
            return true;
        }
        core::hint::spin_loop();
    }

    false
}

/// Simple millisecond delay using PIT
fn delay_ms(ms: u32) {
    // Use PIT channel 0 for timing
    // PIT frequency is 1193182 Hz
    // For 1ms, we need about 1193 ticks
    let ticks_per_ms = 1193u32;

    for _ in 0..ms {
        // Read current count, wait for it to wrap
        let start = read_pit_count();
        let target = start.wrapping_sub(ticks_per_ms as u16);

        loop {
            let current = read_pit_count();
            // Check if we've passed the target (accounting for wrap)
            if start > target {
                if current <= target || current > start {
                    break;
                }
            } else if current <= target && current > start {
                break;
            }
            core::hint::spin_loop();
        }
    }
}

/// Read PIT channel 0 current count
fn read_pit_count() -> u16 {
    // Latch count for channel 0
    super::io::outb(0x43, 0x00);
    let low = super::io::inb(0x40) as u16;
    let high = super::io::inb(0x40) as u16;
    (high << 8) | low
}

/// Get a simple tick count (for timeouts)
fn get_ticks() -> u64 {
    // Use a simple TSC-based tick count
    // This is not precise but good enough for timeouts
    unsafe {
        let mut low: u32;
        let mut high: u32;
        ::core::arch::asm!(
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags)
        );
        // Divide by approximate cycles per ms (assume ~1GHz for rough timing)
        (((high as u64) << 32) | (low as u64)) / 1_000_000
    }
}

/// Copy trampoline code to low memory
fn copy_trampoline() {
    unsafe {
        let start = &raw const __trampoline_start;
        let end = &raw const __trampoline_end;
        let size = end as usize - start as usize;

        // Copy trampoline code to low memory (0x8000)
        let dest = TRAMPOLINE_ADDR as *mut u8;
        core::ptr::copy_nonoverlapping(start, dest, size);
    }
}

/// Flag indicating BSP has finished timer calibration and scheduling is ready
static SCHEDULING_ENABLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Called by BSP after timer calibration to enable AP scheduling
pub fn enable_ap_scheduling() {
    SCHEDULING_ENABLED.store(true, core::sync::atomic::Ordering::Release);
}

/// AP entry point - called from trampoline in 64-bit mode
///
/// # Safety
/// This is called directly from assembly with the CPU in a partially
/// initialized state.
#[unsafe(no_mangle)]
pub extern "C" fn ap_entry(_cpu_id: u32, apic_id: u32) -> ! {
    // Load the kernel's GDT (AP is using trampoline's minimal GDT)
    cpu::reload_gdt();

    // Load the kernel's IDT
    cpu::reload_idt();

    // Get the stack top from our current RSP (set by trampoline)
    let kernel_stack: u64;
    unsafe {
        ::core::arch::asm!("mov {}, rsp", out(reg) kernel_stack);
    }

    // Initialize per-CPU data for this AP
    let _cpu_id = percpu::init_ap(apic_id as u8, kernel_stack);

    // Enable local APIC for this AP
    let lapic = super::lapic::LocalApic::get();
    lapic.enable();

    // Signal that we're ready (BSP will print our status)
    AP_READY.store(1, Ordering::Release);

    // Wait for BSP to finish timer calibration before starting our timer
    while !SCHEDULING_ENABLED.load(core::sync::atomic::Ordering::Acquire) {
        core::hint::spin_loop();
    }

    // Start LAPIC timer on this AP (using BSP's calibration)
    super::lapic::start_timer_on_ap(
        super::interrupts::LAPIC_TIMER_VECTOR,
        10, // 10ms = 100Hz
    );

    // Enable interrupts so timer can fire
    super::interrupts::enable();

    // Enter idle loop
    ap_idle_loop()
}

/// AP idle loop - waits for work
fn ap_idle_loop() -> ! {
    loop {
        // Check if there's preemption pending (timer interrupt may have fired)
        // This will call yield_now() which tries to schedule a task
        super::timer_preempt_check();

        // If no task was scheduled, wait for next interrupt
        unsafe {
            ::core::arch::asm!("hlt", options(nomem, nostack));
        }
    }
}
