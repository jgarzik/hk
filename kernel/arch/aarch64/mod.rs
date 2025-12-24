//! AArch64 architecture support
//!
//! This module provides aarch64-specific implementations for the kernel.

extern crate alloc;

pub mod cache;
pub mod context;
pub mod cpu;
pub mod drivers;
pub mod dtb;
pub mod exceptions;
pub mod gic;
pub mod ioremap;
pub mod irq;
pub mod paging;
pub mod percpu;
pub mod power;
pub mod rtc;
pub mod serial;
pub mod signal;
pub mod smp;
pub mod spinlock;
pub mod syscall;
pub mod timer;
pub mod uaccess;

use alloc::vec;
use core::arch::asm;

use crate::arch::{
    AcpiInfo, AcpiOps, Arch, ArchBusOps, ContextOps, CpuInfo, CpuOps, EarlyArchInit, ExceptionOps,
    FrameAlloc, HaltOps, InitramfsOps, IoremapOps, LocalTimerOps, MemoryLayoutOps, PerCpuOps,
    PowerInfo, PowerOps, SchedArch, SmpOps, SyscallOps, TimekeeperOps, TimerCallbackOps,
    UserModeOps, VfsInitOps,
};
use crate::task::{CurrentTask, Tid};

/// AArch64 trap frame for saving/restoring CPU state on exception entry
///
/// This captures all general-purpose registers plus exception state.
/// Layout matches the order we push/pop in exception vectors.
#[repr(C)]
#[derive(Clone, Default)]
pub struct Aarch64TrapFrame {
    /// General purpose registers x0-x30
    pub x: [u64; 31],
    /// Stack pointer (SP_EL0 for user, current SP for kernel)
    pub sp: u64,
    /// Exception Link Register - return address
    pub elr: u64,
    /// Saved Program Status Register
    pub spsr: u64,
}

// Re-export TaskContext from context module
pub use context::Aarch64TaskContext;

/// AArch64 architecture implementation
#[derive(Debug, Clone, Copy, Default)]
pub struct Aarch64Arch;

impl Arch for Aarch64Arch {
    type TrapFrame = Aarch64TrapFrame;
    type VirtAddr = u64;
    type PhysAddr = u64;

    /// User space starts at 4MB (skip null page and low addresses)
    const USER_START: u64 = 0x0000_0000_0040_0000;
    /// User space ends at TTBR0 limit (48-bit VA space)
    const USER_END: u64 = 0x0000_FFFF_FFFF_FFFF;

    fn user_entry_frame(entry: Self::VirtAddr, user_stack_top: Self::VirtAddr) -> Self::TrapFrame {
        // SPSR: EL0t (return to EL0, use SP_EL0), DAIF clear (interrupts enabled)
        // Bits [3:0] = 0b0000 (EL0t), bits [9:6] = 0 (DAIF clear)
        Aarch64TrapFrame {
            elr: entry,
            sp: user_stack_top,
            spsr: 0,
            ..Default::default()
        }
    }
}

// ============================================================================
// CpuOps trait implementation
// ============================================================================

impl CpuOps for Aarch64Arch {
    #[inline]
    fn enable_interrupts() {
        cpu::enable_interrupts();
    }

    #[inline]
    fn disable_interrupts() {
        cpu::disable_interrupts();
    }

    #[inline]
    fn halt() {
        cpu::halt();
    }

    #[inline]
    fn enable_and_halt() {
        // Enable interrupts and wait for interrupt atomically
        unsafe {
            asm!(
                "msr daifclr, #2", // Clear I bit (enable IRQ)
                "wfi",
                options(nomem, nostack)
            );
        }
    }
}

// ============================================================================
// HaltOps trait implementation
// ============================================================================

impl HaltOps for Aarch64Arch {
    fn halt_loop() -> ! {
        cpu::disable_interrupts();
        loop {
            cpu::halt();
        }
    }
}

// ============================================================================
// EarlyArchInit trait implementation
// ============================================================================

impl EarlyArchInit for Aarch64Arch {
    fn early_init() {
        // Initialize PL011 serial for console output
        // Note: On aarch64, serial is initialized separately in _start_rust
        // before early_init() is called, so we can print debug messages.
        // This is a no-op if already initialized.
        serial::init();

        // Initialize CPU features (FPU, etc.)
        cpu::init();

        // Initialize PL031 RTC (ensure it's enabled)
        rtc::init();

        // Note: MMU is initialized explicitly via init_mmu() from _start_rust
        // because it needs to happen before heap allocation but after serial init.
        // Exception vectors and GIC are initialized later in kmain_aarch64.
    }
}

// ============================================================================
// IoremapOps trait implementation
// ============================================================================

impl IoremapOps for Aarch64Arch {
    type IoremapError = ioremap::IoremapError;

    fn ioremap_init() {
        ioremap::init();
    }

    fn ioremap(phys_addr: u64, size: u64) -> Result<*mut u8, Self::IoremapError> {
        ioremap::ioremap(phys_addr, size)
    }

    fn iounmap(virt_addr: *mut u8, size: u64) {
        ioremap::iounmap(virt_addr, size);
    }
}

// ============================================================================
// AcpiOps trait implementation (DTB parsing - stub for now)
// ============================================================================

impl AcpiOps for Aarch64Arch {
    fn parse_acpi() -> Option<AcpiInfo> {
        // Get DTB pointer saved by _start_rust
        let dtb_ptr = unsafe { crate::DTB_PTR };

        if dtb_ptr == 0 {
            // Fallback to hardcoded values if no DTB
            crate::printkln!("DTB: no pointer, using fallback");
            return Some(fallback_acpi_info());
        }

        // Parse DTB
        match dtb::parse_dtb(dtb_ptr) {
            Some(info) => {
                crate::printkln!(
                    "DTB: GIC at {:#x}, {} CPUs",
                    info.interrupt_controller_base,
                    info.cpus.len()
                );
                Some(info)
            }
            None => {
                crate::printkln!("DTB: parse failed, using fallback");
                Some(fallback_acpi_info())
            }
        }
    }
}

/// Fallback ACPI info with hardcoded QEMU virt values
fn fallback_acpi_info() -> AcpiInfo {
    AcpiInfo {
        interrupt_controller_base: 0x0800_0000,
        cpus: vec![
            CpuInfo {
                hw_cpu_id: 0,
                enabled: true,
                is_bsp: true,
            },
            CpuInfo {
                hw_cpu_id: 1,
                enabled: true,
                is_bsp: false,
            },
            CpuInfo {
                hw_cpu_id: 2,
                enabled: true,
                is_bsp: false,
            },
            CpuInfo {
                hw_cpu_id: 3,
                enabled: true,
                is_bsp: false,
            },
        ],
        bsp_cpu_id: 0,
        power_info: None,
    }
}

// ============================================================================
// SmpOps trait implementation (stub for now)
// ============================================================================

impl SmpOps for Aarch64Arch {
    fn smp_init<FA: FrameAlloc<PhysAddr = u64>>(acpi: &AcpiInfo, frame_alloc: &mut FA) -> usize {
        smp::init(acpi, frame_alloc)
    }

    fn enable_ap_scheduling() {
        smp::enable_ap_scheduling();
    }

    fn set_bsp_cpu_id(acpi: &mut AcpiInfo, hw_id: u32) {
        acpi.bsp_cpu_id = hw_id;
        for cpu in acpi.cpus.iter_mut() {
            cpu.is_bsp = cpu.hw_cpu_id == hw_id;
        }
    }
}

// ============================================================================
// LocalTimerOps trait implementation (stub for now)
// ============================================================================

impl LocalTimerOps for Aarch64Arch {
    const TIMER_VECTOR: u8 = 30; // GIC PPI 30 for physical timer

    unsafe fn init_local_interrupt_controller(_base_virt: u64) {
        // GIC is initialized separately in kmain_aarch64 via gic::init()
        // This function is a no-op on aarch64 since we don't use a LAPIC-style model
    }

    fn current_hw_cpu_id() -> u32 {
        cpu::cpu_id()
    }

    fn calibrate_and_start_timer(_vector: u8, interval_ms: u32) -> u32 {
        // Initialize timer (reads and caches frequency)
        timer::init();
        // Start the periodic timer
        timer::start(interval_ms);
        // Return ticks per ms (frequency / 1000)
        (timer::read_frequency() / 1000) as u32
    }
}

// ============================================================================
// TimekeeperOps trait implementation (stub for now)
// ============================================================================

/// ARM Generic Timer clock source
pub struct GenericTimerClockSource {
    frequency: u64,
}

impl TimekeeperOps for Aarch64Arch {
    type ClockSource = GenericTimerClockSource;

    fn init_clock_source() -> Option<Self::ClockSource> {
        // Read counter frequency from CNTFRQ_EL0
        let freq: u64;
        unsafe {
            asm!("mrs {}, cntfrq_el0", out(reg) freq);
        }
        Some(GenericTimerClockSource { frequency: freq })
    }

    fn clock_frequency(source: &Self::ClockSource) -> u64 {
        source.frequency
    }

    fn clock_is_reliable(_source: &Self::ClockSource) -> bool {
        true // ARM Generic Timer is always reliable
    }

    fn read_cycles() -> u64 {
        let count: u64;
        unsafe {
            asm!("mrs {}, cntpct_el0", out(reg) count);
        }
        count
    }

    fn read_rtc() -> i64 {
        rtc::read_rtc()
    }
}

// ============================================================================
// PowerOps trait implementation
// ============================================================================

impl PowerOps for Aarch64Arch {
    fn power_init(_info: &PowerInfo) {
        // PSCI doesn't need explicit init
    }
}

// ============================================================================
// SyscallOps trait implementation (stub for now)
// ============================================================================

/// Syscall handler function type for aarch64
pub type SyscallHandler = fn(u64, u64, u64, u64, u64, u64, u64) -> u64;

impl SyscallOps for Aarch64Arch {
    type SyscallHandler = SyscallHandler;

    fn set_syscall_handler(_handler: Self::SyscallHandler) {
        // No-op: aarch64 syscalls are handled via exception vectors (SVC instruction)
        // installed in exceptions::init(). The actual dispatch is in exceptions.rs.
    }

    fn syscall_dispatcher() -> Self::SyscallHandler {
        // Note: This function isn't used on aarch64 - syscall dispatch happens
        // directly in handle_el0_sync() via syscall::aarch64_syscall_dispatch()
        |_nr, _a0, _a1, _a2, _a3, _a4, _a5| 0
    }
}

// ============================================================================
// TimerCallbackOps trait implementation
// ============================================================================

static mut TIMER_PREEMPT_CALLBACK: Option<fn()> = None;

impl TimerCallbackOps for Aarch64Arch {
    unsafe fn set_timer_preempt_callback(callback: fn()) {
        unsafe {
            TIMER_PREEMPT_CALLBACK = Some(callback);
        }
    }
}

// ============================================================================
// ArchBusOps trait implementation
// ============================================================================

impl ArchBusOps for Aarch64Arch {
    fn arch_bus_init(bus_manager: &mut crate::bus::BusManager) {
        use crate::bus::{PlatformBus, PlatformDevice};
        use alloc::boxed::Box;

        // Create platform bus with ARM devices (QEMU virt addresses)
        let platform_bus = PlatformBus::new(vec![
            PlatformDevice::new("arm,gic-v3", Some(0x0800_0000), None),
            PlatformDevice::new("arm,pl011", Some(0x0900_0000), Some(33)),
            PlatformDevice::new("arm,pl031", Some(0x0901_0000), None),
        ]);

        bus_manager.register_bus("platform", Box::new(platform_bus));

        // Register aarch64 platform drivers
        drivers::register_platform_drivers(bus_manager);
    }
}

// ============================================================================
// UserModeOps trait implementation (stub for now)
// ============================================================================

impl UserModeOps for Aarch64Arch {
    unsafe fn jump_to_user(
        entry: u64,
        user_stack: u64,
        page_table_root: u64,
        kernel_stack: u64,
    ) -> ! {
        // Switch to user page table and enter user mode via ERET
        //
        // This sets up the CPU state to return to EL0 (user mode):
        // - TTBR0_EL1: User page table (lower VA space, 0x0000_xxxx_xxxx_xxxx)
        // - SP_EL0: User stack pointer
        // - ELR_EL1: Entry point (return address for ERET)
        // - SPSR_EL1: Saved processor state - EL0t with interrupts enabled
        //
        // SPSR_EL1 format for EL0t:
        // - bits [3:0] = 0b0000 (EL0t - user mode, use SP_EL0)
        // - bits [9:6] = 0 (DAIF clear - all interrupts enabled)
        // - All other bits = 0

        // Save kernel stack to per-CPU data for exception handlers
        // This is critical for execve: the new process needs to use
        // the correct kernel stack when it traps back into the kernel.
        unsafe {
            let percpu = percpu::current_cpu_mut();
            percpu.kernel_stack_top = kernel_stack;
        }

        unsafe {
            asm!(
                // Switch to user page table
                // TTBR0_EL1 holds the page table for user space (lower addresses)
                "msr ttbr0_el1, {page_table}",
                // Invalidate TLB entries for this ASID
                "tlbi vmalle1is",
                // Data synchronization barrier to ensure TLB flush completes
                "dsb ish",
                // Instruction synchronization barrier
                "isb",

                // Set up user stack pointer (SP_EL0)
                "msr sp_el0, {user_stack}",

                // Set up kernel stack pointer (SP_EL1 = current SP)
                // This is critical: when exceptions from EL0 occur, the CPU
                // switches to SP_EL1. We must set it to the task's kernel stack.
                "mov sp, {kernel_stack}",

                // Set up return address for ERET
                "msr elr_el1, {entry}",

                // Set up SPSR_EL1 for return to EL0t (user mode)
                // 0x0 = EL0t with all interrupts enabled
                // Use xzr (zero register) instead of an output register
                "msr spsr_el1, xzr",

                // Clear all general-purpose registers for security
                // (don't leak kernel data to user mode)
                "mov x0, #0",
                "mov x1, #0",
                "mov x2, #0",
                "mov x3, #0",
                "mov x4, #0",
                "mov x5, #0",
                "mov x6, #0",
                "mov x7, #0",
                "mov x8, #0",
                "mov x9, #0",
                "mov x10, #0",
                "mov x11, #0",
                "mov x12, #0",
                "mov x13, #0",
                "mov x14, #0",
                "mov x15, #0",
                "mov x16, #0",
                "mov x17, #0",
                "mov x18, #0",
                "mov x19, #0",
                "mov x20, #0",
                "mov x21, #0",
                "mov x22, #0",
                "mov x23, #0",
                "mov x24, #0",
                "mov x25, #0",
                "mov x26, #0",
                "mov x27, #0",
                "mov x28, #0",
                "mov x29, #0", // FP
                "mov x30, #0", // LR

                // Return to user mode
                "eret",

                page_table = in(reg) page_table_root,
                user_stack = in(reg) user_stack,
                kernel_stack = in(reg) kernel_stack,
                entry = in(reg) entry,
                options(noreturn)
            );
        }
    }
}

// ============================================================================
// PerCpuOps trait implementation (stub for now)
// ============================================================================

impl PerCpuOps for Aarch64Arch {
    const MAX_CPUS: usize = percpu::MAX_CPUS;

    #[inline]
    fn try_current_cpu_id() -> Option<u32> {
        percpu::try_current_cpu().map(|p| p.cpu_id)
    }

    #[inline]
    fn current_tid() -> Tid {
        percpu::try_current_cpu()
            .map(|p| p.current_tid.load(core::sync::atomic::Ordering::Relaxed) as Tid)
            .unwrap_or(0)
    }

    #[inline]
    fn set_current_tid(tid: Tid) {
        if percpu::try_current_cpu().is_some() {
            unsafe {
                percpu::current_cpu_mut()
                    .current_tid
                    .store(tid as u32, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    #[inline]
    fn needs_reschedule() -> bool {
        percpu::try_current_cpu()
            .map(|p| {
                p.needs_reschedule
                    .load(core::sync::atomic::Ordering::Relaxed)
            })
            .unwrap_or(false)
    }

    #[inline]
    fn clear_needs_reschedule() -> bool {
        percpu::try_current_cpu()
            .map(|p| {
                p.needs_reschedule
                    .swap(false, core::sync::atomic::Ordering::Relaxed)
            })
            .unwrap_or(false)
    }

    #[inline]
    fn set_needs_reschedule(val: bool) {
        if percpu::try_current_cpu().is_some() {
            unsafe {
                percpu::current_cpu_mut()
                    .needs_reschedule
                    .store(val, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    #[inline]
    fn interrupt_depth() -> u32 {
        percpu::try_current_cpu()
            .map(|p| {
                p.interrupt_depth
                    .load(core::sync::atomic::Ordering::Relaxed)
            })
            .unwrap_or(0)
    }

    #[inline]
    fn get_current_task() -> CurrentTask {
        percpu::try_current_cpu()
            .map(|p| p.current_task)
            .unwrap_or_default()
    }

    #[inline]
    fn set_current_task(task: &CurrentTask) {
        if percpu::try_current_cpu().is_some() {
            unsafe {
                percpu::current_cpu_mut().current_task.set(
                    task.tid, task.pid, task.ppid, task.pgid, task.sid, task.cred,
                );
            }
        }
    }

    #[inline]
    fn get_syscall_user_rip() -> u64 {
        percpu::try_current_cpu()
            .map(|p| p.syscall_user_elr)
            .unwrap_or(0)
    }

    #[inline]
    fn get_syscall_user_rflags() -> u64 {
        percpu::try_current_cpu()
            .map(|p| p.syscall_user_spsr)
            .unwrap_or(0)
    }

    #[inline]
    fn get_syscall_user_rsp() -> u64 {
        percpu::try_current_cpu()
            .map(|p| p.syscall_user_sp)
            .unwrap_or(0)
    }
}

// ============================================================================
// ContextOps trait implementation
// ============================================================================

impl ContextOps for Aarch64Arch {
    type TaskContext = Aarch64TaskContext;

    #[inline]
    fn new_kernel_thread_context(entry: usize, stack_top: u64) -> Self::TaskContext {
        Aarch64TaskContext::new_kernel_thread(entry, stack_top)
    }

    #[inline]
    fn new_clone_child_context(kstack_with_trapframe: u64) -> Self::TaskContext {
        Aarch64TaskContext::new_clone_child(kstack_with_trapframe)
    }

    #[inline]
    unsafe fn context_switch(
        old_ctx: *mut Self::TaskContext,
        new_ctx: *const Self::TaskContext,
        new_kstack: u64,
        new_page_table_root: u64,
        next_tid: Tid,
    ) {
        unsafe {
            context::context_switch(old_ctx, new_ctx, new_kstack, new_page_table_root, next_tid);
        }
    }

    unsafe fn context_switch_first(
        new_ctx: *const Self::TaskContext,
        new_kstack: u64,
        new_page_table_root: u64,
        next_tid: Tid,
    ) -> ! {
        unsafe {
            context::context_switch_first(new_ctx, new_kstack, new_page_table_root, next_tid);
        }
    }
}

// ============================================================================
// Page table re-export from paging module
// ============================================================================

pub use paging::Aarch64PageTable;

// ============================================================================
// Aarch64Arch inherent methods
// ============================================================================

impl Aarch64Arch {
    /// Get the saved user GPRs from syscall entry (for fork/clone)
    #[inline]
    fn get_syscall_user_regs() -> [u64; 31] {
        percpu::try_current_cpu()
            .map(|p| p.syscall_user_regs)
            .unwrap_or([0; 31])
    }
}

// ============================================================================
// SchedArch trait implementation
// ============================================================================

impl SchedArch for Aarch64Arch {
    type SchedPageTable = Aarch64PageTable;

    fn clone_child_trapframe(
        parent_rip: u64,
        parent_rflags: u64,
        child_rsp: u64,
    ) -> Self::TrapFrame {
        // Get parent's saved GPRs from syscall entry
        let mut regs = Self::get_syscall_user_regs();
        // Child returns 0 from fork/clone (x0 is the return value)
        regs[0] = 0;

        Aarch64TrapFrame {
            x: regs,             // All parent GPRs (with x0 = 0 for child)
            elr: parent_rip,     // Return address
            spsr: parent_rflags, // Saved PSTATE
            sp: child_rsp,       // Child's stack pointer
        }
    }
}

/// Initialize page tables and enable the MMU
///
/// This should be called after early_init but before the heap is used.
/// After this, all memory accesses go through the MMU.
///
/// # Safety
/// Must be called exactly once during early boot.
pub unsafe fn init_mmu() {
    unsafe {
        paging::init_boot_page_tables();
        paging::enable_mmu();
    }
}

// ============================================================================
// Kernel Init Unification Trait Implementations
// ============================================================================

// Memory layout constants for aarch64 (QEMU virt machine)
const AARCH64_FRAME_ALLOC_BASE: u64 = 0x4100_0000; // 16MB after kernel load
const AARCH64_FRAME_ALLOC_SIZE: u64 = 0x1000_0000; // 256MB

impl MemoryLayoutOps for Aarch64Arch {
    fn get_frame_alloc_region() -> (u64, u64) {
        // For now, use hardcoded constants for QEMU virt machine
        // Future: could parse DTB memory node for actual available memory
        (AARCH64_FRAME_ALLOC_BASE, AARCH64_FRAME_ALLOC_SIZE)
    }
}

impl ExceptionOps for Aarch64Arch {
    fn init_exceptions() {
        // Install exception vectors early
        exceptions::init();
        // Initialize GIC (distributor + redistributor + CPU interface)
        gic::init();
    }
}

impl InitramfsOps for Aarch64Arch {
    fn get_initramfs() -> &'static [u8] {
        // Get DTB pointer saved by _start_rust
        let dtb_ptr = unsafe { crate::DTB_PTR };

        // Try to extract initramfs from DTB
        if let Some(info) = dtb::extract_initramfs(dtb_ptr) {
            crate::printkln!(
                "Found initramfs in DTB: 0x{:x}-0x{:x} ({} bytes)",
                info.start,
                info.end,
                info.size()
            );
            return unsafe { info.as_slice() };
        }

        // Fall back to embedded initramfs (built into kernel binary)
        crate::printkln!(
            "Using embedded initramfs ({} bytes)",
            crate::EMBEDDED_INITRAMFS.len()
        );
        crate::EMBEDDED_INITRAMFS
    }
}

impl VfsInitOps for Aarch64Arch {
    fn init_vfs_extras() {
        // Create /vfat_test mount point for USB disk VFAT testing
        // (Similar to x86's init_vfat_ramdisk which creates this directory)
        if let Ok(root_dentry) = crate::fs::lookup_path("/") {
            let _ = crate::fs::ramfs::ramfs_create_dir(&root_dentry, "vfat_test");
        }
    }
}
