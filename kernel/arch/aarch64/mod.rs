//! AArch64 architecture support
//!
//! This module provides aarch64-specific implementations for the kernel.

extern crate alloc;

pub mod barrier;
pub mod cache;
pub mod context;
pub mod cpu;
pub mod drivers;
pub mod dtb;
pub mod exceptions;
pub mod gic;
pub mod ioremap;
pub mod ipi;
pub mod irq;
pub mod kmap;
pub mod paging;
pub mod pci_irq;
pub mod percpu;
pub mod power;
pub mod ptrace;
pub mod rtc;
pub mod serial;
pub mod signal;
pub mod smp;
pub mod spinlock;
pub mod syscall;
pub mod timer;
pub mod tlb;
pub mod uaccess;
pub mod uapi;

use alloc::vec;
use core::arch::asm;

use crate::arch::{
    AcpiInfo, AcpiOps, Arch, ArchBusOps, ContextOps, CpuInfo, CpuOps, EarlyArchInit, ExceptionOps,
    FrameAlloc, HaltOps, InitramfsOps, IoremapOps, LocalTimerOps, MemoryLayoutOps, PerCpuOps,
    PowerInfo, PowerOps, SchedArch, SmpOps, TimekeeperOps, UserModeOps, VfsInitOps,
};

/// AArch64 trap frame for saving/restoring CPU state on exception entry
/// (Linux struct pt_regs, with the FP/SIMD state Linux keeps in
/// thread.uw.fpsimd_state)
///
/// This captures all general-purpose registers, exception state and the
/// FP/SIMD registers (the kernel uses NEON, so every exception saves them).
/// Layout matches the order we push/pop in exception vectors (vectors.S
/// TRAP_FRAME_SIZE / TF_*). For an exception from EL0 this is the task's
/// user state, at the top of its kernel stack (`current_pt_regs`): its
/// only copy while the task is in the kernel.
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
    /// Floating-point status register
    pub fpsr: u32,
    /// Floating-point control register
    pub fpcr: u32,
    /// SIMD/FP registers V0-V31
    pub v: [u128; 32],
    /// x0 of a syscall at entry (x0 then holds the return value; Linux
    /// orig_x0, for the restart)
    pub orig_x0: u64,
    /// The syscall number of a syscall frame, else `NO_SYSCALL` (Linux
    /// syscallno)
    pub syscallno: u64,
}

/// `syscallno` of a frame that is not a syscall's (Linux NO_SYSCALL)
pub const NO_SYSCALL: u64 = u64::MAX;

const _: () = assert!(core::mem::size_of::<Aarch64TrapFrame>() == 0x330);
const _: () = assert!(core::mem::offset_of!(Aarch64TrapFrame, v) == 0x120);
const _: () = assert!(core::mem::offset_of!(Aarch64TrapFrame, syscallno) == 0x328);

impl crate::arch::UserRegs for Aarch64TrapFrame {
    fn ip(&self) -> u64 {
        self.elr
    }

    fn sp(&self) -> u64 {
        self.sp
    }

    fn set_sp(&mut self, sp: u64) {
        self.sp = sp;
    }

    fn ret(&self) -> u64 {
        self.x[0]
    }

    fn set_ret(&mut self, v: u64) {
        self.x[0] = v;
    }

    fn in_syscall(&self) -> bool {
        self.syscallno != NO_SYSCALL
    }

    fn forget_syscall(&mut self) {
        self.syscallno = NO_SYSCALL;
    }

    /// ELR back over the `svc`, x0 back to its value at entry (x8 still
    /// holds the number; Linux regs[0] = orig_x0, pc -= 4)
    fn restart_syscall(&mut self) {
        self.elr = self.elr.wrapping_sub(4);
        self.x[0] = self.orig_x0;
    }
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

    fn user_entry_frame(entry: Self::VirtAddr, user_stack_top: Self::VirtAddr) -> Self::TrapFrame {
        // SPSR: EL0t (return to EL0, use SP_EL0), DAIF clear (interrupts enabled)
        // Bits [3:0] = 0b0000 (EL0t), bits [9:6] = 0 (DAIF clear)
        Aarch64TrapFrame {
            elr: entry,
            sp: user_stack_top,
            spsr: 0,
            syscallno: NO_SYSCALL,
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
    unsafe fn jump_to_user(entry: u64, user_stack: u64, kernel_stack: u64) -> ! {
        // Enter user mode at `entry` (the task's TTBR0 is loaded:
        // mm::tlb::switch_mm): every register, FP/SIMD included, zero,
        // FPCR/FPSR default, EL0t with interrupts enabled (Linux
        // start_thread), in the pt_regs at the top of its kernel stack,
        // left through vectors.S ret_to_user. The image's code was synced
        // to the instruction caches when exec loaded it
        // (paging::sync_page).
        let regs = (kernel_stack - core::mem::size_of::<Aarch64TrapFrame>() as u64)
            as *mut Aarch64TrapFrame;
        // SAFETY: the top of this task's kernel stack, below the caller's
        // frames only if the caller runs on another stack (init)
        unsafe { regs.write(Self::user_entry_frame(entry, user_stack)) };
        // Its return to user mode (a signal may be pending, the slice
        // used up), with IRQs masked
        cpu::disable_interrupts();
        // SAFETY: the frame above, this task's
        crate::entry::exit_to_user_mode(unsafe { &mut *regs });
        unsafe {
            asm!(
                // Exec runs with interrupts on: masked for the return
                "msr daifset, #0xf",
                "mov sp, {regs}",
                "b ret_to_user",
                regs = in(reg) regs,
                options(noreturn)
            );
        }
    }
}

// ============================================================================
// PerCpuOps trait implementation (stub for now)
// ============================================================================

impl PerCpuOps for Aarch64Arch {
    #[inline]
    fn try_current_cpu_id() -> Option<u32> {
        percpu::try_current_cpu().map(|p| p.cpu_id)
    }

    #[inline]
    fn current_task_ptr() -> usize {
        match percpu::try_current_cpu() {
            Some(p) => p.curr.load(core::sync::atomic::Ordering::Relaxed),
            None => crate::task::percpu::no_percpu_task(),
        }
    }

    #[inline]
    fn set_current_task_ptr(t: usize) {
        if let Some(p) = percpu::try_current_cpu() {
            p.curr.store(t, core::sync::atomic::Ordering::Relaxed);
        }
    }

    fn current_task_ptr_of(cpu: u32) -> usize {
        percpu::get_percpu(cpu)
            .curr
            .load(core::sync::atomic::Ordering::Relaxed)
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

    fn cpu_online(cpu: u32) -> bool {
        (cpu as usize) < percpu::MAX_CPUS
            && percpu::get_percpu(cpu)
                .is_online
                .load(core::sync::atomic::Ordering::Acquire)
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
        next_tls: u64,
        _next_gs: u64,
    ) {
        unsafe {
            context::context_switch(old_ctx, new_ctx, new_kstack, next_tls);
        }
    }

    unsafe fn context_switch_first(
        new_ctx: *const Self::TaskContext,
        new_kstack: u64,
        next_tls: u64,
        _next_gs: u64,
    ) -> ! {
        unsafe {
            context::context_switch_first(new_ctx, new_kstack, next_tls);
        }
    }
}

// ============================================================================
// Page table re-export from paging module
// ============================================================================

pub use paging::Aarch64PageTable;

// ============================================================================
// SchedArch trait implementation
// ============================================================================

impl SchedArch for Aarch64Arch {
    type SchedPageTable = Aarch64PageTable;

    // The child's TrapFrame carries the inherited FP/SIMD registers
    fn clone_child_fpu(regs: u64) -> u64 {
        regs
    }
}

// ============================================================================
// Kernel Init Unification Trait Implementations
// ============================================================================

impl MemoryLayoutOps for Aarch64Arch {
    fn memblock_init() {
        // RAM was added by `kmap::init` (it linear-maps every range)
        let dtb = unsafe { crate::DTB_PTR };
        let mut mb = crate::mm::memblock::MEMBLOCK.lock();
        mb.set_limit(kmap::direct_end());
        let (start, end) = kmap::image_range();
        mb.reserve(start, end - start);
        if let Some(n) = dtb::total_size(dtb) {
            mb.reserve(dtb, n as u64);
        }
        if let Some(i) = dtb::extract_initramfs(dtb) {
            mb.reserve(i.start, i.end.saturating_sub(i.start));
        }
        dtb::for_each_firmware_reserved(dtb, |base, size| mb.reserve(base, size));
    }

    unsafe fn map_kernel_page(va: u64, pa: u64, table: &mut dyn FnMut() -> u64) {
        unsafe { kmap::map_page(va, pa, table) }
    }
}

impl ExceptionOps for Aarch64Arch {
    fn init_exceptions() {
        // Install exception vectors early
        exceptions::init();
        // ASID width and TLB tagging of the boot CPU
        tlb::init_cpu();
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
