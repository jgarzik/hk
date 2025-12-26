//! hk-arch-x86_64: x86-64 architecture support
//!
//! This crate provides x86-64 specific implementations including:
//! - CPU initialization (GDT, TSS, IDT)
//! - Paging (4-level page tables)
//! - Syscall entry/exit (syscall/sysret)
//! - Interrupt handling (PIC, PIT)
//! - SMP support (ACPI, LAPIC, per-CPU data)
//! - Platform drivers (PIC, PIT, Serial)

// Note: no_std is inherited from the kernel crate

extern crate alloc;

pub mod acpi;
pub mod context;
pub mod cpu;
pub mod drivers;
pub mod interrupts;
pub mod io;
pub mod ioremap;
pub mod irq;
pub mod lapic;
pub mod paging;
pub mod percpu;
pub mod pic;
pub mod pit;
pub mod power;
pub mod rtc;
pub mod signal;
pub mod smp;
pub mod spinlock;
pub mod syscall;
pub mod tsc;
pub mod uaccess;
pub mod vgacon;

use crate::arch::{Arch, CpuOps, SchedArch, UserModeOps};

/// x86-64 architecture implementation
#[derive(Debug, Clone, Copy, Default)]
pub struct X86_64Arch;

// ============================================================================
// CpuOps trait implementation
// ============================================================================

impl CpuOps for X86_64Arch {
    #[inline]
    fn enable_interrupts() {
        unsafe {
            core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
        }
    }

    #[inline]
    fn disable_interrupts() {
        unsafe {
            core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
        }
    }

    #[inline]
    fn halt() {
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }

    #[inline]
    fn enable_and_halt() {
        // STI;HLT is a special pattern - interrupts are enabled only after
        // HLT completes, preventing the race where an interrupt fires between
        // STI and HLT leaving the CPU spinning.
        unsafe {
            core::arch::asm!("sti", "hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

/// x86-64 trap frame - saved CPU state during interrupts/syscalls
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct X86_64TrapFrame {
    // General purpose registers (pushed by software)
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,

    // Pushed by CPU on interrupt/exception
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl X86_64TrapFrame {
    /// Create a new trap frame for entering user mode
    pub fn new_user(entry: u64, user_stack: u64) -> Self {
        Self {
            rip: entry,
            rsp: user_stack,
            cs: cpu::USER_CODE_SELECTOR as u64,
            ss: cpu::USER_DATA_SELECTOR as u64,
            rflags: 0x202, // IF (interrupt enable) + reserved bit 1
            ..Default::default()
        }
    }
}

impl Arch for X86_64Arch {
    type TrapFrame = X86_64TrapFrame;
    type VirtAddr = u64;
    type PhysAddr = u64;

    /// User space starts at 4MB (after kernel low memory)
    const USER_START: u64 = 0x0000_0000_0040_0000;

    /// User space ends at canonical hole (128TB)
    const USER_END: u64 = 0x0000_8000_0000_0000;

    fn user_entry_frame(entry: Self::VirtAddr, user_stack_top: Self::VirtAddr) -> Self::TrapFrame {
        X86_64TrapFrame::new_user(entry, user_stack_top)
    }
}

// ============================================================================
// UserModeOps trait implementation
// ============================================================================

impl UserModeOps for X86_64Arch {
    unsafe fn jump_to_user(
        entry: u64,
        user_stack: u64,
        page_table_root: u64,
        kernel_stack: u64,
    ) -> ! {
        unsafe {
            syscall::jump_to_user_iret(entry, user_stack, page_table_root, kernel_stack);
        }
    }
}

// ============================================================================
// SchedArch trait implementation
// ============================================================================

impl SchedArch for X86_64Arch {
    type SchedPageTable = paging::X86_64PageTable;

    fn clone_child_trapframe(
        parent_rip: u64,
        parent_rflags: u64,
        child_rsp: u64,
    ) -> Self::TrapFrame {
        // Get parent's callee-saved registers from per-CPU storage
        // These were saved during syscall entry
        let (rbx, rbp, r12, r13, r14, r15) = percpu::get_syscall_user_callee_saved();

        X86_64TrapFrame {
            // Callee-saved registers - inherit from parent
            r15,
            r14,
            r13,
            r12,
            r11: parent_rflags, // Restore user RFLAGS (SYSRET convention)
            r10: 0,             // Caller-saved, not needed
            r9: 0,              // Caller-saved, not needed
            r8: 0,              // Caller-saved, not needed
            rbp,
            rdi: 0,          // Caller-saved, first syscall arg (not needed for return)
            rsi: 0,          // Caller-saved, second syscall arg
            rdx: 0,          // Caller-saved, third syscall arg
            rcx: parent_rip, // User return address (SYSRET convention)
            rbx,
            rax: 0, // Child returns 0 from fork/clone

            // IRET frame
            error_code: 0,
            rip: parent_rip,
            cs: cpu::USER_CODE_SELECTOR as u64,
            rflags: parent_rflags,
            rsp: child_rsp, // Child's user stack
            ss: cpu::USER_DATA_SELECTOR as u64,
        }
    }
}

// ============================================================================
// Kernel Initialization Trait Implementations
// ============================================================================

use crate::arch::{
    AcpiInfo, AcpiOps, ArchBusOps, CpuInfo, EarlyArchInit, ExceptionOps, HaltOps, InitramfsOps,
    IoremapOps, LocalTimerOps, MemoryLayoutOps, PowerInfo, PowerOps, SmpOps, SyscallOps,
    TimekeeperOps, TimerCallbackOps, VfsInitOps,
};

impl HaltOps for X86_64Arch {
    fn halt_loop() -> ! {
        unsafe {
            // Disable interrupts first to prevent waking from halt
            core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
        }
        loop {
            unsafe {
                core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
            }
        }
    }
}

impl EarlyArchInit for X86_64Arch {
    fn early_init() {
        early_init();
    }
}

impl IoremapOps for X86_64Arch {
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

impl AcpiOps for X86_64Arch {
    fn parse_acpi() -> Option<AcpiInfo> {
        let acpi_info = acpi::parse_acpi().ok()?;

        // Convert x86-64 AcpiInfo to arch-generic AcpiInfo
        Some(AcpiInfo {
            interrupt_controller_base: acpi_info.lapic_base,
            cpus: acpi_info
                .cpus
                .iter()
                .map(|cpu| CpuInfo {
                    hw_cpu_id: cpu.apic_id,
                    enabled: cpu.enabled,
                    is_bsp: cpu.is_bsp,
                })
                .collect(),
            bsp_cpu_id: acpi_info.bsp_apic_id,
            power_info: acpi_info.power_info.map(|p| PowerInfo {
                pm1a_cnt_blk: p.pm1a_cnt_blk,
                pm1b_cnt_blk: p.pm1b_cnt_blk,
                slp_typa: p.slp_typa,
            }),
        })
    }
}

impl SmpOps for X86_64Arch {
    fn smp_init<FA: crate::arch::FrameAlloc<PhysAddr = u64>>(
        acpi: &AcpiInfo,
        frame_alloc: &mut FA,
    ) -> usize {
        // Convert generic AcpiInfo back to x86-64 specific format for smp::init
        let x86_acpi = acpi::AcpiInfo {
            lapic_base: acpi.interrupt_controller_base,
            cpus: acpi
                .cpus
                .iter()
                .map(|cpu| acpi::CpuInfo {
                    apic_id: cpu.hw_cpu_id,
                    enabled: cpu.enabled,
                    is_bsp: cpu.is_bsp,
                })
                .collect(),
            ioapics: alloc::vec::Vec::new(), // I/O APICs not needed for SMP init
            bsp_apic_id: acpi.bsp_cpu_id,
            power_info: acpi.power_info.map(|p| acpi::PowerInfo {
                pm1a_cnt_blk: p.pm1a_cnt_blk,
                pm1b_cnt_blk: p.pm1b_cnt_blk,
                slp_typa: p.slp_typa,
            }),
        };

        smp::init(&x86_acpi, frame_alloc)
    }

    fn enable_ap_scheduling() {
        smp::enable_ap_scheduling();
    }

    fn set_bsp_cpu_id(acpi: &mut AcpiInfo, hw_id: u32) {
        acpi.bsp_cpu_id = hw_id;
        // Also mark the appropriate CPU as BSP
        for cpu in acpi.cpus.iter_mut() {
            cpu.is_bsp = cpu.hw_cpu_id == hw_id;
        }
    }
}

impl LocalTimerOps for X86_64Arch {
    const TIMER_VECTOR: u8 = interrupts::LAPIC_TIMER_VECTOR;

    unsafe fn init_local_interrupt_controller(base_virt: u64) {
        unsafe {
            lapic::LocalApic::new(base_virt);
        }
    }

    fn current_hw_cpu_id() -> u32 {
        lapic::current_apic_id() as u32
    }

    fn calibrate_and_start_timer(vector: u8, interval_ms: u32) -> u32 {
        lapic::calibrate_and_start_timer(vector, interval_ms)
    }
}

impl TimekeeperOps for X86_64Arch {
    type ClockSource = tsc::TscClockSource;

    fn init_clock_source() -> Option<Self::ClockSource> {
        tsc::TscClockSource::new()
    }

    fn clock_frequency(source: &Self::ClockSource) -> u64 {
        source.frequency_hz()
    }

    fn clock_is_reliable(source: &Self::ClockSource) -> bool {
        source.is_invariant()
    }

    fn read_cycles() -> u64 {
        tsc::read_tsc()
    }

    fn read_rtc() -> i64 {
        rtc::read_rtc()
    }
}

impl PowerOps for X86_64Arch {
    fn power_init(info: &PowerInfo) {
        power::init(info.pm1a_cnt_blk, info.pm1b_cnt_blk, info.slp_typa);
    }
}

impl SyscallOps for X86_64Arch {
    type SyscallHandler = syscall::SyscallHandler;

    fn set_syscall_handler(handler: Self::SyscallHandler) {
        syscall::set_syscall_handler(handler);
    }

    fn syscall_dispatcher() -> Self::SyscallHandler {
        syscall::x86_64_syscall_dispatch
    }
}

impl TimerCallbackOps for X86_64Arch {
    unsafe fn set_timer_preempt_callback(callback: fn()) {
        unsafe {
            set_timer_preempt_callback(callback);
        }
    }
}

impl ArchBusOps for X86_64Arch {
    fn arch_bus_init(bus_manager: &mut crate::bus::BusManager) {
        arch_init(bus_manager);
    }
}

// ============================================================================
// Kernel Init Unification Trait Implementations
// ============================================================================

// Memory layout constants for x86_64
const FRAME_ALLOC_BASE: u64 = 0x1200000; // 18MB
const FRAME_ALLOC_SIZE: u64 = 0xE000000; // ~224MB (up to 256MB total)

impl MemoryLayoutOps for X86_64Arch {
    fn get_frame_alloc_region() -> (u64, u64) {
        // Try to get memory map from multiboot2
        let multiboot_info = unsafe { crate::MULTIBOOT2_INFO };

        let (mem_start, mem_end) = unsafe {
            crate::multiboot2::find_largest_region_above(multiboot_info, FRAME_ALLOC_BASE)
        };

        // Use parsed memory map if valid, otherwise fall back to hardcoded values
        if mem_start >= FRAME_ALLOC_BASE && mem_end > mem_start {
            (mem_start, mem_end - mem_start)
        } else {
            (FRAME_ALLOC_BASE, FRAME_ALLOC_SIZE)
        }
    }
}

impl ExceptionOps for X86_64Arch {
    fn init_exceptions() {
        // No-op on x86_64 - exception handling (IDT, PIC) is done in early_init()
    }
}

impl InitramfsOps for X86_64Arch {
    fn get_initramfs() -> &'static [u8] {
        let multiboot_info = unsafe { crate::MULTIBOOT2_INFO };
        unsafe { crate::multiboot2::find_module(multiboot_info, "initramfs") }
            .expect("initramfs module not loaded by bootloader")
    }
}

impl VfsInitOps for X86_64Arch {
    fn init_vfs_extras() {
        // Initialize VFAT ramdisk from multiboot2 module
        // Look up the needed dentries via VFS
        let root_dentry = match crate::fs::lookup_path("/") {
            Ok(d) => d,
            Err(_) => return,
        };
        let dev_dentry = match crate::fs::lookup_path("/dev") {
            Ok(d) => d,
            Err(_) => return,
        };
        crate::init_vfat_ramdisk(&root_dentry, &dev_dentry);
    }
}

/// Early architecture initialization (before heap)
pub fn early_init() {
    // Initialize GDT and TSS (includes IST stacks)
    cpu::init_gdt();

    // Verify CPU features (x86-64, SSE2, NX)
    cpu::check_cpu_features();

    // Enable NX bit support in page tables (requires EFER.NXE)
    cpu::enable_nx();

    // Enable SMEP/SMAP for kernel/user memory separation security
    // SMEP: prevents kernel from executing user pages
    // SMAP: prevents kernel from accessing user pages without explicit stac/clac
    uaccess::enable_smep();
    uaccess::enable_smap();

    // Initialize FPU and SSE
    cpu::init_fpu_sse();

    // Initialize IDT (with IST entries for DF/NMI)
    interrupts::init_idt();

    // Initialize syscall MSRs (STAR, LSTAR, SFMASK)
    syscall::init();

    // Initialize and remap PIC
    pic::init();

    // Initialize PIT for timer interrupts
    pit::init(100); // 100Hz timer

    // Enable timer interrupt
    pic::enable_irq(0);
}

/// Timer preemption check callback
///
/// This is called from the LAPIC timer handler when it's safe to preempt.
/// The kernel sets this during initialization to point to its scheduler's
/// preemption function.
static mut TIMER_PREEMPT_CALLBACK: Option<fn()> = None;

/// Set the timer preemption callback
///
/// # Safety
/// Must be called once during kernel initialization, before interrupts are enabled.
pub unsafe fn set_timer_preempt_callback(callback: fn()) {
    unsafe {
        TIMER_PREEMPT_CALLBACK = Some(callback);
    }
}

/// Called from timer interrupt handler to check for preemption
#[inline]
pub fn timer_preempt_check() {
    // Safety: This is only called from the timer interrupt handler,
    // and the callback is set once during init before interrupts are enabled.
    if let Some(callback) = unsafe { TIMER_PREEMPT_CALLBACK } {
        callback();
    }
}

/// Architecture-specific bus/driver initialization
///
/// Called after BusManager is created. Registers the platform bus with
/// x86-64 specific devices and their drivers.
pub fn arch_init(bus_manager: &mut crate::bus::BusManager) {
    use crate::bus::{PlatformBus, PlatformDevice};
    use alloc::boxed::Box;
    use alloc::vec;

    // Create platform bus with x86-64 devices
    let platform_bus = PlatformBus::new(vec![
        PlatformDevice::new("intel,8259", Some(0x20), Some(0)), // PIC
        PlatformDevice::new("intel,8254", Some(0x40), Some(0)), // PIT
        PlatformDevice::new("ns16550a", Some(0x3F8), Some(4)),  // COM1
    ]);

    bus_manager.register_bus("platform", Box::new(platform_bus));

    // Register x86-64 platform drivers
    drivers::register_platform_drivers(bus_manager);
}
