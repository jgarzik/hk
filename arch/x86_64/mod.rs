//! hk-arch-x86_64: x86-64 architecture support
//!
//! This crate provides x86-64 specific implementations including:
//! - CPU initialization (GDT, TSS, IDT)
//! - Paging (4-level page tables)
//! - Syscall entry/exit (syscall/sysret)
//! - Interrupt handling (PIC, PIT)
//! - SMP support (ACPI, LAPIC, per-CPU data)
//! - Platform drivers (PIC, PIT, Serial)
#![expect(clippy::undocumented_unsafe_blocks)] // TODO(unsafe): SAFETY comments (doc/UNSAFE.md)

pub mod acpi;
pub mod barrier;
pub mod context;
pub mod cpu;
pub mod entry;
pub mod fpu;
pub mod interrupts;
pub mod io;
pub mod ioremap;
pub mod ipi;
pub mod irq;
pub mod kmap;
pub mod lapic;
pub mod msr;
pub mod multiboot2;
pub mod paging;
pub mod pci_conf;
pub mod percpu;
pub mod pic;
pub mod pit;
pub mod power;
pub mod ptrace;
pub mod rtc;
pub mod signal;
pub mod smp;
pub mod spinlock;
pub mod syscall;
pub mod tlb;
pub mod tsc;
pub mod uaccess;
pub mod uapi;
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
            core::arch::asm!("sti", options(nostack, preserves_flags));
        }
    }

    #[inline]
    fn disable_interrupts() {
        unsafe {
            core::arch::asm!("cli", options(nostack, preserves_flags));
        }
    }

    #[inline]
    fn halt() {
        unsafe {
            core::arch::asm!("hlt", options(nostack, preserves_flags));
        }
    }

    #[inline]
    fn enable_and_halt() {
        // STI;HLT is a special pattern - interrupts are enabled only after
        // HLT completes, preventing the race where an interrupt fires between
        // STI and HLT leaving the CPU spinning.
        unsafe {
            core::arch::asm!("sti", "hlt", options(nostack, preserves_flags));
        }
    }
}

/// The user (or interrupted kernel) registers of an entry (Linux struct
/// pt_regs, exact layout: `user_regs_struct` starts with it). Every
/// entry builds one (entry.rs); for an entry from user mode it is at
/// the top of the task's kernel stack (`task::percpu::current_pt_regs`).
#[derive(Debug, Clone, Default)]
#[repr(C)]
pub struct PtRegs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    /// The syscall number of a syscall, the error code of an exception
    /// (until its handler takes it), else -1 (Linux orig_ax)
    pub orig_rax: u64,
    // Pushed by the CPU (by `syscall_entry` for a syscall)
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

const _: () = assert!(core::mem::size_of::<PtRegs>() == 21 * 8);

impl crate::arch::UserRegs for PtRegs {
    fn ip(&self) -> u64 {
        self.rip
    }

    fn sp(&self) -> u64 {
        self.rsp
    }

    fn set_sp(&mut self, sp: u64) {
        self.rsp = sp;
    }

    fn ret(&self) -> u64 {
        self.rax
    }

    fn set_ret(&mut self, v: u64) {
        self.rax = v;
    }

    fn in_syscall(&self) -> bool {
        (self.orig_rax as i64) >= 0
    }

    fn syscall_nr(&self) -> u64 {
        self.orig_rax
    }

    fn syscall_args(&self) -> [u64; 6] {
        [self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9]
    }

    fn forget_syscall(&mut self) {}

    /// RIP back over the 2-byte `syscall`, the number back in RAX (Linux
    /// regs->ax = regs->orig_ax; regs->ip -= 2). A RIP the 2 bytes do not
    /// fit below (only a debugger could have put one there) is left alone
    /// and the syscall fails with EINTR: the result stays a user address.
    fn syscall_rollback(&mut self) {
        self.rax = self.orig_rax;
    }

    fn restart_syscall(&mut self) {
        match self.rip.checked_sub(2) {
            Some(ip) if ip < paging::TASK_SIZE => {
                self.rip = ip;
                self.rax = self.orig_rax;
            }
            _ => self.rax = crate::util::error::KernelError::Interrupted.sysret() as u64,
        }
    }
}

impl PtRegs {
    /// A frame for entering user mode
    pub fn new_user(entry: u64, user_stack: u64) -> Self {
        Self {
            rip: entry,
            rsp: user_stack,
            cs: u64::from(cpu::USER_CODE_SELECTOR),
            ss: u64::from(cpu::USER_DATA_SELECTOR),
            rflags: 0x202, // IF (interrupt enable) + reserved bit 1
            orig_rax: u64::MAX,
            ..Default::default()
        }
    }
}

impl Arch for X86_64Arch {
    type TrapFrame = PtRegs;
    type VirtAddr = u64;
    type PhysAddr = u64;

    fn user_entry_frame(entry: Self::VirtAddr, user_stack_top: Self::VirtAddr) -> Self::TrapFrame {
        PtRegs::new_user(entry, user_stack_top)
    }
}

// ============================================================================
// UserModeOps trait implementation
// ============================================================================

impl UserModeOps for X86_64Arch {
    unsafe fn jump_to_user(entry: u64, user_stack: u64, kernel_stack: u64) -> ! {
        unsafe { entry::enter_user(entry, user_stack, kernel_stack) }
    }
}

// ============================================================================
// SchedArch trait implementation
// ============================================================================

impl SchedArch for X86_64Arch {
    type SchedPageTable = paging::X86_64PageTable;

    unsafe fn clone_child_fpu(regs: u64) -> u64 {
        // SAFETY: the trait's contract
        unsafe { fpu::save_for_clone_child(regs) }
    }
}

// ============================================================================
// Kernel Initialization Trait Implementations
// ============================================================================

use crate::arch::{
    AcpiInfo, AcpiOps, ArchBusOps, CpuInfo, EarlyArchInit, ExceptionOps, HaltOps, InitramfsOps,
    IoremapOps, LocalTimerOps, MemoryLayoutOps, PowerInfo, PowerOps, SmpOps, TimekeeperOps,
    VfsInitOps,
};

impl HaltOps for X86_64Arch {
    fn halt_loop() -> ! {
        unsafe {
            // Disable interrupts first to prevent waking from halt
            core::arch::asm!("cli", options(nostack, preserves_flags));
        }
        loop {
            unsafe {
                core::arch::asm!("hlt", options(nostack, preserves_flags));
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
    fn ioremap_init() {
        ioremap::init();
    }

    unsafe fn ioremap(
        phys_addr: u64,
        size: u64,
    ) -> Result<*mut u8, crate::util::error::KernelError> {
        // SAFETY: the trait's contract
        unsafe { ioremap::ioremap(phys_addr, size) }
    }

    unsafe fn iounmap(virt_addr: *mut u8, size: u64) {
        // SAFETY: the trait's contract
        unsafe { ioremap::iounmap(virt_addr, size) };
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
            power_info: acpi_info.power_info,
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
            bsp_apic_id: acpi.bsp_cpu_id,
            power_info: acpi.power_info,
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
        u32::from(lapic::current_apic_id())
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

    fn read_cycles() -> u64 {
        tsc::read_tsc()
    }

    fn read_rtc() -> i64 {
        rtc::read_rtc()
    }
}

impl PowerOps for X86_64Arch {
    fn power_init(info: &PowerInfo) {
        power::init(info);
    }

    fn power_enable() {
        power::enable();
    }
}

impl ArchBusOps for X86_64Arch {
    /// The legacy 8250 ports (Linux serial8250 platform device; the
    /// PIC and PIT are set up at boot, not devices)
    fn platform_init() {
        use crate::base::platform::{PlatformDevice, platform_device_register};
        let _ = platform_device_register(PlatformDevice {
            name: "serial8250",
            compatible: &[],
            base: Some(0x3f8),
            irq: Some(4),
        });
        crate::hw::serial::SERIAL8250_DRIVER.register();
    }

    /// Configuration mechanism #1 (ports 0xCF8/0xCFC)
    fn pci_config_init() {
        crate::hw::pci::init_port_io();
        crate::printkln!("PCI: Using port I/O config access");
    }
}

// ============================================================================
// Kernel Init Unification Trait Implementations
// ============================================================================

impl MemoryLayoutOps for X86_64Arch {
    fn memblock_init() {
        use crate::mm::memblock;
        crate::arch::x86_64::multiboot2::for_each_region(|base, len, kind| {
            if kind == crate::arch::x86_64::multiboot2::MEMORY_AVAILABLE {
                memblock::add(base, len);
            }
        });
        // Frames are used through the direct map
        let end = kmap::direct_end();
        let mut mb = memblock::MEMBLOCK.lock();
        mb.remove(end, u64::MAX);
        mb.set_limit(end);
        // The first 1MB: BIOS data, EBDA, the AP trampoline (Linux
        // reserves it all, arch/x86/realmode)
        mb.reserve(0, 1 << 20);
        let (start, end) = kmap::image_range();
        mb.reserve(start, end - start);
        crate::arch::x86_64::multiboot2::boot_ranges(|_, s, e| mb.reserve(s, e.saturating_sub(s)));
    }

    unsafe fn map_kernel_page(va: u64, pa: u64, table: &mut dyn FnMut() -> u64) {
        unsafe { kmap::map_page(va, pa, table) }
    }

    unsafe fn map_kernel_pmd(va: u64, pa: u64, table: &mut dyn FnMut() -> u64) {
        unsafe { kmap::map_pmd(va, pa, table) }
    }
}

impl ExceptionOps for X86_64Arch {
    fn init_exceptions() {
        // No-op on x86_64 - exception handling (IDT, PIC) is done in early_init()
    }
}

impl InitramfsOps for X86_64Arch {
    fn get_initramfs() -> &'static [u8] {
        crate::arch::x86_64::multiboot2::find_module("initramfs")
            .expect("initramfs module not loaded by bootloader")
    }
}

impl VfsInitOps for X86_64Arch {
    fn init_vfs_extras() {
        // Initialize VFAT ramdisk from multiboot2 module
        // Look up the needed dentries via VFS
        let Ok(root_dentry) = crate::fs::lookup_path(b"/") else {
            return;
        };
        let Ok(dev_dentry) = crate::fs::lookup_path(b"/dev") else {
            return;
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

    // Enable SMEP/SMAP for user memory separation security
    // SMEP: prevents kernel from executing user pages
    // SMAP: prevents kernel from accessing user pages without explicit stac/clac
    uaccess::enable_smep();
    uaccess::enable_smap();

    // Enable x87/SSE(/AVX) for user tasks; pick XSAVE or FXSAVE
    fpu::init_cpu(true);

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
