//! Architecture abstraction layer for the kernel
//!
//! This module provides type aliases and traits that abstract over
//! architecture-specific types, allowing the kernel to be written
//! in an architecture-independent way.
//!
//! # Scheduler Architecture Traits
//!
//! The scheduler uses several traits to abstract architecture-specific operations:
//! - [`PerCpuOps`] - Per-CPU data access
//! - [`CpuOps`] - CPU control operations (interrupts, halt)
//! - [`ContextOps`] - Task context and context switching
//! - [`UserModeOps`] - Transition to user mode
//! - [`SchedArch`] - Super-trait combining all scheduler needs
//!
//! # Kernel Initialization Traits
//!
//! Additional traits for architecture-independent kernel initialization:
//! - [`IoremapOps`] - Kernel page-table primitives (ioremap, vmap)
//! - [`EarlyConOps`] - Boot UART output (earlycon, panic)
//! - [`IrqChipOps`] - Device interrupt controller lines (mask, unmask)
//! - [`DmaSyncOps`] - Cache maintenance for streaming DMA
//! - [`AcpiOps`] - Platform hardware discovery (ACPI/device tree)
//! - [`SmpOps`] - Multi-processor initialization
//! - [`LocalTimerOps`] - Per-CPU timer operations
//! - [`TimekeeperOps`] - Clock source and RTC operations
//! - [`PowerOps`] - Power management (shutdown, reboot)
//! - [`HardwareAccess`] - Driver I/O abstraction (port I/O vs MMIO)

extern crate alloc;

use alloc::vec::Vec;
use bitflags::bitflags;

pub mod frame;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

// Architecture abstraction types
#[cfg(target_arch = "x86_64")]
pub use x86_64::uaccess::X86_64Uaccess as Uaccess;
#[cfg(target_arch = "x86_64")]
pub type CurrentArch = x86_64::X86_64Arch;

#[cfg(target_arch = "aarch64")]
pub use aarch64::uaccess::Aarch64Uaccess as Uaccess;
#[cfg(target_arch = "aarch64")]
pub type CurrentArch = aarch64::Aarch64Arch;

/// clone(2) takes tls before child_tid (Linux CONFIG_CLONE_BACKWARDS)
pub const CLONE_BACKWARDS: bool = cfg!(target_arch = "aarch64");

/// The current architecture's page table
pub type ArchPageTable = <CurrentArch as SchedArch>::SchedPageTable;

// I/O port access - x86-64 specific
// Re-exported for platform drivers (PIC, PIT, serial, PCI)
#[cfg(target_arch = "x86_64")]
#[expect(unused_imports)]
pub use x86_64::io::{inb, inl, inw, io_wait, outb, outl, outw};

// The serial ports' ttys (16550 on x86, PL011 on arm64)
#[cfg(target_arch = "x86_64")]
pub use crate::hw::serial::serial_ttys;
#[cfg(target_arch = "aarch64")]
pub use aarch64::serial::serial_ttys;

// Power management
#[cfg(target_arch = "x86_64")]
pub use x86_64::power;

#[cfg(target_arch = "aarch64")]
pub use aarch64::power;

// Device I/O memory barriers (dma_wmb/dma_rmb/wmb)
#[cfg(target_arch = "aarch64")]
pub use aarch64::barrier;
#[cfg(target_arch = "x86_64")]
pub use x86_64::barrier;

#[cfg(target_arch = "x86_64")]
pub use x86_64::percpu::{preempt_count, preempt_disable, preempt_enable};

#[cfg(target_arch = "aarch64")]
pub use aarch64::percpu::{preempt_count, preempt_disable, preempt_enable};

// Ptrace architecture-specific support
#[cfg(target_arch = "x86_64")]
pub use x86_64::ptrace;

#[cfg(target_arch = "aarch64")]
pub use aarch64::ptrace;

// The user registers of an entry (Linux struct pt_regs)
#[cfg(target_arch = "x86_64")]
pub use x86_64::PtRegs;

#[cfg(target_arch = "aarch64")]
pub use aarch64::Aarch64TrapFrame as PtRegs;

/// The current task's user register frame, as the entry code holds it
pub type UserFrame = frame::Frame<PtRegs>;

// Signal frame setup (setup_rt_frame) / rt_sigreturn
#[cfg(target_arch = "x86_64")]
pub use x86_64::signal;

#[cfg(target_arch = "aarch64")]
pub use aarch64::signal;

// Userspace ABI structures/constants whose layout or values differ per arch
#[cfg(target_arch = "x86_64")]
pub use x86_64::uapi;

#[cfg(target_arch = "aarch64")]
pub use aarch64::uapi;

// Program this CPU's next timer interrupt, ns from now (the one-shot
// clock event device: LAPIC timer count / CNTP_CVAL)
#[cfg(target_arch = "x86_64")]
pub use x86_64::lapic::set_next_event as clockevent_next;

#[cfg(target_arch = "aarch64")]
pub use aarch64::timer::set_next_event as clockevent_next;

// The current task's user TLS register (FS base / TPIDR_EL0)
#[cfg(target_arch = "x86_64")]
pub use x86_64::percpu::read_fs_base as read_user_tls;

#[cfg(target_arch = "aarch64")]
pub use aarch64::percpu::read_tpidr_el0 as read_user_tls;

// A value the user TLS register may take
#[cfg(target_arch = "x86_64")]
pub use x86_64::percpu::fs_base_ok as user_tls_ok;

// The current task's user GS base (x86-64 MSR_KERNEL_GS_BASE while in
// the kernel; arm64 has none: 0, writes ignored)
#[cfg(target_arch = "x86_64")]
pub use x86_64::percpu::{read_user_gsbase, write_user_gsbase};

#[cfg(target_arch = "aarch64")]
pub use aarch64::percpu::{read_user_gsbase, write_user_gsbase};

#[cfg(target_arch = "aarch64")]
pub use aarch64::percpu::tpidr_ok as user_tls_ok;

// ELF auxv hardware capabilities and platform string
#[cfg(target_arch = "x86_64")]
pub use x86_64::cpu::{
    ELF_PLATFORM, arch_random_seed, elf_hwcap, elf_hwcap2, min_sigstksz, random_get_entropy,
};

#[cfg(target_arch = "aarch64")]
pub use aarch64::cpu::{
    ELF_PLATFORM, arch_random_seed, elf_hwcap, elf_hwcap2, min_sigstksz, random_get_entropy,
};

// Physical-to-virtual address conversion
#[cfg(target_arch = "x86_64")]
pub use x86_64::paging::{self, phys_to_virt, virt_to_phys};

#[cfg(target_arch = "aarch64")]
pub use aarch64::paging::{self, phys_to_virt, virt_to_phys};

// TLB primitives behind mm::tlb
#[cfg(target_arch = "x86_64")]
pub use x86_64::tlb;

// IPIs behind smp
#[cfg(target_arch = "x86_64")]
pub use x86_64::ipi;

#[cfg(target_arch = "aarch64")]
pub use aarch64::ipi;

#[cfg(target_arch = "aarch64")]
pub use aarch64::tlb;

bitflags! {
    /// Page flags for memory mapping
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PageFlags: u64 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXECUTE = 1 << 2;
        const USER = 1 << 3;
    }
}

/// The user registers of a task in the kernel (Linux struct pt_regs and
/// its accessors: instruction_pointer, user_stack_pointer,
/// regs_return_value, syscall_get_nr): every entry from user mode builds
/// one at the top of the task's kernel stack
/// (`task::percpu::current_pt_regs`)
pub trait UserRegs {
    /// The user PC
    fn ip(&self) -> u64;
    /// The user stack pointer
    fn sp(&self) -> u64;
    fn set_sp(&mut self, sp: u64);
    /// The syscall return register (x86 RAX, arm64 x0)
    fn ret(&self) -> u64;
    fn set_ret(&mut self, v: u64);
    /// The frame is a syscall's (one that may still be restarted)
    fn in_syscall(&self) -> bool;
    /// Its syscall number, u64::MAX if none (Linux syscall_get_nr:
    /// orig_ax / syscallno; a tracer may change it at the entry stop)
    fn syscall_nr(&self) -> u64;
    /// Its six arguments (Linux syscall_get_arguments)
    fn syscall_args(&self) -> [u64; 6];
    /// No restart from here on (Linux forget_syscall; x86 keeps orig_ax,
    /// as Linux does: its restart leaves the syscall number in RAX, never
    /// an -ERESTART* code)
    fn forget_syscall(&mut self);
    /// Re-execute the syscall on return (Linux: the PC back over the
    /// syscall instruction, its number or first argument back in the
    /// return register)
    fn restart_syscall(&mut self);
    /// Give the syscall's registers back as they were at entry, its
    /// return register included (Linux syscall_rollback: x86 RAX =
    /// orig_ax, arm64 x0 = orig_x0), for a skipped syscall's SIGSYS
    fn syscall_rollback(&mut self);
    /// After the PTRACE_SYSCALL entry stop, before seccomp: make the
    /// recorded arguments the live ones, so seccomp filters exactly
    /// what the syscall receives (arm64: orig_x0 = x0; x86 reads rdi
    /// live and needs nothing)
    fn sync_syscall_args(&mut self) {}
}

/// Architecture abstraction trait
pub trait Arch {
    /// Trap frame type for saving/restoring CPU state (Linux pt_regs)
    type TrapFrame: Default + Clone + UserRegs;
    /// Virtual address type
    type VirtAddr: Copy + Eq;
    /// Physical address type
    type PhysAddr: Copy + Eq;

    /// Create a trap frame for entering user mode
    fn user_entry_frame(entry: Self::VirtAddr, user_stack_top: Self::VirtAddr) -> Self::TrapFrame;
}

/// Error type for page table mapping operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// Failed to allocate a frame for an intermediate page table
    FrameAllocationFailed,
    /// Address is already mapped
    AlreadyMapped,
    /// Invalid address or flags
    InvalidArgument,
    /// Address is not properly aligned (e.g., for huge pages)
    InvalidAddress,
}

/// A user mapping met while tearing down an address space
/// (`paging::UserTables::free`); the mm layer drops the reference it holds
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leaf {
    /// A present 4KB page (physical address)
    Page(u64),
    /// A present 2MB page (physical address of its head frame)
    Huge(u64),
    /// A non-present, non-empty PTE (a swap entry), raw value
    Swap(u64),
}

/// Page table abstraction trait
///
/// This trait provides architecture-independent page table operations.
/// Each architecture implements this for its specific page table format:
/// - x86-64: 4-level paging (PML4 → PDPT → PD → PT)
/// - aarch64: 4-level translation tables (TTBR → L0 → L1 → L2 → L3)
pub trait PageTable: Sized {
    type VirtAddr: Copy;
    type PhysAddr: Copy;

    /// Translate a virtual address to a physical address
    fn translate(&self, va: Self::VirtAddr) -> Option<Self::PhysAddr>;

    /// Map a virtual address to physical, allocating intermediate tables as needed
    ///
    /// This is the primary mapping function for user space page tables where
    /// intermediate page table levels may not exist yet.
    fn map_with_alloc<FA: FrameAlloc<PhysAddr = Self::PhysAddr>>(
        &mut self,
        va: Self::VirtAddr,
        pa: Self::PhysAddr,
        flags: PageFlags,
        frame_alloc: &mut FA,
    ) -> Result<(), MapError>;

    /// Create a new user-space page table
    ///
    /// Allocates the root page table (PML4 on x86-64, L0 on aarch64).
    /// Returns None if frame allocation fails.
    fn new_user<FA: FrameAlloc<PhysAddr = Self::PhysAddr>>(frame_alloc: &mut FA) -> Option<Self>;

    /// Copy kernel mappings from the current page table to this one
    ///
    /// This ensures kernel code/data remains accessible when this page
    /// table is loaded (e.g., during syscalls in user processes).
    fn copy_kernel_mappings(&mut self);

    /// Get the physical address of the root page table
    ///
    /// Returns the address to load into the hardware page table register:
    /// - x86-64: CR3 (PML4 physical address)
    /// - aarch64: TTBR0/TTBR1 (translation table base)
    fn root_table_phys(&self) -> Self::PhysAddr;

    /// The root of the table kernel threads run on (x86 swapper, arm64
    /// empty TTBR0), to load only: the shared kernel table is never a
    /// page-table value, so nothing can map into it through one
    fn kernel_root() -> Self::PhysAddr;
}

/// Frame allocator trait
pub trait FrameAlloc {
    type PhysAddr;

    /// Allocate a physical frame
    fn alloc_frame(&mut self) -> Option<Self::PhysAddr>;

    /// Free a physical frame
    fn free_frame(&mut self, frame: Self::PhysAddr);

    /// Drop the caller's reference to a frame that a user mapping may
    /// also hold (a page-cache page mapped MAP_SHARED): freed with the
    /// last reference. Without reference counts it is `free_frame`.
    fn put_frame(&mut self, frame: Self::PhysAddr) {
        self.free_frame(frame)
    }

    /// Allocate `n` physically contiguous frames (kernel stacks, DMA
    /// buffers). None if unsupported or no such run is free.
    fn alloc_contig(&mut self, _n: usize) -> Option<Self::PhysAddr> {
        None
    }

    /// Memory is down to the low watermark: callers adding unevictable
    /// user data (ramfs pages) must fail instead
    fn reserve_low(&self) -> bool {
        false
    }
}

// ============================================================================
// Scheduler Architecture Traits
// ============================================================================

/// Per-CPU operations abstraction
///
/// This trait abstracts access to per-CPU data used by the scheduler.
/// On x86-64, this is accessed via the GS segment. On aarch64, via TPIDR_EL1.
pub trait PerCpuOps {
    /// Try to get the current CPU ID
    ///
    /// Returns None if per-CPU data is not yet initialized (early boot).
    fn try_current_cpu_id() -> Option<u32>;

    /// The running task (`*const Task`), 0 for the boot task
    /// (before the first switch, or before per-CPU data exists)
    fn current_task_ptr() -> usize;

    /// Record the task this CPU switches to (the scheduler, with the
    /// run-queue lock held; the run queue keeps it alive)
    fn set_current_task_ptr(p: usize);

    /// The task running on CPU `cpu` (`*const Task`, 0 for its
    /// boot task): a racy snapshot (Linux task_curr)
    fn current_task_ptr_of(cpu: u32) -> usize;

    /// Get the interrupt nesting depth
    fn interrupt_depth() -> u32;

    /// Whether logical CPU `cpu` has been brought online
    fn cpu_online(cpu: u32) -> bool;
}

/// CPU control operations
///
/// This trait abstracts CPU-level operations like interrupt enable/disable
/// and halt. These are used by the scheduler for idle loops and critical sections.
pub trait CpuOps {
    /// Enable interrupts
    fn enable_interrupts();

    /// Disable interrupts
    fn disable_interrupts();

    /// Halt the CPU until the next interrupt
    fn halt();

    /// Enable interrupts and halt atomically
    ///
    /// This is the STI;HLT pattern on x86-64, which ensures no interrupt
    /// window between enabling and halting.
    fn enable_and_halt();
}

/// Interrupt flag primitives behind `sync::irqflags` (Linux
/// arch_local_save_flags, arch_local_irq_save, arch_local_irq_restore,
/// arch_irqs_disabled_flags)
pub trait IrqFlagsOps {
    /// This CPU's saved interrupt state (x86 RFLAGS, arm64 DAIF)
    type Flags: Copy;

    /// The current state, unchanged
    fn local_save_flags() -> Self::Flags;

    /// Mask interrupts on this CPU, returning the previous state
    fn local_irq_save() -> Self::Flags;

    /// Restore a state saved by `local_irq_save` on this CPU
    fn local_irq_restore(flags: Self::Flags);

    /// `flags` has interrupts masked
    fn irqs_disabled_flags(flags: Self::Flags) -> bool;
}

/// The boot UART's direct output behind printk (Linux earlycon, and
/// the panic path's lockless UART writes)
pub trait EarlyConOps {
    /// printk writes the boot UART while no console is registered
    /// (Linux earlycon: arm64's PL011; x86's COM1 is a console from the
    /// start)
    const EARLYCON: bool;

    /// Write `bytes` to the boot UART, taking no lock (early boot,
    /// panic)
    fn early_write(bytes: &[u8]);
}

/// CPU cache maintenance for streaming DMA behind `hw::dma` (Linux
/// arch_sync_dma_for_device / arch_sync_dma_for_cpu); `va` is the
/// buffer's direct-map address. Coherent arches need none (default)
pub trait DmaSyncOps {
    /// A buffer is mapped for the device (dma_map_single)
    fn dma_map(_va: *const u8, _size: usize, _dir: crate::hw::dma::DmaDirection) {}
    /// A buffer is unmapped (dma_unmap_single)
    fn dma_unmap(_va: *const u8, _size: usize, _dir: crate::hw::dma::DmaDirection) {}
    /// The CPU takes a mapped buffer back (dma_sync_single_for_cpu)
    fn dma_sync_for_cpu(_va: *const u8, _size: usize, _dir: crate::hw::dma::DmaDirection) {}
    /// The device gets a mapped buffer again (dma_sync_single_for_device)
    fn dma_sync_for_device(_va: *const u8, _size: usize, _dir: crate::hw::dma::DmaDirection) {}
}

/// The device interrupt controller behind `crate::irq` (Linux struct
/// irq_chip and the arch's PCI INTx routing): device IRQs are
/// `FIRST_IRQ..FIRST_IRQ + NR_IRQS`. `irq_unmask` and `irq_mask` run
/// under the line's descriptor lock (Linux irq_startup/irq_shutdown
/// under desc->lock); state shared between lines (a mask or trigger
/// register) needs a leaf lock of the chip's
pub trait IrqChipOps {
    /// The first device IRQ number (x86 PIC line 0, arm64 SPI INTID 32)
    const FIRST_IRQ: u32;
    /// Device IRQ lines
    const NR_IRQS: usize;

    /// Configure (trigger, routing) and unmask line `irq` (its first
    /// handler came)
    fn irq_unmask(irq: u32);
    /// Mask line `irq` (its last handler went, or nobody claims it)
    fn irq_mask(irq: u32);
    /// The IRQ of a PCI function's INTx `pin` (1 = INTA, 0 = none);
    /// `line` is its config-space Interrupt Line
    fn pci_intx_irq(bus: u8, device: u8, function: u8, pin: u8, line: u8) -> Option<u32>;
}

/// Task context and context switching operations
///
/// This trait abstracts the task context structure and context switch mechanism.
/// Each architecture has its own register save format and switch implementation.
pub trait ContextOps: Sized {
    /// The task context type (callee-saved registers, etc.)
    type TaskContext: Default + Clone;

    /// An all-zero context (a static task's initial frame)
    const ZERO_CONTEXT: Self::TaskContext;

    /// Create a new kernel thread context
    ///
    /// # Arguments
    /// * `entry` - Entry point function address
    /// * `stack_top` - Top of the kernel stack (highest address)
    fn new_kernel_thread_context(entry: usize, stack_top: u64) -> Self::TaskContext;

    /// Create a clone/fork child context
    ///
    /// # Arguments
    /// * `kstack_with_trapframe` - Stack pointer where TrapFrame is located
    fn new_clone_child_context(kstack_with_trapframe: u64) -> Self::TaskContext;

    /// Switch from current task to a new task, saving current context
    ///
    /// Handles TLS save/restore in Rust before calling assembly, following
    /// the Linux kernel pattern (tls_thread_switch before cpu_switch_to):
    /// `next_tls` is the next task's user TLS register, `next_gs` its
    /// user GS base (x86-64; ignored on arm64).
    ///
    /// # Safety
    /// - `old_ctx` must point to valid, writable memory
    /// - `new_ctx` must point to a valid, previously saved context
    /// - Interrupts should be disabled during the switch
    unsafe fn context_switch(
        old_ctx: *mut Self::TaskContext,
        new_ctx: *const Self::TaskContext,
        new_kstack: u64,
        next_tls: u64,
        next_gs: u64,
    );

    /// Switch to a task without saving current context
    ///
    /// Used for the initial switch to the first task or when exiting.
    /// Handles TLS load for the new task before calling assembly.
    ///
    /// # Safety
    /// Same requirements as `context_switch`, except no saving occurs.
    unsafe fn context_switch_first(
        new_ctx: *const Self::TaskContext,
        new_kstack: u64,
        next_tls: u64,
        next_gs: u64,
    ) -> !;
}

/// User mode transition operations
///
/// This trait abstracts the mechanism for jumping to user mode.
pub trait UserModeOps {
    /// Jump to user mode
    ///
    /// # Arguments
    /// * `entry` - User entry point address
    /// * `user_stack` - User stack pointer
    /// * `kernel_stack` - Kernel stack top for syscalls/interrupts
    ///
    /// # Safety
    /// The task's address space must be loaded (`mm::tlb::switch_mm`)
    /// and map the entry point and stack. This function never returns.
    unsafe fn jump_to_user(entry: u64, user_stack: u64, kernel_stack: u64) -> !;
}

/// Combined scheduler architecture trait
///
/// This super-trait combines all the traits needed by the scheduler,
/// providing a single constraint for generic scheduler code.
///
/// # Example
/// ```ignore
/// fn switch<A: SchedArch>(old: *mut A::TaskContext, new: *const A::TaskContext) {
///     unsafe { A::context_switch(old, new, 0, 0, 0) };
/// }
/// ```
pub trait SchedArch: Arch + PerCpuOps + CpuOps + ContextOps + UserModeOps {
    /// The page table type for this architecture
    type SchedPageTable: PageTable<PhysAddr = u64, VirtAddr = u64>;

    /// Save the calling task's user FP/SIMD state for a clone child whose
    /// TrapFrame (at the top of its kernel stack) is at `regs`; returns
    /// where the child's first switch frame ends (below the saved state,
    /// or `regs` when the TrapFrame itself carries the FP state)
    ///
    /// # Safety
    /// `regs` is the TrapFrame of a kernel stack whose task has not run.
    unsafe fn clone_child_fpu(regs: u64) -> u64;
}

// ============================================================================
// Kernel Initialization Traits
// ============================================================================

/// CPU halt operations
///
/// Provides architecture-specific CPU halt functionality for error paths
/// and idle loops where the CPU should stop executing.
pub trait HaltOps {
    /// Halt the CPU forever (for panic/error paths)
    ///
    /// This function never returns. It disables interrupts and enters
    /// an infinite halt loop.
    fn halt_loop() -> !;

    /// Print this CPU's registers and stack at a panic (Linux
    /// dump_stack); nothing where the arch has no unwinder
    fn dump_stack() {}
}

/// Kernel page-table primitives behind `mm::ioremap` and vmap (the
/// swapper's kernel half; Linux's per-arch pgtable helpers and the
/// PAGE_KERNEL / ioremap protections)
pub trait IoremapOps {
    /// A kernel RAM page: writable, never executable (Linux PAGE_KERNEL)
    const PROT_KERNEL: u64;
    /// A device page (x86 uncached, arm64 Device-nGnRE)
    const PROT_DEVICE: u64;
    /// A new ioremap mapping is flushed from every CPU before use
    const FLUSH_NEW: bool;

    /// The entry is valid (a table, a huge/block entry or a page)
    fn pte_present(e: u64) -> bool;
    /// The upper entry points to a next-level table
    fn pte_is_table(e: u64) -> bool;
    /// The physical address an entry holds
    fn pte_addr(e: u64) -> u64;
    /// An upper entry pointing to the table frame `t`
    fn mk_table(t: u64) -> u64;
    /// A last-level entry mapping `pa` with `prot`
    fn mk_pte(pa: u64, prot: u64) -> u64;
    /// Make a changed last-level entry visible to the table walker
    fn sync_pte(_e: &core::sync::atomic::AtomicU64) {}
    /// A permanent device mapping of [phys, phys + size), if the arch
    /// has one (arm64's device window)
    fn io_window(_phys: u64, _size: u64) -> Option<u64> {
        None
    }
    /// `va` is in that permanent window (iounmap keeps it)
    fn in_io_window(_va: u64) -> bool {
        false
    }
}

/// Boot page-table primitives behind `mm::swapper`, with which each
/// arch's `kmap::init` (Linux paging_init) builds the kernel half
pub trait KmapOps: IoremapOps {
    /// Kernel image virtual minus physical address (`pa_symbol`)
    const KIMAGE_OFFSET: u64;
    /// Page-table pages in the static boot pool
    const POOL_PAGES: usize;
    /// A 2MB leaf entry mapping `pa` with `prot`
    fn mk_pmd(pa: u64, prot: u64) -> u64;
    /// Make kernel table writes visible to the walker before the first
    /// access (arm64 `dsb ishst; isb`)
    fn kmap_sync() {}
}

// ============================================================================
// Platform Discovery Traits and Structs
// ============================================================================

/// CPU information from platform discovery
#[derive(Debug, Clone, Copy)]
pub struct CpuInfo {
    /// Hardware CPU ID (APIC ID on x86, MPIDR on ARM)
    /// 32-bit for X2APIC support on x86-64
    pub hw_cpu_id: u32,
    /// Whether this CPU is enabled
    pub enabled: bool,
    /// Whether this is the bootstrap processor
    pub is_bsp: bool,
}

/// Power management information from ACPI/device tree
/// Fields are x86-specific (ACPI); ARM uses PSCI instead
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code, reason = "some fields are read on x86-64 only")]
pub struct PowerInfo {
    /// The FADT's power management register blocks
    pub pm: crate::hw::acpi::hw::PmRegs,
    /// SLP_TYP values for S5 (soft-off), from \_S5 in the DSDT/SSDTs
    pub s5: crate::hw::acpi::aml::SleepType,
    /// The FADT reset register, if the firmware offers one
    pub reset: Option<crate::hw::acpi::hw::ResetReg>,
}

/// Platform hardware information from ACPI or device tree
///
/// This struct provides an architecture-neutral representation of
/// hardware discovered during boot. On x86, this comes from ACPI tables.
/// On ARM, this would come from the device tree.
#[derive(Debug, Default)]
pub struct AcpiInfo {
    /// Base address of local interrupt controller (LAPIC on x86, GIC on ARM)
    pub interrupt_controller_base: u64,
    /// List of CPUs discovered
    pub cpus: Vec<CpuInfo>,
    /// Bootstrap processor CPU ID (32-bit for X2APIC support)
    pub bsp_cpu_id: u32,
    /// Power management info (if available, x86-specific)
    pub power_info: Option<PowerInfo>,
}

/// Platform hardware discovery operations
///
/// Abstracts ACPI parsing on x86 and device tree parsing on ARM
/// into a common interface for hardware discovery.
pub trait AcpiOps {
    /// Parse platform firmware tables and return hardware info
    ///
    /// Returns None if parsing fails or tables are not available.
    fn parse_acpi() -> Option<AcpiInfo>;

    /// Set up the NUMA topology from firmware (ACPI SRAT/SLIT, DT
    /// numa-node-id); false if it describes none (one node then)
    fn numa_init() -> bool;

    /// The boot framebuffer the firmware set up (multiboot2 tag, DT
    /// simple-framebuffer)
    fn boot_framebuffer() -> Option<crate::gfx::FramebufferInfo>;
}

/// Symmetric Multi-Processing operations
///
/// Handles initialization of additional CPU cores beyond the bootstrap
/// processor.
pub trait SmpOps {
    /// Initialize and start application processors
    ///
    /// # Arguments
    /// * `acpi` - Platform hardware info with CPU list
    /// * `frame_alloc` - Frame allocator for AP stacks
    ///
    /// # Returns
    /// Number of CPUs successfully brought online (including BSP)
    fn smp_init<FA: FrameAlloc<PhysAddr = u64>>(acpi: &AcpiInfo, frame_alloc: &mut FA) -> usize;

    /// Enable scheduling on application processors
    ///
    /// Called after all APs are initialized to allow them to start
    /// running scheduled tasks.
    fn enable_ap_scheduling();

    /// Set the BSP CPU ID in the ACPI info
    ///
    /// # Arguments
    /// * `acpi` - Platform hardware info to update
    /// * `hw_id` - Hardware CPU ID of the bootstrap processor
    fn set_bsp_cpu_id(acpi: &mut AcpiInfo, hw_id: u32);
}

/// Local interrupt controller and timer operations
///
/// Abstracts the local interrupt controller (LAPIC on x86, GIC redistributor
/// on ARM) and its associated per-CPU timer.
pub trait LocalTimerOps {
    /// Interrupt vector number for the local timer
    const TIMER_VECTOR: u8;

    /// Initialize the local interrupt controller
    ///
    /// # Safety
    /// The base_virt address must be a valid mapped address for the
    /// interrupt controller registers.
    ///
    /// # Arguments
    /// * `base_virt` - Virtual address of the interrupt controller
    unsafe fn init_local_interrupt_controller(base_virt: u64);

    /// Get the current CPU's hardware ID
    ///
    /// Returns APIC ID on x86 (32-bit for X2APIC), MPIDR-derived ID on ARM.
    fn current_hw_cpu_id() -> u32;

    /// Calibrate and start the local timer
    ///
    /// # Arguments
    /// * `vector` - Interrupt vector to use for timer interrupts
    /// * `interval_ms` - Timer interval in milliseconds
    ///
    /// # Returns
    /// The timer frequency in ticks per second
    fn calibrate_and_start_timer(vector: u8, interval_ms: u32) -> u32;
}

/// Clock source and RTC operations
///
/// Abstracts timekeeping hardware - high-resolution cycle counters
/// (TSC on x86, generic timer on ARM) and real-time clocks.
pub trait TimekeeperOps {
    /// Clock source type (TSC info on x86, etc.)
    type ClockSource;

    /// Initialize and detect the clock source
    ///
    /// Returns None if no suitable clock source is available.
    fn init_clock_source() -> Option<Self::ClockSource>;

    /// Get the clock source frequency in Hz
    fn clock_frequency(source: &Self::ClockSource) -> u64;

    /// Read the current cycle count
    ///
    /// Returns a monotonically increasing value suitable for
    /// measuring elapsed time.
    fn read_cycles() -> u64;

    /// Read the current time from the RTC
    ///
    /// Returns Unix timestamp (seconds since epoch).
    fn read_rtc() -> i64;
}

/// Power management operations
///
/// Provides interface for system power state transitions
/// (shutdown, reboot, sleep).
pub trait PowerOps {
    /// Initialize power management with platform info
    ///
    /// # Arguments
    /// * `info` - Power management info from ACPI/device tree
    fn power_init(info: &PowerInfo);

    /// Take the power management hardware from the firmware (Linux
    /// acpi_enable_subsystem: ACPI mode on x86), once timekeeping runs
    fn power_enable() {}
}

/// Architecture platform devices and their drivers
pub trait ArchBusOps {
    /// Register the platform devices and drivers (Linux: board files,
    /// DT platform population and the drivers' initcalls)
    fn platform_init();

    /// Set up PCI configuration space access (Linux raw_pci_ops on x86,
    /// the host bridge's ECAM window on arm64)
    fn pci_config_init();

    /// Window for the BARs the firmware left unassigned, [start, end)
    /// (x86: below the LAPIC/IOAPIC region, a fallback since the BIOS
    /// assigns them; arm64: the QEMU virt PCI MMIO window)
    const PCI_MMIO: (u64, u64);
}

// ============================================================================
// Kernel Init Unification Traits
// ============================================================================

/// Memory layout and region discovery operations
///
/// How each architecture reports physical memory (Linux setup_arch:
/// e820__memblock_setup on x86, arm64_memblock_init on arm64)
pub trait MemoryLayoutOps {
    /// Add every firmware RAM range the kernel can reach through the
    /// direct map to memblock and reserve what boot already uses there
    /// (kernel image, boot modules, DTB, initrd, firmware-reserved
    /// ranges)
    fn memblock_init();
}

/// Exception and interrupt controller initialization
///
/// Abstracts late exception/interrupt setup that happens after early_init.
/// On x86_64 this is typically a no-op since IDT/PIC are set up in early_init.
/// On aarch64 this installs exception vectors and initializes the GIC.
pub trait ExceptionOps {
    /// Initialize exception vectors and interrupt controller
    ///
    /// On x86_64: No-op (done in early_init via IDT/PIC)
    /// On aarch64: Install exception vectors + init GIC
    fn init_exceptions();
}

/// Initramfs/boot module discovery operations
///
/// Abstracts how each architecture locates the initramfs data.
/// On x86_64 this uses multiboot2 module lookup.
/// On aarch64 this uses DTB extraction or falls back to embedded initramfs.
pub trait InitramfsOps {
    /// Get initramfs data from boot information
    ///
    /// Returns a static slice containing the initramfs (cpio archive).
    /// Panics if initramfs is not found (required for boot).
    fn get_initramfs() -> &'static [u8];
}

/// Optional VFS initialization extensions
///
/// Allows architectures to perform additional VFS setup after core init.
/// On x86_64 this sets up VFAT ramdisk from multiboot2 module.
/// On aarch64 this is typically a no-op.
pub trait VfsInitOps {
    /// Additional VFS setup after core init
    ///
    /// Called after ramfs root, procfs, and /dev are initialized.
    /// Can create additional device nodes or mount points.
    /// Use fs::lookup_path() to find directories if needed.
    fn init_vfs_extras();
}
