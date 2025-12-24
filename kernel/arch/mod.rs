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
//! - [`EarlyArchInit`] - Early hardware initialization (GDT, IDT, etc.)
//! - [`IoremapOps`] - MMIO mapping operations
//! - [`AcpiOps`] - Platform hardware discovery (ACPI/device tree)
//! - [`SmpOps`] - Multi-processor initialization
//! - [`LocalTimerOps`] - Per-CPU timer operations
//! - [`TimekeeperOps`] - Clock source and RTC operations
//! - [`PowerOps`] - Power management (shutdown, reboot)
//! - [`SyscallOps`] - Syscall handler registration
//! - [`HardwareAccess`] - Driver I/O abstraction (port I/O vs MMIO)

extern crate alloc;

use alloc::vec::Vec;
use bitflags::bitflags;

use crate::task::{CurrentTask, Tid};

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

// I/O port access - x86-64 specific
// Re-exported for platform drivers (PIC, PIT, serial, PCI)
#[cfg(target_arch = "x86_64")]
#[allow(unused_imports)]
pub use x86_64::io::{inb, inl, inw, io_wait, outb, outl, outw};

// Power management
#[cfg(target_arch = "x86_64")]
pub use x86_64::power;

#[cfg(target_arch = "aarch64")]
pub use aarch64::power;

// IRQ-safe spinlock - architecture-specific implementation
#[cfg(target_arch = "x86_64")]
pub use x86_64::spinlock::IrqSpinlock;

#[cfg(target_arch = "aarch64")]
pub use aarch64::spinlock::IrqSpinlock;

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

/// Architecture abstraction trait
pub trait Arch {
    /// Trap frame type for saving/restoring CPU state
    type TrapFrame: Default + Clone;
    /// Virtual address type
    type VirtAddr: Copy + Eq;
    /// Physical address type
    type PhysAddr: Copy + Eq;

    /// Start of user address space
    const USER_START: Self::VirtAddr;
    /// End of user address space
    const USER_END: Self::VirtAddr;

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

    /// Map a virtual address to a physical address with given flags
    ///
    /// Note: This assumes intermediate page tables already exist.
    /// For general use, prefer `map_with_alloc`.
    fn map(&mut self, va: Self::VirtAddr, pa: Self::PhysAddr, flags: PageFlags);

    /// Unmap a virtual address
    fn unmap(&mut self, va: Self::VirtAddr);

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

    /// Create a page table representing the current kernel identity mapping
    ///
    /// This uses the currently active page table (e.g., CR3 on x86-64).
    /// No new allocation is performed.
    fn kernel_identity() -> Self;

    /// Collect all page table frame addresses (for freeing)
    ///
    /// Walks the page table hierarchy and collects all intermediate table
    /// frame addresses (not the mapped user pages, just the table frames).
    /// Used to free page table memory during exec() or process exit.
    ///
    /// Returns a vector of physical addresses of all page table frames,
    /// including the root table.
    fn collect_table_frames(&self) -> alloc::vec::Vec<Self::PhysAddr>;
}

/// Frame allocator trait
pub trait FrameAlloc {
    type PhysAddr;

    /// Allocate a physical frame
    fn alloc_frame(&mut self) -> Option<Self::PhysAddr>;

    /// Free a physical frame
    fn free_frame(&mut self, frame: Self::PhysAddr);
}

// ============================================================================
// Scheduler Architecture Traits
// ============================================================================

/// Per-CPU operations abstraction
///
/// This trait abstracts access to per-CPU data used by the scheduler.
/// On x86-64, this is accessed via the GS segment. On aarch64, via TPIDR_EL1.
#[allow(dead_code)]
pub trait PerCpuOps {
    /// Maximum number of CPUs supported by this architecture
    const MAX_CPUS: usize;

    /// Try to get the current CPU ID
    ///
    /// Returns None if per-CPU data is not yet initialized (early boot).
    fn try_current_cpu_id() -> Option<u32>;

    /// Get the current thread ID from per-CPU data
    ///
    /// Returns 0 if no task is running or per-CPU not initialized.
    fn current_tid() -> Tid;

    /// Set the current thread ID in per-CPU data
    fn set_current_tid(tid: Tid);

    /// Check if reschedule is needed on this CPU
    fn needs_reschedule() -> bool;

    /// Clear the reschedule flag, returning its previous value
    fn clear_needs_reschedule() -> bool;

    /// Set the reschedule flag
    fn set_needs_reschedule(val: bool);

    /// Get the interrupt nesting depth
    fn interrupt_depth() -> u32;

    /// Get the current task context (credentials, pid, etc.)
    fn get_current_task() -> CurrentTask;

    /// Set the current task context
    fn set_current_task(task: &CurrentTask);

    /// Get saved syscall user RIP (return address for clone/fork)
    fn get_syscall_user_rip() -> u64;

    /// Get saved syscall user RFLAGS
    fn get_syscall_user_rflags() -> u64;

    /// Get saved syscall user RSP (stack pointer for fork)
    fn get_syscall_user_rsp() -> u64;
}

/// CPU control operations
///
/// This trait abstracts CPU-level operations like interrupt enable/disable
/// and halt. These are used by the scheduler for idle loops and critical sections.
#[allow(dead_code)]
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

/// Task context and context switching operations
///
/// This trait abstracts the task context structure and context switch mechanism.
/// Each architecture has its own register save format and switch implementation.
#[allow(dead_code)]
pub trait ContextOps: Sized {
    /// The task context type (callee-saved registers, etc.)
    type TaskContext: Default + Clone;

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
    /// the Linux kernel pattern (tls_thread_switch before cpu_switch_to).
    ///
    /// # Safety
    /// - `old_ctx` must point to valid, writable memory
    /// - `new_ctx` must point to a valid, previously saved context
    /// - Interrupts should be disabled during the switch
    unsafe fn context_switch(
        old_ctx: *mut Self::TaskContext,
        new_ctx: *const Self::TaskContext,
        new_kstack: u64,
        new_page_table_root: u64,
        next_tid: Tid,
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
        new_page_table_root: u64,
        next_tid: Tid,
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
    /// * `page_table_root` - Physical address of user page table
    /// * `kernel_stack` - Kernel stack top for syscalls/interrupts
    ///
    /// # Safety
    /// The page table must be valid and contain proper user mappings.
    /// This function never returns.
    unsafe fn jump_to_user(
        entry: u64,
        user_stack: u64,
        page_table_root: u64,
        kernel_stack: u64,
    ) -> !;
}

/// Combined scheduler architecture trait
///
/// This super-trait combines all the traits needed by the scheduler,
/// providing a single constraint for generic scheduler code.
///
/// # Example
/// ```ignore
/// fn schedule<A: SchedArch>() {
///     if A::needs_reschedule() {
///         // ... perform context switch using A::context_switch()
///     }
/// }
/// ```
pub trait SchedArch: Arch + PerCpuOps + CpuOps + ContextOps + UserModeOps {
    /// The page table type for this architecture
    type SchedPageTable: PageTable<PhysAddr = u64, VirtAddr = u64>;

    /// Build a child TrapFrame for clone/fork
    ///
    /// Creates the trap frame that will be placed on the child's kernel stack.
    /// When the child is scheduled, it will restore this frame and return to
    /// user mode with a return value of 0.
    ///
    /// # Arguments
    /// * `parent_rip` - Parent's user return address
    /// * `parent_rflags` - Parent's user flags
    /// * `child_rsp` - Child's user stack pointer
    fn clone_child_trapframe(
        parent_rip: u64,
        parent_rflags: u64,
        child_rsp: u64,
    ) -> Self::TrapFrame;
}

// ============================================================================
// Kernel Initialization Traits
// ============================================================================

/// CPU halt operations
///
/// Provides architecture-specific CPU halt functionality for error paths
/// and idle loops where the CPU should stop executing.
#[allow(dead_code)]
pub trait HaltOps {
    /// Halt the CPU forever (for panic/error paths)
    ///
    /// This function never returns. It disables interrupts and enters
    /// an infinite halt loop.
    fn halt_loop() -> !;
}

/// Early architecture initialization
///
/// Called early in boot before the kernel heap is available.
/// Initializes fundamental hardware needed for kernel operation.
#[allow(dead_code)]
pub trait EarlyArchInit {
    /// Initialize architecture-specific hardware
    ///
    /// On x86-64: GDT, TSS, IDT, PIC, PIT, syscall MSRs, FPU/SSE, SMEP/SMAP
    /// On aarch64: Exception vectors, MMU setup, GIC init
    fn early_init();
}

/// MMIO mapping operations
///
/// Provides architecture-independent interface for mapping device memory
/// into the kernel's virtual address space.
#[allow(dead_code)]
pub trait IoremapOps {
    /// Error type for ioremap operations
    type IoremapError: core::fmt::Debug;

    /// Initialize the ioremap subsystem
    fn ioremap_init();

    /// Map physical device memory into kernel virtual address space
    ///
    /// # Arguments
    /// * `phys_addr` - Physical address of device memory
    /// * `size` - Size of the region to map in bytes
    ///
    /// # Returns
    /// Virtual address pointer to the mapped region, or error
    fn ioremap(phys_addr: u64, size: u64) -> Result<*mut u8, Self::IoremapError>;

    /// Unmap a previously mapped device memory region
    ///
    /// # Arguments
    /// * `virt_addr` - Virtual address returned by ioremap
    /// * `size` - Size of the region (must match ioremap call)
    fn iounmap(virt_addr: *mut u8, size: u64);
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
#[allow(dead_code)]
pub struct PowerInfo {
    /// PM1a control block I/O port (x86 ACPI)
    pub pm1a_cnt_blk: u16,
    /// PM1b control block I/O port (optional)
    pub pm1b_cnt_blk: Option<u16>,
    /// Sleep type value for S5 (shutdown)
    pub slp_typa: u8,
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
    #[allow(dead_code)]
    pub power_info: Option<PowerInfo>,
}

/// Platform hardware discovery operations
///
/// Abstracts ACPI parsing on x86 and device tree parsing on ARM
/// into a common interface for hardware discovery.
#[allow(dead_code)]
pub trait AcpiOps {
    /// Parse platform firmware tables and return hardware info
    ///
    /// Returns None if parsing fails or tables are not available.
    fn parse_acpi() -> Option<AcpiInfo>;
}

/// Symmetric Multi-Processing operations
///
/// Handles initialization of additional CPU cores beyond the bootstrap
/// processor.
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
pub trait TimekeeperOps {
    /// Clock source type (TSC info on x86, etc.)
    type ClockSource;

    /// Initialize and detect the clock source
    ///
    /// Returns None if no suitable clock source is available.
    fn init_clock_source() -> Option<Self::ClockSource>;

    /// Get the clock source frequency in Hz
    fn clock_frequency(source: &Self::ClockSource) -> u64;

    /// Check if the clock source is reliable
    ///
    /// Returns false if the clock may drift or be unreliable
    /// (e.g., TSC on older CPUs that don't support invariant TSC).
    fn clock_is_reliable(source: &Self::ClockSource) -> bool;

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
#[allow(dead_code)]
pub trait PowerOps {
    /// Initialize power management with platform info
    ///
    /// # Arguments
    /// * `info` - Power management info from ACPI/device tree
    fn power_init(info: &PowerInfo);
}

/// Syscall mechanism operations
///
/// Abstracts the syscall entry/exit mechanism. On x86-64 this is
/// the SYSCALL/SYSRET instructions, on ARM64 it's SVC.
#[allow(dead_code)]
pub trait SyscallOps {
    /// Syscall handler function type
    type SyscallHandler: Copy;

    /// Register the syscall handler
    ///
    /// # Arguments
    /// * `handler` - Function to call on syscall entry
    fn set_syscall_handler(handler: Self::SyscallHandler);

    /// Get the default syscall dispatcher function
    fn syscall_dispatcher() -> Self::SyscallHandler;
}

/// Timer preemption callback setup
///
/// Allows the kernel to register a callback that is invoked from
/// the timer interrupt handler to check for preemption.
#[allow(dead_code)]
pub trait TimerCallbackOps {
    /// Set the timer preemption callback
    ///
    /// # Safety
    /// Must be called once during kernel initialization before
    /// interrupts are enabled.
    ///
    /// # Arguments
    /// * `callback` - Function to call from timer interrupt
    unsafe fn set_timer_preempt_callback(callback: fn());
}

/// Architecture-specific bus and driver initialization
///
/// Called after the bus manager is created to register platform-specific
/// buses and drivers.
#[allow(dead_code)]
pub trait ArchBusOps {
    /// Initialize architecture-specific buses and drivers
    ///
    /// # Arguments
    /// * `bus_manager` - The kernel's bus manager to register with
    fn arch_bus_init(bus_manager: &mut crate::bus::BusManager);
}

// ============================================================================
// Kernel Init Unification Traits
// ============================================================================

/// Memory layout and region discovery operations
///
/// Abstracts how each architecture discovers its memory layout for
/// frame allocation. On x86_64 this uses multiboot2 memory maps,
/// on aarch64 this uses hardcoded constants (or DTB in the future).
#[allow(dead_code)]
pub trait MemoryLayoutOps {
    /// Get the frame allocator base address and size
    ///
    /// Returns (base, size) where base is the physical address to start
    /// frame allocation from, and size is the total bytes available.
    fn get_frame_alloc_region() -> (u64, u64);
}

/// Exception and interrupt controller initialization
///
/// Abstracts late exception/interrupt setup that happens after early_init.
/// On x86_64 this is typically a no-op since IDT/PIC are set up in early_init.
/// On aarch64 this installs exception vectors and initializes the GIC.
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
pub trait VfsInitOps {
    /// Additional VFS setup after core init
    ///
    /// Called after ramfs root, procfs, and /dev are initialized.
    /// Can create additional device nodes or mount points.
    /// Use fs::lookup_path() to find directories if needed.
    fn init_vfs_extras();
}
