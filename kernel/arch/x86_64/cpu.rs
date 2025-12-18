//! CPU initialization (GDT, TSS, CPUID, FPU/SSE)
//!
//! Sets up the Global Descriptor Table and Task State Segment
//! for x86-64 long mode operation. Also verifies CPU features
//! and initializes FPU/SSE.

use ::core::mem::size_of;
use ::core::sync::atomic::{AtomicU16, AtomicU64, Ordering};

/// Saved kernel GDT pointer (set by BSP for APs to use)
static KERNEL_GDT_LIMIT: AtomicU16 = AtomicU16::new(0);
static KERNEL_GDT_BASE: AtomicU64 = AtomicU64::new(0);

/// Saved kernel IDT pointer (set by BSP for APs to use)
static KERNEL_IDT_LIMIT: AtomicU16 = AtomicU16::new(0);
static KERNEL_IDT_BASE: AtomicU64 = AtomicU64::new(0);

/// IST indices (1-based as used in IDT)
pub const IST_DOUBLE_FAULT: u8 = 1;
pub const IST_NMI: u8 = 2;

/// Execute CPUID instruction
///
/// Note: We need to preserve rbx since LLVM uses it internally.
/// We push/pop it manually in the asm block.
fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let (eax, ebx, ecx, edx): (u32, u32, u32, u32);
    unsafe {
        ::core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inout("eax") leaf => eax,
            inout("ecx") subleaf => ecx,
            ebx_out = out(reg) ebx,
            lateout("edx") edx,
        );
    }
    (eax, ebx, ecx, edx)
}

/// EFER MSR address
const MSR_EFER: u32 = 0xC0000080;
/// EFER.NXE bit (enables NX/XD bit in page tables)
const EFER_NXE: u64 = 1 << 11;

/// Read a Model Specific Register
#[inline]
fn rdmsr(msr: u32) -> u64 {
    let (low, high): (u32, u32);
    unsafe {
        ::core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((high as u64) << 32) | (low as u64)
}

/// Write a Model Specific Register
#[inline]
fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    unsafe {
        ::core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") low,
            in("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Check required CPU features, panic if missing
pub fn check_cpu_features() {
    // Check extended CPUID support
    let (max_ext, _, _, _) = cpuid(0x80000000, 0);
    if max_ext < 0x80000001 {
        panic!("CPU does not support extended CPUID");
    }

    // Check x86-64 (long mode) and NX support
    let (_, _, _, edx) = cpuid(0x80000001, 0);
    if edx & (1 << 29) == 0 {
        panic!("CPU does not support x86-64 long mode");
    }
    if edx & (1 << 20) == 0 {
        panic!("CPU does not support NX bit");
    }

    // Check SSE2 support (leaf 1, edx bit 26)
    let (_, _, _, edx) = cpuid(0x1, 0);
    if edx & (1 << 26) == 0 {
        panic!("CPU does not support SSE2");
    }
}

/// Enable the NX (No-Execute) bit in page tables
///
/// This sets EFER.NXE which allows the use of the NX bit in page table entries.
/// Must be called after verifying NX support via check_cpu_features().
pub fn enable_nx() {
    let efer = rdmsr(MSR_EFER);
    if efer & EFER_NXE == 0 {
        wrmsr(MSR_EFER, efer | EFER_NXE);
    }
}

/// Initialize FPU and SSE
pub fn init_fpu_sse() {
    unsafe {
        // CR0: Clear EM (bit 2), set MP (bit 1)
        let mut cr0: u64;
        ::core::arch::asm!("mov {}, cr0", out(reg) cr0);
        cr0 &= !(1 << 2); // Clear EM (emulation)
        cr0 |= 1 << 1; // Set MP (monitor coprocessor)
        ::core::arch::asm!("mov cr0, {}", in(reg) cr0);

        // CR4: Set OSFXSR (bit 9) and OSXMMEXCPT (bit 10)
        let mut cr4: u64;
        ::core::arch::asm!("mov {}, cr4", out(reg) cr4);
        cr4 |= (1 << 9) | (1 << 10);
        ::core::arch::asm!("mov cr4, {}", in(reg) cr4);

        // Initialize FPU
        ::core::arch::asm!("fninit");
    }
}

/// GDT segment selectors
pub const KERNEL_CODE_SELECTOR: u16 = 0x08; // Index 1, RPL 0
pub const KERNEL_DATA_SELECTOR: u16 = 0x10; // Index 2, RPL 0
pub const USER_DATA_SELECTOR: u16 = 0x1B; // Index 3, RPL 3
pub const USER_CODE_SELECTOR: u16 = 0x23; // Index 4, RPL 3
pub const TSS_SELECTOR: u16 = 0x28; // Index 5, RPL 0

/// GDT entry flags
const GDT_ACCESSED: u64 = 1 << 40;
const GDT_WRITABLE: u64 = 1 << 41; // For data segments
const GDT_EXECUTABLE: u64 = 1 << 43; // Code segment
const GDT_USER_SEGMENT: u64 = 1 << 44; // Not a system segment
const GDT_PRESENT: u64 = 1 << 47;
const GDT_LONG_MODE: u64 = 1 << 53; // 64-bit code segment
const GDT_DPL_RING3: u64 = 3 << 45; // Ring 3 privilege

/// Kernel code segment descriptor
const KERNEL_CODE: u64 =
    GDT_ACCESSED | GDT_WRITABLE | GDT_EXECUTABLE | GDT_USER_SEGMENT | GDT_PRESENT | GDT_LONG_MODE;

/// Kernel data segment descriptor
const KERNEL_DATA: u64 = GDT_ACCESSED | GDT_WRITABLE | GDT_USER_SEGMENT | GDT_PRESENT;

/// User data segment descriptor (Ring 3)
const USER_DATA: u64 = GDT_ACCESSED | GDT_WRITABLE | GDT_USER_SEGMENT | GDT_PRESENT | GDT_DPL_RING3;

/// User code segment descriptor (Ring 3)
const USER_CODE: u64 = GDT_ACCESSED
    | GDT_WRITABLE
    | GDT_EXECUTABLE
    | GDT_USER_SEGMENT
    | GDT_PRESENT
    | GDT_LONG_MODE
    | GDT_DPL_RING3;

/// Task State Segment
#[repr(C, packed)]
pub struct TaskStateSegment {
    reserved1: u32,
    /// Stack pointers for privilege level changes (RSP0-RSP2)
    pub privilege_stack_table: [u64; 3],
    reserved2: u64,
    /// Interrupt stack table (IST1-IST7)
    pub interrupt_stack_table: [u64; 7],
    reserved3: u64,
    reserved4: u16,
    /// I/O permission bitmap offset
    pub iomap_base: u16,
}

impl TaskStateSegment {
    pub const fn new() -> Self {
        Self {
            reserved1: 0,
            privilege_stack_table: [0; 3],
            reserved2: 0,
            interrupt_stack_table: [0; 7],
            reserved3: 0,
            reserved4: 0,
            iomap_base: size_of::<TaskStateSegment>() as u16,
        }
    }
}

impl Default for TaskStateSegment {
    fn default() -> Self {
        Self::new()
    }
}

/// GDT with null, kernel code/data, user code/data, and TSS
#[repr(C, packed)]
struct Gdt {
    null: u64,
    kernel_code: u64,
    kernel_data: u64,
    user_data: u64,
    user_code: u64,
    tss_low: u64,
    tss_high: u64,
}

/// GDT pointer for LGDT instruction
#[repr(C, packed)]
struct GdtPointer {
    limit: u16,
    base: u64,
}

/// Static GDT - initialized at runtime
static mut GDT: Gdt = Gdt {
    null: 0,
    kernel_code: KERNEL_CODE,
    kernel_data: KERNEL_DATA,
    user_data: USER_DATA,
    user_code: USER_CODE,
    tss_low: 0,  // Set at runtime
    tss_high: 0, // Set at runtime
};

/// Static TSS
static mut TSS: TaskStateSegment = TaskStateSegment::new();

/// Kernel stack size (16KB, matches Linux x86-64 THREAD_SIZE)
pub const KERNEL_STACK_SIZE: usize = 16384;

/// Kernel stack for interrupts
#[repr(C, align(16))]
struct KernelStack([u8; KERNEL_STACK_SIZE]);

static mut KERNEL_STACK: KernelStack = KernelStack([0; KERNEL_STACK_SIZE]);

/// IST stack size (4KB each)
const IST_STACK_SIZE: usize = 4096;

/// IST stack type
#[repr(C, align(16))]
struct IstStack([u8; IST_STACK_SIZE]);

/// Double fault stack (IST1)
static mut DOUBLE_FAULT_STACK: IstStack = IstStack([0; IST_STACK_SIZE]);

/// NMI stack (IST2)
static mut NMI_STACK: IstStack = IstStack([0; IST_STACK_SIZE]);

/// Create a TSS descriptor (128 bits split into two 64-bit entries)
fn create_tss_descriptor(tss_addr: u64) -> (u64, u64) {
    let tss_size = (size_of::<TaskStateSegment>() - 1) as u64;

    let mut low: u64 = 0;
    // Limit bits 0-15
    low |= tss_size & 0xFFFF;
    // Base bits 0-23
    low |= (tss_addr & 0xFFFFFF) << 16;
    // Type (0x9 = 64-bit TSS available)
    low |= 0x9 << 40;
    // Present
    low |= 1 << 47;
    // Limit bits 16-19
    low |= ((tss_size >> 16) & 0xF) << 48;
    // Base bits 24-31
    low |= ((tss_addr >> 24) & 0xFF) << 56;

    // High 64 bits: base bits 32-63
    let high = tss_addr >> 32;

    (low, high)
}

/// Initialize the GDT and load it
pub fn init_gdt() {
    unsafe {
        // Set up kernel stack in TSS
        let stack_top = (&raw const KERNEL_STACK)
            .cast::<u8>()
            .add(KERNEL_STACK_SIZE) as u64;
        TSS.privilege_stack_table[0] = stack_top; // RSP0 for syscalls/interrupts

        // Set up IST stacks for critical exceptions
        let df_stack_top = (&raw const DOUBLE_FAULT_STACK)
            .cast::<u8>()
            .add(IST_STACK_SIZE) as u64;
        let nmi_stack_top = (&raw const NMI_STACK).cast::<u8>().add(IST_STACK_SIZE) as u64;
        TSS.interrupt_stack_table[0] = df_stack_top; // IST1 for double fault
        TSS.interrupt_stack_table[1] = nmi_stack_top; // IST2 for NMI

        // Create TSS descriptor
        let tss_addr = &raw const TSS as u64;
        let (tss_low, tss_high) = create_tss_descriptor(tss_addr);
        GDT.tss_low = tss_low;
        GDT.tss_high = tss_high;

        // Load GDT
        let gdt_ptr = GdtPointer {
            limit: (size_of::<Gdt>() - 1) as u16,
            base: &raw const GDT as u64,
        };

        ::core::arch::asm!(
            "lgdt [{}]",
            in(reg) &gdt_ptr,
            options(nostack)
        );

        // Reload segment registers
        // CS requires a far jump, others can use mov
        ::core::arch::asm!(
            // Push new CS and return address, then retfq
            "push {cs}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            // Reload data segments
            "mov ds, {ds:x}",
            "mov es, {ds:x}",
            "mov fs, {ds:x}",
            "mov gs, {ds:x}",
            "mov ss, {ds:x}",
            cs = in(reg) KERNEL_CODE_SELECTOR as u64,
            ds = in(reg) KERNEL_DATA_SELECTOR as u32,
            tmp = lateout(reg) _,
            options(preserves_flags)
        );

        // Load TSS
        ::core::arch::asm!(
            "ltr {0:x}",
            in(reg) TSS_SELECTOR,
            options(nostack, preserves_flags)
        );
    }
}

/// Set the kernel stack pointer in TSS (for context switches)
///
/// Called from switch_to.S assembly during context switch.
#[unsafe(no_mangle)]
pub extern "C" fn set_kernel_stack(stack_top: u64) {
    unsafe {
        TSS.privilege_stack_table[0] = stack_top;
    }
}

/// Get current kernel stack pointer from TSS
pub fn get_kernel_stack() -> u64 {
    unsafe { TSS.privilege_stack_table[0] }
}

/// Read the current CR3 value (page table root)
pub fn read_cr3() -> u64 {
    let cr3: u64;
    unsafe {
        ::core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3
}

/// Get the current GDT pointer (limit and base)
pub fn get_gdt_ptr() -> (u16, u64) {
    #[repr(C, packed)]
    struct GdtPtr {
        limit: u16,
        base: u64,
    }

    let mut ptr = GdtPtr { limit: 0, base: 0 };
    unsafe {
        ::core::arch::asm!("sgdt [{}]", in(reg) &mut ptr, options(nostack));
    }
    (ptr.limit, ptr.base)
}

/// Get the current IDT pointer (limit and base)
pub fn get_idt_ptr() -> (u16, u64) {
    #[repr(C, packed)]
    struct IdtPtr {
        limit: u16,
        base: u64,
    }

    let mut ptr = IdtPtr { limit: 0, base: 0 };
    unsafe {
        ::core::arch::asm!("sidt [{}]", in(reg) &mut ptr, options(nostack));
    }
    (ptr.limit, ptr.base)
}

/// Load a GDT from raw pointer values
///
/// # Safety
/// The GDT must be valid and properly formatted.
pub unsafe fn load_gdt_raw(limit: u16, base: u64) {
    #[repr(C, packed)]
    struct GdtPtr {
        limit: u16,
        base: u64,
    }

    let ptr = GdtPtr { limit, base };
    unsafe {
        ::core::arch::asm!(
            "lgdt [{}]",
            in(reg) &ptr,
            options(nostack)
        );

        // Reload segment registers
        ::core::arch::asm!(
            "push {cs}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            "mov ds, {ds:x}",
            "mov es, {ds:x}",
            "mov ss, {ds:x}",
            cs = in(reg) KERNEL_CODE_SELECTOR as u64,
            ds = in(reg) KERNEL_DATA_SELECTOR as u32,
            tmp = lateout(reg) _,
            options(preserves_flags)
        );
    }
}

/// Load an IDT from raw pointer values
///
/// # Safety
/// The IDT must be valid and properly formatted.
pub unsafe fn load_idt_raw(limit: u16, base: u64) {
    #[repr(C, packed)]
    struct IdtPtr {
        limit: u16,
        base: u64,
    }

    let ptr = IdtPtr { limit, base };
    unsafe {
        ::core::arch::asm!(
            "lidt [{}]",
            in(reg) &ptr,
            options(nostack)
        );
    }
}

/// Save the kernel's GDT pointer for APs to use
/// Should be called by BSP after GDT is set up
pub fn save_kernel_gdt_for_aps() {
    let (limit, base) = get_gdt_ptr();
    KERNEL_GDT_LIMIT.store(limit, Ordering::SeqCst);
    KERNEL_GDT_BASE.store(base, Ordering::SeqCst);
}

/// Save the kernel's IDT pointer for APs to use
/// Should be called by BSP after IDT is set up
pub fn save_kernel_idt_for_aps() {
    let (limit, base) = get_idt_ptr();
    KERNEL_IDT_LIMIT.store(limit, Ordering::SeqCst);
    KERNEL_IDT_BASE.store(base, Ordering::SeqCst);
}

/// Reload the kernel's GDT on the current CPU
/// Used by APs after they've initialized with the trampoline's minimal GDT
pub fn reload_gdt() {
    let limit = KERNEL_GDT_LIMIT.load(Ordering::SeqCst);
    let base = KERNEL_GDT_BASE.load(Ordering::SeqCst);
    if limit == 0 || base == 0 {
        // GDT not saved yet, use current (for BSP)
        let (limit, base) = get_gdt_ptr();
        unsafe {
            load_gdt_raw(limit, base);
        }
    } else {
        unsafe {
            load_gdt_raw(limit, base);
        }
    }
}

/// Reload the kernel's IDT on the current CPU
/// Used by APs after startup
pub fn reload_idt() {
    let limit = KERNEL_IDT_LIMIT.load(Ordering::SeqCst);
    let base = KERNEL_IDT_BASE.load(Ordering::SeqCst);
    if limit == 0 || base == 0 {
        // IDT not saved yet, use current (for BSP)
        let (limit, base) = get_idt_ptr();
        unsafe {
            load_idt_raw(limit, base);
        }
    } else {
        unsafe {
            load_idt_raw(limit, base);
        }
    }
}
