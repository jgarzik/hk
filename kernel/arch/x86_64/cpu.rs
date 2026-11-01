//! CPU initialization (GDT, TSS, CPUID, FPU/SSE)
//!
//! Sets up the Global Descriptor Table and Task State Segment
//! for x86-64 long mode operation. Also verifies CPU features
//! and initializes FPU/SSE.
//!
//! Every CPU has its own GDT and TSS (Linux per-CPU gdt_page and
//! cpu_tss_rw): the TSS holds this CPU's RSP0 (the kernel stack an
//! interrupt from user mode switches to) and its IST stacks, and a
//! TSS is marked busy by `ltr` in the GDT that names it.

use ::core::cell::UnsafeCell;
use ::core::mem::size_of;

use crate::cpu::PerCpu;

/// IST indices (1-based as used in IDT): the exceptions that must not
/// run on the interrupted stack (it may be the one that overflowed, or
/// not yet the kernel's: Linux DOUBLE_FAULT_STACK, NMI_STACK, MCE_STACK)
pub const IST_DOUBLE_FAULT: u8 = 1;
pub const IST_NMI: u8 = 2;
pub const IST_MCE: u8 = 3;

/// IST stacks per CPU (one per index above)
const IST_COUNT: usize = 3;

/// Execute CPUID instruction
///
/// Note: We need to preserve rbx since LLVM uses it internally.
/// We push/pop it manually in the asm block.
pub(crate) fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
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
    // RDTSCP: TSC_AUX holds the CPU index (user getcpu via RDTSCP/RDPID)
    if edx & (1 << 27) == 0 {
        panic!("CPU does not support RDTSCP");
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

impl Gdt {
    const fn new() -> Self {
        Self {
            null: 0,
            kernel_code: KERNEL_CODE,
            kernel_data: KERNEL_DATA,
            user_data: USER_DATA,
            user_code: USER_CODE,
            tss_low: 0,
            tss_high: 0,
        }
    }
}

/// One CPU's descriptor tables
struct CpuTables {
    gdt: Gdt,
    tss: TaskStateSegment,
}

/// The descriptor tables of one CPU, written only by that CPU (its own
/// RSP0) or by the boot CPU before that CPU starts (IST stacks)
struct TablesCell(UnsafeCell<CpuTables>);

// SAFETY: see TablesCell
unsafe impl Sync for TablesCell {}

static TABLES: PerCpu<TablesCell> = crate::percpu![TablesCell(UnsafeCell::new(CpuTables {
    gdt: Gdt::new(),
    tss: TaskStateSegment::new(),
}))];

/// Size of each IST stack (16KB: the double-fault handler reports a
/// kernel stack overflow and panics on it)
pub const IST_STACK_SIZE: usize = 16384;

/// IST stack type
#[repr(C, align(16))]
struct IstStack([u8; IST_STACK_SIZE]);

/// The boot CPU's IST stacks (it sets up its tables before the frame
/// allocator exists; the APs get theirs from `alloc_ist`)
static mut BOOT_IST: [IstStack; IST_COUNT] = [const { IstStack([0; IST_STACK_SIZE]) }; IST_COUNT];

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

/// CPU `cpu`'s tables
fn tables(cpu: u32) -> *mut CpuTables {
    TABLES.get(cpu).0.get()
}

/// Give CPU `cpu` its IST stacks (tops of `IST_COUNT` stacks)
fn set_ist(cpu: u32, tops: [u64; IST_COUNT]) {
    // SAFETY: `cpu` is not running yet (or is the caller, at boot)
    let tss = unsafe { &mut (*tables(cpu)).tss };
    let mut ist = tss.interrupt_stack_table;
    ist[..IST_COUNT].copy_from_slice(&tops);
    tss.interrupt_stack_table = ist;
}

/// Allocate the IST stacks of AP `cpu` before it starts (Linux
/// cpu_entry_area exception stacks); false if out of memory
pub fn alloc_ist<F: crate::arch::FrameAlloc<PhysAddr = u64>>(cpu: u32, fa: &mut F) -> bool {
    let pages = IST_STACK_SIZE / 4096;
    let mut tops = [0u64; IST_COUNT];
    for t in tops.iter_mut() {
        let Some(phys) = fa.alloc_contig(pages) else {
            return false;
        };
        let base = super::paging::phys_to_virt(phys);
        unsafe { core::ptr::write_bytes(base, 0, IST_STACK_SIZE) };
        *t = base as u64 + IST_STACK_SIZE as u64;
    }
    set_ist(cpu, tops);
    true
}

/// Load CPU `cpu`'s GDT and TSS on this CPU (Linux cpu_init:
/// load_direct_gdt, load_TR_desc): its TSS descriptor in its own GDT,
/// CS/SS/DS/ES reloaded (FS and GS keep their bases: GS is the
/// per-CPU base), then `ltr`
pub fn load_tables(cpu: u32) {
    let t = tables(cpu);
    unsafe {
        let tss_addr = &raw const (*t).tss as u64;
        let (tss_low, tss_high) = create_tss_descriptor(tss_addr);
        (*t).gdt.tss_low = tss_low;
        (*t).gdt.tss_high = tss_high;
        load_gdt_raw((size_of::<Gdt>() - 1) as u16, &raw const (*t).gdt as u64);
        ::core::arch::asm!(
            "ltr {0:x}",
            in(reg) TSS_SELECTOR,
            options(nostack, preserves_flags)
        );
    }
}

/// Initialize the boot CPU's GDT and TSS (early boot, before per-CPU
/// data: CPU 0's tables) and clear the data segment registers
pub fn init_gdt() {
    let tops = core::array::from_fn(|i| unsafe {
        (&raw const BOOT_IST[i]).cast::<u8>().add(IST_STACK_SIZE) as u64
    });
    set_ist(0, tops);
    load_tables(0);
    // FS and GS hold the kernel data selector (their bases are set by
    // MSR later: GS is the per-CPU base, FS the user TLS)
    unsafe {
        ::core::arch::asm!(
            "mov fs, {ds:x}",
            "mov gs, {ds:x}",
            ds = in(reg) KERNEL_DATA_SELECTOR as u32,
            options(nostack, preserves_flags)
        );
    }
}

/// Set the kernel stack an entry from user mode switches to on this
/// CPU: RSP0 in its TSS (interrupts, exceptions) and the per-CPU
/// top_of_stack (`syscall_entry`); called from switch_to.S at every
/// context switch. A kernel thread (`stack_top == 0`) never runs in
/// user mode and leaves both alone.
#[unsafe(no_mangle)]
pub extern "C" fn set_kernel_stack(stack_top: u64) {
    if stack_top == 0 {
        return;
    }
    // SAFETY: this CPU's own TSS and per-CPU data
    unsafe {
        (*tables(crate::cpu::this_id())).tss.privilege_stack_table[0] = stack_top;
        super::percpu::current_cpu_mut().top_of_stack = stack_top;
    }
}

/// Load a GDT from raw pointer values
///
/// # Safety
/// The GDT must be valid and properly formatted.
unsafe fn load_gdt_raw(limit: u16, base: u64) {
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

/// ELF auxv AT_HWCAP: CPUID.1:EDX (Linux ELF_HWCAP on x86-64)
pub fn elf_hwcap() -> u64 {
    core::arch::x86_64::__cpuid(1).edx as u64
}

/// ELF auxv AT_PLATFORM string
pub const ELF_PLATFORM: &[u8] = b"x86_64";

/// A hardware random seed (Linux arch_get_random_seed_longs): RDSEED,
/// else RDRAND, each retried a few times as they may underflow; None if
/// the CPU has neither
pub fn arch_random_seed() -> Option<u64> {
    let rdseed = cpuid(7, 0).1 & (1 << 18) != 0;
    let rdrand = cpuid(1, 0).2 & (1 << 30) != 0;
    for _ in 0..10 {
        let (v, ok): (u64, u8);
        if rdseed {
            // SAFETY: RDSEED is present (CPUID.7.0:EBX[18])
            unsafe {
                ::core::arch::asm!("rdseed {}", "setc {}", out(reg) v, out(reg_byte) ok, options(nomem, nostack))
            };
        } else if rdrand {
            // SAFETY: RDRAND is present (CPUID.1:ECX[30])
            unsafe {
                ::core::arch::asm!("rdrand {}", "setc {}", out(reg) v, out(reg_byte) ok, options(nomem, nostack))
            };
        } else {
            return None;
        }
        if ok != 0 {
            return Some(v);
        }
    }
    None
}

/// A fast-changing counter to mix in as entropy (Linux
/// random_get_entropy: the TSC)
pub fn random_get_entropy() -> u64 {
    super::tsc::read_tsc()
}
