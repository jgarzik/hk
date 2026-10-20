//! Interrupt Descriptor Table (IDT) and interrupt handling
//!
//! Sets up the IDT with exception handlers and IRQ handlers.

use ::core::mem::size_of;
use ::core::sync::atomic::Ordering;

use super::X86_64TrapFrame;
use super::cpu::KERNEL_CODE_SELECTOR;
use super::lapic;
use super::pic;
use crate::mm::fault::{Access, VmFault};
use crate::signal::{KSigInfo, si_code};
use crate::uaccess::pagefault_disabled;

/// LAPIC timer interrupt vector
pub const LAPIC_TIMER_VECTOR: u8 = 0x40;

/// Number of IDT entries (256 interrupt vectors)
const IDT_ENTRIES: usize = 256;

/// IDT gate types
const GATE_INTERRUPT: u8 = 0x8E; // Present, DPL=0, 64-bit interrupt gate
const GATE_TRAP: u8 = 0x8F; // Present, DPL=0, 64-bit trap gate
/// Present, DPL=3, 64-bit trap gate: reachable by `int3`/`into` from user
/// mode (Linux: X86_TRAP_BP and X86_TRAP_OF are system gates)
const GATE_TRAP_USER: u8 = 0xEF;

/// IDT entry (16 bytes in 64-bit mode)
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,       // Interrupt Stack Table index (bits 0-2), rest reserved
    type_attr: u8, // Gate type and attributes
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    fn set_handler(&mut self, handler: u64, gate_type: u8) {
        self.set_handler_with_ist(handler, gate_type, 0);
    }

    fn set_handler_with_ist(&mut self, handler: u64, gate_type: u8, ist: u8) {
        self.offset_low = handler as u16;
        self.selector = KERNEL_CODE_SELECTOR;
        self.ist = ist & 0x7; // IST index in bits 0-2
        self.type_attr = gate_type;
        self.offset_mid = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.reserved = 0;
    }
}

/// IDT pointer for LIDT instruction
#[repr(C, packed)]
struct IdtPointer {
    limit: u16,
    base: u64,
}

/// The Interrupt Descriptor Table
static mut IDT: [IdtEntry; IDT_ENTRIES] = [IdtEntry::missing(); IDT_ENTRIES];

/// Exception names for debugging
const EXCEPTION_NAMES: [&str; 32] = [
    "Division Error",
    "Debug",
    "Non-Maskable Interrupt",
    "Breakpoint",
    "Overflow",
    "Bound Range Exceeded",
    "Invalid Opcode",
    "Device Not Available",
    "Double Fault",
    "Coprocessor Segment Overrun",
    "Invalid TSS",
    "Segment Not Present",
    "Stack-Segment Fault",
    "General Protection Fault",
    "Page Fault",
    "Reserved",
    "x87 FPU Error",
    "Alignment Check",
    "Machine Check",
    "SIMD Floating-Point",
    "Virtualization",
    "Control Protection",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Hypervisor Injection",
    "VMM Communication",
    "Security Exception",
    "Reserved",
];

/// Initialize the IDT
pub fn init_idt() {
    unsafe {
        // Set up exception handlers (vectors 0-31)
        IDT[0].set_handler(exception_handler_0 as *const () as u64, GATE_TRAP);
        IDT[1].set_handler(exception_handler_1 as *const () as u64, GATE_TRAP);
        // NMI uses IST2 for safety
        IDT[2].set_handler_with_ist(
            exception_handler_2 as *const () as u64,
            GATE_INTERRUPT,
            super::cpu::IST_NMI,
        );
        IDT[3].set_handler(exception_handler_3 as *const () as u64, GATE_TRAP_USER);
        IDT[4].set_handler(exception_handler_4 as *const () as u64, GATE_TRAP_USER);
        IDT[5].set_handler(exception_handler_5 as *const () as u64, GATE_TRAP);
        IDT[6].set_handler(exception_handler_6 as *const () as u64, GATE_TRAP);
        IDT[7].set_handler(exception_handler_7 as *const () as u64, GATE_TRAP);
        // Double fault uses IST1 to avoid stack issues
        IDT[8].set_handler_with_ist(
            exception_handler_8 as *const () as u64,
            GATE_TRAP,
            super::cpu::IST_DOUBLE_FAULT,
        );
        IDT[9].set_handler(exception_handler_9 as *const () as u64, GATE_TRAP);
        IDT[10].set_handler(exception_handler_10 as *const () as u64, GATE_TRAP);
        IDT[11].set_handler(exception_handler_11 as *const () as u64, GATE_TRAP);
        IDT[12].set_handler(exception_handler_12 as *const () as u64, GATE_TRAP);
        IDT[13].set_handler(exception_handler_13 as *const () as u64, GATE_TRAP);
        IDT[14].set_handler(exception_handler_14 as *const () as u64, GATE_TRAP);
        // 15 is reserved
        IDT[16].set_handler(exception_handler_16 as *const () as u64, GATE_TRAP);
        IDT[17].set_handler(exception_handler_17 as *const () as u64, GATE_TRAP);
        // Machine check: its own IST stack too
        IDT[18].set_handler_with_ist(
            exception_handler_18 as *const () as u64,
            GATE_TRAP,
            super::cpu::IST_MCE,
        );
        IDT[19].set_handler(exception_handler_19 as *const () as u64, GATE_TRAP);
        IDT[20].set_handler(exception_handler_20 as *const () as u64, GATE_TRAP);
        IDT[21].set_handler(exception_handler_21 as *const () as u64, GATE_TRAP);

        // Set up IRQ handlers (vectors 32-47, after PIC remapping)
        // Master PIC: IRQs 0-7 -> vectors 32-39
        IDT[32].set_handler(irq_handler_0 as *const () as u64, GATE_INTERRUPT); // Timer
        IDT[33].set_handler(irq_handler_1 as *const () as u64, GATE_INTERRUPT); // Keyboard
        IDT[34].set_handler(irq_handler_2 as *const () as u64, GATE_INTERRUPT); // Cascade
        IDT[35].set_handler(irq_handler_3 as *const () as u64, GATE_INTERRUPT); // COM2
        IDT[36].set_handler(irq_handler_4 as *const () as u64, GATE_INTERRUPT); // COM1
        IDT[37].set_handler(irq_handler_5 as *const () as u64, GATE_INTERRUPT); // LPT2
        IDT[38].set_handler(irq_handler_6 as *const () as u64, GATE_INTERRUPT); // Floppy
        IDT[39].set_handler(irq_handler_7 as *const () as u64, GATE_INTERRUPT); // LPT1/Spurious
        // Slave PIC: IRQs 8-15 -> vectors 40-47
        IDT[40].set_handler(irq_handler_8 as *const () as u64, GATE_INTERRUPT); // RTC
        IDT[41].set_handler(irq_handler_9 as *const () as u64, GATE_INTERRUPT); // ACPI/PCI
        IDT[42].set_handler(irq_handler_10 as *const () as u64, GATE_INTERRUPT); // PCI
        IDT[43].set_handler(irq_handler_11 as *const () as u64, GATE_INTERRUPT); // PCI
        IDT[44].set_handler(irq_handler_12 as *const () as u64, GATE_INTERRUPT); // PS/2 Mouse
        IDT[45].set_handler(irq_handler_13 as *const () as u64, GATE_INTERRUPT); // FPU
        IDT[46].set_handler(irq_handler_14 as *const () as u64, GATE_INTERRUPT); // Primary ATA
        IDT[47].set_handler(irq_handler_15 as *const () as u64, GATE_INTERRUPT); // Secondary ATA

        // LAPIC timer interrupt (vector 0x40)
        IDT[LAPIC_TIMER_VECTOR as usize]
            .set_handler(lapic_timer_handler as *const () as u64, GATE_INTERRUPT);

        // IPIs (mm::tlb shootdown, smp calls, remote wakeups)
        IDT[CALL_FUNCTION_VECTOR as usize]
            .set_handler(call_function_ipi as *const () as u64, GATE_INTERRUPT);
        IDT[RESCHEDULE_VECTOR as usize]
            .set_handler(reschedule_ipi as *const () as u64, GATE_INTERRUPT);
    }
    load_idt();
}

/// Load the IDT (shared by every CPU) on this CPU
pub fn load_idt() {
    let idt_ptr = IdtPointer {
        limit: (size_of::<[IdtEntry; IDT_ENTRIES]>() - 1) as u16,
        base: (&raw const IDT) as *const _ as u64,
    };
    unsafe {
        ::core::arch::asm!(
            "lidt [{}]",
            in(reg) &idt_ptr,
            options(nostack)
        );
    }
}

/// Enable interrupts
#[inline]
pub fn enable() {
    unsafe {
        ::core::arch::asm!("sti", options(nostack));
    }
}

// Exception handler stubs
// For no-error exceptions: CPU pushes [RIP, CS, RFLAGS, RSP, SS]
// For error exceptions: CPU pushes [error_code, RIP, CS, RFLAGS, RSP, SS]
// We push dummy error code for no-error exceptions to unify handling

macro_rules! exception_handler_no_error {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() {
            // CPU pushed: [RIP, CS, RFLAGS, RSP, SS]
            // We push dummy error code and vector number
            core::arch::naked_asm!(
                "push 0",          // Dummy error code
                "push {}",         // Vector number
                "jmp {}",
                const $vector as u64,
                sym exception_common,
            );
        }
    };
}

macro_rules! exception_handler_with_error {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() {
            // CPU pushed: [error_code, RIP, CS, RFLAGS, RSP, SS]
            // We push vector number
            core::arch::naked_asm!(
                "push {}",         // Vector number
                "jmp {}",
                const $vector as u64,
                sym exception_common,
            );
        }
    };
}

// Define exception handlers
exception_handler_no_error!(exception_handler_0, 0); // Divide Error
exception_handler_no_error!(exception_handler_1, 1); // Debug
exception_handler_no_error!(exception_handler_2, 2); // NMI
exception_handler_no_error!(exception_handler_3, 3); // Breakpoint
exception_handler_no_error!(exception_handler_4, 4); // Overflow
exception_handler_no_error!(exception_handler_5, 5); // Bound Range
exception_handler_no_error!(exception_handler_6, 6); // Invalid Opcode
exception_handler_no_error!(exception_handler_7, 7); // Device Not Available
exception_handler_with_error!(exception_handler_8, 8); // Double Fault
exception_handler_no_error!(exception_handler_9, 9); // Coprocessor Segment Overrun
exception_handler_with_error!(exception_handler_10, 10); // Invalid TSS
exception_handler_with_error!(exception_handler_11, 11); // Segment Not Present
exception_handler_with_error!(exception_handler_12, 12); // Stack Segment Fault
exception_handler_with_error!(exception_handler_13, 13); // General Protection Fault
exception_handler_with_error!(exception_handler_14, 14); // Page Fault
exception_handler_no_error!(exception_handler_16, 16); // x87 FPU Error
exception_handler_with_error!(exception_handler_17, 17); // Alignment Check
exception_handler_no_error!(exception_handler_18, 18); // Machine Check
exception_handler_no_error!(exception_handler_19, 19); // SIMD FP Exception
exception_handler_no_error!(exception_handler_20, 20); // Virtualization Exception
exception_handler_with_error!(exception_handler_21, 21); // Control Protection

/// Common exception handler
/// Stack on entry: [vector, error_code, RIP, CS, RFLAGS, RSP, SS]
#[unsafe(naked)]
unsafe extern "C" fn exception_common() {
    core::arch::naked_asm!(
        // Stack from CPU/stub: [vector, error_code, RIP, CS, RFLAGS, RSP, SS]

        // We need to preserve ALL registers while extracting the vector number.
        // The vector was pushed by the stub and we need to extract it.

        // Use xchg to atomically swap vector with r15, preserving r15's original value
        "xchg r15, [rsp]",   // Now R15=vector, [rsp]=user_r15

        // Stack is now: [user_r15, error_code, RIP, CS, RFLAGS, RSP, SS]
        // R15 holds the vector number

        // Save all remaining GPRs
        "push r14",
        "push r13",
        "push r12",
        "push r11",
        "push r10",
        "push r9",
        "push r8",
        "push rbp",
        "push rdi",
        "push rsi",
        "push rdx",
        "push rcx",
        "push rbx",
        "push rax",

        // Stack now: [rax, rbx, rcx, rdx, rsi, rdi, rbp, r8-r14, r15, error_code, rip, cs, rflags, rsp, ss]
        // This matches TrapFrame layout!

        // Kernel GS base, whatever the origin (keeps r15, the vector)
        "call {}",

        // Call Rust handler with (frame pointer, vector number)
        "mov rdi, rsp",      // First arg: trap frame pointer
        "mov rsi, r15",      // Second arg: vector number (in R15)
        "call {}",

        // Check return value - if non-zero, fault was handled
        "test rax, rax",
        "jnz 1f",

        // Fault not handled - fatal handler will loop forever
        "1:",

        // Restore all registers
        "pop rax",
        "pop rbx",
        "pop rcx",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        "pop rbp",
        "pop r8",
        "pop r9",
        "pop r10",
        "pop r11",
        "pop r12",
        "pop r13",
        "pop r14",
        "pop r15",

        // Skip error code
        "add rsp, 8",

        "iretq",
        sym super::percpu::restore_kernel_gs,
        sym handle_exception,
    );
}

/// si_code for a user x87 (#MF) or SIMD (#XM) floating-point exception
/// (Linux fpu__exception_code): the first unmasked pending exception
fn math_error_code(vector: u64) -> i32 {
    let err: u32 = if vector == 19 {
        let mut mxcsr: u32 = 0;
        unsafe {
            ::core::arch::asm!("stmxcsr [{}]", in(reg) &mut mxcsr, options(nostack));
        }
        (mxcsr & 0x3f) & !((mxcsr >> 7) & 0x3f)
    } else {
        let (mut cwd, mut swd): (u16, u16) = (0, 0);
        unsafe {
            ::core::arch::asm!(
                "fnstcw [{}]",
                "fnstsw [{}]",
                in(reg) &mut cwd,
                in(reg) &mut swd,
                options(nostack)
            );
        }
        (swd & !cwd) as u32
    };
    if err & 0x001 != 0 {
        si_code::FPE_FLTINV
    } else if err & 0x004 != 0 {
        si_code::FPE_FLTDIV
    } else if err & 0x008 != 0 {
        si_code::FPE_FLTOVF
    } else if err & 0x012 != 0 {
        si_code::FPE_FLTUND
    } else if err & 0x020 != 0 {
        si_code::FPE_FLTRES
    } else {
        0
    }
}

/// Deliver a synchronous fault signal (force_sig_fault) for the user
/// context in `frame`: if a handler runs, IRETQ enters it with every
/// register taken from the (redirected) per-CPU user-register block
fn user_fault(frame: &mut X86_64TrapFrame, sig: u32, info: KSigInfo) {
    super::percpu::load_user_regs_from_trapframe(frame);
    crate::signal::force_sig_fault(sig, info);
    super::percpu::store_user_regs_to_trapframe(frame);
}

/// Rust exception handler
/// Returns 1 if the exception was handled and execution can resume, 0 otherwise
extern "C" fn handle_exception(frame: &mut X86_64TrapFrame, vector: u64) -> u64 {
    // Disable interrupts
    unsafe {
        ::core::arch::asm!("cli", options(nostack, preserves_flags));
    }

    // Read CR2 for page faults
    let cr2: u64;
    unsafe {
        ::core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
    }

    // Page faults: demand paging, copy-on-write, swap-in (kernel/mm/fault.rs)
    if vector == 14 {
        // CR2 is read: interrupts back on if the faulting context had
        // them (Linux do_user_addr_fault), so a fault that sleeps (the
        // mmap_lock, file I/O) does not hold them off
        if frame.rflags & 0x200 != 0 {
            enable();
        }
        let Err(err) = handle_page_fault(frame, cr2) else {
            return 1; // resolved: retry the access
        };
        // Error code bit 2: user mode access
        if frame.error_code & 4 != 0 {
            // Error code bit 3: reserved bit violation
            let bus = frame.error_code & 8 != 0 || err == VmFault::Bus;
            enable();
            if err == VmFault::Oom {
                crate::mm::fault::pagefault_out_of_memory();
            }
            let (sig, code) = if bus {
                (crate::signal::SIGBUS, si_code::BUS_ADRERR)
            } else {
                (crate::signal::SIGSEGV, crate::signal::segv_code(cr2))
            };
            let info = KSigInfo {
                code,
                addr: cr2,
                trapno: 14,
                error: frame.error_code,
            };
            user_fault(frame, sig, info);
            return 1;
        }
        // Kernel-mode fault inside a user-copy routine (out of memory
        // included, Linux kernelmode_fixup_or_oops): resume at its
        // fixup, which reports the uncopied bytes (-> EFAULT)
        if let Some(fixup) = super::uaccess::uaccess_fixup(frame.rip) {
            frame.rip = fixup;
            return 1;
        }
        // Kernel mode fault - fall through to fatal handler
    }

    // Any other exception raised by user code (#DE, #UD, #GP, ...) is the
    // task's fault, not the kernel's: signal it instead of halting
    if frame.cs & 3 == 3 && vector != 14 {
        use crate::signal::{SIGBUS, SIGFPE, SIGILL, SIGSEGV, SIGTRAP};
        // Linux arch/x86/kernel/traps.c: signal, si_code, si_addr
        let rip = frame.rip;
        let (sig, code, addr) = match vector {
            0 => (SIGFPE, si_code::FPE_INTDIV, rip),    // #DE
            1 => (SIGTRAP, si_code::TRAP_TRACE, rip),   // #DB
            3 => (SIGTRAP, si_code::SI_KERNEL, 0),      // #BP (int3)
            6 => (SIGILL, si_code::ILL_ILLOPN, rip),    // #UD
            11 | 12 => (SIGBUS, si_code::SI_KERNEL, 0), // #NP, #SS
            16 | 19 => {
                // #MF, #XM: code from the unmasked exception flags
                let code = math_error_code(vector);
                if code == 0 {
                    return 1; // spurious (Linux: no signal)
                }
                (SIGFPE, code, rip)
            }
            17 => (SIGBUS, si_code::BUS_ADRALN, 0), // #AC
            _ => (SIGSEGV, si_code::SI_KERNEL, 0),  // #GP, #TS, ...
        };
        enable();
        let info = KSigInfo {
            code,
            addr,
            trapno: vector,
            error: frame.error_code,
        };
        user_fault(frame, sig, info);
        return 1;
    }

    // Cast to u8 for the rest of the handler
    let vector = vector as u8;

    // Direct serial output for debugging
    serial_print(b"\r\n========================================\r\n");
    serial_print(b"!!! CPU EXCEPTION !!!\r\n");
    serial_print(b"========================================\r\n");

    // Print exception name if known
    if vector < 32 {
        serial_print(b"Exception: ");
        serial_print(EXCEPTION_NAMES[vector as usize].as_bytes());
        serial_print(b" (#");
        print_dec(vector as u64);
        serial_print(b")\r\n");
    }

    // Print CPU ID if available
    if let Some(cpu) = super::percpu::try_current_cpu() {
        serial_print(b"CPU: ");
        print_dec(cpu.cpu_id as u64);
        serial_print(b"\r\n");
    }

    serial_print(b"\r\nRegisters:\r\n");
    serial_print(b"  RAX: 0x");
    print_hex(frame.rax);
    serial_print(b"  RBX: 0x");
    print_hex(frame.rbx);
    serial_print(b"\r\n");
    serial_print(b"  RCX: 0x");
    print_hex(frame.rcx);
    serial_print(b"  RDX: 0x");
    print_hex(frame.rdx);
    serial_print(b"\r\n");
    serial_print(b"  RSI: 0x");
    print_hex(frame.rsi);
    serial_print(b"  RDI: 0x");
    print_hex(frame.rdi);
    serial_print(b"\r\n");
    serial_print(b"  RBP: 0x");
    print_hex(frame.rbp);
    serial_print(b"  RSP: 0x");
    print_hex(frame.rsp);
    serial_print(b"\r\n");
    serial_print(b"  R8:  0x");
    print_hex(frame.r8);
    serial_print(b"  R9:  0x");
    print_hex(frame.r9);
    serial_print(b"\r\n");
    serial_print(b"  R10: 0x");
    print_hex(frame.r10);
    serial_print(b"  R11: 0x");
    print_hex(frame.r11);
    serial_print(b"\r\n");
    serial_print(b"  R12: 0x");
    print_hex(frame.r12);
    serial_print(b"  R13: 0x");
    print_hex(frame.r13);
    serial_print(b"\r\n");
    serial_print(b"  R14: 0x");
    print_hex(frame.r14);
    serial_print(b"  R15: 0x");
    print_hex(frame.r15);
    serial_print(b"\r\n");
    serial_print(b"  RIP: 0x");
    print_hex(frame.rip);
    serial_print(b"  CS:  0x");
    print_hex(frame.cs);
    serial_print(b"\r\n");
    serial_print(b"  RFLAGS: 0x");
    print_hex(frame.rflags);
    serial_print(b"  SS:  0x");
    print_hex(frame.ss);
    serial_print(b"\r\n");
    serial_print(b"  Error Code: 0x");
    print_hex(frame.error_code);
    serial_print(b"\r\n");

    // Print CR2 for page faults
    if vector == 14 {
        serial_print(b"  CR2 (fault addr): 0x");
        print_hex(cr2);
        serial_print(b"\r\n");

        // Decode page fault error code
        serial_print(b"  Page Fault: ");
        if frame.error_code & 1 == 0 {
            serial_print(b"non-present ");
        } else {
            serial_print(b"protection ");
        }
        if frame.error_code & 2 != 0 {
            serial_print(b"write ");
        } else {
            serial_print(b"read ");
        }
        if frame.error_code & 4 != 0 {
            serial_print(b"user ");
        } else {
            serial_print(b"kernel ");
        }
        if frame.error_code & 8 != 0 {
            serial_print(b"reserved-bit ");
        }
        if frame.error_code & 16 != 0 {
            serial_print(b"instruction-fetch ");
        }
        serial_print(b"\r\n");
    }

    // Stack backtrace
    serial_print(b"\r\nStack backtrace:\r\n");
    let mut frame_ptr = frame.rbp;
    let mut frame_count = 0;
    const MAX_FRAMES: usize = 16;

    while frame_ptr != 0 && frame_count < MAX_FRAMES {
        // Only follow frame pointers on the faulting kernel stack: RBP may
        // hold a user value (no frame pointers, or a user-mode fault), and
        // dereferencing it here would fault again under SMAP.
        if frame.cs & 3 != 0 || !(frame.rsp..frame.rsp.saturating_add(0x10000)).contains(&frame_ptr)
        {
            break;
        }

        // Read return address (stored at frame_ptr + 8)
        let return_addr = unsafe { *((frame_ptr + 8) as *const u64) };
        if return_addr == 0 {
            break;
        }

        serial_print(b"  #");
        print_dec(frame_count as u64);
        serial_print(b": 0x");
        print_hex(return_addr);
        serial_print(b"\r\n");

        // Move to previous frame
        let prev_frame = unsafe { *(frame_ptr as *const u64) };
        if prev_frame <= frame_ptr {
            break;
        }
        frame_ptr = prev_frame;
        frame_count += 1;
    }

    if frame_count == 0 {
        serial_print(b"  <no frames available>\r\n");
    }

    serial_print(b"========================================\r\n");
    serial_print(b"System halted.\r\n");

    // Halt forever
    loop {
        unsafe {
            ::core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Resolve a page fault at `addr` (Linux do_user_addr_fault). Only
/// user addresses are demand-paged or copy-on-write; a kernel access to
/// one (copy_to_user etc.) is resolved like a user access, unless page
/// faults are disabled (a spinlock is held: the copy's fixup reports
/// EFAULT). Kernel-half addresses are never resolved.
fn handle_page_fault(frame: &X86_64TrapFrame, addr: u64) -> Result<(), VmFault> {
    let ec = frame.error_code;
    let user = ec & 4 != 0;
    if addr >= crate::arch::x86_64::paging::TASK_SIZE || (!user && pagefault_disabled()) {
        return Err(VmFault::Segv);
    }
    // A present user page is always readable: a read fault on one (or
    // a reserved-bit fault) has nothing to resolve
    let access = match ec {
        _ if ec & 0x10 != 0 => Access::Exec,
        _ if ec & 2 != 0 => Access::Write,
        _ if ec & 1 != 0 => return Err(VmFault::Segv),
        _ => Access::Read,
    };
    let mm = crate::mm::get_task_mm(crate::task::percpu::current_tid()).ok_or(VmFault::Segv)?;
    crate::mm::fault::handle_mm_fault(&mm, addr, access)
}

fn serial_print(s: &[u8]) {
    for &b in s {
        super::io::outb(0x3F8, b);
    }
}

fn print_hex(val: u64) {
    for i in (0..16).rev() {
        let nibble = ((val >> (i * 4)) & 0xF) as u8;
        let c = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
        super::io::outb(0x3F8, c);
    }
}

fn print_dec(mut val: u64) {
    if val == 0 {
        super::io::outb(0x3F8, b'0');
        return;
    }
    let mut digits = [0u8; 20];
    let mut i = 0;
    while val > 0 {
        digits[i] = (val % 10) as u8 + b'0';
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        super::io::outb(0x3F8, digits[i]);
    }
}

// IRQ handlers
macro_rules! irq_handler {
    ($name:ident, $irq:expr) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                "push 0",           // Dummy error code
                "push rax",
                "push rbx",
                "push rcx",
                "push rdx",
                "push rsi",
                "push rdi",
                "push rbp",
                "push r8",
                "push r9",
                "push r10",
                "push r11",
                "push r12",
                "push r13",
                "push r14",
                "push r15",
                "call {}",          // kernel GS base (every entry)

                "mov rdi, {}",      // IRQ number
                "call {}",

                "pop r15",
                "pop r14",
                "pop r13",
                "pop r12",
                "pop r11",
                "pop r10",
                "pop r9",
                "pop r8",
                "pop rbp",
                "pop rdi",
                "pop rsi",
                "pop rdx",
                "pop rcx",
                "pop rbx",
                "pop rax",
                "add rsp, 8",       // Skip error code
                "iretq",
                sym super::percpu::restore_kernel_gs,
                const $irq,
                sym handle_irq,
            );
        }
    };
}

irq_handler!(irq_handler_0, 0); // Timer (PIT)
irq_handler!(irq_handler_1, 1); // Keyboard
irq_handler!(irq_handler_2, 2); // Cascade
irq_handler!(irq_handler_3, 3); // COM2
irq_handler!(irq_handler_4, 4); // COM1
irq_handler!(irq_handler_5, 5); // LPT2
irq_handler!(irq_handler_6, 6); // Floppy
irq_handler!(irq_handler_7, 7); // LPT1/Spurious
irq_handler!(irq_handler_8, 8); // RTC
irq_handler!(irq_handler_9, 9); // ACPI/PCI
irq_handler!(irq_handler_10, 10); // PCI
irq_handler!(irq_handler_11, 11); // PCI
irq_handler!(irq_handler_12, 12); // PS/2 Mouse
irq_handler!(irq_handler_13, 13); // FPU
irq_handler!(irq_handler_14, 14); // Primary ATA
irq_handler!(irq_handler_15, 15); // Secondary ATA

/// LAPIC timer interrupt handler stub
#[unsafe(naked)]
unsafe extern "C" fn lapic_timer_handler() {
    core::arch::naked_asm!(
        // Save all registers (same as other interrupt handlers)
        "push 0",           // Dummy error code for uniform stack layout
        "push rax",
        "push rbx",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push rbp",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "call {}",          // kernel GS base (every entry)

        // Pass trap frame pointer as argument
        "mov rdi, rsp",
        "call {}",

        // Restore registers
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rbp",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rbx",
        "pop rax",
        "add rsp, 8",       // Skip error code
        "iretq",
        sym super::percpu::restore_kernel_gs,
        sym handle_lapic_timer,
    );
}

/// Call-function IPI vector (Linux CALL_FUNCTION_VECTOR)
pub const CALL_FUNCTION_VECTOR: u8 = 0xfc;
/// Reschedule IPI vector (Linux RESCHEDULE_VECTOR)
pub const RESCHEDULE_VECTOR: u8 = 0xfd;

/// An IPI entry stub: saves the registers, calls `$handler`
macro_rules! ipi_handler {
    ($name:ident, $handler:path) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                "push 0",
                "push rax",
                "push rbx",
                "push rcx",
                "push rdx",
                "push rsi",
                "push rdi",
                "push rbp",
                "push r8",
                "push r9",
                "push r10",
                "push r11",
                "push r12",
                "push r13",
                "push r14",
                "push r15",
                "call {}",          // kernel GS base (every entry)
                "call {}",
                "pop r15",
                "pop r14",
                "pop r13",
                "pop r12",
                "pop r11",
                "pop r10",
                "pop r9",
                "pop r8",
                "pop rbp",
                "pop rdi",
                "pop rsi",
                "pop rdx",
                "pop rcx",
                "pop rbx",
                "pop rax",
                "add rsp, 8",
                "iretq",
                sym super::percpu::restore_kernel_gs,
                sym $handler,
            );
        }
    };
}

ipi_handler!(call_function_ipi, handle_call_function);
ipi_handler!(reschedule_ipi, handle_reschedule);

/// Run `f` as an interrupt handler: interrupt depth and lockdep's
/// interrupt context account for it
fn in_irq(f: fn()) {
    let percpu = super::percpu::try_current_cpu();
    if let Some(p) = percpu {
        p.interrupt_depth.fetch_add(1, Ordering::Relaxed);
    }
    crate::sync::lockdep::irq_enter();
    f();
    crate::sync::lockdep::irq_exit();
    if let Some(p) = percpu {
        p.interrupt_depth.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Call-function IPI (Linux sysvec_call_function): EOI first, so a call
/// queued while this one runs raises the vector again
extern "C" fn handle_call_function() {
    lapic::eoi();
    in_irq(crate::smp::call_function_interrupt);
}

/// Reschedule IPI (Linux sysvec_reschedule_ipi)
extern "C" fn handle_reschedule() {
    lapic::eoi();
    in_irq(crate::smp::reschedule_interrupt);
}

/// Rust LAPIC timer handler
extern "C" fn handle_lapic_timer(_frame: &X86_64TrapFrame) {
    // Track interrupt nesting depth
    let percpu = match super::percpu::try_current_cpu() {
        Some(p) => p,
        None => {
            // Per-CPU not set up yet, just send EOI and return
            lapic::eoi();
            return;
        }
    };

    // Increment interrupt depth
    percpu.interrupt_depth.fetch_add(1, Ordering::Relaxed);

    // Increment per-CPU tick counter
    percpu.ticks.fetch_add(1, Ordering::Relaxed);

    // Update global timekeeper (only on CPU 0 to avoid contention)
    if percpu.cpu_id == 0 {
        crate::time::TIMEKEEPER.update(super::tsc::read_tsc);
    }

    // Global ticks/timers and this CPU's scheduler work
    crate::task::percpu::scheduler_tick();

    // Send EOI to LAPIC (must be done before any potential context switch)
    lapic::eoi();

    // Decrement interrupt depth
    let prev_depth = percpu.interrupt_depth.fetch_sub(1, Ordering::Relaxed);

    // Only set reschedule flag if we're returning to depth 0 (not nested)
    // The actual preemption will happen after IRETQ when the idle loop checks it
    if prev_depth == 1 {
        percpu.needs_reschedule.store(true, Ordering::Release);
    }
}

/// Timer tick counter
static mut TIMER_TICKS: u64 = 0;

/// Rust IRQ handler
extern "C" fn handle_irq(irq: u64) {
    let irq = irq as u8;

    match irq {
        0 => {
            // Timer interrupt (PIT)
            unsafe {
                TIMER_TICKS += 1;
            }
        }
        4 => {
            // COM1 - serial interrupt (input not implemented, output-only console)
        }
        _ => {
            // Dispatch to registered handlers
            super::irq::dispatch_irq(irq);
        }
    }

    // Send End of Interrupt
    pic::send_eoi(irq);
}
