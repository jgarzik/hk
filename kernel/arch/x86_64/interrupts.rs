//! Interrupt Descriptor Table (IDT) and interrupt handling
//!
//! Sets up the IDT with exception handlers and IRQ handlers.

use ::core::mem::size_of;
use ::core::sync::atomic::{AtomicU64, Ordering};

use super::PtRegs;
use super::cpu::KERNEL_CODE_SELECTOR;
use super::entry;
use super::lapic;
use super::pic;
use crate::mm::fault::{Access, VmFault};
use crate::signal::{KSigInfo, si_code};
use crate::uaccess::pagefault_disabled;
use crate::{printk, printkln};

/// LAPIC timer interrupt vector
pub const LAPIC_TIMER_VECTOR: u8 = 0x40;

/// Number of IDT entries (256 interrupt vectors)
const IDT_ENTRIES: usize = 256;

/// IDT gate types: every vector is an interrupt gate (interrupts off on
/// entry, Linux idt.c), so nothing interrupts an entry stub before its
/// `swapgs`; the handlers turn them back on where they may
const GATE_INTERRUPT: u8 = 0x8E; // Present, DPL=0, 64-bit interrupt gate
/// Present, DPL=3, 64-bit interrupt gate: reachable by `int3`/`into` from
/// user mode (Linux: X86_TRAP_BP and X86_TRAP_OF are system gates)
const GATE_INT_USER: u8 = 0xEE;

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
        IDT[0].set_handler(
            entry::exception_handler_0 as *const () as u64,
            GATE_INTERRUPT,
        );
        IDT[1].set_handler(
            entry::exception_handler_1 as *const () as u64,
            GATE_INTERRUPT,
        );
        // NMI uses IST2 for safety
        IDT[2].set_handler_with_ist(
            entry::exception_handler_2 as *const () as u64,
            GATE_INTERRUPT,
            super::cpu::IST_NMI,
        );
        IDT[3].set_handler(
            entry::exception_handler_3 as *const () as u64,
            GATE_INT_USER,
        );
        IDT[4].set_handler(
            entry::exception_handler_4 as *const () as u64,
            GATE_INT_USER,
        );
        IDT[5].set_handler(
            entry::exception_handler_5 as *const () as u64,
            GATE_INTERRUPT,
        );
        IDT[6].set_handler(
            entry::exception_handler_6 as *const () as u64,
            GATE_INTERRUPT,
        );
        IDT[7].set_handler(
            entry::exception_handler_7 as *const () as u64,
            GATE_INTERRUPT,
        );
        // Double fault uses IST1 to avoid stack issues
        IDT[8].set_handler_with_ist(
            entry::exception_handler_8 as *const () as u64,
            GATE_INTERRUPT,
            super::cpu::IST_DOUBLE_FAULT,
        );
        IDT[9].set_handler(
            entry::exception_handler_9 as *const () as u64,
            GATE_INTERRUPT,
        );
        IDT[10].set_handler(
            entry::exception_handler_10 as *const () as u64,
            GATE_INTERRUPT,
        );
        IDT[11].set_handler(
            entry::exception_handler_11 as *const () as u64,
            GATE_INTERRUPT,
        );
        IDT[12].set_handler(
            entry::exception_handler_12 as *const () as u64,
            GATE_INTERRUPT,
        );
        IDT[13].set_handler(
            entry::exception_handler_13 as *const () as u64,
            GATE_INTERRUPT,
        );
        IDT[14].set_handler(
            entry::exception_handler_14 as *const () as u64,
            GATE_INTERRUPT,
        );
        // 15 is reserved
        IDT[16].set_handler(
            entry::exception_handler_16 as *const () as u64,
            GATE_INTERRUPT,
        );
        IDT[17].set_handler(
            entry::exception_handler_17 as *const () as u64,
            GATE_INTERRUPT,
        );
        // Machine check: its own IST stack too
        IDT[18].set_handler_with_ist(
            entry::exception_handler_18 as *const () as u64,
            GATE_INTERRUPT,
            super::cpu::IST_MCE,
        );
        IDT[19].set_handler(
            entry::exception_handler_19 as *const () as u64,
            GATE_INTERRUPT,
        );
        IDT[20].set_handler(
            entry::exception_handler_20 as *const () as u64,
            GATE_INTERRUPT,
        );
        IDT[21].set_handler(
            entry::exception_handler_21 as *const () as u64,
            GATE_INTERRUPT,
        );

        // Set up IRQ handlers (vectors 32-47, after PIC remapping)
        // Master PIC: IRQs 0-7 -> vectors 32-39
        IDT[32].set_handler(entry::irq_handler_0 as *const () as u64, GATE_INTERRUPT); // Timer
        IDT[33].set_handler(entry::irq_handler_1 as *const () as u64, GATE_INTERRUPT); // Keyboard
        IDT[34].set_handler(entry::irq_handler_2 as *const () as u64, GATE_INTERRUPT); // Cascade
        IDT[35].set_handler(entry::irq_handler_3 as *const () as u64, GATE_INTERRUPT); // COM2
        IDT[36].set_handler(entry::irq_handler_4 as *const () as u64, GATE_INTERRUPT); // COM1
        IDT[37].set_handler(entry::irq_handler_5 as *const () as u64, GATE_INTERRUPT); // LPT2
        IDT[38].set_handler(entry::irq_handler_6 as *const () as u64, GATE_INTERRUPT); // Floppy
        IDT[39].set_handler(entry::irq_handler_7 as *const () as u64, GATE_INTERRUPT); // LPT1/Spurious
        // Slave PIC: IRQs 8-15 -> vectors 40-47
        IDT[40].set_handler(entry::irq_handler_8 as *const () as u64, GATE_INTERRUPT); // RTC
        IDT[41].set_handler(entry::irq_handler_9 as *const () as u64, GATE_INTERRUPT); // ACPI/PCI
        IDT[42].set_handler(entry::irq_handler_10 as *const () as u64, GATE_INTERRUPT); // PCI
        IDT[43].set_handler(entry::irq_handler_11 as *const () as u64, GATE_INTERRUPT); // PCI
        IDT[44].set_handler(entry::irq_handler_12 as *const () as u64, GATE_INTERRUPT); // PS/2 Mouse
        IDT[45].set_handler(entry::irq_handler_13 as *const () as u64, GATE_INTERRUPT); // FPU
        IDT[46].set_handler(entry::irq_handler_14 as *const () as u64, GATE_INTERRUPT); // Primary ATA
        IDT[47].set_handler(entry::irq_handler_15 as *const () as u64, GATE_INTERRUPT); // Secondary ATA

        // LAPIC timer interrupt (vector 0x40)
        IDT[LAPIC_TIMER_VECTOR as usize].set_handler(
            entry::lapic_timer_handler as *const () as u64,
            GATE_INTERRUPT,
        );

        // IPIs (mm::tlb shootdown, smp calls, remote wakeups)
        IDT[CALL_FUNCTION_VECTOR as usize]
            .set_handler(entry::call_function_ipi as *const () as u64, GATE_INTERRUPT);
        IDT[RESCHEDULE_VECTOR as usize]
            .set_handler(entry::reschedule_ipi as *const () as u64, GATE_INTERRUPT);

        // Every other vector gets a catch-all stub (Linux idt_setup_apic_
        // and_irq_gates: spurious_entries_start), so a stray interrupt (the
        // LAPIC spurious vector, APIC errors, a vector left programmed by
        // firmware) is reported instead of raising #NP. Not #VC/#SX
        // (29, 30): they push an error code and hk never enables them.
        let idt = &raw mut IDT;
        for v in 0..IDT_ENTRIES {
            let gate = &mut (*idt)[v];
            if gate.type_attr == 0 && !matches!(v, 29 | 30) {
                gate.set_handler(entry::vector_stub(v as u8), GATE_INTERRUPT);
            }
        }
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

/// Exceptions whose entry carries an error code from the CPU (in
/// orig_ax): #DF, #TS, #NP, #SS, #GP, #PF, #AC, #CP
fn has_error_code(vector: u64) -> bool {
    matches!(vector, 8 | 10..=14 | 17 | 21)
}

/// Every IDT vector lands here from `entry::idt_common` (or
/// `paranoid_common`), with the frame at `regs` (Linux idtentry
/// handlers, sysvec_*, common_interrupt)
pub extern "C" fn idt_dispatch(regs: &mut PtRegs, vector: u64) {
    match vector {
        0..=31 => handle_exception(regs, vector),
        32..=47 => handle_irq(vector - 32),
        v if v == LAPIC_TIMER_VECTOR as u64 => handle_lapic_timer(),
        v if v == CALL_FUNCTION_VECTOR as u64 => handle_call_function(),
        v if v == RESCHEDULE_VECTOR as u64 => handle_reschedule(),
        v if v == lapic::ERROR_APIC_VECTOR as u64 => in_irq(handle_apic_error),
        v => in_irq(|| handle_spurious(v as u8)),
    }
    // Back to user mode: its pending work first (Linux
    // irqentry_exit_to_user_mode); not for NMI, #DF, #MC (paranoid)
    if regs.cs & 3 == 3 && !matches!(vector, 2 | 8 | 18) {
        // SAFETY: interrupts off for the exit work's checks
        unsafe { ::core::arch::asm!("cli", options(nostack)) };
        crate::entry::exit_to_user_mode(regs);
    }
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
/// context in `frame`: the task's pt_regs (an entry from user mode), so
/// a handler's frame is set up there and IRETQ enters it
fn user_fault(frame: &mut PtRegs, sig: u32, info: KSigInfo) {
    crate::signal::force_sig_fault(sig, info, frame);
}

/// Rust exception handler (interrupts off: interrupt gates); it returns
/// when execution can resume, else halts
fn handle_exception(frame: &mut PtRegs, vector: u64) {
    // The error code leaves orig_ax, which says "no syscall" from now on
    // (Linux idtentry)
    let error_code = if has_error_code(vector) {
        frame.orig_rax
    } else {
        0
    };
    frame.orig_rax = u64::MAX;

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
        let Err(err) = handle_page_fault(error_code, cr2) else {
            return; // resolved: retry the access
        };
        // Error code bit 2: user mode access
        if error_code & 4 != 0 {
            // Error code bit 3: reserved bit violation
            let bus = error_code & 8 != 0 || err == VmFault::Bus;
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
                error: error_code,
            };
            user_fault(frame, sig, info);
            return;
        }
        // Kernel-mode fault inside a user-copy routine (out of memory
        // included, Linux kernelmode_fixup_or_oops): resume at its
        // fixup, which reports the uncopied bytes (-> EFAULT)
        if let Some(fixup) = super::uaccess::uaccess_fixup(frame.rip) {
            frame.rip = fixup;
            return;
        }
        // Kernel mode fault - fall through to fatal handler
    }

    // An NMI in user mode is not the task's doing: nothing to deliver
    // (hk has no NMI sources it handles; Linux exc_nmi)
    if vector == 2 {
        return;
    }

    // Any other exception raised by user code (#DE, #UD, #GP, ...) is the
    // task's fault, not the kernel's: signal it instead of halting. #DF
    // and #MC are never a task's: they halt below (paranoid, IST stack)
    if frame.cs & 3 == 3 && !matches!(vector, 8 | 14 | 18) {
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
                    return; // spurious (Linux: no signal)
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
            error: error_code,
        };
        user_fault(frame, sig, info);
        return;
    }

    // A kernel stack overflow: a fault in the guard gap below a stack.
    // With RSP itself there the page fault could not push its frame
    // either, so it became a double fault, running on its IST stack
    // (Linux exc_double_fault, handle_stack_overflow)
    let guard = |a| crate::mm::vmstack::in_guard(a);
    if matches!(vector, 8 | 14) && (guard(cr2) || guard(frame.rsp)) {
        panic!(
            "kernel stack overflow: RIP={:#x} RSP={:#x} CR2={:#x} (tid {})",
            frame.rip,
            frame.rsp,
            cr2,
            crate::task::percpu::current_tid()
        );
    }

    die(frame, vector as u8, error_code, cr2)
}

/// A fatal kernel-mode exception (Linux die + "Fatal exception"
/// panic): dump the faulting context through printk, so it reaches
/// every console (VGA on machines without a serial port), then panic
fn die(frame: &PtRegs, vector: u8, error_code: u64, cr2: u64) -> ! {
    crate::printk::set_oops_in_progress();
    let name = EXCEPTION_NAMES.get(vector as usize).copied().unwrap_or("?");
    let cpu = crate::cpu::try_this_id().map_or(-1, |c| c as i64);
    printkln!(
        "Oops: {} (#{}) error {:#x} CPU {} tid {}",
        name,
        vector,
        error_code,
        cpu,
        crate::task::percpu::current_tid()
    );
    printkln!(
        "RIP: {:#018x} CS: {:#x} RFLAGS: {:#x}",
        frame.rip,
        frame.cs,
        frame.rflags
    );
    printkln!(
        "RSP: {:#018x} SS: {:#x} CR2: {:#018x}",
        frame.rsp,
        frame.ss,
        cr2
    );
    printkln!(
        "RAX: {:#018x} RBX: {:#018x} RCX: {:#018x}",
        frame.rax,
        frame.rbx,
        frame.rcx
    );
    printkln!(
        "RDX: {:#018x} RSI: {:#018x} RDI: {:#018x}",
        frame.rdx,
        frame.rsi,
        frame.rdi
    );
    printkln!(
        "RBP: {:#018x} R08: {:#018x} R09: {:#018x}",
        frame.rbp,
        frame.r8,
        frame.r9
    );
    printkln!(
        "R10: {:#018x} R11: {:#018x} R12: {:#018x}",
        frame.r10,
        frame.r11,
        frame.r12
    );
    printkln!(
        "R13: {:#018x} R14: {:#018x} R15: {:#018x}",
        frame.r13,
        frame.r14,
        frame.r15
    );
    if vector == 14 {
        printkln!(
            "#PF: {} {} {}{}{}",
            if error_code & 1 == 0 {
                "not-present"
            } else {
                "protection"
            },
            if error_code & 2 != 0 { "write" } else { "read" },
            if error_code & 4 != 0 {
                "user"
            } else {
                "kernel"
            },
            if error_code & 8 != 0 {
                " reserved-bit"
            } else {
                ""
            },
            if error_code & 16 != 0 { " ifetch" } else { "" }
        );
    }
    oops_backtrace(frame);
    panic!("Fatal exception: {} at RIP={:#x}", name, frame.rip);
}

/// Frame-pointer backtrace of the faulting kernel stack
fn oops_backtrace(frame: &PtRegs) {
    // Only follow frame pointers on the faulting kernel stack: RBP may
    // hold a user value (no frame pointers, or a user-mode fault), and
    // dereferencing it here would fault again under SMAP
    if frame.cs & 3 != 0 {
        return;
    }
    let stack = frame.rsp..frame.rsp.saturating_add(0x10000);
    let mut fp = frame.rbp;
    for depth in 0..16 {
        if fp == 0 || !stack.contains(&fp) {
            break;
        }
        // SAFETY: fp lies within the faulting kernel stack
        let (prev, ret) = unsafe { (*(fp as *const u64), *((fp + 8) as *const u64)) };
        if ret == 0 {
            break;
        }
        printkln!("  #{}: {:#018x}", depth, ret);
        if prev <= fp {
            break;
        }
        fp = prev;
    }
}

/// Resolve a page fault at `addr` (Linux do_user_addr_fault). Only
/// user addresses are demand-paged or copy-on-write; a kernel access to
/// one (copy_to_user etc.) is resolved like a user access, unless page
/// faults are disabled (a spinlock is held: the copy's fixup reports
/// EFAULT). Kernel-half addresses are never resolved.
fn handle_page_fault(ec: u64, addr: u64) -> Result<(), VmFault> {
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

/// Call-function IPI vector (Linux CALL_FUNCTION_VECTOR)
pub const CALL_FUNCTION_VECTOR: u8 = 0xfc;
/// Reschedule IPI vector (Linux RESCHEDULE_VECTOR)
pub const RESCHEDULE_VECTOR: u8 = 0xfd;

/// Run `f` as an interrupt handler: interrupt depth and lockdep's
/// interrupt context account for it
fn in_irq(f: impl FnOnce()) {
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
fn handle_call_function() {
    lapic::eoi();
    in_irq(crate::smp::call_function_interrupt);
}

/// Reschedule IPI (Linux sysvec_reschedule_ipi)
fn handle_reschedule() {
    lapic::eoi();
    in_irq(crate::smp::reschedule_interrupt);
}

/// Spurious interrupts so far (Linux IRQ_COUNT_SPURIOUS)
static SPURIOUS_COUNT: AtomicU64 = AtomicU64::new(0);

/// Report the first few of a kind, then only count (printk from
/// interrupt context is slow; an interrupt storm would flood it)
fn report_irq(count: &AtomicU64) -> bool {
    count.fetch_add(1, Ordering::Relaxed) < 10
}

/// An interrupt on a vector with no handler (Linux spurious_interrupt,
/// handle_spurious_interrupt): the LAPIC's spurious vector is never
/// acknowledged (SDM vol 3); any other is acknowledged if in service
fn handle_spurious(vector: u8) {
    let cpu = crate::cpu::try_this_id().map_or(-1, |c| c as i64);
    let report = report_irq(&SPURIOUS_COUNT);
    if vector == lapic::SPURIOUS_APIC_VECTOR {
        if report {
            printkln!("Spurious APIC interrupt (vector 0xFF) on CPU#{}", cpu);
        }
        return;
    }
    let acked = lapic::in_service(vector);
    if acked {
        lapic::eoi();
    }
    if report {
        printkln!(
            "Spurious interrupt (vector {:#04x}) on CPU#{}. {}",
            vector,
            cpu,
            if acked { "Acked" } else { "Not pending!" }
        );
    }
}

/// APIC errors so far (Linux IRQ_COUNT_PIC_APIC_ERROR)
static APIC_ERROR_COUNT: AtomicU64 = AtomicU64::new(0);

/// LVT Error interrupt (Linux sysvec_error_interrupt): latch the ESR,
/// acknowledge, report the error bits
fn handle_apic_error() {
    const REASONS: [&str; 8] = [
        "Send CS error",
        "Receive CS error",
        "Send accept error",
        "Receive accept error",
        "Redirectable IPI",
        "Send illegal vector",
        "Received illegal vector",
        "Illegal register address",
    ];
    let esr = lapic::read_esr();
    lapic::eoi();
    if !report_irq(&APIC_ERROR_COUNT) {
        return;
    }
    let cpu = crate::cpu::try_this_id().map_or(-1, |c| c as i64);
    printk!("APIC error on CPU{}: {:02x}", cpu, esr & 0xff);
    for (i, why) in REASONS.iter().enumerate() {
        if esr & (1 << i) != 0 {
            printk!(" : {}", why);
        }
    }
    printkln!("");
}

/// LAPIC timer interrupt
fn handle_lapic_timer() {
    // Track interrupt nesting depth
    let percpu = match super::percpu::try_current_cpu() {
        Some(p) => p,
        None => {
            // Per-CPU not set up yet: re-arm the one-shot timer, EOI
            lapic::set_next_event(crate::task::percpu::TICK_NS);
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

    // Due timers (the scheduler tick among them), the next event
    crate::hrtimer::interrupt();

    // Send EOI to LAPIC (must be done before any potential context switch)
    lapic::eoi();

    // Decrement interrupt depth
    percpu.interrupt_depth.fetch_sub(1, Ordering::Relaxed);
}

/// Timer tick counter
static mut TIMER_TICKS: u64 = 0;

/// Legacy PIC interrupt `irq` (0-15)
fn handle_irq(irq: u64) {
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
