//! Interrupt Descriptor Table (IDT) and interrupt handling
//!
//! Sets up the IDT with exception handlers and IRQ handlers.

use ::core::mem::size_of;
use ::core::sync::atomic::Ordering;

use super::X86_64TrapFrame;
use super::cpu::KERNEL_CODE_SELECTOR;
use super::lapic;
use super::paging::phys_to_virt;
use super::pic;

/// LAPIC timer interrupt vector
pub const LAPIC_TIMER_VECTOR: u8 = 0x40;

/// Number of IDT entries (256 interrupt vectors)
const IDT_ENTRIES: usize = 256;

/// IDT gate types
const GATE_INTERRUPT: u8 = 0x8E; // Present, DPL=0, 64-bit interrupt gate
const GATE_TRAP: u8 = 0x8F; // Present, DPL=0, 64-bit trap gate

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
        IDT[3].set_handler(exception_handler_3 as *const () as u64, GATE_TRAP);
        IDT[4].set_handler(exception_handler_4 as *const () as u64, GATE_TRAP);
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
        IDT[18].set_handler(exception_handler_18 as *const () as u64, GATE_TRAP);
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

        // Load IDT
        let idt_ptr = IdtPointer {
            limit: (size_of::<[IdtEntry; IDT_ENTRIES]>() - 1) as u16,
            base: (&raw const IDT) as *const _ as u64,
        };

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
        ::core::arch::asm!("sti", options(nomem, nostack));
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
        sym handle_exception,
    );
}

/// Rust exception handler
/// Returns 1 if the exception was handled and execution can resume, 0 otherwise
extern "C" fn handle_exception(frame: &mut X86_64TrapFrame, vector: u64) -> u64 {
    // Disable interrupts
    unsafe {
        ::core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
    }

    // Read CR2 for page faults
    let cr2: u64;
    unsafe {
        ::core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
    }

    // Handle page faults specially - check for COW, demand paging, etc.
    if vector == 14 {
        match handle_page_fault(frame, cr2) {
            Some(true) => {
                return 1; // Fault handled, resume execution
            }
            Some(false) | None => {
                // Fault not handled - check if user mode
                // Error code bit 2: User mode access (1) or supervisor (0)
                let user = (frame.error_code & 4) != 0;
                if user {
                    // User mode page fault - send signal instead of halting
                    // Error code bit 3: Reserved bit violation (SIGBUS)
                    let is_bus_error = (frame.error_code & 8) != 0;
                    let sig = if is_bus_error {
                        crate::signal::SIGBUS
                    } else {
                        crate::signal::SIGSEGV
                    };

                    let tid = crate::task::percpu::current_tid();
                    crate::signal::send_signal(tid, sig);

                    // Return to user mode, signal will be delivered on syscall exit path
                    return 1;
                }
                // Kernel mode fault - fall through to fatal handler
            }
        }
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
        // Validate frame pointer
        if !(0x1000..=0xFFFF_FFFF_FFFF_0000).contains(&frame_ptr) {
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

/// Handle page fault, potentially as a COW or demand paging fault
///
/// Returns:
/// - Some(true) if the fault was successfully handled
/// - Some(false) if the fault was recognized but handling failed
/// - None if the fault should fall through to fatal handler
fn handle_page_fault(frame: &X86_64TrapFrame, fault_addr: u64) -> Option<bool> {
    use crate::arch::x86_64::paging::{PAGE_COW, PAGE_SIZE, PAGE_WRITABLE};

    let error_code = frame.error_code;

    // Error code bits:
    // - Bit 0 (P): Page was present (1) or not present (0)
    // - Bit 1 (W): Caused by a write access (1) or read (0)
    // - Bit 2 (U): User mode access (1) or supervisor (0)
    let present = (error_code & 1) != 0;
    let write = (error_code & 2) != 0;
    let user = (error_code & 4) != 0;

    // Case 0: Swap fault - non-present page with swap entry in PTE
    // Must check before demand paging since swapped pages have valid PTEs
    if !present && user {
        // Get current task's page table
        let cr3: u64;
        unsafe {
            ::core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        }

        // Check if this is a swap entry
        if let Some(result) = handle_swap_fault(cr3, fault_addr) {
            return Some(result);
        }
        // Fall through to demand paging check
    }

    // Case 1: Demand paging - page not present, check if in mmap'd VMA
    if !present
        && user
        && let Some(result) = handle_mmap_fault(fault_addr, write)
    {
        return Some(result);
    }
    // Fall through - might be a legitimate segfault

    // Case 2: COW fault - must be a write to a present page
    if !present || !write {
        return None; // Not a COW candidate
    }

    // Get current task's page table
    let cr3: u64;
    unsafe {
        ::core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }

    // Check if this address is in a huge page - if so, split it first
    // This implements the "split-first" COW strategy for THP
    {
        use crate::arch::x86_64::paging::X86_64PageTable;
        if let Some((huge_base, _phys)) = X86_64PageTable::is_huge_page_mapped(cr3, fault_addr) {
            // Split the huge page into 512 4KB pages before handling COW
            let _ = X86_64PageTable::split_huge_page(cr3, huge_base, &mut &crate::FRAME_ALLOCATOR);
            // After splitting, the page is now a regular 4KB page - continue with COW handling
        }
    }

    // Look up the PTE for this address
    let (pte_ptr, pte_value) = unsafe { get_pte_for_addr(cr3, fault_addr)? };

    // Check if this is a COW page (has our COW flag set)
    if pte_value & PAGE_COW == 0 {
        return None; // Not a COW page
    }

    // This is a COW fault - handle it
    let old_phys = pte_value & 0x000F_FFFF_FFFF_F000; // ADDR_MASK
    let old_flags = pte_value & !0x000F_FFFF_FFFF_F000;

    // Get anon_vma from VMA for rmap updates (Linux: wp_page_copy sets up rmap)
    use crate::mm::anon_vma::AnonVma;
    use crate::mm::get_task_mm;
    use crate::task::percpu::current_tid;
    use alloc::sync::Arc;

    let anon_vma: Option<Arc<AnonVma>> = {
        let tid = current_tid();
        get_task_mm(tid).and_then(|mm| {
            let mm_guard = mm.lock();
            mm_guard
                .find_vma(fault_addr)
                .and_then(|vma| vma.anon_vma.clone())
        })
    };

    // Check reference count
    let refcount = crate::FRAME_ALLOCATOR.refcount(old_phys);

    // Save original PTE value for race detection
    let orig_pte = pte_value;

    if refcount > 1 {
        // Shared page: allocate new frame and copy
        let new_phys = match crate::FRAME_ALLOCATOR.alloc() {
            Some(p) => p,
            None => {
                serial_print(b"COW: Out of memory!\r\n");
                return Some(false);
            }
        };

        // Copy page contents (4KB)
        unsafe {
            core::ptr::copy_nonoverlapping(
                phys_to_virt(old_phys) as *const u8,
                phys_to_virt(new_phys),
                PAGE_SIZE as usize,
            );
        }

        // Update PTE: new frame, restore writable, clear COW flag, set young+dirty
        // Linux: pte_mkdirty(pte_mkyoung(entry)) in wp_page_copy
        use crate::arch::x86_64::paging::{PAGE_ACCESSED, PAGE_DIRTY};
        let new_flags = (old_flags & !PAGE_COW) | PAGE_WRITABLE | PAGE_ACCESSED | PAGE_DIRTY;
        let new_pte = new_phys | new_flags;

        // Use atomic CAS to update PTE - prevents race with another CPU resolving same fault
        // Linux: pte_offset_map_lock + pte_same check in wp_page_copy
        use core::sync::atomic::{AtomicU64, Ordering};
        let pte_atomic = unsafe { &*(pte_ptr as *const AtomicU64) };
        match pte_atomic.compare_exchange(orig_pte, new_pte, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                // Success - we updated the PTE
                // Update rmap: register new page, remove old page
                // Linux: folio_add_new_anon_rmap + folio_remove_rmap_pte in wp_page_copy
                use crate::mm::lru::lru_add_new;
                use crate::mm::rmap::{page_add_anon_rmap, page_remove_rmap};

                if let Some(ref av) = anon_vma {
                    page_add_anon_rmap(new_phys, av, fault_addr);
                }
                lru_add_new(new_phys);

                // Remove old page from rmap (decrements mapcount)
                page_remove_rmap(old_phys);

                // Decrement old frame's reference count
                crate::FRAME_ALLOCATOR.decref(old_phys);
            }
            Err(_) => {
                // Race detected - another CPU already resolved this fault
                // Free the frame we allocated and return success
                crate::FRAME_ALLOCATOR.free(new_phys);
                // Fault is already resolved, no TLB flush needed from us
                return Some(true);
            }
        }
    } else {
        // Exclusive page (refcount == 1): just restore writable, clear COW flag
        // Also set young+dirty bits since we're writing
        use crate::arch::x86_64::paging::{PAGE_ACCESSED, PAGE_DIRTY};
        let new_flags = (old_flags & !PAGE_COW) | PAGE_WRITABLE | PAGE_ACCESSED | PAGE_DIRTY;
        let new_pte = old_phys | new_flags;

        // Use atomic CAS for exclusive case too - prevents race with munmap
        use core::sync::atomic::{AtomicU64, Ordering};
        let pte_atomic = unsafe { &*(pte_ptr as *const AtomicU64) };
        if pte_atomic
            .compare_exchange(orig_pte, new_pte, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // Race detected - PTE changed, fault resolved elsewhere
            return Some(true);
        }
    }

    // Flush TLB for this address
    unsafe {
        core::arch::asm!(
            "invlpg [{}]",
            in(reg) fault_addr,
            options(nostack, preserves_flags)
        );
    }

    // Increment minor fault counter (COW is minor - no I/O)
    crate::task::percpu::increment_min_flt();

    Some(true) // COW fault handled successfully
}

/// Try to allocate and map a 2MB huge page for a THP-eligible VMA
///
/// Returns:
/// - Some(true) if a huge page was successfully allocated and mapped
/// - Some(false) if allocation/mapping failed
/// - None if THP is not applicable (fall through to 4KB allocation)
fn try_huge_page_fault(
    cr3: u64,
    fault_addr: u64,
    vma_start: u64,
    vma_end: u64,
    vma_prot: u32,
    anon_vma: Option<&alloc::sync::Arc<crate::mm::anon_vma::AnonVma>>,
) -> Option<bool> {
    use crate::arch::PageFlags;
    use crate::arch::x86_64::paging::X86_64PageTable;
    use crate::mm::huge_page::{HUGE_PAGE_SIZE, huge_page_align_down};
    use crate::mm::{PROT_EXEC, PROT_WRITE};

    // Calculate the 2MB-aligned region containing this fault
    let huge_base = huge_page_align_down(fault_addr);
    let huge_end = huge_base + HUGE_PAGE_SIZE;

    // VMA must fully contain the 2MB region
    if vma_start > huge_base || vma_end < huge_end {
        return None; // Fall back to 4KB
    }

    // Try to allocate a contiguous 2MB physical region
    // Falls back to 4KB allocation if no contiguous memory available
    let huge_frame = crate::FRAME_ALLOCATOR.alloc_huge()?;

    // Zero the 2MB region
    unsafe {
        core::ptr::write_bytes(huge_frame as *mut u8, 0, HUGE_PAGE_SIZE as usize);
    }

    // Build page flags from VMA protection
    let mut flags = PageFlags::READ | PageFlags::USER;
    if vma_prot & PROT_WRITE != 0 {
        flags |= PageFlags::WRITE;
    }
    if vma_prot & PROT_EXEC != 0 {
        flags |= PageFlags::EXECUTE;
    }

    // Map the huge page
    if X86_64PageTable::map_huge_page(
        cr3,
        huge_base,
        huge_frame,
        flags,
        &mut &crate::FRAME_ALLOCATOR,
    )
    .is_err()
    {
        // Mapping failed - free the huge page and fall back
        crate::FRAME_ALLOCATOR.free_huge(huge_frame);
        return None;
    }

    // Register with LRU (track head frame only for huge pages)
    {
        use crate::mm::lru::lru_add_new;
        use crate::mm::rmap::page_add_anon_rmap;

        if let Some(anon_vma) = anon_vma {
            page_add_anon_rmap(huge_frame, anon_vma, huge_base);
        }
        lru_add_new(huge_frame);
    }

    // Flush TLB for the huge page region (invlpg on any address in the 2MB
    // range invalidates the entire huge page TLB entry)
    unsafe {
        ::core::arch::asm!(
            "invlpg [{}]",
            in(reg) huge_base,
            options(nostack, preserves_flags)
        );
    }

    // Increment minor fault counter (THP is still minor - no I/O)
    crate::task::percpu::increment_min_flt();

    Some(true) // Huge page mapped successfully
}

/// Handle a page fault for an mmap'd region (demand paging)
///
/// Returns:
/// - Some(true) if the fault was handled successfully
/// - Some(false) if the fault was recognized but handling failed (e.g., OOM)
/// - None if the address is not in any VMA
fn handle_mmap_fault(fault_addr: u64, is_write: bool) -> Option<bool> {
    use crate::arch::x86_64::paging::{
        PAGE_NO_EXECUTE, PAGE_PRESENT, PAGE_SIZE, PAGE_USER, PAGE_WRITABLE,
    };
    use crate::mm::{PROT_EXEC, PROT_WRITE, get_task_mm};
    use crate::task::percpu::current_tid;

    // Get current task's mm
    let tid = current_tid();
    let mm = get_task_mm(tid)?;

    // Lock mm and find VMA
    let mut mm_guard = mm.lock();
    let vma = match mm_guard.find_vma(fault_addr) {
        Some(vma) => vma,
        None => {
            // No VMA found - try stack expansion for VM_GROWSDOWN VMAs
            // Linux: mm/memory.c expand_stack() called from __do_page_fault()
            if let Some(vma_idx) = mm_guard.find_expandable_vma(fault_addr) {
                if mm_guard.expand_downwards(vma_idx, fault_addr).is_err() {
                    return Some(false); // Expansion failed
                }
                // Re-lookup the VMA after expansion
                mm_guard.find_vma(fault_addr)?
            } else {
                return None; // No VMA and no expandable VMA
            }
        }
    };

    // Check permissions
    if is_write && !vma.is_writable() {
        return Some(false); // Write to read-only region
    }

    // Clone VMA info we need (release lock before allocating)
    let vma_prot = vma.prot;
    let vma_is_anonymous = vma.is_anonymous();
    let vma_is_anon_private = vma.is_anon_private();
    let vma_is_thp_eligible = vma.is_thp_eligible();
    let vma_file = vma.file.clone();
    let vma_start = vma.start;
    let vma_end = vma.end;
    let vma_offset = vma.offset;
    let vma_anon_vma = vma.anon_vma.clone();
    drop(mm_guard);

    // Get current page table
    let cr3: u64;
    unsafe {
        ::core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }

    // Try THP (Transparent Huge Page) allocation for eligible VMAs
    if vma_is_thp_eligible
        && let Some(result) = try_huge_page_fault(
            cr3,
            fault_addr,
            vma_start,
            vma_end,
            vma_prot,
            vma_anon_vma.as_ref(),
        )
    {
        return Some(result);
    }
    // Fall through to 4KB allocation if THP failed

    // Allocate a physical frame
    let frame = match crate::FRAME_ALLOCATOR.alloc() {
        Some(f) => f,
        None => return Some(false), // OOM
    };

    // Initialize the page contents
    if vma_is_anonymous {
        // Anonymous mapping - zero the page
        unsafe {
            core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE as usize);
        }
    } else if let Some(file) = vma_file {
        // File-backed mapping - read file contents into the page
        // Calculate file offset for this page
        let page_addr = fault_addr & !0xFFF;
        let file_offset = vma_offset + (page_addr - vma_start);

        // First zero the frame in case the read is partial (e.g., at EOF)
        unsafe {
            core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE as usize);
        }

        // Read from file into the frame
        // Note: We read directly into the physical frame since it's identity-mapped
        // in the kernel's address space for low physical addresses
        let buf = unsafe { core::slice::from_raw_parts_mut(frame as *mut u8, PAGE_SIZE as usize) };
        let _read_result = file.pread(buf, file_offset);
        // If read fails or returns less than PAGE_SIZE, the remaining bytes are already zeroed
        // This matches Linux behavior for holes/errors
    } else {
        // File-backed but no file reference (shouldn't happen) - zero it
        unsafe {
            core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE as usize);
        }
    }

    // Build page table entry flags
    // Set ACCESSED bit since we're mapping due to access (Linux: pte_mkyoung)
    use crate::arch::x86_64::paging::PAGE_ACCESSED;
    let mut flags = PAGE_PRESENT | PAGE_USER | PAGE_ACCESSED;
    if vma_prot & PROT_WRITE != 0 {
        flags |= PAGE_WRITABLE;
    }
    if vma_prot & PROT_EXEC == 0 {
        flags |= PAGE_NO_EXECUTE;
    }

    // Get current page table
    let cr3: u64;
    unsafe {
        ::core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }

    // Map the page
    let page_addr = fault_addr & !0xFFF;
    if map_user_page(cr3, page_addr, frame, flags).is_err() {
        // Mapping failed, free the frame
        crate::FRAME_ALLOCATOR.free(frame);
        return Some(false);
    }

    // Register anonymous page with LRU and page descriptors for swap support
    if vma_is_anon_private {
        use crate::mm::lru::lru_add_new;
        use crate::mm::rmap::page_add_anon_rmap;

        if let Some(ref anon_vma) = vma_anon_vma {
            page_add_anon_rmap(frame, anon_vma, page_addr);
        }
        lru_add_new(frame);
    }

    // Flush TLB for this address
    unsafe {
        ::core::arch::asm!(
            "invlpg [{}]",
            in(reg) page_addr,
            options(nostack, preserves_flags)
        );
    }

    // Increment minor fault counter (demand paging is minor - no I/O from disk)
    crate::task::percpu::increment_min_flt();

    Some(true)
}

/// Map a user page, allocating intermediate page tables as needed
///
/// This function is used by demand paging and shmat to map physical frames
/// into a user process's address space.
///
/// # Arguments
/// * `cr3` - Physical address of the PML4 (page table root)
/// * `vaddr` - Virtual address to map (page-aligned)
/// * `paddr` - Physical address to map to
/// * `flags` - Page table entry flags (PAGE_PRESENT, PAGE_WRITABLE, PAGE_USER, etc.)
pub fn map_user_page(cr3: u64, vaddr: u64, paddr: u64, flags: u64) -> Result<(), ()> {
    use crate::arch::x86_64::paging::{PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE};

    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;

    unsafe {
        let pml4 = cr3 as *mut u64;

        // Get or create PDPT
        let pml4_entry = *pml4.add(pml4_idx);
        let pdpt = if pml4_entry & PAGE_PRESENT != 0 {
            (pml4_entry & 0x000F_FFFF_FFFF_F000) as *mut u64
        } else {
            let new_pdpt = crate::FRAME_ALLOCATOR.alloc().ok_or(())?;
            core::ptr::write_bytes(new_pdpt as *mut u8, 0, 4096);
            *pml4.add(pml4_idx) = new_pdpt | PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER;
            new_pdpt as *mut u64
        };

        // Get or create PD
        let pdpt_entry = *pdpt.add(pdpt_idx);
        let pd = if pdpt_entry & PAGE_PRESENT != 0 {
            (pdpt_entry & 0x000F_FFFF_FFFF_F000) as *mut u64
        } else {
            let new_pd = crate::FRAME_ALLOCATOR.alloc().ok_or(())?;
            core::ptr::write_bytes(new_pd as *mut u8, 0, 4096);
            *pdpt.add(pdpt_idx) = new_pd | PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER;
            new_pd as *mut u64
        };

        // Get or create PT
        let pd_entry = *pd.add(pd_idx);
        let pt = if pd_entry & PAGE_PRESENT != 0 {
            (pd_entry & 0x000F_FFFF_FFFF_F000) as *mut u64
        } else {
            let new_pt = crate::FRAME_ALLOCATOR.alloc().ok_or(())?;
            core::ptr::write_bytes(new_pt as *mut u8, 0, 4096);
            *pd.add(pd_idx) = new_pt | PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER;
            new_pt as *mut u64
        };

        // Set the PTE
        *pt.add(pt_idx) = paddr | flags;

        // Flush TLB for this address
        ::core::arch::asm!(
            "invlpg [{}]",
            in(reg) vaddr,
            options(nostack, preserves_flags)
        );

        Ok(())
    }
}

/// Unmap a user page
///
/// Clears the page table entry for the given virtual address and flushes the TLB.
/// Returns the physical address that was mapped, or None if not mapped.
///
/// # Arguments
/// * `cr3` - Physical address of the PML4 (page table root)
/// * `vaddr` - Virtual address to unmap (page-aligned)
pub fn unmap_user_page(cr3: u64, vaddr: u64) -> Option<u64> {
    use crate::arch::x86_64::paging::{PAGE_HUGE, PAGE_PRESENT};

    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;

    unsafe {
        // PML4
        let pml4 = cr3 as *const u64;
        let pml4_entry = *pml4.add(pml4_idx);
        if pml4_entry & PAGE_PRESENT == 0 {
            return None;
        }

        // PDPT
        let pdpt = (pml4_entry & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pdpt_entry = *pdpt.add(pdpt_idx);
        if pdpt_entry & PAGE_PRESENT == 0 {
            return None;
        }
        if pdpt_entry & PAGE_HUGE != 0 {
            return None; // 1GB huge page, not handling
        }

        // PD
        let pd = (pdpt_entry & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pd_entry = *pd.add(pd_idx);
        if pd_entry & PAGE_PRESENT == 0 {
            return None;
        }
        if pd_entry & PAGE_HUGE != 0 {
            return None; // 2MB huge page, not handling
        }

        // PT
        let pt = (pd_entry & 0x000F_FFFF_FFFF_F000) as *mut u64;
        let pte_ptr = pt.add(pt_idx);
        let pte_value = *pte_ptr;

        if pte_value & PAGE_PRESENT == 0 {
            return None;
        }

        // Get physical address before clearing
        let phys = pte_value & 0x000F_FFFF_FFFF_F000;

        // Clear the entry
        *pte_ptr = 0;

        // Flush TLB for this address
        ::core::arch::asm!(
            "invlpg [{}]",
            in(reg) vaddr,
            options(nostack, preserves_flags)
        );

        Some(phys)
    }
}

/// Walk page tables and return pointer to PTE and its current value
///
/// Returns (pte_pointer, pte_value) or None if page table walk fails
unsafe fn get_pte_for_addr(cr3: u64, vaddr: u64) -> Option<(*mut u64, u64)> {
    use crate::arch::x86_64::paging::{PAGE_HUGE, PAGE_PRESENT};

    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;

    unsafe {
        // PML4
        let pml4 = cr3 as *const u64;
        let pml4_entry = *pml4.add(pml4_idx);
        if pml4_entry & PAGE_PRESENT == 0 {
            return None;
        }

        // PDPT
        let pdpt = (pml4_entry & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pdpt_entry = *pdpt.add(pdpt_idx);
        if pdpt_entry & PAGE_PRESENT == 0 {
            return None;
        }
        if pdpt_entry & PAGE_HUGE != 0 {
            return None; // 1GB huge page, not handling COW for these
        }

        // PD
        let pd = (pdpt_entry & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pd_entry = *pd.add(pd_idx);
        if pd_entry & PAGE_PRESENT == 0 {
            return None;
        }
        if pd_entry & PAGE_HUGE != 0 {
            return None; // 2MB huge page, not handling COW for these
        }

        // PT
        let pt = (pd_entry & 0x000F_FFFF_FFFF_F000) as *mut u64;
        let pte_ptr = pt.add(pt_idx);
        let pte_value = *pte_ptr;

        if pte_value & PAGE_PRESENT == 0 {
            return None;
        }

        Some((pte_ptr, pte_value))
    }
}

/// Walk page tables and return pointer to PTE, even for non-present entries
///
/// Unlike get_pte_for_addr, this returns the PTE value even when PAGE_PRESENT is 0,
/// which is needed to detect swap entries.
///
/// Returns (pte_pointer, pte_value) or None if page table walk fails at higher levels
unsafe fn get_pte_for_swap(cr3: u64, vaddr: u64) -> Option<(*mut u64, u64)> {
    use crate::arch::x86_64::paging::{PAGE_HUGE, PAGE_PRESENT};

    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;

    unsafe {
        // PML4 - must be present
        let pml4 = cr3 as *const u64;
        let pml4_entry = *pml4.add(pml4_idx);
        if pml4_entry & PAGE_PRESENT == 0 {
            return None;
        }

        // PDPT - must be present
        let pdpt = (pml4_entry & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pdpt_entry = *pdpt.add(pdpt_idx);
        if pdpt_entry & PAGE_PRESENT == 0 {
            return None;
        }
        if pdpt_entry & PAGE_HUGE != 0 {
            return None; // 1GB huge page, no swap support
        }

        // PD - must be present
        let pd = (pdpt_entry & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pd_entry = *pd.add(pd_idx);
        if pd_entry & PAGE_PRESENT == 0 {
            return None;
        }
        if pd_entry & PAGE_HUGE != 0 {
            return None; // 2MB huge page, no swap support
        }

        // PT - return PTE regardless of present bit (for swap detection)
        let pt = (pd_entry & 0x000F_FFFF_FFFF_F000) as *mut u64;
        let pte_ptr = pt.add(pt_idx);
        let pte_value = *pte_ptr;

        Some((pte_ptr, pte_value))
    }
}

/// Handle a page fault for a swapped-out page
///
/// Detects swap entries in PTEs and performs swap-in:
/// 1. Check if PTE contains a swap entry (non-present with swap marker)
/// 2. Allocate a new physical frame
/// 3. Read page data from swap device
/// 4. Update PTE to point to the new frame
/// 5. Free the swap slot
///
/// Returns:
/// - Some(true) if the swap fault was handled successfully
/// - Some(false) if swap-in failed (e.g., OOM, I/O error)
/// - None if the PTE is not a swap entry
fn handle_swap_fault(cr3: u64, fault_addr: u64) -> Option<bool> {
    use crate::arch::x86_64::paging::{PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE};
    use crate::mm::{SwapEntry, free_swap_entry, swap_cache_lookup, swap_read_page};

    // Get the PTE (including non-present entries)
    let (pte_ptr, pte_value) = unsafe { get_pte_for_swap(cr3, fault_addr)? };

    // Check if this is a swap entry
    if !SwapEntry::is_swap_pte(pte_value) {
        return None; // Not a swap entry, let other handlers deal with it
    }

    let entry = SwapEntry::from_pte(pte_value);

    // Step 1: Check swap cache first
    if let Some(cached) = swap_cache_lookup(entry) {
        let frame = cached.frame;

        // Update PTE with cached page
        let new_pte = frame | PAGE_PRESENT | PAGE_USER | PAGE_WRITABLE;
        unsafe {
            core::ptr::write_volatile(pte_ptr, new_pte);
        }

        // Flush TLB
        unsafe {
            ::core::arch::asm!(
                "invlpg [{}]",
                in(reg) fault_addr,
                options(nostack, preserves_flags)
            );
        }

        // Increment major fault counter (swap cache hit still counts as major)
        crate::task::percpu::increment_maj_flt();

        return Some(true);
    }

    // Step 2: Allocate new frame
    let frame = match crate::FRAME_ALLOCATOR.alloc() {
        Some(f) => f,
        None => {
            serial_print(b"swap_fault: Out of memory!\r\n");
            return Some(false);
        }
    };

    // Step 3: Read from swap
    if swap_read_page(entry, frame).is_err() {
        // I/O error - free frame and fail
        crate::FRAME_ALLOCATOR.free(frame);
        serial_print(b"swap_fault: Swap I/O error!\r\n");
        return Some(false);
    }

    // Step 4: Update PTE - clear swap entry, set present with user/writable flags
    // Note: This is simplified - real implementation would preserve original flags
    let new_pte = frame | PAGE_PRESENT | PAGE_USER | PAGE_WRITABLE;
    unsafe {
        core::ptr::write_volatile(pte_ptr, new_pte);
    }

    // Step 5: Flush TLB for this address
    unsafe {
        ::core::arch::asm!(
            "invlpg [{}]",
            in(reg) fault_addr,
            options(nostack, preserves_flags)
        );
    }

    // Step 6: Free swap slot (page is now in RAM)
    free_swap_entry(entry);

    // Increment major fault counter (swap-in requires I/O)
    crate::task::percpu::increment_maj_flt();

    Some(true) // Swap-in successful
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
        sym handle_lapic_timer,
    );
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

    // Increment global tick count for percpu_sched
    crate::task::percpu::timer_tick();

    // Check for expired delayed work items (workqueue-based periodic tasks)
    crate::workqueue::timer_tick();

    // Wake any tasks whose sleep time has expired
    crate::task::percpu::wake_sleepers();

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
