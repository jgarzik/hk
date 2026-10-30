//! Kernel entry and exit (Linux arch/x86/entry/entry_64.S)
//!
//! Every entry builds a [`PtRegs`] (Linux struct pt_regs, exact layout);
//! an entry from user mode builds it at the top of the task's kernel
//! stack (TSS.RSP0 for the IDT, the per-CPU top_of_stack for `syscall`),
//! so it is the task's only copy of its user registers while it is in
//! the kernel (`task::percpu::current_pt_regs`): signal frames, fork,
//! exec and ptrace read and write it there.
//!
//! - `syscall_entry`: swapgs, the kernel stack, the frame (orig_ax = the
//!   syscall number, ax = -ENOSYS), `do_syscall_64`; out by SYSRET when
//!   the frame allows it (Linux's check), else by IRET.
//! - IDT vectors: a stub per vector pushes -1 (or keeps the CPU's error
//!   code) as orig_ax and the vector number, `idt_common` swaps GS for a
//!   user CS, saves the rest and calls `idt_dispatch`; `irq_return`
//!   restores and leaves. NMI, #DF and #MC use `paranoid_common`.
//! - `irq_return` is also how a new task (`ret_from_fork`) and a new
//!   program image (`enter_user`) first reach user mode.

use super::PtRegs;
use super::cpu::{USER_CODE_SELECTOR, USER_DATA_SELECTOR};
use super::percpu::PerCpu;

/// -ENOSYS: the syscall frame's ax until the syscall returns
const ENOSYS: i64 = -38;

/// RFLAGS.TF and RFLAGS.RF: SYSRET cannot restore them (Linux
/// syscall_return_via_sysret check)
const SYSRET_BAD_FLAGS: u64 = 0x100 | 0x1_0000;

/// Syscall entry point (MSR_LSTAR)
///
/// On entry: RCX = user RIP, R11 = user RFLAGS, RSP = user stack, RAX =
/// syscall number, RDI, RSI, RDX, R10, R8, R9 = arguments; interrupts
/// off (SFMASK) until `do_syscall_64` has the frame.
#[unsafe(naked)]
pub unsafe extern "C" fn syscall_entry() {
    core::arch::naked_asm!(
        // Kernel GS base, then this task's kernel stack
        "swapgs",
        "mov gs:[{user_rsp}], rsp",
        "mov rsp, gs:[{top}]",

        // pt_regs, top down: ss, sp, flags, cs, ip, orig_ax, then the
        // general registers (ax = -ENOSYS)
        "push {uds}",
        "push gs:[{user_rsp}]",
        "push r11",
        "push {ucs}",
        "push rcx",
        "push rax",
        "push rdi",
        "push rsi",
        "push rdx",
        "push rcx",
        "push {enosys}",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        // do_syscall_64(regs): returns with interrupts off, true if
        // SYSRET can restore the frame
        "mov rdi, rsp",
        "sub rsp, 8",
        "call {do_syscall}",
        "add rsp, 8",
        "test al, al",
        "jz {iret}",

        // SYSRET: RCX and R11 in the frame equal RIP and RFLAGS
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rax",
        "pop rcx",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        "add rsp, 8",           // orig_ax; [rsp] = ip
        "mov rsp, [rsp + 24]",  // the user stack
        "swapgs",
        "sysretq",
        user_rsp = const core::mem::offset_of!(PerCpu, user_rsp),
        top = const core::mem::offset_of!(PerCpu, top_of_stack),
        uds = const USER_DATA_SELECTOR as u64,
        ucs = const USER_CODE_SELECTOR as u64,
        enosys = const ENOSYS,
        do_syscall = sym do_syscall_64,
        iret = sym irq_return,
    );
}

/// The syscall in C (Linux do_syscall_64): interrupts on while it runs,
/// off again on return; true if the return may use SYSRET
extern "C" fn do_syscall_64(regs: &mut PtRegs) -> bool {
    crate::arch::x86_64::interrupts::enable();
    let nr = crate::entry::syscall_enter_from_user_mode(regs);
    if nr != u64::MAX {
        regs.rax = super::syscall::x86_64_syscall_dispatch(
            nr, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9,
        );
    }
    // Signals, -ERESTART* rules, rescheduling before returning to user
    // space (they may redirect the frame to a handler or back up over
    // the syscall instruction; rt_sigreturn restored a whole user
    // context, orig_ax -1, and is not restarted); interrupts off after
    crate::entry::syscall_exit_to_user_mode(regs);
    sysret_ok(regs)
}

/// SYSRET can return to the frame (Linux syscall_return_via_sysret
/// checks): RCX/R11 hold RIP/RFLAGS, the user selectors, a canonical RIP
/// (SYSRET to a non-canonical one faults in kernel mode with the user
/// stack) and no TF/RF; anything else returns through IRET
fn sysret_ok(r: &PtRegs) -> bool {
    r.rcx == r.rip
        && r.r11 == r.rflags
        && r.cs == USER_CODE_SELECTOR as u64
        && r.ss == USER_DATA_SELECTOR as u64
        && r.rip < super::paging::TASK_SIZE
        && r.rflags & SYSRET_BAD_FLAGS == 0
}

/// An IDT stub: orig_ax (-1 unless the CPU pushed an error code), rdi,
/// the vector in edi, then `idt_common` (or `paranoid_common`)
macro_rules! idt_stub {
    ($name:ident, $vector:expr, $err:expr, $common:ident) => {
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                ".if {err} == 0",
                "push -1",
                ".endif",
                "push rdi",
                "mov edi, {vec}",
                "jmp {common}",
                err = const $err as u64,
                vec = const $vector as u32,
                common = sym $common,
            );
        }
    };
}

// Exceptions (Linux idtentry; err = 1: the CPU pushes an error code)
idt_stub!(exception_handler_0, 0, 0, idt_common); // Divide Error
idt_stub!(exception_handler_1, 1, 0, idt_common); // Debug
idt_stub!(exception_handler_2, 2, 0, paranoid_common); // NMI
idt_stub!(exception_handler_3, 3, 0, idt_common); // Breakpoint
idt_stub!(exception_handler_4, 4, 0, idt_common); // Overflow
idt_stub!(exception_handler_5, 5, 0, idt_common); // Bound Range
idt_stub!(exception_handler_6, 6, 0, idt_common); // Invalid Opcode
idt_stub!(exception_handler_7, 7, 0, idt_common); // Device Not Available
idt_stub!(exception_handler_8, 8, 1, paranoid_common); // Double Fault
idt_stub!(exception_handler_9, 9, 0, idt_common); // Coprocessor Segment Overrun
idt_stub!(exception_handler_10, 10, 1, idt_common); // Invalid TSS
idt_stub!(exception_handler_11, 11, 1, idt_common); // Segment Not Present
idt_stub!(exception_handler_12, 12, 1, idt_common); // Stack Segment Fault
idt_stub!(exception_handler_13, 13, 1, idt_common); // General Protection Fault
idt_stub!(exception_handler_14, 14, 1, idt_common); // Page Fault
idt_stub!(exception_handler_16, 16, 0, idt_common); // x87 FPU Error
idt_stub!(exception_handler_17, 17, 1, idt_common); // Alignment Check
idt_stub!(exception_handler_18, 18, 0, paranoid_common); // Machine Check
idt_stub!(exception_handler_19, 19, 0, idt_common); // SIMD FP Exception
idt_stub!(exception_handler_20, 20, 0, idt_common); // Virtualization Exception
idt_stub!(exception_handler_21, 21, 1, idt_common); // Control Protection

// Legacy PIC IRQs 0-15 (vectors 32-47)
idt_stub!(irq_handler_0, 32, 0, idt_common); // Timer (PIT)
idt_stub!(irq_handler_1, 33, 0, idt_common); // Keyboard
idt_stub!(irq_handler_2, 34, 0, idt_common); // Cascade
idt_stub!(irq_handler_3, 35, 0, idt_common); // COM2
idt_stub!(irq_handler_4, 36, 0, idt_common); // COM1
idt_stub!(irq_handler_5, 37, 0, idt_common); // LPT2
idt_stub!(irq_handler_6, 38, 0, idt_common); // Floppy
idt_stub!(irq_handler_7, 39, 0, idt_common); // LPT1/Spurious
idt_stub!(irq_handler_8, 40, 0, idt_common); // RTC
idt_stub!(irq_handler_9, 41, 0, idt_common); // ACPI/PCI
idt_stub!(irq_handler_10, 42, 0, idt_common); // PCI
idt_stub!(irq_handler_11, 43, 0, idt_common); // PCI
idt_stub!(irq_handler_12, 44, 0, idt_common); // PS/2 Mouse
idt_stub!(irq_handler_13, 45, 0, idt_common); // FPU
idt_stub!(irq_handler_14, 46, 0, idt_common); // Primary ATA
idt_stub!(irq_handler_15, 47, 0, idt_common); // Secondary ATA

// LAPIC timer and IPIs
idt_stub!(
    lapic_timer_handler,
    super::interrupts::LAPIC_TIMER_VECTOR,
    0,
    idt_common
);
idt_stub!(
    call_function_ipi,
    super::interrupts::CALL_FUNCTION_VECTOR,
    0,
    idt_common
);
idt_stub!(
    reschedule_ipi,
    super::interrupts::RESCHEDULE_VECTOR,
    0,
    idt_common
);

/// Common IDT entry: interrupts are off (interrupt gates); from user
/// mode (saved CS RPL 3) the kernel GS base comes first. Stack on entry:
/// [rdi, orig_ax, ip, cs, flags, sp, ss]; edi = vector.
#[unsafe(naked)]
unsafe extern "C" fn idt_common() {
    core::arch::naked_asm!(
        "test byte ptr [rsp + 24], 3",
        "jz 1f",
        "swapgs",
        "1:",
        // Interrupt gates leave DF and AC as the interrupted code had
        // them (user `std`/`stac`): forward string instructions, SMAP in
        // force (Linux error_entry: cld, ASM_CLAC)
        "cld",
        "push rsi",
        "push rdx",
        "push rcx",
        "push rax",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "cmp byte ptr [rip + {smap}], 0",
        "je 2f",
        "clac",
        "2:",
        // A fault on the return to user mode's iretq (Linux error_entry,
        // .Lbad_iret): taken in ring 0 after its swapgs, so the user GS
        // base is live although the saved CS is the kernel's. Back to
        // the kernel GS base, and the fault becomes the user's, on the
        // frame iretq was loading (fixup_bad_iret)
        "test byte ptr [rsp + {cs}], 3",
        "jnz 3f",
        "lea rax, [rip + hk_irq_return_iret]",
        "cmp [rsp + {ip}], rax",
        "jne 3f",
        "swapgs",
        "mov r12d, edi",
        "mov rdi, rsp",
        "sub rsp, 8",
        "call {fixup}",
        "mov rsp, rax",
        "mov edi, r12d",
        "3:",
        "mov esi, edi",
        "mov rdi, rsp",
        "sub rsp, 8",
        "call {dispatch}",
        "add rsp, 8",
        "jmp {ret}",
        smap = sym super::uaccess::SMAP_ON,
        cs = const core::mem::offset_of!(PtRegs, cs),
        ip = const core::mem::offset_of!(PtRegs, rip),
        fixup = sym fixup_bad_iret,
        dispatch = sym super::interrupts::idt_dispatch,
        ret = sym irq_return,
    );
}

/// A fault on `irq_return`'s iretq to user mode (Linux fixup_bad_iret):
/// `bad` is the fault's frame, whose registers are the user's (restored
/// already) and whose saved RSP points at the IRET frame being loaded.
/// Build the task's pt_regs from both -- the user's registers and IRET
/// frame, the fault's error code -- so the fault is handled as one
/// taken in user mode (#GP: SIGSEGV); returns them. The two frames
/// overlap at the top of the kernel stack: read all, then write.
extern "C" fn fixup_bad_iret(bad: &PtRegs) -> *mut PtRegs {
    // SAFETY: the IRET frame on this kernel stack, under `bad`'s RSP
    let user = unsafe { (bad.rsp as *const [u64; 5]).read() };
    let regs = PtRegs {
        rip: user[0],
        cs: user[1],
        rflags: user[2],
        rsp: user[3],
        ss: user[4],
        ..bad.clone()
    };
    let dst = crate::task::percpu::task_pt_regs(&crate::task::percpu::current());
    // SAFETY: the current task's pt_regs slot, nothing else lives there
    unsafe { dst.write(regs) };
    dst
}

/// Paranoid IDT entry (NMI, #DF, #MC; Linux paranoid_entry): these may
/// arrive between `syscall` and its `swapgs`, or between a return's
/// `swapgs` and its `iretq`, so the saved CS does not tell which GS
/// base is live. MSR_GS_BASE does: a kernel address is negative. EBX
/// (callee-saved) remembers whether to swap back.
#[unsafe(naked)]
unsafe extern "C" fn paranoid_common() {
    core::arch::naked_asm!(
        "cld",
        "push rsi",
        "push rdx",
        "push rcx",
        "push rax",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov ecx, {gs_base}",
        "rdmsr",
        "xor ebx, ebx",
        "test edx, edx",
        "js 1f",
        "swapgs",
        "mov ebx, 1",
        "1:",
        "cmp byte ptr [rip + {smap}], 0",
        "je 3f",
        "clac",
        "3:",
        "mov esi, edi",
        "mov rdi, rsp",
        "sub rsp, 8",
        "call {dispatch}",
        "add rsp, 8",
        "test ebx, ebx",
        "jz 2f",
        "swapgs",
        "2:",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rax",
        "pop rcx",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        "add rsp, 8",
        "iretq",
        gs_base = const super::percpu::MSR_GS_BASE,
        smap = sym super::uaccess::SMAP_ON,
        dispatch = sym super::interrupts::idt_dispatch,
    );
}

/// Return through IRET to the frame at RSP (Linux
/// restore_regs_and_return_to_kernel / swapgs_restore_regs_and_return_
/// to_usermode): interrupts off, then the user GS base for a user CS
#[unsafe(naked)]
pub unsafe extern "C" fn irq_return() {
    core::arch::naked_asm!(
        "cli",
        "test byte ptr [rsp + {cs}], 3",
        "jz 1f",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rax",
        "pop rcx",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        "add rsp, 8",
        "swapgs",
        // The one IRET to user mode: idt_common recognizes a fault here
        ".global hk_irq_return_iret",
        "hk_irq_return_iret:",
        "iretq",
        "1:",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rax",
        "pop rcx",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        "add rsp, 8",
        "iretq",
        cs = const core::mem::offset_of!(PtRegs, cs),
    );
}

/// Enter user mode at `entry` with the stack `sp` and every other
/// register zero (Linux start_thread + ELF_PLAT_INIT), building the
/// frame at the top of the kernel stack `kstack_top`
///
/// # Safety
/// The current task's address space is loaded and maps `entry` and `sp`;
/// `kstack_top` is its kernel stack.
pub unsafe fn enter_user(entry: u64, sp: u64, kstack_top: u64) -> ! {
    let regs = (kstack_top - core::mem::size_of::<PtRegs>() as u64) as *mut PtRegs;
    // SAFETY: the top of this task's kernel stack, below the caller's
    // frames only if the caller runs on another stack (init)
    unsafe {
        regs.write(PtRegs {
            rip: entry,
            cs: USER_CODE_SELECTOR as u64,
            rflags: 0x202, // IF + reserved bit 1
            rsp: sp,
            ss: USER_DATA_SELECTOR as u64,
            orig_rax: u64::MAX,
            ..Default::default()
        });
    }
    super::cpu::set_kernel_stack(kstack_top);
    // A new program image starts with the initial FP/SIMD state
    super::fpu::load_init_state();
    // Its return to user mode (a signal may be pending, the slice used up)
    // SAFETY: the frame above, this task's
    unsafe { core::arch::asm!("cli", options(nostack)) };
    crate::entry::exit_to_user_mode(unsafe { &mut *regs });
    // SAFETY: the frame above; nothing below it is used again
    unsafe {
        core::arch::asm!(
            "mov rsp, {regs}",
            "jmp {ret}",
            regs = in(reg) regs,
            ret = sym irq_return,
            options(noreturn)
        );
    }
}
