//! Cross-CPU function calls and the reschedule IPI (Linux kernel/smp.c)
//!
//! [`smp_call_function_many`] runs `func(info)` on other CPUs from their
//! call-function IPI and, with `wait`, returns once every one has
//! finished. Each target has a lock-free queue of pending calls
//! (`QUEUE`, Linux call_single_queue: an llist); each sender has one
//! call slot per target (`CFD`, Linux cfd_data). The queue is a LIFO
//! that many CPUs push onto (compare-and-swap) and only its owner
//! empties (one swap), so there is no ABA problem, no lock to order
//! against others and no interrupt masking on the sending side. Only
//! the first push onto an empty queue sends the IPI: whoever finds the
//! queue non-empty knows an IPI is on its way or the owner has not
//! emptied it yet.
//!
//! Waiting (for a call to finish, or for a slot reused before its last
//! call finished) never blocks this CPU's own queue: the wait loop runs
//! the calls queued here (`poll`), so two CPUs calling each other, or
//! a sender whose interrupts are off (a syscall), make progress. Calls
//! must not be made from interrupt context or with an IrqSpinlock held
//! (a target spinning on that lock with interrupts off would never
//! answer: doc/LOCKING.md, Cross-CPU Calls).

use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering, fence};

use crate::arch::{CurrentArch, PerCpuOps, local_irq_restore, local_irq_save};
use crate::cpumask::{CpuMask, CpuSet, NR_CPUS};

/// One call (Linux call_single_data)
struct Csd {
    /// Next queued call (the queue is a singly linked list)
    next: AtomicPtr<Csd>,
    /// `fn(usize)` to run
    func: AtomicUsize,
    info: AtomicUsize,
    /// Queued or running (Linux CSD_FLAG_LOCK): set by the sender,
    /// cleared by the target once `func` returned
    locked: AtomicBool,
}

impl Csd {
    const fn new() -> Self {
        Self {
            next: AtomicPtr::new(core::ptr::null_mut()),
            func: AtomicUsize::new(0),
            info: AtomicUsize::new(0),
            locked: AtomicBool::new(false),
        }
    }
}

/// Per sender CPU, one call slot per target CPU (Linux per-CPU cfd_data).
/// A CPU sends from thread context only and the kernel is not
/// preemptive, so its row is used by one call at a time.
static CFD: [[Csd; NR_CPUS]; NR_CPUS] = [const { [const { Csd::new() }; NR_CPUS] }; NR_CPUS];

/// Per-CPU queue of calls to run there (Linux call_single_queue)
static QUEUE: [AtomicPtr<Csd>; NR_CPUS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; NR_CPUS];

/// CPUs that take call-function IPIs (Linux cpu_active_mask): set by
/// each CPU once it services interrupts. One global mask: every sender
/// needs every CPU's state, and it changes once per CPU at boot.
static ACTIVE: CpuMask = CpuMask::new();

/// This CPU's id (0 before per-CPU data exists: only the boot CPU runs)
fn this_cpu() -> u32 {
    CurrentArch::try_current_cpu_id().unwrap_or(0)
}

/// This CPU now services call-function IPIs (its interrupt controller
/// is up and interrupts are enabled)
pub fn set_active(cpu: u32) {
    ACTIVE.set(cpu);
    // Before the local flush: a kernel-range flush that missed this
    // CPU changed its page tables before reading the mask
    fence(Ordering::SeqCst);
    crate::mm::tlb::cpu_active();
}

/// The CPUs that take call-function IPIs
pub fn active_cpus() -> CpuSet {
    ACTIVE.snapshot()
}

/// Run `func(info)` on each active CPU of `mask` other than this one
/// (Linux smp_call_function_many); with `wait`, return once all of them
/// finished it. Thread context only; interrupts may be off.
pub fn smp_call_function_many(mask: &CpuSet, func: fn(usize), info: usize, wait: bool) {
    check_context();
    let me = this_cpu();
    let mut targets = mask.and(&ACTIVE.snapshot());
    targets.clear(me);
    let row = &CFD[me as usize];
    for cpu in targets.iter() {
        let csd = &row[cpu as usize];
        // The slot's last (async) call must be done before reuse
        csd_wait(csd, me);
        csd.func.store(func as usize, Ordering::Relaxed);
        csd.info.store(info, Ordering::Relaxed);
        csd.locked.store(true, Ordering::Relaxed);
        if enqueue(&QUEUE[cpu as usize], csd) {
            crate::arch::ipi::send_call_function(cpu);
        }
    }
    if wait {
        for cpu in targets.iter() {
            csd_wait(&row[cpu as usize], me);
        }
    }
}

/// Run `func(info)` on every active CPU, this one included (with
/// interrupts off, as on the others), and wait for all (Linux
/// on_each_cpu)
pub fn on_each_cpu(func: fn(usize), info: usize) {
    smp_call_function_many(&ACTIVE.snapshot(), func, info, true);
    let irq = local_irq_save();
    func(info);
    local_irq_restore(irq);
}

/// Ask `cpu` to reschedule (Linux smp_send_reschedule): wakes it from
/// idle to pick up a remote wakeup. Any context.
pub fn smp_send_reschedule(cpu: u32) {
    if cpu != this_cpu() && ACTIVE.test(cpu) {
        crate::arch::ipi::send_reschedule(cpu);
    }
}

/// Push `csd` onto `head`; true if the queue was empty (the IPI is ours
/// to send)
fn enqueue(head: &AtomicPtr<Csd>, csd: &Csd) -> bool {
    let new = csd as *const Csd as *mut Csd;
    let mut old = head.load(Ordering::Relaxed);
    loop {
        csd.next.store(old, Ordering::Relaxed);
        // Release: the slot's fields are visible to the owner's swap
        match head.compare_exchange_weak(old, new, Ordering::Release, Ordering::Relaxed) {
            Ok(_) => return old.is_null(),
            Err(cur) => old = cur,
        }
    }
}

/// Spin until `csd` is free, running this CPU's queued calls meanwhile
fn csd_wait(csd: &Csd, me: u32) {
    while csd.locked.load(Ordering::Acquire) {
        poll(me);
        core::hint::spin_loop();
    }
}

/// Run the calls queued for this CPU now, with interrupts off (the IPI
/// handler may otherwise run calls concurrently on this CPU)
fn poll(me: u32) {
    if !QUEUE[me as usize].load(Ordering::Relaxed).is_null() {
        let irq = local_irq_save();
        run_queue(me);
        local_irq_restore(irq);
    }
}

/// Call-function IPI handler (interrupts off, arch IPI entry): run the
/// calls queued for this CPU (Linux generic_smp_call_function_interrupt)
pub fn call_function_interrupt() {
    run_queue(this_cpu());
}

/// Reschedule IPI handler: the woken task is picked at this CPU's next
/// scheduling point (the idle loop's, right after this interrupt)
pub fn reschedule_interrupt() {
    CurrentArch::set_needs_reschedule(true);
}

/// Take every call queued for `me` and run them in queue order
fn run_queue(me: u32) {
    // Acquire: pairs with the senders' Release pushes
    let mut list = QUEUE[me as usize].swap(core::ptr::null_mut(), Ordering::Acquire);
    // LIFO to FIFO (Linux llist_reverse_order)
    let mut fifo: *mut Csd = core::ptr::null_mut();
    while !list.is_null() {
        // SAFETY: a slot in CFD (static), queued and owned by us until
        // `locked` is cleared
        let csd = unsafe { &*list };
        list = csd.next.load(Ordering::Relaxed);
        csd.next.store(fifo, Ordering::Relaxed);
        fifo = csd as *const Csd as *mut Csd;
    }
    while !fifo.is_null() {
        // SAFETY: as above
        let csd = unsafe { &*fifo };
        fifo = csd.next.load(Ordering::Relaxed);
        let func = csd.func.load(Ordering::Relaxed);
        let info = csd.info.load(Ordering::Relaxed);
        // SAFETY: stored from a `fn(usize)` by the sender
        let func: fn(usize) = unsafe { core::mem::transmute::<usize, fn(usize)>(func) };
        func(info);
        // Release: the function's effects before the sender's return;
        // the slot is the sender's again
        csd.locked.store(false, Ordering::Release);
    }
}

/// A cross-CPU call from interrupt context, or with this CPU's interrupt
/// state owned by an IrqSpinlock, could deadlock (reported once)
fn check_context() {
    if CurrentArch::interrupt_depth() > 0 || crate::arch::preempt_count() > 0 {
        static WARNED: AtomicBool = AtomicBool::new(false);
        if !WARNED.swap(true, Ordering::Relaxed) {
            crate::printkln!(
                "\nLOCKDEP:FAIL smp_call_function_many in atomic context (irq depth {}, preempt {})",
                CurrentArch::interrupt_depth(),
                crate::arch::preempt_count()
            );
        }
    }
}
