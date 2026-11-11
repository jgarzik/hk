//! Lockdep-lite (feature `lockdep`; Linux lockdep / might_sleep, much
//! reduced)
//!
//! Checks, reported once each as `LOCKDEP:FAIL ...` on the console (the
//! boot tests fail on it):
//! - sleeping in atomic context: `might_sleep()` (sleeping locks,
//!   `schedule`, wait queues, socket waits, user copies) with a tracked
//!   spin lock held, a raised preempt count or interrupts disabled;
//! - lock order: classes (the source location of a lock's `new()`, like
//!   Linux's static lock_class_key) form A -> B edges when B is taken
//!   while A is held; taking B under A after A was seen under B reports
//!   both orders (direct inversions only, no transitive cycles; nesting
//!   within one class is not checked);
//! - a tracked (non-IRQ-safe) spin lock taken in interrupt context;
//! - interrupts enabled with an `IrqSpinlock` held (Linux lockdep's
//!   inconsistent lock state): a guard released out of nesting order
//!   restores the outer interrupt state while an inner lock is held,
//!   and an interrupt that takes that lock spins forever on its CPU.
//!
//! Audit list, not a failure (yet): a heap allocation in atomic context
//! (`might_alloc`, Linux might_alloc), once per site, as
//! `LOCKDEP:ATOMIC_ALLOC`.
//!
//! State: a per-CPU stack of held tracked locks (the kernel is not
//! preemptive and a task never sleeps holding one, so per-CPU equals
//! per-task) and a global fixed-size edge table under an untracked
//! spin lock. Nothing allocates. Without the feature every hook is an
//! empty inline function.

#[cfg(feature = "lockdep")]
pub use imp::{
    acquire, irq_enter, irq_exit, irqs_off, irqs_on, irqsafe_acquire, irqsafe_release, might_alloc,
    might_sleep, release,
};

/// Where a lock or interrupt state was taken
pub type Loc = &'static core::panic::Location<'static>;

/// Interrupt handler entry/exit (no-ops without `lockdep`)
#[cfg(not(feature = "lockdep"))]
#[inline(always)]
pub fn irq_enter() {}

#[cfg(not(feature = "lockdep"))]
#[inline(always)]
pub fn irq_exit() {}

/// An `IrqSpinlock` was taken at `at` / is being released (no-ops
/// without `lockdep`)
#[cfg(not(feature = "lockdep"))]
#[inline(always)]
pub fn irqsafe_acquire(_at: Loc) {}

#[cfg(not(feature = "lockdep"))]
#[inline(always)]
pub fn irqsafe_release(_lock: usize, _enables: bool) {}

/// Sleeping is about to be possible here (no-op without `lockdep`)
#[cfg(not(feature = "lockdep"))]
#[inline(always)]
pub fn might_sleep() {}

/// `local_irq_save` at `at` turned interrupts off / a restore turned
/// them back on (no-ops without `lockdep`)
#[cfg(not(feature = "lockdep"))]
#[inline(always)]
pub fn irqs_off(_at: Loc) {}

#[cfg(not(feature = "lockdep"))]
#[inline(always)]
pub fn irqs_on() {}

/// The heap is about to allocate `size` bytes (no-op without `lockdep`)
#[cfg(not(feature = "lockdep"))]
#[inline(always)]
pub fn might_alloc(_size: usize, _align: usize) {}

#[cfg(feature = "lockdep")]
mod imp {
    use core::cell::Cell;
    use core::panic::Location;
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    use super::Loc;
    use crate::cpu::PerCpu;
    use crate::sync::IrqSpinlock;

    /// Held tracked locks per CPU
    const DEPTH: usize = 48;
    /// Order edges (open addressing)
    const EDGES: usize = 4096;
    /// Distinct reports
    const REPORTS: usize = 256;

    #[derive(Clone, Copy)]
    struct HeldLock {
        id: usize,
        class: Loc,
        at: Loc,
    }

    /// A CPU's lockdep state: `Cell`s, because the same CPU re-enters
    /// it (an interrupt arriving mid-update, the `IrqSpinlock` of the
    /// graph taken while a slot is in use), so no `&mut` to it may exist
    struct Cpu {
        held: [Cell<Option<HeldLock>>; DEPTH],
        depth: Cell<usize>,
        /// Inside lockdep's own reporting: track nothing
        busy: Cell<bool>,
        /// Interrupt handler nesting
        irq: Cell<u32>,
        /// `IrqSpinlock`s held (a lock held across a context switch
        /// counts on the CPU, which the task switched to releases it on)
        irqsafe: Cell<u32>,
        /// Where the held `IrqSpinlock`s were taken, by nesting depth
        /// (report only: the innermost locates an atomic allocation,
        /// as Linux's preempt_disable_ip does; nested deeper than the
        /// table, the eighth)
        irqsafe_at: [Cell<Option<Loc>>; IRQSAFE_AT],
        /// The `local_irq_save` that turned interrupts off (report only)
        irqoff_at: Cell<Option<Loc>>,
    }

    /// `IrqSpinlock` nesting depths whose sites are kept
    const IRQSAFE_AT: usize = 8;

    struct Slot(Cpu);
    // SAFETY: each CPU touches only its own slot (`PerCpu::this`; the
    // kernel switches tasks only at points that hold no slot reference)
    unsafe impl Sync for Slot {}

    static CPUS: PerCpu<Slot> = crate::percpu![Slot(Cpu {
        held: [const { Cell::new(None) }; DEPTH],
        depth: Cell::new(0),
        busy: Cell::new(false),
        irq: Cell::new(0),
        irqsafe: Cell::new(0),
        irqsafe_at: [const { Cell::new(None) }; IRQSAFE_AT],
        irqoff_at: Cell::new(None),
    })];

    #[derive(Clone, Copy)]
    struct Edge {
        a: u64,
        b: u64,
        /// Where a and b were taken when the edge was first seen
        at_a: Loc,
        at_b: Loc,
    }

    struct Graph {
        edges: [Option<Edge>; EDGES],
        used: usize,
        reported: [u64; REPORTS],
        nreported: usize,
    }

    static GRAPH: IrqSpinlock<Graph> = IrqSpinlock::new(Graph {
        edges: [None; EDGES],
        used: 0,
        reported: [0; REPORTS],
        nreported: 0,
    });
    static FULL: AtomicBool = AtomicBool::new(false);
    /// Reports printed (for the summary line)
    static NREPORTS: AtomicU32 = AtomicU32::new(0);
    /// Distinct sites heap allocations were made at in atomic context
    static NATOMIC: AtomicU32 = AtomicU32::new(0);
    /// Their keys, apart from the report table (`Graph.reported`): the
    /// audit list cannot use up the room real reports need
    static ATOMIC_SEEN: [core::sync::atomic::AtomicU64; 2048] =
        [const { core::sync::atomic::AtomicU64::new(0) }; 2048];

    /// First time `k` (nonzero) is seen in ATOMIC_SEEN; false once full
    fn atomic_first(k: u64) -> bool {
        let n = ATOMIC_SEEN.len();
        for i in 0..n {
            let slot = &ATOMIC_SEEN[(k as usize + i) % n];
            match slot.compare_exchange(0, k, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(v) if v == k => return false,
                Err(_) => {}
            }
        }
        false
    }

    fn cpu() -> Option<&'static Cpu> {
        Some(&CPUS.this().0)
    }

    impl Cpu {
        /// The held locks, oldest first
        fn held(&self) -> impl Iterator<Item = HeldLock> + '_ {
            self.held[..self.depth.get().min(DEPTH)]
                .iter()
                .filter_map(Cell::get)
        }
    }

    fn key(l: Loc) -> u64 {
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for b in l.file().bytes() {
            h = (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3);
        }
        h ^ (u64::from(l.line()) << 20) ^ u64::from(l.column())
    }

    fn slot(a: u64, b: u64) -> usize {
        ((a.rotate_left(17) ^ b).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 51) as usize % EDGES
    }

    impl Graph {
        fn find(&self, a: u64, b: u64) -> Option<Edge> {
            let mut i = slot(a, b);
            for _ in 0..EDGES {
                match self.edges[i] {
                    None => return None,
                    Some(e) if e.a == a && e.b == b => return Some(e),
                    _ => i = (i + 1) % EDGES,
                }
            }
            None
        }

        fn add(&mut self, e: Edge) {
            if self.used >= EDGES * 3 / 4 {
                FULL.store(true, Ordering::Relaxed);
                return;
            }
            let mut i = slot(e.a, e.b);
            loop {
                match self.edges[i] {
                    None => {
                        self.edges[i] = Some(e);
                        self.used += 1;
                        return;
                    }
                    Some(x) if x.a == e.a && x.b == e.b => return,
                    _ => i = (i + 1) % EDGES,
                }
            }
        }

        /// First time for report `k`
        fn first(&mut self, k: u64) -> bool {
            if self.reported[..self.nreported].contains(&k) || self.nreported == REPORTS {
                return false;
            }
            self.reported[self.nreported] = k;
            self.nreported += 1;
            true
        }
    }

    fn report(c: &Cpu, f: impl FnOnce()) {
        c.busy.set(true);
        NREPORTS.fetch_add(1, Ordering::Relaxed);
        f();
        c.busy.set(false);
    }

    /// Before taking tracked lock `id` of `class` at `at` (`check`:
    /// a blocking acquisition, which records order edges)
    pub fn acquire(id: usize, class: Loc, at: Loc, check: bool) {
        let Some(c) = cpu() else {
            return;
        };
        if c.busy.get() {
            return;
        }
        if c.irq.get() > 0 {
            irq_report(c, class, at);
        }
        if check {
            order(c, class, at);
        }
        let d = c.depth.get();
        if d < DEPTH {
            c.held[d].set(Some(HeldLock { id, class, at }));
            c.depth.set(d + 1);
        }
    }

    fn irq_report(c: &Cpu, class: Loc, at: Loc) {
        let first = GRAPH.lock().first(key(class) ^ 0x1);
        if first {
            report(c, || {
                crate::printkln!(
                    "LOCKDEP:FAIL non-IRQ-safe spin lock {} taken in interrupt context at {}",
                    class,
                    at
                );
            });
        }
    }

    /// Record held -> `class` edges; report an inverse edge
    fn order(c: &Cpu, class: Loc, at: Loc) {
        let b = key(class);
        let mut bad: Option<(HeldLock, Edge)> = None;
        {
            let mut g = GRAPH.lock();
            for h in c.held() {
                let a = key(h.class);
                if a == b {
                    continue;
                }
                if g.find(a, b).is_none() {
                    g.add(Edge {
                        a,
                        b,
                        at_a: h.at,
                        at_b: at,
                    });
                }
                if bad.is_none()
                    && let Some(inv) = g.find(b, a)
                    && g.first(a.rotate_left(1) ^ b)
                {
                    bad = Some((h, inv));
                }
            }
        }
        if let Some((h, inv)) = bad {
            report(c, || {
                crate::printkln!(
                    "LOCKDEP:FAIL lock order inversion: {} (taken at {}) held while taking {} at {}; \
                     earlier the reverse order: {} taken at {} held while taking {} at {}",
                    h.class,
                    h.at,
                    class,
                    at,
                    class,
                    inv.at_a,
                    h.class,
                    inv.at_b
                );
            });
        }
    }

    /// After releasing tracked lock `id`
    pub fn release(id: usize) {
        let Some(c) = cpu() else {
            return;
        };
        let n = c.depth.get().min(DEPTH);
        let Some(i) = (0..n)
            .rev()
            .find(|&i| c.held[i].get().is_some_and(|h| h.id == id))
        else {
            return;
        };
        for j in i..n - 1 {
            c.held[j].set(c.held[j + 1].get());
        }
        c.held[n - 1].set(None);
        c.depth.set(n - 1);
    }

    /// Interrupt handler entry (generic tick and device IRQ dispatch)
    pub fn irq_enter() {
        if let Some(c) = cpu() {
            c.irq.set(c.irq.get() + 1);
        }
    }

    pub fn irq_exit() {
        if let Some(c) = cpu() {
            c.irq.set(c.irq.get().saturating_sub(1));
        }
    }

    /// This CPU's slot once its per-CPU data exists (an AP coming up
    /// takes `IrqSpinlock`s before; they are not counted)
    fn this_cpu() -> Option<&'static Cpu> {
        crate::cpu::try_this_id()?;
        cpu()
    }

    /// An `IrqSpinlock` was taken at `at` (interrupts off)
    pub fn irqsafe_acquire(at: Loc) {
        if let Some(c) = this_cpu() {
            let n = c.irqsafe.get();
            // Past the table the held sites are kept: a report names the
            // eighth lock, which is held, not a released deeper one
            if let Some(slot) = c.irqsafe_at.get(n as usize) {
                slot.set(Some(at));
            }
            c.irqsafe.set(n + 1);
        }
    }

    /// `local_irq_save` at `at` turned interrupts off
    pub fn irqs_off(at: Loc) {
        if let Some(c) = this_cpu() {
            c.irqoff_at.set(Some(at));
        }
    }

    /// A `local_irq_restore` turned interrupts back on
    pub fn irqs_on() {
        if let Some(c) = this_cpu() {
            c.irqoff_at.set(None);
        }
    }

    /// `IrqSpinlock` `lock` was released, interrupts still off; `enables`:
    /// its guard turns them back on, which another one held forbids
    pub fn irqsafe_release(lock: usize, enables: bool) {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        let Some(c) = this_cpu() else {
            return;
        };
        let held = c.irqsafe.get().saturating_sub(1);
        c.irqsafe.set(held);
        if !enables || held == 0 || c.busy.get() || REPORTED.swap(true, Ordering::Relaxed) {
            return;
        }
        report(c, || {
            crate::printkln!(
                "LOCKDEP:FAIL interrupts enabled with {} IRQ-safe spin lock(s) held: \
                 releasing {:#x} out of order (tid {})",
                held,
                lock,
                crate::task::percpu::current_tid()
            );
        });
    }

    /// Linux might_sleep: no spinlock may be held (tracked spin locks, or
    /// any `IrqSpinlock` / preemption disable via the preempt count)
    #[track_caller]
    pub fn might_sleep() {
        if !crate::task::percpu::can_sleep() {
            return;
        }
        let Some(c) = cpu() else {
            return;
        };
        let pc = crate::arch::preempt_count();
        // Syscalls and faults run with interrupts on: sleeping with them
        // off (and no spinlock owning them) is a bug (Linux might_sleep's
        // irqs_disabled check)
        let irqs_off = crate::sync::irqs_disabled();
        let depth = c.depth.get().min(DEPTH);
        let irq = c.irq.get();
        if c.busy.get() || (depth == 0 && pc == 0 && irq == 0 && !irqs_off) {
            return;
        }
        let at = Location::caller();
        let first = GRAPH.lock().first(key(at) ^ 0x2);
        if !first {
            return;
        }
        let held: [Option<HeldLock>; DEPTH] = core::array::from_fn(|i| c.held[i].get());
        report(c, || {
            crate::printkln!(
                "LOCKDEP:FAIL sleeping function called from atomic context at {} \
                 (spin locks held: {}, preempt count {}, irq {}, irqs off {}, tid {})",
                at,
                depth,
                pc,
                irq,
                irqs_off,
                crate::task::percpu::current_tid()
            );
            for h in held[..depth].iter().flatten() {
                crate::printkln!("LOCKDEP:   held {} taken at {}", h.class, h.at);
            }
        });
    }

    /// The heap is about to allocate `size` bytes with no GFP named:
    /// implicitly GFP_KERNEL, which atomic context (a spin lock of any
    /// kind, preemption or interrupts off) may not use (Linux
    /// might_alloc -> might_sleep_if). Not checked in an interrupt
    /// handler (implicitly GFP_ATOMIC), within reclaim (PF_MEMALLOC),
    /// or before the scheduler runs tasks (Linux skips SYSTEM_BOOTING).
    /// Listed once per site as `LOCKDEP:ATOMIC_ALLOC` (an audit list,
    /// not a failure): the innermost `IrqSpinlock` taken, else the
    /// innermost tracked spin lock, else where interrupts went off.
    pub fn might_alloc(size: usize, align: usize) {
        use crate::arch::{CurrentArch, PerCpuOps};
        let Some(c) = this_cpu() else {
            return;
        };
        let depth = c.depth.get().min(DEPTH);
        let pc = crate::arch::preempt_count();
        let off = crate::sync::irqs_disabled();
        if c.busy.get() || (depth == 0 && pc == 0 && !off) {
            return;
        }
        if c.irq.get() != 0 || CurrentArch::interrupt_depth() != 0 {
            return;
        }
        if !crate::task::percpu::can_sleep()
            || crate::task::percpu::current().has_flag(crate::task::pf::MEMALLOC)
        {
            return;
        }
        let n = c.irqsafe.get() as usize;
        let irqsafe = n
            .checked_sub(1)
            .and_then(|i| c.irqsafe_at[i.min(IRQSAFE_AT - 1)].get());
        let spin = depth.checked_sub(1).and_then(|i| c.held[i].get());
        let irqoff = if off { c.irqoff_at.get() } else { None };
        let k = irqsafe
            .map(|l| key(l) ^ 0x10)
            .or(spin.map(|h| key(h.class) ^ 0x11))
            .or(irqoff.map(|l| key(l) ^ 0x12))
            .unwrap_or(0x13 ^ (u64::from(pc) << 8));
        if !atomic_first(k | 1) {
            return;
        }
        c.busy.set(true);
        NATOMIC.fetch_add(1, Ordering::Relaxed);
        crate::printkln!(
            "LOCKDEP:ATOMIC_ALLOC heap allocation of {} (align {}) in atomic context: \
             IRQ-safe lock taken at {}; spin lock {} taken at {}; irqs off at {}; \
             preempt count {}, tid {}",
            size,
            align,
            Site(irqsafe),
            Site(spin.map(|h| h.class)),
            Site(spin.map(|h| h.at)),
            Site(irqoff),
            pc,
            crate::task::percpu::current_tid()
        );
        c.busy.set(false);
    }

    /// A location, or "-"
    struct Site(Option<Loc>);

    impl core::fmt::Display for Site {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self.0 {
                Some(l) => write!(f, "{}", l),
                None => f.write_str("-"),
            }
        }
    }

    /// Summary (shutdown): reports and edge-table use
    pub fn summary() {
        // Read under the graph lock, print after (printing may take
        // tracked locks, which take the graph lock)
        let used = GRAPH.lock().used;
        crate::printkln!(
            "lockdep: {} reports, {} order edges, {} atomic allocation sites{}",
            NREPORTS.load(Ordering::Relaxed),
            used,
            NATOMIC.load(Ordering::Relaxed),
            if FULL.load(Ordering::Relaxed) {
                " (table full)"
            } else {
                ""
            }
        );
    }
}

#[cfg(feature = "lockdep")]
pub use imp::summary;
