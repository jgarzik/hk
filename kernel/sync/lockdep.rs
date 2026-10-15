//! Lockdep-lite (feature `lockdep`; Linux lockdep / might_sleep, much
//! reduced)
//!
//! Checks, reported once each as `LOCKDEP:FAIL ...` on the console (the
//! boot tests fail on it):
//! - sleeping in atomic context: `might_sleep()` (sleeping locks,
//!   `schedule`, wait queues, socket waits, user copies) with a tracked
//!   spin lock held or a raised preempt count;
//! - lock order: classes (the source location of a lock's `new()`, like
//!   Linux's static lock_class_key) form A -> B edges when B is taken
//!   while A is held; taking B under A after A was seen under B reports
//!   both orders (direct inversions only, no transitive cycles; nesting
//!   within one class is not checked);
//! - a tracked (non-IRQ-safe) spin lock taken in interrupt context.
//!
//! State: a per-CPU stack of held tracked locks (the kernel is not
//! preemptive and a task never sleeps holding one, so per-CPU equals
//! per-task) and a global fixed-size edge table under an untracked
//! spin lock. Nothing allocates. Without the feature every hook is an
//! empty inline function.

#[cfg(feature = "lockdep")]
pub use imp::{acquire, irq_enter, irq_exit, might_sleep, release};

/// Interrupt handler entry/exit (no-ops without `lockdep`)
#[cfg(not(feature = "lockdep"))]
#[inline(always)]
pub fn irq_enter() {}

#[cfg(not(feature = "lockdep"))]
#[inline(always)]
pub fn irq_exit() {}

/// Sleeping is about to be possible here (no-op without `lockdep`)
#[cfg(not(feature = "lockdep"))]
#[inline(always)]
pub fn might_sleep() {}

#[cfg(feature = "lockdep")]
mod imp {
    use core::cell::UnsafeCell;
    use core::panic::Location;
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    use crate::arch::{CurrentArch, IrqSpinlock, PerCpuOps};

    type Loc = &'static Location<'static>;

    const MAX_CPUS: usize = <CurrentArch as PerCpuOps>::MAX_CPUS;
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

    struct Cpu {
        held: [Option<HeldLock>; DEPTH],
        depth: usize,
        /// Inside lockdep's own reporting: track nothing
        busy: bool,
        /// Interrupt handler nesting
        irq: u32,
    }

    struct PerCpu(UnsafeCell<Cpu>);
    // SAFETY: each CPU touches only its own slot, with no tracked lock
    // taken in interrupt context (reported otherwise)
    unsafe impl Sync for PerCpu {}

    static CPUS: [PerCpu; MAX_CPUS] = [const {
        PerCpu(UnsafeCell::new(Cpu {
            held: [None; DEPTH],
            depth: 0,
            busy: false,
            irq: 0,
        }))
    }; MAX_CPUS];

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

    fn cpu() -> Option<&'static mut Cpu> {
        let id = CurrentArch::try_current_cpu_id()? as usize;
        // SAFETY: see PerCpu
        CPUS.get(id).map(|c| unsafe { &mut *c.0.get() })
    }

    fn key(l: Loc) -> u64 {
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for b in l.file().bytes() {
            h = (h ^ b as u64).wrapping_mul(0x100_0000_01b3);
        }
        h ^ ((l.line() as u64) << 20) ^ l.column() as u64
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

    fn report(c: &mut Cpu, f: impl FnOnce()) {
        c.busy = true;
        NREPORTS.fetch_add(1, Ordering::Relaxed);
        f();
        c.busy = false;
    }

    /// Before taking tracked lock `id` of `class` at `at` (`check`:
    /// a blocking acquisition, which records order edges)
    pub fn acquire(id: usize, class: Loc, at: Loc, check: bool) {
        let Some(c) = cpu() else {
            return;
        };
        if c.busy {
            return;
        }
        if c.irq > 0 {
            irq_report(c, class, at);
        }
        if check {
            order(c, class, at);
        }
        if c.depth < DEPTH {
            c.held[c.depth] = Some(HeldLock { id, class, at });
            c.depth += 1;
        }
    }

    fn irq_report(c: &mut Cpu, class: Loc, at: Loc) {
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
    fn order(c: &mut Cpu, class: Loc, at: Loc) {
        let b = key(class);
        let mut bad: Option<(HeldLock, Edge)> = None;
        {
            let mut g = GRAPH.lock();
            for h in c.held[..c.depth].iter().flatten() {
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
                    bad = Some((*h, inv));
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
        let n = c.depth;
        let Some(i) = (0..n)
            .rev()
            .find(|&i| c.held[i].is_some_and(|h| h.id == id))
        else {
            return;
        };
        c.held.copy_within(i + 1..n, i);
        c.held[n - 1] = None;
        c.depth = n - 1;
    }

    /// Interrupt handler entry (generic tick and device IRQ dispatch)
    pub fn irq_enter() {
        if let Some(c) = cpu() {
            c.irq += 1;
        }
    }

    pub fn irq_exit() {
        if let Some(c) = cpu() {
            c.irq = c.irq.saturating_sub(1);
        }
    }

    /// Linux might_sleep: no spinlock may be held (tracked spin locks, or
    /// any `IrqSpinlock` / preemption disable via the preempt count)
    #[track_caller]
    pub fn might_sleep() {
        if !crate::task::percpu::SCHEDULING_ENABLED.load(Ordering::Acquire) {
            return;
        }
        let Some(c) = cpu() else {
            return;
        };
        let pc = crate::arch::preempt_count();
        if c.busy || (c.depth == 0 && pc == 0 && c.irq == 0) {
            return;
        }
        let at = Location::caller();
        let first = GRAPH.lock().first(key(at) ^ 0x2);
        if !first {
            return;
        }
        let held = c.held;
        let depth = c.depth;
        let irq = c.irq;
        report(c, || {
            crate::printkln!(
                "LOCKDEP:FAIL sleeping function called from atomic context at {} \
                 (spin locks held: {}, preempt count {}, irq {}, tid {})",
                at,
                depth,
                pc,
                irq,
                crate::task::percpu::current_tid()
            );
            for h in held[..depth].iter().flatten() {
                crate::printkln!("LOCKDEP:   held {} taken at {}", h.class, h.at);
            }
        });
    }

    /// Summary (shutdown): reports and edge-table use
    pub fn summary() {
        // Read under the graph lock, print after (printing may take
        // tracked locks, which take the graph lock)
        let used = GRAPH.lock().used;
        crate::printkln!(
            "lockdep: {} reports, {} order edges{}",
            NREPORTS.load(Ordering::Relaxed),
            used,
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
