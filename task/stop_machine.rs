//! CPU stoppers (Linux kernel/stop_machine.c, reduced to stop_one_cpu)
//!
//! Each CPU with a scheduler runs `migration/N`, a kernel thread bound
//! to it at the highest priority: work queued for it with
//! [`stop_one_cpu`] preempts whatever runs there at its next scheduling
//! point (a reschedule IPI and the task's return to user mode; the
//! kernel is not preemptive) and runs with no task of that CPU queued
//! ahead. The scheduler uses it to move a task off a CPU it may no
//! longer run on, or to a better one at exec (`migration_cpu_stop`).
//!
//! Locking: a CPU's stopper takes one work item at a time; waiting
//! callers queue under its sleeping `lock` and wait for completion with
//! it held; `stop_one_cpu_nowait` (any context, the soft lockup
//! detector) only fills an empty slot (`work`, an IrqSpinlock leaf).

use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::IrqSpinlock;
use crate::completion::Completion;
use crate::cpu::PerCpu;
use crate::sync::Mutex;
use crate::waitqueue::WaitQueue;

/// One queued call (Linux cpu_stop_work)
#[derive(Clone, Copy)]
struct Work {
    func: fn(usize),
    arg: usize,
    /// Null for `stop_one_cpu_nowait`
    done: *const Completion,
}

// SAFETY: the completion lives on the caller's stack until `done` fires,
// which the caller waits for
unsafe impl Send for Work {}

/// A CPU's stopper (Linux struct cpu_stopper)
struct Stopper {
    /// One caller at a time
    lock: Mutex<()>,
    /// The call to run
    work: IrqSpinlock<Option<Work>>,
    /// The thread sleeps here
    wq: WaitQueue,
    /// Its thread runs
    enabled: AtomicBool,
}

static STOPPERS: PerCpu<Stopper> = crate::percpu![Stopper {
    lock: Mutex::new(()),
    work: IrqSpinlock::new(None),
    wq: WaitQueue::new(),
    enabled: AtomicBool::new(false),
}];

/// Run `func(arg)` on `cpu` from its stopper and wait for it (Linux
/// stop_one_cpu); thread context, may sleep. False if `cpu` has no
/// stopper (yet).
pub fn stop_one_cpu(cpu: u32, func: fn(usize), arg: usize) -> bool {
    let Some(st) = STOPPERS.try_get(cpu) else {
        return false;
    };
    if !st.enabled.load(Ordering::Acquire) {
        return false;
    }
    let _g = st.lock.lock();
    let done = Completion::new();
    // A nowait call may hold the slot: wait for the stopper to take it
    loop {
        let mut w = st.work.lock();
        if w.is_none() {
            *w = Some(Work {
                func,
                arg,
                done: &done,
            });
            break;
        }
        drop(w);
        crate::task::percpu::yield_now();
    }
    st.wq.wake_all();
    done.wait();
    true
}

/// Queue `func(arg)` on `cpu`'s stopper without waiting (Linux
/// stop_one_cpu_nowait); any context. False if it has no stopper or
/// already has a call queued.
pub fn stop_one_cpu_nowait(cpu: u32, func: fn(usize), arg: usize) -> bool {
    let Some(st) = STOPPERS.try_get(cpu) else {
        return false;
    };
    if !st.enabled.load(Ordering::Acquire) {
        return false;
    }
    {
        let mut w = st.work.lock();
        if w.is_some() {
            return false;
        }
        *w = Some(Work {
            func,
            arg,
            done: core::ptr::null(),
        });
    }
    st.wq.wake_all();
    true
}

/// `migration/N`: run what is queued for this CPU (Linux
/// cpu_stopper_thread)
fn stopper_thread(cpu: usize) {
    let st = STOPPERS.get(cpu as u32);
    loop {
        st.wq.wait_event(|| st.work.lock().is_some());
        let Some(w) = st.work.lock().take() else {
            continue;
        };
        (w.func)(w.arg);
        // SAFETY: the caller waits for this before its stack goes
        if let Some(done) = unsafe { w.done.as_ref() } {
            done.complete();
        }
    }
}

/// Start `migration/N` on every CPU with a scheduler (Linux
/// cpu_stop_init)
pub fn start() {
    for cpu in 0..crate::cpu::nr_cpu_ids() {
        if !super::percpu::cpu_has_scheduler(cpu) {
            continue;
        }
        let name = alloc::format!("migration/{}", cpu);
        match super::kthread::kthread_run_prio(
            &name,
            stopper_thread,
            cpu as usize,
            Some(cpu),
            super::PRIORITY_REALTIME,
        ) {
            Ok(_) => STOPPERS.get(cpu).enabled.store(true, Ordering::Release),
            Err(e) => crate::printkln!("stop_machine: cannot start {}: {:?}", name, e),
        }
    }
}
