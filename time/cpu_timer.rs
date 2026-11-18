//! POSIX CPU-time timers (Linux kernel/time/posix-cpu-timers.c, with
//! CONFIG_POSIX_CPU_TIMERS_TASK_WORK)
//!
//! Timers on a thread or process CPU clock, ITIMER_VIRTUAL/ITIMER_PROF,
//! RLIMIT_CPU and clock_nanosleep on a process CPU clock all run here:
//!
//! - The tick (interrupt context, no locks) compares the running task's
//!   CPU time and, while its thread group has process timers, the
//!   group's running totals with cached expiry times; past one it sets
//!   TIF_NOTIFY_RESUME (`tick`).
//! - On the way back to user mode the task, in its own context, runs
//!   the timers that are due (`run`): it rearms or disarms them, counts
//!   overruns, recomputes the caches and sends the signals once the
//!   registry lock is dropped.
//!
//! A thread timer is checked when its thread runs; a process timer when
//! any thread of the group runs (time only passes while one does).
//!
//! The group totals (Linux thread_group_cputimer) are atomics in the
//! SignalStruct, started from the group's CPU time when the first
//! process timer or a finite RLIMIT_CPU is armed and fed after by
//! every thread's runtime charges (`sched::update_se`) and tick samples
//! (`cputime::account_process_tick`), so they are exact to a tick. Thread caches
//! are per-task atomics. Both are hints: a stale one only costs a pass
//! of `run`.
//!
//! Locking: atomics only, except `run` and arming, which hold the
//! group's `posix_timers` while they decide and store the group's state
//! (`run` takes each timer's `inner` and the rlimit lock inside it);
//! the group's CPU time, which may take TASKLIST, is read before it.
//! Signals go out after it is dropped.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::time::posix_timer::ElistAdapter;
use crate::util::list::ArcList;

use crate::task::Tid;
use crate::task::cputime::TaskCputime;

/// No expiry
pub const NONE: u64 = u64::MAX;

/// What a CPU timer counts (Linux CPUCLOCK_PROF / VIRT / SCHED)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sample {
    /// utime + stime
    Prof = 0,
    /// utime
    Virt = 1,
    /// sum_exec_runtime
    Sched = 2,
}

/// The samples, in `Sample` order
const SAMPLES: [Sample; 3] = [Sample::Prof, Sample::Virt, Sample::Sched];

impl Sample {
    /// From a CPU clock id's low bits (CPUCLOCK_PROF 0, VIRT 1, SCHED
    /// 2; validated by the caller)
    pub fn of(which: u8) -> Self {
        match which {
            0 => Sample::Prof,
            1 => Sample::Virt,
            _ => Sample::Sched,
        }
    }

    /// This sample of `c` (Linux store_samples)
    pub fn pick(self, c: &TaskCputime) -> u64 {
        match self {
            Sample::Prof => c.utime.saturating_add(c.stime),
            Sample::Virt => c.utime,
            Sample::Sched => c.sum_exec_runtime,
        }
    }
}

/// The clock a CPU timer runs on: a thread of the owning group, or the
/// group itself
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CpuClock {
    /// The thread (None: the whole process)
    pub thread: Option<Tid>,
    pub sample: Sample,
}

/// A thread group's CPU timer state (Linux signal->cputimer and the
/// process part of posix_cputimers)
pub struct GroupCputimer {
    /// The totals below are kept (Linux posix_cputimers.timers_active)
    active: AtomicBool,
    /// Group utime, stime, sum_exec_runtime (ns) while active (Linux
    /// cputimer->cputime_atomic): every thread of the group adds to
    /// them from its own CPU, hence RMWs
    sums: [AtomicU64; 3],
    /// Earliest process-timer expiry per sample (ns), NONE if none
    next: [AtomicU64; 3],
}

impl GroupCputimer {
    pub const fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            sums: [const { AtomicU64::new(0) }; 3],
            next: [const { AtomicU64::new(NONE) }; 3],
        }
    }

    /// A thread of the group got `delta` ns of user time (Linux
    /// account_group_user_time)
    pub fn account_user_time(&self, delta: u64) {
        if self.active.load(Ordering::Relaxed) {
            self.sums[0].fetch_add(delta, Ordering::Relaxed);
        }
    }

    /// A thread of the group got `delta` ns of system time (Linux
    /// account_group_system_time)
    pub fn account_system_time(&self, delta: u64) {
        if self.active.load(Ordering::Relaxed) {
            self.sums[1].fetch_add(delta, Ordering::Relaxed);
        }
    }

    /// A thread of the group was charged `delta` ns of runtime (Linux
    /// account_group_exec_runtime)
    pub fn account_exec_runtime(&self, delta: u64) {
        if self.active.load(Ordering::Relaxed) {
            self.sums[2].fetch_add(delta, Ordering::Relaxed);
        }
    }

    /// The group's CPU time, if kept (Linux proc_sample_cputime_atomic)
    pub fn totals(&self) -> Option<TaskCputime> {
        self.active.load(Ordering::Acquire).then(|| TaskCputime {
            utime: self.sums[0].load(Ordering::Relaxed),
            stime: self.sums[1].load(Ordering::Relaxed),
            sum_exec_runtime: self.sums[2].load(Ordering::Relaxed),
        })
    }

    /// Start keeping totals from the group's CPU time `now` (Linux
    /// thread_group_start_cputime); under the group's `posix_timers`,
    /// as every start and stop, so the load-then-stores cannot race
    fn start(&self, now: TaskCputime) {
        if !self.active.load(Ordering::Acquire) {
            self.sums[0].store(now.utime, Ordering::Relaxed);
            self.sums[1].store(now.stime, Ordering::Relaxed);
            self.sums[2].store(now.sum_exec_runtime, Ordering::Relaxed);
            self.active.store(true, Ordering::Release);
        }
    }

    fn stop(&self) {
        self.active.store(false, Ordering::Release);
        for n in &self.next {
            n.store(NONE, Ordering::Relaxed);
        }
    }

    /// Lower the cached expiry of `s` to `at`
    fn arm(&self, s: Sample, at: u64) {
        self.next[s as usize].fetch_min(at, Ordering::Relaxed);
    }

    /// Past a process expiry
    fn due(&self) -> bool {
        self.totals().is_some_and(|t| past(&t, &self.next))
    }
}

/// `c` is past one of the expiries `next` (Linux
/// task_cputimers_expired)
fn past(c: &TaskCputime, next: &[AtomicU64; 3]) -> bool {
    SAMPLES
        .iter()
        .zip(next)
        .any(|(s, n)| s.pick(c) >= n.load(Ordering::Relaxed))
}

/// Group `pid`'s current CPU time: its kept totals, else the sum over
/// its threads (Linux cpu_clock_sample_group with start=false; thread
/// context). Never starts the totals: only arming a process timer does
/// (`arm_group`, under `posix_timers`), so clock_gettime,
/// timer_gettime, settime's old value and clock_nanosleep's remainder
/// leave the group's accounting as they found it.
pub fn group_sample(sig: &crate::signal::SignalStruct, pid: crate::task::Pid) -> TaskCputime {
    sig.cputimer.totals().unwrap_or_else(|| {
        let table = crate::task::percpu::TASKLIST.read();
        crate::task::cputime::thread_group_cputime(&table, pid)
    })
}

/// Thread `t`'s clock `s` now (Linux cpu_clock_sample): its runtime
/// with the running slice, or its utime/stime samples
pub fn cpu_clock_sample(t: &crate::task::Task, s: Sample) -> u64 {
    match s {
        Sample::Sched => crate::task::percpu::task_sched_runtime(t),
        _ => s.pick(&crate::task::cputime::task_cputime(t)),
    }
}

/// Thread `tid`'s clock `s` now, if it is alive
pub fn thread_sample(tid: Tid, s: Sample) -> Option<u64> {
    let me = crate::task::percpu::current();
    if me.tid() == tid {
        return Some(cpu_clock_sample(&me, s));
    }
    // Found and sampled under RCU (Linux cpu_timer_task_rcu,
    // cpu_clock_sample under rcu_read_lock)
    let g = crate::sync::rcu::read_lock();
    crate::task::percpu::pid_ns_task(tid, &crate::ns::INIT_PID_NS, &g)
        .map(|t| cpu_clock_sample(t, s))
}

/// The value of `clock` now (process: group `pid`'s totals)
pub fn sample_now(clock: CpuClock, pid: crate::task::Pid) -> Option<u64> {
    match clock.thread {
        Some(tid) => thread_sample(tid, clock.sample),
        None => crate::signal::current_signal().map(|g| clock.sample.pick(&group_sample(&g, pid))),
    }
}

/// Lower group `sig`'s cached expiry of `s` to `at`, keeping its totals
/// (restarted from `sample`, a fresh group CPU time, if `run` stopped
/// them meanwhile). Under `posix_timers`, like the end of `run`, so a
/// pass that found nothing armed cannot stop or overwrite this one.
fn arm_group(sig: &crate::signal::SignalStruct, s: Sample, at: u64, sample: TaskCputime) {
    let _reg = sig.posix_timers.lock();
    sig.cputimer.start(sample);
    sig.cputimer.arm(s, at);
}

/// A timer on `clock` expires at `at`: lower the cache that sees it
pub fn arm(clock: CpuClock, at: u64) {
    match clock.thread {
        Some(tid) => {
            // The thread's task, then its hint under the group's
            // posix_timers (which that thread's `run` holds while it
            // recomputes the hint), so a pass under way cannot erase it
            let me = crate::task::percpu::current();
            let task = if me.tid() == tid {
                Some(crate::task::percpu::task_ref(&me))
            } else {
                crate::task::percpu::find_task(tid)
            };
            let (Some(t), Some(g)) = (task, crate::signal::current_signal()) else {
                return;
            };
            let _reg = g.posix_timers.lock();
            t.cpu_next[clock.sample as usize].fetch_min(at, Ordering::Relaxed);
        }
        None => {
            if let Some(g) = crate::signal::current_signal() {
                let sample = group_sample(&g, crate::task::percpu::current_pid());
                arm_group(&g, clock.sample, at, sample);
            }
        }
    }
}

/// The tick, on task `t` (interrupt context): past an expiry of the
/// thread's own or of its group's, run the timers on the way back to
/// user mode (Linux run_posix_cpu_timers' fastpath + task_work)
pub fn tick(t: &crate::task::Task) {
    let armed = t.cpu_next.iter().any(|n| n.load(Ordering::Relaxed) != NONE);
    let mut due = armed && past(&crate::task::cputime::task_cputime(t), &t.cpu_next);
    if !due {
        due = t.cpu_group().is_some_and(|g| g.cputimer.due());
    }
    if due {
        t.set_tif(crate::task::tif::NOTIFY_RESUME);
    }
}

/// Run the calling task's due CPU timers and its group's (task context,
/// on the way back to user mode; Linux handle_posix_cpu_timers). Out of
/// line: inlined, its sends grew the return path's frame (every return
/// to user mode, and the signal delivery under it) by ~370 bytes on
/// arm64
#[inline(never)]
pub fn run() {
    use crate::task::percpu;
    let me = percpu::current();
    let tid = me.tid();
    let Some(sig) = me.cpu_group().cloned() else {
        return;
    };
    // Its samples as of the last charge (Linux check_thread_timers:
    // task_sample_cputime)
    let mine = crate::task::cputime::task_cputime(&me);
    // Expired timers, linked under the lock and fired after it (Linux
    // collect_timerqueue's firing list); the process signals of the
    // itimers (VIRT, PROF) and RLIMIT_CPU, at most one each
    let mut firing: ArcList<ElistAdapter> = ArcList::new();
    let mut itimer_sig = [None; 2];
    let mut rlimit_sig = None;
    let mut thread_next = [NONE; 3];
    let mut proc_next = [NONE; 3];
    let mut any_process = false;
    // The whole pass under `posix_timers`: arming (`arm_group`) takes
    // it too, so what is decided below holds until it is stored
    let reg = sig.posix_timers.lock();
    let group = sig.cputimer.totals();
    for t in reg.iter() {
        let Some(clock) = t.cpu_clock() else {
            continue;
        };
        let now = match clock.thread {
            Some(x) if x == tid => clock.sample.pick(&mine),
            // Another thread's timer: checked when it runs
            Some(_) => continue,
            None => {
                any_process |= t.armed();
                match group {
                    Some(g) => clock.sample.pick(&g),
                    None => continue,
                }
            }
        };
        if let Some(Expired::Collect) = t.cpu_expire(now) {
            firing.push_back(t.clone());
        }
        if let Some(at) = t.cpu_expiry() {
            let n = match clock.thread {
                Some(_) => &mut thread_next[clock.sample as usize],
                None => &mut proc_next[clock.sample as usize],
            };
            *n = (*n).min(at);
        }
    }
    // The process's ITIMER_VIRTUAL and ITIMER_PROF, in its SignalStruct
    // (Linux check_process_timers: check_cpu_itimer after the timers)
    for (t, out) in sig.itimers.cpu.iter().zip(&mut itimer_sig) {
        any_process |= t.armed();
        let (Some(g), Some(clock)) = (group, t.cpu_clock()) else {
            continue;
        };
        if let Some(Expired::Signal(s)) = t.cpu_expire(clock.sample.pick(&g)) {
            *out = Some(s);
        }
        if let Some(at) = t.cpu_expiry() {
            let n = &mut proc_next[clock.sample as usize];
            *n = (*n).min(at);
        }
    }
    // Still under posix_timers: `arm` of a thread timer lowers this
    // under it too
    for (i, n) in thread_next.iter().enumerate() {
        me.cpu_next[i].store(*n, Ordering::Relaxed);
    }
    // RLIMIT_CPU (Linux check_process_timers): SIGXCPU at the soft
    // limit and each second after it (the soft limit moves up a second
    // each time), SIGKILL at the hard limit
    let limited = match group {
        Some(g) => rlimit_cpu(
            &sig,
            Sample::Prof.pick(&g),
            &mut rlimit_sig,
            &mut proc_next[0],
        ),
        None => rlimit_finite(&sig),
    };
    if any_process || limited {
        for (i, n) in proc_next.iter().enumerate() {
            sig.cputimer.next[i].store(*n, Ordering::Relaxed);
        }
    } else {
        sig.cputimer.stop();
    }
    drop(reg);
    while let Some(t) = firing.pop_front() {
        t.cpu_fire();
    }
    // From the kernel to the process (Linux SEND_SIG_PRIV)
    for s in itimer_sig.into_iter().chain([rlimit_sig]).flatten() {
        let _ = crate::signal::send_group_signal(&me, s, crate::signal::SendInfo::Kernel);
    }
}

/// RLIMIT_CPU is finite
fn rlimit_finite(sig: &crate::signal::SignalStruct) -> bool {
    sig.get_rlimit(crate::task::rlimit::RLIMIT_CPU)
        .is_some_and(|r| r.rlim_cur != crate::task::rlimit::RLIM_INFINITY)
}

/// The RLIMIT_CPU part of `run` at process CPU time `prof`; true if the
/// limit is finite (the totals must stay kept)
fn rlimit_cpu(
    sig: &crate::signal::SignalStruct,
    prof: u64,
    send: &mut Option<crate::signal::Signal>,
    next: &mut u64,
) -> bool {
    use crate::task::rlimit::{RLIM_INFINITY, RLIMIT_CPU};
    const SEC: u64 = 1_000_000_000;
    let Some(r) = sig.get_rlimit(RLIMIT_CPU) else {
        return false;
    };
    if r.rlim_cur == RLIM_INFINITY {
        return false;
    }
    let secs = prof / SEC;
    if r.rlim_max != RLIM_INFINITY && secs >= r.rlim_max {
        *send = Some(crate::signal::SIGKILL);
        return true;
    }
    let mut soft = r.rlim_cur;
    if secs >= soft {
        *send = Some(crate::signal::SIGXCPU);
        if soft < r.rlim_max {
            soft += 1;
            sig.set_rlimit_cur(RLIMIT_CPU, soft);
        }
    }
    let at = |s: u64| s.saturating_mul(SEC);
    *next = (*next).min(at(soft));
    if r.rlim_max != RLIM_INFINITY {
        *next = (*next).min(at(r.rlim_max));
    }
    true
}

/// setrlimit(RLIMIT_CPU) of process `pid`, or a fork with a finite one
/// (Linux update_rlimit_cpu, posix_cpu_timers_init_group): keep the
/// group's totals and look at the limit at its next tick
pub fn rlimit_cpu_changed(sig: &crate::signal::SignalStruct, pid: crate::task::Pid) {
    if rlimit_finite(sig) {
        let sample = group_sample(sig, pid);
        arm_group(sig, Sample::Prof, 0, sample);
    }
}

/// What an expired CPU timer asks for
pub enum Expired {
    /// An itimer's signal for the process
    Signal(crate::signal::Signal),
    /// To go on the firing list (a timer_create timer's queued signal,
    /// a clock_nanosleep's wakeup), marked collected
    Collect,
}
