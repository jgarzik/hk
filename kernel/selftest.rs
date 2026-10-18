//! Boot-time kernel self-test of kernel threads, workqueues and ticks
//!
//! Runs in its own kernel thread (on CPU 1 when it exists, exercising
//! cross-CPU wakeups) in parallel with user space, and prints one line:
//! `KSELFTEST:OK`, or `KSELFTEST:FAIL ...` per failed check (make check
//! fails on any FAIL in the serial log).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::sync::spin::Mutex;

use crate::printkln;
use crate::task::kthread::{
    kthread_park, kthread_parkme, kthread_run, kthread_should_park, kthread_should_stop,
    kthread_stop, kthread_unpark,
};
use crate::task::percpu::{TICK_MS, cpu_has_scheduler, get_ticks, sleep_until_ns};
use crate::waitqueue::WaitQueue;
use crate::workqueue::{DelayedWork, SYSTEM_WQ, Work};

/// Selftest events land here
static EVENT_WQ: WaitQueue = WaitQueue::new();
static WORK_RAN: AtomicBool = AtomicBool::new(false);
static DELAYED_RAN_TICK: AtomicU64 = AtomicU64::new(0);
static CHILD_COUNT: AtomicU64 = AtomicU64::new(0);

/// Start the self-test thread
pub fn start() {
    let cpu = if cpu_has_scheduler(1) { 1 } else { 0 };
    if let Err(e) = kthread_run("kselftest", selftest_thread, 0, Some(cpu)) {
        printkln!("\nKSELFTEST:FAIL cannot start kthread: {:?}", e);
    }
}

fn sleep_ms(ms: u64) {
    let _ = sleep_until_ns(crate::time::monotonic_ns() + ms * 1_000_000, false);
}

fn selftest_thread(_arg: usize) {
    let mut ok = true;
    let mut check = |name: &str, pass: bool, detail: u64| {
        if !pass {
            printkln!("\nKSELFTEST:FAIL {} ({})", name, detail);
            ok = false;
        }
    };

    // 1. Scheduler tick rate: 200 ms of CLOCK_MONOTONIC is ~20 ticks
    let k0 = get_ticks();
    sleep_ms(200);
    let dk = get_ticks() - k0;
    let want = 200 / TICK_MS;
    check("tick_rate", dk >= want * 3 / 4 && dk <= want * 3 / 2, dk);

    // 2. queue_work runs on the system workqueue worker
    let work = Arc::new(Mutex::new(Work::new(|| {
        WORK_RAN.store(true, Ordering::Release);
        EVENT_WQ.wake_all();
    })));
    check("queue_work_queued", SYSTEM_WQ.queue_work(work), 0);
    let left = EVENT_WQ.wait_event_timeout(|| WORK_RAN.load(Ordering::Acquire), 100);
    check("queue_work_ran", left > 0, 0);

    // 3. Delayed work runs no earlier than its delay
    let t0 = get_ticks();
    let dwork = Arc::new(Mutex::new(DelayedWork::new(|| {
        DELAYED_RAN_TICK.store(get_ticks(), Ordering::Release);
        EVENT_WQ.wake_all();
    })));
    SYSTEM_WQ.queue_delayed_work(dwork, 5);
    let left = EVENT_WQ.wait_event_timeout(|| DELAYED_RAN_TICK.load(Ordering::Acquire) != 0, 200);
    let ran = DELAYED_RAN_TICK.load(Ordering::Acquire);
    check("delayed_work_ran", left > 0, 0);
    check("delayed_work_delay", ran >= t0 + 5, ran.saturating_sub(t0));

    // 4. kthread park/unpark/stop with the child on another CPU
    let other = if crate::task::percpu::current_cpu() == 0 && cpu_has_scheduler(1) {
        1
    } else {
        0
    };
    match kthread_run("kselftest-child", child_thread, 0, Some(other)) {
        Ok(child) => {
            let started =
                EVENT_WQ.wait_event_timeout(|| CHILD_COUNT.load(Ordering::Acquire) > 0, 100);
            check("kthread_started", started > 0, 0);
            kthread_park(&child);
            let parked_at = CHILD_COUNT.load(Ordering::Acquire);
            sleep_ms(50);
            check(
                "kthread_parked",
                CHILD_COUNT.load(Ordering::Acquire) == parked_at,
                0,
            );
            kthread_unpark(&child);
            let resumed = EVENT_WQ
                .wait_event_timeout(|| CHILD_COUNT.load(Ordering::Acquire) > parked_at, 100);
            check("kthread_unparked", resumed > 0, 0);
            kthread_stop(&child);
        }
        Err(e) => check("kthread_run", false, e.errno() as u64),
    }

    // 5. ICMP echo over a real lo in a private network namespace (the
    //    init namespace belongs to userspace): bring lo up (127.0.0.1/8
    //    appears, like Linux), add 192.0.2.1/24 on it, ping both. Request
    //    and reply travel xmit -> netif_rx backlog -> softnet -> icmp_rcv.
    use crate::net::icmp;
    use crate::net::inet::ifaddr::{InIfaddr, inet_insert_ifa};
    use crate::net::netlink::NlInfo;
    use crate::net::{Ipv4Addr, device::flags::IFF_UP, rtnl};
    let net = crate::net::NetNamespace::new();
    let extra = Ipv4Addr::new(192, 0, 2, 1);
    if let Some(lo) = net.loopback() {
        let r = rtnl::lock();
        let up =
            rtnl::dev_change_flags(&r, &net, &lo, lo.admin_flags() | IFF_UP, NlInfo::default());
        check("netns_lo_up", up.is_ok(), 0);
        let ifa = InIfaddr::new(extra, 24, lo.name());
        check(
            "netns_lo_addr",
            inet_insert_ifa(&r, &net, &lo, ifa, NlInfo::default()).is_ok(),
            0,
        );
    }
    let targets = [Ipv4Addr::new(127, 0, 0, 1), extra];
    for (i, &dst) in targets.iter().enumerate() {
        let before = icmp::ICMP_IN_ECHO_REPS.load(Ordering::Acquire);
        let sent = icmp::icmp_send_echo(&net, dst, 0x6b6b, i as u16, b"hk-selftest");
        check("icmp_lo_send", sent.is_ok(), i as u64);
        let left = icmp::ICMP_ECHO_REPLY_WQ.wait_event_timeout(
            || icmp::ICMP_IN_ECHO_REPS.load(Ordering::Acquire) > before,
            200,
        );
        check("icmp_lo_reply", left > 0, dst.to_u32() as u64);
    }

    // 6. mremap's move allocates first: ENOMEM loses no page
    if let Some(what) = crate::mm::mremap::selftest() {
        check(what, false, 0);
    }
    if let Some(what) = crate::mm::pagewalk::selftest() {
        check(what, false, 0);
    }

    // 7. Cross-CPU calls from every CPU at once: none lost, no deadlock
    if let Err((what, n)) = ipi_stress() {
        check(what, false, n);
    }

    // 8. A kernel mapping changed under another CPU's TLB: it reads the
    //    new page after flush_tlb_kernel_range (LOCKDEP builds)
    #[cfg(feature = "lockdep")]
    if let Err((what, n)) = tlb_canary() {
        check(what, false, n);
    }

    if ok {
        printkln!("\nKSELFTEST:OK");
    }
}

/// Calls each stress thread makes to every other CPU
const IPI_ROUNDS: u64 = 300;
/// Calls run on each CPU by the stress test
static IPI_RECV: [AtomicU64; crate::cpumask::NR_CPUS] =
    [const { AtomicU64::new(0) }; crate::cpumask::NR_CPUS];
/// Stress threads finished
static IPI_DONE: AtomicU64 = AtomicU64::new(0);

/// One stress call: count it on the CPU running it
fn ipi_count(_info: usize) {
    let cpu = crate::task::percpu::current_cpu() as usize;
    IPI_RECV[cpu].fetch_add(1, Ordering::Relaxed);
}

/// A stress thread (one per CPU, all at once): rounds of calls to every
/// other CPU, some without waiting, some with interrupts off (as from a
/// syscall: the wait polls this CPU's own queue), then one call
/// everywhere including here
fn ipi_stress_thread(_arg: usize) {
    use crate::arch::{local_irq_restore, local_irq_save};
    use crate::smp::{active_cpus, on_each_cpu, smp_call_function_many};
    let all = active_cpus();
    for r in 0..IPI_ROUNDS {
        let wait = r % 4 != 3 || r == IPI_ROUNDS - 1;
        if r % 3 == 0 {
            let irq = local_irq_save();
            smp_call_function_many(&all, ipi_count, 0, wait);
            local_irq_restore(irq);
        } else {
            smp_call_function_many(&all, ipi_count, 0, wait);
        }
    }
    on_each_cpu(ipi_count, 0);
    IPI_DONE.fetch_add(1, Ordering::Release);
}

/// Every active CPU calls every other one concurrently: each CPU must
/// run exactly the calls sent to it, and all senders finish
fn ipi_stress() -> Result<(), (&'static str, u64)> {
    let cpus = crate::smp::active_cpus();
    let n = cpus.iter().count() as u64;
    if n < 2 {
        return Ok(());
    }
    for c in &IPI_RECV {
        c.store(0, Ordering::Relaxed);
    }
    IPI_DONE.store(0, Ordering::Relaxed);
    for cpu in cpus.iter() {
        kthread_run("ipi-stress", ipi_stress_thread, 0, Some(cpu))
            .map_err(|e| ("ipi_stress_thread", e.errno() as u64))?;
    }
    // 10 s: a deadlock or a lost IPI leaves a thread waiting forever
    for _ in 0..1000 {
        if IPI_DONE.load(Ordering::Acquire) == n {
            break;
        }
        sleep_ms(10);
    }
    let done = IPI_DONE.load(Ordering::Acquire);
    if done != n {
        return Err(("ipi_stress_hang", done));
    }
    let want = (n - 1) * IPI_ROUNDS + n;
    for cpu in cpus.iter() {
        let got = IPI_RECV[cpu as usize].load(Ordering::Relaxed);
        if got != want {
            return Err(("ipi_stress_count", got));
        }
    }
    Ok(())
}

/// TLB canary: the page the reader reads, its progress, what it saw
#[cfg(feature = "lockdep")]
static CANARY_VA: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "lockdep")]
static CANARY_PHASE: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "lockdep")]
static CANARY_SEEN: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

#[cfg(feature = "lockdep")]
fn canary_read() -> u64 {
    // SAFETY: the canary's mapped page
    unsafe { core::ptr::read_volatile(CANARY_VA.load(Ordering::Acquire) as *const u64) }
}

/// Canary reader (another CPU): read the page often enough that its
/// TLB caches the translation, then again after the remap. Spins with
/// interrupts on, so the flush IPI reaches it.
#[cfg(feature = "lockdep")]
fn canary_reader(_arg: usize) {
    let mut v = 0;
    for _ in 0..1000 {
        v = canary_read();
    }
    CANARY_SEEN[0].store(v, Ordering::Relaxed);
    CANARY_PHASE.store(1, Ordering::Release);
    while CANARY_PHASE.load(Ordering::Acquire) != 2 {
        core::hint::spin_loop();
    }
    CANARY_SEEN[1].store(canary_read(), Ordering::Relaxed);
    CANARY_PHASE.store(3, Ordering::Release);
}

/// Wait (sleeping) for the canary reader to reach `phase`, up to 5 s
#[cfg(feature = "lockdep")]
fn canary_wait(phase: u64) -> bool {
    for _ in 0..500 {
        if CANARY_PHASE.load(Ordering::Acquire) == phase {
            return true;
        }
        sleep_ms(10);
    }
    false
}

/// A kernel page (ioremap window) read on another CPU, then pointed at
/// another frame (`ioremap_retarget`: clear, flush_tlb_kernel_range,
/// map): the reader must see the new frame. A missed cross-CPU flush
/// leaves it reading the old one through its TLB (x86 under KVM).
#[cfg(feature = "lockdep")]
fn tlb_canary() -> Result<(), (&'static str, u64)> {
    const OLD: u64 = 0x01d0_1d01_d01d_0001;
    const NEW: u64 = 0x0ee0_0ee0_0ee0_0002;
    let me = crate::task::percpu::current_cpu();
    let Some(other) = crate::smp::active_cpus().iter().find(|&c| c != me) else {
        return Ok(());
    };
    let fa = &crate::FRAME_ALLOCATOR;
    let (Some(f1), Some(f2)) = (fa.alloc(), fa.alloc()) else {
        return Err(("tlb_canary_alloc", 0));
    };
    // SAFETY: fresh frames, through the direct map
    unsafe {
        *(crate::arch::phys_to_virt(f1) as *mut u64) = OLD;
        *(crate::arch::phys_to_virt(f2) as *mut u64) = NEW;
    }
    let r = canary_run(f1, f2, other);
    fa.free(f1);
    fa.free(f2);
    match r? {
        (OLD, NEW) => Ok(()),
        (OLD, seen) => Err(("tlb_canary_stale", seen)),
        (seen, _) => Err(("tlb_canary_first", seen)),
    }
}

/// Map `f1`, have `cpu` read it, retarget to `f2`, have it read again:
/// what it saw
#[cfg(feature = "lockdep")]
fn canary_run(f1: u64, f2: u64, cpu: u32) -> Result<(u64, u64), (&'static str, u64)> {
    use crate::arch::{CurrentArch, IoremapOps};
    let va = CurrentArch::ioremap(f1, 4096).map_err(|_| ("tlb_canary_ioremap", 0))? as u64;
    CANARY_VA.store(va, Ordering::Release);
    CANARY_PHASE.store(0, Ordering::Release);
    let r = (|| {
        kthread_run("tlb-canary", canary_reader, 0, Some(cpu))
            .map_err(|e| ("tlb_canary_thread", e.errno() as u64))?;
        if !canary_wait(1) {
            return Err(("tlb_canary_hang", 1));
        }
        crate::arch::ioremap_retarget(va, f2).map_err(|_| ("tlb_canary_remap", 0))?;
        CANARY_PHASE.store(2, Ordering::Release);
        if !canary_wait(3) {
            return Err(("tlb_canary_hang", 3));
        }
        Ok((
            CANARY_SEEN[0].load(Ordering::Relaxed),
            CANARY_SEEN[1].load(Ordering::Relaxed),
        ))
    })();
    CurrentArch::iounmap(va as *mut u8, 4096);
    r
}

/// Counts loop iterations, parking and stopping on request
fn child_thread(_arg: usize) {
    while !kthread_should_stop() {
        if kthread_should_park() {
            kthread_parkme();
            continue;
        }
        CHILD_COUNT.store(CHILD_COUNT.load(Ordering::Relaxed) + 1, Ordering::Release);
        EVENT_WQ.wake_all();
        // Re-check every tick (stop/park requests also wake us directly)
        EVENT_WQ.wait_event_timeout(|| kthread_should_stop() || kthread_should_park(), 1);
    }
}
