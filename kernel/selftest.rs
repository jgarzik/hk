//! Boot-time kernel self-test of kernel threads, workqueues and ticks
//!
//! Runs in its own kernel thread (on CPU 1 when it exists, exercising
//! cross-CPU wakeups) in parallel with user space, and prints one line:
//! `KSELFTEST:OK`, or `KSELFTEST:FAIL ...` per failed check (make check
//! fails on any FAIL in the serial log).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use spin::Mutex;

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

    // 5. ICMP echo to 127.0.0.1 and to our own eth0 address: request and
    //    reply both travel through the real lo (xmit -> netif_rx backlog ->
    //    softnet thread of this CPU -> icmp_rcv), never synchronously
    use crate::net::icmp;
    let net = crate::net::init_net_ns();
    let mut targets = alloc::vec![crate::net::Ipv4Addr::new(127, 0, 0, 1)];
    if let Some(c) = net.get_config() {
        targets.push(c.ipv4_addr);
    }
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

    if ok {
        printkln!("\nKSELFTEST:OK");
    }
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
