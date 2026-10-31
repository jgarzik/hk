//! EEVDF, the fair class's policy (Linux kernel/sched/fair.c, reduced)
//!
//! Each fair task advances its virtual runtime by the time it runs
//! scaled by NICE_0_LOAD / its weight (nice sets the weight,
//! `sched_prio_to_weight`; SCHED_IDLE weighs 3), and gets a virtual
//! deadline one slice ahead. The next task is the eligible one (its
//! vruntime not past the run queue's weighted average, `avg_vruntime`)
//! with the earliest deadline (`pick_eevdf`). A task that sleeps keeps
//! its lag (how far it was behind the average) and is placed by it when
//! it wakes (`place`), so sleeping neither gains nor loses its share.
//!
//! Deviations: the fair tasks are a list scanned per pick (Linux: an
//! rbtree augmented with min_vruntime, O(log n)); the average is
//! computed per use, not kept incrementally; slices end at tick
//! granularity (no hrtick); a weight change keeps the vruntime (no
//! reweight_entity).
//!
//! Locking: the fields are the task's `SchedEntity` atomics, changed
//! under the rq lock of its CPU.

use core::sync::atomic::Ordering;

use super::sched::SchedEntity;

/// The weight of nice 0 (Linux NICE_0_LOAD, without the fixed-point
/// shift)
pub const NICE_0_LOAD: u64 = 1024;

/// SCHED_IDLE's weight (Linux WEIGHT_IDLEPRIO)
const WEIGHT_IDLEPRIO: u64 = 3;

/// Nice -20..19 to weight; each step is ~10% of CPU (Linux
/// sched_prio_to_weight)
const PRIO_TO_WEIGHT: [u32; 40] = [
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916, 9548, 7620, 6100, 4904,
    3906, 3121, 2501, 1991, 1586, 1277, 1024, 820, 655, 526, 423, 335, 272, 215, 172, 137, 110, 87,
    70, 56, 45, 36, 29, 23, 18, 15,
];

/// A fair task's weight
pub fn weight(se: &SchedEntity) -> u64 {
    if se.policy() == crate::task::SCHED_IDLE {
        return WEIGHT_IDLEPRIO;
    }
    PRIO_TO_WEIGHT[(se.nice() + 20).clamp(0, 39) as usize] as u64
}

/// The base slice in ns (Linux sysctl_sched_base_slice, 0.75 ms scaled
/// by 1 + log2 of the CPUs up to 8: sched_update_scaling)
pub fn base_slice() -> u64 {
    let n = crate::cpu::nr_cpu_ids().clamp(1, 8);
    750_000 * (1 + n.ilog2() as u64)
}

/// `delta` ns of real time in `se`'s virtual time (Linux
/// calc_delta_fair)
fn calc_delta_fair(delta: u64, se: &SchedEntity) -> u64 {
    let w = weight(se);
    if w == NICE_0_LOAD {
        return delta;
    }
    (delta as u128 * NICE_0_LOAD as u128 / w as u128) as u64
}

/// Charge the running `se` for the time since it last was (Linux
/// update_curr, update_deadline): true once it used up its slice, which
/// gives it a new deadline
pub fn update_curr(se: &SchedEntity, now: u64) -> bool {
    let start = se.exec_start.swap(now, Ordering::Relaxed);
    if start == 0 || now <= start {
        return false;
    }
    let v = se.vruntime.load(Ordering::Relaxed) + calc_delta_fair(now - start, se);
    se.vruntime.store(v, Ordering::Relaxed);
    if v < se.deadline.load(Ordering::Relaxed) {
        return false;
    }
    se.deadline
        .store(v + calc_delta_fair(base_slice(), se), Ordering::Relaxed);
    true
}

/// The weighted average vruntime of `ents` (Linux avg_vruntime), None
/// for none
pub fn avg_vruntime<'a>(ents: impl Iterator<Item = &'a SchedEntity> + Clone) -> Option<u64> {
    let base = ents
        .clone()
        .map(|e| e.vruntime.load(Ordering::Relaxed))
        .min()?;
    let (mut sum, mut w) = (0i128, 0i128);
    for e in ents {
        let ew = weight(e) as i128;
        sum += ew * (e.vruntime.load(Ordering::Relaxed) - base) as i128;
        w += ew;
    }
    Some(base + (sum / w) as u64)
}

/// The entity to run next of `ents`: the earliest deadline among those
/// not ahead of the average (Linux pick_eevdf; the one with the least
/// vruntime is always eligible)
pub fn pick<'a, T: Copy>(ents: impl Iterator<Item = (T, &'a SchedEntity)> + Clone) -> Option<T> {
    let avg = avg_vruntime(ents.clone().map(|(_, e)| e))?;
    ents.filter(|(_, e)| e.vruntime.load(Ordering::Relaxed) <= avg)
        .min_by_key(|(_, e)| e.deadline.load(Ordering::Relaxed))
        .map(|(t, _)| t)
}

/// Remember how far `se`, leaving the run queue, is behind the average
/// `avg` (Linux update_entity_lag: clamped to about two slices)
pub fn save_lag(se: &SchedEntity, avg: u64) {
    let limit = calc_delta_fair(2 * base_slice().max(super::percpu::TICK_NS), se) as i64;
    let lag = (avg as i128 - se.vruntime.load(Ordering::Relaxed) as i128)
        .clamp(-limit as i128, limit as i128) as i64;
    se.vlag.store(lag, Ordering::Relaxed);
}

/// Place `se`, joining a run queue whose entities average `avg` with
/// total weight `load`, by its saved lag (Linux place_entity: the lag
/// scaled so the average stays put); a new task (`initial`) gets half a
/// slice to its first deadline (PLACE_DEADLINE_INITIAL)
pub fn place(se: &SchedEntity, avg: u64, load: u64, initial: bool) {
    let w = weight(se) as i128;
    let mut lag = se.vlag.swap(0, Ordering::Relaxed) as i128;
    if load > 0 {
        lag = lag * (load as i128 + w) / load as i128;
    }
    let v = (avg as i128 - lag).max(0) as u64;
    se.vruntime.store(v, Ordering::Relaxed);
    let mut vslice = calc_delta_fair(base_slice(), se);
    if initial {
        vslice /= 2;
    }
    se.deadline.store(v + vslice, Ordering::Relaxed);
}

/// A sched_yield: its deadline moves a slice on (Linux
/// yield_task_fair)
pub fn yield_task(se: &SchedEntity) {
    se.deadline
        .fetch_add(calc_delta_fair(base_slice(), se), Ordering::Relaxed);
}
