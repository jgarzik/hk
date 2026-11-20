//! Neighbour sysctls (Linux net/core/neighbour.c neigh_sysctl_template,
//! neigh_sysctl_register)
//!
//! /proc/sys/net/ipv4/neigh/<dev>/ shows a device's ARP parameters
//! (Linux in_dev->arp_parms), and net/ipv4/neigh/default/ the table's
//! defaults with its GC knobs, in the initial namespace only (Linux
//! registers arp_tbl.parms in init_net). A write marks the value as the
//! set's own; a write to "default" reaches every device of the initial
//! namespace that never had that value written (neigh_proc_update,
//! neigh_copy_dflt_parms). Values are kept in ms and shown in the
//! units of Linux's handlers: seconds (proc_dointvec_jiffies), USER_HZ
//! ticks (proc_dointvec_userhz_jiffies) or ms.

use alloc::vec;
use alloc::vec::Vec;

use crate::net::NetNamespace;
use crate::net::arp::arp_tbl;
use crate::net::neigh::{NeighParms, var};
use crate::net::sysctl::{DevCtl, DevDir, Target};
use crate::sysctl::range;
use crate::util::error::KernelError;

const INT_MAX: i64 = i32::MAX as i64;
/// Linux NTBL_PARM_MS_MAX: a day
const PARM_MS_MAX: i64 = 24 * 60 * 60 * 1000;
/// Linux SKB_TRUESIZE(ETH_FRAME_LEN) on 64-bit: unres_qlen's packet
/// size (1514 + the aligned sk_buff and skb_shared_info)
const QLEN_TRUESIZE: i64 = 1514 + 256 + 320;
/// ms per USER_HZ tick
const MS_PER_TICK: i64 = 1000 / crate::time::USER_HZ as i64;
/// Linux HZ of the reference, for proc_dointvec_jiffies's bound
const HZ: i64 = 1000;

/// The parameters a directory stands for: a device's, or the table's
/// defaults
fn parms(t: &Target) -> &NeighParms {
    match t {
        Target::Dev(d) => &d.in_dev().arp_parms,
        Target::All | Target::Default => &arp_tbl().parms,
    }
}

/// A write of value `i` (Linux neigh_proc_update): marked as the set's
/// own; for the defaults, every device of the initial namespace still
/// inheriting it follows (neigh_copy_dflt_parms, under RCU)
fn update(t: &Target, i: usize) {
    let p = parms(t);
    p.mark(i);
    if !matches!(t, Target::Dev(_)) {
        let net = crate::net::init_net_ns();
        let g = crate::sync::rcu::read_lock();
        for dev in net.devices_rcu(&g) {
            let d = &dev.in_dev().arp_parms;
            if !d.is_set(i) {
                d.set(i, p.get(i));
            }
        }
    }
}

fn set(t: &Target, i: usize, v: i64) {
    parms(t).set(i, v);
    update(t, i);
}

/// Linux neigh_proc_dointvec_zero_intmax
fn int_store(t: &Target, i: usize, v: &[i64]) -> Result<(), KernelError> {
    range(v[0], 0, INT_MAX)?;
    set(t, i, v[0]);
    Ok(())
}

/// Linux neigh_proc_dointvec_jiffies: seconds, at most INT_MAX / HZ
fn secs_store(t: &Target, i: usize, v: &[i64]) -> Result<(), KernelError> {
    range(v[0], -INT_MAX / HZ, INT_MAX / HZ)?;
    set(t, i, v[0] * 1000);
    Ok(())
}

/// Linux neigh_proc_dointvec_userhz_jiffies: USER_HZ ticks
fn ticks_store(t: &Target, i: usize, v: &[i64]) -> Result<(), KernelError> {
    range(v[0], -INT_MAX, INT_MAX)?;
    set(t, i, v[0] * MS_PER_TICK);
    Ok(())
}

/// Linux neigh_proc_dointvec_ms_jiffies: ms that fit an int of
/// jiffies (a negative value does not)
fn ms_store(t: &Target, i: usize, v: &[i64]) -> Result<(), KernelError> {
    range(v[0], 0, INT_MAX)?;
    set(t, i, v[0]);
    Ok(())
}

/// Linux neigh_proc_base_reachable_time: a new base draws a new
/// reachable time at once (neigh_set_reach_time)
fn base_store(t: &Target, v: &[i64], ms: bool) -> Result<(), KernelError> {
    if ms {
        ms_store(t, var::BASE_REACHABLE_TIME, v)?;
    } else {
        secs_store(t, var::BASE_REACHABLE_TIME, v)?;
    }
    parms(t).set_reach_time();
    Ok(())
}

/// Linux neigh_proc_dointvec_unres_qlen: packets of
/// SKB_TRUESIZE(ETH_FRAME_LEN) bytes in unres_qlen_bytes
fn qlen_store(t: &Target, v: &[i64]) -> Result<(), KernelError> {
    range(v[0], 0, INT_MAX / QLEN_TRUESIZE)?;
    set(t, var::QUEUE_LEN_BYTES, v[0] * QLEN_TRUESIZE);
    Ok(())
}

fn get(t: &Target, i: usize) -> i64 {
    parms(t).get(i)
}

/// The table's GC knob `i` (0 gc_interval, 1..=3 gc_thresh1..3)
fn gc(i: usize) -> &'static core::sync::atomic::AtomicI64 {
    let tbl = arp_tbl();
    match i {
        0 => &tbl.gc_interval,
        _ => &tbl.gc_thresh[i - 1],
    }
}

fn gc_show(i: usize) -> Vec<i64> {
    let v = gc(i).load(core::sync::atomic::Ordering::Relaxed);
    vec![if i == 0 { v / 1000 } else { v }]
}

/// gc_interval: proc_dointvec_jiffies; gc_thresh*: 0..INT_MAX
fn gc_store(i: usize, v: &[i64]) -> Result<(), KernelError> {
    let x = if i == 0 {
        range(v[0], -INT_MAX / HZ, INT_MAX / HZ)?;
        v[0] * 1000
    } else {
        range(v[0], 0, INT_MAX)?;
        v[0]
    };
    gc(i).store(x, core::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// "default" in the initial namespace only
fn fixed(net: &NetNamespace) -> &'static [(&'static str, bool)] {
    if crate::net::sysctl::is_init(net) {
        &[("default", false)]
    } else {
        &[]
    }
}

macro_rules! ctl {
    ($name:literal, $show:expr, $store:expr) => {
        DevCtl {
            name: $name,
            mode: 0o644,
            default_only: false,
            show: $show,
            store: $store,
        }
    };
}

macro_rules! int {
    ($name:literal, $i:expr) => {
        ctl!($name, |_, t| vec![get(t, $i)], |_, t, v| int_store(
            t, $i, v
        ))
    };
}

macro_rules! secs {
    ($name:literal, $i:expr) => {
        ctl!($name, |_, t| vec![get(t, $i) / 1000], |_, t, v| secs_store(
            t, $i, v
        ))
    };
}

macro_rules! ticks {
    ($name:literal, $i:expr) => {
        ctl!($name, |_, t| vec![get(t, $i) / MS_PER_TICK], |_, t, v| {
            ticks_store(t, $i, v)
        })
    };
}

macro_rules! gc_ctl {
    ($name:literal, $i:expr) => {
        DevCtl {
            name: $name,
            mode: 0o644,
            default_only: true,
            show: |_, _| gc_show($i),
            store: |_, _, v| gc_store($i, v),
        }
    };
}

/// net/ipv4/neigh/{default,<dev>} (Linux neigh_sysctl_template)
pub static NEIGH_DIR: DevDir = DevDir {
    path: "net/ipv4/neigh",
    fixed,
    ctls: &[
        int!("mcast_solicit", var::MCAST_PROBES),
        int!("ucast_solicit", var::UCAST_PROBES),
        int!("app_solicit", var::APP_PROBES),
        int!("mcast_resolicit", var::MCAST_REPROBES),
        ticks!("retrans_time", var::RETRANS_TIME),
        ctl!(
            "base_reachable_time",
            |_, t| vec![get(t, var::BASE_REACHABLE_TIME) / 1000],
            |_, t, v| base_store(t, v, false)
        ),
        secs!("delay_first_probe_time", var::DELAY_PROBE_TIME),
        ctl!(
            "interval_probe_time_ms",
            |_, t| vec![get(t, var::INTERVAL_PROBE_TIME_MS)],
            |_, t, v| {
                range(v[0], 1, PARM_MS_MAX)?;
                set(t, var::INTERVAL_PROBE_TIME_MS, v[0]);
                Ok(())
            }
        ),
        secs!("gc_stale_time", var::GC_STALETIME),
        int!("unres_qlen_bytes", var::QUEUE_LEN_BYTES),
        int!("proxy_qlen", var::PROXY_QLEN),
        ticks!("anycast_delay", var::ANYCAST_DELAY),
        ticks!("proxy_delay", var::PROXY_DELAY),
        ticks!("locktime", var::LOCKTIME),
        ctl!(
            "unres_qlen",
            |_, t| vec![get(t, var::QUEUE_LEN_BYTES) / QLEN_TRUESIZE],
            |_, t, v| qlen_store(t, v)
        ),
        ctl!(
            "retrans_time_ms",
            |_, t| vec![get(t, var::RETRANS_TIME)],
            |_, t, v| ms_store(t, var::RETRANS_TIME, v)
        ),
        ctl!(
            "base_reachable_time_ms",
            |_, t| vec![get(t, var::BASE_REACHABLE_TIME)],
            |_, t, v| base_store(t, v, true)
        ),
        gc_ctl!("gc_interval", 0),
        gc_ctl!("gc_thresh1", 1),
        gc_ctl!("gc_thresh2", 2),
        gc_ctl!("gc_thresh3", 3),
    ],
};
