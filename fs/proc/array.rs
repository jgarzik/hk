//! /proc/<pid>/{status,stat,cmdline,environ} (Linux 6.8 fs/proc/array.c
//! proc_pid_status / do_task_stat, fs/proc/base.c proc_pid_cmdline_read
//! / environ_read)
//!
//! Pids are numbered in the pid namespace of the procfs read (Linux
//! proc_pid_ns): translated under TASKLIST from the `Pid`s of the task,
//! its leader, parent, tracer, group and session, which TASKLIST keeps
//! listed meanwhile.
//!
//! Locking: the task's fields are copied under TASKLIST, which is
//! dropped before anything else is taken; then, one at a time and never
//! nested, the address space's mmap_lock (VM sizes, page counts and the
//! remote reads of cmdline/environ), the sighand action lock, the shared
//! pending set, `FsStruct.inner` (umask) and the descriptor table lock.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;

use crate::fs::KernelError;
use crate::mm::{Mm, MmLayout, MmStruct, PROT_EXEC, PROT_WRITE, VM_GROWSDOWN, VM_SHARED};
use crate::ns::PidNamespace;
use crate::ns::pid::MAX_PID_NS_LEVEL;
use crate::task::percpu::{TASKLIST, TaskRef};
use crate::task::{Cred, Pid, Task, TaskKind, TaskState, Tid};

/// Linux PF_KTHREAD / PF_EXITING (stat field 9)
const PF_EXITING: u64 = 0x0000_0004;
const PF_KTHREAD: u64 = 0x0020_0000;
/// The most cmdline/environ return (Linux reads them a page at a time
/// but exec caps the strings at 128 KiB)
const ARGS_MAX: u64 = 128 * 1024;

/// Levels a task can have numbers at
const LEVELS: usize = MAX_PID_NS_LEVEL as usize + 1;

/// What /proc reads of a task, copied under TASKLIST; the pids as the
/// reading procfs's namespace numbers them (0 if not visible there)
struct Snap {
    pid: Pid,
    tgid: Pid,
    ppid: Pid,
    pgid: Pid,
    sid: Pid,
    /// (tgid, pid, pgid, sid) in each namespace from the procfs's down
    /// to the task's own (Linux NStgid, NSpid, NSpgid, NSsid)
    ns_ids: [[u32; 4]; LEVELS],
    levels: usize,
    comm: [u8; 16],
    state: TaskState,
    cred: Cred,
    kthread: bool,
    exiting: bool,
    utime: u64,
    stime: u64,
    /// Reaped children's (Linux signal->cutime/cstime)
    cutime: u64,
    cstime: u64,
    start: u64,
    nvcsw: u64,
    nivcsw: u64,
    min_flt: u64,
    maj_flt: u64,
    nice: i32,
    policy: i32,
    rt_priority: i32,
    cpus: crate::util::cpumask::CpuSet,
    cpu: u32,
    exit_signal: i32,
    exit_code: i32,
    threads: u64,
    tracer: Pid,
    no_new_privs: bool,
    seccomp: u8,
    blocked: u64,
    pending: u64,
    shared: Option<crate::signal::SharedPending>,
    sighand: Option<Arc<crate::signal::SigHand>>,
    signal: Option<Arc<crate::signal::SignalStruct>>,
    fs: Option<Arc<crate::fs::FsStruct>>,
    files: Option<Arc<crate::task::fdtable::Files>>,
}

/// Copy task `pid` out of TASKLIST, its pids numbered in `ns` (Linux
/// task_state, do_task_stat with proc_pid_ns)
fn snap(task: &Task, ns: &PidNamespace) -> Option<Snap> {
    let table = TASKLIST.read();
    // Still listed: then its tid names it for this read hold
    let t = table.view(task)?;
    let pid = task.tid();
    let threads = table.threads(pid).count() as u64;
    let nr = |p: Option<&Arc<crate::task::pid::Pid>>, n: &PidNamespace| p.map_or(0, |p| p.nr_ns(n));
    // A listed task's process (by its root number) in `ns`
    let task_nr = |root: Tid| {
        u64::from(nr(
            table.get(root).and_then(|x| x.fields().thread_pid()),
            ns,
        ))
    };
    let me = t.thread_pid();
    // A task the namespace cannot see is not shown there (Linux reaches
    // it only through a lookup in that namespace); then its levels from
    // `ns` down are the namespaces of its own chain
    me?.nr_in(ns)?;
    let leader = table.get(t.task.pid).and_then(|l| l.fields().thread_pid());
    let (pg, se) = (t.pgrp(), t.session());
    let tracer = t.tracer().map_or(0, |x| task_nr(x.tid()));
    let mut ns_ids = [[0u32; 4]; LEVELS];
    let mut levels = 0;
    if let Some(p) = me {
        for u in p.numbers().iter().skip(ns.level as usize) {
            ns_ids[levels] = [nr(leader, &u.ns), u.nr, nr(pg, &u.ns), nr(se, &u.ns)];
            levels += 1;
        }
    }
    // comm and the resources together, under task_lock
    let (comm, fs, files) = {
        let a = t.task.task_lock();
        (a.comm(), a.fs().cloned(), a.files().cloned())
    };
    let (blocked, pending, shared) = {
        let s = t.task.sig.lock();
        (s.blocked.0, s.pending.signal.0, s.shared_pending.clone())
    };
    // The whole thread group's CPU time (Linux do_task_stat with whole)
    let (utime, stime) = crate::task::percpu::group_times(&table, pid);
    Some(Snap {
        pid: u64::from(nr(me, ns)),
        tgid: u64::from(nr(leader, ns)),
        ppid: task_nr(t.task.ppid()),
        pgid: u64::from(nr(pg, ns)),
        sid: u64::from(nr(se, ns)),
        ns_ids,
        levels,
        comm,
        state: match t.state() {
            // The run state as of its last switch (Linux task_state)
            TaskState::Ready | TaskState::Running | TaskState::Sleeping => {
                if t.task.se.state() != crate::task::percpu::SleepState::Running as u8 {
                    TaskState::Sleeping
                } else {
                    TaskState::Running
                }
            }
            s => s,
        },
        cred: t.cred(),
        kthread: matches!(t.task.kind, TaskKind::KernelThread),
        exiting: t.task.has_flag(crate::task::pf::EXITING),
        utime,
        stime,
        cutime: t.signal().map_or(0, |s| s.child_times().0),
        cstime: t.signal().map_or(0, |s| s.child_times().1),
        start: t.task.start_time(),
        nvcsw: t.task.nvcsw.load(core::sync::atomic::Ordering::Relaxed),
        nivcsw: t.task.nivcsw.load(core::sync::atomic::Ordering::Relaxed),
        min_flt: t.task.min_flt.load(core::sync::atomic::Ordering::Relaxed),
        maj_flt: t.task.maj_flt.load(core::sync::atomic::Ordering::Relaxed),
        nice: t.task.se.nice(),
        policy: t.task.se.policy(),
        rt_priority: i32::from(t.task.se.rt_priority()),
        cpus: t.task.cpus_mask.snapshot(),
        cpu: t.task.cpu.load(core::sync::atomic::Ordering::Relaxed),
        exit_signal: t.exit_signal().raw(),
        exit_code: t.exit_code(),
        threads,
        tracer,
        no_new_privs: t.no_new_privs(),
        seccomp: t.task.seccomp_mode(),
        blocked,
        pending,
        shared: Some(shared),
        sighand: t.sighand().cloned(),
        signal: t.signal().cloned(),
        fs,
        files,
    })
}

/// Linux task_state_array letter and name
fn state(s: &Snap) -> (char, &'static str) {
    match s.state {
        TaskState::Ready | TaskState::Running => ('R', "running"),
        TaskState::Sleeping => ('S', "sleeping"),
        TaskState::Traced(_) => ('t', "tracing stop"),
        TaskState::Zombie(_) => ('Z', "zombie"),
    }
}

/// comm's raw bytes (Linux proc_task_name: not re-encoded), with '\n'
/// and '\\' escaped for status (seq_escape_str ESCAPE_SPACE |
/// ESCAPE_SPECIAL, "\n\\")
fn comm(s: &Snap, escape: bool) -> Vec<u8> {
    let n = s.comm.iter().position(|&b| b == 0).unwrap_or(16);
    let mut out = Vec::new();
    for &b in &s.comm[..n] {
        match b {
            b'\n' if escape => out.extend_from_slice(b"\\n"),
            b'\\' if escape => out.extend_from_slice(b"\\\\"),
            _ => out.push(b),
        }
    }
    out
}

/// A byte buffer that formats like a String but also takes raw bytes
struct Out(Vec<u8>);

impl core::fmt::Write for Out {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// (ignored, caught) signals (Linux collect_sigign_sigcatch)
fn ign_cgt(s: &Snap) -> (u64, u64) {
    s.sighand.as_ref().map_or((0, 0), |h| h.ign_cgt())
}

/// Pending signals shared by the thread group
fn shd_pnd(s: &Snap) -> u64 {
    s.shared.as_ref().map_or(0, |p| p.lock().signal.0)
}

/// The fd table's size (Linux max_fds: 64, then doubling in 128s)
fn fd_size(s: &Snap) -> u64 {
    let Some(f) = &s.files else {
        return 0;
    };
    let need = f.lock().fds().last().map_or(0, |&fd| fd as u64 + 1);
    if need <= 64 {
        64
    } else {
        128 * need.div_ceil(128).next_power_of_two()
    }
}

/// RLIMIT_RSS soft limit
fn rss_lim(s: &Snap) -> u64 {
    s.signal
        .as_ref()
        .and_then(|sig| sig.get_rlimit(crate::task::rlimit::RLIMIT_RSS))
        .map_or(crate::task::rlimit::RLIM_INFINITY, |r| r.rlim_cur)
}

/// Memory figures of an address space, in pages (Linux task_mem)
#[derive(Default)]
struct VmStat {
    total: u64,
    locked: u64,
    rss: u64,
    swap: u64,
    data: u64,
    stack: u64,
    text: u64,
    lib: u64,
    start_brk: u64,
    lay: MmLayout,
}

/// Walk the VMAs, mmap_lock held: sizes by kind (Linux data_vm =
/// private writable, stack_vm = grows-down, exec_vm split into the
/// image's text, start_code..end_code, and the rest), and the pages
/// mapped and swapped
fn vm_stat(mm: &Mm, m: &MmStruct) -> VmStat {
    const PAGE: u64 = 4096;
    let mut v = VmStat {
        locked: m.locked_vm(),
        start_brk: m.get_start_brk(),
        lay: m.args(),
        ..VmStat::default()
    };
    let mut exec = 0;
    for vma in m.iter() {
        let pages = vma.size() / PAGE;
        let t = crate::mm::pgtable::PgTables::new(mm, m);
        let (rss, swap) = crate::mm::memory::count_ptes(t, vma.start, vma.end);
        v.total += pages;
        v.rss += rss;
        v.swap += swap;
        if vma.flags & VM_GROWSDOWN != 0 {
            v.stack += pages;
        } else if vma.prot & PROT_WRITE != 0 && vma.flags & VM_SHARED == 0 {
            v.data += pages;
        }
        if vma.prot & PROT_EXEC != 0 {
            exec += pages;
        }
    }
    let code = v.lay.end_code.next_multiple_of(PAGE) - (v.lay.start_code & !(PAGE - 1));
    v.text = (code / PAGE).min(exec);
    v.lib = exec - v.text;
    v
}

/// The figures of task `tid`'s address space, if it has a live one
fn task_vm(t: &Task) -> Option<VmStat> {
    let mm = crate::mm::mmget_not_zero(&super::task_mm(t)?)?;
    let m = mm.mmap_read_killable().ok()?;
    Some(vm_stat(&mm, &m))
}

/// /proc/<pid>/status (Linux proc_pid_status), pids numbered in `ns`
pub fn gen_status(t: &TaskRef, ns: &PidNamespace) -> Vec<u8> {
    let Some(s) = snap(t, ns) else {
        return Vec::new();
    };
    let mut o = Out(Vec::new());
    let c = &s.cred;
    let (letter, name) = state(&s);
    o.0.extend_from_slice(b"Name:\t");
    o.0.extend_from_slice(&comm(&s, true));
    o.0.push(b'\n');
    if let Some(fs) = &s.fs {
        let _ = writeln!(o, "Umask:\t{:04o}", fs.get_umask());
    }
    let _ = writeln!(o, "State:\t{letter} ({name})");
    let _ = writeln!(o, "Tgid:\t{}\nNgid:\t0\nPid:\t{}", s.tgid, s.pid);
    let _ = writeln!(o, "PPid:\t{}\nTracerPid:\t{}", s.ppid, s.tracer);
    let _ = writeln!(o, "Uid:\t{}\t{}\t{}\t{}", c.uid, c.euid, c.suid, c.fsuid);
    let _ = writeln!(o, "Gid:\t{}\t{}\t{}\t{}", c.gid, c.egid, c.sgid, c.fsgid);
    let _ = write!(o, "FDSize:\t{}\nGroups:\t", fd_size(&s));
    // Linux: the groups space-separated, then a trailing space
    for (i, g) in c.groups.as_slice().iter().enumerate() {
        let _ = write!(o, "{}{g}", if i > 0 { " " } else { "" });
    }
    let _ = writeln!(o, " ");
    for (i, key) in ["NStgid:", "NSpid:", "NSpgid:", "NSsid:"]
        .iter()
        .enumerate()
    {
        let _ = write!(o, "{key}");
        for ids in &s.ns_ids[..s.levels] {
            let _ = write!(o, "\t{}", ids[i]);
        }
        let _ = writeln!(o);
    }
    let _ = writeln!(o, "Kthread:\t{}", u8::from(s.kthread));
    if let Some(v) = task_vm(t) {
        status_mem(&mut o, &v);
    }
    status_sig(&mut o, &s);
    let caps = [
        ("CapInh", c.cap_inheritable.0),
        ("CapPrm", c.cap_permitted.0),
        ("CapEff", c.cap_effective.0),
        ("CapBnd", c.cap_bset.0),
        ("CapAmb", c.cap_ambient.0),
    ];
    for (k, v) in caps {
        let _ = writeln!(o, "{k}:\t{v:016x}");
    }
    let _ = writeln!(o, "NoNewPrivs:\t{}", u8::from(s.no_new_privs));
    let _ = writeln!(o, "Seccomp:\t{}\nSeccomp_filters:\t0", s.seccomp);
    let _ = writeln!(o, "Speculation_Store_Bypass:\tunknown");
    let _ = writeln!(o, "SpeculationIndirectBranch:\tunknown");
    let n = crate::cpu::nr_cpu_ids();
    let cpus = s.cpus.and(&crate::util::cpumask::CpuSet::first(n));
    let _ = writeln!(o, "Cpus_allowed:\t{}", cpus.fmt_hex(n));
    let _ = writeln!(o, "Cpus_allowed_list:\t{}", cpus.fmt_list());
    let _ = writeln!(o, "Mems_allowed:\t1\nMems_allowed_list:\t0");
    let _ = writeln!(o, "voluntary_ctxt_switches:\t{}", s.nvcsw);
    let _ = writeln!(o, "nonvoluntary_ctxt_switches:\t{}", s.nivcsw);
    o.0
}

/// The Vm* lines (Linux task_mem; hk keeps no high-water marks, so
/// VmPeak/VmHWM are the current sizes)
fn status_mem(o: &mut Out, v: &VmStat) {
    let kb = |pages: u64| pages * 4;
    let lines = [
        ("VmPeak", kb(v.total)),
        ("VmSize", kb(v.total)),
        ("VmLck", kb(v.locked)),
        ("VmPin", 0),
        ("VmHWM", kb(v.rss)),
        ("VmRSS", kb(v.rss)),
        ("RssAnon", kb(v.rss)),
        ("RssFile", 0),
        ("RssShmem", 0),
        ("VmData", kb(v.data)),
        ("VmStk", kb(v.stack)),
        ("VmExe", kb(v.text)),
        ("VmLib", kb(v.lib)),
        ("VmPTE", 0),
        ("VmSwap", kb(v.swap)),
    ];
    for (k, val) in lines {
        let _ = writeln!(o, "{k}:\t{val:>8} kB");
    }
    let _ = writeln!(o, "HugetlbPages:\t{:>8} kB", 0);
    let _ = writeln!(o, "CoreDumping:\t0\nTHP_enabled:\t1");
}

/// Threads, SigQ and the signal sets (Linux task_sig)
fn status_sig(o: &mut Out, s: &Snap) {
    let qlim = s
        .signal
        .as_ref()
        .and_then(|sig| sig.get_rlimit(crate::task::rlimit::RLIMIT_SIGPENDING))
        .map_or(0, |r| r.rlim_cur);
    // Signals queued for the task's user (Linux task_sig: its ucounts)
    let queued = crate::task::ucount(s.cred.uid, crate::task::Ucount::Sigpending);
    let (ign, cgt) = ign_cgt(s);
    let _ = writeln!(o, "Threads:\t{}\nSigQ:\t{}/{}", s.threads, queued, qlim);
    let sets = [
        ("SigPnd", s.pending),
        ("ShdPnd", shd_pnd(s)),
        ("SigBlk", s.blocked),
        ("SigIgn", ign),
        ("SigCgt", cgt),
    ];
    for (k, v) in sets {
        let _ = writeln!(o, "{k}:\t{v:016x}");
    }
}

/// /proc/<pid>/stat (Linux do_task_stat, whole thread group): all 52
/// fields; the address-space ones and exit_code only with ptrace-read
/// access, as in Linux
pub fn gen_stat(t: &TaskRef, ns: &PidNamespace) -> Vec<u8> {
    let Some(s) = snap(t, ns) else {
        return Vec::new();
    };
    // The access decision and the mm it covers, as one (Linux holds
    // exec_update_lock across do_task_stat)
    let guard = crate::signal::ExecUpdateRead::lock(t);
    let permitted = crate::task::ptrace::may_access_task(t, true);
    let v = task_vm(t);
    drop(guard);
    fmt_stat(&s, v.as_ref(), permitted, ign_cgt(&s), rss_lim(&s))
}

/// The /proc/<pid>/stat line from what `gen_stat` gathered: 52 fields
/// in Linux do_task_stat's order; without ptrace-read access the code,
/// stack and argument addresses read as 0 (start/end_code 1)
fn fmt_stat(
    s: &Snap,
    v: Option<&VmStat>,
    permitted: bool,
    (ign, cgt): (u64, u64),
    rlim: u64,
) -> Vec<u8> {
    let ticks = crate::time::ns_to_clock_t;
    let rt = s.policy == crate::task::SCHED_FIFO || s.policy == crate::task::SCHED_RR;
    let prio = if rt { -1 - s.rt_priority } else { 20 + s.nice };
    let flags = if s.kthread { PF_KTHREAD } else { 0 } | if s.exiting { PF_EXITING } else { 0 };
    let running = matches!(s.state, TaskState::Running | TaskState::Ready);
    let wchan = u8::from(permitted && s.threads < 2 && !running);
    let mut o = Out(Vec::new());
    let _ = write!(o, "{} (", s.pid);
    o.0.extend_from_slice(&comm(s, false));
    let _ = write!(o, ") {} ", state(s).0);
    let _ = write!(o, "{} {} {} 0 -1 {} ", s.ppid, s.pgid, s.sid, flags);
    let _ = write!(o, "{} 0 {} 0 ", s.min_flt, s.maj_flt);
    let _ = write!(
        o,
        "{} {} {} {} ",
        ticks(s.utime),
        ticks(s.stime),
        ticks(s.cutime),
        ticks(s.cstime)
    );
    let _ = write!(o, "{} {} {} 0 {} ", prio, s.nice, s.threads, ticks(s.start));
    let (vsize, rss) = v.map_or((0, 0), |v| (v.total * 4096, v.rss));
    let _ = write!(o, "{vsize} {rss} {rlim} ");
    let code = |x: u64| if permitted { x } else { 1 };
    let (sc, ec, ss) = match v {
        Some(v) => (
            code(v.lay.start_code),
            code(v.lay.end_code),
            if permitted { v.lay.start_stack } else { 0 },
        ),
        None => (0, 0, 0),
    };
    let _ = write!(o, "{sc} {ec} {ss} 0 0 ");
    let low = |x: u64| x & 0x7fff_ffff;
    let _ = write!(
        o,
        "{} {} {} {} ",
        low(s.pending),
        low(s.blocked),
        low(ign),
        low(cgt)
    );
    let _ = write!(o, "{wchan} 0 0 {} {} ", s.exit_signal, s.cpu);
    let _ = write!(o, "{} {} 0 0 0", s.rt_priority, s.policy);
    match v {
        Some(v) if permitted => {
            let a = &v.lay;
            let _ = write!(
                o,
                " {} {} {} {} {} {} {}",
                a.start_data,
                a.end_data,
                v.start_brk,
                a.arg_start,
                a.arg_end,
                a.env_start,
                a.env_end
            );
        }
        _ => o.0.extend_from_slice(b" 0 0 0 0 0 0 0"),
    }
    let _ = writeln!(o, " {}", if permitted { s.exit_code } else { 0 });
    o.0
}

/// Read [start, end) of `mm` (Linux access_remote_vm, FOLL_FORCE), the
/// mmap_lock not held; what could be read, at most ARGS_MAX bytes
fn read_remote(mm: &Mm, start: u64, end: u64) -> Vec<u8> {
    let len = end.saturating_sub(start).min(ARGS_MAX) as usize;
    let Ok(mut buf) = crate::util::kmem::try_vec(len, 0u8) else {
        return Vec::new();
    };
    let n = crate::mm::remote::access_remote_vm_read(mm, start, &mut buf, true).unwrap_or(0);
    buf.truncate(n);
    buf
}

/// /proc/<pid>/cmdline (Linux get_mm_cmdline): the argument strings;
/// if the program overwrote the final NUL of its arguments
/// (setproctitle), the area through the environment up to the first NUL
pub fn gen_cmdline(t: &TaskRef) -> Vec<u8> {
    let Some(mm) = super::task_mm(t).and_then(|m| crate::mm::mmget_not_zero(&m)) else {
        return Vec::new();
    };
    let a = match mm.mmap_read_killable() {
        Ok(m) => m.args(),
        Err(_) => return Vec::new(),
    };
    if a.arg_start >= a.arg_end {
        return Vec::new();
    }
    let args = read_remote(&mm, a.arg_start, a.arg_end);
    if args.last().is_none_or(|&c| c == 0) {
        return args;
    }
    // setproctitle: past the arguments only if the environment follows
    let end = if a.env_start == a.arg_end && a.env_end >= a.env_start {
        a.env_end
    } else {
        a.arg_end
    };
    let mut all = read_remote(&mm, a.arg_start, end);
    if let Some(nul) = all.iter().position(|&c| c == 0) {
        all.truncate(nul + 1);
    }
    all
}

/// /proc/<pid>/environ (Linux environ_read): the environment strings of
/// the address space pinned at open, which checked ptrace-read access
pub fn gen_environ(mm: &Mm) -> Result<Vec<u8>, KernelError> {
    let a = mm.mmap_read_killable()?.args();
    if a.env_end == 0 {
        return Ok(Vec::new());
    }
    Ok(read_remote(mm, a.env_start, a.env_end))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test task (its Arc fields None); never dropped, so the host
    /// test does not link the drop paths of the signal and fd tables
    fn snap_of(comm: &[u8]) -> core::mem::ManuallyDrop<Snap> {
        let mut c = [0u8; 16];
        c[..comm.len()].copy_from_slice(comm);
        core::mem::ManuallyDrop::new(Snap {
            pid: 42,
            tgid: 42,
            ppid: 1,
            pgid: 40,
            sid: 30,
            ns_ids: [[0; 4]; LEVELS],
            levels: 0,
            comm: c,
            state: TaskState::Sleeping,
            cred: Cred::ROOT,
            kthread: false,
            exiting: false,
            utime: 2_000_000_000,
            stime: 1_000_000_000,
            cutime: 0,
            cstime: 0,
            start: 5_000_000_000,
            nvcsw: 0,
            nivcsw: 0,
            min_flt: 7,
            maj_flt: 3,
            nice: 5,
            policy: 0,
            rt_priority: 0,
            cpus: crate::util::cpumask::CpuSet::new(),
            cpu: 2,
            exit_signal: 17,
            exit_code: 0,
            threads: 1,
            tracer: 0,
            no_new_privs: false,
            seccomp: 0,
            blocked: 1 << 1,
            pending: 0,
            shared: None,
            sighand: None,
            signal: None,
            fs: None,
            files: None,
        })
    }

    /// The fields after the comm's closing ')', 1-based from field 3
    fn fields(line: &[u8]) -> Vec<&[u8]> {
        let close = line.iter().rposition(|&b| b == b')').unwrap();
        line[close + 2..]
            .strip_suffix(b"\n")
            .unwrap()
            .split(|&b| b == b' ')
            .collect()
    }

    /// 52 fields in Linux do_task_stat's order; a comm with spaces and
    /// parentheses stays one field, found by the last ')'
    #[test]
    fn stat_fields() {
        let s = snap_of(b"a) (b c");
        let mut v = VmStat {
            total: 10,
            rss: 4,
            ..VmStat::default()
        };
        v.lay.start_code = 0x40_0000;
        let line = fmt_stat(&s, Some(&v), true, (1 << 12, 1 << 14), 99);
        assert!(line.starts_with(b"42 (a) (b c) S "));
        let f = fields(&line);
        assert_eq!(f.len(), 52 - 2);
        let at = |n: usize| core::str::from_utf8(f[n - 3]).unwrap();
        assert_eq!((at(4), at(5), at(6)), ("1", "40", "30"));
        assert_eq!((at(10), at(12)), ("7", "3"));
        assert_eq!((at(14), at(15)), ("200", "100"));
        assert_eq!((at(18), at(19), at(20)), ("25", "5", "1"));
        assert_eq!(at(22), "500");
        assert_eq!((at(23), at(24), at(25)), ("40960", "4", "99"));
        assert_eq!(at(26), "4194304");
        assert_eq!((at(32), at(33), at(34)), ("2", "4096", "16384"));
        assert_eq!((at(38), at(39)), ("17", "2"));
        assert_eq!(at(52), "0");
    }

    /// Without ptrace-read access the code range reads as 1, the stack
    /// and argument addresses as 0 (Linux do_task_stat !permitted)
    #[test]
    fn stat_hides_addresses() {
        let mut v = VmStat::default();
        v.lay.start_code = 0x40_0000;
        v.lay.start_stack = 0x7fff_0000;
        v.lay.arg_start = 0x7fff_1000;
        let line = fmt_stat(&snap_of(b"x"), Some(&v), false, (0, 0), 0);
        let f = fields(&line);
        assert_eq!(f.len(), 50);
        let at = |n: usize| f[n - 3];
        assert_eq!((at(26), at(27), at(28)), (&b"1"[..], &b"1"[..], &b"0"[..]));
        assert!((45..=51).all(|n| at(n) == b"0"));
    }
}
