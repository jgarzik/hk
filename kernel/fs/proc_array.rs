//! /proc/<pid>/{status,stat,cmdline,environ} (Linux 6.8 fs/proc/array.c
//! proc_pid_status / do_task_stat, fs/proc/base.c proc_pid_cmdline_read
//! / environ_read)
//!
//! Locking: the task's fields are copied under TASKLIST, which is
//! dropped before anything else is taken; then, one at a time and never
//! nested, the address space's mmap_lock (VM sizes, page counts and the
//! remote reads of cmdline/environ), the sighand action lock, the shared
//! pending set, `FsStruct.inner` (umask) and the descriptor table lock.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;

use crate::mm::{Mm, MmLayout, MmStruct, PROT_EXEC, PROT_WRITE, VM_GROWSDOWN, VM_SHARED};
use crate::task::percpu::TASKLIST;
use crate::task::{Cred, Pid, TaskKind, TaskState, Tid};

/// Linux PF_KTHREAD / PF_EXITING (stat field 9)
const PF_EXITING: u64 = 0x0000_0004;
const PF_KTHREAD: u64 = 0x0020_0000;
/// USER_HZ: stat times are in clock ticks
const NS_PER_TICK: u64 = 10_000_000;
/// The most cmdline/environ return (Linux reads them a page at a time
/// but exec caps the strings at 128 KiB)
const ARGS_MAX: u64 = 128 * 1024;

/// What /proc reads of a task, copied under TASKLIST
struct Snap {
    pid: Pid,
    tid: Tid,
    tgid: Pid,
    ppid: Pid,
    pgid: Pid,
    sid: Pid,
    comm: [u8; 16],
    state: TaskState,
    cred: Cred,
    kthread: bool,
    exiting: bool,
    utime: u64,
    stime: u64,
    start: u64,
    nvcsw: u64,
    nivcsw: u64,
    min_flt: u64,
    maj_flt: u64,
    nice: i32,
    policy: i32,
    rt_priority: i32,
    cpus: crate::cpumask::CpuSet,
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
    fs: Option<Arc<super::FsStruct>>,
    files: Option<Arc<crate::task::fdtable::Files>>,
}

/// Copy process `pid` (its first task, the leader) out of TASKLIST
fn snap(pid: Pid) -> Option<Snap> {
    let table = TASKLIST.read();
    let t = table.get(pid)?;
    let threads = table.threads(pid).count() as u64;
    let tracer = t.tracer().map_or(0, |x| x.pid);
    // comm and the resources together, under task_lock
    let (comm, fs, files) = {
        let a = t.task.task_lock();
        (a.comm(), a.fs().cloned(), a.files().cloned())
    };
    let sig = t.task.sig.lock().clone();
    Some(Snap {
        pid,
        tid: t.task.tid(),
        tgid: t.task.pid,
        ppid: t.task.ppid(),
        pgid: t.task.pgid(),
        sid: t.task.sid(),
        comm,
        state: match t.state {
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
        utime: t.task.utime.load(core::sync::atomic::Ordering::Relaxed),
        stime: t.task.stime.load(core::sync::atomic::Ordering::Relaxed),
        start: t.task.start_time(),
        nvcsw: t.task.nvcsw.load(core::sync::atomic::Ordering::Relaxed),
        nivcsw: t.task.nivcsw.load(core::sync::atomic::Ordering::Relaxed),
        min_flt: t.task.min_flt.load(core::sync::atomic::Ordering::Relaxed),
        maj_flt: t.task.maj_flt.load(core::sync::atomic::Ordering::Relaxed),
        nice: t.task.se.nice(),
        policy: t.task.se.policy(),
        rt_priority: t.task.se.rt_priority() as i32,
        cpus: t.task.cpus_mask.snapshot(),
        cpu: t.task.cpu.load(core::sync::atomic::Ordering::Relaxed),
        exit_signal: t.exit_signal,
        exit_code: t.exit_code,
        threads,
        tracer,
        no_new_privs: t.prctl.no_new_privs,
        seccomp: t.task.seccomp_mode(),
        blocked: sig.blocked.0,
        pending: sig.pending.signal.0,
        shared: Some(sig.shared_pending.clone()),
        sighand: t.sighand.clone(),
        signal: t.signal.clone(),
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

/// comm as text, with '\n' and '\\' escaped for status (Linux
/// seq_escape_str ESCAPE_SPACE | ESCAPE_SPECIAL, "\n\\")
fn comm(s: &Snap, escape: bool) -> String {
    let n = s.comm.iter().position(|&b| b == 0).unwrap_or(16);
    let mut out = String::new();
    for &b in &s.comm[..n] {
        match b {
            b'\n' if escape => out.push_str("\\n"),
            b'\\' if escape => out.push_str("\\\\"),
            _ => out.push(b as char),
        }
    }
    out
}

/// (ignored, caught) signals (Linux collect_sigign_sigcatch)
fn ign_cgt(s: &Snap) -> (u64, u64) {
    use crate::signal::SigHandler;
    let Some(h) = &s.sighand else {
        return (0, 0);
    };
    let (mut ign, mut cgt) = (0, 0);
    for sig in 1..=64u32 {
        match h.get_action(sig).map(|a| a.handler) {
            Some(SigHandler::Ignore) => ign |= 1u64 << (sig - 1),
            Some(SigHandler::Handler(_)) => cgt |= 1u64 << (sig - 1),
            _ => {}
        }
    }
    (ign, cgt)
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
        .and_then(|sig| sig.get_rlimit(crate::rlimit::RLIMIT_RSS))
        .map_or(crate::rlimit::RLIM_INFINITY, |r| r.rlim_cur)
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
        let (rss, swap) = crate::mm::memory::count_ptes(mm.pgd(), vma.start, vma.end);
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
fn task_vm(tid: Tid) -> Option<VmStat> {
    let mm = crate::mm::get_task_mm_users(tid)?;
    let m = mm.mmap_read_killable().ok()?;
    Some(vm_stat(&mm, &m))
}

/// /proc/<pid>/status (Linux proc_pid_status)
pub fn gen_status(pid: Pid) -> Vec<u8> {
    let Some(s) = snap(pid) else {
        return Vec::new();
    };
    let mut o = String::new();
    let c = &s.cred;
    let (letter, name) = state(&s);
    let _ = writeln!(o, "Name:\t{}", comm(&s, true));
    if let Some(fs) = &s.fs {
        let _ = writeln!(o, "Umask:\t{:04o}", fs.get_umask());
    }
    let _ = writeln!(o, "State:\t{letter} ({name})");
    let _ = writeln!(o, "Tgid:\t{}\nNgid:\t0\nPid:\t{}", s.tgid, s.pid);
    let _ = writeln!(o, "PPid:\t{}\nTracerPid:\t{}", s.ppid, s.tracer);
    let _ = writeln!(o, "Uid:\t{}\t{}\t{}\t{}", c.uid, c.euid, c.suid, c.fsuid);
    let _ = writeln!(o, "Gid:\t{}\t{}\t{}\t{}", c.gid, c.egid, c.sgid, c.fsgid);
    let _ = writeln!(o, "FDSize:\t{}\nGroups:\t ", fd_size(&s));
    let _ = writeln!(o, "NStgid:\t{}\nNSpid:\t{}", s.tgid, s.pid);
    let _ = writeln!(o, "NSpgid:\t{}\nNSsid:\t{}", s.pgid, s.sid);
    let _ = writeln!(o, "Kthread:\t{}", s.kthread as u8);
    if let Some(v) = task_vm(s.tid) {
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
    let _ = writeln!(o, "NoNewPrivs:\t{}", s.no_new_privs as u8);
    let _ = writeln!(o, "Seccomp:\t{}\nSeccomp_filters:\t0", s.seccomp);
    let _ = writeln!(o, "Speculation_Store_Bypass:\tunknown");
    let _ = writeln!(o, "SpeculationIndirectBranch:\tunknown");
    let n = crate::cpu::nr_cpu_ids();
    let cpus = s.cpus.and(&crate::cpumask::CpuSet::first(n));
    let _ = writeln!(o, "Cpus_allowed:\t{}", cpus.fmt_hex(n));
    let _ = writeln!(o, "Cpus_allowed_list:\t{}", cpus.fmt_list());
    let _ = writeln!(o, "Mems_allowed:\t1\nMems_allowed_list:\t0");
    let _ = writeln!(o, "voluntary_ctxt_switches:\t{}", s.nvcsw);
    let _ = writeln!(o, "nonvoluntary_ctxt_switches:\t{}", s.nivcsw);
    o.into_bytes()
}

/// The Vm* lines (Linux task_mem; hk keeps no high-water marks, so
/// VmPeak/VmHWM are the current sizes)
fn status_mem(o: &mut String, v: &VmStat) {
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
fn status_sig(o: &mut String, s: &Snap) {
    let qlim = s
        .signal
        .as_ref()
        .and_then(|sig| sig.get_rlimit(crate::rlimit::RLIMIT_SIGPENDING))
        .map_or(0, |r| r.rlim_cur);
    let (ign, cgt) = ign_cgt(s);
    let _ = writeln!(o, "Threads:\t{}\nSigQ:\t0/{}", s.threads, qlim);
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
pub fn gen_stat(pid: Pid) -> Vec<u8> {
    let Some(s) = snap(pid) else {
        return Vec::new();
    };
    // The access decision and the mm it covers, as one (Linux holds
    // exec_update_lock across do_task_stat)
    let guard = crate::signal::ExecUpdateRead::lock(s.tid);
    let permitted = crate::task::ptrace::may_read_task(s.tid);
    let v = task_vm(s.tid);
    drop(guard);
    let (ign, cgt) = ign_cgt(&s);
    let ticks = |ns: u64| ns / NS_PER_TICK;
    let rt = s.policy == crate::task::SCHED_FIFO || s.policy == crate::task::SCHED_RR;
    let prio = if rt { -1 - s.rt_priority } else { 20 + s.nice };
    let flags = if s.kthread { PF_KTHREAD } else { 0 } | if s.exiting { PF_EXITING } else { 0 };
    let running = matches!(s.state, TaskState::Running | TaskState::Ready);
    let wchan = (permitted && s.threads < 2 && !running) as u8;
    let mut o = String::new();
    let _ = write!(o, "{} ({}) {} ", s.pid, comm(&s, false), state(&s).0);
    let _ = write!(o, "{} {} {} 0 -1 {} ", s.ppid, s.pgid, s.sid, flags);
    let _ = write!(o, "{} 0 {} 0 ", s.min_flt, s.maj_flt);
    let _ = write!(o, "{} {} 0 0 ", ticks(s.utime), ticks(s.stime));
    let _ = write!(o, "{} {} {} 0 {} ", prio, s.nice, s.threads, ticks(s.start));
    let (vsize, rss) = v.as_ref().map_or((0, 0), |v| (v.total * 4096, v.rss));
    let _ = write!(o, "{} {} {} ", vsize, rss, rss_lim(&s));
    let code = |x: u64| if permitted { x } else { 1 };
    let (sc, ec, ss) = match &v {
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
    match &v {
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
        _ => o.push_str(" 0 0 0 0 0 0 0"),
    }
    let _ = writeln!(o, " {}", if permitted { s.exit_code } else { 0 });
    o.into_bytes()
}

/// Read [start, end) of `mm` (Linux access_remote_vm), mmap_lock held;
/// what could be read, at most ARGS_MAX bytes
fn read_remote(mm: &Mm, m: &MmStruct, start: u64, end: u64) -> Vec<u8> {
    let len = end.saturating_sub(start).min(ARGS_MAX) as usize;
    let mut buf = alloc::vec![0u8; len];
    let n = crate::mm::remote::access_remote_vm_read(mm, m, start, &mut buf).unwrap_or(0);
    buf.truncate(n);
    buf
}

/// /proc/<pid>/cmdline (Linux get_mm_cmdline): the argument strings;
/// if the program overwrote the final NUL of its arguments
/// (setproctitle), the area through the environment up to the first NUL
pub fn gen_cmdline(pid: Pid) -> Vec<u8> {
    let Some(tid) = super::procfs::get_tid_for_pid(pid) else {
        return Vec::new();
    };
    let Some(mm) = crate::mm::get_task_mm_users(tid) else {
        return Vec::new();
    };
    let Ok(m) = mm.mmap_read_killable() else {
        return Vec::new();
    };
    let a = m.args();
    if a.arg_start >= a.arg_end {
        return Vec::new();
    }
    let args = read_remote(&mm, &m, a.arg_start, a.arg_end);
    if args.last().is_none_or(|&c| c == 0) {
        return args;
    }
    // setproctitle: past the arguments only if the environment follows
    let end = if a.env_start == a.arg_end && a.env_end >= a.env_start {
        a.env_end
    } else {
        a.arg_end
    };
    let mut all = read_remote(&mm, &m, a.arg_start, end);
    if let Some(nul) = all.iter().position(|&c| c == 0) {
        all.truncate(nul + 1);
    }
    all
}

/// /proc/<pid>/environ (Linux environ_read): the environment strings of
/// the address space pinned at open, which checked ptrace-read access
pub fn gen_environ(mm: &Mm, m: &MmStruct) -> Vec<u8> {
    let a = m.args();
    if a.env_end == 0 {
        return Vec::new();
    }
    read_remote(mm, m, a.env_start, a.env_end)
}
