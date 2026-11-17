//! Trace ring buffer and its tracefs files (Linux kernel/trace:
//! ring_buffer.c, trace.c's `trace` file, trace_events.c's enable
//! files; the filesystem is `fs::tracefs`)
//!
//! Trace events (`emit`) are formatted at the call into a per-CPU ring
//! of records, overwriting the oldest when full (Linux's default
//! overwrite mode); they never reach printk or the consoles, so a
//! console driver's own code paths may be traced. tracefs (mounted at
//! /sys/kernel/tracing) shows the rings, merged by timestamp, in its
//! `trace` file in Linux's format.
//!
//! Events belong to systems (`TraceSystem`, Linux TRACE_SYSTEM), each
//! registered with its events at init; an event records only while
//! enabled, through tracefs's `events/[<system>/[<event>/]]enable` or
//! the `trace_event=` boot parameter (Linux kernel/trace/
//! trace_events.c).
//!
//! The buffers are allocated when an event is first enabled, at boot
//! for `trace_event=` (Linux keeps them minimal until tracing is used:
//! tracing_update_buffers).
//!
//! ## Locking
//!
//! Each CPU's ring is an `IrqSpinlock` leaf (`emit` runs in any
//! context: hardirq, under any lock). A reader copies each ring out
//! under its lock into a buffer allocated before taking it, then
//! formats with no lock held. `EVENT_MUTEX` (sleeping, Linux
//! event_mutex) holds the registered systems and serializes enabling,
//! which allocates the rings under it; an event's flag is an atomic
//! the emitters read lock-free. A system's tracefs directories are made
//! under it (`EVENT_MUTEX` -> the tracefs directory's i_rwsem); an
//! enable file's write takes it under that file's i_rwsem.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use spin::Once;

use crate::fs::KernelError;
use crate::fs::dentry::DentryRef;
use crate::fs::iov_iter::{IovDest, IovSource};
use crate::fs::libfs;
use crate::fs::tracefs::{self, TraceFops};
use crate::sync::{IrqSpinlock, Mutex};
use crate::util::kalloc::arc_nofail;
use crate::util::kmem::try_vec;

/// Bytes of each CPU's ring
const RING_SIZE: usize = 64 * 1024;
/// Longest event text kept (the rest is cut)
const TEXT_MAX: usize = 256;
/// Record header: length u16, pid u32, timestamp u64, comm [u8; 16];
/// the text ("event: ...") follows
const HDR: usize = 2 + 4 + 8 + 16;

/// A CPU's ring of records (Linux ring_buffer_per_cpu): bytes from
/// `head` (oldest) for `used`, wrapping
struct Ring {
    buf: Vec<u8>,
    head: usize,
    used: usize,
    /// Records written, and those overwritten (Linux entries/overrun)
    written: u64,
    overrun: u64,
}

impl Ring {
    fn put(&mut self, at: usize, b: &[u8]) {
        let n = self.buf.len();
        for (i, &x) in b.iter().enumerate() {
            self.buf[(at + i) % n] = x;
        }
    }

    fn get(&self, at: usize, b: &mut [u8]) {
        let n = self.buf.len();
        for (i, x) in b.iter_mut().enumerate() {
            *x = self.buf[(at + i) % n];
        }
    }

    /// Length of the oldest record
    fn first_len(&self) -> usize {
        let mut l = [0u8; 2];
        self.get(self.head, &mut l);
        usize::from(u16::from_le_bytes(l))
    }

    /// Append one record, dropping the oldest ones for room
    fn push(&mut self, hdr: &[u8; HDR], text: &[u8]) {
        let len = HDR + text.len();
        while self.buf.len() - self.used < len {
            let l = self.first_len();
            self.head = (self.head + l) % self.buf.len();
            self.used -= l;
            self.overrun += 1;
        }
        let at = (self.head + self.used) % self.buf.len();
        self.put(at, hdr);
        self.put(at + HDR, text);
        self.used += len;
        self.written += 1;
    }

    /// Copy the records out, oldest first, into `out` (sized
    /// `RING_SIZE` by the caller)
    fn copy_out(&self, out: &mut Vec<u8>) {
        out.resize(self.used, 0);
        self.get(self.head, out);
    }
}

crate::percpu! {
    /// Each CPU's ring, once allocated
    static RINGS: Once<Box<IrqSpinlock<Ring>>> = Once::new();
}

/// Events dropped for lack of a ring
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Allocate every CPU's ring not allocated yet (Linux
/// tracing_update_buffers); thread context, under `EVENT_MUTEX`
fn update_buffers() -> Result<(), KernelError> {
    for cpu in 0..crate::cpu::nr_cpu_ids() {
        let slot = RINGS.get(cpu);
        if slot.get().is_some() {
            continue;
        }
        let ring = IrqSpinlock::new(Ring {
            buf: try_vec(RING_SIZE, 0u8)?,
            head: 0,
            used: 0,
            written: 0,
            overrun: 0,
        });
        let b = crate::util::kalloc::try_box(ring)?;
        slot.call_once(|| b);
    }
    Ok(())
}

/// A trace event (Linux trace_event_call and its trace_event_file's
/// enable flag)
pub struct TraceEvent {
    name: &'static str,
    enabled: AtomicBool,
}

impl TraceEvent {
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            enabled: AtomicBool::new(false),
        }
    }

    /// Recording (lock-free: the tracepoint's static key)
    #[inline]
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
}

/// A trace system and its events (Linux TRACE_SYSTEM)
pub struct TraceSystem {
    pub name: &'static str,
    pub events: &'static [&'static TraceEvent],
}

/// The registered systems (Linux event_mutex over the event list)
static EVENT_MUTEX: Mutex<Vec<&'static TraceSystem>> = Mutex::new(Vec::new());

/// Turn `ev` on or off (Linux ftrace_event_enable_disable), the rings
/// allocated first; under `EVENT_MUTEX`
fn enable_event(ev: &TraceEvent, on: bool) -> Result<(), KernelError> {
    if on {
        update_buffers()?;
    }
    ev.enabled.store(on, Ordering::Relaxed);
    Ok(())
}

/// Set or clear the events of `systems` that `spec` names (Linux
/// ftrace_set_clr_event): `<system>:<event>`, either side empty or `*`
/// for any, or a bare name matching an event or a system. EINVAL if it
/// names none
fn set_clr(systems: &[&'static TraceSystem], spec: &str, on: bool) -> Result<(), KernelError> {
    let any = |s: &str| s.is_empty() || s == "*";
    let (matches, sub, event) = match spec.split_once(':') {
        Some((sub, ev)) => (None, (!any(sub)).then_some(sub), (!any(ev)).then_some(ev)),
        None => (Some(spec), None, None),
    };
    let (mut matched, mut err) = (false, None);
    for sys in systems {
        for ev in sys.events {
            if matches.is_some_and(|m| m != ev.name && m != sys.name)
                || sub.is_some_and(|s| s != sys.name)
                || event.is_some_and(|e| e != ev.name)
            {
                continue;
            }
            matched = true;
            // The first error is returned, the rest still set (Linux eret)
            if let Err(e) = enable_event(ev, on) {
                err.get_or_insert(e);
            }
        }
    }
    match (matched, err) {
        (false, _) => Err(KernelError::InvalidArgument),
        (true, Some(e)) => Err(e),
        (true, None) => Ok(()),
    }
}

/// The `trace_event=` boot parameters' events, comma separated, every
/// occurrence (Linux setup_trace_event appends them to
/// bootup_event_buf)
fn boot_events() -> impl Iterator<Item = &'static str> {
    crate::cmdline::saved()
        .split_whitespace()
        .filter_map(|w| w.strip_prefix("trace_event="))
        .flat_map(|l| l.split(','))
        .filter(|e| !e.is_empty())
}

/// Register a system's events (thread context, after `init`): its
/// tracefs directories, then the boot parameter's events among them
/// (Linux trace_module_add_events, early_enable_events)
pub fn register_system(sys: &'static TraceSystem) {
    let mut systems = EVENT_MUTEX.lock();
    if systems.try_reserve(1).is_err() {
        return;
    }
    systems.push(sys);
    if let Some(events) = EVENTS_DIR.get()
        && let Ok(d) = tracefs::create_dir(sys.name.as_bytes(), Some(events))
    {
        let f = arc_nofail(SystemEnable(sys));
        let _ = tracefs::create_file(b"enable", 0o640, Some(&d), f);
        for &ev in sys.events {
            if let Ok(e) = tracefs::create_dir(ev.name.as_bytes(), Some(&d)) {
                let f = arc_nofail(EventEnable(ev));
                let _ = tracefs::create_file(b"enable", 0o640, Some(&e), f);
            }
        }
    }
    for spec in boot_events() {
        let _ = set_clr(&[sys], spec, true);
    }
}

/// An enable file's write: 0 or 1, else EINVAL (Linux
/// kstrtoul_from_user, then the 0/1 switch)
fn parse_enable(data: &[u8]) -> Result<bool, KernelError> {
    let d = data.strip_suffix(b"\n").unwrap_or(data);
    match d {
        b"0" => Ok(false),
        b"1" => Ok(true),
        _ => Err(KernelError::InvalidArgument),
    }
}

/// The value an enable file's write gives (Linux kstrtoul_from_user:
/// the write's first bytes, as many as a long's digits can need, then
/// parsed) and the write's length, all of it taken once applied
fn enable_write(from: &mut IovSource<'_>) -> Result<(bool, usize), KernelError> {
    let len = from.len();
    let mut buf = [0u8; 1 + 64 + 1];
    let n = len.min(buf.len());
    from.copy_from_full(&mut buf[..n])?;
    Ok((parse_enable(&buf[..n])?, len))
}

/// '0' all off, '1' all on, 'X' mixed (Linux system_enable_read)
fn enable_char<'a>(events: impl Iterator<Item = &'a TraceEvent>) -> u8 {
    let mut set = 0u8;
    for ev in events {
        set |= if ev.enabled() { 2 } else { 1 };
    }
    b"001X"[usize::from(set)]
}

/// events/<system>/<event>/enable (Linux event_enable_fops)
struct EventEnable(&'static TraceEvent);

impl TraceFops for EventEnable {
    /// Linux event_enable_read
    fn read(&self, to: &mut IovDest<'_>, pos: &mut u64) -> Result<usize, KernelError> {
        let s: &[u8] = if self.0.enabled() { b"1\n" } else { b"0\n" };
        libfs::simple_read_from_buffer(to, pos, s)
    }

    /// Linux event_enable_write
    fn write(&self, from: &mut IovSource<'_>, pos: &mut u64) -> Result<usize, KernelError> {
        let (on, n) = enable_write(from)?;
        let _g = EVENT_MUTEX.lock();
        enable_event(self.0, on)?;
        *pos += n as u64;
        Ok(n)
    }
}

/// events/<system>/enable (Linux system_enable_fops)
struct SystemEnable(&'static TraceSystem);

impl TraceFops for SystemEnable {
    /// Linux system_enable_read
    fn read(&self, to: &mut IovDest<'_>, pos: &mut u64) -> Result<usize, KernelError> {
        let s = [enable_char(self.0.events.iter().copied()), b'\n'];
        libfs::simple_read_from_buffer(to, pos, &s)
    }

    /// Linux system_enable_write
    fn write(&self, from: &mut IovSource<'_>, pos: &mut u64) -> Result<usize, KernelError> {
        let (on, n) = enable_write(from)?;
        let _g = EVENT_MUTEX.lock();
        for &ev in self.0.events {
            enable_event(ev, on)?;
        }
        *pos += n as u64;
        Ok(n)
    }
}

/// events/enable: every system's events (Linux the top-level
/// system_enable_fops, dir->subsystem NULL)
struct AllEnable;

impl TraceFops for AllEnable {
    fn read(&self, to: &mut IovDest<'_>, pos: &mut u64) -> Result<usize, KernelError> {
        let systems = EVENT_MUTEX.lock();
        let c = enable_char(systems.iter().flat_map(|s| s.events.iter().copied()));
        drop(systems);
        libfs::simple_read_from_buffer(to, pos, &[c, b'\n'])
    }

    fn write(&self, from: &mut IovSource<'_>, pos: &mut u64) -> Result<usize, KernelError> {
        let (on, n) = enable_write(from)?;
        let systems = EVENT_MUTEX.lock();
        for ev in systems.iter().flat_map(|s| s.events.iter()) {
            enable_event(ev, on)?;
        }
        *pos += n as u64;
        Ok(n)
    }
}

/// tracefs's events directory
static EVENTS_DIR: Once<DentryRef> = Once::new();

/// A writer into a fixed buffer that cuts what does not fit
struct Cut<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl Write for Cut<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// Record event `ev`, if enabled, with text `args` on this CPU's ring
/// (Linux trace_event_buffer_commit), in any context; nothing allocated
pub fn emit(ev: &TraceEvent, args: fmt::Arguments<'_>) {
    if !ev.enabled() {
        return;
    }
    let Some(cpu) = crate::cpu::try_this_id() else {
        return;
    };
    let Some(ring) = RINGS.get(cpu).get() else {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let mut text = [0u8; TEXT_MAX];
    let mut w = Cut {
        buf: &mut text,
        len: 0,
    };
    let _ = write!(w, "{}: ", ev.name);
    let _ = w.write_fmt(args);
    let tlen = w.len;
    let cur = crate::task::percpu::current();
    let mut hdr = [0u8; HDR];
    let len = (HDR + tlen) as u16;
    hdr[0..2].copy_from_slice(&len.to_le_bytes());
    hdr[2..6].copy_from_slice(&(cur.tid() as u32).to_le_bytes());
    hdr[6..14].copy_from_slice(&crate::time::monotonic_ns().to_le_bytes());
    hdr[14..30].copy_from_slice(&cur.comm());
    ring.lock().push(&hdr, &text[..tlen]);
}

/// One record copied out of a ring
struct Rec<'a> {
    cpu: u32,
    pid: u32,
    ts: u64,
    comm: &'a [u8],
    text: &'a [u8],
}

/// The record at the start of `b` and its length
fn parse(cpu: u32, b: &[u8]) -> Option<(Rec<'_>, usize)> {
    let len = usize::from(u16::from_le_bytes(b.get(0..2)?.try_into().ok()?));
    let rec = b.get(..len).filter(|r| r.len() >= HDR)?;
    let comm = &rec[14..30];
    let comm = &comm[..comm.iter().position(|&c| c == 0).unwrap_or(16)];
    Some((
        Rec {
            cpu,
            pid: u32::from_le_bytes(rec[2..6].try_into().ok()?),
            ts: u64::from_le_bytes(rec[6..14].try_into().ok()?),
            comm,
            text: &rec[HDR..],
        },
        len,
    ))
}

/// The `trace` file's text (Linux print_trace_header and the default
/// event output, merged across CPUs by timestamp)
fn trace_text() -> Result<Vec<u8>, KernelError> {
    let mut copies: Vec<(u32, Vec<u8>)> = Vec::new();
    let (mut entries, mut written) = (0u64, 0u64);
    for (cpu, slot) in RINGS.for_each_possible() {
        let Some(ring) = slot.get() else {
            continue;
        };
        let mut b = try_vec(RING_SIZE, 0u8)?;
        b.clear();
        {
            let r = ring.lock();
            r.copy_out(&mut b);
            written += r.written;
            entries += r.written - r.overrun;
        }
        copies
            .try_reserve(1)
            .map_err(|_| KernelError::OutOfMemory)?;
        copies.push((cpu, b));
    }
    let mut out = Out(Vec::new());
    let _ = write!(
        out,
        "# tracer: nop\n#\n# entries-in-buffer/entries-written: {}/{}   #P:{}\n#\n\
         #           TASK-PID     CPU#     TIMESTAMP  FUNCTION\n\
         #              | |         |         |         |\n",
        entries,
        written,
        crate::cpu::nr_cpu_ids()
    );
    let mut pos: Vec<usize> = try_vec(copies.len(), 0)?;
    loop {
        let mut best: Option<(usize, Rec<'_>, usize)> = None;
        for (i, (cpu, b)) in copies.iter().enumerate() {
            if let Some((r, l)) = parse(*cpu, &b[pos[i]..])
                && best.as_ref().is_none_or(|(_, x, _)| r.ts < x.ts)
            {
                best = Some((i, r, l));
            }
        }
        let Some((i, r, l)) = best else {
            break;
        };
        let comm = core::str::from_utf8(r.comm).unwrap_or("?");
        let _ = write!(
            out,
            "{:>16}-{:<7} [{:03}] {:5}.{:06}: ",
            comm,
            r.pid,
            r.cpu,
            r.ts / 1_000_000_000,
            r.ts % 1_000_000_000 / 1000
        );
        out.0.extend_from_slice(r.text);
        out.0.push(b'\n');
        pos[i] += l;
    }
    Ok(out.0)
}

/// The `trace` file's text as it grows (formatting cannot fail)
struct Out(Vec<u8>);

impl Write for Out {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// /sys/kernel/tracing/trace (Linux tracing_fops)
struct TraceFile;

impl TraceFops for TraceFile {
    /// Linux tracing_open: an open for writing with O_TRUNC empties
    /// every CPU's ring (tracing_reset_online_cpus)
    fn open(&self, writable: bool, flags: u32) -> Result<(), KernelError> {
        if writable && flags & crate::fs::file::flags::O_TRUNC != 0 {
            reset();
        }
        Ok(())
    }

    /// The text from `*pos` on (Linux seq_read of the trace iterator)
    fn read(&self, to: &mut IovDest<'_>, pos: &mut u64) -> Result<usize, KernelError> {
        libfs::simple_read_from_buffer(to, pos, &trace_text()?)
    }

    /// Writes are accepted and dropped (Linux tracing_write_stub), so
    /// `echo > trace` clears through its O_TRUNC open
    fn write(&self, from: &mut IovSource<'_>, _pos: &mut u64) -> Result<usize, KernelError> {
        Ok(from.len())
    }
}

/// Empty every CPU's ring, its counts too (Linux tracing_reset_online_cpus)
fn reset() {
    for (_, slot) in RINGS.for_each_possible() {
        if let Some(ring) = slot.get() {
            let mut r = ring.lock();
            r.head = 0;
            r.used = 0;
            r.written = 0;
            r.overrun = 0;
        }
    }
}

/// Linux tracer_init_tracefs (the `trace` file) and event_trace_init
/// (the events directory); the rings now if `trace_event=` asks for
/// events (Linux setup_trace_event expands the ring buffer)
pub fn init() {
    if boot_events().next().is_some() {
        let _g = EVENT_MUTEX.lock();
        let _ = update_buffers();
    }
    let _ = tracefs::create_file(b"trace", 0o640, None, arc_nofail(TraceFile));
    if let Ok(events) = tracefs::create_dir(b"events", None) {
        let f = arc_nofail(AllEnable);
        let _ = tracefs::create_file(b"enable", 0o640, Some(&events), f);
        EVENTS_DIR.call_once(|| events);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static A: TraceEvent = TraceEvent::new("a_ev");
    static B: TraceEvent = TraceEvent::new("b_ev");
    static C: TraceEvent = TraceEvent::new("a_ev");
    static S1: TraceSystem = TraceSystem {
        name: "sys1",
        events: &[&A, &B],
    };
    static S2: TraceSystem = TraceSystem {
        name: "sys2",
        events: &[&C],
    };

    fn all_on() {
        for e in [&A, &B, &C] {
            e.enabled.store(true, Ordering::Relaxed);
        }
    }

    fn state() -> [bool; 3] {
        [A.enabled(), B.enabled(), C.enabled()]
    }

    /// Linux ftrace_parse_event_string's forms, clearing (no buffers);
    /// one test, as the events are shared statics
    #[test]
    fn event_specs() {
        let sys = [&S1, &S2];
        all_on();
        assert!(set_clr(&sys, "sys1:b_ev", false).is_ok());
        assert_eq!(state(), [true, false, true]);
        assert_eq!(enable_char(S1.events.iter().copied()), b'X');
        all_on();
        assert!(set_clr(&sys, "sys1:", false).is_ok());
        assert_eq!(state(), [false, false, true]);
        assert_eq!(enable_char(S1.events.iter().copied()), b'0');
        all_on();
        assert!(set_clr(&sys, "*:a_ev", false).is_ok());
        assert_eq!(state(), [false, true, false]);
        all_on();
        // A bare name: an event or a system of that name
        assert!(set_clr(&sys, "sys2", false).is_ok());
        assert_eq!(state(), [true, true, false]);
        assert_eq!(enable_char(S1.events.iter().copied()), b'1');
        all_on();
        assert!(set_clr(&sys, "a_ev", false).is_ok());
        assert_eq!(state(), [false, true, false]);
        assert!(matches!(
            set_clr(&sys, "nope", false),
            Err(KernelError::InvalidArgument)
        ));
        assert!(matches!(
            set_clr(&sys, "sys1:nope", false),
            Err(KernelError::InvalidArgument)
        ));
    }

    #[test]
    fn enable_values() {
        assert!(matches!(parse_enable(b"1\n"), Ok(true)));
        assert!(matches!(parse_enable(b"0"), Ok(false)));
        assert!(parse_enable(b"2").is_err());
        assert!(parse_enable(b"x").is_err());
    }
}
