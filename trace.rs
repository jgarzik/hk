//! Trace ring buffer and tracefs (Linux kernel/trace: ring_buffer.c,
//! trace.c's `trace` file; fs/tracefs)
//!
//! Trace events (`emit`) are formatted at the call into a per-CPU ring
//! of records, overwriting the oldest when full (Linux's default
//! overwrite mode); they never reach printk or the consoles, so a
//! console driver's own code paths may be traced. tracefs (mounted at
//! /sys/kernel/tracing) shows the rings, merged by timestamp, in its
//! `trace` file in Linux's format.
//!
//! The buffers are allocated at boot only when something asked for
//! tracing on the command line (Linux keeps them minimal until tracing
//! is used: ring_buffer_expanded); events before that are dropped.
//!
//! ## Locking
//!
//! Each CPU's ring is an `IrqSpinlock` leaf (`emit` runs in any
//! context: hardirq, under any lock). A reader copies each ring out
//! under its lock into a buffer allocated before taking it, then
//! formats with no lock held.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use spin::Once;

use crate::cpu::PerCpu;
use crate::fs::KernelError;
use crate::fs::dentry::Dentry;
use crate::fs::inode::{Inode, InodeMode, InodeOps};
use crate::fs::kernfs::{self, BinAttr, KNode, sysfs};
use crate::fs::superblock::{FileSystemType, StatFs, SuperBlock, SuperOps, fs_flags};
use crate::sync::IrqSpinlock;
use crate::util::kalloc::{arc_nofail, try_arc};
use crate::util::kmem::try_vec;

/// Bytes of each CPU's ring
const RING_SIZE: usize = 64 * 1024;
/// Longest event text kept (the rest is cut)
const TEXT_MAX: usize = 256;
/// Record header: length u16, pid u32, timestamp u64, comm [u8; 16];
/// the text ("event: ...") follows
const HDR: usize = 2 + 4 + 8 + 16;

/// Linux TRACEFS_MAGIC
pub const TRACEFS_MAGIC: u64 = 0x7472_6163;

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

/// Each CPU's ring, once allocated
static RINGS: PerCpu<Once<Box<IrqSpinlock<Ring>>>> = crate::percpu![Once::new()];

/// Tracing was asked for on the command line: allocate the rings
static WANTED: AtomicBool = AtomicBool::new(false);

/// Events dropped for lack of a ring (before allocation)
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Ask for the trace buffers (command line parsing; Linux trace_event=
/// expands the ring buffer at boot)
pub fn want_buffers() {
    WANTED.store(true, Ordering::Release);
}

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

/// Record event `name` with text `args` on this CPU's ring (Linux
/// trace_event_buffer_commit), in any context; nothing allocated
pub fn emit(name: &'static str, args: fmt::Arguments<'_>) {
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
    let _ = write!(w, "{}: ", name);
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
    let mut out = kernfs::SysBuf::default();
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
        out.bytes(r.text);
        out.bytes(b"\n");
        pos[i] += l;
    }
    Ok(out.0)
}

/// /sys/kernel/tracing/trace (Linux tracing_fops, read side)
struct TraceFile;

impl BinAttr for TraceFile {
    /// Linux shows the trace files with size 0
    fn size(&self) -> u64 {
        0
    }

    fn read(&self, off: u64, buf: &mut [u8]) -> Result<usize, KernelError> {
        let t = trace_text()?;
        let start = usize::try_from(off).map_or(t.len(), |o| o.min(t.len()));
        let n = buf.len().min(t.len() - start);
        buf[..n].copy_from_slice(&t[start..start + n]);
        Ok(n)
    }
}

static ROOT: Once<Arc<KNode>> = Once::new();

fn root() -> &'static Arc<KNode> {
    ROOT.call_once(KNode::new_root)
}

struct TracefsSops;

impl SuperOps for TracefsSops {
    fn alloc_inode(
        &self,
        _sb: &Arc<SuperBlock>,
        _mode: InodeMode,
        _i_op: &'static dyn InodeOps,
    ) -> Result<Arc<Inode>, KernelError> {
        Err(KernelError::OperationNotSupported)
    }

    fn statfs(&self, _sb: &SuperBlock) -> StatFs {
        StatFs {
            f_type: TRACEFS_MAGIC,
            f_bsize: 4096,
            f_namelen: 255,
            ..StatFs::default()
        }
    }
}

static TRACEFS_SOPS: TracefsSops = TracefsSops;

/// One superblock for every mount (Linux tracefs: get_tree_single)
fn mount(t: &'static FileSystemType, _opts: &[u8]) -> Result<Arc<SuperBlock>, KernelError> {
    crate::fs::superblock::sget(
        t,
        |_| true,
        || {
            let sb = SuperBlock::alloc(t, &TRACEFS_SOPS, 0)?;
            sb.set_private(try_arc(kernfs::vfs::KfSuper { ns: 0 })?);
            let ri = kernfs::vfs::inode(&sb, root())?;
            sb.set_root(crate::fs::DentryRef::new(Dentry::new_root(
                ri,
                Arc::downgrade(&sb),
            ))?);
            Ok(sb)
        },
    )
}

pub static TRACEFS_TYPE: FileSystemType = FileSystemType {
    name: "tracefs",
    fs_flags: fs_flags::FS_PSEUDO,
    mount,
    mount_dev: None,
    file_ops: &kernfs::vfs::KERNFS_FOPS,
    next: crate::fs::superblock::FsNext::new(None),
    fs_supers: crate::fs::superblock::FsSupers::new(crate::util::list::WeakList::new()),
};

/// Linux tracefs_init (the type, /sys/kernel/tracing to mount it on)
/// and tracer_init_tracefs (the `trace` file); the rings if asked for
pub fn init() {
    if WANTED.load(Ordering::Acquire) {
        for cpu in 0..crate::cpu::nr_cpu_ids() {
            let Ok(buf) = try_vec(RING_SIZE, 0u8) else {
                break;
            };
            let ring = IrqSpinlock::new(Ring {
                buf,
                head: 0,
                used: 0,
                written: 0,
                overrun: 0,
            });
            if let Ok(b) = crate::util::kalloc::try_box(ring) {
                RINGS.get(cpu).call_once(|| b);
            }
        }
    }
    let _ = root().create_bin(b"trace", 0o440, arc_nofail(TraceFile));
    sysfs::mount_point(&sysfs::top_dir(b"kernel"), b"tracing");
    crate::fs::superblock::register_filesystem(&TRACEFS_TYPE).expect("tracefs type");
}
