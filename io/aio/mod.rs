//! Linux native AIO: io_setup, io_destroy, io_submit, io_cancel,
//! io_getevents, io_pgetevents (Linux fs/aio.c; libaio's ABI)
//!
//! A context is a ring of events mapped into the process (`ring`), its
//! address the context id, found through the address space's table
//! (`IoctxTable`, Linux mm->ioctx_table) by the id the ring's header
//! holds. io_submit makes a request per iocb (`kiocb`), which reads or
//! writes (`rw`), syncs or polls (`poll`); its event lands in the ring
//! when it ends, from wherever it ends (`ctx`). io_destroy and the
//! address space's end (exit, exec) wait for every request to end, so
//! no I/O reaches user memory afterwards. aio-nr / aio-max-nr
//! (/proc/sys/fs) bound the events asked for system-wide.

pub mod abi;
pub mod ctx;
pub mod kiocb;
pub mod poll;
pub mod ring;
pub mod rw;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::sync::spin::Mutex;
use crate::uaccess::{UserPtr, copy_val_from_user, get_user, put_user};
use crate::util::error::{KernelError, KernelResult};
use crate::util::kalloc::try_arc;
use abi::*;
use ctx::{CtxRef, Kioctx};
use kiocb::Base;
use ring::{AIO_RING_FOPS, AioRing, ring_size};

// ============================================================================
// Limits (Linux aio_nr, aio_max_nr: /proc/sys/fs/aio-nr, aio-max-nr)
// ============================================================================

/// Events asked for by every live context (Linux aio_nr under
/// aio_nr_lock: system-wide by definition)
static AIO_NR: Mutex<u64> = Mutex::new(0);
/// Most events all contexts may ask for (Linux aio_max_nr)
static AIO_MAX_NR: AtomicU64 = AtomicU64::new(0x10000);

/// Count `n` events in aio-nr; EAGAIN past aio-max-nr
fn aio_nr_add(n: u32) -> KernelResult<()> {
    let max = AIO_MAX_NR.load(Ordering::Relaxed);
    let mut nr = AIO_NR.lock();
    match nr.checked_add(u64::from(n)) {
        Some(v) if v <= max => {
            *nr = v;
            Ok(())
        }
        _ => Err(KernelError::WouldBlock),
    }
}

fn aio_nr_sub(n: u32) {
    let mut nr = AIO_NR.lock();
    *nr = nr.saturating_sub(u64::from(n));
}

fn to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// /proc/sys/fs/aio-nr and aio-max-nr (Linux aio_sysctls)
pub static AIO_CTLS: &[crate::sysctl::Ctl] = &[
    crate::sysctl::Ctl {
        path: "fs/aio-nr",
        mode: 0o444,
        show: || alloc::vec![to_i64(*AIO_NR.lock())],
        store: |_| Err(KernelError::PermissionDenied),
        text: None,
    },
    crate::sysctl::Ctl {
        path: "fs/aio-max-nr",
        mode: 0o644,
        show: || alloc::vec![to_i64(AIO_MAX_NR.load(Ordering::Relaxed))],
        // proc_doulongvec_minmax: no negative value
        store: |v| {
            let n = u64::try_from(v[0]).map_err(|_| KernelError::InvalidArgument)?;
            AIO_MAX_NR.store(n, Ordering::Relaxed);
            Ok(())
        },
        text: None,
    },
];

// ============================================================================
// The address space's contexts (Linux mm->ioctx_table, mm->ioctx_lock)
// ============================================================================

/// An address space's AIO contexts by id (Linux kioctx_table): a spin
/// leaf, thread context; taken under the mmap_lock by mremap
pub struct IoctxTable {
    slots: Mutex<Vec<Option<Arc<Kioctx>>>>,
}

impl Default for IoctxTable {
    fn default() -> Self {
        Self::new()
    }
}

impl IoctxTable {
    pub const fn new() -> Self {
        Self {
            slots: Mutex::new(Vec::new()),
        }
    }

    /// Give `ctx` the first free id (Linux ioctx_add_table: the table
    /// grows fourfold, allocated outside the lock); ENOMEM
    fn add(&self, ctx: &Arc<Kioctx>) -> KernelResult<()> {
        loop {
            let cap = {
                let mut t = self.slots.lock();
                let free = t.iter().position(Option::is_none);
                let id = match free {
                    Some(i) => Some(i),
                    None if t.len() < t.capacity() => {
                        t.push(None);
                        Some(t.len() - 1)
                    }
                    None => None,
                };
                if let Some(i) = id {
                    t[i] = Some(ctx.clone());
                    // Lossless: ids are bounded by aio-max-nr contexts
                    ctx.set_id(i as u32);
                    return Ok(());
                }
                t.capacity()
            };
            let spare = crate::util::kmem::spare(cap.max(1) * 2)?;
            let old = crate::util::kmem::adopt(&mut self.slots.lock(), spare);
            drop(old);
        }
    }

    /// The live context `id` whose ring is at `user_id`
    fn get(&self, id: u32, user_id: u64) -> Option<Arc<Kioctx>> {
        let t = self.slots.lock();
        let c = t.get(id as usize)?.as_ref()?;
        (c.user_id() == user_id).then(|| c.clone())
    }

    /// Take `ctx` out
    fn remove(&self, ctx: &Kioctx) {
        let mut t = self.slots.lock();
        if let Some(s) = t.get_mut(ctx.id() as usize)
            && s.as_ref()
                .is_some_and(|c| core::ptr::eq(Arc::as_ptr(c), ctx))
        {
            *s = None;
        }
    }

    /// The ring `ring` moved to `start` (`len` bytes) by mremap, the
    /// mmap_lock held (Linux aio_ring_mremap: the context of this
    /// table whose ring it is, under ioctx_lock): EINVAL if none is
    pub fn ring_moved(&self, ring: &AioRing, start: u64, len: u64) -> KernelResult<()> {
        let t = self.slots.lock();
        let c = t
            .iter()
            .flatten()
            .find(|c| core::ptr::eq(c.ring(), ring))
            .ok_or(KernelError::InvalidArgument)?;
        c.ring_moved(start, len)
    }

    /// Take every context out
    fn take_all(&self) -> impl Iterator<Item = Arc<Kioctx>> {
        // Out under the lock as it is, sifted after (nothing allocates
        // under it)
        let t = core::mem::take(&mut *self.slots.lock());
        t.into_iter().flatten()
    }
}

/// The current address space
fn cur_mm() -> KernelResult<crate::mm::MmRef> {
    crate::task::percpu::current()
        .mm_ref()
        .ok_or(KernelError::InvalidArgument)
}

/// The live context named `ctx_id` (Linux lookup_ioctx: the id read
/// from the ring's header in user memory, the ring at that address)
fn lookup(ctx_id: u64) -> KernelResult<CtxRef> {
    let id = get_user::<u32>(ctx_id + RING_ID as u64).map_err(|_| KernelError::InvalidArgument)?;
    let mm = cur_mm()?;
    let c = mm
        .ioctx()
        .get(id, ctx_id)
        .ok_or(KernelError::InvalidArgument)?;
    CtxRef::get(c).ok_or(KernelError::InvalidArgument)
}

// ============================================================================
// io_setup / io_destroy (Linux ioctx_alloc, kill_ioctx)
// ============================================================================

/// Map `ring` shared into the current address space (Linux
/// aio_setup_ring: do_mmap of the "[aio]" file, VM_DONTCOPY: a child
/// does not inherit it; VM_DONTEXPAND: mremap cannot grow it): its
/// address
fn map_ring(ring: &Arc<AioRing>) -> KernelResult<u64> {
    let file = crate::fs::anon_inodes::anon_inode_getfile(
        "[aio]",
        &AIO_RING_FOPS,
        ring.clone(),
        crate::fs::file::flags::O_RDWR,
    )?;
    use crate::mm::vma::{MAP_SHARED, PROT_READ, PROT_WRITE, VM_DONTCOPY, VM_DONTEXPAND};
    crate::mm::syscall::do_mmap(
        0,
        ring.bytes(),
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        Some(file),
        0,
        VM_DONTCOPY | VM_DONTEXPAND,
    )
    .map_err(|e| match e {
        KernelError::Interrupted => e,
        _ => KernelError::OutOfMemory,
    })
}

/// A context for `nr_events` events (Linux ioctx_alloc): its ring
/// rounded up from twice that (and at least 4 per possible CPU, as Linux
/// sizes for its per-CPU slot caches), mapped, counted in aio-nr, in the
/// table
fn ioctx_alloc(nr_events: u32) -> KernelResult<Arc<Kioctx>> {
    let max_reqs = nr_events;
    // Linux's unsigned arithmetic, wrapping included
    let nr = nr_events
        .max(crate::cpu::nr_cpu_ids().saturating_mul(4))
        .wrapping_mul(2);
    if nr as usize > 0x1000_0000 / EVENT_SIZE {
        return Err(KernelError::InvalidArgument);
    }
    if nr == 0 || u64::from(max_reqs) > AIO_MAX_NR.load(Ordering::Relaxed) {
        return Err(KernelError::WouldBlock);
    }
    let (nr, pages) = ring_size(nr)?;
    let ring = try_arc(AioRing::new(nr, pages)?)?;
    let ctx = Kioctx::new(ring.clone(), max_reqs)?;
    let addr = map_ring(&ring)?;
    ctx.set_user_id(addr);
    let unmap = |e| {
        let _ = crate::mm::syscall::sys_munmap(addr, ring.bytes());
        e
    };
    aio_nr_add(max_reqs).map_err(unmap)?;
    if let Err(e) = cur_mm().and_then(|mm| mm.ioctx().add(&ctx)) {
        aio_nr_sub(max_reqs);
        return Err(unmap(e));
    }
    Ok(ctx)
}

/// Kill `ctx` (Linux kill_ioctx): dead, out of `table`, its sleepers
/// woken, out of aio-nr, its ring unmapped from the current address
/// space if `unmap`; EINVAL if it was dead already
fn kill(table: &IoctxTable, ctx: &Kioctx, unmap: bool) -> KernelResult<()> {
    if !ctx.mark_dead() {
        return Err(KernelError::InvalidArgument);
    }
    table.remove(ctx);
    aio_nr_sub(ctx.max_reqs());
    if unmap {
        let _ = crate::mm::syscall::sys_munmap(ctx.user_id(), ctx.ring().bytes());
    }
    Ok(())
}

/// io_setup(nr_events, ctxp) (Linux sys_io_setup): *ctxp must be 0
/// (EINVAL), as must not nr_events; EAGAIN past aio-max-nr
pub fn sys_io_setup(nr_events: u32, ctxp: UserPtr<u64>) -> KernelResult<i64> {
    let old = get_user::<u64>(ctxp.addr())?;
    if old != 0 || nr_events == 0 {
        return Err(KernelError::InvalidArgument);
    }
    let ctx = ioctx_alloc(nr_events)?;
    if let Err(e) = put_user(ctxp.addr(), ctx.user_id()) {
        let mm = cur_mm()?;
        let _ = kill(mm.ioctx(), &ctx, true);
        ctx.drain();
        return Err(e.into());
    }
    Ok(0)
}

/// io_destroy(ctx) (Linux sys_io_destroy): kill it and wait until every
/// request ended (EINVAL for an unknown or dead context)
pub fn sys_io_destroy(ctx_id: u64) -> KernelResult<i64> {
    let r = lookup(ctx_id)?;
    let ctx = Arc::clone(&r);
    let killed = kill(cur_mm()?.ioctx(), &ctx, true);
    drop(r);
    killed?;
    ctx.drain();
    Ok(0)
}

/// The address space `mm` is torn down (Linux exit_aio, from mmput):
/// kill each context, no unmapping (the mappings go with it), and wait
/// for its requests
pub fn exit_aio(table: &IoctxTable) {
    for ctx in table.take_all() {
        if ctx.mark_dead() {
            aio_nr_sub(ctx.max_reqs());
        }
        ctx.drain();
    }
}

// ============================================================================
// io_submit / io_cancel
// ============================================================================

/// One event slot taken for a request, given back unless it was issued
struct Slot<'a>(&'a Kioctx, bool);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        if !self.1 {
            self.0.put_slots(1);
        }
    }
}

/// The operation of `iocb` at user address `obj` (Linux __io_submit_one)
fn submit_op(ctx: &Arc<Kioctx>, iocb: &Iocb, obj: u64) -> KernelResult<()> {
    let file = crate::fs::io::fget(iocb.aio_fildes as i32)?;
    let eventfd = if iocb.aio_flags & IOCB_FLAG_RESFD != 0 {
        let f = crate::fs::io::fget(iocb.aio_resfd as i32)?;
        Some(crate::io::eventfd::get_eventfd(&f).ok_or(KernelError::InvalidArgument)?)
    } else {
        None
    };
    put_user(obj + IOCB_KEY_OFF, KIOCB_KEY)?;
    let b = Base {
        ctx: ctx.clone(),
        file,
        eventfd,
        data: iocb.aio_data,
        obj,
    };
    match iocb.aio_lio_opcode {
        IOCB_CMD_PREAD => rw::aio_rw(b, iocb, false, false),
        IOCB_CMD_PWRITE => rw::aio_rw(b, iocb, true, false),
        IOCB_CMD_PREADV => rw::aio_rw(b, iocb, false, true),
        IOCB_CMD_PWRITEV => rw::aio_rw(b, iocb, true, true),
        IOCB_CMD_FSYNC => rw::aio_fsync(b, iocb, false),
        IOCB_CMD_FDSYNC => rw::aio_fsync(b, iocb, true),
        IOCB_CMD_POLL => poll::aio_poll(
            b,
            iocb.aio_buf,
            iocb.aio_offset,
            iocb.aio_nbytes,
            iocb.aio_rw_flags,
        ),
        // IOCB_CMD_NOOP included: Linux has no case for it
        _ => Err(KernelError::InvalidArgument),
    }
}

/// Submit the iocb at user address `obj` (Linux io_submit_one): EAGAIN
/// when the ring could not hold its event
fn submit_one(ctx: &Arc<Kioctx>, obj: u64) -> KernelResult<()> {
    let iocb: Iocb = copy_val_from_user(obj)?;
    if iocb.aio_reserved2 != 0 {
        return Err(KernelError::InvalidArgument);
    }
    // aio_buf and aio_nbytes fit a pointer and an ssize_t
    if i64::try_from(iocb.aio_nbytes).is_err() {
        return Err(KernelError::InvalidArgument);
    }
    if !ctx.get_slot() {
        return Err(KernelError::WouldBlock);
    }
    let mut slot = Slot(ctx, false);
    submit_op(ctx, &iocb, obj)?;
    slot.1 = true;
    Ok(())
}

/// Requests from which on io_submit plugs (Linux AIO_PLUG_THRESHOLD)
const AIO_PLUG_THRESHOLD: usize = 2;

/// io_submit(ctx, nr, iocbpp) (Linux sys_io_submit): the iocbs
/// submitted, or the first one's error if none was
pub fn sys_io_submit(ctx_id: u64, nr: i64, iocbpp: u64) -> KernelResult<i64> {
    let nr = usize::try_from(nr).map_err(|_| KernelError::InvalidArgument)?;
    let r = lookup(ctx_id)?;
    let ctx: &Arc<Kioctx> = &r;
    ctx.reap_now();
    let nr = nr.min(ctx.nr_events() as usize);
    let run = || {
        let mut done = 0usize;
        while done < nr {
            let p = iocbpp
                .checked_add(done as u64 * 8)
                .ok_or(KernelError::BadAddress)
                .and_then(|a| get_user::<u64>(a).map_err(KernelError::from));
            if let Err(e) = p.and_then(|obj| submit_one(ctx, obj)) {
                return if done > 0 { Ok(done) } else { Err(e) };
            }
            done += 1;
        }
        Ok(done)
    };
    let n = if nr > AIO_PLUG_THRESHOLD {
        crate::block::plug::blk_plug(run)?
    } else {
        run()?
    };
    Ok(n as i64)
}

/// io_cancel(ctx, iocb, result) (Linux sys_io_cancel): only a request
/// that can be cancelled (IOCB_CMD_POLL) is; its event still comes
/// through the ring, so the answer is EINPROGRESS; EINVAL for any other
pub fn sys_io_cancel(ctx_id: u64, iocb: u64, _result: u64) -> KernelResult<i64> {
    // An iocb at the top of the address space: its aio_key is not user
    // memory (Linux: the pointer wraps and get_user faults)
    let at = iocb
        .checked_add(IOCB_KEY_OFF)
        .ok_or(KernelError::BadAddress)?;
    let key = get_user::<u32>(at)?;
    if key != KIOCB_KEY {
        return Err(KernelError::InvalidArgument);
    }
    let r = lookup(ctx_id)?;
    r.cancel(iocb)?;
    Err(KernelError::InProgress)
}

// ============================================================================
// io_getevents / io_pgetevents
// ============================================================================

/// A relative __kernel_timespec as a CLOCK_MONOTONIC deadline (Linux
/// timespec64_to_ktime, unvalidated: negative is now); 0 stays 0 (no
/// wait)
fn deadline(ts: u64) -> KernelResult<Option<u64>> {
    if ts == 0 {
        return Ok(None);
    }
    let [sec, nsec]: [i64; 2] = copy_val_from_user(ts)?;
    let ns = (i128::from(sec) * 1_000_000_000 + i128::from(nsec)).clamp(0, i128::from(u64::MAX));
    // Lossless after the clamp
    let ns = ns as u64;
    if ns == 0 {
        return Ok(Some(0));
    }
    let now = crate::time::monotonic_ns();
    Ok(Some(crate::time::deadline_after(now, ns).max(1)))
}

/// Linux do_io_getevents
fn do_getevents(
    ctx_id: u64,
    min: i64,
    nr: i64,
    events: u64,
    dl: Option<u64>,
) -> KernelResult<usize> {
    let r = lookup(ctx_id)?;
    if min < 0 || min > nr {
        return Err(KernelError::InvalidArgument);
    }
    // Lossless: 0 <= min <= nr
    let (min, nr) = (min as usize, nr as usize);
    let got = r.read_events(min, nr, events, dl);
    r.reap_now();
    got
}

/// io_getevents(ctx, min_nr, nr, events, timeout) (Linux
/// sys_io_getevents): EINTR if a signal ended it with no event
pub fn sys_io_getevents(ctx_id: u64, min: i64, nr: i64, events: u64, ts: u64) -> KernelResult<i64> {
    let dl = deadline(ts)?;
    let n = do_getevents(ctx_id, min, nr, events, dl)?;
    if n == 0 && crate::sync::waitqueue::signal_pending() {
        return Err(KernelError::Interrupted);
    }
    Ok(n as i64)
}

/// io_pgetevents(ctx, min_nr, nr, events, timeout, usig) (Linux
/// sys_io_pgetevents): as io_getevents under the signal mask `usig`
/// names (a struct __aio_sigset); a signal with no event restarts it
/// unless a handler ran (ERESTARTNOHAND)
pub fn sys_io_pgetevents(
    ctx_id: u64,
    min: i64,
    nr: i64,
    events: u64,
    ts: u64,
    usig: u64,
) -> KernelResult<i64> {
    let dl = deadline(ts)?;
    let sig: AioSigset = if usig != 0 {
        copy_val_from_user(usig)?
    } else {
        AioSigset::default()
    };
    crate::signal::set_user_sigmask(sig.sigmask, sig.sigsetsize)?;
    let r = do_getevents(ctx_id, min, nr, events, dl);
    let interrupted = crate::sync::waitqueue::signal_pending();
    crate::signal::restore_saved_sigmask_unless(interrupted);
    match r {
        Ok(0) | Err(KernelError::RestartSys) if interrupted => Err(KernelError::RestartNoHand),
        r => r.map(|n| n as i64),
    }
}
