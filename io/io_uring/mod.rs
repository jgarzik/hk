//! io_uring (Linux io_uring/io_uring.c, register.c, memmap.c)
//!
//! io_uring_setup makes the rings (`rings::Rings`): the SQ and CQ ring
//! region and the SQE array, mapped by user space at IORING_OFF_SQ_RING
//! (or CQ_RING: one region, IORING_FEAT_SINGLE_MMAP) and IORING_OFF_SQES.
//! io_uring_enter consumes the SQEs user space published (each copied
//! once), runs them, and posts one CQE each (unless
//! IOSQE_CQE_SKIP_SUCCESS); a full CQ keeps CQEs on an overflow list
//! (IORING_FEAT_NODROP, IORING_SQ_CQ_OVERFLOW), moved to the CQ by a
//! later io_uring_enter with IORING_ENTER_GETEVENTS once there is room.
//!
//! ## Locking (doc/LOCKING.md 3.11)
//!
//! - `IoRing.submit` (Linux uring_lock; sleeping Mutex): the kernel's SQ
//!   head, the registered files and the pending list; held across a
//!   whole submission (the operations run under it, so they may sleep)
//!   and across registration. Above `Files` (registering reads the fd
//!   table) and above `IoRing.cq`.
//! - `IoRing.cq` (Linux completion_lock; spin Mutex, thread context): the
//!   kernel's CQ tail and the overflow list; a leaf, but for the
//!   overflow list's (Linux GFP_ATOMIC) allocation. Wakeups come after
//!   it is released.

pub mod abi;
mod ops;
mod rings;
mod rw;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use abi::*;
use rings::Rings;

use crate::fs::KernelError;
use crate::fs::file::{File, FileOps, flags};
use crate::io::pipe::FD_CLOEXEC;
use crate::io::poll::{POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM, PollTable};
use crate::sync::Mutex;
use crate::sync::waitqueue::WaitQueue;
use crate::task::percpu::current;
use crate::uaccess::{UserPtr, copy_from_user, copy_val_from_user};
use crate::util::error::KernelResult;
use crate::util::kalloc::try_arc;
use crate::util::kmem::{KDeque, KVec};

/// Valid SQE flags (Linux SQE_VALID_FLAGS)
const SQE_VALID_FLAGS: u8 = IOSQE_FIXED_FILE
    | IOSQE_IO_DRAIN
    | IOSQE_IO_LINK
    | IOSQE_IO_HARDLINK
    | IOSQE_ASYNC
    | IOSQE_BUFFER_SELECT
    | IOSQE_CQE_SKIP_SUCCESS;

/// Opcodes past Linux's last fail the SQE before it is queued (Linux
/// io_init_req: opcode >= IORING_OP_LAST)
const IORING_OP_LAST: u8 = 64;

/// What io_uring_setup reports (Linux IORING_FEAT_FLAGS, as far as hk
/// has them)
const FEATURES: u32 = IORING_FEAT_SINGLE_MMAP
    | IORING_FEAT_NODROP
    | IORING_FEAT_SUBMIT_STABLE
    | IORING_FEAT_RW_CUR_POS
    | IORING_FEAT_CUR_PERSONALITY
    | IORING_FEAT_CQE_SKIP;

/// Setup flags hk implements
const SETUP_FLAGS: u32 = IORING_SETUP_CQSIZE | IORING_SETUP_CLAMP;

/// io_uring_enter flags hk accepts; SQ_WAKEUP and SQ_WAIT do nothing on
/// a ring without SQPOLL (Linux)
const ENTER_FLAGS: u32 = IORING_ENTER_GETEVENTS | IORING_ENTER_SQ_WAKEUP | IORING_ENTER_SQ_WAIT;

/// The submission side, under `IoRing.submit` (Linux uring_lock)
pub struct Submit {
    /// SQ entries consumed (Linux cached_sq_head)
    sq_head: u32,
    /// Registered files
    files: Option<Vec<Option<Arc<File>>>>,
    /// user_data of poll and timeout requests noted but never completed
    pending: KVec<u64>,
}

/// The completion side, under `IoRing.cq` (Linux completion_lock)
struct Cq {
    /// CQEs posted (Linux cached_cq_tail)
    tail: u32,
    /// CQEs waiting for room (Linux cq_overflow_list)
    overflow: KDeque<IoUringCqe>,
}

/// One io_uring (Linux io_ring_ctx)
pub struct IoRing {
    rings: Rings,
    submit: Mutex<Submit>,
    cq: crate::sync::spin::Mutex<Cq>,
    /// `cq.overflow` holds CQEs (Linux IO_CHECK_CQ_OVERFLOW_BIT): set and
    /// cleared under `cq`, read lock-free by poll and GETEVENTS to skip
    /// the lock when nothing waits
    overflowed: AtomicBool,
    /// Pollers of the ring fd (Linux poll_wq)
    wq: WaitQueue,
}

/// The SQEs' link state across one submission: chains run in order,
/// and a failed member cancels the rest of its chain (Linux
/// IOSQE_IO_LINK; a hard link keeps going)
#[derive(Default)]
struct Link {
    /// Inside a chain
    on: bool,
    /// A member of this chain failed
    failed: bool,
}

impl IoRing {
    fn new(sq: u32, cq: u32) -> KernelResult<Arc<Self>> {
        try_arc(Self {
            rings: Rings::new(sq, cq)?,
            submit: Mutex::new(Submit {
                sq_head: 0,
                files: None,
                pending: KVec::new(),
            }),
            cq: crate::sync::spin::Mutex::new(Cq {
                tail: 0,
                overflow: KDeque::new(),
            }),
            overflowed: AtomicBool::new(false),
            wq: WaitQueue::new(),
        })
    }

    /// Consume up to `nr` published SQEs and run them (Linux
    /// io_submit_sqes): the number consumed. An SQ array slot naming no
    /// SQE is dropped (sq_dropped) and ends the batch; so does an SQE
    /// that fails before it runs, counted.
    fn submit(&self, nr: u32) -> u32 {
        let mut s = self.submit.lock();
        let ready = self.rings.sq_tail().wrapping_sub(s.sq_head);
        let n = nr.min(ready.min(self.rings.sq_entries()));
        let mut link = Link::default();
        let mut done = 0;
        for _ in 0..n {
            let slot = s.sq_head;
            s.sq_head = slot.wrapping_add(1);
            let i = self.rings.sq_index(slot);
            if i >= self.rings.sq_entries() {
                self.rings.inc_dropped();
                break;
            }
            let sqe = self.rings.sqe(i);
            done += 1;
            if !self.submit_sqe(&mut s, &sqe, &mut link) {
                break;
            }
        }
        // The SQEs are copied: their slots are user space's again
        self.rings.set_sq_head(s.sq_head);
        done
    }

    /// Run one SQE and post its CQE: false if it failed before running
    /// (Linux io_init_req), which ends the batch
    fn submit_sqe(&self, s: &mut Submit, sqe: &IoUringSqe, link: &mut Link) -> bool {
        let linked = sqe.flags & (IOSQE_IO_LINK | IOSQE_IO_HARDLINK) != 0;
        let hard = sqe.flags & IOSQE_IO_HARDLINK != 0;
        let init = init_check(sqe);
        let res = match init {
            Err(e) => Err(e),
            Ok(()) if link.failed && link.on => Err(KernelError::Canceled),
            Ok(()) => self.issue(s, sqe, link.on),
        };
        let res = res.unwrap_or_else(KernelError::to_errno_neg);
        if res < 0 && (linked || link.on) && !hard {
            link.failed = true;
        }
        if linked {
            link.on = true;
        } else {
            *link = Link::default();
        }
        if sqe.flags & IOSQE_CQE_SKIP_SUCCESS == 0 || res < 0 {
            self.post_cqe(sqe.user_data, res, 0);
        }
        init.is_ok()
    }

    /// Run the operation of `sqe` (`in_link`: a later member of a chain)
    fn issue(&self, s: &mut Submit, sqe: &IoUringSqe, in_link: bool) -> KernelResult<i32> {
        match sqe.opcode {
            IORING_OP_READ => rw::rw(self, s, sqe, false),
            IORING_OP_WRITE => rw::rw(self, s, sqe, true),
            IORING_OP_READV => rw::rwv(self, s, sqe, false),
            IORING_OP_WRITEV => rw::rwv(self, s, sqe, true),
            // Valid only inside a chain; it arms nothing (BUGS "io_uring
            // gaps")
            IORING_OP_LINK_TIMEOUT if in_link => Ok(0),
            IORING_OP_LINK_TIMEOUT => Err(KernelError::InvalidArgument),
            _ => ops::issue(self, s, sqe).unwrap_or(Err(KernelError::InvalidArgument)),
        }
    }

    /// The SQE's file: a registered one with IOSQE_FIXED_FILE, else its
    /// fd's; EBADF
    fn sqe_file(&self, s: &Submit, sqe: &IoUringSqe) -> KernelResult<Arc<File>> {
        if sqe.flags & IOSQE_FIXED_FILE != 0 {
            let fixed = s.files.as_ref().and_then(|f| f.get(sqe.fd as u32 as usize));
            return fixed.cloned().flatten().ok_or(KernelError::BadFd);
        }
        crate::fs::io::fget(sqe.fd).map_err(|_| KernelError::BadFd)
    }

    /// Post a CQE (Linux io_post_aux_cqe / io_req_complete_post): into
    /// the CQ if it has room and nothing overflowed before, else onto the
    /// overflow list; if even that cannot grow, it is lost and counted
    /// (cq_overflow)
    pub fn post_cqe(&self, user_data: u64, res: i32, flags: u32) {
        let cqe = IoUringCqe {
            user_data,
            res,
            flags,
        };
        {
            let mut cq = self.cq.lock();
            if cq.overflow.is_empty() && self.cq_room(cq.tail) {
                self.rings.write_cqe(cq.tail, cqe);
                cq.tail = cq.tail.wrapping_add(1);
                self.rings.set_cq_tail(cq.tail);
            } else {
                self.overflow(&mut cq, cqe);
            }
        }
        self.wq.wake_poll(u32::from(POLLIN | POLLRDNORM));
    }

    /// The CQ has room past `tail`
    fn cq_room(&self, tail: u32) -> bool {
        tail.wrapping_sub(self.rings.cq_head()) < self.rings.cq_entries()
    }

    /// Keep `cqe` until there is room (Linux io_cqring_event_overflow)
    fn overflow(&self, cq: &mut Cq, cqe: IoUringCqe) {
        if cq.overflow.try_push_back(cqe).is_err() {
            self.rings.inc_cq_overflow();
            return;
        }
        if cq.overflow.len() == 1 {
            self.overflowed.store(true, Ordering::Release);
            self.rings.sq_flags(IORING_SQ_CQ_OVERFLOW, true);
        }
    }

    /// Move overflowed CQEs into the CQ while it has room (Linux
    /// __io_cqring_overflow_flush)
    fn flush_overflow(&self) {
        if !self.overflowed.load(Ordering::Acquire) {
            return;
        }
        let mut cq = self.cq.lock();
        let start = cq.tail;
        while let Some(&cqe) = cq.overflow.front() {
            if !self.cq_room(cq.tail) {
                break;
            }
            self.rings.write_cqe(cq.tail, cqe);
            cq.tail = cq.tail.wrapping_add(1);
            cq.overflow.pop_front();
        }
        if cq.tail != start {
            self.rings.set_cq_tail(cq.tail);
        }
        if cq.overflow.is_empty() {
            self.overflowed.store(false, Ordering::Release);
            self.rings.sq_flags(IORING_SQ_CQ_OVERFLOW, false);
        }
    }

    /// CQEs user space has not consumed, or overflowed ones wait
    fn cq_ready(&self) -> bool {
        self.rings.cq_tail() != self.rings.cq_head() || self.overflowed.load(Ordering::Acquire)
    }

    /// Register files for fixed file access (Linux
    /// io_sqe_files_register): EBUSY if some are
    fn register_files(&self, fds: &[i32]) -> KernelResult<()> {
        // Reserved before any lock: no allocation under the fd table's
        let mut files = KVec::try_with_capacity(fds.len())?;
        let fd_table = current().files().ok_or(KernelError::BadFd)?;
        let mut s = self.submit.lock();
        if s.files.is_some() {
            return Err(KernelError::Busy);
        }
        {
            let t = fd_table.lock();
            for &fd in fds {
                let slot = if fd == -1 {
                    None
                } else {
                    Some(reg_file(t.get(fd))?)
                };
                // Capacity is reserved; this cannot fail
                let _ = files.try_push(slot);
            }
        }
        s.files = Some(files.into_vec());
        Ok(())
    }

    /// Drop the registered files (ENXIO if none, Linux
    /// io_sqe_files_unregister); released after the lock
    fn unregister_files(&self) -> KernelResult<()> {
        let old = self.submit.lock().files.take();
        old.map(drop).ok_or(KernelError::NoDeviceOrAddress)
    }

    /// Replace registered files from `offset` on (-1 empties a slot):
    /// the number updated (Linux __io_sqe_files_update)
    fn update_files(&self, offset: u32, fds: &[i32]) -> KernelResult<usize> {
        // The replaced files are released after both locks
        let mut old = KVec::try_with_capacity(fds.len())?;
        let fd_table = current().files().ok_or(KernelError::BadFd)?;
        let mut s = self.submit.lock();
        let reg = s.files.as_mut().ok_or(KernelError::NoDeviceOrAddress)?;
        let offset = offset as usize;
        if offset.checked_add(fds.len()).is_none_or(|e| e > reg.len()) {
            return Err(KernelError::InvalidArgument);
        }
        let t = fd_table.lock();
        for (i, &fd) in fds.iter().enumerate() {
            let new = if fd == -1 {
                None
            } else {
                Some(reg_file(t.get(fd))?)
            };
            // Capacity is reserved; this cannot fail
            let _ = old.try_push(core::mem::replace(&mut reg[offset + i], new));
        }
        drop(t);
        drop(s);
        drop(old);
        Ok(fds.len())
    }

    /// The SQ head user space sees (the kernel's last published one)
    fn sq_head(&self) -> u32 {
        self.rings.sq_head()
    }
}

/// The checks an SQE fails before it is queued (Linux io_init_req):
/// an opcode past the last, unknown SQE flags, a personality (none can
/// be registered)
fn init_check(sqe: &IoUringSqe) -> KernelResult<()> {
    if sqe.opcode >= IORING_OP_LAST || sqe.flags & !SQE_VALID_FLAGS != 0 || sqe.personality != 0 {
        return Err(KernelError::InvalidArgument);
    }
    Ok(())
}

// ============================================================================
// The io_uring file
// ============================================================================

/// File operations of an io_uring fd (Linux io_uring_fops)
pub struct IoUringFileOps;

static IO_URING_FOPS: IoUringFileOps = IoUringFileOps;

impl FileOps for IoUringFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    /// Readable with CQEs to reap (or overflowed ones), writable while
    /// the SQ has room (Linux io_uring_poll)
    fn poll(&self, file: &File, pt: Option<&mut PollTable<'_>>) -> u16 {
        let Some(r) = file.private_ref::<IoRing>() else {
            return crate::io::poll::POLLERR;
        };
        if let Some(pt) = pt {
            pt.poll_wait(&r.wq);
        }
        let mut mask = 0;
        if r.rings.sq_tail().wrapping_sub(r.sq_head()) != r.rings.sq_entries() {
            mask |= POLLOUT | POLLWRNORM;
        }
        if r.cq_ready() {
            mask |= POLLIN | POLLRDNORM;
        }
        mask
    }

    /// The rings map, shared or private (Linux io_uring_mmap)
    fn mmap(&self, _file: &File, _shared: bool) -> Result<(), KernelError> {
        Ok(())
    }

    /// At IORING_OFF_SQ_RING, CQ_RING or SQES only (Linux
    /// io_uring_validate_mmap_request)
    fn mmap_offset(&self, file: &File, off: u64) -> Result<(), KernelError> {
        let r = file.private_ref::<IoRing>().ok_or(KernelError::BadFd)?;
        r.rings
            .region(off & IORING_OFF_MMAP_MASK)
            .map(|_| ())
            .ok_or(KernelError::InvalidArgument)
    }

    /// Page `idx` of the region the mapping's offset selects, whatever
    /// the offset's low bits (Linux io_region_mmap: vm_insert_pages from
    /// the region's first page); past the region SIGBUS
    fn map_page(&self, file: &File, off: u64, idx: u64) -> Option<Result<u64, KernelError>> {
        let r = file.private_ref::<IoRing>()?;
        let region = r.rings.region(off & IORING_OFF_MMAP_MASK)?;
        Some(region.map_page(idx).ok_or(KernelError::BadAddress))
    }
}

/// The io_uring behind `file`
pub fn get_io_uring(file: &File) -> Option<Arc<IoRing>> {
    file.private_arc::<IoRing>()
}

/// Copy an `int fds[n]` array from user space (EMFILE over
/// IORING_MAX_FIXED_FILES, as Linux io_sqe_files_register)
fn read_user_fds(arg: u64, n: usize) -> Result<Vec<i32>, KernelError> {
    /// Most registered files (Linux IORING_MAX_FIXED_FILES)
    const IORING_MAX_FIXED_FILES: usize = 1 << 15;
    if n > IORING_MAX_FIXED_FILES {
        return Err(KernelError::ProcessFileLimit);
    }
    let mut fds = crate::util::kmem::try_vec(n, 0i32)?;
    copy_from_user(crate::util::pod::slice_bytes_mut(&mut fds), arg, n * 4)?;
    Ok(fds)
}

/// A file to register: none, or a path-only one, is EBADF (Linux
/// io_sqe_files_register: fget)
fn reg_file(f: Option<Arc<File>>) -> KernelResult<Arc<File>> {
    f.filter(|f| !f.is_path()).ok_or(KernelError::BadFd)
}

// ============================================================================
// Syscalls
// ============================================================================

/// The SQ and CQ sizes for `entries` and `p` (Linux io_uring_fill_params):
/// powers of two, the CQ twice the SQ unless IORING_SETUP_CQSIZE; past
/// the limits EINVAL, or the limit with IORING_SETUP_CLAMP
fn ring_sizes(entries: u32, p: &IoUringParams) -> KernelResult<(u32, u32)> {
    let clamp = p.flags & IORING_SETUP_CLAMP != 0;
    let fit = |n: u32, max: u32| match n {
        0 => Err(KernelError::InvalidArgument),
        n if n > max && !clamp => Err(KernelError::InvalidArgument),
        n => Ok(n.min(max).next_power_of_two()),
    };
    let sq = fit(entries, IORING_MAX_ENTRIES)?;
    if p.flags & IORING_SETUP_CQSIZE == 0 {
        return Ok((sq, 2 * sq));
    }
    let cq = fit(p.cq_entries, IORING_MAX_CQ_ENTRIES)?;
    if cq < sq {
        return Err(KernelError::InvalidArgument);
    }
    Ok((sq, cq))
}

/// io_uring_setup(entries, params): a new io_uring's fd, its sizes,
/// features and ring offsets written to `params` (Linux io_uring_setup)
pub fn sys_io_uring_setup(entries: u32, params_ptr: UserPtr<IoUringParams>) -> KernelResult<i32> {
    let mut p = params_ptr.read()?;
    if p.resv.iter().any(|&r| r != 0) || p.flags & !SETUP_FLAGS != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let (sq, cq) = ring_sizes(entries, &p)?;
    let ring = IoRing::new(sq, cq)?;
    p.sq_entries = sq;
    p.cq_entries = cq;
    p.features = FEATURES;
    (p.sq_off, p.cq_off) = ring.rings.offsets();
    params_ptr.write(&p)?;
    let file = crate::fs::anon_inodes::anon_inode_getfile(
        "[io_uring]",
        &IO_URING_FOPS,
        ring,
        flags::O_RDWR,
    )?;
    crate::fs::io::fd_install(file, FD_CLOEXEC)
}

/// io_uring_enter(fd, to_submit, min_complete, flags, argp, argsz):
/// consume up to `to_submit` SQEs, the number consumed (Linux
/// io_uring_enter); with IORING_ENTER_GETEVENTS, after a full
/// submission, overflowed CQEs move into the CQ
pub fn sys_io_uring_enter(
    fd: u32,
    to_submit: u32,
    _min_complete: u32,
    flags: u32,
    _argp: u64,
    _argsz: usize,
) -> KernelResult<u32> {
    if flags & !ENTER_FLAGS != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let ring = ring_of(fd)?;
    let mut ret = 0;
    if to_submit > 0 {
        ret = ring.submit(to_submit);
        if ret != to_submit {
            return Ok(ret);
        }
    }
    if flags & IORING_ENTER_GETEVENTS != 0 {
        ring.flush_overflow();
    }
    Ok(ret)
}

/// The io_uring open at `fd`: EBADF for no file, EOPNOTSUPP for another
/// kind (Linux io_uring_ctx_get_file)
fn ring_of(fd: u32) -> KernelResult<Arc<IoRing>> {
    let file = crate::fs::io::fget(fd as i32)?;
    get_io_uring(&file).ok_or(KernelError::OperationNotSupported)
}

/// struct io_uring_files_update
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FilesUpdate {
    offset: u32,
    resv: u32,
    fds: u64,
}
crate::pod!(FilesUpdate { offset, resv, fds });

/// io_uring_register(fd, opcode, arg, nr_args) (Linux
/// __io_uring_register): 0, or the number updated for
/// IORING_REGISTER_FILES_UPDATE
pub fn sys_io_uring_register(fd: u32, opcode: u32, arg: u64, nr_args: u32) -> KernelResult<usize> {
    let ring = ring_of(fd)?;
    match opcode {
        IORING_REGISTER_FILES => {
            if nr_args == 0 {
                return Err(KernelError::InvalidArgument);
            }
            let fds = read_user_fds(arg, nr_args as usize)?;
            ring.register_files(&fds).map(|()| 0)
        }
        IORING_UNREGISTER_FILES if arg == 0 && nr_args == 0 => ring.unregister_files().map(|()| 0),
        IORING_UNREGISTER_FILES => Err(KernelError::InvalidArgument),
        // Not implemented yet
        IORING_REGISTER_BUFFERS
        | IORING_UNREGISTER_BUFFERS
        | IORING_REGISTER_EVENTFD
        | IORING_UNREGISTER_EVENTFD => Err(KernelError::OperationNotSupported),
        IORING_REGISTER_FILES_UPDATE => {
            if nr_args == 0 {
                return Err(KernelError::InvalidArgument);
            }
            let up: FilesUpdate = copy_val_from_user(arg)?;
            if up.resv != 0 {
                return Err(KernelError::InvalidArgument);
            }
            let fds = read_user_fds(up.fds, nr_args as usize)?;
            ring.update_files(up.offset, &fds)
        }
        _ => Err(KernelError::InvalidArgument),
    }
}
