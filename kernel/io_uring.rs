//! io_uring - Linux's high-performance async I/O interface
//!
//! io_uring provides a mechanism for async I/O operations using shared memory
//! ring buffers between kernel and userspace.
//!
//! ## Architecture
//!
//! ```text
//! User Process                         Kernel
//!     |                                   |
//!     v                                   |
//! io_uring_setup(entries, params)         |
//!     |----------------------------->     |
//!     |  Returns fd + ring offsets        |
//!     |<-----------------------------     |
//!     |                                   |
//! mmap(fd, IORING_OFF_SQ_RING)           |
//! mmap(fd, IORING_OFF_SQES)              |
//!     |  Creates shared memory rings      |
//!     |                                   |
//!     v                                   |
//! Write SQEs to ring                     |
//! Update SQ tail                         |
//!     |                                   |
//! io_uring_enter(fd, to_submit, ...)     |
//!     |----------------------------->     |
//!     |  Kernel processes SQEs            |
//!     |  Posts CQEs                       |
//!     |<-----------------------------     |
//!     |                                   |
//! Read CQEs from ring                    |
//! Update CQ head                         |
//! ```
//!
//! ## Key Features
//!
//! - Zero-copy I/O through shared memory rings
//! - Batched submissions and completions
//! - Optional kernel-side polling (SQPOLL)
//! - Registered buffers and files for performance

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::arch::{IrqSpinlock, Uaccess};
use crate::fs::KernelError;
use crate::fs::dentry::Dentry;
use crate::fs::file::{File, FileOps, flags};
use crate::fs::inode::{Inode, InodeMode, NULL_INODE_OPS, Timespec as InodeTimespec};
use crate::mm::PAGE_SIZE;
use crate::pipe::FD_CLOEXEC;
use crate::poll::PollTable;
use crate::task::fdtable::get_task_fd;
use crate::task::percpu::current_tid;
use crate::uaccess::{get_user, put_user};
use crate::waitqueue::WaitQueue;

// ============================================================================
// io_uring constants
// ============================================================================

/// mmap offsets for ring buffers
pub const IORING_OFF_SQ_RING: u64 = 0;
pub const IORING_OFF_CQ_RING: u64 = 0x8000000;
pub const IORING_OFF_SQES: u64 = 0x10000000;

/// io_uring_setup flags
pub const IORING_SETUP_IOPOLL: u32 = 1 << 0;
pub const IORING_SETUP_SQPOLL: u32 = 1 << 1;
pub const IORING_SETUP_SQ_AFF: u32 = 1 << 2;
pub const IORING_SETUP_CQSIZE: u32 = 1 << 3;
pub const IORING_SETUP_CLAMP: u32 = 1 << 4;
pub const IORING_SETUP_ATTACH_WQ: u32 = 1 << 5;
pub const IORING_SETUP_R_DISABLED: u32 = 1 << 6;

/// io_uring_enter flags
pub const IORING_ENTER_GETEVENTS: u32 = 1 << 0;
pub const IORING_ENTER_SQ_WAKEUP: u32 = 1 << 1;
pub const IORING_ENTER_SQ_WAIT: u32 = 1 << 2;
pub const IORING_ENTER_EXT_ARG: u32 = 1 << 3;

/// SQE flags
pub const IOSQE_FIXED_FILE: u8 = 1 << 0;
pub const IOSQE_IO_DRAIN: u8 = 1 << 1;
pub const IOSQE_IO_LINK: u8 = 1 << 2;
pub const IOSQE_IO_HARDLINK: u8 = 1 << 3;
pub const IOSQE_ASYNC: u8 = 1 << 4;
pub const IOSQE_BUFFER_SELECT: u8 = 1 << 5;
pub const IOSQE_CQE_SKIP_SUCCESS: u8 = 1 << 6;

/// CQE flags
pub const IORING_CQE_F_BUFFER: u32 = 1 << 0;
pub const IORING_CQE_F_MORE: u32 = 1 << 1;

/// SQ ring flags
pub const IORING_SQ_NEED_WAKEUP: u32 = 1 << 0;
pub const IORING_SQ_CQ_OVERFLOW: u32 = 1 << 1;

/// CQ ring flags
pub const IORING_CQ_EVENTFD_DISABLED: u32 = 1 << 0;

/// Feature flags (returned in params.features)
pub const IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;
pub const IORING_FEAT_NODROP: u32 = 1 << 1;
pub const IORING_FEAT_SUBMIT_STABLE: u32 = 1 << 2;
pub const IORING_FEAT_RW_CUR_POS: u32 = 1 << 3;
pub const IORING_FEAT_CUR_PERSONALITY: u32 = 1 << 4;
pub const IORING_FEAT_FAST_POLL: u32 = 1 << 5;
pub const IORING_FEAT_POLL_32BITS: u32 = 1 << 6;

/// Operation codes
pub const IORING_OP_NOP: u8 = 0;
pub const IORING_OP_READV: u8 = 1;
pub const IORING_OP_WRITEV: u8 = 2;
pub const IORING_OP_FSYNC: u8 = 3;
pub const IORING_OP_READ_FIXED: u8 = 4;
pub const IORING_OP_WRITE_FIXED: u8 = 5;
pub const IORING_OP_POLL_ADD: u8 = 6;
pub const IORING_OP_POLL_REMOVE: u8 = 7;
pub const IORING_OP_SYNC_FILE_RANGE: u8 = 8;
pub const IORING_OP_SENDMSG: u8 = 9;
pub const IORING_OP_RECVMSG: u8 = 10;
pub const IORING_OP_TIMEOUT: u8 = 11;
pub const IORING_OP_TIMEOUT_REMOVE: u8 = 12;
pub const IORING_OP_ACCEPT: u8 = 13;
pub const IORING_OP_ASYNC_CANCEL: u8 = 14;
pub const IORING_OP_LINK_TIMEOUT: u8 = 15;
pub const IORING_OP_CONNECT: u8 = 16;
pub const IORING_OP_FALLOCATE: u8 = 17;
pub const IORING_OP_OPENAT: u8 = 18;
pub const IORING_OP_CLOSE: u8 = 19;
pub const IORING_OP_FILES_UPDATE: u8 = 20;
pub const IORING_OP_STATX: u8 = 21;
pub const IORING_OP_READ: u8 = 22;
pub const IORING_OP_WRITE: u8 = 23;
pub const IORING_OP_FADVISE: u8 = 24;
pub const IORING_OP_MADVISE: u8 = 25;
pub const IORING_OP_SEND: u8 = 26;
pub const IORING_OP_RECV: u8 = 27;
pub const IORING_OP_OPENAT2: u8 = 28;
pub const IORING_OP_EPOLL_CTL: u8 = 29;
pub const IORING_OP_SPLICE: u8 = 30;
pub const IORING_OP_PROVIDE_BUFFERS: u8 = 31;
pub const IORING_OP_REMOVE_BUFFERS: u8 = 32;
pub const IORING_OP_TEE: u8 = 33;
pub const IORING_OP_SHUTDOWN: u8 = 34;
pub const IORING_OP_RENAMEAT: u8 = 35;
pub const IORING_OP_UNLINKAT: u8 = 36;
pub const IORING_OP_MKDIRAT: u8 = 37;
pub const IORING_OP_SYMLINKAT: u8 = 38;
pub const IORING_OP_LINKAT: u8 = 39;
pub const IORING_OP_FSETXATTR: u8 = 40;
pub const IORING_OP_SETXATTR: u8 = 41;
pub const IORING_OP_FGETXATTR: u8 = 42;
pub const IORING_OP_GETXATTR: u8 = 43;
pub const IORING_OP_SOCKET: u8 = 44;
pub const IORING_OP_URING_CMD: u8 = 45;
pub const IORING_OP_FTRUNCATE: u8 = 46;

/// FSYNC flags (for op_flags in IORING_OP_FSYNC)
pub const IORING_FSYNC_DATASYNC: u32 = 1 << 0;

/// io_uring_register opcodes
pub const IORING_REGISTER_BUFFERS: u32 = 0;
pub const IORING_UNREGISTER_BUFFERS: u32 = 1;
pub const IORING_REGISTER_FILES: u32 = 2;
pub const IORING_UNREGISTER_FILES: u32 = 3;
pub const IORING_REGISTER_EVENTFD: u32 = 4;
pub const IORING_UNREGISTER_EVENTFD: u32 = 5;
pub const IORING_REGISTER_FILES_UPDATE: u32 = 6;

/// Maximum ring size
const IORING_MAX_ENTRIES: u32 = 32768;

/// Minimum ring size (used for validation)
#[allow(dead_code)] // Used in future phases
const IORING_MIN_ENTRIES: u32 = 1;

// ============================================================================
// io_uring data structures (Linux ABI compatible)
// ============================================================================

/// SQ ring offsets (returned in io_uring_params)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SqRingOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub flags: u32,
    pub dropped: u32,
    pub array: u32,
    pub resv1: u32,
    pub user_addr: u64,
}

/// CQ ring offsets (returned in io_uring_params)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CqRingOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub overflow: u32,
    pub cqes: u32,
    pub flags: u32,
    pub resv1: u32,
    pub user_addr: u64,
}

/// io_uring_params structure passed to io_uring_setup (248 bytes)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IoUringParams {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    pub features: u32,
    pub wq_fd: u32,
    pub resv: [u32; 3],
    pub sq_off: SqRingOffsets,
    pub cq_off: CqRingOffsets,
}

/// Submission queue entry (64 bytes)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IoUringSqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off: u64,       // offset or addr2
    pub addr: u64,      // buffer address or splice offset
    pub len: u32,       // buffer length
    pub op_flags: u32,  // operation-specific flags
    pub user_data: u64, // data passed back in CQE
    pub buf_index: u16, // fixed buffer index or buffer group
    pub personality: u16,
    pub splice_fd_in: i32,
    pub __pad2: [u64; 2],
}

/// Completion queue entry (16 bytes)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IoUringCqe {
    pub user_data: u64, // from corresponding SQE
    pub res: i32,       // result code
    pub flags: u32,     // completion flags
}

/// Ring memory layout for SQ (used when mmap support is implemented)
#[repr(C)]
#[allow(dead_code)] // Used for mmap in future phases
struct SqRing {
    head: AtomicU32,
    tail: AtomicU32,
    ring_mask: u32,
    ring_entries: u32,
    flags: AtomicU32,
    dropped: AtomicU32,
    // array follows (u32 indices into SQE array)
}

/// Ring memory layout for CQ (used when mmap support is implemented)
#[repr(C)]
#[allow(dead_code)] // Used for mmap in future phases
struct CqRing {
    head: AtomicU32,
    tail: AtomicU32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: AtomicU32,
    // CQEs follow
}

// ============================================================================
// io_uring implementation
// ============================================================================

/// Pending operation types for async operations
#[derive(Clone, Copy, Debug, PartialEq)]
enum PendingOpType {
    Poll { fd: i32, events: u32 },
    Timeout { deadline_ns: u64 },
}

/// Pending operation that hasn't completed yet
struct PendingOp {
    user_data: u64,
    #[allow(dead_code)] // Used for async completion handling
    op_type: PendingOpType,
    cancelled: bool,
}

/// Inner state protected by spinlock
struct IoUringInner {
    /// Ring parameters
    sq_entries: u32,
    cq_entries: u32,
    sq_mask: u32,
    cq_mask: u32,

    /// Kernel's view of ring head/tail
    sq_head: u32,
    cq_tail: u32,

    /// Ring memory (kernel-side copy for processing)
    sq_array: Vec<u32>,
    sqes: Vec<IoUringSqe>,
    cqes: Vec<IoUringCqe>,

    /// Overflow count
    cq_overflow: u32,

    /// Dropped SQE count
    sq_dropped: u32,

    /// Registered files (Phase 4)
    registered_files: Option<Vec<Option<Arc<File>>>>,

    /// Pending operations (Phase 5)
    pending_ops: Vec<PendingOp>,

    /// Next pending op ID counter
    next_pending_id: u64,
}

impl IoUringInner {
    fn new(sq_entries: u32, cq_entries: u32) -> Self {
        let sq_mask = sq_entries - 1;
        let cq_mask = cq_entries - 1;

        Self {
            sq_entries,
            cq_entries,
            sq_mask,
            cq_mask,
            sq_head: 0,
            cq_tail: 0,
            sq_array: alloc::vec![0u32; sq_entries as usize],
            sqes: alloc::vec![IoUringSqe::default(); sq_entries as usize],
            cqes: alloc::vec![IoUringCqe::default(); cq_entries as usize],
            cq_overflow: 0,
            sq_dropped: 0,
            registered_files: None,
            pending_ops: Vec::new(),
            next_pending_id: 0,
        }
    }

    /// Post a completion queue entry
    fn post_cqe(&mut self, user_data: u64, res: i32, cqe_flags: u32) -> bool {
        let cq_head = 0u32; // TODO: Read from shared memory
        let cq_next = self.cq_tail.wrapping_add(1);

        // Check for overflow
        if cq_next.wrapping_sub(cq_head) > self.cq_entries {
            self.cq_overflow += 1;
            return false;
        }

        let index = (self.cq_tail & self.cq_mask) as usize;
        self.cqes[index] = IoUringCqe {
            user_data,
            res,
            flags: cqe_flags,
        };
        self.cq_tail = cq_next;
        true
    }

    /// Add a pending operation
    fn add_pending(&mut self, user_data: u64, op_type: PendingOpType) {
        self.pending_ops.push(PendingOp {
            user_data,
            op_type,
            cancelled: false,
        });
        self.next_pending_id += 1;
    }

    /// Cancel a pending operation by user_data
    fn cancel_pending(&mut self, user_data: u64) -> bool {
        for op in &mut self.pending_ops {
            if op.user_data == user_data && !op.cancelled {
                op.cancelled = true;
                return true;
            }
        }
        false
    }

    /// Remove cancelled operations and return their user_data
    fn drain_cancelled(&mut self) -> Vec<u64> {
        let mut cancelled = Vec::new();
        self.pending_ops.retain(|op| {
            if op.cancelled {
                cancelled.push(op.user_data);
                false
            } else {
                true
            }
        });
        cancelled
    }

    /// Find and remove a pending poll by fd
    #[allow(dead_code)] // Will be used for poll completion
    fn find_poll_by_fd(&mut self, fd: i32) -> Option<u64> {
        let mut found_idx = None;
        for (i, op) in self.pending_ops.iter().enumerate() {
            if let PendingOpType::Poll { fd: poll_fd, .. } = op.op_type
                && poll_fd == fd
                && !op.cancelled
            {
                found_idx = Some(i);
                break;
            }
        }
        found_idx.map(|i| {
            let op = self.pending_ops.remove(i);
            op.user_data
        })
    }
}

/// Main io_uring instance
pub struct IoUring {
    /// Inner state protected by spinlock
    inner: IrqSpinlock<IoUringInner>,

    /// Wait queue for blocking waits
    wq: WaitQueue,

    /// Unique ID
    id: u64,

    /// Ring sizes (immutable after creation, used for mmap)
    #[allow(dead_code)] // Used for mmap in future
    sq_entries: u32,
    #[allow(dead_code)] // Used for mmap in future
    cq_entries: u32,

    /// Physical addresses for mmap (set during setup)
    rings_size: usize,
    sqes_size: usize,
}

/// Global counter for io_uring IDs
static NEXT_IOURING_ID: AtomicU64 = AtomicU64::new(1);

/// Global io_uring registry
static IOURING_REGISTRY: IrqSpinlock<Vec<(u64, Weak<IoUring>)>> = IrqSpinlock::new(Vec::new());

impl IoUring {
    /// Create a new io_uring instance
    pub fn new(sq_entries: u32, cq_entries: u32) -> Arc<Self> {
        let id = NEXT_IOURING_ID.fetch_add(1, Ordering::Relaxed);

        // Calculate memory sizes
        let rings_size = Self::calc_rings_size(sq_entries, cq_entries);
        let sqes_size = (sq_entries as usize) * core::mem::size_of::<IoUringSqe>();

        let ring = Arc::new(Self {
            inner: IrqSpinlock::new(IoUringInner::new(sq_entries, cq_entries)),
            wq: WaitQueue::new(),
            id,
            sq_entries,
            cq_entries,
            rings_size,
            sqes_size,
        });

        // Register in global registry
        let weak = Arc::downgrade(&ring);
        IOURING_REGISTRY.lock().push((id, weak));

        ring
    }

    /// Calculate total ring buffer size
    fn calc_rings_size(sq_entries: u32, cq_entries: u32) -> usize {
        // SQ ring: head, tail, mask, entries, flags, dropped + array
        let sq_ring_size = 6 * 4 + (sq_entries as usize) * 4;
        // CQ ring: head, tail, mask, entries, overflow, flags + CQEs
        let cq_ring_size = 6 * 4 + (cq_entries as usize) * core::mem::size_of::<IoUringCqe>();

        // Round up to page size
        (sq_ring_size + cq_ring_size).div_ceil(PAGE_SIZE as usize) * PAGE_SIZE as usize
    }

    /// Submit operations from the SQ ring
    pub fn submit(&self, nr: u32) -> i64 {
        let mut inner = self.inner.lock();
        let mut submitted = 0u32;
        let mut link_failed = false;
        let mut in_link = false;

        for _ in 0..nr {
            // In a real implementation, we'd read from shared memory
            // For now, just process what we have in the kernel-side copy
            if submitted >= inner.sq_entries {
                break;
            }

            let sq_idx = inner.sq_head & inner.sq_mask;
            let sqe_idx = inner.sq_array.get(sq_idx as usize).copied().unwrap_or(0);

            if sqe_idx >= inner.sq_entries {
                inner.sq_dropped += 1;
                inner.sq_head = inner.sq_head.wrapping_add(1);
                continue;
            }

            let sqe = inner
                .sqes
                .get(sqe_idx as usize)
                .copied()
                .unwrap_or_default();
            inner.sq_head = inner.sq_head.wrapping_add(1);

            // Check if this SQE is linked (starts or continues a link chain)
            let is_linked = sqe.flags & IOSQE_IO_LINK != 0;
            let is_hard_linked = sqe.flags & IOSQE_IO_HARDLINK != 0;
            let is_drain = sqe.flags & IOSQE_IO_DRAIN != 0;

            // Handle IOSQE_IO_DRAIN - in a full implementation, we'd wait for
            // all pending operations to complete. For now, we process synchronously
            // so drain is implicit.
            let _ = is_drain;

            // Process the SQE (unless link chain has failed)
            let result = if link_failed && in_link && !is_hard_linked {
                // Link chain has failed, skip this SQE
                KernelError::Canceled.to_errno_neg()
            } else {
                // Handle LINK_TIMEOUT specially
                if sqe.opcode == IORING_OP_LINK_TIMEOUT {
                    // LINK_TIMEOUT is only valid in a link chain
                    if !in_link {
                        KernelError::InvalidArgument.to_errno_neg()
                    } else {
                        // For now, just return success (proper implementation
                        // would set up a timeout for the linked operation)
                        0
                    }
                } else {
                    self.process_sqe(&sqe, &mut inner)
                }
            };

            // Check if this operation failed (for link chain handling)
            let op_failed = result < 0;
            if op_failed && (is_linked || in_link) && !is_hard_linked {
                link_failed = true;
            }

            // Update link chain state
            if is_linked || is_hard_linked {
                in_link = true;
            } else {
                // End of link chain (or single operation)
                in_link = false;
                link_failed = false;
            }

            // Post CQE unless IOSQE_CQE_SKIP_SUCCESS and result >= 0
            let skip_cqe = sqe.flags & IOSQE_CQE_SKIP_SUCCESS != 0 && result >= 0;
            if !skip_cqe {
                inner.post_cqe(sqe.user_data, result, 0);
            }

            submitted += 1;
        }

        // Wake up any waiters
        if submitted > 0 {
            self.wq.wake_all();
        }

        submitted as i64
    }

    /// Process a single SQE
    fn process_sqe(&self, sqe: &IoUringSqe, inner: &mut IoUringInner) -> i32 {
        match sqe.opcode {
            IORING_OP_NOP => 0, // Success

            // Phase 2: File I/O
            IORING_OP_READ => self.do_read(sqe),
            IORING_OP_WRITE => self.do_write(sqe),
            IORING_OP_READV => self.do_readv(sqe),
            IORING_OP_WRITEV => self.do_writev(sqe),

            // Phase 3: File management
            IORING_OP_OPENAT => self.do_openat(sqe),
            IORING_OP_CLOSE => self.do_close(sqe),
            IORING_OP_FSYNC => self.do_fsync(sqe),
            IORING_OP_STATX => self.do_statx(sqe),
            IORING_OP_FTRUNCATE => self.do_ftruncate(sqe),

            // Phase 5: Poll/timeout
            IORING_OP_POLL_ADD => self.do_poll_add(sqe, inner),
            IORING_OP_POLL_REMOVE => self.do_poll_remove(sqe, inner),
            IORING_OP_TIMEOUT => self.do_timeout(sqe, inner),
            IORING_OP_TIMEOUT_REMOVE => self.do_timeout_remove(sqe, inner),
            IORING_OP_ASYNC_CANCEL => self.do_async_cancel(sqe, inner),

            // Phase 6: Networking
            IORING_OP_ACCEPT => self.do_accept(sqe),
            IORING_OP_CONNECT => self.do_connect(sqe),
            IORING_OP_SEND => self.do_send(sqe),
            IORING_OP_RECV => self.do_recv(sqe),
            IORING_OP_SENDMSG => self.do_sendmsg(sqe),
            IORING_OP_RECVMSG => self.do_recvmsg(sqe),
            IORING_OP_SHUTDOWN => self.do_shutdown(sqe),

            _ => KernelError::InvalidArgument.to_errno_neg(), // Unknown opcode
        }
    }

    /// Handle IORING_OP_READ
    #[allow(clippy::needless_range_loop)] // Need raw pointer indexing for user memory
    fn do_read(&self, sqe: &IoUringSqe) -> i32 {
        let fd = sqe.fd;
        let buf_addr = sqe.addr;
        let len = sqe.len as usize;
        let offset = sqe.off;

        // Get file - either from fixed file table or regular fd
        let file = if sqe.flags & IOSQE_FIXED_FILE != 0 {
            // Use fixed file from registered file table
            match self.get_fixed_file(fd as u32) {
                Some(f) => f,
                None => return KernelError::BadFd.to_errno_neg(),
            }
        } else {
            // Use regular fd
            match get_file_from_fd(fd) {
                Some(f) => f,
                None => return KernelError::BadFd.to_errno_neg(),
            }
        };

        // Create buffer for read
        if buf_addr == 0 || len == 0 {
            return KernelError::InvalidArgument.to_errno_neg();
        }

        // Allocate kernel buffer
        let mut kbuf = alloc::vec![0u8; len];

        // Read from file
        let result = if offset == u64::MAX {
            // Use current file position (offset -1 means current pos)
            match file.f_op.read(&file, &mut kbuf) {
                Ok(n) => n as i32,
                Err(e) => fs_error_to_errno(e) as i32,
            }
        } else {
            // Use specified offset (pread)
            match file.f_op.pread(&file, &mut kbuf, offset) {
                Ok(n) => n as i32,
                Err(e) => fs_error_to_errno(e) as i32,
            }
        };

        // Copy to userspace if read succeeded
        if result > 0 {
            let bytes_to_copy = result as usize;
            let user_ptr = buf_addr as *mut u8;
            for i in 0..bytes_to_copy {
                unsafe {
                    core::ptr::write_volatile(user_ptr.add(i), kbuf[i]);
                }
            }
        }

        result
    }

    /// Handle IORING_OP_WRITE
    #[allow(clippy::needless_range_loop)] // Need raw pointer indexing for user memory
    fn do_write(&self, sqe: &IoUringSqe) -> i32 {
        let fd = sqe.fd;
        let buf_addr = sqe.addr;
        let len = sqe.len as usize;
        let offset = sqe.off;

        // Get file - either from fixed file table or regular fd
        let file = if sqe.flags & IOSQE_FIXED_FILE != 0 {
            match self.get_fixed_file(fd as u32) {
                Some(f) => f,
                None => return KernelError::BadFd.to_errno_neg(),
            }
        } else {
            match get_file_from_fd(fd) {
                Some(f) => f,
                None => return KernelError::BadFd.to_errno_neg(),
            }
        };

        // Validate buffer
        if buf_addr == 0 || len == 0 {
            return KernelError::InvalidArgument.to_errno_neg();
        }

        // Copy from userspace
        let mut kbuf = alloc::vec![0u8; len];
        let user_ptr = buf_addr as *const u8;
        for i in 0..len {
            unsafe {
                kbuf[i] = core::ptr::read_volatile(user_ptr.add(i));
            }
        }

        // Write to file
        if offset == u64::MAX {
            // Use current file position
            match file.f_op.write(&file, &kbuf) {
                Ok(n) => n as i32,
                Err(e) => fs_error_to_errno(e) as i32,
            }
        } else {
            // Use specified offset (pwrite)
            match file.f_op.pwrite(&file, &kbuf, offset) {
                Ok(n) => n as i32,
                Err(e) => fs_error_to_errno(e) as i32,
            }
        }
    }

    /// Handle IORING_OP_READV (vectored read)
    #[allow(clippy::needless_range_loop)] // Need raw pointer indexing for user memory
    fn do_readv(&self, sqe: &IoUringSqe) -> i32 {
        let fd = sqe.fd;
        let iov_addr = sqe.addr;
        let iov_count = sqe.len as usize;
        let offset = sqe.off;

        // Get file - either from fixed file table or regular fd
        let file = if sqe.flags & IOSQE_FIXED_FILE != 0 {
            match self.get_fixed_file(fd as u32) {
                Some(f) => f,
                None => return KernelError::BadFd.to_errno_neg(),
            }
        } else {
            match get_file_from_fd(fd) {
                Some(f) => f,
                None => return KernelError::BadFd.to_errno_neg(),
            }
        };

        if iov_addr == 0 || iov_count == 0 {
            return KernelError::InvalidArgument.to_errno_neg();
        }

        // Read iovec array from userspace
        let mut total_read: usize = 0;
        let iov_ptr = iov_addr as *const IoVec;

        for i in 0..iov_count {
            let iov: IoVec = unsafe { core::ptr::read_volatile(iov_ptr.add(i)) };
            if iov.iov_len == 0 {
                continue;
            }

            let mut kbuf = alloc::vec![0u8; iov.iov_len];

            let result = if offset == u64::MAX {
                file.f_op.read(&file, &mut kbuf)
            } else {
                let adjusted_offset = offset.saturating_add(total_read as u64);
                file.f_op.pread(&file, &mut kbuf, adjusted_offset)
            };

            match result {
                Ok(n) => {
                    // Copy to userspace
                    let user_ptr = iov.iov_base as *mut u8;
                    for j in 0..n {
                        unsafe {
                            core::ptr::write_volatile(user_ptr.add(j), kbuf[j]);
                        }
                    }
                    total_read += n;
                    if n < iov.iov_len {
                        break; // Short read
                    }
                }
                Err(e) => {
                    if total_read > 0 {
                        return total_read as i32;
                    }
                    return fs_error_to_errno(e) as i32;
                }
            }
        }

        total_read as i32
    }

    /// Handle IORING_OP_WRITEV (vectored write)
    #[allow(clippy::needless_range_loop)] // Need raw pointer indexing for user memory
    fn do_writev(&self, sqe: &IoUringSqe) -> i32 {
        let fd = sqe.fd;
        let iov_addr = sqe.addr;
        let iov_count = sqe.len as usize;
        let offset = sqe.off;

        // Get file - either from fixed file table or regular fd
        let file = if sqe.flags & IOSQE_FIXED_FILE != 0 {
            match self.get_fixed_file(fd as u32) {
                Some(f) => f,
                None => return KernelError::BadFd.to_errno_neg(),
            }
        } else {
            match get_file_from_fd(fd) {
                Some(f) => f,
                None => return KernelError::BadFd.to_errno_neg(),
            }
        };

        if iov_addr == 0 || iov_count == 0 {
            return KernelError::InvalidArgument.to_errno_neg();
        }

        // Read iovec array from userspace and write
        let mut total_written: usize = 0;
        let iov_ptr = iov_addr as *const IoVec;

        for i in 0..iov_count {
            let iov: IoVec = unsafe { core::ptr::read_volatile(iov_ptr.add(i)) };
            if iov.iov_len == 0 {
                continue;
            }

            // Copy from userspace
            let mut kbuf = alloc::vec![0u8; iov.iov_len];
            let user_ptr = iov.iov_base as *const u8;
            for j in 0..iov.iov_len {
                unsafe {
                    kbuf[j] = core::ptr::read_volatile(user_ptr.add(j));
                }
            }

            let result = if offset == u64::MAX {
                file.f_op.write(&file, &kbuf)
            } else {
                let adjusted_offset = offset.saturating_add(total_written as u64);
                file.f_op.pwrite(&file, &kbuf, adjusted_offset)
            };

            match result {
                Ok(n) => {
                    total_written += n;
                    if n < iov.iov_len {
                        break; // Short write
                    }
                }
                Err(e) => {
                    if total_written > 0 {
                        return total_written as i32;
                    }
                    return fs_error_to_errno(e) as i32;
                }
            }
        }

        total_written as i32
    }

    // =========================================================================
    // Phase 3: File management operations
    // =========================================================================

    /// Handle IORING_OP_OPENAT
    fn do_openat(&self, sqe: &IoUringSqe) -> i32 {
        // SQE fields for openat:
        // - fd: directory fd (AT_FDCWD = -100)
        // - addr: pathname pointer
        // - len: mode
        // - op_flags: open flags (O_RDONLY, etc.)
        let dirfd = sqe.fd;
        let path_ptr = sqe.addr;
        let flags = sqe.op_flags;
        let mode = sqe.len;

        crate::fs::syscall::sys_openat(dirfd, path_ptr, flags, mode) as i32
    }

    /// Handle IORING_OP_CLOSE
    fn do_close(&self, sqe: &IoUringSqe) -> i32 {
        let fd = sqe.fd;
        crate::fs::syscall::sys_close(fd) as i32
    }

    /// Handle IORING_OP_FSYNC
    fn do_fsync(&self, sqe: &IoUringSqe) -> i32 {
        let fd = sqe.fd;
        // op_flags can have IORING_FSYNC_DATASYNC for fdatasync behavior
        let datasync = (sqe.op_flags & IORING_FSYNC_DATASYNC) != 0;

        if datasync {
            crate::fs::syscall::sys_fdatasync(fd) as i32
        } else {
            crate::fs::syscall::sys_fsync(fd) as i32
        }
    }

    /// Handle IORING_OP_STATX
    fn do_statx(&self, sqe: &IoUringSqe) -> i32 {
        // SQE fields for statx:
        // - fd: directory fd
        // - addr: pathname pointer
        // - off: statx buffer pointer (used as addr2)
        // - len: statx mask
        // - op_flags: AT_* flags
        let dirfd = sqe.fd;
        let path_ptr = sqe.addr;
        let flags = sqe.op_flags as i32;
        let mask = sqe.len;
        let statx_buf = sqe.off;

        crate::fs::syscall::sys_statx(dirfd, path_ptr, flags, mask, statx_buf) as i32
    }

    /// Handle IORING_OP_FTRUNCATE
    fn do_ftruncate(&self, sqe: &IoUringSqe) -> i32 {
        let fd = sqe.fd;
        let length = sqe.off as i64;

        crate::fs::syscall::sys_ftruncate(fd, length) as i32
    }

    /// Wait for completions
    pub fn wait_completions(&self, min_complete: u32, _timeout_ms: i32) -> i64 {
        let inner = self.inner.lock();

        // For now, just return the number of CQEs available
        // A proper implementation would block until min_complete CQEs are ready
        let available = inner.cq_tail; // Simplified - should compare with user's CQ head

        if available >= min_complete {
            return available as i64;
        }

        // TODO: Implement proper blocking wait
        available as i64
    }

    /// Get mmap size for the given offset
    pub fn mmap_size(&self, offset: u64) -> Option<usize> {
        match offset {
            IORING_OFF_SQ_RING | IORING_OFF_CQ_RING => Some(self.rings_size),
            IORING_OFF_SQES => Some(self.sqes_size),
            _ => None,
        }
    }

    /// Release the io_uring instance
    fn release(&self) {
        let mut registry = IOURING_REGISTRY.lock();
        registry.retain(|(id, _)| *id != self.id);
    }

    // =========================================================================
    // Phase 4: Resource registration
    // =========================================================================

    /// Register files for fixed file access
    pub fn register_files(&self, fds: &[i32]) -> i64 {
        let mut inner = self.inner.lock();

        // Can't register if already registered
        if inner.registered_files.is_some() {
            return KernelError::Busy.sysret();
        }

        // Resolve fds to File references
        let fd_table = match get_task_fd(current_tid()) {
            Some(t) => t,
            None => return KernelError::BadFd.sysret(),
        };

        let fd_table_locked = fd_table.lock();
        let mut files = Vec::with_capacity(fds.len());

        for &fd in fds {
            if fd == -1 {
                // -1 means empty slot
                files.push(None);
            } else {
                match fd_table_locked.get(fd) {
                    Some(f) => files.push(Some(f)),
                    None => return KernelError::BadFd.sysret(),
                }
            }
        }

        inner.registered_files = Some(files);
        0
    }

    /// Unregister previously registered files
    pub fn unregister_files(&self) -> i64 {
        let mut inner = self.inner.lock();

        if inner.registered_files.is_none() {
            return KernelError::InvalidArgument.sysret();
        }

        inner.registered_files = None;
        0
    }

    /// Update registered files
    pub fn update_files(&self, offset: u32, fds: &[i32]) -> i64 {
        let mut inner = self.inner.lock();

        let registered = match inner.registered_files.as_mut() {
            Some(r) => r,
            None => return KernelError::InvalidArgument.sysret(),
        };

        let offset = offset as usize;
        if offset + fds.len() > registered.len() {
            return KernelError::InvalidArgument.sysret();
        }

        // Resolve fds to File references
        let fd_table = match get_task_fd(current_tid()) {
            Some(t) => t,
            None => return KernelError::BadFd.sysret(),
        };

        let fd_table_locked = fd_table.lock();

        for (i, &fd) in fds.iter().enumerate() {
            if fd == -1 {
                registered[offset + i] = None;
            } else {
                match fd_table_locked.get(fd) {
                    Some(f) => registered[offset + i] = Some(f),
                    None => return KernelError::BadFd.sysret(),
                }
            }
        }

        fds.len() as i64
    }

    /// Get a registered file by fixed file index
    pub fn get_fixed_file(&self, index: u32) -> Option<Arc<File>> {
        let inner = self.inner.lock();
        inner
            .registered_files
            .as_ref()?
            .get(index as usize)?
            .clone()
    }

    // =========================================================================
    // Phase 5: Poll and Timeout operations
    // =========================================================================

    /// Handle IORING_OP_POLL_ADD - monitor fd for events
    fn do_poll_add(&self, sqe: &IoUringSqe, inner: &mut IoUringInner) -> i32 {
        let fd = sqe.fd;
        // poll_events is in op_flags (or addr for some versions)
        let events = sqe.op_flags;

        // Get file to poll
        let file = if sqe.flags & IOSQE_FIXED_FILE != 0 {
            match self.get_fixed_file(fd as u32) {
                Some(f) => f,
                None => return KernelError::BadFd.to_errno_neg(),
            }
        } else {
            match get_file_from_fd(fd) {
                Some(f) => f,
                None => return KernelError::BadFd.to_errno_neg(),
            }
        };

        // Check if fd is already ready (synchronous completion)
        let ready = file.f_op.poll(&file, None);
        let wanted = (events & 0xFFFF) as u16;

        if ready & wanted != 0 {
            // Already ready - return the events
            return ready as i32;
        }

        // Not ready - add to pending operations
        // In a full implementation, we'd register with the file's wait queue
        // and complete the CQE when events fire. For now, we track it.
        inner.add_pending(sqe.user_data, PendingOpType::Poll { fd, events });

        // Return a special value indicating "pending" - don't post CQE yet
        // We use EAGAIN to indicate async completion later
        // Actually, for poll_add, we should return 0 and post CQE later when ready
        // But since we don't have async infrastructure, we'll return the current state
        0
    }

    /// Handle IORING_OP_POLL_REMOVE - cancel a pending poll
    fn do_poll_remove(&self, sqe: &IoUringSqe, inner: &mut IoUringInner) -> i32 {
        // addr contains the user_data of the poll to cancel
        let target_user_data = sqe.addr;

        // Find and cancel the pending poll
        if inner.cancel_pending(target_user_data) {
            // Post CQE for the cancelled operation
            inner.post_cqe(target_user_data, KernelError::Canceled.to_errno_neg(), 0);
            0 // Success
        } else {
            // Not found
            KernelError::NotFound.to_errno_neg()
        }
    }

    /// Handle IORING_OP_TIMEOUT - add a timeout
    fn do_timeout(&self, sqe: &IoUringSqe, inner: &mut IoUringInner) -> i32 {
        // addr points to __kernel_timespec
        let ts_ptr = sqe.addr;
        // off contains the completion count to wait for (or 0)
        let count = sqe.off;
        // op_flags contains IORING_TIMEOUT_ABS for absolute time

        if ts_ptr == 0 {
            return KernelError::InvalidArgument.to_errno_neg();
        }

        // Read timespec from userspace
        // struct __kernel_timespec { i64 tv_sec; i64 tv_nsec; }
        let tv_sec: i64 = unsafe { core::ptr::read_volatile(ts_ptr as *const i64) };
        let tv_nsec: i64 = unsafe { core::ptr::read_volatile((ts_ptr + 8) as *const i64) };

        if tv_sec < 0 || !(0..1_000_000_000).contains(&tv_nsec) {
            return KernelError::InvalidArgument.to_errno_neg();
        }

        // Calculate deadline in nanoseconds
        let timeout_ns = (tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(tv_nsec as u64);

        // Get current time in nanoseconds
        let current_time = crate::time::TIMEKEEPER.current_time();
        let now_ns = (current_time.sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(current_time.nsec as u64);

        // For absolute time, use as-is; for relative, add current time
        let is_abs = (sqe.op_flags & 0x1) != 0; // IORING_TIMEOUT_ABS
        let deadline_ns = if is_abs {
            timeout_ns
        } else {
            // Get current time and add timeout
            now_ns.saturating_add(timeout_ns)
        };

        // If count is 0, this is a pure timeout
        // If count > 0, complete after count CQEs OR timeout, whichever first
        if count == 0 {
            // Pure timeout - check if already expired
            if now_ns >= deadline_ns {
                return KernelError::TimerExpired.to_errno_neg();
            }
        }

        // Add to pending operations
        inner.add_pending(sqe.user_data, PendingOpType::Timeout { deadline_ns });

        // For now, we can't actually wait asynchronously, so check immediately
        // In a full implementation, we'd use a timer and complete later
        if now_ns >= deadline_ns {
            // Already expired
            KernelError::TimerExpired.to_errno_neg()
        } else {
            // Still pending - return 0, CQE will be posted when timeout fires
            // Since we can't do async timers, return success
            0
        }
    }

    /// Handle IORING_OP_TIMEOUT_REMOVE - cancel a pending timeout
    fn do_timeout_remove(&self, sqe: &IoUringSqe, inner: &mut IoUringInner) -> i32 {
        // addr contains the user_data of the timeout to cancel
        let target_user_data = sqe.addr;

        // Find and cancel the pending timeout
        if inner.cancel_pending(target_user_data) {
            // Post CQE for the cancelled timeout with ECANCELED
            inner.post_cqe(target_user_data, KernelError::Canceled.to_errno_neg(), 0);
            0 // Success
        } else {
            // Not found
            KernelError::NotFound.to_errno_neg()
        }
    }

    /// Handle IORING_OP_ASYNC_CANCEL - cancel any pending operation
    fn do_async_cancel(&self, sqe: &IoUringSqe, inner: &mut IoUringInner) -> i32 {
        // addr contains the user_data of the operation to cancel
        let target_user_data = sqe.addr;
        // op_flags can contain IORING_ASYNC_CANCEL_ALL (0x1) to cancel all matching

        let cancel_all = (sqe.op_flags & 0x1) != 0;

        if cancel_all {
            // Cancel all operations with matching user_data
            let mut cancelled_count = 0;
            for op in &mut inner.pending_ops {
                if op.user_data == target_user_data && !op.cancelled {
                    op.cancelled = true;
                    cancelled_count += 1;
                }
            }

            // Post CQEs for all cancelled operations
            let cancelled = inner.drain_cancelled();
            for user_data in cancelled {
                inner.post_cqe(user_data, KernelError::Canceled.to_errno_neg(), 0);
            }

            if cancelled_count > 0 {
                cancelled_count
            } else {
                KernelError::NotFound.to_errno_neg()
            }
        } else {
            // Cancel first matching operation
            if inner.cancel_pending(target_user_data) {
                let cancelled = inner.drain_cancelled();
                for user_data in cancelled {
                    inner.post_cqe(user_data, KernelError::Canceled.to_errno_neg(), 0);
                }
                0 // Success
            } else {
                KernelError::NotFound.to_errno_neg()
            }
        }
    }

    // =========================================================================
    // Phase 6: Networking operations
    // =========================================================================

    /// Handle IORING_OP_ACCEPT - accept a connection
    fn do_accept(&self, sqe: &IoUringSqe) -> i32 {
        let fd = sqe.fd;
        let addr = sqe.addr;
        let addrlen = sqe.off; // off is used for addrlen pointer
        let flags = sqe.op_flags as i32;

        // Use accept4 if flags are provided, otherwise accept
        if flags != 0 {
            crate::net::syscall::sys_accept4(fd, addr, addrlen, flags) as i32
        } else {
            crate::net::syscall::sys_accept(fd, addr, addrlen) as i32
        }
    }

    /// Handle IORING_OP_CONNECT - connect a socket
    fn do_connect(&self, sqe: &IoUringSqe) -> i32 {
        let fd = sqe.fd;
        let addr = sqe.addr;
        let addrlen = sqe.off;

        crate::net::syscall::sys_connect(fd, addr, addrlen) as i32
    }

    /// Handle IORING_OP_SEND - send data on a socket
    fn do_send(&self, sqe: &IoUringSqe) -> i32 {
        let fd = sqe.fd;
        let buf = sqe.addr;
        let len = sqe.len as u64;
        let flags = sqe.op_flags as i32;

        // send is equivalent to sendto with NULL destination
        crate::net::syscall::sys_sendto(fd, buf, len, flags, 0, 0) as i32
    }

    /// Handle IORING_OP_RECV - receive data from a socket
    fn do_recv(&self, sqe: &IoUringSqe) -> i32 {
        let fd = sqe.fd;
        let buf = sqe.addr;
        let len = sqe.len as u64;
        let flags = sqe.op_flags as i32;

        // recv is equivalent to recvfrom with NULL source
        crate::net::syscall::sys_recvfrom(fd, buf, len, flags, 0, 0) as i32
    }

    /// Handle IORING_OP_SENDMSG - send a message on a socket
    fn do_sendmsg(&self, sqe: &IoUringSqe) -> i32 {
        let fd = sqe.fd;
        let msg = sqe.addr;
        let flags = sqe.op_flags as i32;

        crate::net::syscall::sys_sendmsg(fd, msg, flags) as i32
    }

    /// Handle IORING_OP_RECVMSG - receive a message from a socket
    fn do_recvmsg(&self, sqe: &IoUringSqe) -> i32 {
        let fd = sqe.fd;
        let msg = sqe.addr;
        let flags = sqe.op_flags as i32;

        crate::net::syscall::sys_recvmsg(fd, msg, flags) as i32
    }

    /// Handle IORING_OP_SHUTDOWN - shutdown part of a socket
    fn do_shutdown(&self, sqe: &IoUringSqe) -> i32 {
        let fd = sqe.fd;
        let how = sqe.len as i32; // how is in len field

        crate::net::syscall::sys_shutdown(fd, how) as i32
    }
}

// ============================================================================
// File operations for io_uring fd
// ============================================================================

/// File operations for io_uring file descriptor
pub struct IoUringFileOps {
    ring: Arc<IoUring>,
}

impl IoUringFileOps {
    pub fn new(ring: Arc<IoUring>) -> Self {
        Self { ring }
    }
}

impl FileOps for IoUringFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read(&self, _file: &File, _buf: &mut [u8]) -> Result<usize, KernelError> {
        // io_uring fds are not directly readable
        Err(KernelError::InvalidArgument)
    }

    fn write(&self, _file: &File, _buf: &[u8]) -> Result<usize, KernelError> {
        // io_uring fds are not directly writable
        Err(KernelError::InvalidArgument)
    }

    fn poll(&self, _file: &File, pt: Option<&mut PollTable>) -> u16 {
        if let Some(poll_table) = pt {
            poll_table.poll_wait(&self.ring.wq);
        }

        // Check if CQEs are available
        let inner = self.ring.inner.lock();
        if inner.cq_tail > 0 {
            crate::poll::POLLIN | crate::poll::POLLRDNORM
        } else {
            0
        }
    }

    fn release(&self, _file: &File) -> Result<(), KernelError> {
        self.ring.release();
        Ok(())
    }
}

/// Get the IoUring from a File
pub fn get_io_uring(file: &File) -> Option<Arc<IoUring>> {
    file.f_op
        .as_any()
        .downcast_ref::<IoUringFileOps>()
        .map(|ops| Arc::clone(&ops.ring))
}

/// Create an io_uring file
fn create_io_uring_file(ring: Arc<IoUring>) -> Result<Arc<File>, KernelError> {
    let ops: &'static dyn FileOps = Box::leak(Box::new(IoUringFileOps::new(ring)));

    // Create dummy dentry
    let mode = InodeMode::regular(0o600);
    let inode = Arc::new(Inode::new(
        0,
        mode,
        0,
        0,
        0,
        InodeTimespec::from_secs(0),
        Weak::new(),
        &NULL_INODE_OPS,
    ));

    let dentry = Arc::new(Dentry::new_anonymous(String::from("io_uring"), Some(inode)));
    let file = Arc::new(File::new(dentry, flags::O_RDWR, ops));

    Ok(file)
}

// ============================================================================
// Helper structures and functions
// ============================================================================

/// iovec structure for vectored I/O
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct IoVec {
    iov_base: u64,  // Pointer to buffer
    iov_len: usize, // Length of buffer
}

/// Get file from fd for current task
fn get_file_from_fd(fd: i32) -> Option<Arc<File>> {
    let fd_table = get_task_fd(current_tid())?;
    fd_table.lock().get(fd)
}

/// Convert KernelError to negative errno value
fn fs_error_to_errno(e: KernelError) -> i64 {
    e.sysret()
}

// ============================================================================
// Syscall implementations
// ============================================================================

/// Get RLIMIT_NOFILE for fd allocation
fn get_nofile_limit() -> u64 {
    let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_NOFILE);
    if limit == crate::rlimit::RLIM_INFINITY {
        u64::MAX
    } else {
        limit
    }
}

/// Validate and adjust ring entries to power of 2
fn round_up_pow2(n: u32) -> u32 {
    if n == 0 {
        return 1;
    }
    let mut v = n - 1;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v + 1
}

/// Check if n is a power of 2
fn is_power_of_2(n: u32) -> bool {
    n != 0 && (n & (n - 1)) == 0
}

/// sys_io_uring_setup - Set up an io_uring instance
///
/// # Arguments
/// * `entries` - Number of SQ entries requested
/// * `params_ptr` - Pointer to io_uring_params structure
///
/// # Returns
/// File descriptor on success, negative errno on failure
pub fn sys_io_uring_setup(entries: u32, params_ptr: u64) -> i64 {
    // Validate entries
    if entries == 0 || entries > IORING_MAX_ENTRIES {
        return KernelError::InvalidArgument.sysret();
    }

    if params_ptr == 0 {
        return KernelError::BadAddress.sysret();
    }

    // Read params from user space
    let mut params: IoUringParams = match get_user::<Uaccess, IoUringParams>(params_ptr) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Check reserved fields are zero
    for r in &params.resv {
        if *r != 0 {
            return KernelError::InvalidArgument.sysret();
        }
    }

    // Validate flags - we only support a subset for now
    let supported_flags = IORING_SETUP_CQSIZE | IORING_SETUP_CLAMP;
    if params.flags & !supported_flags != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Round entries to power of 2
    let sq_entries = if params.flags & IORING_SETUP_CLAMP != 0 {
        core::cmp::min(round_up_pow2(entries), IORING_MAX_ENTRIES)
    } else {
        if !is_power_of_2(entries) {
            return KernelError::InvalidArgument.sysret();
        }
        entries
    };

    // Determine CQ entries (default 2x SQ, or custom if IORING_SETUP_CQSIZE)
    let cq_entries = if params.flags & IORING_SETUP_CQSIZE != 0 {
        let cq = params.cq_entries;
        if cq == 0 || cq > IORING_MAX_ENTRIES * 2 {
            return KernelError::InvalidArgument.sysret();
        }
        if params.flags & IORING_SETUP_CLAMP != 0 {
            core::cmp::min(round_up_pow2(cq), IORING_MAX_ENTRIES * 2)
        } else {
            if !is_power_of_2(cq) {
                return KernelError::InvalidArgument.sysret();
            }
            cq
        }
    } else {
        // Default: CQ is 2x SQ size
        core::cmp::min(sq_entries * 2, IORING_MAX_ENTRIES * 2)
    };

    // Create io_uring instance
    let ring = IoUring::new(sq_entries, cq_entries);

    // Fill in params
    params.sq_entries = sq_entries;
    params.cq_entries = cq_entries;
    params.features = IORING_FEAT_SINGLE_MMAP | IORING_FEAT_SUBMIT_STABLE;

    // Fill in SQ ring offsets
    params.sq_off = SqRingOffsets {
        head: 0,
        tail: 4,
        ring_mask: 8,
        ring_entries: 12,
        flags: 16,
        dropped: 20,
        array: 24,
        resv1: 0,
        user_addr: 0,
    };

    // Fill in CQ ring offsets (CQ follows SQ in memory)
    let sq_ring_size = 24 + (sq_entries as u32) * 4;
    let cq_base = sq_ring_size;
    params.cq_off = CqRingOffsets {
        head: cq_base,
        tail: cq_base + 4,
        ring_mask: cq_base + 8,
        ring_entries: cq_base + 12,
        overflow: cq_base + 16,
        cqes: cq_base + 24, // Skip flags at +20
        flags: cq_base + 20,
        resv1: 0,
        user_addr: 0,
    };

    // Create file
    let file = match create_io_uring_file(ring) {
        Ok(f) => f,
        Err(_) => return KernelError::OutOfMemory.sysret(),
    };

    // Allocate fd
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return KernelError::OutOfMemory.sysret(),
    };

    let fd = match fd_table
        .lock()
        .alloc_with_flags(file, FD_CLOEXEC, get_nofile_limit())
    {
        Ok(fd) => fd,
        Err(e) => return -(e as i64),
    };

    // Write params back to user space
    if put_user::<Uaccess, IoUringParams>(params_ptr, params).is_err() {
        // Close the fd we just allocated
        let _ = fd_table.lock().close(fd);
        return KernelError::BadAddress.sysret();
    }

    fd as i64
}

/// sys_io_uring_enter - Submit I/O and/or wait for completions
///
/// # Arguments
/// * `fd` - io_uring file descriptor
/// * `to_submit` - Number of SQEs to submit
/// * `min_complete` - Minimum CQEs to wait for
/// * `flags` - IORING_ENTER_* flags
/// * `argp` - Extended arguments (for IORING_ENTER_EXT_ARG)
/// * `argsz` - Size of extended arguments
///
/// # Returns
/// Number of CQEs/SQEs processed, or negative errno
pub fn sys_io_uring_enter(
    fd: u32,
    to_submit: u32,
    min_complete: u32,
    flags: u32,
    _argp: u64,
    _argsz: usize,
) -> i64 {
    // Validate flags
    let supported = IORING_ENTER_GETEVENTS | IORING_ENTER_SQ_WAKEUP | IORING_ENTER_SQ_WAIT;
    if flags & !supported != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Get io_uring from fd
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return KernelError::BadFd.sysret(),
    };

    let file = match fd_table.lock().get(fd as i32) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    let ring = match get_io_uring(&file) {
        Some(r) => r,
        None => return KernelError::BadFd.sysret(),
    };

    let mut ret = 0i64;

    // Submit SQEs
    if to_submit > 0 {
        ret = ring.submit(to_submit);
        if ret < 0 {
            return ret;
        }
    }

    // Wait for completions
    if flags & IORING_ENTER_GETEVENTS != 0 && min_complete > 0 {
        let wait_ret = ring.wait_completions(min_complete, -1);
        if wait_ret < 0 {
            return wait_ret;
        }
        ret = wait_ret;
    }

    ret
}

/// sys_io_uring_register - Register resources with an io_uring instance
///
/// # Arguments
/// * `fd` - io_uring file descriptor
/// * `opcode` - IORING_REGISTER_* operation
/// * `arg` - Operation-specific argument
/// * `nr_args` - Number of arguments
///
/// # Returns
/// 0 on success, or negative errno
#[allow(clippy::needless_range_loop)] // Need raw pointer indexing for user memory
pub fn sys_io_uring_register(fd: u32, opcode: u32, arg: u64, nr_args: u32) -> i64 {
    // Get io_uring from fd
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return KernelError::BadFd.sysret(),
    };

    let file = match fd_table.lock().get(fd as i32) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    let ring = match get_io_uring(&file) {
        Some(r) => r,
        None => return KernelError::BadFd.sysret(),
    };

    // Handle register operations
    match opcode {
        IORING_REGISTER_BUFFERS => {
            // Buffer registration not yet implemented (requires different data structure)
            KernelError::OperationNotSupported.sysret()
        }

        IORING_UNREGISTER_BUFFERS => {
            // Buffer unregistration not yet implemented
            KernelError::OperationNotSupported.sysret()
        }

        IORING_REGISTER_FILES => {
            if nr_args == 0 {
                return KernelError::InvalidArgument.sysret();
            }

            // Read fd array from userspace
            let fds_ptr = arg as *const i32;
            let mut fds = alloc::vec![0i32; nr_args as usize];

            for i in 0..nr_args as usize {
                unsafe {
                    fds[i] = core::ptr::read_volatile(fds_ptr.add(i));
                }
            }

            ring.register_files(&fds)
        }

        IORING_UNREGISTER_FILES => ring.unregister_files(),

        IORING_REGISTER_FILES_UPDATE => {
            // struct io_uring_files_update { u32 offset; u32 resv; i64 fds; };
            // For simplicity, we expect arg to point to the fds array directly
            // with offset = 0. Full implementation would parse the struct.
            if nr_args == 0 {
                return KernelError::InvalidArgument.sysret();
            }

            // Read fd array from userspace
            let fds_ptr = arg as *const i32;
            let mut fds = alloc::vec![0i32; nr_args as usize];

            for i in 0..nr_args as usize {
                unsafe {
                    fds[i] = core::ptr::read_volatile(fds_ptr.add(i));
                }
            }

            ring.update_files(0, &fds)
        }

        IORING_REGISTER_EVENTFD | IORING_UNREGISTER_EVENTFD => {
            // Eventfd registration not yet implemented
            KernelError::OperationNotSupported.sysret()
        }

        _ => KernelError::InvalidArgument.sysret(),
    }
}
