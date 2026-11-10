//! io_uring user ABI (Linux include/uapi/linux/io_uring.h)

/// mmap offsets of the rings (one region: IORING_FEAT_SINGLE_MMAP) and
/// of the SQE array; the high bits select, the rest is ignored (Linux
/// IORING_OFF_MMAP_MASK)
pub const IORING_OFF_SQ_RING: u64 = 0;
pub const IORING_OFF_CQ_RING: u64 = 0x800_0000;
pub const IORING_OFF_SQES: u64 = 0x1000_0000;
pub const IORING_OFF_MMAP_MASK: u64 = 0xf800_0000;

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

/// SQ ring flags
pub const IORING_SQ_NEED_WAKEUP: u32 = 1 << 0;
pub const IORING_SQ_CQ_OVERFLOW: u32 = 1 << 1;

/// Feature flags (io_uring_params.features)
pub const IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;
pub const IORING_FEAT_NODROP: u32 = 1 << 1;
pub const IORING_FEAT_SUBMIT_STABLE: u32 = 1 << 2;
pub const IORING_FEAT_RW_CUR_POS: u32 = 1 << 3;
pub const IORING_FEAT_CUR_PERSONALITY: u32 = 1 << 4;
pub const IORING_FEAT_EXT_ARG: u32 = 1 << 8;
pub const IORING_FEAT_CQE_SKIP: u32 = 1 << 11;

/// Operation codes
pub const IORING_OP_NOP: u8 = 0;
pub const IORING_OP_READV: u8 = 1;
pub const IORING_OP_WRITEV: u8 = 2;
pub const IORING_OP_FSYNC: u8 = 3;
pub const IORING_OP_READ_FIXED: u8 = 4;
pub const IORING_OP_WRITE_FIXED: u8 = 5;
pub const IORING_OP_POLL_ADD: u8 = 6;
pub const IORING_OP_POLL_REMOVE: u8 = 7;
pub const IORING_OP_SENDMSG: u8 = 9;
pub const IORING_OP_RECVMSG: u8 = 10;
pub const IORING_OP_TIMEOUT: u8 = 11;
pub const IORING_OP_TIMEOUT_REMOVE: u8 = 12;
pub const IORING_OP_ACCEPT: u8 = 13;
pub const IORING_OP_ASYNC_CANCEL: u8 = 14;
pub const IORING_OP_LINK_TIMEOUT: u8 = 15;
pub const IORING_OP_CONNECT: u8 = 16;
pub const IORING_OP_OPENAT: u8 = 18;
pub const IORING_OP_CLOSE: u8 = 19;
pub const IORING_OP_STATX: u8 = 21;
pub const IORING_OP_READ: u8 = 22;
pub const IORING_OP_WRITE: u8 = 23;
pub const IORING_OP_SEND: u8 = 26;
pub const IORING_OP_RECV: u8 = 27;
pub const IORING_OP_SHUTDOWN: u8 = 34;
pub const IORING_OP_FTRUNCATE: u8 = 46;

/// IORING_OP_TIMEOUT on CLOCK_REALTIME (Linux IORING_TIMEOUT_REALTIME)
pub const IORING_TIMEOUT_REALTIME: u32 = 1 << 3;

/// FSYNC flags (op_flags of IORING_OP_FSYNC)
pub const IORING_FSYNC_DATASYNC: u32 = 1 << 0;

/// io_uring_register opcodes
pub const IORING_REGISTER_BUFFERS: u32 = 0;
pub const IORING_UNREGISTER_BUFFERS: u32 = 1;
pub const IORING_REGISTER_FILES: u32 = 2;
pub const IORING_UNREGISTER_FILES: u32 = 3;
pub const IORING_REGISTER_EVENTFD: u32 = 4;
pub const IORING_UNREGISTER_EVENTFD: u32 = 5;
pub const IORING_REGISTER_FILES_UPDATE: u32 = 6;

/// Most SQ entries (Linux IORING_MAX_ENTRIES); twice that for the CQ
pub const IORING_MAX_ENTRIES: u32 = 32768;
pub const IORING_MAX_CQ_ENTRIES: u32 = 2 * IORING_MAX_ENTRIES;

/// SQ ring offsets (io_uring_params.sq_off)
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
crate::pod!(SqRingOffsets {
    head,
    tail,
    ring_mask,
    ring_entries,
    flags,
    dropped,
    array,
    resv1,
    user_addr
});

/// CQ ring offsets (io_uring_params.cq_off)
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
crate::pod!(CqRingOffsets {
    head,
    tail,
    ring_mask,
    ring_entries,
    overflow,
    cqes,
    flags,
    resv1,
    user_addr
});

/// io_uring_params, passed to io_uring_setup (120 bytes)
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
crate::pod!(IoUringParams {
    sq_entries,
    cq_entries,
    flags,
    sq_thread_cpu,
    sq_thread_idle,
    features,
    wq_fd,
    resv,
    sq_off,
    cq_off
});

/// Submission queue entry (64 bytes)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IoUringSqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    /// Offset, or addr2
    pub off: u64,
    /// Buffer address, or splice offset
    pub addr: u64,
    pub len: u32,
    /// The operation's flags (rw_flags, fsync_flags, ...)
    pub op_flags: u32,
    pub user_data: u64,
    /// Fixed buffer index, or buffer group
    pub buf_index: u16,
    pub personality: u16,
    pub splice_fd_in: i32,
    pub pad2: [u64; 2],
}
crate::pod!(IoUringSqe {
    opcode,
    flags,
    ioprio,
    fd,
    off,
    addr,
    len,
    op_flags,
    user_data,
    buf_index,
    personality,
    splice_fd_in,
    pad2
});

/// Completion queue entry (16 bytes)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IoUringCqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}
crate::pod!(IoUringCqe {
    user_data,
    res,
    flags
});
