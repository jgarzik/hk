//! Linux native AIO's user ABI (include/uapi/linux/aio_abi.h; fs/aio.c
//! struct aio_ring)

/// IOCB_CMD_*: the operation of a `struct iocb`
pub const IOCB_CMD_PREAD: u16 = 0;
pub const IOCB_CMD_PWRITE: u16 = 1;
pub const IOCB_CMD_FSYNC: u16 = 2;
pub const IOCB_CMD_FDSYNC: u16 = 3;
pub const IOCB_CMD_POLL: u16 = 5;
pub const IOCB_CMD_NOOP: u16 = 6;
pub const IOCB_CMD_PREADV: u16 = 7;
pub const IOCB_CMD_PWRITEV: u16 = 8;

/// aio_resfd names an eventfd signalled at completion
pub const IOCB_FLAG_RESFD: u32 = 1 << 0;
/// aio_reqprio is an I/O priority (class and level)
pub const IOCB_FLAG_IOPRIO: u32 = 1 << 1;

/// What io_submit stores in aio_key, and io_cancel expects there
pub const KIOCB_KEY: u32 = 0;

/// `struct aio_ring`'s magic, features and size (fs/aio.c)
pub const AIO_RING_MAGIC: u32 = 0xa10a_10a1;
pub const AIO_RING_COMPAT_FEATURES: u32 = 1;
pub const AIO_RING_INCOMPAT_FEATURES: u32 = 0;
/// sizeof(struct aio_ring): eight words, the events follow
pub const RING_HEADER: usize = 32;

/// Word offsets in `struct aio_ring`
pub const RING_ID: usize = 0;
pub const RING_NR: usize = 4;
pub const RING_HEAD: usize = 8;
pub const RING_TAIL: usize = 12;
pub const RING_MAGIC: usize = 16;
pub const RING_COMPAT: usize = 20;
pub const RING_INCOMPAT: usize = 24;
pub const RING_HEADER_LENGTH: usize = 28;

/// `struct iocb` (64 bytes; little-endian layout, both arches)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Iocb {
    /// Returned in the event's `data`
    pub aio_data: u64,
    /// Set to KIOCB_KEY by io_submit
    pub aio_key: u32,
    /// RWF_* flags
    pub aio_rw_flags: i32,
    pub aio_lio_opcode: u16,
    pub aio_reqprio: i16,
    pub aio_fildes: u32,
    pub aio_buf: u64,
    pub aio_nbytes: u64,
    pub aio_offset: i64,
    /// Must be 0
    pub aio_reserved2: u64,
    /// IOCB_FLAG_*
    pub aio_flags: u32,
    pub aio_resfd: u32,
}
crate::pod!(Iocb {
    aio_data,
    aio_key,
    aio_rw_flags,
    aio_lio_opcode,
    aio_reqprio,
    aio_fildes,
    aio_buf,
    aio_nbytes,
    aio_offset,
    aio_reserved2,
    aio_flags,
    aio_resfd
});

/// Byte offset of `aio_key` in `struct iocb`
pub const IOCB_KEY_OFF: u64 = 8;

/// `struct io_event` (32 bytes)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoEvent {
    /// The iocb's aio_data
    pub data: u64,
    /// The iocb's user address
    pub obj: u64,
    /// The result: bytes, or a negative errno
    pub res: i64,
    pub res2: i64,
}
crate::pod!(IoEvent {
    data,
    obj,
    res,
    res2
});

/// Bytes of one event
pub const EVENT_SIZE: usize = size_of::<IoEvent>();

/// `struct __aio_sigset` of io_pgetevents
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AioSigset {
    pub sigmask: u64,
    pub sigsetsize: u64,
}
crate::pod!(AioSigset {
    sigmask,
    sigsetsize
});

const _: () = assert!(size_of::<Iocb>() == 64 && EVENT_SIZE == 32);
