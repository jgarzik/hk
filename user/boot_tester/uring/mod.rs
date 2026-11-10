//! io_uring tests through the mapped rings (Linux io_uring/*.c,
//! liburing's ring layout), raw syscalls only

pub mod dio;
pub mod ring;
pub mod setup;
pub mod wait;

use core::sync::atomic::{AtomicU32, Ordering};

use hk_syscall::{
    IORING_ENTER_GETEVENTS, IORING_OFF_SQ_RING, IORING_OFF_SQES, IoUringCqe, IoUringParams,
    IoUringSqe, MAP_POPULATE, MAP_SHARED, PROT_READ, PROT_WRITE, sys_close, sys_io_uring_enter,
    sys_io_uring_setup, sys_mmap, sys_munmap,
};

pub const EINVAL: i64 = -22;
pub const EOPNOTSUPP: i64 = -95;

pub fn run_tests() {
    setup::run_tests();
    ring::run_tests();
    wait::run_tests();
    dio::run_tests();
}

/// One mapped region
struct Map {
    p: *mut u8,
    len: u64,
}

impl Map {
    fn new(fd: i32, len: u64, off: u64) -> Result<Self, i64> {
        let p = sys_mmap(
            0,
            len,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_POPULATE,
            fd,
            off,
        );
        if p < 0 {
            return Err(p);
        }
        Ok(Self {
            p: p as *mut u8,
            len,
        })
    }

    fn word(&self, off: u32) -> &AtomicU32 {
        // SAFETY: an aligned word of the live mapping
        unsafe { &*(self.p.add(off as usize) as *const AtomicU32) }
    }
}

impl Drop for Map {
    fn drop(&mut self) {
        sys_munmap(self.p as u64, self.len);
    }
}

/// An io_uring with its rings mapped (liburing's struct io_uring)
pub struct Ring {
    pub fd: i32,
    pub p: IoUringParams,
    rings: Map,
    sqes: Map,
    /// The SQ tail user space has written (published at `publish`)
    sq_tail: u32,
}

impl Ring {
    /// A ring of `entries` with `p` (flags, cq_entries), mapped:
    /// the SQ ring at IORING_OFF_SQ_RING (holding the CQ too:
    /// IORING_FEAT_SINGLE_MMAP), the SQEs at IORING_OFF_SQES
    pub fn new(entries: u32, mut p: IoUringParams) -> Result<Self, i64> {
        let fd = sys_io_uring_setup(entries, &mut p);
        if fd < 0 {
            return Err(fd);
        }
        let fd = fd as i32;
        let sq_len = u64::from(p.sq_off.array) + u64::from(p.sq_entries) * 4;
        let cq_len = u64::from(p.cq_off.cqes) + u64::from(p.cq_entries) * 16;
        let maps = Map::new(fd, sq_len.max(cq_len), IORING_OFF_SQ_RING).and_then(|r| {
            Map::new(fd, u64::from(p.sq_entries) * 64, IORING_OFF_SQES).map(|s| (r, s))
        });
        match maps {
            Ok((rings, sqes)) => Ok(Self {
                fd,
                p,
                rings,
                sqes,
                sq_tail: 0,
            }),
            Err(e) => {
                sys_close(fd as u64);
                Err(e)
            }
        }
    }

    /// A ring of `entries`, default parameters
    pub fn simple(entries: u32) -> Result<Self, i64> {
        Self::new(entries, IoUringParams::default())
    }

    fn w(&self, off: u32) -> &AtomicU32 {
        self.rings.word(off)
    }

    pub fn sq_head(&self) -> u32 {
        self.w(self.p.sq_off.head).load(Ordering::Acquire)
    }

    pub fn sq_flags(&self) -> u32 {
        self.w(self.p.sq_off.flags).load(Ordering::Acquire)
    }

    pub fn sq_dropped(&self) -> u32 {
        self.w(self.p.sq_off.dropped).load(Ordering::Acquire)
    }

    pub fn cq_overflow(&self) -> u32 {
        self.w(self.p.cq_off.overflow).load(Ordering::Acquire)
    }

    pub fn cq_tail(&self) -> u32 {
        self.w(self.p.cq_off.tail).load(Ordering::Acquire)
    }

    pub fn cq_head(&self) -> u32 {
        self.w(self.p.cq_off.head).load(Ordering::Relaxed)
    }

    /// Word `off` of the rings region (masks, entries)
    pub fn ring_word(&self, off: u32) -> u32 {
        self.w(off).load(Ordering::Relaxed)
    }

    /// Queue `sqe` in SQE slot and SQ array slot `tail & mask`, naming
    /// SQE `idx` (normally the same slot); not yet published
    pub fn push_at(&mut self, sqe: IoUringSqe, idx: u32) {
        let mask = self.p.sq_entries - 1;
        let slot = self.sq_tail & mask;
        if idx < self.p.sq_entries {
            // SAFETY: SQE `idx` of the live SQE mapping
            unsafe {
                (self.sqes.p as *mut IoUringSqe)
                    .add(idx as usize)
                    .write_volatile(sqe)
            };
        }
        self.w(self.p.sq_off.array + slot * 4)
            .store(idx, Ordering::Relaxed);
        self.sq_tail = self.sq_tail.wrapping_add(1);
    }

    /// Queue `sqe` and publish the SQ tail
    pub fn push(&mut self, sqe: IoUringSqe) {
        let idx = self.sq_tail & (self.p.sq_entries - 1);
        self.push_at(sqe, idx);
        self.publish();
    }

    /// Publish the SQ tail (the SQEs before it are written)
    pub fn publish(&self) {
        self.w(self.p.sq_off.tail)
            .store(self.sq_tail, Ordering::Release);
    }

    /// io_uring_enter
    pub fn enter(&self, submit: u32, min: u32, flags: u32) -> i64 {
        sys_io_uring_enter(self.fd as u32, submit, min, flags, 0, 0)
    }

    /// Submit `n` and wait for `min` CQEs
    pub fn submit_wait(&self, n: u32, min: u32) -> i64 {
        self.enter(n, min, IORING_ENTER_GETEVENTS)
    }

    /// The next CQE, consumed
    pub fn pop(&self) -> Option<IoUringCqe> {
        let head = self.cq_head();
        if head == self.cq_tail() {
            return None;
        }
        let i = head & (self.p.cq_entries - 1);
        let off = self.p.cq_off.cqes as usize + i as usize * 16;
        // SAFETY: CQE `i` of the live rings mapping, published by the tail
        let cqe = unsafe { (self.rings.p.add(off) as *const IoUringCqe).read_volatile() };
        self.w(self.p.cq_off.head)
            .store(head.wrapping_add(1), Ordering::Release);
        Some(cqe)
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        sys_close(self.fd as u64);
    }
}

/// An SQE of `op` on `fd`
pub fn sqe(op: u8, fd: i32, addr: u64, len: u32, off: u64, user_data: u64) -> IoUringSqe {
    IoUringSqe {
        opcode: op,
        fd,
        addr,
        len,
        off,
        user_data,
        ..IoUringSqe::default()
    }
}
