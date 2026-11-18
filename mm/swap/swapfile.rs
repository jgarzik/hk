//! Swap devices and swap slots (Linux mm/swapfile.c)
//!
//! A swap area (a partition, or a file whose blocks are mapped to its
//! device at swapon, Linux swap extents) is a
//! [`SwapInfo`]: its slots (one page each; slot 0 holds the mkswap
//! header) are counted in `swap_map` like Linux: the number of swap
//! PTEs referencing a slot, plus [`SWAP_HAS_CACHE`] while a swap-cache
//! page stands for it (`swap_state`). A slot is free when both are
//! gone. Its swap cache (`SwapInfo.cache`) holds those pages by slot.
//!
//! Locking (Linux si->lock, swap_lock, swapon_mutex): `SwapInfo.map`
//! (`spin::Mutex`, thread context only) guards the counts and the
//! allocation hint; it is a leaf taken under the PTE lock (fork, zap,
//! swap-in), never with the swap cache's lock held. `SWAP_INFO` (a
//! spin `RwLock`, read mostly; Linux swap_lock and swap_info[]) holds
//! the devices and the types in use: swapon reserves a type under it
//! first (alloc_swap_info), sets the area up under its file's i_rwsem
//! and publishes it under `SWAPON` (a sleeping `Mutex`, swapon_mutex:
//! enable_swap_info); swapoff takes SWP_WRITEOK away under it, empties
//! the device with neither held, and takes it out of the table under
//! `SWAPON`, so swapons and swapoffs of different areas run in
//! parallel.
//!
//! Lifetime (Linux si->users, get_swap_device / put_swap_device): every
//! use of a device by swap entry or type holds a [`SwapDev`], one count
//! of the device's per-CPU `users` reference. swapoff, once its device
//! is empty, kills `users`, waits out a grace period and the last
//! [`SwapDev`], and only then drops the table's and its own `Arc`: the
//! device is released (block device closed, swap file's inode put,
//! which sleep) in swapoff's process context, never in a user's drop
//! under a PTE lock.

extern crate alloc;

use crate::util::kalloc::try_arc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::sync::spin::{Mutex, RwLock};

use super::swap_entry::{MAX_SWAPFILES, SwapEntry};
use crate::block::BlockDevice;
use crate::block::blkdev::{BioOp, bdev_rw_frame};
use crate::fs::{Inode, InodeRef, LookupFlags, lookup_path};
use crate::mm::filemap::PAGE_SIZE;
use crate::mm::page::PAGE_SHIFT;
use crate::mm::xarray::XArray;
use crate::sync::IrqSpinlock;
use crate::task::{CAP_SYS_ADMIN, capable};
use crate::uaccess::UserPtr;
use crate::util::error::{KernelError, KernelResult};
use crate::util::percpu_ref::PercpuRef;
use core::ptr::NonNull;

/// 512-byte sectors per page
const SECTORS_PER_PAGE: u64 = (PAGE_SIZE / 512) as u64;

// ============================================================================
// Swap flags (for swapon syscall)
// ============================================================================

/// Prefer this swap device (priority set to 32767)
pub const SWAP_FLAG_PREFER: i32 = 0x8000;

/// Extract priority from flags (low 15 bits when SWAP_FLAG_PREFER is set)
pub const SWAP_FLAG_PRIO_MASK: i32 = 0x7FFF;

/// Enable discard (TRIM) for SSD swap
pub const SWAP_FLAG_DISCARD: i32 = 0x10000;

/// Discard the whole area at swapon (Linux SWAP_FLAG_DISCARD_ONCE)
const SWAP_FLAG_DISCARD_ONCE: i32 = 0x20000;

/// Discard freed page clusters (Linux SWAP_FLAG_DISCARD_PAGES)
const SWAP_FLAG_DISCARD_PAGES: i32 = 0x40000;

/// The flags swapon accepts (Linux SWAP_FLAGS_VALID)
const SWAP_FLAGS_VALID: i32 = SWAP_FLAG_PRIO_MASK
    | SWAP_FLAG_PREFER
    | SWAP_FLAG_DISCARD
    | SWAP_FLAG_DISCARD_ONCE
    | SWAP_FLAG_DISCARD_PAGES;

/// The device takes new slots (Linux SWP_WRITEOK)
const SWP_WRITEOK: u32 = 1 << 1;

// ============================================================================
// Slot counts (Linux swap_map)
// ============================================================================

/// A swap-cache page stands for the slot (Linux SWAP_HAS_CACHE)
pub const SWAP_HAS_CACHE: u16 = 0x8000;

/// Most swap PTEs one slot can count (Linux continues counts on extra
/// pages past SWAP_MAP_MAX; hk refuses, see `swap_duplicate`)
const SWAP_MAP_MAX: u16 = 0x7ffe;

// ============================================================================
// Swap header (mkswap format)
// ============================================================================

/// Magic string for swap signature (at offset 4086)
const SWAP_MAGIC: &[u8; 10] = b"SWAPSPACE2";

/// Offset of magic string in first page
const SWAP_MAGIC_OFFSET: usize = 4086;

/// Offset of swap header info
const SWAP_HEADER_INFO_OFFSET: usize = 1024;

/// Swap header info structure (at offset 1024)
#[repr(C)]
#[derive(Clone, Copy)]
struct SwapHeaderInfo {
    version: u32,
    last_page: u32,
    nr_badpages: u32,
    uuid: [u8; 16],
    volume_name: [u8; 16],
    _padding: [u32; 117],
}

// ============================================================================
// Global swap state
// ============================================================================

/// The swap types (Linux swap_info[] under swap_lock)
pub struct SwapTable {
    /// The enabled device of each type
    pub(super) dev: [Option<Arc<SwapInfo>>; MAX_SWAPFILES],
    /// Types in use, one bit each (Linux SWP_USED): reserved by swapon
    /// before it opens anything, given back by a failed swapon or by
    /// swapoff once the device is released
    used: u32,
}

const _: () = assert!(MAX_SWAPFILES <= u32::BITS as usize);

/// The swap types and their devices (Linux swap_lock, swap_info[])
pub static SWAP_INFO: RwLock<SwapTable> = RwLock::new(SwapTable {
    dev: [const { None }; MAX_SWAPFILES],
    used: 0,
});

/// Usable slots of every device (Linux total_swap_pages)
pub static TOTAL_SWAP_PAGES: AtomicU64 = AtomicU64::new(0);

/// Slots in use (counted or cached)
pub static TOTAL_SWAP_USED: AtomicU64 = AtomicU64::new(0);

/// A device entering or leaving the table (Linux swapon_mutex:
/// enable_swap_info, swapoff's teardown); under a swap file's i_rwsem
static SWAPON: crate::sync::Mutex<()> = crate::sync::Mutex::new(());

/// A swap type swapon reserved (Linux alloc_swap_info: SWP_USED under
/// swap_lock), given back on drop (Linux bad_swap: flags = 0 under
/// swap_lock, after the area's resources are freed) unless enabled
struct SwapType(u8);

impl SwapType {
    /// The lowest type not in use; EPERM if there is none
    fn alloc() -> KernelResult<Self> {
        let mut t = SWAP_INFO.write();
        let ty = (0..MAX_SWAPFILES)
            .find(|&i| t.used & (1 << i) == 0)
            .ok_or(KernelError::NotPermitted)?;
        t.used |= 1 << ty;
        Ok(Self(ty as u8))
    }

    /// The type stays in use, enabled, until swapoff frees it
    fn keep(self) {
        core::mem::forget(self);
    }
}

impl Drop for SwapType {
    fn drop(&mut self) {
        free_type(self.0);
    }
}

/// Give swap type `t` back (Linux: si->flags = 0 under swap_lock)
fn free_type(t: u8) {
    SWAP_INFO.write().used &= !(1 << t);
}

// ============================================================================
// SwapInfo - per-device state
// ============================================================================

/// Slot counts of a device (under `SwapInfo.map`)
struct SwapMap {
    /// Per slot: swap PTE count | SWAP_HAS_CACHE (0: free)
    count: Vec<u16>,
    /// Where the next allocation search starts
    next: u64,
}

/// A run of a swap file's slots on its device (Linux struct
/// swap_extent): slots `start_page..start_page + nr_pages` are the
/// device's pages from `start_block` on
#[derive(Clone, Copy)]
struct SwapExtent {
    start_page: u64,
    nr_pages: u64,
    start_block: u64,
}

/// One swap area (Linux swap_info_struct)
pub struct SwapInfo {
    /// Backing file (a swap file)
    pub inode: Option<InodeRef>,
    /// Backing block device (a swap partition)
    pub bdev: Option<crate::block::blkdev::BdevHandle>,
    /// A swap file's device, its filesystem's (Linux si->bdev =
    /// i_sb->s_bdev), and its slots' runs there, mapped at swapon and
    /// in slot order (Linux swap_extent_root)
    file_map: Option<(Arc<BlockDevice>, Vec<SwapExtent>)>,
    /// Device state (SWP_WRITEOK)
    flags: AtomicU32,
    /// Allocation priority (higher first)
    pub priority: i16,
    /// Index in SWAP_INFO
    pub swap_type: u8,
    /// One past the last usable slot (slot 0 is the header)
    pub max: u64,
    /// Slot counts (Linux si->lock + swap_map)
    map: Mutex<SwapMap>,
    /// Slots in use (counted or cached)
    pub inuse: AtomicU64,
    /// The swap cache: page frame by slot (Linux swapper_spaces
    /// i_pages, an IRQ-safe xarray lock); see `swap_state`
    pub(super) cache: IrqSpinlock<XArray>,
    /// Pages in the swap cache (meminfo SwapCached)
    pub(super) cached: AtomicU64,
    /// Its users, each a [`SwapDev`] (Linux si->users)
    users: PercpuRef,
    /// What swapon opened (Linux si->swap_file's path): its mount stays
    /// busy, so the swap file or device node outlives no mount of its
    /// filesystem (umount is EBUSY meanwhile). Last, so the inode and
    /// device go before it.
    swap_file: Option<crate::fs::Path>,
}

impl Drop for SwapInfo {
    /// Its backing goes (block device release, iput), which may sleep:
    /// only swapoff (or a failed swapon) drops the last `Arc`, after
    /// every user is gone (Linux swapoff: filp_close after the wait)
    fn drop(&mut self) {
        crate::sync::might_sleep();
    }
}

/// A use of a live swap device (Linux a `swap_info_struct *` from
/// get_swap_device): one count of its `users`, put on drop (Linux
/// put_swap_device)
///
/// # Invariants
/// Holds one count of the device's `users`, taken while `SWAP_INFO`
/// held the device; swapoff drops its `Arc`s only after `users` is
/// killed and drained, so the device outlives this.
pub struct SwapDev(NonNull<SwapInfo>);

impl core::ops::Deref for SwapDev {
    type Target = SwapInfo;

    fn deref(&self) -> &SwapInfo {
        // SAFETY: the type invariant keeps the device alive
        unsafe { self.0.as_ref() }
    }
}

impl Drop for SwapDev {
    fn drop(&mut self) {
        self.users.put();
    }
}

impl SwapInfo {
    /// The inode writes to which are ETXTBSY while active (Linux
    /// S_SWAPFILE): the swap file's, or the partition's bdev inode
    pub fn swapfile_inode(&self) -> &Inode {
        match (&self.inode, &self.bdev) {
            (Some(i), _) => i,
            (None, Some(b)) => &b.bd_inode,
            (None, None) => unreachable!("a swap area has a backing"),
        }
    }

    fn new(
        backing: (Option<InodeRef>, Option<crate::block::blkdev::BdevHandle>),
        file_map: Option<(Arc<BlockDevice>, Vec<SwapExtent>)>,
        swap_type: u8,
        max: u64,
        priority: i16,
    ) -> Result<Self, KernelError> {
        // A large sparse file may still ask for more than there is
        let mut count = Vec::new();
        count
            .try_reserve_exact(max as usize)
            .map_err(|_| KernelError::OutOfMemory)?;
        count.resize(max as usize, 0u16);
        // The header page is never handed out
        count[0] = SWAP_MAP_MAX;
        Ok(Self {
            inode: backing.0,
            bdev: backing.1,
            file_map,
            flags: AtomicU32::new(SWP_WRITEOK),
            priority,
            swap_type,
            max,
            map: Mutex::new(SwapMap { count, next: 1 }),
            inuse: AtomicU64::new(0),
            cache: IrqSpinlock::new(XArray::new()),
            cached: AtomicU64::new(0),
            users: PercpuRef::new()?,
            swap_file: None,
        })
    }

    fn writeok(&self) -> bool {
        self.flags.load(Ordering::Acquire) & SWP_WRITEOK != 0
    }

    /// Set or clear SWP_WRITEOK under `map` (alloc_slot checks it there)
    fn set_writeok(&self, on: bool) {
        let _m = self.map.lock();
        if on {
            self.flags.fetch_or(SWP_WRITEOK, Ordering::AcqRel);
        } else {
            self.flags.fetch_and(!SWP_WRITEOK, Ordering::AcqRel);
        }
    }

    /// Take a free slot, its count SWAP_HAS_CACHE (Linux
    /// scan_swap_map_slots). None once swapoff has begun: SWP_WRITEOK
    /// is cleared under `map`, so a slot taken here is counted in
    /// `inuse` before swapoff's scans start
    fn alloc_slot(&self) -> Option<u64> {
        let mut m = self.map.lock();
        if !self.writeok() {
            return None;
        }
        let from = m.next;
        let off = (from..self.max)
            .chain(1..from)
            .find(|&o| m.count[o as usize] == 0)?;
        m.count[off as usize] = SWAP_HAS_CACHE;
        m.next = off + 1;
        self.used(1);
        Some(off)
    }

    /// Change the count of slot `off` with `f` (None: refused), freeing
    /// it when it drops to 0: the new count
    fn update(&self, off: u64, f: impl FnOnce(u16) -> Option<u16>) -> Option<u16> {
        if off == 0 || off >= self.max {
            return None;
        }
        let mut m = self.map.lock();
        let c = &mut m.count[off as usize];
        let new = f(*c)?;
        let freed = *c != 0 && new == 0;
        *c = new;
        if freed {
            self.used(-1);
            if off < m.next {
                m.next = off;
            }
        }
        Some(new)
    }

    /// Account `n` slots taken (or given back)
    fn used(&self, n: i64) {
        self.inuse.fetch_add(n as u64, Ordering::Relaxed);
        TOTAL_SWAP_USED.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// SWAP_HAS_CACHE is set on slot `off`
    pub fn has_cache(&self, off: u64) -> bool {
        off < self.max && self.map.lock().count[off as usize] & SWAP_HAS_CACHE != 0
    }

    /// Swap PTEs referencing slot `off`
    pub fn count(&self, off: u64) -> u16 {
        if off >= self.max {
            return 0;
        }
        self.map.lock().count[off as usize] & !SWAP_HAS_CACHE
    }
}

// ============================================================================
// Swap device lookup
// ============================================================================

/// A use of the device of swap type `t`, unless there is none or
/// swapoff is tearing it down (Linux get_swap_device_info)
fn get_device(t: u8) -> Option<SwapDev> {
    let tbl = SWAP_INFO.read();
    let si = tbl.dev.get(t as usize)?.as_ref()?;
    // Counted while the table holds it: swapoff kills `users` before
    // it lets go
    si.users
        .tryget_live()
        .then(|| SwapDev(NonNull::from(&**si)))
}

/// A use of the device of `e`, keeping it from swapoff's teardown
/// until dropped (Linux get_swap_device): None for an invalid entry,
/// no device, a device going away, or an offset past its end
pub fn get_swap_device(e: SwapEntry) -> Option<SwapDev> {
    if !e.is_valid() {
        return None;
    }
    let si = get_device(e.swap_type())?;
    (e.offset() < si.max).then_some(si)
}

/// The inode whose mapping a swap area at `inode` uses (Linux
/// file->f_mapping->host): a block device node's device inode, else
/// the file's own
fn mapping_host(inode: InodeRef) -> KernelResult<InodeRef> {
    if !inode.mode().is_blkdev() {
        return Ok(inode);
    }
    let b = crate::block::get_blkdev(inode.rdev).ok_or(KernelError::NoDeviceOrAddress)?;
    Ok(b.bd_inode.clone())
}

// ============================================================================
// Slot references (Linux swap_duplicate, swap_free, ...)
// ============================================================================

/// A free slot for a page entering the swap cache, its count
/// SWAP_HAS_CACHE (Linux folio_alloc_swap): the writable device of
/// highest priority with room
pub fn get_swap_page() -> Option<SwapEntry> {
    // Each device's priority (no reference kept past the table's lock),
    // then the usable ones in priority order, each in use while a slot
    // is taken from it (Linux swap_alloc_slow: get_swap_device_info)
    let mut prio: [Option<i16>; MAX_SWAPFILES] = [None; MAX_SWAPFILES];
    for (p, d) in prio.iter_mut().zip(SWAP_INFO.read().dev.iter()) {
        *p = d.as_ref().map(|s| s.priority);
    }
    loop {
        let best = prio
            .iter()
            .enumerate()
            .filter_map(|(i, p)| p.map(|p| (i, p)))
            // Equal priorities: the lower type first, as before
            .max_by_key(|&(i, p)| (p, core::cmp::Reverse(i)))?
            .0;
        prio[best] = None;
        let Some(si) = get_device(best as u8) else {
            continue;
        };
        if !si.writeok() {
            continue;
        }
        if let Some(off) = si.alloc_slot() {
            return Some(SwapEntry::new(si.swap_type, off));
        }
    }
}

/// One more swap PTE references `e` (Linux swap_duplicate: fork, and
/// reclaim replacing a PTE); false if the slot is free or its count is
/// full (the caller fails with ENOMEM)
pub fn swap_duplicate(e: SwapEntry) -> bool {
    let Some(si) = get_swap_device(e) else {
        return false;
    };
    si.update(e.offset(), |c| {
        let n = c & !SWAP_HAS_CACHE;
        (c != 0 && n < SWAP_MAP_MAX).then_some(c + 1)
    })
    .is_some()
}

/// A swap PTE referencing `e` went (Linux swap_free): the slot is freed
/// with its last reference; the new count (cache bit included)
pub fn swap_free(e: SwapEntry) -> u16 {
    let Some(si) = get_swap_device(e) else {
        return 0;
    };
    si.update(e.offset(), |c| (c & !SWAP_HAS_CACHE != 0).then(|| c - 1))
        .unwrap_or(0)
}

/// Claim the slot for a page about to be read into the swap cache
/// (Linux swapcache_prepare): Err(true) if a cache page already stands
/// for it (another reader), Err(false) if no PTE references it any more
pub fn swapcache_prepare(e: SwapEntry) -> Result<(), bool> {
    let si = get_swap_device(e).ok_or(false)?;
    let mut busy = false;
    si.update(e.offset(), |c| {
        busy = c & SWAP_HAS_CACHE != 0;
        (!busy && c != 0).then_some(c | SWAP_HAS_CACHE)
    })
    .map(|_| ())
    .ok_or(busy)
}

/// The swap-cache page of `e` is gone (Linux put_swap_folio /
/// swapcache_clear): the slot is freed if no PTE references it
pub fn swapcache_clear(e: SwapEntry) {
    if let Some(si) = get_swap_device(e) {
        si.update(e.offset(), |c| Some(c & !SWAP_HAS_CACHE));
    }
    // A reader waiting for the claim to settle looks again
    swap_wait(e).wake_all();
}

/// Another task claimed `e` for the swap cache (SWAP_HAS_CACHE) and
/// has not put its page there yet: `read_swap_page` waits on this
pub fn swap_wait(e: SwapEntry) -> &'static crate::sync::waitqueue::WaitQueue {
    // Hashed like the page wait table (Linux folio_waitqueue)
    crate::sync::waitqueue::page_wait_queue(e.raw() << 12)
}

/// SWAP_HAS_CACHE is set on `e`
pub fn swapcache_busy(e: SwapEntry) -> bool {
    get_swap_device(e).is_some_and(|si| si.has_cache(e.offset()))
}

/// Swap PTEs referencing `e` (Linux swp_swapcount)
pub fn swap_count(e: SwapEntry) -> u16 {
    get_swap_device(e).map_or(0, |si| si.count(e.offset()))
}

/// A swap PTE was zapped (munmap, exit; Linux free_swap_and_cache): its
/// reference goes, and a swap-cache page no PTE needs any more is
/// dropped with the slot
pub fn free_swap_and_cache(e: SwapEntry) {
    if swap_free(e) == SWAP_HAS_CACHE {
        super::swap_state::try_reclaim_swap(e);
    }
}

// ============================================================================
// Swap I/O
// ============================================================================

/// The device and first sector of slot `off` (Linux swap_page_sector:
/// a swap file's through its extents); None past them
fn swap_page_sector(si: &SwapInfo, off: u64) -> Option<(&BlockDevice, u64)> {
    if let Some(b) = &si.bdev {
        return Some((b, off * SECTORS_PER_PAGE));
    }
    let (bdev, ext) = si.file_map.as_ref()?;
    Some((bdev, extent_block(ext, off)? * SECTORS_PER_PAGE))
}

/// The device page of slot `off` in a swap file's extents (Linux
/// offset_to_swap_extent)
fn extent_block(ext: &[SwapExtent], off: u64) -> Option<u64> {
    let i = ext.partition_point(|e| e.start_page + e.nr_pages <= off);
    let e = ext.get(i).filter(|e| e.start_page <= off)?;
    Some(e.start_block + off - e.start_page)
}

/// Transfer slot `entry` and the frame at `frame_phys` (may sleep):
/// straight to the disk, a swap file's too (Linux swap_read_folio_bdev,
/// __swap_writepage)
fn swap_rw_frame(entry: SwapEntry, op: BioOp, frame_phys: u64) -> KernelResult<()> {
    let si = get_swap_device(entry).ok_or(KernelError::InvalidArgument)?;
    let (bdev, sector) =
        swap_page_sector(&si, entry.offset()).ok_or(KernelError::InvalidArgument)?;
    bdev_rw_frame(bdev, op, sector, frame_phys)
}

/// Read slot `entry` into the frame at `frame_phys` (may sleep)
pub fn swap_read_page(entry: SwapEntry, frame_phys: u64) -> KernelResult<()> {
    swap_rw_frame(entry, BioOp::Read, frame_phys)
}

/// Write the frame at `frame_phys` to slot `entry` (may sleep)
pub fn swap_write_page(entry: SwapEntry, frame_phys: u64) -> KernelResult<()> {
    // Allocations on the way to the device (bio, buffers, the file's
    // own) must not reclaim through swap I/O again (Linux: swap_writepage
    // under memalloc_noio / PF_MEMALLOC)
    crate::mm::memalloc_scope(crate::task::pf::MEMALLOC_NOIO, || {
        swap_rw_frame(entry, BioOp::Write, frame_phys)
    })
}

// ============================================================================
// swapon/swapoff syscalls
// ============================================================================

/// The path argument of swapon/swapoff
fn user_path(p: UserPtr<u8>) -> KernelResult<alloc::vec::Vec<u8>> {
    crate::fs::namei::getname(p, false)
}

/// The slots of the area whose header page is `hdr` on a file or
/// device of `size` pages: one past the last usable one (Linux
/// read_swap_header: last_page is the last usable page; 0, or an area
/// longer than the file or device, is EINVAL, not clamped)
fn parse_header(hdr: &[u8; PAGE_SIZE], size: u64) -> Result<u64, KernelError> {
    if &hdr[SWAP_MAGIC_OFFSET..SWAP_MAGIC_OFFSET + 10] != SWAP_MAGIC {
        return Err(KernelError::InvalidArgument);
    }
    // SAFETY: the header info lies inside the page; read unaligned
    let info = unsafe {
        core::ptr::read_unaligned(
            hdr[SWAP_HEADER_INFO_OFFSET..]
                .as_ptr()
                .cast::<SwapHeaderInfo>(),
        )
    };
    let max = u64::from(info.last_page) + 1;
    if info.version != 1 || info.last_page == 0 || max > size {
        return Err(KernelError::InvalidArgument);
    }
    Ok(max)
}

/// A swap area's header page, read through the page cache of its file
/// or device inode (Linux read_mapping_folio); `hdr` is a page long
fn read_header(inode: &Inode, hdr: &mut [u8]) -> Result<(), KernelError> {
    let phys = crate::mm::filemap::read_page(inode, 0)?;
    assert!(hdr.len() <= PAGE_SIZE);
    // SAFETY: a page-cache page our reference keeps allocated; `hdr`
    // is at most a page
    unsafe { crate::mm::page::copy_from_frame_racy(hdr, phys, 0) };
    crate::mm::filemap::put_page(phys);
    Ok(())
}

/// Add slots `start_page..start_page + nr_pages` at device page
/// `start_block` to a swap file's extents (Linux add_swap_extent),
/// merged into the last one if they continue it
fn add_swap_extent(
    ext: &mut Vec<SwapExtent>,
    start_page: u64,
    nr_pages: u64,
    start_block: u64,
) -> Result<(), KernelError> {
    if let Some(l) = ext.last_mut()
        && l.start_page + l.nr_pages == start_page
        && l.start_block + l.nr_pages == start_block
    {
        l.nr_pages += nr_pages;
        return Ok(());
    }
    ext.try_reserve(1).map_err(|_| KernelError::OutOfMemory)?;
    ext.push(SwapExtent {
        start_page,
        nr_pages,
        start_block,
    });
    Ok(())
}

/// The device block of a swap file's block `block` (Linux bmap): EINVAL
/// for a hole or a file without ->bmap ("swapfile has holes")
fn swap_bmap(inode: &Inode, block: u64) -> Result<u64, KernelError> {
    match inode.i_data.aops().bmap(inode, block) {
        Ok(b) if b != 0 => Ok(b),
        _ => {
            crate::printkln!("swapon: swapfile has holes");
            Err(KernelError::InvalidArgument)
        }
    }
}

/// Map a swap file's pages to its device (Linux
/// generic_swapfile_activate, under i_rwsem): every page-sized run of
/// its blocks that is contiguous and page-aligned on the disk is a
/// slot, in file order, up to `max` (a misaligned or broken run is
/// skipped a block at a time). The extents and the slots mapped (at
/// least 1, so an empty file is "Empty swap-file").
fn generic_swapfile_activate(
    inode: &Inode,
    max: u64,
) -> Result<(Vec<SwapExtent>, u64), KernelError> {
    let blkbits = inode.blkbits();
    let blocks_per_page = (PAGE_SIZE >> blkbits) as u64;
    let last_block = inode.get_size() >> blkbits;
    let mut ext = Vec::new();
    let (mut probe_block, mut page_no) = (0, 0);
    'probe: while probe_block + blocks_per_page <= last_block && page_no < max {
        crate::task::percpu::cond_resched();
        let first_block = swap_bmap(inode, probe_block)?;
        // It must be PAGE_SIZE aligned on-disk
        if first_block & (blocks_per_page - 1) != 0 {
            probe_block += 1;
            continue;
        }
        for block_in_page in 1..blocks_per_page {
            if swap_bmap(inode, probe_block + block_in_page)? != first_block + block_in_page {
                // Discontiguity
                probe_block += 1;
                continue 'probe;
            }
        }
        add_swap_extent(&mut ext, page_no, 1, first_block >> (PAGE_SHIFT - blkbits))?;
        page_no += 1;
        probe_block += blocks_per_page;
    }
    Ok((ext, page_no.max(1)))
}

/// swapon(2): activate a swap partition or file (Linux
/// SYSCALL_DEFINE2(swapon)). Under its mapping host's i_rwsem (the
/// file's inode, or a device's bdev inode): an active swap area is
/// EBUSY (IS_SWAPFILE, whatever path reached it), the header is read
/// through the page cache, a file's pages are mapped to its disk, and
/// S_SWAPFILE is set before its writes are drained, so no write or
/// truncate of the file runs from the mapping to the swap's end. The
/// type is reserved first (Linux alloc_swap_info), the area published
/// under `SWAPON` inside the i_rwsem (enable_swap_info). Unknown flags
/// are EINVAL before anything else.
pub fn sys_swapon(path: UserPtr<u8>, swap_flags: i32) -> KernelResult<()> {
    if swap_flags & !SWAP_FLAGS_VALID != 0 {
        return Err(KernelError::InvalidArgument);
    }
    if !capable(CAP_SYS_ADMIN) {
        return Err(KernelError::NotPermitted);
    }
    // Given back after everything below is released (dropped last)
    let ty = SwapType::alloc()?;
    let swap_type = ty.0;
    let path = user_path(path)?;
    let swap_file =
        crate::fs::namei::path_lookup(crate::fs::namei::Start::Cwd, &path, LookupFlags::open())
            .map_err(|_| KernelError::NotFound)?;
    let node = swap_file.dentry.get_inode().ok_or(KernelError::NotFound)?;
    // claim_swapfile: a block device opened and claimed for the swap's
    // life (Linux file_open_name O_EXCL: holder the swap area, EBUSY if
    // another holder has it); the holder is the type's slot, unique
    // while the area exists. A file swaps to its filesystem's device.
    let bdev = if node.mode().is_blkdev() {
        let b = crate::block::get_blkdev(node.rdev).ok_or(KernelError::NoDeviceOrAddress)?;
        let slot = core::ptr::from_ref(&SWAP_INFO) as usize + usize::from(swap_type);
        Some(b.open_handle(Some(slot))?)
    } else {
        None
    };
    let inode = match &bdev {
        Some(b) => b.bd_inode.clone(),
        None => node,
    };
    let lock = inode.lock();
    if swap_file.dentry.d_unlinked() {
        return Err(KernelError::NotFound);
    }
    if inode.is_swapfile() {
        return Err(KernelError::Busy);
    }
    // Read the swap header (Linux read_mapping_folio), off the stack
    let mut hdr = crate::util::kmem::try_vec(PAGE_SIZE, 0u8)?;
    read_header(&inode, &mut hdr)?;
    // No slots past the end of the file or device (Linux
    // read_swap_header: i_size of either)
    let size = bdev
        .as_ref()
        .map_or(inode.get_size() / PAGE_SIZE as u64, |b| {
            b.nr_sects() / SECTORS_PER_PAGE
        });
    let hdr =
        <&[u8; PAGE_SIZE]>::try_from(hdr.as_slice()).map_err(|_| KernelError::InvalidArgument)?;
    let mut max = parse_header(hdr, size)?;
    // setup_swap_extents: a file's pages mapped to its disk
    let file_map = match &bdev {
        Some(_) => None,
        None => {
            let (ext, pages) = generic_swapfile_activate(&inode, max)?;
            max = pages;
            let sb = inode.superblock().ok_or(KernelError::InvalidArgument)?;
            let b = sb.bdev().ok_or(KernelError::InvalidArgument)?.clone();
            Some((b, ext))
        }
    };
    // No usable slot past the header (Linux "Empty swap-file")
    if max <= 1 {
        return Err(KernelError::InvalidArgument);
    }
    let priority = if swap_flags & SWAP_FLAG_PREFER != 0 {
        (swap_flags & SWAP_FLAG_PRIO_MASK) as i16
    } else {
        -1
    };
    // Allocated before it takes its backing, whose release (a device's
    // close, an iput) a failure leaves for after the unlock (Linux
    // bad_swap: filp_close after inode_unlock)
    let mut si = try_arc(SwapInfo::new(
        (None, None),
        file_map,
        swap_type,
        max,
        priority,
    )?)?;
    let s = Arc::get_mut(&mut si).expect("swapon: a new area is unshared");
    (s.inode, s.bdev) = match bdev {
        Some(b) => (None, Some(b)),
        None => (Some(inode.clone()), None),
    };
    s.swap_file = Some(swap_file);
    // Flush any pending I/O and dirty pages before the area is used
    // (Linux: S_SWAPFILE, then inode_drain_writes)
    inode.set_swapfile(true);
    if let Err(e) = inode_drain_writes(&inode) {
        inode.set_swapfile(false);
        drop(lock);
        drop(si);
        return Err(e);
    }
    // Linux enable_swap_info, under swapon_mutex
    let g = SWAPON.lock();
    SWAP_INFO.write().dev[swap_type as usize] = Some(si);
    TOTAL_SWAP_PAGES.fetch_add(max - 1, Ordering::Relaxed);
    drop(g);
    ty.keep();
    drop(lock);
    Ok(())
}

/// Wait out direct I/O and write back the dirty pages of `inode`
/// (Linux inode_drain_writes); the caller holds its i_rwsem
fn inode_drain_writes(inode: &Inode) -> KernelResult<()> {
    inode.inode_dio_wait();
    crate::mm::filemap::write_and_wait(inode)
}

/// The enabled device whose swap file (or device inode) is `inode`,
/// SWP_WRITEOK taken from it so no other swapoff finds it (Linux
/// swapoff under swap_lock: p->swap_file->f_mapping == mapping among
/// the SWP_WRITEOK areas, then del_from_avail_list under si->lock)
fn swapoff_find(inode: &Inode) -> Option<Arc<SwapInfo>> {
    let tbl = SWAP_INFO.write();
    let si = tbl
        .dev
        .iter()
        .flatten()
        .find(|si| si.writeok() && core::ptr::eq(si.swapfile_inode(), inode))?;
    si.set_writeok(false);
    Some(si.clone())
}

/// swapoff(2): bring every page of a swap area back into memory and
/// deactivate it (Linux try_to_unuse), with no swapoff lock held while
/// it empties the device
pub fn sys_swapoff(path: UserPtr<u8>) -> KernelResult<()> {
    if !capable(CAP_SYS_ADMIN) {
        return Err(KernelError::NotPermitted);
    }
    let path = user_path(path)?;
    // A nonexistent file is ENOENT, an existing non-swap file EINVAL;
    // the area is found by its mapping, whatever path names it (Linux
    // swapoff: file_open_name, then f_mapping)
    let dentry = lookup_path(&path)?;
    let victim = mapping_host(dentry.get_inode().ok_or(KernelError::NotFound)?)?;
    // No new slots from it (an allocator past get_swap_page's filter
    // rechecks under `map`); only this swapoff takes it out of the table
    let si = swapoff_find(&victim).ok_or(KernelError::InvalidArgument)?;
    let t = si.swap_type;
    if let Err(e) = super::swap_state::try_to_unuse(&si) {
        // Linux reinsert_swap_info, under swap_lock
        let _tbl = SWAP_INFO.write();
        si.set_writeok(true);
        return Err(e);
    }
    // Wait for every use of the device to end (Linux percpu_ref_kill,
    // synchronize_rcu, wait_for_completion(&p->comp)): from here the
    // last `Arc`s are the table's and this one, dropped below, so the
    // device is released here, in process context
    si.users.kill();
    si.users.wait();
    let table = {
        let _g = SWAPON.lock();
        SWAP_INFO.write().dev[t as usize].take()
    };
    let si_inode = si.swapfile_inode();
    let lock = si_inode.lock();
    si_inode.set_swapfile(false);
    drop(lock);
    TOTAL_SWAP_PAGES.fetch_sub(si.max - 1, Ordering::Relaxed);
    super::swap_state::destroy_cache(&si);
    drop(table);
    debug_assert_eq!(
        Arc::strong_count(&si),
        1,
        "swapoff: device still referenced"
    );
    drop(si);
    // Last: a new area of this type may claim a device with its holder
    free_type(t);
    Ok(())
}

/// Over half of swap is in use (Linux vm_swap_full): a page read back
/// gives its slot up at once rather than keep a clean copy
pub fn swap_full() -> bool {
    let (total, free) = swap_totals();
    free * 2 < total
}

/// Swap totals in pages: (total, free) (meminfo, sysinfo)
pub fn swap_totals() -> (u64, u64) {
    let total = TOTAL_SWAP_PAGES.load(Ordering::Relaxed);
    let used = TOTAL_SWAP_USED.load(Ordering::Relaxed);
    (total, total.saturating_sub(used))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(last_page: u32, version: u32) -> [u8; PAGE_SIZE] {
        let mut h = [0u8; PAGE_SIZE];
        h[SWAP_MAGIC_OFFSET..SWAP_MAGIC_OFFSET + 10].copy_from_slice(SWAP_MAGIC);
        h[1024..1028].copy_from_slice(&version.to_le_bytes());
        h[1028..1032].copy_from_slice(&last_page.to_le_bytes());
        h
    }

    #[test]
    fn header_sizes_the_area() {
        // mkswap of 64MB: last_page 16383, slots 1..=16383
        assert_eq!(parse_header(&hdr(16383, 1), u64::MAX), Ok(16384));
        assert!(parse_header(&hdr(16383, 1), 1000).is_err());
        assert_eq!(parse_header(&hdr(16383, 1), 16384), Ok(16384));
        assert!(parse_header(&hdr(16383, 2), u64::MAX).is_err());
        assert!(parse_header(&hdr(0, 1), u64::MAX).is_err());
        let mut bad = hdr(10, 1);
        bad[SWAP_MAGIC_OFFSET] = b'X';
        assert!(parse_header(&bad, u64::MAX).is_err());
    }

    #[test]
    fn slot_counts_and_cache_bit() {
        let si = SwapInfo::new((None, None), None, 0, 4, 0).unwrap();
        let a = si.alloc_slot().unwrap();
        let b = si.alloc_slot().unwrap();
        assert_eq!((a, b), (1, 2));
        assert_eq!(si.inuse.load(Ordering::Relaxed), 2);
        // A PTE took the slot, then the cache let go: one reference left
        assert_eq!(si.update(a, |c| Some(c + 1)), Some(SWAP_HAS_CACHE | 1));
        assert_eq!(si.update(a, |c| Some(c & !SWAP_HAS_CACHE)), Some(1));
        assert_eq!(si.count(a), 1);
        // The last reference frees it; it is handed out again first
        assert_eq!(si.update(a, |c| Some(c - 1)), Some(0));
        assert_eq!(si.inuse.load(Ordering::Relaxed), 1);
        assert_eq!(si.alloc_slot(), Some(1));
        assert_eq!(si.alloc_slot(), Some(3));
        assert_eq!(si.alloc_slot(), None);
        // The header slot is never touched
        assert_eq!(si.update(0, |_| Some(0)), None);
    }

    #[test]
    fn swap_extents() {
        let mut ext = Vec::new();
        // Pages 0..3 at device pages 10..13, then 3 at 20, 4 at 21
        for (page, block) in [(0, 10), (1, 11), (2, 12), (3, 20), (4, 21)] {
            add_swap_extent(&mut ext, page, 1, block).unwrap();
        }
        assert_eq!(ext.len(), 2);
        let got: Vec<_> = (0..6).map(|o| extent_block(&ext, o)).collect();
        assert_eq!(
            got,
            [Some(10), Some(11), Some(12), Some(20), Some(21), None]
        );
    }
}
