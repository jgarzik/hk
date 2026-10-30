//! Swap devices and swap slots (Linux mm/swapfile.c)
//!
//! A swap area (a partition, or a file through its inode) is a
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
//! spin `RwLock`, read mostly) holds the devices; `SWAPON` (a sleeping
//! `Mutex`) serializes swapon and swapoff.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::sync::spin::{Mutex, RwLock};

use crate::arch::{IrqSpinlock, Uaccess};
use crate::error::KernelError;
use crate::fs::{Inode, lookup_path};
use crate::mm::page_cache::PAGE_SIZE;
use crate::mm::swap_entry::{MAX_SWAPFILES, SwapEntry};
use crate::mm::xarray::XArray;
use crate::storage::BlockDevice;
use crate::storage::blkdev::{BioOp, bdev_rw, bdev_rw_frame};
use crate::task::{CAP_SYS_ADMIN, capable};
use crate::uaccess::strncpy_from_user;

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

/// Active swap devices, by type
pub static SWAP_INFO: RwLock<[Option<Arc<SwapInfo>>; MAX_SWAPFILES]> =
    RwLock::new([const { None }; MAX_SWAPFILES]);

/// Usable slots of every device (Linux total_swap_pages)
pub static TOTAL_SWAP_PAGES: AtomicU64 = AtomicU64::new(0);

/// Slots in use (counted or cached)
pub static TOTAL_SWAP_USED: AtomicU64 = AtomicU64::new(0);

/// swapon and swapoff, one at a time (Linux swapon_mutex)
static SWAPON: crate::sync::Mutex<()> = crate::sync::Mutex::new(());

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

/// One swap area (Linux swap_info_struct)
pub struct SwapInfo {
    /// Backing file (a swap file)
    pub inode: Option<Arc<Inode>>,
    /// Backing block device (a swap partition)
    pub bdev: Option<Arc<BlockDevice>>,
    /// Path given to swapon
    pub path: Vec<u8>,
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
}

impl SwapInfo {
    fn new(
        backing: (Option<Arc<Inode>>, Option<Arc<BlockDevice>>),
        path: Vec<u8>,
        swap_type: u8,
        max: u64,
        priority: i16,
    ) -> Self {
        let mut count = vec![0u16; max as usize];
        // The header page is never handed out
        count[0] = SWAP_MAP_MAX;
        Self {
            inode: backing.0,
            bdev: backing.1,
            path,
            flags: AtomicU32::new(SWP_WRITEOK),
            priority,
            swap_type,
            max,
            map: Mutex::new(SwapMap { count, next: 1 }),
            inuse: AtomicU64::new(0),
            cache: IrqSpinlock::new(XArray::new()),
            cached: AtomicU64::new(0),
        }
    }

    fn writeok(&self) -> bool {
        self.flags.load(Ordering::Acquire) & SWP_WRITEOK != 0
    }

    /// Take a free slot, its count SWAP_HAS_CACHE (Linux
    /// scan_swap_map_slots)
    fn alloc_slot(&self) -> Option<u64> {
        let mut m = self.map.lock();
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

/// The device of swap type `t`
pub fn get_swap_info(t: u8) -> Option<Arc<SwapInfo>> {
    SWAP_INFO.read().get(t as usize)?.clone()
}

/// The device of `e`
fn info_of(e: SwapEntry) -> Option<Arc<SwapInfo>> {
    e.is_valid().then(|| get_swap_info(e.swap_type()))?
}

/// The type of the device at `path`
fn find_swap_by_path(path: &[u8]) -> Option<u8> {
    let info = SWAP_INFO.read();
    info.iter()
        .flatten()
        .find(|si| si.path == path)
        .map(|si| si.swap_type)
}

// ============================================================================
// Slot references (Linux swap_duplicate, swap_free, ...)
// ============================================================================

/// A free slot for a page entering the swap cache, its count
/// SWAP_HAS_CACHE (Linux folio_alloc_swap): the writable device of
/// highest priority with room
///
/// Direct reclaim (PF_MEMALLOC) takes only block-device areas: a swap
/// file's pages go out through its filesystem's writepage, which may
/// need locks the allocating task holds (Linux maps a swap file's
/// blocks at swapon and bypasses the filesystem)
pub fn get_swap_page() -> Option<SwapEntry> {
    let reclaiming = crate::task::percpu::current().has_flag(crate::task::pf::MEMALLOC);
    let devs: Vec<Arc<SwapInfo>> = SWAP_INFO.read().iter().flatten().cloned().collect();
    let mut devs: Vec<_> = devs
        .into_iter()
        .filter(|s| s.writeok() && !(reclaiming && s.inode.is_some()))
        .collect();
    devs.sort_by_key(|s| core::cmp::Reverse(s.priority));
    devs.iter()
        .find_map(|si| si.alloc_slot().map(|off| SwapEntry::new(si.swap_type, off)))
}

/// One more swap PTE references `e` (Linux swap_duplicate: fork, and
/// reclaim replacing a PTE); false if the slot is free or its count is
/// full (the caller fails with ENOMEM)
pub fn swap_duplicate(e: SwapEntry) -> bool {
    let Some(si) = info_of(e) else {
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
    let Some(si) = info_of(e) else {
        return 0;
    };
    si.update(e.offset(), |c| (c & !SWAP_HAS_CACHE != 0).then(|| c - 1))
        .unwrap_or(0)
}

/// Claim the slot for a page about to be read into the swap cache
/// (Linux swapcache_prepare): Err(true) if a cache page already stands
/// for it (another reader), Err(false) if no PTE references it any more
pub fn swapcache_prepare(e: SwapEntry) -> Result<(), bool> {
    let si = info_of(e).ok_or(false)?;
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
    if let Some(si) = info_of(e) {
        si.update(e.offset(), |c| Some(c & !SWAP_HAS_CACHE));
    }
    // A reader waiting for the claim to settle looks again
    swap_wait(e).wake_all();
}

/// Another task claimed `e` for the swap cache (SWAP_HAS_CACHE) and
/// has not put its page there yet: `read_swap_page` waits on this
pub fn swap_wait(e: SwapEntry) -> &'static crate::waitqueue::WaitQueue {
    // Hashed like the page wait table (Linux folio_waitqueue)
    crate::waitqueue::page_wait_queue(e.raw() << 12)
}

/// SWAP_HAS_CACHE is set on `e`
pub fn swapcache_busy(e: SwapEntry) -> bool {
    info_of(e).is_some_and(|si| si.has_cache(e.offset()))
}

/// Swap PTEs referencing `e` (Linux swp_swapcount)
pub fn swap_count(e: SwapEntry) -> u16 {
    info_of(e).map_or(0, |si| si.count(e.offset()))
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

/// Read slot `entry` into the frame at `frame_phys` (may sleep)
pub fn swap_read_page(entry: SwapEntry, frame_phys: u64) -> Result<(), i64> {
    let si = info_of(entry).ok_or(KernelError::InvalidArgument.sysret())?;
    let off = entry.offset();
    if let Some(ref inode) = si.inode {
        let mut buf = alloc::vec![0u8; PAGE_SIZE];
        let n = inode
            .i_op
            .readpage(inode, off, &mut buf)
            .map_err(|_| KernelError::Io.sysret())?;
        buf[n.min(PAGE_SIZE)..].fill(0);
        // SAFETY: the caller's frame, reached through the direct map
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                crate::arch::phys_to_virt(frame_phys),
                PAGE_SIZE,
            )
        };
        Ok(())
    } else if let Some(ref bdev) = si.bdev {
        bdev_rw_frame(bdev, BioOp::Read, off * SECTORS_PER_PAGE, frame_phys).map_err(|e| e.sysret())
    } else {
        Err(KernelError::InvalidArgument.sysret())
    }
}

/// Write the frame at `frame_phys` to slot `entry` (may sleep)
pub fn swap_write_page(entry: SwapEntry, frame_phys: u64) -> Result<(), i64> {
    // Allocations on the way to the device (bio, buffers, the file's
    // own) must not reclaim through swap I/O again (Linux: swap_writepage
    // under memalloc_noio / PF_MEMALLOC)
    super::memalloc_scope(crate::task::pf::MEMALLOC_NOIO, || {
        write_page(entry, frame_phys)
    })
}

/// `swap_write_page` with PF_MEMALLOC_NOIO set
fn write_page(entry: SwapEntry, frame_phys: u64) -> Result<(), i64> {
    let si = info_of(entry).ok_or(KernelError::InvalidArgument.sysret())?;
    let off = entry.offset();
    if let Some(ref inode) = si.inode {
        // Not from direct reclaim (PF_MEMALLOC): the file's writepage may
        // need filesystem locks the allocating task holds. A page already
        // in the swap cache of a swap file stays dirty and in memory.
        if crate::task::percpu::current().has_flag(crate::task::pf::MEMALLOC) {
            return Err(KernelError::WouldBlock.sysret());
        }
        let mut buf = alloc::vec![0u8; PAGE_SIZE];
        // SAFETY: the caller's frame, reached through the direct map
        unsafe {
            core::ptr::copy_nonoverlapping(
                crate::arch::phys_to_virt(frame_phys),
                buf.as_mut_ptr(),
                PAGE_SIZE,
            )
        };
        let n = inode
            .i_op
            .writepage(inode, off, &buf)
            .map_err(|_| KernelError::Io.sysret())?;
        if n != PAGE_SIZE {
            return Err(KernelError::Io.sysret());
        }
        Ok(())
    } else if let Some(ref bdev) = si.bdev {
        bdev_rw_frame(bdev, BioOp::Write, off * SECTORS_PER_PAGE, frame_phys)
            .map_err(|e| e.sysret())
    } else {
        Err(KernelError::InvalidArgument.sysret())
    }
}

// ============================================================================
// swapon/swapoff syscalls
// ============================================================================

/// The path argument of swapon/swapoff
fn user_path(ptr: u64) -> Result<alloc::string::String, KernelError> {
    strncpy_from_user::<Uaccess>(ptr, 4096).map_err(|_| KernelError::BadAddress)
}

/// The slots of the area whose header page is `hdr`, at most `cap`
/// (the device size): one past the last usable one (Linux
/// read_swap_header: last_page is the last usable page)
fn parse_header(hdr: &[u8; PAGE_SIZE], cap: u64) -> Result<u64, KernelError> {
    if &hdr[SWAP_MAGIC_OFFSET..SWAP_MAGIC_OFFSET + 10] != SWAP_MAGIC {
        return Err(KernelError::InvalidArgument);
    }
    // SAFETY: the header info lies inside the page; read unaligned
    let info = unsafe {
        core::ptr::read_unaligned(hdr[SWAP_HEADER_INFO_OFFSET..].as_ptr() as *const SwapHeaderInfo)
    };
    let max = (info.last_page as u64 + 1).min(cap);
    if info.version != 1 || max < 2 {
        return Err(KernelError::InvalidArgument);
    }
    Ok(max)
}

/// swapon(2): activate a swap partition or file
pub fn sys_swapon(path_ptr: u64, swap_flags: i32) -> i64 {
    match swapon(path_ptr, swap_flags) {
        Ok(()) => 0,
        Err(e) => e.sysret(),
    }
}

fn swapon(path_ptr: u64, swap_flags: i32) -> Result<(), KernelError> {
    if !capable(CAP_SYS_ADMIN) {
        return Err(KernelError::NotPermitted);
    }
    let path = user_path(path_ptr)?;
    let inode = lookup_path(&path)
        .map_err(|_| KernelError::NotFound)?
        .get_inode()
        .ok_or(KernelError::NotFound)?;
    let _g = SWAPON.lock();
    if find_swap_by_path(path.as_bytes()).is_some() {
        return Err(KernelError::Busy);
    }
    let swap_type = SWAP_INFO
        .read()
        .iter()
        .position(|s| s.is_none())
        .ok_or(KernelError::Busy)? as u8;
    // A block device swaps through bios, a file through its inode
    let bdev = if inode.mode().is_blkdev() {
        Some(crate::storage::get_blkdev(inode.rdev).ok_or(KernelError::NoDeviceOrAddress)?)
    } else {
        None
    };
    let mut hdr = [0u8; PAGE_SIZE];
    let read = match &bdev {
        Some(b) => bdev_rw(b, BioOp::Read, 0, &mut hdr).map(|_| PAGE_SIZE),
        None => inode.i_op.readpage(&inode, 0, &mut hdr),
    };
    if read.unwrap_or(0) < PAGE_SIZE {
        return Err(KernelError::InvalidArgument);
    }
    // No slots past the end of the device (Linux read_swap_header)
    let cap = bdev
        .as_ref()
        .map_or(u64::MAX, |b| b.nr_sects() / SECTORS_PER_PAGE);
    let max = parse_header(&hdr, cap)?;
    let priority = if swap_flags & SWAP_FLAG_PREFER != 0 {
        (swap_flags & SWAP_FLAG_PRIO_MASK) as i16
    } else {
        -1
    };
    let backing = match bdev {
        Some(b) => (None, Some(b)),
        None => (Some(inode), None),
    };
    let si = SwapInfo::new(backing, path.into_bytes(), swap_type, max, priority);
    SWAP_INFO.write()[swap_type as usize] = Some(Arc::new(si));
    TOTAL_SWAP_PAGES.fetch_add(max - 1, Ordering::Relaxed);
    Ok(())
}

/// swapoff(2): bring every page of a swap area back into memory and
/// deactivate it (Linux try_to_unuse)
pub fn sys_swapoff(path_ptr: u64) -> i64 {
    match swapoff(path_ptr) {
        Ok(()) => 0,
        Err(e) => e.sysret(),
    }
}

fn swapoff(path_ptr: u64) -> Result<(), KernelError> {
    if !capable(CAP_SYS_ADMIN) {
        return Err(KernelError::NotPermitted);
    }
    let path = user_path(path_ptr)?;
    // A nonexistent file is ENOENT, an existing non-swap file EINVAL
    // (Linux swapoff: file_open_name first)
    lookup_path(&path)?;
    let _g = SWAPON.lock();
    let t = find_swap_by_path(path.as_bytes()).ok_or(KernelError::InvalidArgument)?;
    let si = get_swap_info(t).ok_or(KernelError::InvalidArgument)?;
    // No new slots from it (Linux del_from_avail_list)
    si.flags.fetch_and(!SWP_WRITEOK, Ordering::AcqRel);
    if let Err(e) = super::swap_state::try_to_unuse(&si) {
        si.flags.fetch_or(SWP_WRITEOK, Ordering::AcqRel);
        return Err(e);
    }
    SWAP_INFO.write()[t as usize] = None;
    TOTAL_SWAP_PAGES.fetch_sub(si.max - 1, Ordering::Relaxed);
    super::swap_state::destroy_cache(&si);
    Ok(())
}

/// Over half of swap is in use (Linux vm_swap_full): a page read back
/// gives its slot up at once rather than keep a clean copy
pub fn swap_full() -> bool {
    let (total, free) = swap_totals();
    free * 2 < total
}

/// A swap area on a block device is on (direct reclaim swaps only there)
pub fn bdev_swap_active() -> bool {
    SWAP_INFO
        .read()
        .iter()
        .flatten()
        .any(|si| si.bdev.is_some())
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
        assert_eq!(parse_header(&hdr(16383, 1), 1000), Ok(1000));
        assert!(parse_header(&hdr(16383, 2), u64::MAX).is_err());
        assert!(parse_header(&hdr(0, 1), u64::MAX).is_err());
        let mut bad = hdr(10, 1);
        bad[SWAP_MAGIC_OFFSET] = b'X';
        assert!(parse_header(&bad, u64::MAX).is_err());
    }

    #[test]
    fn slot_counts_and_cache_bit() {
        let si = SwapInfo::new((None, None), Vec::new(), 0, 4, 0);
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
}
