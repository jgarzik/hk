//! The page cache of one file (Linux mm/filemap.c, mm/truncate.c,
//! include/linux/pagemap.h)
//!
//! Every inode has an [`AddressSpace`] (Linux `inode->i_data`): its
//! cached pages by page index in an [`XArray`] (`i_pages`). A cached
//! page is an ordinary page frame (order 0: a folio is one page here)
//! whose `struct page` records the mapping (`Page.mapping`, the
//! AddressSpace address, low bit clear) and its index; the cache holds
//! one reference on it. `PG_uptodate` says its data is valid, the page
//! lock (`PG_locked`) serializes filling, writing into and removing it.
//!
//! The filesystem supplies the I/O through [`Aops`] (Linux
//! address_space_operations): `read_folio` fills a locked page; writes
//! go through `write_begin`/`write_end`.
//!
//! Locking (doc/LOCKING.md): `AddressSpace.i_pages` is a spin lock
//! (Linux xa_lock), a leaf apart from the heap (index nodes) and page
//! reference counts; thread context only (I/O completion is waited for
//! in the submitting thread, so nothing touches it in an interrupt).
//! Order: i_rwsem -> invalidate_lock -> page lock -> i_pages. A lookup
//! takes its page reference under `i_pages` (get_page_unless_zero), so
//! a page removed meanwhile is never returned. A page is inserted and
//! removed locked; removal happens under the page lock and `i_pages`.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use spin::Once;

use super::anon_vma::AnonVma;
use super::fault::VmFault;
use super::page::{
    PG_DIRTY, PG_LOCKED, PG_UPTODATE, Page, frame_bytes, lock_page, phys_to_page, unlock_page,
};
use super::xarray::{MARK_DIRTY, Preload, XArray, node_alloc};
use crate::FRAME_ALLOCATOR;
use crate::error::KernelError;
use crate::fs::inode::Inode;
use crate::sync::spin::Mutex;

/// Page size
pub const PAGE_SIZE: usize = 4096;

/// The mapping's pages never leave memory (Linux AS_UNEVICTABLE: ramfs)
pub const AS_UNEVICTABLE: u32 = 1 << 0;

/// Filesystem I/O of a mapping (Linux address_space_operations)
pub trait Aops: Sync {
    /// Fill the locked, not uptodate page `phys`, index `index` of
    /// `inode`, and mark it uptodate (Linux ->read_folio); the page
    /// stays locked. An error leaves it not uptodate.
    fn read_folio(&self, inode: &Inode, phys: u64, index: u64) -> Result<(), KernelError>;

    /// The locked page with a reference that a write of `len` bytes at
    /// `pos` (within one page) goes to (Linux ->write_begin); default
    /// simple_write_begin
    fn write_begin(&self, inode: &Inode, pos: u64, len: usize) -> Result<u64, KernelError> {
        simple_write_begin(inode, pos, len)
    }

    /// `copied` bytes were copied into `phys` at `pos` (Linux
    /// ->write_end): extend i_size, dirty and release the page. Returns
    /// the bytes accepted. Default simple_write_end.
    fn write_end(&self, inode: &Inode, pos: u64, copied: usize, phys: u64) -> usize {
        simple_write_end(inode, pos, copied, phys)
    }

    /// Write the locked, dirty page `phys`, index `index`, to the
    /// backing store (Linux ->writepage, synchronous); the page stays
    /// locked. Default: no backing store (EIO).
    fn writepage(&self, inode: &Inode, phys: u64, index: u64) -> Result<(), KernelError> {
        let _ = (inode, phys, index);
        Err(KernelError::Io)
    }

    /// Read (`write` false) or write page `index` of a swap file to or
    /// from `buf` straight on the disk, bypassing the cache (Linux
    /// ->swap_rw after ->swap_activate). Default: the file cannot be a
    /// swap area (swapon EINVAL).
    fn swap_rw(
        &self,
        inode: &Inode,
        index: u64,
        buf: &mut [u8],
        write: bool,
    ) -> Result<(), KernelError> {
        let _ = (inode, index, buf, write);
        Err(KernelError::OperationNotSupported)
    }

    /// Pages get dirty (false: Linux noop_dirty_folio, a mapping with
    /// no backing store, e.g. ramfs, never writes back)
    fn can_dirty(&self) -> bool {
        true
    }
}

/// A mapping with no I/O: pages read as zeros (a new inode before its
/// filesystem sets its operations)
struct NoAops;

impl Aops for NoAops {
    fn read_folio(&self, _inode: &Inode, phys: u64, _index: u64) -> Result<(), KernelError> {
        zero_page(phys, 0);
        set_uptodate(phys);
        Ok(())
    }
}

static NO_AOPS: NoAops = NoAops;

/// The page cache of one file (Linux struct address_space)
pub struct AddressSpace {
    /// Cached pages by index (Linux i_pages; its lock is the xa_lock)
    i_pages: Mutex<XArray>,
    /// Pages in `i_pages`
    nrpages: AtomicU64,
    /// AS_* flags
    flags: AtomicU32,
    /// The filesystem's I/O
    a_ops: Once<&'static dyn Aops>,
    /// Every VMA mapping the file (Linux i_mmap + i_mmap_rwsem; the
    /// same chain type as an anon_vma's): written under the mmap_lock
    /// held for writing, read by truncate and the reverse map
    pub i_mmap: AnonVma,
}

impl AddressSpace {
    #[track_caller]
    pub fn new() -> Self {
        Self {
            i_pages: Mutex::new(XArray::new()),
            nrpages: AtomicU64::new(0),
            flags: AtomicU32::new(0),
            a_ops: Once::new(),
            i_mmap: AnonVma::default(),
        }
    }

    /// Set the filesystem's operations (once, before any page is cached)
    pub fn set_aops(&self, a: &'static dyn Aops) {
        self.a_ops.call_once(|| a);
    }

    pub fn aops(&self) -> &'static dyn Aops {
        self.a_ops.get().copied().unwrap_or(&NO_AOPS)
    }

    pub fn set_flags(&self, f: u32) {
        self.flags.fetch_or(f, Ordering::Relaxed);
    }

    pub fn has_flag(&self, f: u32) -> bool {
        self.flags.load(Ordering::Relaxed) & f != 0
    }

    /// Pages cached (Linux mapping->nrpages)
    pub fn nrpages(&self) -> u64 {
        self.nrpages.load(Ordering::Relaxed)
    }

    fn key(&self) -> u64 {
        self as *const Self as u64
    }
}

impl Default for AddressSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        truncate_final(self);
    }
}

/// Dirty page-cache pages, per CPU (Linux NR_FILE_DIRTY vmstat): summed
/// for balance_dirty_pages and /proc/meminfo
static NR_DIRTY: crate::cpu::PerCpu<core::sync::atomic::AtomicI64> =
    crate::percpu![core::sync::atomic::AtomicI64::new(0)];

/// Page-cache pages, and those of unevictable mappings, per CPU
/// (Linux NR_FILE_PAGES, NR_UNEVICTABLE): /proc/meminfo
static NR_FILE: crate::cpu::PerCpu<core::sync::atomic::AtomicI64> =
    crate::percpu![core::sync::atomic::AtomicI64::new(0)];
static NR_UNEVICT: crate::cpu::PerCpu<core::sync::atomic::AtomicI64> =
    crate::percpu![core::sync::atomic::AtomicI64::new(0)];

fn sum(c: &crate::cpu::PerCpu<core::sync::atomic::AtomicI64>) -> u64 {
    c.for_each_possible()
        .map(|(_, c)| c.load(Ordering::Relaxed))
        .sum::<i64>()
        .max(0) as u64
}

/// `d` pages entered (or left) the cache of `m`
fn count_file(m: &AddressSpace, d: i64) {
    NR_FILE.this().fetch_add(d, Ordering::Relaxed);
    if m.has_flag(AS_UNEVICTABLE) {
        NR_UNEVICT.this().fetch_add(d, Ordering::Relaxed);
    }
}

/// Page-cache pages (Linux NR_FILE_PAGES)
pub fn nr_file_pages() -> u64 {
    sum(&NR_FILE)
}

/// Page-cache pages that never leave memory (ramfs; Linux Unevictable)
pub fn nr_unevictable() -> u64 {
    sum(&NR_UNEVICT)
}

fn count_dirty(d: i64) {
    NR_DIRTY.this().fetch_add(d, Ordering::Relaxed);
}

/// Dirty page-cache pages (Linux global_node_page_state(NR_FILE_DIRTY))
pub fn nr_dirty() -> u64 {
    sum(&NR_DIRTY)
}

/// Clear the page's dirty bit; true (and uncounted) if it was set
fn test_clear_dirty(pg: &Page) -> bool {
    let was = pg.flags.fetch_and(!PG_DIRTY, Ordering::AcqRel) & PG_DIRTY != 0;
    if was {
        count_dirty(-1);
    }
    was
}

fn page(phys: u64) -> &'static Page {
    phys_to_page(phys).expect("page cache frame outside RAM")
}

/// The page is uptodate (Linux folio_test_uptodate)
pub fn uptodate(phys: u64) -> bool {
    page(phys).flags.load(Ordering::Acquire) & PG_UPTODATE != 0
}

/// Mark the (locked) page uptodate (Linux folio_mark_uptodate): its
/// data is published before the flag
pub fn set_uptodate(phys: u64) {
    page(phys).flags.fetch_or(PG_UPTODATE, Ordering::Release);
}

/// Zero the page from byte `from` to its end
pub fn zero_page(phys: u64, from: usize) {
    if from < PAGE_SIZE {
        // The caller owns it: locked or not yet visible
        frame_bytes(phys)[from..].fill(0);
    }
}

/// Drop a page reference (Linux folio_put)
pub fn put_page(phys: u64) {
    FRAME_ALLOCATOR.decref(phys);
}

/// The cached page at `index` with a reference (Linux
/// filemap_get_folio), or None
pub fn find_get(m: &AddressSpace, index: u64) -> Option<u64> {
    let pages = m.i_pages.lock();
    let phys = pages.load(index);
    (phys != 0 && FRAME_ALLOCATOR.incref(phys)).then_some(phys)
}

/// Insert the locked page `phys` at `index` (Linux filemap_add_folio);
/// the cache takes a reference. AlreadyExists if a page is there.
fn add(m: &AddressSpace, phys: u64, index: u64) -> Result<(), KernelError> {
    let pg = page(phys);
    pg.index.store(index, Ordering::Relaxed);
    pg.mapping.store(m.key(), Ordering::Release);
    FRAME_ALLOCATOR.incref(phys);
    let mut pre: Option<Preload> = None;
    loop {
        let mut pages = m.i_pages.lock();
        if pages.load(index) != 0 {
            drop(pages);
            pg.mapping.store(0, Ordering::Release);
            put_page(phys);
            return Err(KernelError::AlreadyExists);
        }
        let stored = match pre.as_mut() {
            Some(p) => pages.store(index, phys, &mut || p.take()),
            None => pages.store(index, phys, &mut node_alloc),
        };
        if stored.is_some() {
            m.nrpages.fetch_add(1, Ordering::Relaxed);
            count_file(m, 1);
            return Ok(());
        }
        drop(pages);
        if pre.is_some() {
            pg.mapping.store(0, Ordering::Release);
            put_page(phys);
            return Err(KernelError::OutOfMemory);
        }
        // Linux xas_nomem: allocate with no lock held (may reclaim)
        pre = Some(Preload::new().ok_or_else(|| {
            pg.mapping.store(0, Ordering::Release);
            put_page(phys);
            KernelError::OutOfMemory
        })?);
    }
}

/// The page at `index`, locked, with a reference, created (not
/// uptodate) if absent (Linux __filemap_get_folio FGP_LOCK|FGP_CREAT)
pub fn grab(m: &AddressSpace, index: u64) -> Result<u64, KernelError> {
    loop {
        if let Some(phys) = find_get(m, index) {
            lock_page(phys);
            if page(phys).mapping.load(Ordering::Acquire) == m.key() {
                return Ok(phys);
            }
            // Removed while we waited for the lock (truncate)
            unlock_page(phys);
            put_page(phys);
            continue;
        }
        let phys = crate::mm::fault::alloc_user().ok_or(KernelError::OutOfMemory)?;
        let pg = page(phys);
        pg.flags.fetch_or(PG_LOCKED, Ordering::Acquire);
        match add(m, phys, index) {
            Ok(()) => return Ok(phys),
            Err(KernelError::AlreadyExists) => {
                pg.flags.fetch_and(!PG_LOCKED, Ordering::Release);
                put_page(phys);
            }
            Err(e) => {
                pg.flags.fetch_and(!PG_LOCKED, Ordering::Release);
                put_page(phys);
                return Err(e);
            }
        }
    }
}

/// The page at `index` of `inode`, uptodate, unlocked, with a
/// reference (Linux read_mapping_folio)
pub fn read_page(inode: &Inode, index: u64) -> Result<u64, KernelError> {
    let m = &inode.i_data;
    if let Some(phys) = find_get(m, index) {
        if uptodate(phys) {
            return Ok(phys);
        }
        put_page(phys);
    }
    let phys = grab(m, index)?;
    if !uptodate(phys)
        && let Err(e) = m.aops().read_folio(inode, phys, index)
    {
        // A failed read leaves no page behind (Linux filemap_read_folio
        // error: the folio stays !uptodate and is retried; hk drops it
        // so a later read starts over)
        remove(m, phys);
        unlock_page(phys);
        put_page(phys);
        return Err(e);
    }
    unlock_page(phys);
    Ok(phys)
}

/// Remove the locked page `phys` from `m` (Linux
/// __filemap_remove_folio + the cache's reference)
pub fn remove(m: &AddressSpace, phys: u64) {
    let pg = page(phys);
    if pg.mapping.load(Ordering::Acquire) != m.key() {
        return;
    }
    let index = pg.index.load(Ordering::Relaxed);
    {
        let mut pages = m.i_pages.lock();
        let old = pages.erase(index);
        debug_assert_eq!(old, phys);
        pg.mapping.store(0, Ordering::Release);
    }
    test_clear_dirty(pg);
    pg.flags.fetch_and(!PG_UPTODATE, Ordering::Relaxed);
    pg.private.store(0, Ordering::Relaxed);
    m.nrpages.fetch_sub(1, Ordering::Relaxed);
    count_file(m, -1);
    put_page(phys);
}

/// Remove the pages from index `from` on (Linux
/// truncate_inode_pages_range): each is locked first, so a writer or
/// reader holding it finishes
pub fn truncate_from(m: &AddressSpace, from: u64) {
    let mut at = from;
    loop {
        let next = {
            let pages = m.i_pages.lock();
            pages
                .find(at, u64::MAX, None)
                .filter(|&(_, p)| FRAME_ALLOCATOR.incref(p))
        };
        let Some((index, phys)) = next else {
            return;
        };
        lock_page(phys);
        remove(m, phys);
        unlock_page(phys);
        put_page(phys);
        at = index + 1;
    }
}

/// Drop every page of a mapping nobody else can reach any more (Linux
/// truncate_inode_pages_final, from eviction): no page lock, no sleep
fn truncate_final(m: &AddressSpace) {
    count_file(m, -(m.nrpages() as i64));
    let mut pages = m.i_pages.lock();
    pages.destroy(&mut |phys| {
        let pg = page(phys);
        pg.mapping.store(0, Ordering::Release);
        test_clear_dirty(pg);
        pg.flags.fetch_and(!PG_UPTODATE, Ordering::Relaxed);
        pg.private.store(0, Ordering::Relaxed);
        put_page(phys);
    });
    m.nrpages.store(0, Ordering::Relaxed);
}

/// Set the page's dirty bit and the mapping's DIRTY mark (Linux
/// filemap_dirty_folio)
pub fn dirty_page(m: &AddressSpace, phys: u64) {
    if !m.aops().can_dirty() {
        return;
    }
    let pg = page(phys);
    if pg.mapping.load(Ordering::Acquire) == m.key()
        && pg.flags.fetch_or(PG_DIRTY, Ordering::AcqRel) & PG_DIRTY == 0
    {
        count_dirty(1);
        m.i_pages
            .lock()
            .set_mark(pg.index.load(Ordering::Relaxed), MARK_DIRTY);
    }
}

/// Write-protect every writable PTE mapping page `index` (`phys`) of
/// `m` (Linux folio_mkclean through i_mmap), so the next write through
/// a shared mapping faults and dirties the page again. Sleeps (the
/// chain); takes each PTE lock.
fn mkclean(m: &AddressSpace, index: u64, phys: u64) {
    use crate::arch::paging;
    let chain = m.i_mmap.read();
    for avc in chain.iter() {
        let (Some(addr), Some(mm)) = (avc.address(index), avc.mm.upgrade()) else {
            continue;
        };
        let Some(ptep) = paging::pte_ptr(avc.pgd, addr) else {
            continue;
        };
        let _l = super::ptl::pte_lock(ptep);
        // SAFETY: a live table of a VMA in the chain, under its PTE lock
        let e = unsafe { AtomicU64::from_ptr(ptep) };
        let pte = e.load(Ordering::Acquire);
        if paging::pte_present(pte) && paging::pte_addr(pte) == phys && paging::pte_write(pte) {
            e.store(paging::pte_wrprotect(pte), Ordering::Release);
            super::tlb::flush_tlb_page(&mm, addr);
        }
    }
}

/// Write every dirty page of `inode` and wait (Linux
/// filemap_write_and_wait, synchronous I/O): each is locked, its dirty
/// bit and mark cleared, then written. The first error is returned
/// after the others were tried; a page that failed stays clean (Linux
/// records the error on the mapping; the data is in the page still).
pub fn write_and_wait(inode: &Inode) -> Result<(), KernelError> {
    write_range(inode, 0, u64::MAX)
}

/// `write_and_wait` of the pages with index in [first, last] (Linux
/// filemap_write_and_wait_range)
pub fn write_range(inode: &Inode, first: u64, last: u64) -> Result<(), KernelError> {
    let m = &inode.i_data;
    let mut err = Ok(());
    let mut at = first;
    loop {
        let next = {
            let pages = m.i_pages.lock();
            pages
                .find(at, last, Some(MARK_DIRTY))
                .filter(|&(_, p)| FRAME_ALLOCATOR.incref(p))
        };
        let Some((index, phys)) = next else {
            return err;
        };
        lock_page(phys);
        let pg = page(phys);
        if pg.mapping.load(Ordering::Acquire) == m.key() {
            m.i_pages.lock().clear_mark(index, MARK_DIRTY);
            // Write-protected first: a write through a mapping after
            // this faults and dirties the page again (folio_mkclean)
            mkclean(m, index, phys);
            if test_clear_dirty(pg)
                && let Err(e) = m.aops().writepage(inode, phys, index)
                && err.is_ok()
            {
                err = Err(e);
            }
        }
        unlock_page(phys);
        put_page(phys);
        match index.checked_add(1) {
            Some(n) => at = n,
            None => return err,
        }
    }
}

/// Write back and drop the pages holding bytes [start, end) of `inode`
/// (Linux clean_bdev_aliases on the device's cache): a dirty page is
/// written first, since it may hold other blocks too
pub fn invalidate_range(inode: &Inode, start: u64, end: u64) -> Result<(), KernelError> {
    let m = &inode.i_data;
    let (first, last) = (start / PAGE_SIZE as u64, end.div_ceil(PAGE_SIZE as u64));
    if first >= last {
        return Ok(());
    }
    // Unmapped (a mapping of the device node) before the pages go
    unmap_pages(m, first, last - 1);
    let mut at = first;
    while at < last {
        let next = {
            let pages = m.i_pages.lock();
            pages
                .find(at, last - 1, None)
                .filter(|&(_, p)| FRAME_ALLOCATOR.incref(p))
        };
        let Some((index, phys)) = next else {
            return Ok(());
        };
        lock_page(phys);
        let pg = page(phys);
        let mut r = Ok(());
        if pg.mapping.load(Ordering::Acquire) == m.key() {
            if test_clear_dirty(pg) {
                m.i_pages.lock().clear_mark(index, MARK_DIRTY);
                r = m.aops().writepage(inode, phys, index);
            }
            if r.is_ok() {
                remove(m, phys);
            } else {
                dirty_page(m, phys);
            }
        }
        unlock_page(phys);
        put_page(phys);
        r?;
        at = index + 1;
    }
    Ok(())
}

/// Drop the clean, unmapped, unused pages of `inode` with index in
/// [first, last] (Linux invalidate_mapping_pages: best effort; dirty,
/// locked, mapped or otherwise referenced pages stay)
pub fn invalidate_clean(inode: &Inode, first: u64, last: u64) -> u64 {
    let m = &inode.i_data;
    // The cache is the only copy of an unevictable mapping's data
    // (ramfs: its pages are never dirty, yet cannot be re-read)
    if m.has_flag(AS_UNEVICTABLE) {
        return 0;
    }
    let mut freed = 0;
    let mut at = first;
    while at <= last {
        let next = {
            let pages = m.i_pages.lock();
            pages
                .find(at, last, None)
                .filter(|&(_, p)| FRAME_ALLOCATOR.incref(p))
        };
        let Some((index, phys)) = next else {
            return freed;
        };
        if super::page::trylock_page(phys) {
            let pg = page(phys);
            // The cache's reference and ours: no PTE or user holds it
            if pg.mapping.load(Ordering::Acquire) == m.key()
                && pg.flags.load(Ordering::Acquire) & PG_DIRTY == 0
                && FRAME_ALLOCATOR.refcount(phys) == 2
            {
                remove(m, phys);
                freed += 1;
            }
            unlock_page(phys);
        }
        put_page(phys);
        match index.checked_add(1) {
            Some(n) => at = n,
            None => return freed,
        }
    }
    freed
}

/// Drop every page of `inode` (Linux kill_bdev / truncate_inode_pages
/// from 0), after `write_and_wait` if they must reach the disk
pub fn invalidate(inode: &Inode) {
    // Unmapped first and again after (Linux truncate_inode_pages unmaps
    // a mapped folio): no mapping keeps an orphaned page whose writes
    // would reach nothing
    unmap_mapping_range(&inode.i_data, 0);
    truncate_from(&inode.i_data, 0);
    unmap_mapping_range(&inode.i_data, 0);
}

/// Linux simple_write_begin: the page, read first unless the write
/// covers it whole or it lies at or past EOF (then zeroed)
pub fn simple_write_begin(inode: &Inode, pos: u64, len: usize) -> Result<u64, KernelError> {
    let m = &inode.i_data;
    let index = pos / PAGE_SIZE as u64;
    let phys = grab(m, index)?;
    if uptodate(phys) || len == PAGE_SIZE {
        return Ok(phys);
    }
    let r = if index * PAGE_SIZE as u64 >= inode.get_size() {
        zero_page(phys, 0);
        set_uptodate(phys);
        Ok(())
    } else {
        m.aops().read_folio(inode, phys, index)
    };
    if let Err(e) = r {
        unlock_page(phys);
        put_page(phys);
        return Err(e);
    }
    Ok(phys)
}

/// Linux simple_write_end: mark uptodate, extend i_size, dirty, unlock
pub fn simple_write_end(inode: &Inode, pos: u64, copied: usize, phys: u64) -> usize {
    set_uptodate(phys);
    let end = pos + copied as u64;
    if end > inode.get_size() {
        inode.set_size(end);
    }
    dirty_page(&inode.i_data, phys);
    unlock_page(phys);
    put_page(phys);
    copied
}

/// Read file data at `pos` into `buf` (Linux filemap_read): up to EOF
pub fn read(inode: &Inode, buf: &mut [u8], pos: u64) -> Result<usize, KernelError> {
    let mut done = 0;
    while done < buf.len() {
        let at = pos + done as u64;
        let size = inode.get_size();
        if at >= size {
            break;
        }
        let phys = match read_page(inode, at / PAGE_SIZE as u64) {
            Ok(p) => p,
            Err(_) if done > 0 => break,
            Err(e) => return Err(e),
        };
        // i_size again after the page was read (a truncate may have
        // raced the read)
        let size = inode.get_size();
        let off = (at % PAGE_SIZE as u64) as usize;
        let n = (PAGE_SIZE - off)
            .min(buf.len() - done)
            .min(size.saturating_sub(at) as usize);
        // An uptodate page with our reference
        buf[done..done + n].copy_from_slice(&frame_bytes(phys)[off..off + n]);
        put_page(phys);
        if n == 0 {
            break;
        }
        done += n;
    }
    Ok(done)
}

/// Write `buf` at `pos` through the page cache (Linux
/// generic_perform_write); the caller holds i_rwsem. A failure after
/// some bytes reports those.
pub fn perform_write(inode: &Inode, buf: &[u8], pos: u64) -> Result<usize, KernelError> {
    let a = inode.i_data.aops();
    let mut done = 0;
    while done < buf.len() {
        let at = pos + done as u64;
        let off = (at % PAGE_SIZE as u64) as usize;
        let n = (PAGE_SIZE - off).min(buf.len() - done);
        let phys = match a.write_begin(inode, at, n) {
            Ok(p) => p,
            Err(_) if done > 0 => break,
            Err(e) => return Err(e),
        };
        // The locked page with our reference
        frame_bytes(phys)[off..off + n].copy_from_slice(&buf[done..done + n]);
        done += a.write_end(inode, at, n, phys);
    }
    Ok(done)
}

/// Unmap the file's pages from index `from` on in every mapping of it
/// (Linux unmap_mapping_range with even_cows: private copies too, so
/// they go SIGBUS with the file). The chain held for reading keeps each
/// VMA's page tables (an unmap unlinks the VMA first). Sleeps.
pub fn unmap_mapping_range(m: &AddressSpace, from: u64) {
    unmap_pages(m, from, u64::MAX);
}

/// `unmap_mapping_range` of the pages with index in [from, last]
pub fn unmap_pages(m: &AddressSpace, from: u64, last: u64) {
    let chain = m.i_mmap.read();
    for avc in chain.iter() {
        let pages = (avc.end - avc.start) / PAGE_SIZE as u64;
        if avc.pgoff + pages <= from || avc.pgoff > last {
            continue;
        }
        let Some(mm) = avc.mm.upgrade() else {
            continue;
        };
        let page_addr = |i: u64| {
            avc.start
                .saturating_add(i.saturating_sub(avc.pgoff).saturating_mul(PAGE_SIZE as u64))
        };
        let start = page_addr(from);
        let end = page_addr(last.saturating_add(1)).min(avc.end);
        let mut tlb = super::gather::Gather::new(&mm);
        super::memory::zap_range(&mut tlb, start, end);
    }
}

/// Set i_size and drop the cache beyond it (Linux truncate_setsize +
/// truncate_pagecache): mappings of the pages past the new size are
/// zapped (before and after, catching a fault that raced), the pages
/// removed, and the partial last page zeroed past the size. The
/// caller holds i_rwsem.
pub fn truncate_setsize(inode: &Inode, size: u64) {
    let old = inode.get_size();
    inode.set_size(size);
    if size >= old {
        return;
    }
    let m = &inode.i_data;
    let from = size.div_ceil(PAGE_SIZE as u64);
    unmap_mapping_range(m, from);
    truncate_from(m, from);
    unmap_mapping_range(m, from);
    let off = (size % PAGE_SIZE as u64) as usize;
    if off != 0
        && let Some(phys) = find_get(m, size / PAGE_SIZE as u64)
    {
        lock_page(phys);
        if uptodate(phys) {
            zero_page(phys, off);
        }
        unlock_page(phys);
        put_page(phys);
    }
}

/// The page at `index` for a mapping's fault (Linux filemap_fault):
/// uptodate, LOCKED, with a reference for the PTE; past EOF or a read
/// error is SIGBUS. The size is checked again under the page lock and
/// the caller maps the page before unlocking it, so a truncate (which
/// sets the size, then removes pages under their lock, then unmaps)
/// never leaves a mapping of a page past EOF.
pub fn fault(inode: &Inode, index: u64) -> Result<u64, VmFault> {
    let past = |i: &Inode| index >= i.get_size().div_ceil(PAGE_SIZE as u64);
    if past(inode) {
        return Err(VmFault::Bus);
    }
    let err = |e| match e {
        KernelError::OutOfMemory | KernelError::NoSpace => VmFault::Oom,
        _ => VmFault::Bus,
    };
    loop {
        let phys = read_page(inode, index).map_err(err)?;
        lock_page(phys);
        if page(phys).mapping.load(Ordering::Acquire) != inode.i_data.key() {
            // Truncated meanwhile
            unlock_page(phys);
            put_page(phys);
            if past(inode) {
                return Err(VmFault::Bus);
            }
            continue;
        }
        if past(inode) {
            unlock_page(phys);
            put_page(phys);
            return Err(VmFault::Bus);
        }
        return Ok(phys);
    }
}

/// `f` on each inode that may hold reclaimable cache (every hashed
/// inode, every block device's) until it returns false; no allocation
fn for_each_cache_inode(f: &mut dyn FnMut(&Inode) -> bool) {
    let mut more = true;
    crate::fs::icache::for_each_inode(&mut |i| {
        more = i.i_data.nrpages() == 0 || f(i);
        more
    });
    if more {
        crate::storage::blkdev::for_each_bdev_inode(&mut |i| i.i_data.nrpages() == 0 || f(i));
    }
}

/// Drop up to `nr` clean, unmapped page-cache pages for direct reclaim
/// (Linux shrink_inactive_list of the file LRU). Deviation: no file
/// LRU, so the pages go inode by inode, not oldest first. Allocates
/// nothing (it runs when memory is short) and never sleeps on a page
/// lock (trylock); stops once `nr` are freed. The number freed.
pub fn shrink_cache(nr: usize) -> usize {
    let mut freed = 0;
    for_each_cache_inode(&mut |inode| {
        freed += invalidate_clean(inode, 0, u64::MAX) as usize;
        freed < nr
    });
    freed
}

/// vm.drop_caches 1 (Linux drop_pagecache_sb over every superblock):
/// drop every clean, unmapped page-cache page
pub fn drop_pagecache() {
    for_each_cache_inode(&mut |inode| {
        invalidate_clean(inode, 0, u64::MAX);
        true
    });
}
