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
use super::page::{PG_DIRTY, PG_LOCKED, PG_UPTODATE, Page, lock_page, phys_to_page, unlock_page};
use super::xarray::{MARK_DIRTY, Preload, XArray, node_alloc};
use crate::FRAME_ALLOCATOR;
use crate::arch::phys_to_virt;
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
        // SAFETY: a page frame through the direct map, owned by the
        // caller (locked or not yet visible)
        unsafe { core::ptr::write_bytes(phys_to_virt(phys).add(from), 0, PAGE_SIZE - from) };
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
    pg.flags
        .fetch_and(!(PG_DIRTY | PG_UPTODATE), Ordering::Relaxed);
    m.nrpages.fetch_sub(1, Ordering::Relaxed);
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
    let mut pages = m.i_pages.lock();
    pages.destroy(&mut |phys| {
        let pg = page(phys);
        pg.mapping.store(0, Ordering::Release);
        pg.flags
            .fetch_and(!(PG_DIRTY | PG_UPTODATE), Ordering::Relaxed);
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
    if pg.flags.fetch_or(PG_DIRTY, Ordering::AcqRel) & PG_DIRTY == 0
        && pg.mapping.load(Ordering::Acquire) == m.key()
    {
        m.i_pages
            .lock()
            .set_mark(pg.index.load(Ordering::Relaxed), MARK_DIRTY);
    }
}

/// Write every dirty page of `inode` and wait (Linux
/// filemap_write_and_wait, synchronous I/O): each is locked, its dirty
/// bit and mark cleared, then written. The first error is returned
/// after the others were tried; a page that failed stays clean (Linux
/// records the error on the mapping; the data is in the page still).
pub fn write_and_wait(inode: &Inode) -> Result<(), KernelError> {
    let m = &inode.i_data;
    let mut err = Ok(());
    let mut at = 0;
    loop {
        let next = {
            let pages = m.i_pages.lock();
            pages
                .find(at, u64::MAX, Some(MARK_DIRTY))
                .filter(|&(_, p)| FRAME_ALLOCATOR.incref(p))
        };
        let Some((index, phys)) = next else {
            return err;
        };
        lock_page(phys);
        let pg = page(phys);
        if pg.mapping.load(Ordering::Acquire) == m.key() {
            m.i_pages.lock().clear_mark(index, MARK_DIRTY);
            if pg.flags.fetch_and(!PG_DIRTY, Ordering::AcqRel) & PG_DIRTY != 0
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

/// Drop every page of `inode` (Linux kill_bdev / truncate_inode_pages
/// from 0), after `write_and_wait` if they must reach the disk
pub fn invalidate(inode: &Inode) {
    truncate_from(&inode.i_data, 0);
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
        // SAFETY: an uptodate page with our reference, through the
        // direct map
        unsafe {
            core::ptr::copy_nonoverlapping(phys_to_virt(phys).add(off), buf[done..].as_mut_ptr(), n)
        };
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
        // SAFETY: the locked page with our reference, direct map
        unsafe {
            core::ptr::copy_nonoverlapping(buf[done..].as_ptr(), phys_to_virt(phys).add(off), n)
        };
        done += a.write_end(inode, at, n, phys);
    }
    Ok(done)
}

/// Unmap the file's pages from index `from` on in every mapping of it
/// (Linux unmap_mapping_range with even_cows: private copies too, so
/// they go SIGBUS with the file). The chain held for reading keeps each
/// VMA's page tables (an unmap unlinks the VMA first). Sleeps.
pub fn unmap_mapping_range(m: &AddressSpace, from: u64) {
    let chain = m.i_mmap.read();
    for avc in chain.iter() {
        let pages = (avc.end - avc.start) / PAGE_SIZE as u64;
        if avc.pgoff + pages <= from {
            continue;
        }
        let Some(mm) = avc.mm.upgrade() else {
            continue;
        };
        let start = avc.start + from.saturating_sub(avc.pgoff) * PAGE_SIZE as u64;
        let mut tlb = super::gather::Gather::new(&mm);
        super::memory::zap_range(&mut tlb, start, avc.end);
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
