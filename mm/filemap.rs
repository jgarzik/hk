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
use super::xarray::{MARK_DIRTY, MARK_WRITEBACK, XArray};
use crate::FRAME_ALLOCATOR;
use crate::fs::inode::Inode;
use crate::fs::iov_iter::{IovDest, IovSource};
use crate::sync::spin::Mutex;
use crate::util::error::KernelError;

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

    /// Dirty the page (Linux ->dirty_folio); default `filemap::dirty_folio`
    fn dirty_folio(&self, m: &AddressSpace, phys: u64) {
        dirty_folio(m, phys);
    }

    /// Pages get dirty (false: Linux noop_dirty_folio, a mapping with
    /// no backing store, e.g. ramfs, never writes back)
    fn can_dirty(&self) -> bool {
        true
    }
}

/// Block accounting of a mapping's file system (Linux tmpfs
/// shmem_inode_acct_blocks / shmem_inode_unacct_blocks): a page is
/// charged before it enters the cache (ENOSPC when the file system is
/// full) and released when it leaves. Called with the page locked and
/// no spin lock held; must not sleep.
pub trait PageAcct: Send + Sync {
    /// Take `pages` blocks (NoSpace when short)
    fn charge(&self, pages: u64) -> Result<(), KernelError>;
    /// Give `pages` blocks back
    fn uncharge(&self, pages: u64);
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
    /// Where its pages are charged (tmpfs; none: not counted)
    acct: Once<alloc::sync::Arc<dyn PageAcct>>,
    /// F_SEAL_* of a tmpfs file (Linux shmem_inode_info.seals, kept
    /// here so a write reaches them in one load; 0 elsewhere): changed
    /// under the inode's i_rwsem, read lock-free
    pub seals: AtomicU32,
    /// Shared mappings that may write (VM_SHARED with VM_MAYWRITE), or
    /// below 0 while F_SEAL_WRITE denies them (Linux i_mmap_writable)
    writable: core::sync::atomic::AtomicI64,
    /// Every VMA mapping the file (Linux i_mmap + i_mmap_rwsem; the
    /// same chain type as an anon_vma's): written under the mmap_lock
    /// held for writing, read by truncate and the reverse map
    pub i_mmap: AnonVma,
    /// When its first dirty page since it was last clean came,
    /// monotonic ns (Linux inode->dirtied_when, set as I_DIRTY_PAGES
    /// is): written under the `i_pages` lock, read by the periodic
    /// writeback (vm.dirty_expire_centisecs)
    pub dirtied_when: AtomicU64,
    /// The inode it belongs to, for page dirtying to mark it dirty
    /// (Linux mapping->host; set with the aops by `set_aops`)
    host: Once<alloc::sync::Weak<Inode>>,
    /// Writeback errors, reported once to each open file by fsync
    /// (Linux mapping->wb_err)
    pub wb_err: crate::util::errseq::ErrSeq,
}

impl AddressSpace {
    #[track_caller]
    pub fn new() -> Self {
        Self {
            i_pages: Mutex::new(XArray::new()),
            nrpages: AtomicU64::new(0),
            flags: AtomicU32::new(0),
            a_ops: Once::new(),
            acct: Once::new(),
            seals: AtomicU32::new(0),
            writable: core::sync::atomic::AtomicI64::new(0),
            i_mmap: AnonVma::default(),
            dirtied_when: AtomicU64::new(0),
            host: Once::new(),
            wb_err: crate::util::errseq::ErrSeq::new(),
        }
    }

    /// Set the filesystem's operations and, for a mapping whose pages
    /// get dirty, the inode it belongs to (once, before any page is
    /// cached; Linux inode->i_mapping->a_ops, mapping->host)
    pub fn set_aops(&self, a: &'static dyn Aops, host: Option<&alloc::sync::Arc<Inode>>) {
        self.a_ops.call_once(|| a);
        if let Some(h) = host {
            self.host.call_once(|| alloc::sync::Arc::downgrade(h));
        }
    }

    pub fn aops(&self) -> &'static dyn Aops {
        self.a_ops.get().copied().unwrap_or(&NO_AOPS)
    }

    /// Charge its pages to `a` (once, before any page is cached)
    pub fn set_acct(&self, a: alloc::sync::Arc<dyn PageAcct>) {
        self.acct.call_once(|| a);
    }

    /// Its pages are charged to a file system (a tmpfs file)
    pub fn charged(&self) -> bool {
        self.acct.get().is_some()
    }

    fn charge(&self) -> Result<(), KernelError> {
        self.acct.get().map_or(Ok(()), |a| a.charge(1))
    }

    fn uncharge(&self, pages: u64) {
        if let Some(a) = self.acct.get()
            && pages != 0
        {
            a.uncharge(pages);
        }
    }

    /// A new shared writable mapping may be made (Linux
    /// mapping_map_writable): EPERM while denied
    pub fn map_writable(&self) -> Result<(), KernelError> {
        self.writable
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n >= 0).then_some(n + 1)
            })
            .map(|_| ())
            .map_err(|_| KernelError::NotPermitted)
    }

    /// One more shared writable mapping of an existing one (a split,
    /// fork; Linux mapping_allow_writable)
    pub fn allow_writable(&self) {
        self.writable.fetch_add(1, Ordering::AcqRel);
    }

    /// One shared writable mapping fewer (Linux mapping_unmap_writable)
    pub fn unmap_writable(&self) {
        self.writable.fetch_sub(1, Ordering::AcqRel);
    }

    /// Deny new shared writable mappings for good (F_SEAL_WRITE; Linux
    /// mapping_deny_writable): EBUSY while there is one
    pub fn deny_writable(&self) -> Result<(), KernelError> {
        self.writable
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n <= 0).then_some(n - 1)
            })
            .map(|_| ())
            .map_err(|_| KernelError::Busy)
    }

    /// Undo a `deny_writable` (Linux mapping_allow_writable after a
    /// failed seal)
    pub fn undeny_writable(&self) {
        self.writable.fetch_add(1, Ordering::AcqRel);
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
        core::ptr::from_ref::<Self>(self) as u64
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
/// tmpfs pages (Linux NR_SHMEM): those of a mapping charged to a tmpfs
static NR_SHMEM: crate::cpu::PerCpu<core::sync::atomic::AtomicI64> =
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
    if m.acct.get().is_some() {
        NR_SHMEM.this().fetch_add(d, Ordering::Relaxed);
    }
}

/// tmpfs and shared memory pages (Linux NR_SHMEM): /proc/meminfo Shmem
pub fn nr_shmem() -> u64 {
    sum(&NR_SHMEM)
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
    zero_bytes(phys, from, PAGE_SIZE);
}

/// Zero the page's bytes [from, to)
fn zero_bytes(phys: u64, from: usize, to: usize) {
    let to = to.min(PAGE_SIZE);
    if from < to {
        // SAFETY: the caller owns it (locked or not yet visible)
        let bytes = unsafe { frame_bytes(phys) };
        bytes[from..to].fill(0);
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

/// Insert the locked page `phys` at `index` (Linux filemap_add_folio),
/// charged to the mapping's file system first (NoSpace); the cache
/// takes a reference. AlreadyExists if a page is there.
fn add(m: &AddressSpace, phys: u64, index: u64) -> Result<(), KernelError> {
    m.charge()?;
    let r = insert(m, phys, index);
    if r.is_err() {
        m.uncharge(1);
    }
    r
}

/// The insertion of `add`, its block charged
fn insert(m: &AddressSpace, phys: u64, index: u64) -> Result<(), KernelError> {
    let pg = page(phys);
    pg.index.store(index, Ordering::Relaxed);
    pg.mapping.store(m.key(), Ordering::Release);
    FRAME_ALLOCATOR.incref(phys);
    // Nothing allocated under the spin lock (Linux xas_nomem)
    let stored = super::xarray::store_nomem(
        || m.i_pages.lock(),
        index,
        phys,
        |pages| {
            if pages.load(index) != 0 {
                Err(KernelError::AlreadyExists)
            } else {
                Ok(())
            }
        },
        KernelError::OutOfMemory,
    );
    match stored {
        Ok(_) => {
            m.nrpages.fetch_add(1, Ordering::Relaxed);
            count_file(m, 1);
            Ok(())
        }
        Err(e) => {
            pg.mapping.store(0, Ordering::Release);
            put_page(phys);
            Err(e)
        }
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
    m.uncharge(1);
    put_page(phys);
}

/// Remove the pages from index `from` on (Linux
/// truncate_inode_pages_range): each is locked first, so a writer or
/// reader holding it finishes
pub fn truncate_from(m: &AddressSpace, from: u64) {
    truncate_pages(m, from, u64::MAX);
}

/// Remove the pages with index in [from, last], as `truncate_from`
fn truncate_pages(m: &AddressSpace, from: u64, last: u64) {
    let mut at = from;
    while at <= last {
        let next = {
            let pages = m.i_pages.lock();
            pages
                .find(at, last, None)
                .filter(|&(_, p)| FRAME_ALLOCATOR.incref(p))
        };
        let Some((index, phys)) = next else {
            return;
        };
        lock_page(phys);
        remove(m, phys);
        unlock_page(phys);
        put_page(phys);
        match index.checked_add(1) {
            Some(i) => at = i,
            None => return,
        }
    }
}

/// Drop every page of a mapping nobody else can reach any more (Linux
/// truncate_inode_pages_final, from eviction): no page lock, no sleep
fn truncate_final(m: &AddressSpace) {
    count_file(m, -(m.nrpages() as i64));
    m.uncharge(m.nrpages());
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

/// Set the page's dirty bit and the mapping's DIRTY mark, and mark its
/// inode dirty (Linux folio_mark_dirty: ->dirty_folio, whose
/// __folio_mark_dirty calls __mark_inode_dirty(I_DIRTY_PAGES)). Under
/// the page lock at most
pub fn dirty_page(m: &AddressSpace, phys: u64) {
    if !m.aops().can_dirty() {
        return;
    }
    m.aops().dirty_folio(m, phys);
    if let Some(inode) = m.host.get().and_then(alloc::sync::Weak::upgrade) {
        crate::fs::fs_writeback::mark_inode_dirty(&inode);
    }
}

/// The generic dirtying (Linux filemap_dirty_folio): PG_dirty and the
/// DIRTY mark, counted
pub fn dirty_folio(m: &AddressSpace, phys: u64) {
    let pg = page(phys);
    if pg.mapping.load(Ordering::Acquire) == m.key()
        && pg.flags.fetch_or(PG_DIRTY, Ordering::AcqRel) & PG_DIRTY == 0
    {
        count_dirty(1);
        let mut pages = m.i_pages.lock();
        if !pages.marked(MARK_DIRTY) {
            m.dirtied_when
                .store(crate::time::monotonic_ns(), Ordering::Release);
        }
        pages.set_mark(pg.index.load(Ordering::Relaxed), MARK_DIRTY);
    }
}

/// Write-protect every writable PTE mapping page `index` (`phys`) of
/// `m` (Linux folio_mkclean through i_mmap), so the next write through
/// a shared mapping faults and dirties the page again. Sleeps (the
/// chain); takes each PTE lock.
fn mkclean(m: &AddressSpace, index: u64, phys: u64) {
    use crate::arch::paging;
    let chain = m.i_mmap.read();
    for (avc, tables) in chain.entries() {
        let (Some(addr), Some(mm)) = (avc.address(index), avc.mm.upgrade()) else {
            continue;
        };
        let Some(ptep) = tables.pte(addr) else {
            continue;
        };
        let t = ptep.lock();
        let e = t.entry(addr);
        // The MMU may set accessed/dirty meanwhile (under the PTE lock
        // only it changes the entry): a compare-exchange keeps those
        // bits, where a load then store could drop a dirty bit set by a
        // write racing the clean (as mprotect's change_pte)
        let mut pte = e.load(Ordering::Acquire);
        let cleaned = loop {
            if !(paging::pte_present(pte)
                && paging::pte_addr(pte) == phys
                && paging::pte_write(pte))
            {
                break false;
            }
            match e.compare_exchange(
                pte,
                paging::pte_wrprotect(pte),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break true,
                Err(now) => pte = now,
            }
        };
        if cleaned {
            super::tlb::flush_tlb_page(&mm, addr);
        }
    }
}

/// Record a writeback error of `inode`'s pages on its mapping and its
/// filesystem, for fsync and syncfs to report (Linux mapping_set_error:
/// wb_err and s_wb_err)
pub fn mapping_set_error(inode: &Inode, e: KernelError) {
    inode.i_data.wb_err.set(e);
    if let Some(sb) = inode.superblock() {
        sb.s_wb_err.set(e);
    }
}

/// The pages over a direct write could not be dropped after it (Linux
/// dio_warn_stale_pagecache): the mapping's writeback error is EIO,
/// which the next fsync of each open file reports, and a warning
pub fn dio_warn_stale_pagecache(inode: &Inode) {
    inode.i_data.wb_err.set(KernelError::Io);
    crate::printkln!(
        "Page cache invalidation failure on direct I/O.  Possible data corruption due to collision with buffered I/O!"
    );
}

/// Write every dirty page of `inode` and wait (Linux
/// filemap_write_and_wait, synchronous I/O): each is locked, its dirty
/// bit and mark cleared, then written. The first error is returned
/// after the others were tried, and each is recorded on the mapping
/// (`mapping_set_error`); a page that failed stays clean (the data is
/// in the page still, as Linux).
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
            break;
        };
        lock_page(phys);
        let pg = page(phys);
        if pg.mapping.load(Ordering::Acquire) == m.key() {
            // Under writeback while it is written (Linux
            // folio_start_writeback): a concurrent write_range of the
            // same pages, which no longer finds it dirty, waits for it
            {
                let mut pages = m.i_pages.lock();
                pages.clear_mark(index, MARK_DIRTY);
                pages.set_mark(index, MARK_WRITEBACK);
            }
            // Write-protected first: a write through a mapping after
            // this faults and dirties the page again (folio_mkclean)
            mkclean(m, index, phys);
            if test_clear_dirty(pg)
                && let Err(e) = m.aops().writepage(inode, phys, index)
            {
                mapping_set_error(inode, e);
                if err.is_ok() {
                    err = Err(e);
                }
            }
            m.i_pages.lock().clear_mark(index, MARK_WRITEBACK);
        }
        unlock_page(phys);
        put_page(phys);
        match index.checked_add(1) {
            Some(n) => at = n,
            None => break,
        }
    }
    wait_writeback(m, first, last);
    err
}

/// Write back the dirty pages holding bytes [start, end] of `inode` and
/// wait (Linux filemap_write_and_wait_range): nothing to do in an empty
/// mapping
pub fn write_and_wait_range(inode: &Inode, start: u64, end: u64) -> Result<(), KernelError> {
    if end < start || inode.i_data.nrpages() == 0 {
        return Ok(());
    }
    let p = PAGE_SIZE as u64;
    write_range(inode, start / p, end / p)
}

/// A page is cached for bytes [start, end] (Linux
/// filemap_range_has_page)
pub fn range_has_page(m: &AddressSpace, start: u64, end: u64) -> bool {
    let p = PAGE_SIZE as u64;
    end >= start && m.i_pages.lock().find(start / p, end / p, None).is_some()
}

/// A page for bytes [start, end] is dirty, locked or under writeback:
/// direct I/O there would first wait for it (Linux
/// filemap_range_needs_writeback). The flags are read without a
/// reference (a racing change is a stale answer, as Linux under RCU).
pub fn range_needs_writeback(m: &AddressSpace, start: u64, end: u64) -> bool {
    if end < start || m.nrpages() == 0 {
        return false;
    }
    let (first, last) = (start / PAGE_SIZE as u64, end / PAGE_SIZE as u64);
    {
        let pages = m.i_pages.lock();
        if !pages.marked(MARK_DIRTY) && !pages.marked(MARK_WRITEBACK) {
            return false;
        }
    }
    let mut at = first;
    loop {
        let next = {
            let pages = m.i_pages.lock();
            pages
                .find(at, last, None)
                .map(|(i, phys)| (i, phys, pages.get_mark(i, MARK_WRITEBACK)))
        };
        let Some((index, phys, wb)) = next else {
            return false;
        };
        if wb || page(phys).flags.load(Ordering::Acquire) & (PG_DIRTY | PG_LOCKED) != 0 {
            return true;
        }
        match index.checked_add(1) {
            Some(n) => at = n,
            None => return false,
        }
    }
}

/// Drop the pages of `inode` with index in [first, last], unmapping them
/// from every mapping first (Linux invalidate_inode_pages2_range): EBUSY
/// if one could not go, the others still do. Sleeps (page locks).
pub fn invalidate_pages2(inode: &Inode, first: u64, last: u64) -> Result<(), KernelError> {
    let m = &inode.i_data;
    if m.nrpages() == 0 {
        return Ok(());
    }
    let (mut ret, mut unmapped, mut at) = (Ok(()), false, first);
    while at <= last {
        let next = {
            let pages = m.i_pages.lock();
            pages
                .find(at, last, None)
                .filter(|&(_, p)| FRAME_ALLOCATOR.incref(p))
        };
        let Some((index, phys)) = next else {
            break;
        };
        // A mapped file: the rest of the range is unmapped at once first
        // (Linux: at the first mapped folio)
        if !unmapped && !m.i_mmap.is_empty() {
            unmap_pages(m, index, last);
            unmapped = true;
        }
        lock_page(phys);
        if page(phys).mapping.load(Ordering::Acquire) == m.key()
            && let Err(e) = unmap_invalidate(m, phys, index)
        {
            ret = Err(e);
        }
        unlock_page(phys);
        put_page(phys);
        match index.checked_add(1) {
            Some(n) => at = n,
            None => break,
        }
    }
    ret
}

/// Drop the locked page `phys`, index `index` of `m`, unmapped first
/// (Linux folio_unmap_invalidate): EBUSY if it is dirty (no
/// ->launder_folio; a device page's dirty sectors are Linux's dirty
/// buffers, which try_to_free_buffers keeps). Unmapped again under the
/// page lock: a fault maps a file page under it, so none can have
/// mapped it since.
fn unmap_invalidate(m: &AddressSpace, phys: u64, index: u64) -> Result<(), KernelError> {
    if !m.i_mmap.is_empty() {
        unmap_pages(m, index, index);
    }
    if page(phys).flags.load(Ordering::Acquire) & PG_DIRTY != 0 {
        return Err(KernelError::Busy);
    }
    remove(m, phys);
    Ok(())
}

/// Wait for the pages with index in [first, last] that another thread
/// is writing back (Linux filemap_fdatawait_range): it holds each one's
/// page lock across the write
fn wait_writeback(m: &AddressSpace, first: u64, last: u64) {
    let mut at = first;
    loop {
        let next = {
            let pages = m.i_pages.lock();
            pages
                .find(at, last, Some(MARK_WRITEBACK))
                .filter(|&(_, p)| FRAME_ALLOCATOR.incref(p))
        };
        let Some((index, phys)) = next else {
            return;
        };
        lock_page(phys);
        unlock_page(phys);
        put_page(phys);
        match index.checked_add(1) {
            Some(n) => at = n,
            None => return,
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
                if let Err(e) = r {
                    mapping_set_error(inode, e);
                }
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

/// Data already moved wins over a later error
fn short(done: usize, e: KernelError) -> Result<usize, KernelError> {
    if done > 0 { Ok(done) } else { Err(e) }
}

/// Read file data at `pos` into `buf` (Linux filemap_read): up to EOF
pub fn read(inode: &Inode, buf: &mut [u8], pos: u64) -> Result<usize, KernelError> {
    read_iter(inode, &mut IovDest::kernel(buf), pos)
}

/// Read file data at `pos` into `to` up to EOF (Linux filemap_read):
/// page by page, each uptodate and held by a reference, not locked,
/// while it is copied out
pub fn read_iter(inode: &Inode, to: &mut IovDest<'_>, pos: u64) -> Result<usize, KernelError> {
    read_with(inode, to, pos, &|i| read_page(inode, i).map(Some))
}

/// `read_iter` that waits for no I/O (Linux filemap_read with
/// IOCB_NOWAIT): only cached, uptodate pages are copied; EAGAIN at the
/// first other one if nothing was read
pub fn read_iter_nowait(
    inode: &Inode,
    to: &mut IovDest<'_>,
    pos: u64,
) -> Result<usize, KernelError> {
    read_with(inode, to, pos, &|i| match find_get(&inode.i_data, i) {
        Some(p) if uptodate(p) => Ok(Some(p)),
        Some(p) => {
            put_page(p);
            Err(KernelError::WouldBlock)
        }
        None => Err(KernelError::WouldBlock),
    })
}

/// `read_iter` of a file whose cache is its only copy (Linux
/// shmem_file_read_iter, SGP_READ): a page not cached is a hole, read
/// as zeros without adding one
pub fn read_iter_holes(
    inode: &Inode,
    to: &mut IovDest<'_>,
    pos: u64,
) -> Result<usize, KernelError> {
    read_with(inode, to, pos, &|i| match find_get(&inode.i_data, i) {
        None => Ok(None),
        Some(p) if uptodate(p) => Ok(Some(p)),
        Some(p) => {
            put_page(p);
            read_page(inode, i).map(Some)
        }
    })
}

/// The loop of `read_iter`: `get` gives each page uptodate with a
/// reference, or None for zeros
fn read_with(
    inode: &Inode,
    to: &mut IovDest<'_>,
    pos: u64,
    get: &dyn Fn(u64) -> Result<Option<u64>, KernelError>,
) -> Result<usize, KernelError> {
    let mut done = 0;
    while !to.is_empty() {
        let at = pos + done as u64;
        if at >= inode.get_size() {
            break;
        }
        let page = match get(at / PAGE_SIZE as u64) {
            Ok(p) => p,
            Err(e) => return short(done, e),
        };
        // i_size again after the page was read (a truncate may have
        // raced the read)
        let size = inode.get_size();
        let off = (at % PAGE_SIZE as u64) as usize;
        let n = (PAGE_SIZE - off)
            .min(to.len())
            .min(size.saturating_sub(at) as usize);
        let r = match page {
            Some(phys) => {
                // SAFETY: an uptodate page with our reference, no
                // reference to it held; writers hold its lock, a racing
                // one gives torn data as on Linux
                let r = unsafe { to.copy_from_page(phys, off, n) };
                put_page(phys);
                r
            }
            None => to.zero(n),
        };
        match r {
            Ok(c) if c == n && n > 0 => done += c,
            Ok(c) => return Ok(done + c),
            Err(e) => return short(done, e),
        }
    }
    Ok(done)
}

/// Write `buf` at `pos` through the page cache; see [`write_iter`]
pub fn perform_write(inode: &Inode, buf: &[u8], pos: u64) -> Result<usize, KernelError> {
    write_iter(inode, &mut IovSource::kernel(buf), pos)
}

/// Write `from` at `pos` through the page cache (Linux
/// generic_perform_write); the caller holds i_rwsem. Each page's source
/// bytes are faulted in before the page is locked and copied with
/// faults disabled under the lock (a fault there could need that very
/// page); a rejected copy is retried, for just the bytes it got if
/// some. A failure after some bytes reports those; a source that
/// cannot be faulted in is EFAULT.
pub fn write_iter(inode: &Inode, from: &mut IovSource<'_>, pos: u64) -> Result<usize, KernelError> {
    let a = inode.i_data.aops();
    write_with(inode, from, pos, &|at, n| a.write_begin(inode, at, n))
}

/// `write_iter` that waits for nothing (Linux generic_perform_write
/// with IOCB_NOWAIT: FGP_NOWAIT pages): a page another holds locked,
/// or one a partial write would first have to read, ends it with
/// EAGAIN (the bytes before it written). For a mapping with the
/// default write_begin (simple_write_begin): block devices.
pub fn write_iter_nowait(
    inode: &Inode,
    from: &mut IovSource<'_>,
    pos: u64,
) -> Result<usize, KernelError> {
    write_with(inode, from, pos, &|at, n| grab_nowait(inode, at, n))
}

/// simple_write_begin's page for a write of `n` bytes at `at`, without
/// waiting: EAGAIN where that would wait for a page lock or a read
fn grab_nowait(inode: &Inode, at: u64, n: usize) -> Result<u64, KernelError> {
    let m = &inode.i_data;
    let index = at / PAGE_SIZE as u64;
    let whole = n == PAGE_SIZE || index * PAGE_SIZE as u64 >= inode.get_size();
    let Some(phys) = find_get(m, index) else {
        if !whole {
            return Err(KernelError::WouldBlock);
        }
        return simple_write_begin(inode, at, n);
    };
    if !super::page::trylock_page(phys) {
        put_page(phys);
        return Err(KernelError::WouldBlock);
    }
    if page(phys).mapping.load(Ordering::Acquire) != m.key() || !(whole || uptodate(phys)) {
        unlock_page(phys);
        put_page(phys);
        return Err(KernelError::WouldBlock);
    }
    if !uptodate(phys) && index * PAGE_SIZE as u64 >= inode.get_size() {
        zero_page(phys, 0);
        set_uptodate(phys);
    }
    Ok(phys)
}

/// The loop of `write_iter`: `begin` gives each page locked, with a
/// reference (Linux ->write_begin)
fn write_with(
    inode: &Inode,
    from: &mut IovSource<'_>,
    pos: u64,
    begin: &dyn Fn(u64, usize) -> Result<u64, KernelError>,
) -> Result<usize, KernelError> {
    let a = inode.i_data.aops();
    let mut done = 0;
    let mut limit = PAGE_SIZE;
    while !from.is_empty() {
        let at = pos + done as u64;
        let off = (at % PAGE_SIZE as u64) as usize;
        let n = (PAGE_SIZE - off).min(from.len()).min(limit);
        if from.fault_in(n) == n {
            return short(done, KernelError::BadAddress);
        }
        let phys = match begin(at, n) {
            Ok(p) => p,
            Err(e) => return short(done, e),
        };
        match copy_page(inode, a, from, phys, at, n) {
            Ok(w) => {
                done += w;
                limit = PAGE_SIZE;
            }
            Err(0) => {}
            Err(c) => limit = c,
        }
        // After each page, so a short write still lands (an exiting
        // task's acct record), but a copy the source keeps refusing
        // cannot hold i_rwsem forever (Linux generic_perform_write)
        if crate::signal::fatal_signal_pending() {
            return short(done, KernelError::Interrupted);
        }
    }
    Ok(done)
}

/// Copy up to `n` bytes of `from` into the locked page `phys` for a
/// write at `at` and release it; the bytes accepted. A copy that comes
/// up empty, or short into a page that was not read in (Linux
/// block_write_end), is rejected with the bytes it got: the source
/// steps back over them and the page stays as it was.
fn copy_page(
    inode: &Inode,
    a: &dyn Aops,
    from: &mut IovSource<'_>,
    phys: u64,
    at: u64,
    n: usize,
) -> Result<usize, usize> {
    let off = (at % PAGE_SIZE as u64) as usize;
    // SAFETY: the locked page with our reference, no reference to it
    // held
    let c = unsafe { from.copy_to_page_nofault(phys, off, n) };
    if c == 0 || (c < n && !uptodate(phys)) {
        from.revert(c);
        unlock_page(phys);
        put_page(phys);
        return Err(c);
    }
    Ok(a.write_end(inode, at, c, phys))
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
    for (avc, t) in chain.entries() {
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
        super::memory::zap_range(&mut tlb, t, start, end);
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

/// Zero bytes [start, end) of a file whose cache is its only copy
/// (Linux shmem_truncate_range for a punched hole, with
/// truncate_pagecache_range): whole pages are unmapped and dropped (they
/// read back as zeroes), the partial pages at either edge zeroed in
/// place. The caller holds i_rwsem.
pub fn punch_range(inode: &Inode, start: u64, end: u64) {
    if start >= end {
        return;
    }
    let m = &inode.i_data;
    let ps = PAGE_SIZE as u64;
    let (first, past) = (start.div_ceil(ps), end / ps);
    if first < past {
        unmap_pages(m, first, past - 1);
        truncate_pages(m, first, past - 1);
        unmap_pages(m, first, past - 1);
    }
    let zero = |index: u64, from: u64, to: u64| {
        if let Some(phys) = find_get(m, index) {
            lock_page(phys);
            if uptodate(phys) {
                zero_bytes(phys, from as usize, to as usize);
            }
            unlock_page(phys);
            put_page(phys);
        }
    };
    let (si, ei) = (start / ps, end / ps);
    if si == ei {
        zero(si, start % ps, end % ps);
        return;
    }
    if !start.is_multiple_of(ps) {
        zero(si, start % ps, ps);
    }
    if !end.is_multiple_of(ps) {
        zero(ei, 0, end % ps);
    }
}

/// Allocate the pages of bytes [start, end) of a file whose cache is
/// its only copy (Linux shmem_fallocate, SGP_FALLOC): each new page is
/// charged and cached locked, then left unlocked and not uptodate (it
/// reads as zeros: `read_folio` fills it), so a failure can remove just
/// those again; a page left so by an earlier fallocate is zeroed and
/// made uptodate now, so that undo cannot take it. A fatal signal stops
/// it (EINTR). The caller holds i_rwsem.
pub fn falloc_range(inode: &Inode, start: u64, end: u64) -> Result<(), KernelError> {
    let m = &inode.i_data;
    let ps = PAGE_SIZE as u64;
    let (first, past) = (start / ps, end.div_ceil(ps));
    for index in first..past {
        let r = if crate::signal::fatal_signal_pending() {
            Err(KernelError::Interrupted)
        } else {
            falloc_page(m, index)
        };
        if let Err(e) = r {
            if index > first {
                undo_falloc(m, first, index - 1);
            }
            return Err(e);
        }
    }
    Ok(())
}

/// One page of `falloc_range`
fn falloc_page(m: &AddressSpace, index: u64) -> Result<(), KernelError> {
    let old = find_get(m, index);
    let phys = match old {
        Some(p) => {
            lock_page(p);
            p
        }
        None => grab(m, index)?,
    };
    if old.is_some() && !uptodate(phys) {
        zero_page(phys, 0);
        set_uptodate(phys);
    }
    unlock_page(phys);
    put_page(phys);
    Ok(())
}

/// Remove the pages with index in [first, last] that are not uptodate:
/// those a failed `falloc_range` added (Linux shmem_undo_range,
/// unfalloc)
fn undo_falloc(m: &AddressSpace, first: u64, last: u64) {
    for index in first..=last {
        if let Some(phys) = find_get(m, index) {
            lock_page(phys);
            if !uptodate(phys) {
                remove(m, phys);
            }
            unlock_page(phys);
            put_page(phys);
        }
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
    // Linux vmf_error: ENOMEM is OOM, anything else (a full tmpfs's
    // ENOSPC) SIGBUS
    let err = |e| match e {
        KernelError::OutOfMemory => VmFault::Oom,
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
        crate::block::blkdev::for_each_bdev_inode(&mut |i| i.i_data.nrpages() == 0 || f(i));
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
