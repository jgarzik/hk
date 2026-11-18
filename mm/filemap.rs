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
//! Order: i_rwsem -> invalidate_lock -> page lock -> i_private_lock ->
//! i_pages. A lookup
//! takes its page reference under `i_pages` (get_page_unless_zero), so
//! a page removed meanwhile is never returned. A page is inserted and
//! removed locked; removal happens under the page lock and `i_pages`.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use spin::Once;

use super::anon_vma::AnonVma;
use super::fault::VmFault;
use super::page::{
    PG_ANON, PG_DIRTY, PG_LOCKED, PG_PRIVATE, PG_SLAB, PG_UPTODATE, PG_WRITEBACK, Page,
    frame_bytes, lock_page, phys_to_page, unlock_page,
};
use super::xarray::{MARK_DIRTY, MARK_WRITEBACK, XArray};
use crate::FRAME_ALLOCATOR;
use crate::fs::inode::{Inode, InodeRef};
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

    /// The page for a write of `len` bytes at `pos` without waiting
    /// (Linux ->write_begin with FGP_NOWAIT): EAGAIN where that would
    /// wait for a page lock or a read; default `grab_nowait`
    /// (simple_write_begin's page)
    fn write_begin_nowait(&self, inode: &Inode, pos: u64, len: usize) -> Result<u64, KernelError> {
        grab_nowait(inode, pos, len)
    }

    /// Dirty the page (Linux ->dirty_folio); default `filemap::dirty_folio`
    fn dirty_folio(&self, m: &AddressSpace, phys: u64) {
        dirty_folio(m, phys);
    }

    /// Bytes [offset, offset + len) of the locked page `phys`, which has
    /// private data, are being truncated (Linux ->invalidate_folio):
    /// the private data must stop referring to them, and goes if the
    /// whole page does. Default: nothing (no private data).
    fn invalidate_folio(&self, m: &AddressSpace, phys: u64, offset: usize, len: usize) {
        let _ = (m, phys, offset, len);
    }

    /// Release the private data of the locked page `phys`, so the page
    /// can leave the cache (Linux ->release_folio); false if it is in
    /// use. Default: the page's buffers (Linux filemap_release_folio
    /// without ->release_folio: try_to_free_buffers).
    fn release_folio(&self, m: &AddressSpace, phys: u64) -> bool {
        crate::fs::buffer::try_to_free_buffers(Some(m), phys)
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
    /// The inode it belongs to, for page dirtying to mark it dirty
    /// (Linux mapping->host; set with the aops by `set_aops`): null, or
    /// the inode whose `i_data` this is, set before any page is cached
    host: core::sync::atomic::AtomicPtr<Inode>,
    /// Writeback errors, reported once to each open file by fsync
    /// (Linux mapping->wb_err)
    pub wb_err: crate::util::errseq::ErrSeq,
    /// Its pages' private data (buffer heads) attached, freed and
    /// dirtied against each other (Linux i_private_lock): spin, thread
    /// context; page lock -> it -> `i_pages`
    pub i_private_lock: Mutex<()>,
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
            host: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            wb_err: crate::util::errseq::ErrSeq::new(),
            i_private_lock: Mutex::new(()),
        }
    }

    /// Set the filesystem's operations and, for a mapping whose pages
    /// get dirty, the inode it belongs to (once, before any page is
    /// cached; Linux inode->i_mapping->a_ops, mapping->host)
    pub fn set_aops(&self, a: &'static dyn Aops, host: Option<&InodeRef>) {
        self.a_ops.call_once(|| a);
        if let Some(h) = host {
            // INVARIANT: the host's own mapping (Linux inode->i_data)
            assert!(
                core::ptr::eq(&raw const *h.i_data, self),
                "filemap: a host's own mapping"
            );
            self.host
                .store(InodeRef::as_ptr(h).cast_mut(), Ordering::Release);
        }
    }

    /// The inode it belongs to (Linux mapping->host), if one was set:
    /// borrowed with the mapping, which is part of it
    fn host(&self) -> Option<&Inode> {
        let p = self.host.load(Ordering::Acquire);
        // SAFETY: null or the inode this mapping is the `i_data` of
        // (`set_aops`), so its memory outlives this borrow of the mapping
        (!p.is_null()).then(|| unsafe { &*p })
    }

    /// Its inode's superblock `Weak`, cloned (keeps the memory, not the
    /// superblock)
    pub fn host_sb(&self) -> Option<alloc::sync::Weak<crate::fs::superblock::SuperBlock>> {
        self.host().map(|i| (*i.sb).clone())
    }

    /// The device number of its inode, if a device's (a block device's
    /// cache): read with the mapping borrowed
    pub fn host_rdev(&self) -> Option<crate::fs::chardev::DevId> {
        self.host()
            .map(|i| i.rdev)
            .filter(|d| *d != crate::fs::chardev::DevId::null())
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

use super::vmstat::{Item, add as vm_add, read as vm_read};

/// `d` pages entered (or left) the cache of `m`
fn count_file(m: &AddressSpace, d: i64) {
    vm_add(Item::FilePages, d);
    if m.has_flag(AS_UNEVICTABLE) {
        vm_add(Item::Unevictable, d);
    }
    if m.acct.get().is_some() {
        vm_add(Item::Shmem, d);
    }
}

/// tmpfs and shared memory pages (Linux NR_SHMEM): /proc/meminfo Shmem
pub fn nr_shmem() -> u64 {
    vm_read(Item::Shmem)
}

/// Page-cache pages (Linux NR_FILE_PAGES)
pub fn nr_file_pages() -> u64 {
    vm_read(Item::FilePages)
}

/// Page-cache pages that never leave memory (ramfs; Linux Unevictable)
pub fn nr_unevictable() -> u64 {
    vm_read(Item::Unevictable)
}

fn count_dirty(d: i64) {
    vm_add(Item::FileDirty, d);
    if d > 0 {
        // Linux account_page_dirtied: this_cpu_inc(bdp_ratelimits)
        super::writeback::dirtied(d);
    }
}

/// Dirty page-cache pages (Linux global_node_page_state(NR_FILE_DIRTY))
pub fn nr_dirty() -> u64 {
    vm_read(Item::FileDirty)
}

/// Set the page's dirty bit; true if it was set already (Linux
/// folio_test_set_dirty)
pub fn test_set_page_dirty(phys: u64) -> bool {
    page(phys).flags.fetch_or(PG_DIRTY, Ordering::AcqRel) & PG_DIRTY != 0
}

/// The page's dirty bit (Linux folio_test_dirty)
pub fn page_dirty(phys: u64) -> bool {
    page(phys).flags.load(Ordering::Acquire) & PG_DIRTY != 0
}

/// A page of `m` just got its dirty bit: count it and set its DIRTY
/// mark, if it is still in `m` (Linux __folio_mark_dirty, under the
/// i_pages lock)
pub fn account_dirtied(m: &AddressSpace, phys: u64) {
    let pg = page(phys);
    if pg.mapping.load(Ordering::Acquire) != m.key() {
        return;
    }
    let mut pages = m.i_pages.lock();
    if pg.mapping.load(Ordering::Acquire) == m.key() {
        count_dirty(1);
        pages.set_mark(pg.index.load(Ordering::Relaxed), MARK_DIRTY);
    }
}

/// Clear the dirty bit of a page of `m` whose data needs no writing
/// any more (Linux folio_cancel_dirty)
pub fn cancel_dirty(m: &AddressSpace, phys: u64) {
    let pg = page(phys);
    if pg.mapping.load(Ordering::Acquire) == m.key() {
        test_clear_dirty(pg);
    }
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

/// The page's private data, if it has some (Linux folio_get_private
/// under folio_test_private)
pub fn folio_private(phys: u64) -> Option<u64> {
    let pg = page(phys);
    (pg.flags.load(Ordering::Acquire) & PG_PRIVATE != 0).then(|| pg.private.load(Ordering::Acquire))
}

/// Hang `data` on the locked page, which takes a reference for it
/// (Linux folio_attach_private)
pub fn folio_attach_private(phys: u64, data: u64) {
    let pg = page(phys);
    debug_assert!(pg.flags.load(Ordering::Relaxed) & PG_PRIVATE == 0);
    FRAME_ALLOCATOR.incref(phys);
    pg.private.store(data, Ordering::Release);
    pg.flags.fetch_or(PG_PRIVATE, Ordering::Release);
}

/// Take the locked page's private data off, with its reference (Linux
/// folio_detach_private); the data
pub fn folio_detach_private(phys: u64) -> u64 {
    let pg = page(phys);
    if pg.flags.fetch_and(!PG_PRIVATE, Ordering::AcqRel) & PG_PRIVATE == 0 {
        return 0;
    }
    let data = pg.private.swap(0, Ordering::AcqRel);
    put_page(phys);
    data
}

/// The page is under writeback (Linux folio_test_writeback)
pub fn writeback(phys: u64) -> bool {
    page(phys).flags.load(Ordering::Acquire) & PG_WRITEBACK != 0
}

/// Set or clear the page's writeback flag (Linux
/// folio_start_writeback / folio_end_writeback's flag); any context
pub fn set_writeback(phys: u64, on: bool) {
    let f = &page(phys).flags;
    if on {
        f.fetch_or(PG_WRITEBACK, Ordering::Release);
    } else {
        f.fetch_and(!PG_WRITEBACK, Ordering::Release);
    }
}

/// Byte offset of the page in its file (Linux folio_pos)
pub fn folio_pos(phys: u64) -> u64 {
    page(phys).index.load(Ordering::Relaxed) * PAGE_SIZE as u64
}

/// The page-cache mapping the page is in, if any (Linux
/// folio->mapping), for the guard's life: a mapping is part of an
/// inode, whose memory is freed a grace period after its teardown, and
/// the teardown takes every page out first. As Linux, a caller that
/// changes the mapping keeps the page from being truncated meanwhile.
pub fn folio_mapping(phys: u64, _rcu: &crate::sync::rcu::RcuReadGuard) -> Option<&AddressSpace> {
    let pg = page(phys);
    if pg.flags.load(Ordering::Acquire) & (PG_ANON | PG_SLAB) != 0 {
        return None;
    }
    let key = pg.mapping.load(Ordering::Acquire);
    if key == 0 || key & 1 != 0 {
        return None;
    }
    // SAFETY: a page-cache page's mapping word is its AddressSpace's
    // address (`insert`), cleared before the inode holding it is torn
    // down; read under the guard, the inode's memory outlives it
    // (freed by RCU, `i_callback`)
    Some(unsafe { &*(key as *const AddressSpace) })
}

/// The first cached page with index in [from, last], with a reference
pub fn find_get_range(m: &AddressSpace, from: u64, last: u64) -> Option<(u64, u64)> {
    let pages = m.i_pages.lock();
    pages
        .find(from, last, None)
        .filter(|&(_, p)| FRAME_ALLOCATOR.incref(p))
}

/// Release the locked page's private data so it can leave the cache
/// (Linux filemap_release_folio): true if it has none left; never
/// while under writeback
pub fn filemap_release_folio(m: &AddressSpace, phys: u64) -> bool {
    if folio_private(phys).is_none() {
        return true;
    }
    if writeback(phys) {
        return false;
    }
    m.aops().release_folio(m, phys)
}

/// Bytes [offset, offset + len) of the locked page are truncated
/// (Linux folio_invalidate)
fn folio_invalidate(m: &AddressSpace, phys: u64, offset: usize, len: usize) {
    m.aops().invalidate_folio(m, phys, offset, len);
}

/// Truncate the locked page `phys` out of `m` (Linux
/// truncate_inode_folio: truncate_cleanup_folio, then
/// filemap_remove_folio): its private data invalidated whole first; a
/// page whose data stays busy leaves the cache with it
fn truncate_folio(m: &AddressSpace, phys: u64) {
    if page(phys).mapping.load(Ordering::Acquire) != m.key() {
        return;
    }
    if folio_private(phys).is_some() {
        folio_invalidate(m, phys, 0, PAGE_SIZE);
    }
    remove(m, phys);
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
    let stored = super::xarray::store_nomem_locked(
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
        Ok((_, pages)) => {
            // Under the i_pages lock, read lock-free (Linux nrpages under
            // the xa_lock, READ_ONCE): a load and a store
            crate::sync::Sole::sole_add(&m.nrpages, 1);
            drop(pages);
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
    loop {
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
            // Truncated while the read was in flight (a ->read_folio may
            // unlock at the end of the read and lock again): again (Linux
            // filemap_read's retry of a folio that lost its mapping)
            let gone = page(phys).mapping.load(Ordering::Acquire) != m.key();
            // The page stays cached, not uptodate, for a later read to
            // retry (Linux do_read_cache_folio / filemap_read_folio
            // error): it may hold dirty buffers a write left (a block
            // device page written in part), which must not be dropped
            unlock_page(phys);
            put_page(phys);
            if gone {
                continue;
            }
            return Err(e);
        }
        unlock_page(phys);
        return Ok(phys);
    }
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
        // Under the i_pages lock (Linux page_cache_delete: nrpages -= nr)
        crate::sync::Sole::sole_add(&m.nrpages, u64::MAX);
    }
    test_clear_dirty(pg);
    pg.flags.fetch_and(!PG_UPTODATE, Ordering::Relaxed);
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
        truncate_folio(m, phys);
        unlock_page(phys);
        put_page(phys);
        match index.checked_add(1) {
            Some(i) => at = i,
            None => return,
        }
    }
}

/// Drop every page of a mapping nobody else can reach any more (Linux
/// truncate_inode_pages_final, from eviction): pages with private data
/// (buffers) through ->invalidate_folio under their lock, as Linux
/// truncates every page; the rest with no page lock and no sleep. A
/// page whose buffers stay busy (a reference held elsewhere) leaves
/// with them.
fn truncate_final(m: &AddressSpace) {
    truncate_private(m);
    count_file(m, -(m.nrpages() as i64));
    m.uncharge(m.nrpages());
    let mut pages = m.i_pages.lock();
    pages.destroy(&mut |phys| {
        let pg = page(phys);
        pg.mapping.store(0, Ordering::Release);
        test_clear_dirty(pg);
        pg.flags.fetch_and(!PG_UPTODATE, Ordering::Relaxed);
        put_page(phys);
    });
    m.nrpages.store(0, Ordering::Relaxed);
}

/// Truncate the pages of `m` that have private data (`truncate_final`)
fn truncate_private(m: &AddressSpace) {
    let mut at = 0;
    while m.nrpages() != 0 {
        let next = {
            let pages = m.i_pages.lock();
            let mut i = at;
            loop {
                match pages.find(i, u64::MAX, None) {
                    Some((index, p)) if folio_private(p).is_some() => {
                        break FRAME_ALLOCATOR.incref(p).then_some((index, p));
                    }
                    Some((index, _)) => match index.checked_add(1) {
                        Some(n) => i = n,
                        None => break None,
                    },
                    None => break None,
                }
            }
        };
        let Some((index, phys)) = next else {
            return;
        };
        lock_page(phys);
        truncate_folio(m, phys);
        unlock_page(phys);
        put_page(phys);
        match index.checked_add(1) {
            Some(n) => at = n,
            None => return,
        }
    }
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
    mark_host_dirty(m);
}

/// The generic dirtying (Linux filemap_dirty_folio): PG_dirty and the
/// DIRTY mark, counted
pub fn dirty_folio(m: &AddressSpace, phys: u64) {
    if !test_set_page_dirty(phys) {
        account_dirtied(m, phys);
    }
}

/// Mark the mapping's inode dirty for its pages (Linux
/// __mark_inode_dirty(I_DIRTY_PAGES)), a reference taken unless its
/// last went (Linux skips an I_FREEING inode)
pub fn mark_host_dirty(m: &AddressSpace) {
    if let Some(inode) = host_igrab(m) {
        crate::fs::fs_writeback::mark_inode_dirty_pages(&inode);
    }
}

/// A reference on the mapping's inode, unless it has none or its last
/// went
pub fn host_igrab(m: &AddressSpace) -> Option<InodeRef> {
    m.host().and_then(Inode::igrab)
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

/// `mapping_set_error` from any context, taking no reference: the
/// mapping's `wb_err` and its inode's superblock's `s_wb_err`, reached
/// through the inode's `Weak` (`superblock::sb_wb_err_set`; Linux
/// mapping_set_error from a bio completion)
///
/// # Safety
/// The mapping's inode has not dropped its superblock `Weak` (its
/// teardown is not past `destroy_inode` dropping its `i_data`): the
/// caller holds a reference, or a locked buffer of a page still in the
/// mapping (the teardown's truncate waits for every buffer's lock,
/// `discard_buffer`, before `i_data` is gone).
pub unsafe fn mapping_set_error_raw(m: &AddressSpace, e: KernelError) {
    m.wb_err.set(e);
    if let Some(h) = m.host() {
        crate::fs::superblock::sb_wb_err_set(&h.sb, e);
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

/// Write back the dirty pages of `file`'s mapping holding bytes
/// [start, end] and wait, then report its writeback error since the
/// file last looked, once; the first error (Linux
/// file_write_and_wait_range)
pub fn file_write_and_wait_range(
    file: &crate::fs::file::File,
    start: u64,
    end: u64,
) -> Result<(), KernelError> {
    if end < start {
        return Ok(());
    }
    let r = match file.mapping_inode() {
        Some(host) => write_and_wait_range(&host, start, end),
        None => Ok(()),
    };
    r.and(file.check_and_advance_wb_err())
}

/// Some page of `m` has mark `mark` (Linux mapping_tagged)
pub fn mapping_tagged(m: &AddressSpace, mark: usize) -> bool {
    m.i_pages.lock().marked(mark)
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
/// (Linux folio_unmap_invalidate): EBUSY if its private data stays (a
/// dirty or busy buffer) or it is dirty (no ->launder_folio). Unmapped
/// again under the page lock: a fault maps a file page under it, so
/// none can have mapped it since.
fn unmap_invalidate(m: &AddressSpace, phys: u64, index: u64) -> Result<(), KernelError> {
    if !m.i_mmap.is_empty() {
        unmap_pages(m, index, index);
    }
    if !filemap_release_folio(m, phys) || page_dirty(phys) {
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
    // The per-CPU buffer LRUs hold buffers: emptied first, so pages with
    // buffers can drop them (as kill_bdev)
    if range_has_page(m, start, end - 1) {
        crate::fs::buffer::invalidate_bh_lrus();
    }
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
                truncate_folio(m, phys);
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
            if evict_folio(m, phys) {
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

/// Drop the locked page `phys` of `m` if clean and used by nobody
/// else (Linux mapping_evict_folio): its private data released first
fn evict_folio(m: &AddressSpace, phys: u64) -> bool {
    let pg = page(phys);
    if pg.mapping.load(Ordering::Acquire) != m.key()
        || pg.flags.load(Ordering::Acquire) & (PG_DIRTY | PG_WRITEBACK) != 0
    {
        return false;
    }
    // The cache's reference, ours, and the private data's: no PTE or
    // user holds it
    let private = u32::from(folio_private(phys).is_some());
    if FRAME_ALLOCATOR.refcount(phys) > 2 + private {
        return false;
    }
    if !filemap_release_folio(m, phys) {
        return false;
    }
    // Linux remove_mapping: the count frozen at the cache's and ours
    if FRAME_ALLOCATOR.refcount(phys) != 2 || page_dirty(phys) {
        return false;
    }
    remove(m, phys);
    true
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
/// EAGAIN (the bytes before it written), through ->write_begin_nowait:
/// block devices (an O_DIRECT write's buffered rest).
pub fn write_iter_nowait(
    inode: &Inode,
    from: &mut IovSource<'_>,
    pos: u64,
) -> Result<usize, KernelError> {
    let a = inode.i_data.aops();
    write_with(inode, from, pos, &|at, n| {
        a.write_begin_nowait(inode, at, n)
    })
}

/// simple_write_begin's page for a write of `n` bytes at `at`, without
/// waiting: EAGAIN where that would wait for a page lock or a read
pub fn grab_nowait(inode: &Inode, at: u64, n: usize) -> Result<u64, KernelError> {
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
        // Linux truncate_inode_partial_folio: the private data past the
        // size goes too
        if page(phys).mapping.load(Ordering::Acquire) == m.key() && folio_private(phys).is_some() {
            folio_invalidate(m, phys, off, PAGE_SIZE - off);
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

/// `f` on each inode that may hold reclaimable cache (every
/// superblock's, the block devices' on the bdev superblock) until it
/// returns false; no allocation. `reclaim`: skip a superblock whose
/// s_umount is not free at once (reclaim may run under one)
fn for_each_cache_inode(reclaim: bool, f: &mut dyn FnMut(&Inode) -> bool) {
    use crate::fs::superblock::{iterate_supers, iterate_supers_trylock};
    let mut more = true;
    let each = |sb: &alloc::sync::Arc<crate::fs::superblock::SuperBlock>| {
        more = more
            && crate::fs::inode::for_each_sb_inode(sb, &mut |i| i.i_data.nrpages() == 0 || f(i));
    };
    if reclaim {
        iterate_supers_trylock(each);
    } else {
        iterate_supers(each);
    }
}

/// Drop up to `nr` clean, unmapped page-cache pages for direct reclaim
/// (Linux shrink_inactive_list of the file LRU). Deviation: no file
/// LRU, so the pages go inode by inode, not oldest first. Allocates
/// nothing (it runs when memory is short) and never sleeps on a page
/// lock (trylock); stops once `nr` are freed. The number freed.
pub fn shrink_cache(nr: usize) -> usize {
    let mut freed = 0;
    for_each_cache_inode(true, &mut |inode| {
        freed += invalidate_clean(inode, 0, u64::MAX) as usize;
        freed < nr
    });
    freed
}

/// vm.drop_caches 1 (Linux drop_pagecache_sb over every superblock):
/// drop every clean, unmapped page-cache page
pub fn drop_pagecache() {
    for_each_cache_inode(false, &mut |inode| {
        invalidate_clean(inode, 0, u64::MAX);
        true
    });
}
