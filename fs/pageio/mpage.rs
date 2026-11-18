//! Page I/O in one bio per page where its blocks are contiguous on the
//! disk (Linux fs/mpage.c): a page whose blocks map to one run (holes
//! only at its end) is read or written with a single bio; anything
//! else ("confused": buffers already on the page, a hole before a
//! block, blocks out of order, a get_block error) falls back to the
//! buffer-head paths, block_read_full_folio and
//! __block_write_full_folio. The mpage code never puts part of a page
//! into a bio but its end at end of file, so a page's read or write
//! ends with its one bio.
//!
//! hk reads a page at a time (->read_folio; no readahead, so no
//! mpage_readahead) and writes a page at a time, synchronously
//! (->writepage, which keeps the page locked and waits for its bio,
//! where Linux's mpage_writepages adds contiguous pages to one bio and
//! unlocks each once added): every bio here carries one page. No
//! get_block reads data or sets BH_Boundary in hk, so Linux's
//! map_buffer_to_folio and boundary-block pushes have no users; hk
//! pages have no PG_mappedtodisk to set.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::block::blkdev::{Bio, BioOp, BlockDevice, SECTOR_SHIFT, submit_bio};
use crate::fs::inode::Inode;
use crate::fs::pageio::buffer::{
    self, BufferHead, GetBlock, folio_buffers, folio_end_read, folio_end_writeback,
    folio_start_writeback, folio_wait_writeback, guard_bio_eod, ring, zero_frame,
};
use crate::mm::filemap::{self, PAGE_SIZE};
use crate::util::error::KernelError;

/// The disk run a page's first blocks map to: its first block, how many
/// blocks, and the device
struct Run {
    first_block: u64,
    blocks: usize,
    bdev: Arc<BlockDevice>,
}

/// Add `bh`'s mapping at block `page_block` of the page to `run`: the
/// run, or None if the block does not follow it on the disk (Linux
/// "Contiguous blocks?")
fn run_add<'a>(
    run: &'a mut Option<Run>,
    bh: &BufferHead,
    page_block: usize,
) -> Option<&'a mut Run> {
    match run {
        Some(r) if r.first_block + page_block as u64 != bh.blocknr() => None,
        Some(r) => Some(r),
        None => Some(run.insert(Run {
            first_block: bh.blocknr(),
            blocks: 0,
            bdev: bh.bdev()?,
        })),
    }
}

/// One bio of `run`'s blocks to or from the start of page `phys`, ending
/// with `end_io` (Linux bio_alloc + bio_add_folio + mpage_bio_submit_*)
fn submit(phys: u64, run: &Run, blkbits: u32, op: BioOp, end_io: fn(Box<Bio>), private: usize) {
    let mut bio = Bio::new(op, run.first_block << (blkbits - SECTOR_SHIFT));
    bio.add_seg(phys, 0, run.blocks << blkbits);
    bio.end_io = Some(end_io);
    bio.private = private;
    guard_bio_eod(&run.bdev, &mut bio);
    submit_bio(&run.bdev, bio);
}

/// I/O completion of a read (Linux mpage_read_end_io): the page's read
/// ends, uptodate if it worked
fn mpage_read_end_io(bio: Box<Bio>) {
    let (phys, ok) = (bio.private as u64, bio.status.is_ok());
    drop(bio);
    folio_end_read(phys, ok);
}

/// Map the blocks of page `phys` below the size, without allocating
/// (do_mpage_readpage's loop): the run they make and the first hole,
/// in blocks of the page; None if confused (a get_block error, data
/// read by get_block, a hole before a block, blocks not contiguous)
fn map_read(inode: &Inode, phys: u64, get_block: GetBlock) -> Option<(Option<Run>, usize)> {
    let blkbits = inode.blkbits();
    let blocks_per_folio = PAGE_SIZE >> blkbits;
    let mut block_in_file = filemap::folio_pos(phys) >> blkbits;
    let last_block =
        (block_in_file + blocks_per_folio as u64).min(inode.get_size().div_ceil(1 << blkbits));
    let map_bh = BufferHead::new_map(0);
    let mut first_hole = blocks_per_folio;
    let mut run: Option<Run> = None;
    let mut page_block = 0;
    while page_block < blocks_per_folio {
        map_bh.clear_state();
        map_bh.set_size(0);
        if block_in_file < last_block {
            map_bh.set_size(((last_block - block_in_file) << blkbits) as usize);
            get_block(inode, block_in_file, &map_bh, false).ok()?;
        }
        if !map_bh.mapped() {
            if first_hole == blocks_per_folio {
                first_hole = page_block;
            }
            page_block += 1;
            block_in_file += 1;
            continue;
        }
        // Data get_block read in, or a hole before a block
        if map_bh.uptodate() || first_hole != blocks_per_folio {
            return None;
        }
        // Contiguous blocks?
        run_add(&mut run, &map_bh, page_block)?;
        let nblocks = map_bh.size() >> blkbits;
        let take = nblocks.min(blocks_per_folio - page_block);
        page_block += take;
        block_in_file += take as u64;
    }
    if let Some(r) = &mut run {
        r.blocks = first_hole;
    }
    Some((run, first_hole))
}

/// Read the locked page `phys` of `inode` (Linux mpage_read_folio, one
/// page of do_mpage_readpage): blocks contiguous on the disk with holes
/// only at the end are read in one bio, the holes zeroed; otherwise
/// block_read_full_folio. The page is unlocked when the read ends,
/// uptodate if it worked.
pub fn mpage_read_folio(inode: &Inode, phys: u64, get_block: GetBlock) {
    // SAFETY: the caller holds the page lock
    let mapped = if unsafe { folio_buffers(phys) }.is_some() {
        None
    } else {
        map_read(inode, phys, get_block)
    };
    let Some((run, first_hole)) = mapped else {
        // confused
        if filemap::uptodate(phys) {
            return crate::mm::page::unlock_page(phys);
        }
        return buffer::block_read_full_folio(inode, phys, get_block);
    };
    let blkbits = inode.blkbits();
    if first_hole != PAGE_SIZE >> blkbits {
        zero_frame(
            phys,
            first_hole << blkbits,
            PAGE_SIZE - (first_hole << blkbits),
        );
    }
    match run {
        Some(r) => submit(
            phys,
            &r,
            blkbits,
            BioOp::Read,
            mpage_read_end_io,
            phys as usize,
        ),
        // All holes
        None => folio_end_read(phys, true),
    }
}

// ============================================================================
// Writing (Linux mpage_write_folio)
// ============================================================================

/// A page's write in flight: its page, and whether the bio failed, set
/// by the completion before it ends the writeback that its writer
/// waits for (so this, on the writer's stack, outlives every access)
struct WriteIo {
    phys: u64,
    failed: AtomicBool,
}

/// I/O completion of a write (Linux mpage_write_end_io): the page's
/// writeback ends, the error kept for the writer, which returns it to
/// ->writepage's caller (that records it on the mapping: Linux
/// mapping_set_error here)
fn mpage_write_end_io(bio: Box<Bio>) {
    // SAFETY: `submit`'s private is the writer's `WriteIo`, alive until
    // the writeback ends below (`mpage_write_folio` waits for that)
    let w = unsafe { &*(bio.private as *const WriteIo) };
    if bio.status.is_err() {
        w.failed.store(true, Ordering::Relaxed);
    }
    drop(bio);
    let phys = w.phys;
    folio_end_writeback(phys);
}

/// The disk run of a page whose buffers are all mapped, dirty and
/// uptodate up to unmapped ones at its end (mpage_write_folio's buffer
/// walk): with the mapped count; None if confused
///
/// # Safety
/// The caller holds the page lock.
unsafe fn buffers_run(phys: u64, head: &BufferHead) -> Option<Run> {
    let blocks_per_folio = PAGE_SIZE / head.size();
    let mut first_unmapped = blocks_per_folio;
    let mut run: Option<Run> = None;
    let mut page_block = 0;
    for bh in ring(head) {
        debug_assert!(
            !bh.locked(),
            "mpage_write_folio: locked buffer of {phys:#x}"
        );
        if !bh.mapped() {
            // Unmapped dirty buffers are created by block_dirty_folio:
            // mmapped data
            if bh.dirty() {
                return None;
            }
            if first_unmapped == blocks_per_folio {
                first_unmapped = page_block;
            }
            continue;
        }
        // A hole before a block; a clean or stale block
        if first_unmapped != blocks_per_folio || !bh.dirty() || !bh.uptodate() {
            return None;
        }
        run_add(&mut run, bh, page_block)?;
        page_block += 1;
    }
    // All unmapped: read over a hole by block_read_full_folio
    let mut r = run?;
    r.blocks = page_block;
    Some(r)
}

/// Map the page's blocks below the size, allocating them (the page has
/// no buffers): their run; None if confused
fn map_write(inode: &Inode, phys: u64, get_block: GetBlock) -> Option<Run> {
    let blkbits = inode.blkbits();
    let blocks_per_folio = PAGE_SIZE >> blkbits;
    let i_size = inode.get_size();
    let first = filemap::folio_pos(phys) >> blkbits;
    let last_block = i_size.checked_sub(1)? >> blkbits;
    let map_bh = BufferHead::new_map(0);
    let mut run: Option<Run> = None;
    for (block_in_file, page_block) in (first..=last_block).zip(0..blocks_per_folio) {
        map_bh.clear_state();
        map_bh.set_size(1 << blkbits);
        get_block(inode, block_in_file, &map_bh, true).ok()?;
        if !map_bh.mapped() {
            return None;
        }
        if map_bh.new_block() {
            buffer::clean_bdev_bh_alias(&map_bh);
        }
        run_add(&mut run, &map_bh, page_block)?.blocks = page_block + 1;
    }
    run
}

/// Clean the buffers the bio writes, the first `blocks` (Linux
/// clean_buffers)
///
/// # Safety
/// The caller holds the page lock.
unsafe fn clean_buffers(phys: u64, blocks: usize) {
    // SAFETY: the caller holds the page lock
    if let Some(head) = unsafe { folio_buffers(phys) } {
        for bh in ring(head).take(blocks) {
            bh.clear_dirty();
        }
    }
}

/// Write the locked, dirty page `phys` of `inode` back (Linux
/// mpage_write_folio, with hk's synchronous ->writepage): a page whose
/// blocks below the size are contiguous on the disk (mapped, dirty and
/// uptodate buffers, or none and mapped here) goes in one bio, the part
/// past the size zeroed first; any other page through
/// block_write_full_folio, its dirty buffers only. The page stays
/// locked; EIO if the write failed.
pub fn mpage_write_folio(inode: &Inode, phys: u64, get_block: GetBlock) -> Result<(), KernelError> {
    let i_size = inode.get_size();
    let pos = filemap::folio_pos(phys);
    // SAFETY: the caller holds the page lock throughout
    let run = match unsafe { folio_buffers(phys) } {
        // SAFETY: as above
        Some(head) => unsafe { buffers_run(phys, head) },
        // Whole page beyond EOF? Skip allocating blocks to avoid leaking
        // space
        None if pos >= i_size => None,
        None => {
            debug_assert!(filemap::uptodate(phys));
            map_write(inode, phys, get_block)
        }
    };
    // Don't bother writing beyond EOF, truncate will discard the folio
    let Some(run) = run.filter(|_| pos < i_size) else {
        // confused
        return buffer::block_write_full_folio(inode, phys, get_block);
    };
    if pos + PAGE_SIZE as u64 > i_size {
        // The page straddles i_size: zeroed past it on each and every
        // write, as it may be mmapped
        let length = (i_size - pos) as usize;
        zero_frame(phys, length, PAGE_SIZE - length);
    }
    let w = WriteIo {
        phys,
        failed: AtomicBool::new(false),
    };
    // SAFETY: the caller holds the page lock
    unsafe { clean_buffers(phys, run.blocks) };
    debug_assert!(!filemap::writeback(phys));
    folio_start_writeback(phys);
    let private = core::ptr::from_ref(&w) as usize;
    submit(
        phys,
        &run,
        inode.blkbits(),
        BioOp::Write,
        mpage_write_end_io,
        private,
    );
    folio_wait_writeback(phys);
    if w.failed.load(Ordering::Relaxed) {
        return Err(KernelError::Io);
    }
    Ok(())
}
