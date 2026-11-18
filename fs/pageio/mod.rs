//! Page-cache I/O to and from disks: buffer heads (Linux fs/buffer.c),
//! page-sized bios (fs/mpage.c), the block device files and their page
//! cache (block/fops.c, def_blk_aops), inode writeback
//! (fs/fs-writeback.c) and the sync calls (fs/sync.c)

pub mod blkdev_ops;
pub mod buffer;
pub mod fs_writeback;
pub mod mpage;
pub mod sync;
