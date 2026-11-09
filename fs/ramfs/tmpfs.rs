//! tmpfs: ramfs with limits (Linux mm/shmem.c, CONFIG_TMPFS)
//!
//! A tmpfs superblock is a ramfs one (`fs::ramfs` makes its inodes,
//! directories and page-cache files) whose private data is a [`ShmemSb`]:
//! the block limit its file pages are charged to as they enter the cache
//! (`filemap::PageAcct`), and the inode space (Linux free_ispace) that
//! every inode, every extra hard link and every user.* xattr takes from.
//! Options: size=, nr_blocks=, nr_inodes= (0: unlimited), mode=, uid=,
//! gid=, inode32/inode64, noswap, huge=never; defaults half of RAM's
//! pages for both limits, mode 01777 (Linux shmem_fill_super).
//!
//! ## Locking
//!
//! No lock (doc/LOCKING.md, tmpfs accounting): the free blocks and the
//! free inode space are atomic counters whose limit check and update are
//! one compare-exchange (Linux takes sbinfo->stat_lock and a percpu
//! counter); a remount moves a limit by adding the difference to the
//! free counter in one compare-exchange that fails if the use already
//! exceeds the new limit, under s_umount. Charges run in any context
//! (an inode's last reference) and never sleep.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::fs::KernelError;
use crate::fs::inode::{AsAny, Gid, Uid};
use crate::fs::superblock::{
    FileSystemType, StatFs, SuperBlock, SuperBlockData, SuperOps, TMPFS_MAGIC, sb_flag_word,
};
use crate::mm::filemap::{self, PageAcct};
use crate::util::kalloc::try_arc;

/// Inode space one inode takes (Linux BOGO_INODE_SIZE)
const BOGO_INODE_SIZE: u64 = 1024;

/// RAM's pages (Linux totalram_pages)
fn totalram_pages() -> u64 {
    #[cfg(not(test))]
    return crate::FRAME_ALLOCATOR.stats().total_bytes / filemap::PAGE_SIZE as u64;
    #[cfg(test)]
    return 1 << 20;
}

/// Linux shmem_default_max_blocks: half of RAM
fn default_blocks() -> u64 {
    totalram_pages() / 2
}

/// Linux shmem_default_max_inodes: one per page of half of RAM (no
/// highmem on 64-bit)
fn default_inodes() -> u64 {
    (totalram_pages() / 2).min(u64::MAX / BOGO_INODE_SIZE)
}

/// The block limit file pages are charged to
pub struct Blocks {
    /// The limit in pages, 0 for none (Linux max_blocks)
    max: AtomicU64,
    /// Pages left under it (Linux max_blocks - used_blocks); not kept
    /// while there is no limit
    free: AtomicU64,
}

impl PageAcct for Blocks {
    fn charge(&self, pages: u64) -> Result<(), KernelError> {
        if self.max.load(Ordering::Relaxed) == 0 {
            return Ok(());
        }
        take(&self.free, pages)
    }

    fn uncharge(&self, pages: u64) {
        if self.max.load(Ordering::Relaxed) != 0 {
            self.free.fetch_add(pages, Ordering::Relaxed);
        }
    }
}

/// Take `n` from the counter `c` (NoSpace when short)
fn take(c: &AtomicU64, n: u64) -> Result<(), KernelError> {
    c.try_update(Ordering::Relaxed, Ordering::Relaxed, |f| f.checked_sub(n))
        .map(|_| ())
        .map_err(|_| KernelError::NoSpace)
}

/// Move the limit `max` with free counter `free` to `new` (not 0):
/// EINVAL if more than `new` is in use (Linux shmem_reconfigure "Too
/// small a size for current use"), the counter unchanged
fn relimit(max: &AtomicU64, free: &AtomicU64, new: u64) -> Result<(), KernelError> {
    let old = max.load(Ordering::Relaxed);
    free.try_update(Ordering::Relaxed, Ordering::Relaxed, |f| {
        let used = old.saturating_sub(f);
        new.checked_sub(used)
    })
    .map_err(|_| KernelError::InvalidArgument)?;
    max.store(new, Ordering::Relaxed);
    Ok(())
}

/// One tmpfs superblock's limits and options (Linux shmem_sb_info)
pub struct ShmemSb {
    blocks: Arc<Blocks>,
    /// The inode limit, 0 for none (Linux max_inodes)
    max_inodes: AtomicU64,
    /// Inode space left: inodes times BOGO_INODE_SIZE, less xattrs
    /// (Linux free_ispace); the xattr pool of its inodes
    ispace: Arc<AtomicU64>,
    /// The root's mode and owner (fixed at mount)
    mode: u16,
    uid: Uid,
    gid: Gid,
    /// inode64 (Linux full_inums)
    inode64: AtomicBool,
    noswap: AtomicBool,
}

impl SuperBlockData for ShmemSb {}

impl AsAny for ShmemSb {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

/// `f` on `sb`'s tmpfs data; None if `sb` is not a tmpfs
pub fn with<R>(sb: &SuperBlock, f: impl FnOnce(&ShmemSb) -> R) -> Option<R> {
    let p = sb.get_private()?;
    p.as_ref().as_any().downcast_ref::<ShmemSb>().map(f)
}

/// The block limit of tmpfs `sb` (0: none); None if not a tmpfs
pub fn max_blocks(sb: &SuperBlock) -> Option<u64> {
    with(sb, |t| t.blocks.max.load(Ordering::Relaxed))
}

impl ShmemSb {
    fn new(o: &Opts) -> Result<Self, KernelError> {
        let blocks = o.blocks.unwrap_or_else(default_blocks);
        let inodes = o.inodes.unwrap_or_else(default_inodes);
        Ok(Self {
            blocks: try_arc(Blocks {
                max: AtomicU64::new(blocks),
                free: AtomicU64::new(blocks),
            })?,
            max_inodes: AtomicU64::new(inodes),
            ispace: try_arc(AtomicU64::new(inodes * BOGO_INODE_SIZE))?,
            mode: o.mode.unwrap_or(0o1777),
            uid: o.uid.unwrap_or(0),
            gid: o.gid.unwrap_or(0),
            inode64: AtomicBool::new(o.inode64.unwrap_or(true)),
            noswap: AtomicBool::new(o.noswap),
        })
    }

    fn limited_inodes(&self) -> bool {
        self.max_inodes.load(Ordering::Relaxed) != 0
    }

    /// Where its file pages are charged
    pub fn page_acct(&self) -> Arc<dyn PageAcct> {
        self.blocks.clone()
    }

    /// The xattr space (None: no inode limit, so none for xattrs;
    /// Linux shmem_xattr_handler_set)
    pub fn xattr_pool(&self) -> Option<Arc<AtomicU64>> {
        self.limited_inodes().then(|| self.ispace.clone())
    }

    /// Take an inode (Linux shmem_reserve_inode): ENOSPC when none left
    pub fn reserve_inode(&self) -> Result<(), KernelError> {
        if !self.limited_inodes() {
            return Ok(());
        }
        take(&self.ispace, BOGO_INODE_SIZE)
    }

    /// Give an inode back (Linux shmem_free_inode)
    pub fn free_inode(&self) {
        if self.limited_inodes() {
            self.ispace.fetch_add(BOGO_INODE_SIZE, Ordering::Relaxed);
        }
    }

    /// Linux shmem_statfs: the limits and what is left under them; 0
    /// for an unlimited one, as simple_statfs
    fn statfs(&self) -> StatFs {
        let mut st = StatFs {
            f_type: TMPFS_MAGIC,
            f_bsize: filemap::PAGE_SIZE as u64,
            f_namelen: 255,
            ..StatFs::default()
        };
        let max = self.blocks.max.load(Ordering::Relaxed);
        if max != 0 {
            st.f_blocks = max;
            st.f_bfree = self.blocks.free.load(Ordering::Relaxed).min(max);
            st.f_bavail = st.f_bfree;
        }
        let inodes = self.max_inodes.load(Ordering::Relaxed);
        if inodes != 0 {
            st.f_files = inodes;
            st.f_ffree = self.ispace.load(Ordering::Relaxed) / BOGO_INODE_SIZE;
        }
        st
    }

    /// Linux shmem_reconfigure: a new limit must cover what is in use
    /// and cannot be put on an unlimited mount; noswap cannot be turned
    /// on. Checked before anything changes. mode=, uid=, gid= are
    /// parsed but change nothing.
    fn reconfigure(&self, o: &Opts) -> Result<(), KernelError> {
        let b = &self.blocks;
        if let Some(n) = o.blocks.filter(|&n| n != 0) {
            let max = b.max.load(Ordering::Relaxed);
            let used = max.saturating_sub(b.free.load(Ordering::Relaxed));
            if max == 0 || used > n {
                return Err(KernelError::InvalidArgument);
            }
        }
        if let Some(n) = o.inodes.filter(|&n| n != 0) {
            let max = self.max_inodes.load(Ordering::Relaxed);
            let used = (max * BOGO_INODE_SIZE).saturating_sub(self.ispace.load(Ordering::Relaxed));
            if max == 0 || n * BOGO_INODE_SIZE < used {
                return Err(KernelError::InvalidArgument);
            }
        }
        if o.noswap && !self.noswap.load(Ordering::Relaxed) {
            return Err(KernelError::InvalidArgument);
        }
        if let Some(n) = o.blocks {
            if n == 0 {
                b.max.store(0, Ordering::Relaxed);
            } else {
                relimit(&b.max, &b.free, n)?;
            }
        }
        if let Some(n) = o.inodes {
            if n == 0 {
                self.max_inodes.store(0, Ordering::Relaxed);
            } else {
                let (max, space) = (&self.max_inodes, &self.ispace);
                let old = max.load(Ordering::Relaxed);
                space
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |f| {
                        let used = (old * BOGO_INODE_SIZE).saturating_sub(f);
                        (n * BOGO_INODE_SIZE).checked_sub(used)
                    })
                    .map_err(|_| KernelError::InvalidArgument)?;
                max.store(n, Ordering::Relaxed);
            }
        }
        if let Some(i) = o.inode64 {
            self.inode64.store(i, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Linux shmem_show_options: the limits unless the defaults, the
    /// root's mode and owner unless 01777 root:root, inode32/inode64
    /// (CONFIG_TMPFS_INODE64), noswap
    fn show(&self, out: &mut Vec<u8>) {
        use core::fmt::Write;
        let mut s = alloc::string::String::new();
        let blocks = self.blocks.max.load(Ordering::Relaxed);
        if blocks != default_blocks() {
            let _ = write!(s, ",size={}k", blocks * (filemap::PAGE_SIZE as u64 / 1024));
        }
        let inodes = self.max_inodes.load(Ordering::Relaxed);
        if inodes != default_inodes() {
            let _ = write!(s, ",nr_inodes={inodes}");
        }
        if self.mode != 0o1777 {
            let _ = write!(s, ",mode={:03o}", self.mode);
        }
        if self.uid != 0 {
            let _ = write!(s, ",uid={}", self.uid);
        }
        if self.gid != 0 {
            let _ = write!(s, ",gid={}", self.gid);
        }
        let bits = if self.inode64.load(Ordering::Relaxed) {
            64
        } else {
            32
        };
        let _ = write!(s, ",inode{bits}");
        if self.noswap.load(Ordering::Relaxed) {
            s.push_str(",noswap");
        }
        out.extend_from_slice(s.as_bytes());
    }
}

// ============================================================================
// Options (Linux shmem_fs_parameters, shmem_parse_one)
// ============================================================================

/// What one options string sets (None: not given)
#[derive(Default)]
struct Opts {
    blocks: Option<u64>,
    inodes: Option<u64>,
    mode: Option<u16>,
    uid: Option<Uid>,
    gid: Option<Gid>,
    inode64: Option<bool>,
    noswap: bool,
}

/// An unsigned number as Linux simple_strtoull with base 0 (0x hex,
/// leading 0 octal, else decimal): its value and the rest. Wraps on
/// overflow, as Linux.
fn strtoull(s: &[u8]) -> (u64, &[u8]) {
    let (base, mut i) = match s {
        [b'0', b'x' | b'X', c, ..] if c.is_ascii_hexdigit() => (16, 2),
        [b'0', ..] => (8, 0),
        _ => (10, 0),
    };
    let mut v = 0u64;
    while let Some(d) = s.get(i).and_then(|&c| (c as char).to_digit(base)) {
        v = v.wrapping_mul(u64::from(base)).wrapping_add(u64::from(d));
        i += 1;
    }
    (v, &s[i..])
}

/// Linux memparse: a number with an optional K, M, G, T, P or E suffix
/// (either case); its value and the rest
fn memparse(s: &[u8]) -> (u64, &[u8]) {
    let (v, rest) = strtoull(s);
    let shift = match rest.first().map(u8::to_ascii_lowercase) {
        Some(b'k') => 10,
        Some(b'm') => 20,
        Some(b'g') => 30,
        Some(b't') => 40,
        Some(b'p') => 50,
        Some(b'e') => 60,
        _ => return (v, rest),
    };
    (v << shift, &rest[1..])
}

/// A whole-string unsigned number in `base` (Linux kstrtouint: a
/// leading '+', base 0 as strtoull, a trailing newline), fitting u32
fn kstrtou32(s: &[u8], base: u32) -> Option<u32> {
    let s = s.strip_prefix(b"+").unwrap_or(s);
    let s = s.strip_suffix(b"\n").unwrap_or(s);
    let (v, rest) = if base == 0 {
        strtoull(s)
    } else {
        let n = s
            .iter()
            .take_while(|&&c| (c as char).is_digit(base))
            .count();
        let v = s[..n].iter().try_fold(0u64, |v, &c| {
            v.checked_mul(u64::from(base))?
                .checked_add(u64::from((c as char).to_digit(base)?))
        })?;
        (v, &s[n..])
    };
    if s.is_empty() || !rest.is_empty() {
        return None;
    }
    u32::try_from(v).ok()
}

/// A uid or gid option: -1 is not a valid id (Linux make_kuid)
fn id(v: &[u8]) -> Option<u32> {
    kstrtou32(v, 0).filter(|&n| n != u32::MAX)
}

/// Split an options string at commas not followed by a digit (Linux
/// shmem_next_opt: mpol node lists hold commas); empty ones dropped
fn split_opts(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = data;
    core::iter::from_fn(move || {
        while !rest.is_empty() {
            let mut end = rest.len();
            let mut i = 0;
            while let Some(p) = rest[i..].iter().position(|&c| c == b',') {
                let at = i + p;
                if !rest.get(at + 1).is_some_and(u8::is_ascii_digit) {
                    end = at;
                    break;
                }
                i = at + 1;
            }
            let opt = &rest[..end];
            rest = rest.get(end + 1..).unwrap_or(&[]);
            if !opt.is_empty() {
                return Some(opt);
            }
        }
        None
    })
}

/// Parse a tmpfs options string: EINVAL for an unknown option, a bad
/// value or one Linux would refuse here (huge= other than never: no
/// huge pages in the page cache; mpol=: no shmem NUMA policy)
fn parse(data: &[u8]) -> Result<Opts, KernelError> {
    let bad = KernelError::InvalidArgument;
    let mut o = Opts::default();
    for opt in split_opts(data) {
        if sb_flag_word(opt) {
            continue;
        }
        let (k, v) = match opt.iter().position(|&c| c == b'=') {
            Some(i) => (&opt[..i], Some(&opt[i + 1..])),
            None => (opt, None),
        };
        // A value option needs a non-empty value, a flag has none
        let val = || {
            v.filter(|v| !v.is_empty())
                .ok_or(KernelError::InvalidArgument)
        };
        match k {
            b"size" => {
                let (mut size, mut rest) = memparse(val()?);
                if let Some(r) = rest.strip_prefix(b"%") {
                    size = (size << 12).wrapping_mul(totalram_pages()) / 100;
                    rest = r;
                }
                if !rest.is_empty() {
                    return Err(bad);
                }
                o.blocks = Some(size.div_ceil(filemap::PAGE_SIZE as u64));
            }
            b"nr_blocks" => {
                let (n, rest) = memparse(val()?);
                if !rest.is_empty() || n > i64::MAX as u64 {
                    return Err(bad);
                }
                o.blocks = Some(n);
            }
            b"nr_inodes" => {
                let (n, rest) = memparse(val()?);
                if !rest.is_empty() || n > u64::MAX / BOGO_INODE_SIZE {
                    return Err(bad);
                }
                o.inodes = Some(n);
            }
            // Linux fsparam_u32oct: octal, masked to the mode bits
            b"mode" => o.mode = Some((kstrtou32(val()?, 8).ok_or(bad)? & 0o7777) as u16),
            b"uid" => o.uid = Some(id(val()?).ok_or(bad)?),
            b"gid" => o.gid = Some(id(val()?).ok_or(bad)?),
            b"huge" if val()? == b"never" => {}
            b"inode32" | b"inode64" | b"noswap" if v.is_some() => return Err(bad),
            b"inode32" => o.inode64 = Some(false),
            b"inode64" => o.inode64 = Some(true),
            b"noswap" => o.noswap = true,
            _ => return Err(bad),
        }
    }
    Ok(o)
}

/// Check a tmpfs options string (EINVAL as `parse`) without using it
/// (devtmpfs: a mount shows the one superblock, Linux devtmpfs_get_tree)
pub fn check_opts(data: &[u8]) -> Result<(), KernelError> {
    parse(data).map(|_| ())
}

// ============================================================================
// The file system type
// ============================================================================

/// tmpfs superblock operations (Linux shmem_ops)
pub struct TmpfsSuperOps;

impl SuperOps for TmpfsSuperOps {
    fn alloc_inode(
        &self,
        sb: &Arc<SuperBlock>,
        mode: crate::fs::inode::InodeMode,
        i_op: &'static dyn crate::fs::inode::InodeOps,
    ) -> Result<Arc<crate::fs::inode::Inode>, KernelError> {
        super::RAMFS_SUPER_OPS.alloc_inode(sb, mode, i_op)
    }

    fn statfs(&self, sb: &SuperBlock) -> StatFs {
        with(sb, ShmemSb::statfs).unwrap_or_default()
    }

    fn remount(&self, sb: &SuperBlock, data: &[u8]) -> Result<(), KernelError> {
        let o = parse(data)?;
        with(sb, |t| t.reconfigure(&o)).unwrap_or(Ok(()))
    }

    fn show_options(&self, sb: &SuperBlock, out: &mut Vec<u8>) {
        with(sb, |t| t.show(out));
    }
}

pub static TMPFS_SUPER_OPS: TmpfsSuperOps = TmpfsSuperOps;

/// A new tmpfs superblock of type `fs_type` from `opts` (Linux
/// shmem_fill_super): the root directory takes the first inode
pub(crate) fn tmpfs_mount(
    fs_type: &'static FileSystemType,
    opts: &[u8],
) -> Result<Arc<SuperBlock>, KernelError> {
    let o = parse(opts)?;
    let t = ShmemSb::new(&o)?;
    let (mode, uid, gid) = (t.mode, t.uid, t.gid);
    let sb = SuperBlock::new(fs_type, &TMPFS_SUPER_OPS, 0)?;
    sb.set_private(try_arc(t)?);
    super::fill_root(&sb, mode, uid, gid)?;
    Ok(sb)
}

/// The rootfs filesystem type (Linux init/do_mounts.c rootfs_fs_type
/// with CONFIG_TMPFS and no root=: rootfs_init_fs_context fills it as
/// tmpfs): the initramfs's, mounted on the nullfs root by
/// init_mount_tree, with tmpfs's default limits (half of RAM). A tmpfs
/// under its own name, which mountinfo shows. Not registered, as
/// Linux: mount(2) cannot name it.
pub static ROOTFS_TYPE: FileSystemType = FileSystemType {
    name: "rootfs",
    fs_flags: 0,
    mount: tmpfs_mount,
    mount_dev: None,
    file_ops: &super::TMPFS_FILE_OPS,
};

/// The kernel's own tmpfs (Linux shm_mnt, kern_mount: no limits, in
/// no mount namespace): memfd_create's files
static SHM_MNT: spin::Once<Arc<crate::fs::mount::Mount>> = spin::Once::new();

/// Make the kernel's tmpfs (Linux shmem_init's kern_mount; mnt_init)
pub fn shmem_init() -> Result<(), KernelError> {
    let sb = tmpfs_mount(&TMPFS_TYPE, b"size=0,nr_inodes=0")?;
    let root = sb.get_root().ok_or(KernelError::Io)?;
    let m = crate::fs::mount::Mount::new(sb, root, 0, b"tmpfs".as_slice().into())?;
    SHM_MNT.call_once(|| m);
    Ok(())
}

/// An unnamed regular file of `size` bytes on the kernel's tmpfs, open
/// with `flags` (O_RDWR, plus O_LARGEFILE for a memfd; Linux
/// shmem_file_setup: mode 0777, a pseudo
/// dentry `name` that /proc shows as "/<name> (deleted)")
pub fn shmem_file_setup(
    name: &[u8],
    size: u64,
    flags: u32,
) -> Result<Arc<crate::fs::File>, KernelError> {
    let mnt = SHM_MNT.get().ok_or(KernelError::NoDevice)?.clone();
    let inode = super::new_file(&mnt.sb, 0o777)?;
    inode.set_size(size);
    let dentry = crate::fs::Dentry::tmpfile_named(&mnt.root, name, inode.clone())?;
    let w = mnt.want_write()?;
    let iw = inode.get_write_access()?;
    let mut f = crate::fs::File::new(dentry, Some(mnt), flags, &super::TMPFS_FILE_OPS);
    f.write_access = Some(w);
    f.i_write = Some(iw);
    try_arc(f)
}

/// The file of a SysV shm segment or of shared anonymous memory (Linux
/// shmem_kernel_file_setup / shmem_zero_setup's "dev/zero")
pub fn shmem_kernel_file_setup(
    name: &[u8],
    size: u64,
) -> Result<Arc<crate::fs::File>, KernelError> {
    shmem_file_setup(name, size, crate::fs::flags::O_RDWR)
}

/// The tmpfs filesystem type (Linux shmem_fs_type)
pub static TMPFS_TYPE: FileSystemType = FileSystemType {
    name: "tmpfs",
    fs_flags: 0,
    mount: tmpfs_mount,
    mount_dev: None,
    file_ops: &super::TMPFS_FILE_OPS,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers() {
        assert_eq!(memparse(b"8k"), (8192, &b""[..]));
        assert_eq!(memparse(b"0x10M"), (16 << 20, &b""[..]));
        assert_eq!(memparse(b"010"), (8, &b""[..]));
        assert_eq!(memparse(b"5%"), (5, &b"%"[..]));
        assert_eq!(kstrtou32(b"755", 8), Some(0o755));
        assert_eq!(kstrtou32(b"8", 8), None);
        assert_eq!(kstrtou32(b"", 8), None);
        assert_eq!(id(b"4294967295"), None);
        assert_eq!(id(b"1000"), Some(1000));
    }

    #[test]
    fn options() {
        let o = parse(b"size=8k,nr_inodes=4,mode=700,uid=5,rw,inode32").unwrap();
        assert_eq!(o.blocks, Some(2));
        assert_eq!(o.inodes, Some(4));
        assert_eq!(o.mode, Some(0o700));
        assert_eq!(o.uid, Some(5));
        assert_eq!(o.inode64, Some(false));
        assert_eq!(parse(b"size=50%").unwrap().blocks, Some((1 << 20) / 2));
        assert!(parse(b"size=").is_err());
        assert!(parse(b"bogus").is_err());
        assert!(parse(b"huge=always").is_err());
        assert!(parse(b"huge=never,noswap").unwrap().noswap);
        assert!(parse(b"noswap=1").is_err());
        assert_eq!(
            split_opts(b"a,,b,1").collect::<Vec<_>>(),
            [&b"a"[..], b"b,1"]
        );
    }

    #[test]
    fn limits() {
        let t = ShmemSb::new(&parse(b"nr_blocks=2,nr_inodes=1").unwrap()).unwrap();
        let a = t.page_acct();
        assert!(a.charge(1).is_ok() && a.charge(1).is_ok());
        assert!(a.charge(1).is_err());
        assert!(t.reserve_inode().is_ok() && t.reserve_inode().is_err());
        // Shrinking below the use fails, growing works
        assert!(t.reconfigure(&parse(b"nr_blocks=1").unwrap()).is_err());
        assert!(t.reconfigure(&parse(b"nr_blocks=3").unwrap()).is_ok());
        assert!(a.charge(1).is_ok());
        assert_eq!(t.statfs().f_bfree, 0);
        a.uncharge(3);
        assert_eq!(t.statfs().f_bfree, 3);
        t.free_inode();
        assert_eq!(t.statfs().f_ffree, 1);
    }
}
