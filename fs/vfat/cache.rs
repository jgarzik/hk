//! A vfat file's cluster chain positions (Linux fs/fat/cache.c:
//! fat_cache, fat_get_cluster, fat_bmap): up to `FAT_MAX_CACHE` runs of
//! file clusters contiguous on disk, most recently used first, so that
//! mapping a file position walks the FAT only from the nearest cached
//! run at or before it, not from the first cluster.
//!
//! A walk reads its FAT entries from one FAT block kept for it (Linux
//! fatent's buffer head), with no lock held, and caches the run it ends
//! in. Every cluster it uses, the first one, a cached one or one read
//! from the FAT, is checked to be a data cluster (EIO otherwise, Linux
//! fat_valid_entry), so a corrupt image never sends I/O outside the
//! data area.
//!
//! The cache holds the chain's first cluster itself (`FatCache.start`,
//! set with the inode's): a walk takes the first cluster, the cache's
//! id and its starting run in one hold, so they always belong to the
//! same chain. A new first cluster (`set_start`) and a cut of the
//! chain (`free_past`: before and again after the FAT is changed)
//! invalidate the cache and bump its id (Linux fat_cache_inval_inode,
//! cache_valid_id); a walk caches its run only if the id is unchanged,
//! so nothing walked on a chain being cut outlives the cut.

use alloc::vec::Vec;

use crate::fs::inode::Inode;
use crate::sync::spin::Mutex;
use crate::util::error::KernelError;

use super::{VfatInode, VfatSbData, cluster_to_offset, is_end_of_chain, read_bytes, with_vi};

/// Runs cached per file (Linux FAT_MAX_CACHE)
const FAT_MAX_CACHE: usize = 8;

/// File clusters `fclus..=fclus + nr_contig` are disk clusters
/// `dclus..=dclus + nr_contig` (Linux struct fat_cache)
#[derive(Clone, Copy, Default)]
struct Run {
    fclus: u32,
    dclus: u32,
    nr_contig: u32,
}

impl Run {
    /// The file cluster after the run's last
    fn next_f(&self) -> u32 {
        self.fclus + self.nr_contig + 1
    }

    /// Disk cluster `d` as file cluster `f` extends the run
    fn extends(&self, f: u32, d: u32) -> bool {
        f == self.next_f() && d == self.dclus + self.nr_contig + 1
    }
}

/// A cached run and the offset into it where a walk resumes
type Hit = Option<(Run, u32)>;

/// A file's cached runs (Linux msdos_inode_info cache_lru, nr_caches,
/// cache_valid_id), in `VfatInode.cache`
#[derive(Default)]
pub struct FatCache {
    /// Most recently used first; the first `nr` are valid
    runs: [Run; FAT_MAX_CACHE],
    nr: usize,
    /// Bumped by each invalidation
    id: u32,
    /// The chain's first cluster (0: none), the inode's `start_cluster`
    start: u32,
}

impl FatCache {
    /// Move run `i` to the front
    fn touch(&mut self, i: usize) {
        self.runs[..=i].rotate_right(1);
    }

    /// The run holding file cluster `fclus`, or else the nearest one
    /// before it (Linux fat_cache_lookup), moved to the front; with the
    /// offset into it where a walk to `fclus` resumes
    fn lookup(&mut self, fclus: u32) -> Hit {
        let mut hit: Option<usize> = None;
        for (i, r) in self.runs[..self.nr].iter().enumerate() {
            if r.fclus <= fclus && hit.is_none_or(|h| self.runs[h].fclus < r.fclus) {
                hit = Some(i);
                if fclus < r.next_f() {
                    break;
                }
            }
        }
        let i = hit?;
        self.touch(i);
        let r = self.runs[0];
        Some((r, (fclus - r.fclus).min(r.nr_contig)))
    }

    /// Cache `new`, found by a walk that began at invalidation `id`
    /// (Linux fat_cache_add): merged into a run starting at the same
    /// cluster, else in a free slot or the least recently used one
    fn add(&mut self, id: u32, new: Run) {
        if id != self.id {
            return;
        }
        if let Some(i) = self.runs[..self.nr]
            .iter()
            .position(|r| r.fclus == new.fclus)
        {
            let r = &mut self.runs[i];
            r.nr_contig = r.nr_contig.max(new.nr_contig);
            self.touch(i);
            return;
        }
        if self.nr < FAT_MAX_CACHE {
            self.nr += 1;
        }
        self.touch(self.nr - 1);
        self.runs[0] = new;
    }

    /// Forget every run (Linux __fat_cache_inval_inode)
    pub fn inval(&mut self) {
        self.nr = 0;
        self.id = self.id.wrapping_add(1);
    }

    /// The chain now starts at `start`: the runs of the old one go
    pub fn set_start(&mut self, start: u32) {
        if start != self.start {
            self.start = start;
            self.inval();
        }
    }

    /// A walk's beginning toward file cluster `fclus`: the id, the first
    /// cluster and the nearest run (`lookup`); None for no clusters
    fn begin(&mut self, fclus: u32) -> Option<(u32, u32, Hit)> {
        if self.start == 0 {
            return None;
        }
        Some((self.id, self.start, self.lookup(fclus)))
    }
}

/// `c` is a data cluster (Linux fat_valid_entry)
fn valid(max_cluster: u32, c: u32) -> bool {
    (2..max_cluster).contains(&c)
}

/// Where a walk resumes: its run up to there, file cluster and disk
/// cluster, from the cached `hit` or else the first cluster `start`.
/// EIO for a first or cached cluster that is not a data cluster.
fn resume(max_cluster: u32, start: u32, hit: Hit) -> Result<(Run, u32, u32), KernelError> {
    if !valid(max_cluster, start) {
        return Err(KernelError::Io);
    }
    let (cid, off) = hit.unwrap_or((
        Run {
            fclus: 0,
            dclus: start,
            nr_contig: 0,
        },
        0,
    ));
    let d = cid.dclus.checked_add(off).ok_or(KernelError::Io)?;
    if !valid(max_cluster, d) {
        return Err(KernelError::Io);
    }
    // The run as far as the walk's position (Linux fat_cache_id): a walk
    // going on from there extends it
    Ok((
        Run {
            nr_contig: off,
            ..cid
        },
        cid.fclus + off,
        d,
    ))
}

/// The cluster after one whose FAT entry is `n`: None at the end of the
/// chain; EIO for a free, bad, reserved or out-of-range entry
fn chain_next(max_cluster: u32, n: u32) -> Result<Option<u32>, KernelError> {
    if is_end_of_chain(n) {
        return Ok(None);
    }
    if !valid(max_cluster, n) {
        return Err(KernelError::Io);
    }
    Ok(Some(n))
}

/// The FAT block a walk reads its entries from (Linux fatent's buffer
/// head): read again only when the chain leaves it
struct FatBuf {
    /// Device byte offset of `buf`, None before the first read
    at: Option<u64>,
    buf: [u8; FatBuf::SIZE],
}

impl FatBuf {
    /// FAT entries are read 512 bytes at a time (a FAT sector at least)
    const SIZE: usize = 512;

    fn new() -> Self {
        Self {
            at: None,
            buf: [0; Self::SIZE],
        }
    }

    /// The FAT entry of `cluster` (Linux fat_ent_read): EIO for one
    /// outside the data clusters
    fn ent(&mut self, sb: &VfatSbData, cluster: u32) -> Result<u32, KernelError> {
        if !valid(sb.max_cluster, cluster) {
            return Err(KernelError::Io);
        }
        let off = sb.fat_start_sector * u64::from(sb.bytes_per_sector) + u64::from(cluster) * 4;
        let base = off & !(Self::SIZE as u64 - 1);
        if self.at != Some(base) {
            self.at = None;
            read_bytes(&sb.bdev, base, &mut self.buf)?;
            self.at = Some(base);
        }
        let i = (off - base) as usize;
        let e = u32::from_le_bytes([
            self.buf[i],
            self.buf[i + 1],
            self.buf[i + 2],
            self.buf[i + 3],
        ]);
        Ok(e & 0x0FFF_FFFF)
    }
}

/// A walk along a file's chain (Linux fat_get_cluster's loop): at file
/// cluster `f`, disk cluster `d`, in the contiguous run `cid`
struct Walk<'a> {
    sb: &'a VfatSbData,
    vi: &'a VfatInode,
    fat: FatBuf,
    /// The cache's id when the walk began
    id: u32,
    cid: Run,
    f: u32,
    d: u32,
}

impl<'a> Walk<'a> {
    /// A walk toward file cluster `fclus` of the inode's chain, from the
    /// nearest cached run at or before it (else from the first
    /// cluster); None for a file with no clusters
    fn new(sb: &'a VfatSbData, vi: &'a VfatInode, fclus: u32) -> Result<Option<Self>, KernelError> {
        let Some((id, start, hit)) = vi.cache.lock().begin(fclus) else {
            return Ok(None);
        };
        let (cid, f, d) = resume(sb.max_cluster, start, hit)?;
        Ok(Some(Self {
            sb,
            vi,
            fat: FatBuf::new(),
            id,
            cid,
            f,
            d,
        }))
    }

    /// Step to the next cluster: false at the end of the chain. EIO for
    /// a corrupt chain: a free, bad or out-of-range entry, or more
    /// clusters than a file of at most 4 GiB has (a loop; Linux bounds
    /// the walk by s_maxbytes >> cluster_bits)
    fn next(&mut self) -> Result<bool, KernelError> {
        let limit = (1u64 << 32) / u64::from(self.sb.cluster_size);
        if u64::from(self.f) >= limit {
            return Err(KernelError::Io);
        }
        let e = self.fat.ent(self.sb, self.d)?;
        let Some(n) = chain_next(self.sb.max_cluster, e)? else {
            return Ok(false);
        };
        self.f += 1;
        self.d = n;
        if self.cid.extends(self.f, n) {
            self.cid.nr_contig += 1;
        } else {
            self.cid = Run {
                fclus: self.f,
                dclus: n,
                nr_contig: 0,
            };
        }
        Ok(true)
    }

    /// Walk on to file cluster `fclus`, or the chain's end before it
    fn to(&mut self, fclus: u32) -> Result<(), KernelError> {
        while self.f < fclus && self.next()? {}
        Ok(())
    }

    /// Cache the run the walk ended in
    fn done(self) {
        self.vi.cache.lock().add(self.id, self.cid);
    }
}

/// Run `f` on a walk toward file cluster `fclus` of the inode's chain;
/// None for a file with no clusters
fn with_walk<R>(
    sb: &VfatSbData,
    inode: &Inode,
    fclus: u32,
    f: impl FnOnce(&mut Walk<'_>) -> Result<R, KernelError>,
) -> Result<Option<R>, KernelError> {
    with_vi(inode, |vi| {
        let Some(mut w) = Walk::new(sb, vi, fclus)? else {
            return Ok(None);
        };
        w.to(fclus)?;
        let r = f(&mut w)?;
        w.done();
        Ok(Some(r))
    })?
}

/// File cluster `fclus` of `inode`, or the last before the chain ends
/// (Linux fat_get_cluster): (file cluster, disk cluster) reached; None
/// for a file with no clusters
pub fn get_cluster(
    sb: &VfatSbData,
    inode: &Inode,
    fclus: u32,
) -> Result<Option<(u32, u32)>, KernelError> {
    with_walk(sb, inode, fclus, |w| Ok((w.f, w.d)))
}

/// The file's last cluster (Linux fat_get_cluster with FAT_ENT_EOF):
/// (file cluster, disk cluster); None for a file with no clusters
pub fn last_cluster(sb: &VfatSbData, inode: &Inode) -> Result<Option<(u32, u32)>, KernelError> {
    get_cluster(sb, inode, u32::MAX)
}

/// Forget `inode`'s cached runs around a cut of its chain (Linux
/// fat_cache_inval_inode)
pub fn inval(inode: &Inode) -> Result<(), KernelError> {
    with_vi(inode, |vi| vi.cache.lock().inval())
}

/// The device extents (byte offset, length) holding bytes [pos, pos +
/// len) of the file, contiguous clusters merged (Linux fat_bmap through
/// fat_get_cluster): one walk from the nearest cached run; short where
/// the chain ends
pub fn extents(
    sb: &VfatSbData,
    inode: &Inode,
    pos: u64,
    len: usize,
) -> Result<Vec<(u64, usize)>, KernelError> {
    let mut out: Vec<(u64, usize)> = Vec::new();
    if len == 0 {
        return Ok(out);
    }
    let cs = u64::from(sb.cluster_size);
    let first = u32::try_from(pos / cs).map_err(|_| KernelError::Io)?;
    with_walk(sb, inode, first, |w| {
        let (mut at, end) = (pos, pos + len as u64);
        // Short if the chain ends before the first cluster
        let mut more = w.f == first;
        while more {
            // The cluster reached holds byte `at`
            let off = cluster_to_offset(sb, w.d) + at % cs;
            let n = (cs - at % cs).min(end - at) as usize;
            match out.last_mut() {
                Some((o, l)) if *o + *l as u64 == off => *l += n,
                _ => {
                    out.try_reserve(1).map_err(|_| KernelError::OutOfMemory)?;
                    out.push((off, n));
                }
            }
            at += n as u64;
            more = at < end && w.next()?;
        }
        Ok(())
    })?;
    Ok(out)
}

/// The cache of a chain starting at `start`, for `VfatInode`
pub fn new_cache(start: u32) -> Mutex<FatCache> {
    Mutex::new(FatCache {
        start,
        ..FatCache::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(fclus: u32, dclus: u32, nr_contig: u32) -> Run {
        Run {
            fclus,
            dclus,
            nr_contig,
        }
    }

    #[test]
    fn lookup_nearest() {
        let mut c = FatCache::default();
        assert!(c.lookup(5).is_none());
        c.add(0, run(0, 100, 3));
        c.add(0, run(10, 200, 4));
        // Inside a run: the offset of the cluster
        let (r, off) = c.lookup(12).unwrap();
        assert_eq!((r.fclus, off), (10, 2));
        // Past a run: its end, where the walk resumes
        let (r, off) = c.lookup(8).unwrap();
        assert_eq!((r.fclus, off), (0, 3));
        let (r, off) = c.lookup(30).unwrap();
        assert_eq!((r.fclus, off), (10, 4));
    }

    #[test]
    fn add_merge_evict() {
        let mut c = FatCache::default();
        c.add(0, run(4, 50, 1));
        c.add(0, run(4, 50, 6));
        assert_eq!(c.nr, 1);
        assert_eq!(c.runs[0].nr_contig, 6);
        for i in 0..FAT_MAX_CACHE as u32 + 2 {
            c.add(0, run(100 + i * 10, 1000 + i * 100, 0));
        }
        assert_eq!(c.nr, FAT_MAX_CACHE);
        // The least recently used went first
        assert!(c.runs.iter().all(|r| r.fclus != 4));
        // A walk begun before an invalidation caches nothing
        let id = c.id;
        c.inval();
        c.add(id, run(1, 2, 3));
        assert_eq!(c.nr, 0);
        assert!(c.lookup(1).is_none());
    }

    #[test]
    fn new_start_drops_runs() {
        let mut c = FatCache::default();
        c.set_start(10);
        c.add(c.id, run(0, 10, 4));
        let (id, start, hit) = c.begin(2).unwrap();
        assert_eq!((start, hit.unwrap().1), (10, 2));
        // A walk begun on the old chain caches nothing on the new one
        c.set_start(50);
        c.add(id, run(0, 10, 9));
        let (_, start, hit) = c.begin(2).unwrap();
        assert_eq!(start, 50);
        assert!(hit.is_none());
        // Same first cluster: nothing changes
        let id = c.id;
        c.set_start(50);
        assert_eq!(c.id, id);
        c.set_start(0);
        assert!(c.begin(0).is_none());
    }

    #[test]
    fn bad_clusters_are_eio() {
        const MAX: u32 = 1000;
        for start in [1, MAX, u32::MAX] {
            assert_eq!(resume(MAX, start, None).err(), Some(KernelError::Io));
        }
        assert_eq!(resume(MAX, 5, None).ok().map(|r| (r.1, r.2)), Some((0, 5)));
        // A cached run whose clusters leave the data area
        let hit = Some((run(4, MAX - 2, 6), 3));
        assert_eq!(resume(MAX, 5, hit).err(), Some(KernelError::Io));
        let hit = Some((run(4, u32::MAX - 1, 6), 3));
        assert_eq!(resume(MAX, 5, hit).err(), Some(KernelError::Io));
        let hit = Some((run(4, 100, 6), 3));
        assert_eq!(resume(MAX, 5, hit).ok().map(|r| (r.1, r.2)), Some((7, 103)));
        // FAT entries: end of chain, free, reserved, bad, past the end
        assert_eq!(chain_next(MAX, 0x0FFF_FFF8), Ok(None));
        assert_eq!(chain_next(MAX, 0x0FFF_FFFF), Ok(None));
        for e in [0, 1, 0x0FFF_FFF7, MAX] {
            assert_eq!(chain_next(MAX, e), Err(KernelError::Io));
        }
        assert_eq!(chain_next(MAX, 7), Ok(Some(7)));
    }

    #[test]
    fn walk_from_mid_run_keeps_one_run() {
        let mut c = FatCache::default();
        c.set_start(100);
        c.add(c.id, run(0, 100, 9));
        // A walk resuming at cluster 3 and stepping on contiguously
        // past the run's end extends that run, not a fragment of it
        let (id, start, hit) = c.begin(3).unwrap();
        let (mut cid, mut f, mut d) = resume(1000, start, hit).unwrap();
        assert_eq!((f, d), (3, 103));
        for _ in 0..12 {
            f += 1;
            d += 1;
            assert!(cid.extends(f, d), "cluster {f}");
            cid.nr_contig += 1;
        }
        c.add(id, cid);
        assert_eq!(c.nr, 1);
        assert_eq!((c.runs[0].fclus, c.runs[0].nr_contig), (0, 15));
    }

    #[test]
    fn contiguity() {
        let r = run(3, 40, 2);
        assert!(r.extends(6, 43));
        assert!(!r.extends(6, 44));
        assert!(!r.extends(7, 44));
    }
}
