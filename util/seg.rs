//! Byte positions in runs of segments (iovecs, pinned page pieces, bio
//! segments): the step back that Linux iov_iter_revert and
//! bio_iov_iter_align_down share

use super::smallvec::SmallVec;

/// Move the position byte `at` of segment `i` back `n` bytes, segment
/// `k` holding `len(k)` (Linux iov_iter_revert's walk); the position
/// stays at the end of a segment rather than the start of the next.
/// `n` must not pass the start.
pub fn step_back(len: impl Fn(usize) -> usize, i: &mut usize, at: &mut usize, mut n: usize) {
    while n > 0 {
        if *at == 0 {
            *i -= 1;
            *at = len(*i);
            continue;
        }
        let k = (*at).min(n);
        *at -= k;
        n -= k;
    }
}

/// Drop the last `n` bytes of `v`, whose elements hold `len(e)` bytes:
/// whole elements go to `dropped`, the one cut through keeps its first
/// bytes (`set_len`)
pub fn trim_tail<T: Default, const N: usize>(
    v: &mut SmallVec<T, N>,
    n: usize,
    len: impl Fn(&T) -> usize,
    set_len: impl Fn(&mut T, usize),
    mut dropped: impl FnMut(T),
) {
    let total: usize = v.iter().map(&len).sum();
    let (mut i, mut at) = (v.len(), 0);
    step_back(|k| len(&v[k]), &mut i, &mut at, n.min(total));
    while v.len() > i + usize::from(at > 0) {
        if let Some(e) = v.pop() {
            dropped(e);
        }
    }
    if at > 0 {
        set_len(&mut v[i], at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn back_over_segments() {
        let lens = [3usize, 0, 5];
        let (mut i, mut at) = (2, 2);
        step_back(|k| lens[k], &mut i, &mut at, 4);
        assert_eq!((i, at), (0, 1));
        let (mut i, mut at) = (3, 0);
        step_back(|k| lens[k], &mut i, &mut at, 5);
        assert_eq!((i, at), (2, 0));
    }

    #[test]
    fn trim() {
        let mut v: SmallVec<usize, 2> = SmallVec::new();
        for l in [4, 4, 4] {
            v.push(l);
        }
        let mut gone = Vec::new();
        trim_tail(&mut v, 6, |&l| l, |e, l| *e = l, |e| gone.push(e));
        assert_eq!((&v[..], &gone[..]), (&[4, 2][..], &[4][..]));
        trim_tail(&mut v, 2, |&l| l, |e, l| *e = l, |e| gone.push(e));
        assert_eq!(&v[..], [4]);
        trim_tail(&mut v, 0, |&l| l, |e, l| *e = l, |e| gone.push(e));
        assert_eq!(&v[..], [4]);
        trim_tail(&mut v, 9, |&l| l, |e, l| *e = l, |e| gone.push(e));
        assert!(v.is_empty());
    }
}
