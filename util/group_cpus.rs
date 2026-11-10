//! Spread CPUs evenly over groups (Linux lib/group_cpus.c
//! group_cpus_evenly, for a single node with no sibling structure):
//! `n` CPUs make `g` runs of consecutive ids, the first `n % g` one CPU
//! longer. blk-mq maps CPUs to hardware queues this way, and a queue's
//! interrupt is aimed at its group (Linux irq_create_affinity_masks,
//! blk_mq_map_hw_queues). With more groups than CPUs, group `i` gets
//! CPU `i % n` (each CPU leads one group).

/// The group of `cpu` (< `n`) when `n` CPUs make `g` groups
pub fn group_of(cpu: u32, n: u32, g: u32) -> u32 {
    let (n, g) = (n.max(1), g.max(1));
    if g >= n {
        return cpu;
    }
    let (base, extra) = (n / g, n % g);
    let long = extra * (base + 1);
    if cpu < long {
        cpu / (base + 1)
    } else {
        extra + (cpu - long) / base
    }
}

/// The first CPU of group `i` (< `g`) when `n` CPUs make `g` groups
pub fn first_cpu(i: u32, n: u32, g: u32) -> u32 {
    let (n, g) = (n.max(1), g.max(1));
    if g >= n {
        return i % n;
    }
    let (base, extra) = (n / g, n % g);
    i * base + i.min(extra)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn even_and_uneven() {
        let groups: alloc::vec::Vec<u32> = (0..4).map(|c| group_of(c, 4, 2)).collect();
        assert_eq!(groups, [0, 0, 1, 1]);
        let groups: alloc::vec::Vec<u32> = (0..5).map(|c| group_of(c, 5, 2)).collect();
        assert_eq!(groups, [0, 0, 0, 1, 1]);
        let groups: alloc::vec::Vec<u32> = (0..7).map(|c| group_of(c, 7, 3)).collect();
        assert_eq!(groups, [0, 0, 0, 1, 1, 2, 2]);
        assert_eq!(
            (first_cpu(0, 7, 3), first_cpu(1, 7, 3), first_cpu(2, 7, 3)),
            (0, 3, 5)
        );
        assert_eq!(first_cpu(1, 5, 2), 3);
    }

    #[test]
    fn every_group_leads_with_its_own() {
        for n in 1..20 {
            for g in 1..20 {
                for i in 0..g {
                    let c = first_cpu(i, n, g);
                    assert!(c < n);
                    if g <= n {
                        assert_eq!(group_of(c, n, g), i);
                    }
                }
                for c in 0..n {
                    assert!(group_of(c, n, g) < g.min(n));
                }
            }
        }
        assert_eq!((group_of(3, 2, 8), first_cpu(5, 2, 8)), (3, 1));
    }
}
