//! VMA/PTE agreement check (debug aid, feature `mmcheck`, part of
//! `make check LOCKDEP=1`)
//!
//! After each address-range operation (mprotect, munmap and the paths
//! built on it, mremap), with the mm lock still held: the VMAs are
//! sorted and do not overlap, and every user leaf entry that maps a
//! page (protnone included) lies in a VMA that allows at least what the
//! entry allows (writable entry: PROT_WRITE; executable: PROT_EXEC; an
//! accessible entry: some access) and is never executable by the
//! kernel (arm64 PXN). A violation prints `MMCHECK:FAIL`
//! (once per boot), which fails `make check`.

use core::sync::atomic::{AtomicBool, Ordering};

use super::{MmStruct, PROT_EXEC, PROT_READ, PROT_WRITE};
use crate::arch::paging;

static REPORTED: AtomicBool = AtomicBool::new(false);

/// Report a violation found after `op`
fn fail(op: &str, what: &str, va: u64, entry: u64) {
    if !REPORTED.swap(true, Ordering::Relaxed) {
        crate::printkln!(
            "\nMMCHECK:FAIL after {}: {} at {:#x} (entry {:#x})",
            op,
            what,
            va,
            entry
        );
    }
}

/// What a VMA allowing `prot` misses for the leaf `entry`, if anything
fn excess(entry: u64, prot: u32) -> Option<&'static str> {
    let none = paging::pte_protnone(entry);
    if !none && prot & (PROT_READ | PROT_WRITE | PROT_EXEC) == 0 {
        Some("accessible entry in a PROT_NONE VMA")
    } else if !none && paging::pte_write(entry) && prot & PROT_WRITE == 0 {
        Some("writable entry in a VMA without PROT_WRITE")
    } else if paging::pte_exec(entry) && prot & PROT_EXEC == 0 {
        Some("executable entry in a VMA without PROT_EXEC")
    } else if paging::pte_kexec(entry) {
        Some("user entry executable by the kernel")
    } else if paging::pte_global(entry) {
        Some("global user entry (no ASID tag)")
    } else {
        None
    }
}

/// Check the address space `map` with tables rooted at `pgd` after `op`
pub fn verify(map: &MmStruct, pgd: u64, op: &str) {
    let mut prev_end = 0;
    for v in map.iter() {
        if v.start >= v.end || v.start < prev_end {
            return fail(op, "empty or overlapping VMA", v.start, v.end);
        }
        prev_end = v.end;
    }
    // Leaves come in address order: one pass over the VMAs
    let mut vmas = map.iter().peekable();
    paging::walk_user(pgd, &mut |va, entry, _huge| {
        while vmas.peek().is_some_and(|v| v.end <= va) {
            vmas.next();
        }
        match vmas.peek() {
            Some(v) if v.start <= va => {
                if let Some(what) = excess(entry, v.prot) {
                    fail(op, what, va, entry);
                }
            }
            _ => fail(op, "page mapped outside every VMA", va, entry),
        }
    });
}
