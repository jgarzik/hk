//! Seccomp filters (Linux kernel/seccomp.c seccomp_prepare_filter,
//! seccomp_check_filter, seccomp_attach_filter, seccomp_run_filters)
//!
//! A filter is a classic BPF program checked twice when installed:
//! `bpf::classic::check` (Linux bpf_check_classic), then
//! `check_filter`, which allows only what seccomp_data needs and
//! rewrites its loads as Linux does. Filters stack: each holds the one
//! it was installed on, and a syscall runs all of them, the most
//! restrictive action winning. The instructions on one path are capped
//! (MAX_INSNS_PER_PATH, ENOMEM), which also bounds the chain's length;
//! a chain is walked and dropped iteratively, never by recursion.
//!
//! No locks: a filter is immutable and shared by `Arc` (the task's
//! pointer to its chain is under TASKLIST).

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::bpf::classic::{self, Insn};
use crate::util::error::KernelError;

use super::{SECCOMP_RET_ACTION_FULL, SeccompData};

/// Most instructions on one path through stacked filters (Linux
/// MAX_INSNS_PER_PATH: 256 KiB of sock_filter)
pub const MAX_INSNS_PER_PATH: usize = (1 << 18) / 8;

/// A seccomp filter: a checked classic program and the filter it stacks on
#[derive(Debug)]
pub struct SeccompFilter {
    insns: Vec<Insn>,
    /// The filter this one was installed on (run after it)
    prev: Option<Arc<SeccompFilter>>,
    /// Whether to log non-ALLOW actions
    log: bool,
}

/// seccomp_data words for the classic program (LDX_W_ABS)
impl classic::Env for SeccompData {
    fn word(&self, k: u32) -> Option<u32> {
        let b = crate::util::pod::IntoBytes::as_bytes(self);
        let k = k as usize;
        let w = b.get(k..k.checked_add(4)?)?;
        Some(u32::from_ne_bytes([w[0], w[1], w[2], w[3]]))
    }
}

/// What seccomp allows of a checked program, rewriting the seccomp_data
/// loads (Linux seccomp_check_filter)
fn check_filter(insns: &mut [Insn]) -> Result<(), KernelError> {
    use classic::*;
    for f in insns {
        match f.code {
            c if c == LD | W | ABS => {
                // 32-bit aligned and inside seccomp_data
                if f.k as usize >= SeccompData::SIZE || f.k & 3 != 0 {
                    return Err(KernelError::InvalidArgument);
                }
                f.code = LDX_W_ABS;
            }
            c if c == LD | W | LEN => {
                f.code = LD | IMM;
                f.k = SeccompData::SIZE as u32;
            }
            c if c == LDX | W | LEN => {
                f.code = LDX | IMM;
                f.k = SeccompData::SIZE as u32;
            }
            c if c == RET | K || c == RET | A => {}
            c if c & 0x07 == ALU => {
                if !matches!(
                    c & 0xf0,
                    ADD | SUB | MUL | DIV | AND | OR | XOR | LSH | RSH | NEG
                ) {
                    return Err(KernelError::InvalidArgument);
                }
            }
            c if c == LD | IMM || c == LDX | IMM => {}
            c if c == MISC | TAX || c == MISC | TXA => {}
            c if c == LD | MEM || c == LDX | MEM || c == ST || c == STX => {}
            c if c & 0x07 == JMP => {}
            _ => return Err(KernelError::InvalidArgument),
        }
    }
    Ok(())
}

/// The action of `ret` ordered by restrictiveness: lower is stricter,
/// KILL_PROCESS (0x80000000) lowest (Linux ACTION_ONLY)
fn action_rank(ret: u32) -> i32 {
    (ret & SECCOMP_RET_ACTION_FULL) as i32
}

impl SeccompFilter {
    /// `self` is `filter` or one of the filters it stacks on (Linux
    /// is_ancestor; no filter is everyone's ancestor)
    pub fn is_ancestor_of(this: Option<&Arc<Self>>, filter: Option<&Arc<Self>>) -> bool {
        let Some(this) = this else {
            return true;
        };
        let mut f = filter;
        while let Some(cur) = f {
            if Arc::ptr_eq(cur, this) {
                return true;
            }
            f = cur.prev.as_ref();
        }
        false
    }

    /// A filter from user instructions, stacked on `prev` (Linux
    /// seccomp_prepare_filter + the seccomp_attach_filter size check)
    pub fn new(
        mut insns: Vec<Insn>,
        prev: Option<Arc<SeccompFilter>>,
        log: bool,
    ) -> Result<Arc<Self>, KernelError> {
        classic::check(&insns)?;
        check_filter(&mut insns)?;
        let mut total = insns.len();
        let mut f = prev.as_ref();
        while let Some(cur) = f {
            // Each stacked filter costs 4 more (Linux's call penalty)
            total += cur.insns.len() + 4;
            f = cur.prev.as_ref();
        }
        if total > MAX_INSNS_PER_PATH {
            return Err(KernelError::OutOfMemory);
        }
        Ok(Arc::new(Self { insns, prev, log }))
    }

    /// Run this filter and every one it stacks on: the most restrictive
    /// result, the first one found on a tie (Linux seccomp_run_filters)
    pub fn run(&self, data: &SeccompData) -> u32 {
        let mut ret = classic::run(&self.insns, data);
        let mut f = self.prev.as_deref();
        while let Some(cur) = f {
            let r = classic::run(&cur.insns, data);
            if action_rank(r) < action_rank(ret) {
                ret = r;
            }
            f = cur.prev.as_deref();
        }
        ret
    }

    /// Get the previous filter in the chain
    pub fn prev(&self) -> Option<&Arc<SeccompFilter>> {
        self.prev.as_ref()
    }

    /// Check if logging is enabled for this filter
    pub fn should_log(&self) -> bool {
        self.log
    }
}

impl Drop for SeccompFilter {
    /// Free the chain below iteratively: a recursive drop of thousands
    /// of stacked filters would overflow the kernel stack
    fn drop(&mut self) {
        let mut next = self.prev.take();
        while let Some(f) = next {
            next = match Arc::into_inner(f) {
                Some(mut f) => f.prev.take(),
                None => None,
            };
        }
    }
}

/// Copy a struct sock_fprog from user memory and build a filter on
/// `prev` (Linux seccomp_prepare_user_filter)
pub fn create_filter_from_user<A: crate::uaccess::UaccessArch>(
    fprog_ptr: u64,
    prev: Option<Arc<SeccompFilter>>,
    log: bool,
) -> Result<Arc<SeccompFilter>, KernelError> {
    use crate::uaccess::{copy_from_user, get_user};

    // struct sock_fprog { u16 len; struct sock_filter *filter; }
    let len = get_user::<A, u16>(fprog_ptr).map_err(|_| KernelError::BadAddress)? as usize;
    let ptr = get_user::<A, u64>(fprog_ptr + 8).map_err(|_| KernelError::BadAddress)?;
    if len == 0 || len > classic::BPF_MAXINSNS {
        return Err(KernelError::InvalidArgument);
    }
    let mut raw = crate::util::kmem::try_vec(len * 8, 0u8)?;
    copy_from_user::<A>(&mut raw, ptr, len * 8).map_err(|_| KernelError::BadAddress)?;
    let insns = raw
        .as_chunks::<8>()
        .0
        .iter()
        .map(Insn::from_bytes)
        .collect();
    SeccompFilter::new(insns, prev, log)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf::classic::*;
    use crate::seccomp::check::{Verdict, check_syscall};
    use crate::seccomp::{
        AUDIT_ARCH_X86_64, SECCOMP_MODE_FILTER, SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO,
        SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_TRAP,
    };

    fn stmt(code: u16, k: u32) -> Insn {
        Insn {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    fn jmp(code: u16, k: u32, jt: u8, jf: u8) -> Insn {
        Insn { code, jt, jf, k }
    }

    fn data(nr: i32, arch: u32, a0: u64) -> SeccompData {
        SeccompData {
            nr,
            arch,
            instruction_pointer: 0x1000,
            args: [a0, 0, 0, 0, 0, 0],
        }
    }

    fn filter(p: &[Insn]) -> Arc<SeccompFilter> {
        SeccompFilter::new(p.to_vec(), None, false).unwrap()
    }

    fn run(p: &[Insn], d: &SeccompData) -> u32 {
        filter(p).run(d)
    }

    const ERRNO5: u32 = SECCOMP_RET_ERRNO | 5;

    /// libseccomp's prologue: the arch check (a constant >= 2^31)
    #[test]
    fn arch_prologue() {
        let p = [
            stmt(LD | W | ABS, 4),
            jmp(JMP | JEQ | K, AUDIT_ARCH_X86_64, 1, 0),
            stmt(RET | K, SECCOMP_RET_KILL_PROCESS),
            stmt(LD | W | ABS, 0),
            jmp(JMP | JEQ | K, 110, 0, 1),
            stmt(RET | K, ERRNO5),
            stmt(RET | K, SECCOMP_RET_ALLOW),
        ];
        assert_eq!(run(&p, &data(110, AUDIT_ARCH_X86_64, 0)), ERRNO5);
        assert_eq!(run(&p, &data(39, AUDIT_ARCH_X86_64, 0)), SECCOMP_RET_ALLOW);
        assert_eq!(
            run(&p, &data(110, 0x4000_0003, 0)),
            SECCOMP_RET_KILL_PROCESS
        );
    }

    /// Unsigned 32-bit compares against constants with the high bit set
    #[test]
    fn high_constants() {
        let jge = |k: u32, a: u32| {
            let p = [
                stmt(LD | W | ABS, 16),
                jmp(JMP | JGE | K, k, 0, 1),
                stmt(RET | K, 1),
                stmt(RET | K, 2),
            ];
            run(&p, &data(0, 0, a as u64))
        };
        assert_eq!(jge(0x8000_0000, 0x8000_0000), 1);
        assert_eq!(jge(0x8000_0000, 0x7fff_ffff), 2);
        assert_eq!(jge(0xffff_ffff, 0xffff_ffff), 1);
        let p = [
            stmt(LD | W | ABS, 16),
            jmp(JMP | JGT | K, 0xffff_fffe, 0, 1),
            stmt(RET | K, 1),
            jmp(JMP | JSET | K, 0x8000_0000, 0, 1),
            stmt(RET | K, 3),
            stmt(RET | K, 4),
        ];
        assert_eq!(run(&p, &data(0, 0, 0xffff_ffff)), 1);
        assert_eq!(run(&p, &data(0, 0, 0x8000_0001)), 3);
        assert_eq!(run(&p, &data(0, 0, 1)), 4);
    }

    /// Jumps with jt = jf = 0 fall through without shifting later ones
    #[test]
    fn empty_jumps() {
        let p = [
            stmt(LD | W | ABS, 0),
            jmp(JMP | JEQ | K, 1, 0, 0),
            jmp(JMP | JEQ | K, 2, 0, 0),
            jmp(JMP | JGT | K, 3, 0, 0),
            jmp(JMP | JEQ | K, 7, 0, 1),
            stmt(RET | K, ERRNO5),
            stmt(RET | K, SECCOMP_RET_ALLOW),
        ];
        assert_eq!(run(&p, &data(7, 0, 0)), ERRNO5);
        assert_eq!(run(&p, &data(1, 0, 0)), SECCOMP_RET_ALLOW);
    }

    /// Every scratch slot round-trips
    #[test]
    fn scratch() {
        let mut p = alloc::vec![];
        for i in 0..16 {
            p.push(stmt(LD | IMM, 100 + i));
            p.push(stmt(ST, i));
        }
        p.push(stmt(LDX | MEM, 3));
        p.push(stmt(LD | MEM, 15));
        p.push(stmt(ALU | ADD | X, 0));
        p.push(stmt(RET | A, 0));
        assert_eq!(run(&p, &data(0, 0, 0)), 103 + 115);
    }

    /// 32-bit unsigned division, a zero X ending the program with 0
    #[test]
    fn division() {
        let div = |k: u32, a: u64| {
            let p = [
                stmt(LD | W | ABS, 16),
                stmt(ALU | DIV | K, k),
                stmt(RET | A, 0),
            ];
            run(&p, &data(0, 0, a))
        };
        assert_eq!(div(0x8000_0000, 0xffff_ffff), 1);
        assert_eq!(div(0xffff_ffff, 0xffff_fffe), 0);
        let p = [
            stmt(LDX | IMM, 0),
            stmt(LD | IMM, 9),
            stmt(ALU | DIV | X, 0),
            stmt(RET | K, SECCOMP_RET_ALLOW),
        ];
        assert_eq!(run(&p, &data(0, 0, 0)), 0);
    }

    /// LEN is sizeof(seccomp_data); the high word of an argument loads
    #[test]
    fn len_and_high_word() {
        let p = [stmt(LD | W | LEN, 0), stmt(RET | A, 0)];
        assert_eq!(run(&p, &data(0, 0, 0)), 64);
        let p = [stmt(LD | W | ABS, 20), stmt(RET | A, 0)];
        assert_eq!(run(&p, &data(0, 0, 0x1234_5678_0000_0000)), 0x1234_5678);
    }

    /// What Linux seccomp_check_filter refuses
    #[test]
    fn rejects() {
        let ret = stmt(RET | K, 0);
        let bad = |f: Insn| SeccompFilter::new(alloc::vec![f, ret], None, false).is_err();
        assert!(bad(stmt(LD | H | ABS, 0)));
        assert!(bad(stmt(LD | B | ABS, 0)));
        assert!(bad(stmt(LD | W | IND, 0)));
        assert!(bad(stmt(LDX | B | MSH, 0)));
        assert!(bad(stmt(LD | W | ABS, 2)));
        assert!(bad(stmt(LD | W | ABS, 64)));
        assert!(bad(stmt(LD | W | ABS, SKF_AD_OFF as u32)));
        assert!(bad(stmt(ALU | MOD | K, 3)));
        assert!(bad(stmt(ALU | MOD | X, 0)));
        assert!(bad(stmt(ALU | DIV | K, 0)));
        assert!(
            SeccompFilter::new(
                alloc::vec![stmt(LD | IMM, 0), stmt(RET | X, 0)],
                None,
                false
            )
            .is_err()
        );
        assert!(SeccompFilter::new(alloc::vec![ret; BPF_MAXINSNS + 1], None, false).is_err());
    }

    /// The most restrictive action wins; on a tie the newest filter's
    #[test]
    fn chains() {
        let ret = |v: u32| filter(&[stmt(RET | K, v)]);
        let on = |f: &Arc<SeccompFilter>, v: u32| {
            SeccompFilter::new(alloc::vec![stmt(RET | K, v)], Some(f.clone()), false).unwrap()
        };
        let d = data(0, 0, 0);
        let kill = ret(SECCOMP_RET_KILL_PROCESS);
        assert_eq!(
            on(&kill, SECCOMP_RET_ALLOW).run(&d),
            SECCOMP_RET_KILL_PROCESS
        );
        let trap = ret(SECCOMP_RET_TRAP | 1);
        assert_eq!(on(&trap, SECCOMP_RET_ERRNO).run(&d), SECCOMP_RET_TRAP | 1);
        let e1 = ret(SECCOMP_RET_ERRNO | 1);
        assert_eq!(
            on(&e1, SECCOMP_RET_ERRNO | 2).run(&d),
            SECCOMP_RET_ERRNO | 2
        );
    }

    /// Verdicts: ERRNO clamps to 4095, an unknown action kills the process
    #[test]
    fn verdicts() {
        let v = |r: u32| {
            let f = filter(&[stmt(RET | K, r)]);
            check_syscall(SECCOMP_MODE_FILTER, Some(&f), 0, 0, [0; 6])
        };
        assert_eq!(v(SECCOMP_RET_ERRNO | 0xffff), Verdict::Ret(-4095));
        assert_eq!(v(0x0001_0000), Verdict::KillProcess);
        assert_eq!(v(SECCOMP_RET_ALLOW), Verdict::Allow);
    }

    /// 4096-instruction filters stack 7 deep (MAX_INSNS_PER_PATH)
    #[test]
    fn path_limit() {
        let mut p = alloc::vec![stmt(LD | IMM, 0); BPF_MAXINSNS];
        p[BPF_MAXINSNS - 1] = stmt(RET | K, SECCOMP_RET_ALLOW);
        let mut f = None;
        for _ in 0..7 {
            f = Some(SeccompFilter::new(p.clone(), f, false).unwrap());
        }
        assert_eq!(
            SeccompFilter::new(p, f, false).unwrap_err(),
            KernelError::OutOfMemory
        );
    }

    /// A long chain drops without recursion (built directly: deeper
    /// than the path limit allows, so a recursive drop would overflow)
    #[test]
    fn deep_drop() {
        let mut f = None;
        for _ in 0..500_000 {
            f = Some(Arc::new(SeccompFilter {
                insns: Vec::new(),
                prev: f,
                log: false,
            }));
        }
        drop(f);
    }
}
