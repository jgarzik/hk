//! eBPF verifier (Linux kernel/bpf/verifier.c check_cfg + do_check, a
//! strict subset)
//!
//! Two passes, both iterative: no program shape reaches the kernel
//! stack.
//!
//! 1. `check_cfg`, one sweep: every instruction is well formed (known
//!    opcode, registers, fields that must be zero, shifts below the
//!    width, no division by a zero constant, no write to R10), every
//!    jump goes forward and lands inside the program and not on the
//!    second half of a 64-bit immediate, every instruction is reachable
//!    and none falls off the end. Forward-only jumps make every program
//!    terminate within its length (Linux before bounded loops).
//! 2. `do_check` follows every path with an explicit worklist, tracking
//!    each register as uninitialized, a scalar (a known constant or
//!    not) or a pointer at a known offset into the context or the
//!    stack, and which stack bytes are written. A path is dropped where
//!    an already-checked state at that jump target covers it. Errors:
//!    malformed EINVAL; uninitialized reads, out-of-bounds or misaligned
//!    context access, stores to the context, pointer arithmetic other
//!    than a constant offset, and a pointer in R0 at EXIT are EACCES;
//!    more than `COMPLEXITY_LIMIT` instructions processed is E2BIG.
//!
//! The interpreter checks every access again at run time
//! (bpf/interp.rs), so a verifier bug cannot reach kernel memory.
//! No locks: all state is the caller's.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::insn::*;
use super::interp::{self, BPF_CMPXCHG, BPF_FETCH, BPF_MEMSX, BPF_XCHG};
use crate::util::error::KernelError;

/// Most instructions processed over all paths (Linux
/// BPF_COMPLEXITY_LIMIT_INSNS)
pub const COMPLEXITY_LIMIT: usize = 1_000_000;

/// Most states kept for pruning (bounds the verifier's memory)
const MAX_STORED: usize = 4096;

/// Most states kept at one jump target (bounds each pruning check)
const MAX_PER_TARGET: usize = 16;

/// Most paths waiting to be followed (E2BIG past it)
const MAX_PENDING: usize = 4096;

/// What a program type allows
#[derive(Clone, Copy, Debug)]
pub struct Kind {
    /// Bytes of the context R1 points to (read-only)
    pub ctx_size: usize,
    /// Callable helpers: (id, number of scalar arguments)
    pub helpers: &'static [(i32, u8)],
}

/// What the verifier learned about a program it accepted
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Verified {
    /// Deepest stack byte used
    pub stack_depth: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Region {
    Ctx,
    Stack,
}

/// What a register holds
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Val {
    Uninit,
    /// A number, with its value if known
    Scalar(Option<u64>),
    /// A pointer at a known offset into a region (stack: from its end)
    Ptr(Region, i32),
}

const UNKNOWN: Val = Val::Scalar(None);
const SLOTS: usize = BPF_STACK_SIZE / 8;

/// The abstract machine at one instruction
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct State {
    regs: [Val; MAX_BPF_REG],
    /// One bit per written stack byte (bit i: offset i from the base)
    init: [u64; BPF_STACK_SIZE / 64],
    /// The pointer spilled to each 8-byte slot
    spill: [Option<(Region, i32)>; SLOTS],
}

impl State {
    fn entry() -> Self {
        let mut regs = [Val::Uninit; MAX_BPF_REG];
        regs[BPF_REG_1 as usize] = Val::Ptr(Region::Ctx, 0);
        regs[BPF_REG_10 as usize] = Val::Ptr(Region::Stack, 0);
        Self {
            regs,
            init: [0; BPF_STACK_SIZE / 64],
            spill: [None; SLOTS],
        }
    }

    /// Whether every path safe from `self` is safe from `new` (Linux
    /// states_equal, without range tracking)
    fn covers(&self, new: &State) -> bool {
        let regs = self.regs.iter().zip(&new.regs).all(|(o, n)| {
            *o == Val::Uninit || o == n || (*o == UNKNOWN && matches!(n, Val::Scalar(_)))
        });
        let init = self.init.iter().zip(&new.init).all(|(o, n)| o & !n == 0);
        regs && init && self.spill == new.spill
    }

    fn written(&self, at: usize, size: usize) -> bool {
        (at..at + size).all(|b| self.init[b / 64] & (1 << (b % 64)) != 0)
    }

    fn mark(&mut self, at: usize, size: usize) {
        for b in at..at + size {
            self.init[b / 64] |= 1 << (b % 64);
        }
    }
}

fn inval<T>() -> Result<T, KernelError> {
    Err(KernelError::InvalidArgument)
}

fn acces<T>() -> Result<T, KernelError> {
    Err(KernelError::PermissionDenied)
}

// ============================================================================
// Pass 1: shape
// ============================================================================

/// A well-formed ALU instruction
fn alu_ok(insn: &BpfInsn) -> bool {
    let code = insn.code;
    let w64 = bpf_class(code) == BPF_ALU64;
    let x = bpf_src(code) == BPF_X;
    let (src, off, imm) = (insn.src_reg(), insn.off, insn.imm);
    let fields = if x { imm == 0 } else { src == 0 };
    match bpf_op(code) {
        BPF_END => src == 0 && off == 0 && matches!(imm, 16 | 32 | 64) && !(w64 && x),
        BPF_NEG => !x && src == 0 && off == 0 && imm == 0,
        BPF_MOV => {
            fields
                && match off {
                    0 => true,
                    8 | 16 => x,
                    32 => x && w64,
                    _ => false,
                }
        }
        BPF_DIV | BPF_MOD => fields && matches!(off, 0 | 1) && (x || imm != 0),
        BPF_LSH | BPF_RSH | BPF_ARSH => {
            let width = if w64 { 64 } else { 32 };
            fields && off == 0 && (x || (0..width).contains(&imm))
        }
        BPF_ADD | BPF_SUB | BPF_MUL | BPF_OR | BPF_AND | BPF_XOR => fields && off == 0,
        _ => false,
    }
}

/// A well-formed load, store or atomic instruction
fn mem_ok(insn: &BpfInsn) -> bool {
    let code = insn.code;
    let (src, imm) = (insn.src_reg(), insn.imm);
    match (bpf_class(code), bpf_mode(code)) {
        (BPF_LDX, BPF_MEM) => imm == 0,
        (BPF_LDX, BPF_MEMSX) => imm == 0 && bpf_size(code) != BPF_DW,
        (BPF_ST, BPF_MEM) => src == 0,
        (BPF_STX, BPF_MEM) => imm == 0,
        (BPF_STX, BPF_ATOMIC) => {
            let ops = [BPF_ADD, BPF_OR, BPF_AND, BPF_XOR].map(|o| o as i32);
            matches!(bpf_size(code), BPF_W | BPF_DW)
                && (ops.contains(&(imm & !BPF_FETCH)) || imm == BPF_XCHG || imm == BPF_CMPXCHG)
        }
        _ => false,
    }
}

/// A well-formed jump; `kind` decides which helpers exist
fn jmp_ok(insn: &BpfInsn, kind: &Kind) -> bool {
    let code = insn.code;
    let w32 = bpf_class(code) == BPF_JMP32;
    let x = bpf_src(code) == BPF_X;
    let (dst, src, off, imm) = (insn.dst_reg(), insn.src_reg(), insn.off, insn.imm);
    match bpf_op(code) {
        BPF_JA if w32 => !x && dst == 0 && src == 0 && off == 0,
        BPF_JA => !x && dst == 0 && src == 0 && imm == 0,
        BPF_EXIT => !w32 && !x && dst == 0 && src == 0 && off == 0 && imm == 0,
        BPF_CALL => {
            !w32 && !x
                && dst == 0
                && src == 0
                && off == 0
                && kind.helpers.iter().any(|h| h.0 == imm)
        }
        BPF_JEQ | BPF_JNE | BPF_JGT | BPF_JGE | BPF_JLT | BPF_JLE | BPF_JSET | BPF_JSGT
        | BPF_JSGE | BPF_JSLT | BPF_JSLE => {
            if x {
                imm == 0
            } else {
                src == 0
            }
        }
        _ => false,
    }
}

/// Where control goes after `pc`: (fall-through, jump target)
fn successors(insns: &[BpfInsn], pc: usize) -> (Option<usize>, Option<isize>) {
    let insn = &insns[pc];
    let class = bpf_class(insn.code);
    if class == BPF_LD {
        return (Some(pc + 2), None);
    }
    if class != BPF_JMP && class != BPF_JMP32 {
        return (Some(pc + 1), None);
    }
    let off = |o: i64| Some(pc as isize + 1 + o as isize);
    match bpf_op(insn.code) {
        BPF_EXIT => (None, None),
        BPF_CALL => (Some(pc + 1), None),
        BPF_JA if class == BPF_JMP32 => (None, off(insn.imm as i64)),
        BPF_JA => (None, off(insn.off as i64)),
        _ => (Some(pc + 1), off(insn.off as i64)),
    }
}

/// Pass 1: shape, forward jumps, reachability; the jump targets
fn check_cfg(insns: &[BpfInsn], kind: &Kind) -> Result<Vec<bool>, KernelError> {
    let len = insns.len();
    let mut reach = crate::util::kmem::try_vec(len, false)?;
    let mut target = crate::util::kmem::try_vec(len, false)?;
    let mut second = crate::util::kmem::try_vec(len, false)?;
    reach[0] = true;
    for pc in 0..len {
        let insn = &insns[pc];
        if insn.dst_reg() > BPF_REG_10 || insn.src_reg() > BPF_REG_10 {
            return inval();
        }
        let class = bpf_class(insn.code);
        let ok = match class {
            BPF_ALU | BPF_ALU64 => alu_ok(insn),
            BPF_LDX | BPF_ST | BPF_STX => mem_ok(insn),
            BPF_JMP | BPF_JMP32 => jmp_ok(insn, kind),
            _ if second[pc] => true,
            _ => {
                let hi = insns.get(pc + 1);
                insn.code == BPF_LD | BPF_IMM | BPF_DW
                    && insn.src_reg() == 0
                    && insn.off == 0
                    && hi.is_some_and(|h| h.code == 0 && h.regs == 0 && h.off == 0)
            }
        };
        if !ok {
            return inval();
        }
        // Only stores name R10 as their destination (its base)
        if insn.dst_reg() == BPF_REG_10 && !matches!(class, BPF_ST | BPF_STX) {
            return inval();
        }
        if second[pc] {
            continue;
        }
        if class == BPF_LD {
            second[pc + 1] = true;
        }
        if !reach[pc] {
            return inval();
        }
        let (next, jump) = successors(insns, pc);
        if let Some(n) = next {
            // Falling off the end
            if n >= len {
                return inval();
            }
            reach[n] = true;
        }
        if let Some(t) = jump {
            // Forward only, inside the program
            if t <= pc as isize || t as usize >= len {
                return inval();
            }
            reach[t as usize] = true;
            target[t as usize] = true;
        }
    }
    // Nothing may jump into the second half of a 64-bit immediate
    if (0..len).any(|pc| second[pc] && reach[pc]) {
        return inval();
    }
    Ok(target)
}

// ============================================================================
// Pass 2: values
// ============================================================================

struct Checker<'a> {
    insns: &'a [BpfInsn],
    kind: &'a Kind,
    /// Jump targets: where states are kept for pruning
    target: Vec<bool>,
    /// Checked states at each jump target
    seen: BTreeMap<usize, Vec<State>>,
    stored: usize,
    depth: usize,
}

/// A register's value as an operand: uninitialized is EACCES
fn read(v: Val) -> Result<Val, KernelError> {
    if v == Val::Uninit { acces() } else { Ok(v) }
}

impl Checker<'_> {
    /// The ALU instruction's result
    fn alu(&self, insn: &BpfInsn, st: &State) -> Result<Val, KernelError> {
        let code = insn.code;
        let (d, s) = (insn.dst_reg() as usize, insn.src_reg() as usize);
        let w64 = bpf_class(code) == BPF_ALU64;
        let op = bpf_op(code);
        let src = if bpf_src(code) == BPF_X {
            read(st.regs[s])?
        } else if w64 {
            Val::Scalar(Some(insn.imm as i64 as u64))
        } else {
            Val::Scalar(Some(insn.imm as u32 as u64))
        };
        if op == BPF_MOV && insn.off == 0 && w64 {
            return Ok(src);
        }
        if op == BPF_END {
            return match read(st.regs[d])? {
                Val::Scalar(a) => {
                    let swap = interp::end_swaps(code);
                    Ok(Val::Scalar(
                        a.and_then(|a| interp::endian(a, insn.imm, swap)),
                    ))
                }
                _ => acces(),
            };
        }
        let dst = if op == BPF_MOV {
            Val::Scalar(Some(0))
        } else {
            read(st.regs[d])?
        };
        match (dst, src) {
            (Val::Scalar(a), Val::Scalar(b)) => {
                let v = match (a, b) {
                    (Some(a), Some(b)) if w64 => interp::alu64(op, insn.off, a, b),
                    (Some(a), Some(b)) => interp::alu32(op, insn.off, a, b),
                    _ => None,
                };
                Ok(Val::Scalar(v))
            }
            // A pointer moves only by a known constant, in 64 bits
            (Val::Ptr(r, o), Val::Scalar(Some(c))) if w64 && op == BPF_ADD => offset(r, o, c),
            (Val::Ptr(r, o), Val::Scalar(Some(c))) if w64 && op == BPF_SUB => {
                offset(r, o, c.wrapping_neg())
            }
            (Val::Scalar(Some(c)), Val::Ptr(r, o)) if w64 && op == BPF_ADD => offset(r, o, c),
            (Val::Ptr(r1, _), Val::Ptr(r2, _)) if w64 && op == BPF_SUB && r1 == r2 => Ok(UNKNOWN),
            _ => acces(),
        }
    }

    /// Byte offset of `[ptr + off, + size)`, if in bounds for `write`
    fn place(
        &self,
        base: Val,
        off: i16,
        size: usize,
        write: bool,
    ) -> Result<(Region, usize), KernelError> {
        let Val::Ptr(r, o) = read(base)? else {
            return acces();
        };
        let at = o as i64 + off as i64;
        let size = size as i64;
        match r {
            Region::Ctx if !write && at >= 0 && at + size <= self.kind.ctx_size as i64 => {
                if at % size != 0 {
                    return acces();
                }
                Ok((r, at as usize))
            }
            Region::Stack if at >= -(BPF_STACK_SIZE as i64) && at + size <= 0 => {
                Ok((r, (at + BPF_STACK_SIZE as i64) as usize))
            }
            _ => acces(),
        }
    }

    fn load(&mut self, insn: &BpfInsn, st: &mut State) -> Result<(), KernelError> {
        let size = interp::size_bytes(insn.code);
        let (r, at) = self.place(st.regs[insn.src_reg() as usize], insn.off, size, false)?;
        let v = match r {
            Region::Ctx => UNKNOWN,
            Region::Stack => {
                if !st.written(at, size) {
                    return acces();
                }
                let spilled = st.spill[at / 8].filter(|_| size == 8 && at.is_multiple_of(8));
                match spilled {
                    Some((r, o)) if bpf_mode(insn.code) == BPF_MEM => Val::Ptr(r, o),
                    _ => UNKNOWN,
                }
            }
        };
        st.regs[insn.dst_reg() as usize] = v;
        Ok(())
    }

    fn store(&mut self, insn: &BpfInsn, st: &mut State, v: Val) -> Result<(), KernelError> {
        let size = interp::size_bytes(insn.code);
        let (_, at) = self.place(st.regs[insn.dst_reg() as usize], insn.off, size, true)?;
        read(v)?;
        st.spill[at / 8] = None;
        st.spill[(at + size - 1) / 8] = None;
        if let Val::Ptr(r, o) = v {
            // Only whole, aligned pointer spills
            if size != 8 || !at.is_multiple_of(8) {
                return acces();
            }
            st.spill[at / 8] = Some((r, o));
        }
        st.mark(at, size);
        self.depth = self.depth.max(BPF_STACK_SIZE - at);
        Ok(())
    }

    fn atomic(&mut self, insn: &BpfInsn, st: &mut State) -> Result<(), KernelError> {
        let size = interp::size_bytes(insn.code);
        let (r, at) = self.place(st.regs[insn.dst_reg() as usize], insn.off, size, true)?;
        let s = insn.src_reg() as usize;
        if r != Region::Stack || !st.written(at, size) || st.spill[at / 8].is_some() {
            return acces();
        }
        if !matches!(read(st.regs[s])?, Val::Scalar(_)) {
            return acces();
        }
        if insn.imm == BPF_CMPXCHG {
            if !matches!(read(st.regs[0])?, Val::Scalar(_)) {
                return acces();
            }
            st.regs[0] = UNKNOWN;
        } else if insn.imm & BPF_FETCH != 0 {
            st.regs[s] = UNKNOWN;
        }
        Ok(())
    }

    fn call(&self, insn: &BpfInsn, st: &mut State) -> Result<(), KernelError> {
        let n = self
            .kind
            .helpers
            .iter()
            .find(|h| h.0 == insn.imm)
            .map_or(0, |h| h.1);
        for r in 1..=n as usize {
            if !matches!(read(st.regs[r])?, Val::Scalar(_)) {
                return acces();
            }
        }
        st.regs[0] = UNKNOWN;
        for r in &mut st.regs[1..=5] {
            *r = Val::Uninit;
        }
        Ok(())
    }

    /// Whether the jump is taken: Some if decided by constants
    fn branch(&self, insn: &BpfInsn, st: &State) -> Result<Option<bool>, KernelError> {
        let a = read(st.regs[insn.dst_reg() as usize])?;
        let b = if bpf_src(insn.code) == BPF_X {
            read(st.regs[insn.src_reg() as usize])?
        } else {
            Val::Scalar(Some(insn.imm as i64 as u64))
        };
        let w32 = bpf_class(insn.code) == BPF_JMP32;
        Ok(match (a, b) {
            (Val::Scalar(Some(a)), Val::Scalar(Some(b))) => {
                interp::cond(bpf_op(insn.code), w32, a, b)
            }
            _ => None,
        })
    }

    /// Whether a checked state at `pc` covers `st`; else keep `st`
    fn prune(&mut self, pc: usize, st: &State) -> Result<bool, KernelError> {
        if !self.target[pc] {
            return Ok(false);
        }
        let seen = self.seen.entry(pc).or_default();
        if seen.iter().any(|o| o.covers(st)) {
            return Ok(true);
        }
        if self.stored < MAX_STORED && seen.len() < MAX_PER_TARGET {
            seen.try_reserve(1).map_err(|_| KernelError::OutOfMemory)?;
            seen.push(*st);
            self.stored += 1;
        }
        Ok(false)
    }

    /// Pass 2: follow every path from the entry
    fn run(&mut self) -> Result<(), KernelError> {
        let mut work: Vec<(usize, State)> = Vec::new();
        work.try_reserve(1).map_err(|_| KernelError::OutOfMemory)?;
        work.push((0, State::entry()));
        let mut steps = 0usize;
        while let Some((mut pc, mut st)) = work.pop() {
            loop {
                steps += 1;
                if steps > COMPLEXITY_LIMIT {
                    return Err(KernelError::ArgListTooLong);
                }
                if self.prune(pc, &st)? {
                    break;
                }
                let insn = &self.insns[pc];
                let (d, s) = (insn.dst_reg() as usize, insn.src_reg() as usize);
                match bpf_class(insn.code) {
                    BPF_ALU | BPF_ALU64 => st.regs[d] = self.alu(insn, &st)?,
                    BPF_LDX => self.load(insn, &mut st)?,
                    BPF_ST => {
                        let v = Val::Scalar(Some(insn.imm as i64 as u64));
                        self.store(insn, &mut st, v)?;
                    }
                    BPF_STX if bpf_mode(insn.code) == BPF_ATOMIC => self.atomic(insn, &mut st)?,
                    BPF_STX => {
                        let v = st.regs[s];
                        self.store(insn, &mut st, v)?;
                    }
                    BPF_LD => {
                        let hi = self.insns[pc + 1].imm as u32 as u64;
                        st.regs[d] = Val::Scalar(Some(hi << 32 | insn.imm as u32 as u64));
                    }
                    _ => match bpf_op(insn.code) {
                        BPF_EXIT => {
                            // R0 is the result: a number, never a pointer
                            if !matches!(st.regs[0], Val::Scalar(_)) {
                                return acces();
                            }
                            break;
                        }
                        BPF_CALL => self.call(insn, &mut st)?,
                        BPF_JA => {}
                        _ => {
                            let (_, Some(t)) = successors(self.insns, pc) else {
                                return inval();
                            };
                            match self.branch(insn, &st)? {
                                Some(true) => {
                                    pc = t as usize;
                                    continue;
                                }
                                Some(false) => {}
                                None => {
                                    if work.len() >= MAX_PENDING {
                                        return Err(KernelError::ArgListTooLong);
                                    }
                                    work.try_reserve(1).map_err(|_| KernelError::OutOfMemory)?;
                                    work.push((t as usize, st));
                                }
                            }
                        }
                    },
                }
                let (next, jump) = successors(self.insns, pc);
                pc = match (next, jump) {
                    (_, Some(t)) if bpf_op(insn.code) == BPF_JA => t as usize,
                    (Some(n), _) => n,
                    _ => return inval(),
                };
            }
        }
        Ok(())
    }
}

/// `r + o + c` if it stays a sane offset
fn offset(r: Region, o: i32, c: u64) -> Result<Val, KernelError> {
    let v = o as i64 + c as i64;
    if (i16::MIN as i64..=i16::MAX as i64).contains(&v) {
        Ok(Val::Ptr(r, v as i32))
    } else {
        acces()
    }
}

/// Check `insns` for a program of `kind` (Linux bpf_check)
pub fn verify(insns: &[BpfInsn], kind: &Kind, max: usize) -> Result<Verified, KernelError> {
    if insns.is_empty() || insns.len() > max {
        return inval();
    }
    let target = check_cfg(insns, kind)?;
    let mut c = Checker {
        insns,
        kind,
        target,
        seen: BTreeMap::new(),
        stored: 0,
        depth: 0,
    };
    c.run()?;
    Ok(Verified {
        stack_depth: c.depth,
    })
}
