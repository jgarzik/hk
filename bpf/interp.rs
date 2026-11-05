//! eBPF interpreter (RFC 9669, the BPF instruction set)
//!
//! A register holds a 64-bit value and, when it is a pointer, the
//! memory region it points into: the read-only context or the 512-byte
//! stack. A pointer's value is its offset inside its region, never a
//! kernel address, so a program can neither forge a pointer nor learn
//! one. Every load and store is bounds-checked against its region, so a
//! verifier bug gives a wrong result or a fault, never a kernel memory
//! access. Pointer + scalar keeps the region; any other operation on a
//! pointer gives a plain scalar. An 8-byte aligned stack slot that holds
//! a spilled pointer remembers its region until it is overwritten.
//!
//! The verifier proves termination; `MAX_STEPS` is only a backstop.
//!
//! Semantics follow RFC 9669: 32-bit ALU results are zero-extended,
//! 32-bit jumps compare the low halves, shift counts are masked to the
//! operand width, unsigned division by zero gives 0, modulo by zero
//! leaves the dividend, signed forms (offset 1) and sign-extending
//! moves and loads, byte swaps, and the atomic operations on the stack.
//! No locks: all state is on the caller's stack.

// Run by classic filters once they are converted (bpf/convert.rs)
#![cfg_attr(not(test), allow(dead_code))]

use super::insn::*;

/// Instructions one run may execute before it is stopped
pub const MAX_STEPS: u64 = 1 << 20;

/// Why a run stopped without reaching EXIT
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// An instruction the interpreter does not know
    BadInsn,
    /// A load or store outside its region, or through a non-pointer
    Mem,
    /// A helper the program may not call, or one that failed
    Call,
    /// More than `MAX_STEPS` instructions
    Budget,
}

/// What a program runs against
pub trait Env {
    /// The context R1 points to at entry (read-only)
    fn ctx(&self) -> &[u8];
    /// Helper `id` with R1..R5; None if the program may not call it
    fn call(&mut self, id: i32, args: [u64; 5]) -> Option<u64> {
        let _ = (id, args);
        None
    }
}

/// Where a pointer points
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Region {
    /// Not a pointer
    None,
    Ctx,
    Stack,
}

/// One register: its value and, if a pointer, its region
#[derive(Clone, Copy, Debug)]
struct Reg {
    v: u64,
    r: Region,
}

impl Reg {
    const fn scalar(v: u64) -> Self {
        Self { v, r: Region::None }
    }
}

/// Byte size of an access of size field `size`
pub(super) fn size_bytes(code: u8) -> usize {
    match bpf_size(code) {
        BPF_B => 1,
        BPF_H => 2,
        BPF_W => 4,
        _ => 8,
    }
}

/// Mode of a sign-extending load (RFC 9669 MEMSX)
pub const BPF_MEMSX: u8 = 0x80;

/// Atomic operation codes (in `imm` of STX | ATOMIC)
pub const BPF_FETCH: i32 = 0x01;
pub const BPF_XCHG: i32 = 0xe0 | BPF_FETCH;
pub const BPF_CMPXCHG: i32 = 0xf0 | BPF_FETCH;

/// The result of a 64-bit ALU operation `op` (offset `off` selects the
/// signed forms of DIV/MOD and the widths of MOVSX), or None if unknown
pub(super) fn alu64(op: u8, off: i16, dst: u64, src: u64) -> Option<u64> {
    let signed = off == 1;
    Some(match op {
        BPF_ADD => dst.wrapping_add(src),
        BPF_SUB => dst.wrapping_sub(src),
        BPF_MUL => dst.wrapping_mul(src),
        BPF_DIV if src == 0 => 0,
        BPF_DIV if signed => (dst as i64).wrapping_div(src as i64) as u64,
        BPF_DIV => dst / src,
        BPF_MOD if src == 0 => dst,
        BPF_MOD if signed => (dst as i64).wrapping_rem(src as i64) as u64,
        BPF_MOD => dst % src,
        BPF_OR => dst | src,
        BPF_AND => dst & src,
        BPF_XOR => dst ^ src,
        BPF_LSH => dst << (src & 63),
        BPF_RSH => dst >> (src & 63),
        BPF_ARSH => ((dst as i64) >> (src & 63)) as u64,
        BPF_NEG => dst.wrapping_neg(),
        BPF_MOV => match off {
            0 => src,
            8 => src as i8 as i64 as u64,
            16 => src as i16 as i64 as u64,
            32 => src as i32 as i64 as u64,
            _ => return None,
        },
        _ => return None,
    })
}

/// The result of a 32-bit ALU operation, zero-extended
pub(super) fn alu32(op: u8, off: i16, dst: u64, src: u64) -> Option<u64> {
    let (d, s) = (dst as u32, src as u32);
    let signed = off == 1;
    let v = match op {
        BPF_ADD => d.wrapping_add(s),
        BPF_SUB => d.wrapping_sub(s),
        BPF_MUL => d.wrapping_mul(s),
        BPF_DIV if s == 0 => 0,
        BPF_DIV if signed => (d as i32).wrapping_div(s as i32) as u32,
        BPF_DIV => d / s,
        BPF_MOD if s == 0 => d,
        BPF_MOD if signed => (d as i32).wrapping_rem(s as i32) as u32,
        BPF_MOD => d % s,
        BPF_OR => d | s,
        BPF_AND => d & s,
        BPF_XOR => d ^ s,
        BPF_LSH => d << (s & 31),
        BPF_RSH => d >> (s & 31),
        BPF_ARSH => ((d as i32) >> (s & 31)) as u32,
        BPF_NEG => d.wrapping_neg(),
        BPF_MOV => match off {
            0 => s,
            8 => s as i8 as i32 as u32,
            16 => s as i16 as i32 as u32,
            _ => return None,
        },
        _ => return None,
    };
    Some(v as u64)
}

/// Byte-order conversion (class ALU: `to_be` per the source bit; class
/// ALU64: an unconditional swap), truncated to `bits`
pub(super) fn endian(v: u64, bits: i32, swap: bool) -> Option<u64> {
    Some(match (bits, swap) {
        (16, false) => v as u16 as u64,
        (16, true) => (v as u16).swap_bytes() as u64,
        (32, false) => v as u32 as u64,
        (32, true) => (v as u32).swap_bytes() as u64,
        (64, false) => v,
        (64, true) => v.swap_bytes(),
        _ => return None,
    })
}

/// Whether ALU instruction `code` with `imm` swaps bytes on this host
pub(super) fn end_swaps(code: u8) -> bool {
    let to_be = bpf_src(code) == BPF_X;
    bpf_class(code) == BPF_ALU64 || to_be == cfg!(target_endian = "little")
}

/// Whether conditional jump `op` is taken; `w32` compares low halves
pub(super) fn cond(op: u8, w32: bool, a: u64, b: u64) -> Option<bool> {
    let (a, b, sa, sb) = if w32 {
        let (a, b) = (a as u32, b as u32);
        (a as u64, b as u64, a as i32 as i64, b as i32 as i64)
    } else {
        (a, b, a as i64, b as i64)
    };
    Some(match op {
        BPF_JEQ => a == b,
        BPF_JNE => a != b,
        BPF_JGT => a > b,
        BPF_JGE => a >= b,
        BPF_JLT => a < b,
        BPF_JLE => a <= b,
        BPF_JSET => a & b != 0,
        BPF_JSGT => sa > sb,
        BPF_JSGE => sa >= sb,
        BPF_JSLT => sa < sb,
        BPF_JSLE => sa <= sb,
        _ => return None,
    })
}

/// One run's machine state
struct Vm<'a, E: Env> {
    env: &'a mut E,
    regs: [Reg; MAX_BPF_REG],
    stack: [u8; BPF_STACK_SIZE],
    /// The region of the pointer spilled to each 8-byte stack slot
    spill: [Region; BPF_STACK_SIZE / 8],
}

impl<E: Env> Vm<'_, E> {
    /// Offset in `r`'s region of `[r + off, + size)`, if inside it
    fn place(&self, r: Reg, off: i16, size: usize, write: bool) -> Result<usize, Fault> {
        let len = match r.r {
            Region::Ctx if !write => self.env.ctx().len(),
            Region::Stack => BPF_STACK_SIZE,
            _ => return Err(Fault::Mem),
        };
        let at = r.v.wrapping_add(off as i64 as u64);
        match at.checked_add(size as u64) {
            Some(end) if end <= len as u64 => Ok(at as usize),
            _ => Err(Fault::Mem),
        }
    }

    fn read(&self, r: Reg, off: i16, size: usize) -> Result<Reg, Fault> {
        let at = self.place(r, off, size, false)?;
        let bytes = match r.r {
            Region::Ctx => &self.env.ctx()[at..at + size],
            _ => &self.stack[at..at + size],
        };
        let mut b = [0u8; 8];
        b[..size].copy_from_slice(bytes);
        let v = match size {
            1 => b[0] as u64,
            2 => u16::from_ne_bytes([b[0], b[1]]) as u64,
            4 => u32::from_ne_bytes([b[0], b[1], b[2], b[3]]) as u64,
            _ => u64::from_ne_bytes(b),
        };
        let mut reg = Reg::scalar(v);
        if r.r == Region::Stack && size == 8 && at.is_multiple_of(8) {
            reg.r = self.spill[at / 8];
        }
        Ok(reg)
    }

    fn write(&mut self, r: Reg, off: i16, size: usize, v: Reg) -> Result<(), Fault> {
        let at = self.place(r, off, size, true)?;
        let b = v.v.to_ne_bytes();
        self.stack[at..at + size].copy_from_slice(&b[..size]);
        // A store covers at most two slots; any store ends a spill there
        self.spill[at / 8] = Region::None;
        self.spill[(at + size - 1) / 8] = Region::None;
        if size == 8 && at.is_multiple_of(8) {
            self.spill[at / 8] = v.r;
        }
        Ok(())
    }

    fn alu(&mut self, insn: &BpfInsn) -> Result<(), Fault> {
        let code = insn.code;
        let (d, s) = (insn.dst_reg() as usize, insn.src_reg() as usize);
        let w64 = bpf_class(code) == BPF_ALU64;
        let op = bpf_op(code);
        let dst = self.regs[d];
        if op == BPF_END {
            let swap = end_swaps(code);
            let v = endian(dst.v, insn.imm, swap).ok_or(Fault::BadInsn)?;
            self.regs[d] = Reg::scalar(v);
            return Ok(());
        }
        let src = if bpf_src(code) == BPF_X {
            self.regs[s]
        } else if w64 {
            Reg::scalar(insn.imm as i64 as u64)
        } else {
            Reg::scalar(insn.imm as u32 as u64)
        };
        let v = if w64 {
            alu64(op, insn.off, dst.v, src.v)
        } else {
            alu32(op, insn.off, dst.v, src.v)
        }
        .ok_or(Fault::BadInsn)?;
        // Pointer arithmetic keeps the region; anything else is a scalar
        let r = match (w64, op, dst.r, src.r) {
            (true, BPF_MOV, _, r) if insn.off == 0 => r,
            (true, BPF_ADD, r, Region::None) | (true, BPF_ADD, Region::None, r) => r,
            (true, BPF_SUB, r, Region::None) => r,
            _ => Region::None,
        };
        self.regs[d] = Reg { v, r };
        Ok(())
    }

    fn atomic(&mut self, insn: &BpfInsn) -> Result<(), Fault> {
        let size = size_bytes(insn.code);
        if size < 4 {
            return Err(Fault::BadInsn);
        }
        let (d, s) = (insn.dst_reg() as usize, insn.src_reg() as usize);
        let (base, src) = (self.regs[d], self.regs[s]);
        let old = self.read(base, insn.off, size)?;
        let trunc = |v: u64| if size == 4 { v as u32 as u64 } else { v };
        let new = match insn.imm {
            BPF_XCHG => src.v,
            BPF_CMPXCHG => {
                let r0 = self.regs[BPF_REG_0 as usize].v;
                let new = if trunc(r0) == old.v { src.v } else { old.v };
                self.write(base, insn.off, size, Reg::scalar(new))?;
                self.regs[BPF_REG_0 as usize] = Reg::scalar(old.v);
                return Ok(());
            }
            imm => {
                let op = (imm & !BPF_FETCH) as u8;
                if !matches!(op, BPF_ADD | BPF_OR | BPF_AND | BPF_XOR) {
                    return Err(Fault::BadInsn);
                }
                alu64(op, 0, old.v, src.v).ok_or(Fault::BadInsn)?
            }
        };
        self.write(base, insn.off, size, Reg::scalar(trunc(new)))?;
        if insn.imm & BPF_FETCH != 0 {
            self.regs[s] = Reg::scalar(old.v);
        }
        Ok(())
    }

    fn call(&mut self, insn: &BpfInsn) -> Result<(), Fault> {
        if insn.src_reg() != 0 {
            return Err(Fault::Call);
        }
        let mut args = [0u64; 5];
        for (a, r) in args.iter_mut().zip(&self.regs[1..=5]) {
            *a = r.v;
        }
        let v = self.env.call(insn.imm, args).ok_or(Fault::Call)?;
        self.regs[BPF_REG_0 as usize] = Reg::scalar(v);
        for r in &mut self.regs[1..=5] {
            *r = Reg::scalar(0);
        }
        Ok(())
    }

    /// Execute from instruction 0 until EXIT
    fn exec(&mut self, prog: &[BpfInsn]) -> Result<u64, Fault> {
        let mut pc = 0usize;
        let mut steps = 0u64;
        loop {
            steps += 1;
            if steps > MAX_STEPS {
                return Err(Fault::Budget);
            }
            let insn = prog.get(pc).ok_or(Fault::BadInsn)?;
            let code = insn.code;
            let (d, s) = (insn.dst_reg() as usize, insn.src_reg() as usize);
            if d >= MAX_BPF_REG || s >= MAX_BPF_REG {
                return Err(Fault::BadInsn);
            }
            pc += 1;
            match bpf_class(code) {
                BPF_ALU | BPF_ALU64 => self.alu(insn)?,
                BPF_LDX => {
                    let size = size_bytes(code);
                    let mut v = self.read(self.regs[s], insn.off, size)?;
                    match bpf_mode(code) {
                        BPF_MEM => {}
                        BPF_MEMSX if size < 8 => {
                            let sh = 64 - 8 * size as u32;
                            v = Reg::scalar((((v.v << sh) as i64) >> sh) as u64);
                        }
                        _ => return Err(Fault::BadInsn),
                    }
                    self.regs[d] = v;
                }
                BPF_ST if bpf_mode(code) == BPF_MEM => {
                    let v = Reg::scalar(insn.imm as i64 as u64);
                    self.write(self.regs[d], insn.off, size_bytes(code), v)?;
                }
                BPF_STX if bpf_mode(code) == BPF_MEM => {
                    let v = self.regs[s];
                    self.write(self.regs[d], insn.off, size_bytes(code), v)?;
                }
                BPF_STX if bpf_mode(code) == BPF_ATOMIC => self.atomic(insn)?,
                BPF_LD if code == BPF_LD | BPF_IMM | BPF_DW && s == 0 => {
                    let hi = prog.get(pc).ok_or(Fault::BadInsn)?;
                    let v = (hi.imm as u32 as u64) << 32 | insn.imm as u32 as u64;
                    self.regs[d] = Reg::scalar(v);
                    pc += 1;
                }
                BPF_JMP | BPF_JMP32 => {
                    let w32 = bpf_class(code) == BPF_JMP32;
                    match bpf_op(code) {
                        BPF_EXIT if !w32 => return Ok(self.regs[BPF_REG_0 as usize].v),
                        BPF_CALL if !w32 => self.call(insn)?,
                        BPF_JA => {
                            let off = if w32 {
                                insn.imm as i64
                            } else {
                                insn.off as i64
                            };
                            pc = (pc as i64).wrapping_add(off) as usize;
                        }
                        op => {
                            let b = if bpf_src(code) == BPF_X {
                                self.regs[s].v
                            } else {
                                insn.imm as i64 as u64
                            };
                            let a = self.regs[d].v;
                            if cond(op, w32, a, b).ok_or(Fault::BadInsn)? {
                                pc = (pc as i64).wrapping_add(insn.off as i64) as usize;
                            }
                        }
                    }
                }
                _ => return Err(Fault::BadInsn),
            }
        }
    }
}

/// Run `prog` against `env`: R0 at EXIT, or why it stopped
pub fn run<E: Env>(prog: &[BpfInsn], env: &mut E) -> Result<u64, Fault> {
    let mut vm = Vm {
        env,
        regs: [Reg::scalar(0); MAX_BPF_REG],
        stack: [0; BPF_STACK_SIZE],
        spill: [Region::None; BPF_STACK_SIZE / 8],
    };
    vm.regs[BPF_REG_1 as usize] = Reg {
        v: 0,
        r: Region::Ctx,
    };
    vm.regs[BPF_REG_10 as usize] = Reg {
        v: BPF_STACK_SIZE as u64,
        r: Region::Stack,
    };
    vm.exec(prog)
}
