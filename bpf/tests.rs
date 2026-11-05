//! BPF engine tests: interpreter conformance (RFC 9669 known answers)

use super::insn::*;
use super::interp::{self, BPF_CMPXCHG, BPF_FETCH, BPF_MEMSX, BPF_XCHG, Env, Fault};

/// A context of 64 bytes 0..63 and one helper (id 7: R1 + R2)
struct T {
    ctx: [u8; 64],
}

impl Env for T {
    fn ctx(&self) -> &[u8] {
        &self.ctx
    }
    fn call(&mut self, id: i32, a: [u64; 5]) -> Option<u64> {
        (id == 7).then(|| a[0].wrapping_add(a[1]))
    }
}

fn env() -> T {
    let mut ctx = [0u8; 64];
    for (i, b) in ctx.iter_mut().enumerate() {
        *b = i as u8;
    }
    T { ctx }
}

const fn i(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> BpfInsn {
    BpfInsn::new(code, dst, src, off, imm)
}

const EXIT: BpfInsn = i(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);

fn mov64(d: u8, imm: i32) -> BpfInsn {
    i(BPF_ALU64 | BPF_MOV | BPF_K, d, 0, 0, imm)
}

fn mov32(d: u8, imm: i32) -> BpfInsn {
    i(BPF_ALU | BPF_MOV | BPF_K, d, 0, 0, imm)
}

/// R0 = `v` (64-bit, two instructions)
fn lddw(d: u8, v: u64) -> [BpfInsn; 2] {
    [
        i(BPF_LD | BPF_IMM | BPF_DW, d, 0, 0, v as u32 as i32),
        i(0, 0, 0, 0, (v >> 32) as u32 as i32),
    ]
}

fn run(p: &[BpfInsn]) -> Result<u64, Fault> {
    interp::run(p, &mut env())
}

/// R0 = `a`, R1 = `b`, then `op`, then exit: R0
fn op2(a: u64, b: u64, op: BpfInsn) -> u64 {
    let mut p = alloc::vec::Vec::new();
    p.extend(lddw(0, a));
    p.extend(lddw(1, b));
    p.push(op);
    p.push(EXIT);
    run(&p).unwrap()
}

fn alu64x(op: u8, off: i16) -> BpfInsn {
    i(BPF_ALU64 | op | BPF_X, 0, 1, off, 0)
}

fn alu32x(op: u8, off: i16) -> BpfInsn {
    i(BPF_ALU | op | BPF_X, 0, 1, off, 0)
}

#[test]
fn alu_widths() {
    // ALU32 zero-extends; ALU64 immediates sign-extend
    assert_eq!(run(&[mov32(0, -1), EXIT]), Ok(0xffff_ffff));
    assert_eq!(run(&[mov64(0, -1), EXIT]), Ok(u64::MAX));
    assert_eq!(op2(u64::MAX, 1, alu32x(BPF_ADD, 0)), 0);
    assert_eq!(op2(u64::MAX, 1, alu64x(BPF_ADD, 0)), 0);
    assert_eq!(op2(0x1_0000_0005, 3, alu32x(BPF_SUB, 0)), 2);
    assert_eq!(op2(0xffff_ffff, 0xffff_ffff, alu32x(BPF_MUL, 0)), 1);
    // A 32-bit immediate is not sign-extended into the operation
    let p = [
        mov64(0, -1),
        i(BPF_ALU | BPF_DIV | BPF_K, 0, 0, 0, -2),
        EXIT,
    ];
    assert_eq!(run(&p), Ok(1));
}

#[test]
fn division_by_zero() {
    assert_eq!(op2(9, 0, alu64x(BPF_DIV, 0)), 0);
    assert_eq!(op2(9, 0, alu64x(BPF_MOD, 0)), 9);
    assert_eq!(op2(0x1_0000_0009, 0, alu32x(BPF_MOD, 0)), 9);
    assert_eq!(op2(0x1_0000_0009, 0x1_0000_0000, alu32x(BPF_DIV, 0)), 0);
}

#[test]
fn signed_division() {
    let m7 = -7i64 as u64;
    assert_eq!(op2(m7, 2, alu64x(BPF_DIV, 1)), -3i64 as u64);
    assert_eq!(op2(m7, 2, alu64x(BPF_MOD, 1)), -1i64 as u64);
    let min = i64::MIN as u64;
    assert_eq!(op2(min, u64::MAX, alu64x(BPF_DIV, 1)), min);
    assert_eq!(op2(min, u64::MAX, alu64x(BPF_MOD, 1)), 0);
    assert_eq!(op2(m7, 2, alu32x(BPF_DIV, 1)), -3i32 as u32 as u64);
    // Unsigned forms of the same operands
    assert_eq!(op2(m7, 2, alu64x(BPF_DIV, 0)), m7 / 2);
}

#[test]
fn shifts() {
    assert_eq!(op2(1, 65, alu64x(BPF_LSH, 0)), 2);
    assert_eq!(op2(1, 33, alu32x(BPF_LSH, 0)), 2);
    assert_eq!(op2(0x8000_0000_0000_0000, 63, alu64x(BPF_RSH, 0)), 1);
    assert_eq!(
        op2(0x8000_0000_0000_0000, 63, alu64x(BPF_ARSH, 0)),
        u64::MAX
    );
    assert_eq!(op2(0x8000_0000, 31, alu32x(BPF_ARSH, 0)), 0xffff_ffff);
}

#[test]
fn neg_and_movsx() {
    assert_eq!(op2(5, 0, i(BPF_ALU64 | BPF_NEG, 0, 0, 0, 0)), -5i64 as u64);
    assert_eq!(
        op2(5, 0, i(BPF_ALU | BPF_NEG, 0, 0, 0, 0)),
        -5i32 as u32 as u64
    );
    assert_eq!(op2(0, 0x80, alu64x(BPF_MOV, 8)), -128i64 as u64);
    assert_eq!(op2(0, 0x8000, alu64x(BPF_MOV, 16)), -32768i64 as u64);
    assert_eq!(
        op2(0, 0x8000_0000, alu64x(BPF_MOV, 32)),
        i32::MIN as i64 as u64
    );
    assert_eq!(op2(0, 0x80, alu32x(BPF_MOV, 8)), 0xffff_ff80);
}

#[test]
fn byte_order() {
    let v = 0x0102_0304_0506_0708u64;
    let le = |bits| op2(v, 0, i(BPF_ALU | BPF_END | BPF_K, 0, 0, 0, bits));
    let be = |bits| op2(v, 0, i(BPF_ALU | BPF_END | BPF_X, 0, 0, 0, bits));
    let swap = |bits| op2(v, 0, i(BPF_ALU64 | BPF_END | BPF_K, 0, 0, 0, bits));
    assert_eq!(le(16), 0x0708);
    assert_eq!(le(32), 0x0506_0708);
    assert_eq!(le(64), v);
    assert_eq!(be(16), 0x0807);
    assert_eq!(be(32), 0x0807_0605);
    assert_eq!(swap(64), 0x0807_0605_0403_0201);
}

/// R0 = 1 if `j` (comparing R0 = `a` with R1 = `b`, or `imm`) is taken
fn taken(a: u64, b: u64, j: BpfInsn) -> u64 {
    let mut p = alloc::vec::Vec::new();
    p.extend(lddw(2, a));
    p.extend(lddw(1, b));
    p.push(i(j.code, 2, j.src_reg(), 2, j.imm));
    p.push(mov64(0, 0));
    p.push(EXIT);
    p.push(mov64(0, 1));
    p.push(EXIT);
    run(&p).unwrap()
}

#[test]
fn jumps() {
    let x = |op| i(BPF_JMP | op | BPF_X, 0, 1, 0, 0);
    let x32 = |op| i(BPF_JMP32 | op | BPF_X, 0, 1, 0, 0);
    let k = |op, imm| i(BPF_JMP | op | BPF_K, 0, 0, 0, imm);
    let k32 = |op, imm| i(BPF_JMP32 | op | BPF_K, 0, 0, 0, imm);
    // 32-bit jumps compare the low halves
    assert_eq!(taken(0x1_0000_0000, 0, x32(BPF_JEQ)), 1);
    assert_eq!(taken(0x1_0000_0000, 0, x(BPF_JEQ)), 0);
    // A 64-bit jump's immediate is sign-extended
    assert_eq!(taken(u64::MAX, 0, k(BPF_JEQ, -1)), 1);
    assert_eq!(taken(0xffff_ffff, 0, k(BPF_JEQ, -1)), 0);
    assert_eq!(taken(0xffff_ffff, 0, k32(BPF_JEQ, -1)), 1);
    // Signed and unsigned orderings differ
    assert_eq!(taken(u64::MAX, 1, x(BPF_JGT)), 1);
    assert_eq!(taken(u64::MAX, 1, x(BPF_JSGT)), 0);
    assert_eq!(taken(u64::MAX, 1, x(BPF_JSLT)), 1);
    assert_eq!(taken(0x8000_0000, 1, x32(BPF_JSLT)), 1);
    assert_eq!(taken(0x8000_0000, 1, x(BPF_JSLT)), 0);
    assert_eq!(taken(3, 3, x(BPF_JLE)), 1);
    assert_eq!(taken(3, 3, x(BPF_JLT)), 0);
    assert_eq!(taken(3, 3, x(BPF_JGE)), 1);
    assert_eq!(taken(6, 2, x(BPF_JSET)), 1);
    assert_eq!(taken(6, 1, x(BPF_JSET)), 0);
    assert_eq!(taken(6, 1, x(BPF_JNE)), 1);
    assert_eq!(taken(5, 5, x(BPF_JSGE)), 1);
    assert_eq!(taken(5, 5, x(BPF_JSLE)), 1);
    // JMP32 JA takes its offset from imm (gotol)
    let p = [
        i(BPF_JMP32 | BPF_JA, 0, 0, 0, 2),
        mov64(0, 1),
        EXIT,
        mov64(0, 3),
        EXIT,
    ];
    assert_eq!(run(&p), Ok(3));
}

#[test]
fn memory() {
    let ldx = |size: u8, mode: u8, d, s, off| i(BPF_LDX | mode | size, d, s, off, 0);
    // Context loads (native endian) and their bounds
    assert_eq!(run(&[ldx(BPF_B, BPF_MEM, 0, 1, 5), EXIT]), Ok(5));
    assert_eq!(
        run(&[ldx(BPF_W, BPF_MEM, 0, 1, 4), EXIT]),
        Ok(u32::from_ne_bytes([4, 5, 6, 7]) as u64)
    );
    assert_eq!(
        run(&[ldx(BPF_DW, BPF_MEM, 0, 1, 57), EXIT]),
        Err(Fault::Mem)
    );
    assert_eq!(run(&[ldx(BPF_B, BPF_MEM, 0, 1, -1), EXIT]), Err(Fault::Mem));
    // The context is read-only
    let st = i(BPF_ST | BPF_MEM | BPF_B, 1, 0, 0, 1);
    assert_eq!(run(&[st, mov64(0, 0), EXIT]), Err(Fault::Mem));
    // A scalar is not a pointer
    assert_eq!(
        run(&[mov64(2, 0), ldx(BPF_B, BPF_MEM, 0, 2, 0), EXIT]),
        Err(Fault::Mem)
    );
    // Stack: R10 is its end, stores and loads round-trip
    let p = [
        i(BPF_ST | BPF_MEM | BPF_W, 10, 0, -4, -2),
        ldx(BPF_W, BPF_MEM, 0, 10, -4),
        EXIT,
    ];
    assert_eq!(run(&p), Ok(0xffff_fffe));
    let p = [
        i(BPF_ST | BPF_MEM | BPF_H, 10, 0, -2, 0x8001),
        ldx(BPF_H, BPF_MEMSX, 0, 10, -2),
        EXIT,
    ];
    assert_eq!(run(&p), Ok(0x8001u16 as i16 as i64 as u64));
    assert_eq!(run(&[ldx(BPF_B, BPF_MEM, 0, 10, 0), EXIT]), Err(Fault::Mem));
    assert_eq!(
        run(&[ldx(BPF_B, BPF_MEM, 0, 10, -513), EXIT]),
        Err(Fault::Mem)
    );
    // Pointer values are offsets, never addresses
    let p = [i(BPF_ALU64 | BPF_MOV | BPF_X, 0, 10, 0, 0), EXIT];
    assert_eq!(run(&p), Ok(BPF_STACK_SIZE as u64));
    // Pointer arithmetic keeps the region
    let p = [
        i(BPF_ALU64 | BPF_MOV | BPF_X, 2, 1, 0, 0),
        i(BPF_ALU64 | BPF_ADD | BPF_K, 2, 0, 0, 8),
        ldx(BPF_B, BPF_MEM, 0, 2, 1),
        EXIT,
    ];
    assert_eq!(run(&p), Ok(9));
    // ... but 32-bit arithmetic does not
    let p = [
        i(BPF_ALU64 | BPF_MOV | BPF_X, 2, 1, 0, 0),
        i(BPF_ALU | BPF_ADD | BPF_K, 2, 0, 0, 8),
        ldx(BPF_B, BPF_MEM, 0, 2, 1),
        EXIT,
    ];
    assert_eq!(run(&p), Err(Fault::Mem));
}

#[test]
fn spills() {
    let ldx = |size: u8, d, s, off| i(BPF_LDX | BPF_MEM | size, d, s, off, 0);
    let spill = i(BPF_STX | BPF_MEM | BPF_DW, 10, 1, -8, 0);
    let fill = ldx(BPF_DW, 2, 10, -8);
    let use_it = ldx(BPF_B, 0, 2, 3);
    assert_eq!(run(&[spill, fill, use_it, EXIT]), Ok(3));
    // Overwriting part of the slot ends the spill
    let clobber = i(BPF_ST | BPF_MEM | BPF_B, 10, 0, -3, 0);
    assert_eq!(run(&[spill, clobber, fill, use_it, EXIT]), Err(Fault::Mem));
    // A 4-byte reload is a scalar
    let half = ldx(BPF_W, 2, 10, -8);
    assert_eq!(run(&[spill, half, use_it, EXIT]), Err(Fault::Mem));
}

#[test]
fn atomics() {
    let st = |v| i(BPF_ST | BPF_MEM | BPF_DW, 10, 0, -8, v);
    let at = |size: u8, imm| i(BPF_STX | BPF_ATOMIC | size, 10, 1, -8, imm);
    let ld = i(BPF_LDX | BPF_MEM | BPF_DW, 0, 10, -8, 0);
    assert_eq!(
        run(&[st(5), mov64(1, 3), at(BPF_DW, BPF_ADD as i32), ld, EXIT]),
        Ok(8)
    );
    // FETCH returns the old value in the source register
    let p = [
        st(5),
        mov64(1, 3),
        at(BPF_DW, BPF_OR as i32 | BPF_FETCH),
        i(BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0),
        EXIT,
    ];
    assert_eq!(run(&p), Ok(5));
    let p = [st(5), mov64(1, 9), at(BPF_DW, BPF_XCHG), ld, EXIT];
    assert_eq!(run(&p), Ok(9));
    // CMPXCHG: stores only on a match, R0 gets the old value
    let p = [
        st(5),
        mov64(0, 5),
        mov64(1, 9),
        at(BPF_DW, BPF_CMPXCHG),
        ld,
        EXIT,
    ];
    assert_eq!(run(&p), Ok(9));
    let p = [
        st(5),
        mov64(0, 4),
        mov64(1, 9),
        at(BPF_DW, BPF_CMPXCHG),
        EXIT,
    ];
    assert_eq!(run(&p), Ok(5));
    // 32-bit atomics truncate; byte atomics do not exist
    let p = [st(-1), mov64(1, 1), at(BPF_W, BPF_ADD as i32), ld, EXIT];
    assert_eq!(run(&p), Ok(0xffff_ffff_0000_0000));
    assert_eq!(
        run(&[st(0), at(BPF_B, BPF_ADD as i32), EXIT]),
        Err(Fault::BadInsn)
    );
}

#[test]
fn calls_and_control() {
    // Helper 7 adds R1 and R2; R1..R5 are clobbered after a call
    let p = [
        mov64(1, 2),
        mov64(2, 3),
        i(BPF_JMP | BPF_CALL, 0, 0, 0, 7),
        i(BPF_ALU64 | BPF_ADD | BPF_X, 0, 1, 0, 0),
        EXIT,
    ];
    assert_eq!(run(&p), Ok(5));
    assert_eq!(
        run(&[i(BPF_JMP | BPF_CALL, 0, 0, 0, 8), EXIT]),
        Err(Fault::Call)
    );
    // A backward loop stops at the step budget
    assert_eq!(run(&[i(BPF_JMP | BPF_JA, 0, 0, -1, 0)]), Err(Fault::Budget));
    // Falling off the end, unknown opcodes, bad registers
    assert_eq!(run(&[mov64(0, 1)]), Err(Fault::BadInsn));
    assert_eq!(run(&[i(0xff, 0, 0, 0, 0), EXIT]), Err(Fault::BadInsn));
    assert_eq!(run(&[mov64(11, 0), EXIT]), Err(Fault::BadInsn));
    // A 64-bit immediate needs its second half
    assert_eq!(run(&[lddw(0, 1)[0]]), Err(Fault::BadInsn));
}

// ============================================================================
// Verifier
// ============================================================================

use super::verifier::{Kind, Verified, verify};
use crate::util::error::KernelError;

const KIND: Kind = Kind {
    ctx_size: 64,
    helpers: &[(7, 2)],
    unreachable_ok: false,
};

fn check(p: &[BpfInsn]) -> Result<Verified, KernelError> {
    verify(p, &KIND, BPF_MAXINSNS)
}

const INVAL: Result<Verified, KernelError> = Err(KernelError::InvalidArgument);
const ACCES: Result<Verified, KernelError> = Err(KernelError::PermissionDenied);

fn ok(p: &[BpfInsn]) -> bool {
    check(p).is_ok()
}

/// R2 = an unknown scalar (a context load)
const LOAD: BpfInsn = i(BPF_LDX | BPF_MEM | BPF_W, 2, 1, 0, 0);

#[test]
fn verifier_shape() {
    assert!(ok(&[mov64(0, 0), EXIT]));
    assert_eq!(check(&[]), INVAL);
    assert_eq!(check(&[mov64(0, 0)]), INVAL); // falls off the end
    assert_eq!(check(&[i(BPF_JMP | BPF_JA, 0, 0, -1, 0), EXIT]), INVAL); // back edge
    assert_eq!(check(&[i(BPF_JMP | BPF_JA, 0, 0, 1, 0), EXIT]), INVAL); // past the end
    assert_eq!(check(&[mov64(0, 0), EXIT, EXIT]), INVAL); // unreachable
    assert_eq!(check(&[i(0xff, 0, 0, 0, 0), EXIT]), INVAL);
    assert_eq!(check(&[mov64(11, 0), EXIT]), INVAL);
    assert_eq!(check(&[mov64(10, 0), mov64(0, 0), EXIT]), INVAL); // R10 is read-only
    let div0 = i(BPF_ALU64 | BPF_DIV | BPF_K, 0, 0, 0, 0);
    assert_eq!(check(&[mov64(0, 1), div0, EXIT]), INVAL);
    let shl = i(BPF_ALU | BPF_LSH | BPF_K, 0, 0, 0, 32);
    assert_eq!(check(&[mov64(0, 1), shl, EXIT]), INVAL);
    assert_eq!(check(&[i(BPF_JMP | BPF_CALL, 0, 0, 0, 8), EXIT]), INVAL);
    // No jump into the second half of a 64-bit immediate
    let mut p = alloc::vec![LOAD, mov64(0, 0), i(BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 1, 0)];
    p.extend(lddw(0, 1));
    p.push(EXIT);
    assert_eq!(check(&p), INVAL);
    p[2].off = 2;
    assert!(ok(&p));
    // A 64-bit immediate needs its second half
    assert_eq!(check(&[lddw(0, 1)[0], EXIT]), INVAL);
}

#[test]
fn verifier_values() {
    // Reads of uninitialized registers and stack
    assert_eq!(check(&[EXIT]), ACCES);
    assert_eq!(
        check(&[i(BPF_ALU64 | BPF_ADD | BPF_K, 0, 0, 0, 1), EXIT]),
        ACCES
    );
    let ld = i(BPF_LDX | BPF_MEM | BPF_W, 0, 10, -4, 0);
    assert_eq!(check(&[ld, EXIT]), ACCES);
    let st = i(BPF_ST | BPF_MEM | BPF_H, 10, 0, -4, 0);
    assert_eq!(check(&[st, ld, EXIT]), ACCES); // two of four bytes written
    let st = i(BPF_ST | BPF_MEM | BPF_W, 10, 0, -4, 0);
    assert!(ok(&[st, ld, EXIT]));
    // Context: in bounds, aligned, read-only
    assert!(ok(&[i(BPF_LDX | BPF_MEM | BPF_DW, 0, 1, 56, 0), EXIT]));
    assert_eq!(
        check(&[i(BPF_LDX | BPF_MEM | BPF_DW, 0, 1, 60, 0), EXIT]),
        ACCES
    );
    assert_eq!(
        check(&[i(BPF_LDX | BPF_MEM | BPF_W, 0, 1, 2, 0), EXIT]),
        ACCES
    );
    let w = i(BPF_ST | BPF_MEM | BPF_W, 1, 0, 0, 0);
    assert_eq!(check(&[w, mov64(0, 0), EXIT]), ACCES);
    // Stack bounds
    let st = |off| i(BPF_ST | BPF_MEM | BPF_B, 10, 0, off, 0);
    assert_eq!(check(&[st(0), mov64(0, 0), EXIT]), ACCES);
    assert_eq!(check(&[st(-513), mov64(0, 0), EXIT]), ACCES);
    assert!(ok(&[st(-512), mov64(0, 0), EXIT]));
    // A pointer never leaves in R0
    let leak = i(BPF_ALU64 | BPF_MOV | BPF_X, 0, 10, 0, 0);
    assert_eq!(check(&[leak, EXIT]), ACCES);
    // Pointer arithmetic: constant offsets in 64 bits only
    let p = |op: BpfInsn| {
        [
            i(BPF_ALU64 | BPF_MOV | BPF_X, 3, 1, 0, 0),
            LOAD,
            op,
            mov64(0, 0),
            EXIT,
        ]
    };
    assert!(ok(&p(i(BPF_ALU64 | BPF_ADD | BPF_K, 3, 0, 0, 8))));
    assert_eq!(check(&p(i(BPF_ALU64 | BPF_ADD | BPF_X, 3, 2, 0, 0))), ACCES);
    assert_eq!(check(&p(i(BPF_ALU | BPF_ADD | BPF_K, 3, 0, 0, 8))), ACCES);
    assert_eq!(check(&p(i(BPF_ALU64 | BPF_MUL | BPF_K, 3, 0, 0, 2))), ACCES);
    assert_eq!(check(&p(i(BPF_ALU | BPF_MOV | BPF_X, 3, 1, 0, 0))), ACCES);
    // ... and the moved pointer is bounds-checked at its new offset
    let p = [
        i(BPF_ALU64 | BPF_MOV | BPF_X, 3, 1, 0, 0),
        i(BPF_ALU64 | BPF_ADD | BPF_K, 3, 0, 0, 60),
        i(BPF_LDX | BPF_MEM | BPF_W, 0, 3, 0, 0),
        EXIT,
    ];
    assert!(ok(&p));
    let mut q = p;
    q[1].imm = 64;
    assert_eq!(check(&q), ACCES);
    // A spilled pointer comes back whole; a partial spill is refused
    let p = [
        i(BPF_STX | BPF_MEM | BPF_DW, 10, 1, -8, 0),
        i(BPF_LDX | BPF_MEM | BPF_DW, 3, 10, -8, 0),
        i(BPF_LDX | BPF_MEM | BPF_W, 0, 3, 4, 0),
        EXIT,
    ];
    assert!(ok(&p));
    let half = i(BPF_STX | BPF_MEM | BPF_W, 10, 1, -8, 0);
    assert_eq!(check(&[half, mov64(0, 0), EXIT]), ACCES);
    // Helpers: scalar arguments; R1..R5 are dead after the call
    let call = i(BPF_JMP | BPF_CALL, 0, 0, 0, 7);
    assert!(ok(&[mov64(1, 1), mov64(2, 2), call, EXIT]));
    assert_eq!(check(&[mov64(2, 2), call, EXIT]), ACCES); // R1 is the ctx
    let use_r1 = i(BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 0, 0);
    assert_eq!(
        check(&[mov64(1, 1), mov64(2, 2), call, use_r1, EXIT]),
        ACCES
    );
}

/// Both sides of every branch are checked; constants decide branches
#[test]
fn verifier_paths() {
    // The bad path is only on one side
    let p = [
        LOAD,
        i(BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 1, 0),
        mov64(0, 0),
        EXIT,
    ];
    assert_eq!(check(&p), ACCES);
    // A constant comparison never takes the bad side
    let p = [
        mov64(2, 5),
        i(BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 1, 5),
        EXIT,
        mov64(0, 0),
        EXIT,
    ];
    assert!(ok(&p));
}

/// 2000 branches in a row: no recursion, and pruning keeps it linear
#[test]
fn verifier_deep() {
    let mut p = alloc::vec![LOAD, mov64(0, 0)];
    for _ in 0..2000 {
        p.push(i(BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 1, 1));
        p.push(mov64(3, 1));
    }
    p.push(EXIT);
    assert_eq!(check(&p), Ok(Verified::default()));
}

/// 2^n distinct states: E2BIG at the complexity limit, not a hang
#[test]
fn verifier_explosion() {
    let mut p = alloc::vec![LOAD, mov64(0, 0), mov64(4, 0)];
    for _ in 0..40 {
        p.push(i(BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 1, 1));
        p.push(i(BPF_ALU64 | BPF_ADD | BPF_K, 4, 0, 0, 1));
        p.push(i(BPF_ALU64 | BPF_LSH | BPF_K, 4, 0, 0, 1));
    }
    p.push(EXIT);
    assert_eq!(check(&p), Err(KernelError::ArgListTooLong));
}

// ============================================================================
// Classic BPF: convert-then-eBPF against the classic interpreter
// ============================================================================

use super::classic::{self as cl, Insn as CInsn};
use super::convert;

/// xorshift64*: deterministic test randomness
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    /// A constant from the interesting ones, or random
    fn k(&mut self) -> u32 {
        const K: [u32; 8] = [
            0,
            1,
            2,
            31,
            0x7fff_ffff,
            0x8000_0000,
            0xc000_003e,
            0xffff_ffff,
        ];
        if self.below(2) == 0 {
            K[self.below(8) as usize]
        } else {
            self.next() as u32
        }
    }
}

/// A packet and ancillary values (classic Env)
struct Pkt {
    data: alloc::vec::Vec<u8>,
    salt: u32,
}

impl cl::Env for Pkt {
    fn pkt_len(&self) -> u32 {
        self.data.len() as u32
    }
    fn load(&self, off: i32, size: usize) -> Option<u32> {
        let o = if off >= 0 {
            off as usize
        } else if off >= cl::SKF_LL_OFF && off < cl::SKF_NET_OFF {
            (off - cl::SKF_LL_OFF) as usize
        } else {
            return None;
        };
        let b = self.data.get(o..o.checked_add(size)?)?;
        Some(b.iter().fold(0u32, |v, &b| (v << 8) | b as u32))
    }
    fn anc(&self, ad: u32) -> u32 {
        ad.wrapping_mul(0x9e37_79b9) ^ self.salt
    }
}

/// seccomp_data-like words (classic Env, LDX_W_ABS)
struct Words([u8; 64]);

impl cl::Env for Words {
    fn word(&self, k: u32) -> Option<u32> {
        let k = k as usize;
        let w = self.0.get(k..k + 4)?;
        Some(u32::from_ne_bytes([w[0], w[1], w[2], w[3]]))
    }
}

const fn c(code: u16, jt: u8, jf: u8, k: u32) -> CInsn {
    CInsn { code, jt, jf, k }
}

/// One random body instruction at `pc` of `len` (`sc`: seccomp's subset)
fn gen_insn(r: &mut Rng, pc: usize, len: usize, sc: bool) -> CInsn {
    use cl::*;
    let left = (len - pc - 1) as u64; // instructions after this one
    let jt = |r: &mut Rng| r.below(left.min(255)) as u8;
    loop {
        let f = match r.below(14) {
            0 | 1 => {
                let ops = [ADD, SUB, MUL, DIV, OR, AND, LSH, RSH, XOR, MOD, NEG];
                let op = ops[r.below(if sc { 9 } else { 11 }) as usize];
                let x = r.below(2) == 1;
                let mut k = r.k();
                if !x && (op == LSH || op == RSH) {
                    k %= 32;
                }
                if !x && (op == DIV || op == MOD) && k == 0 {
                    k = 3;
                }
                let src = if x && op != NEG { X } else { K };
                c(ALU | op | src, 0, 0, k)
            }
            2 => c(LD | IMM, 0, 0, r.k()),
            3 => c(LDX | IMM, 0, 0, r.k()),
            4 => c(
                if r.below(2) == 0 { LD | MEM } else { LDX | MEM },
                0,
                0,
                r.below(16) as u32,
            ),
            5 => c(
                if r.below(2) == 0 { ST } else { STX },
                0,
                0,
                r.below(16) as u32,
            ),
            6 => c(MISC | if r.below(2) == 0 { TAX } else { TXA }, 0, 0, 0),
            7 if sc => c(LD | W | ABS, 0, 0, 4 * r.below(16) as u32),
            7 => {
                let size = [W, H, B][r.below(3) as usize];
                let k = match r.below(4) {
                    0 => (SKF_AD_OFF as u32).wrapping_add(4 * r.below(16) as u32),
                    1 => (SKF_LL_OFF as u32).wrapping_add(r.below(40) as u32),
                    _ => r.below(48) as u32,
                };
                c(LD | size | ABS, 0, 0, k)
            }
            8 if !sc => c(
                LD | [W, H, B][r.below(3) as usize] | IND,
                0,
                0,
                r.below(48) as u32,
            ),
            9 if !sc => c(LDX | B | MSH, 0, 0, r.below(48) as u32),
            10 => c(
                if r.below(2) == 0 {
                    LD | W | LEN
                } else {
                    LDX | W | LEN
                },
                0,
                0,
                0,
            ),
            11 | 12 if left > 0 => {
                let op = [JEQ, JGT, JGE, JSET][r.below(4) as usize];
                let src = if r.below(3) == 0 { X } else { K };
                c(JMP | op | src, jt(r), jt(r), r.k())
            }
            13 if left > 0 => c(JMP | JA, 0, 0, r.below(left) as u32),
            13 => c(RET | if r.below(2) == 0 { A } else { K }, 0, 0, r.k()),
            _ => continue,
        };
        return f;
    }
}

/// A random program that passes classic::check: all of M[] stored
/// first, then a random body, then a RET
fn gen_prog(r: &mut Rng, sc: bool) -> alloc::vec::Vec<CInsn> {
    use cl::*;
    let body = 1 + r.below(120) as usize;
    let mut p = alloc::vec::Vec::new();
    for m in 0..16 {
        p.push(c(LD | IMM, 0, 0, r.k()));
        p.push(c(ST, 0, 0, m));
    }
    let len = p.len() + body + 1;
    for pc in p.len()..len - 1 {
        p.push(gen_insn(r, pc, len, sc));
    }
    p.push(c(RET | A, 0, 0, 0));
    p
}

/// seccomp's load rewrite (as seccomp_check_filter does)
fn seccomp_rewrite(p: &mut [CInsn]) {
    for f in p {
        if f.code == cl::LD | cl::W | cl::ABS {
            f.code = cl::LDX_W_ABS;
        } else if f.code == cl::LD | cl::W | cl::LEN {
            *f = c(cl::LD | cl::IMM, 0, 0, 64);
        } else if f.code == cl::LDX | cl::W | cl::LEN {
            *f = c(cl::LDX | cl::IMM, 0, 0, 64);
        }
    }
}

#[test]
fn differential_socket() {
    let mut r = Rng(0x1234_5678_9abc_def1);
    for _ in 0..3000 {
        let p = gen_prog(&mut r, false);
        cl::check(&p).unwrap();
        let e = convert::convert(&p, &convert::SOCKET).unwrap();
        assert!(super::verifier::verify(&e, &convert::SOCKET, usize::MAX).is_ok());
        for _ in 0..4 {
            let n = r.below(48) as usize;
            let data = (0..n).map(|_| r.next() as u8).collect();
            let env = Pkt {
                data,
                salt: r.next() as u32,
            };
            assert_eq!(cl::run(&p, &env), convert::run(&e, &[], &env), "{p:?}");
        }
    }
}

#[test]
fn differential_seccomp() {
    let mut r = Rng(0xfeed_face_cafe_beef);
    for _ in 0..3000 {
        let mut p = gen_prog(&mut r, true);
        cl::check(&p).unwrap();
        seccomp_rewrite(&mut p);
        let e = convert::convert(&p, &convert::SECCOMP).unwrap();
        assert!(super::verifier::verify(&e, &convert::SECCOMP, usize::MAX).is_ok());
        for _ in 0..4 {
            let mut w = [0u8; 64];
            for b in &mut w {
                *b = r.next() as u8;
            }
            let env = Words(w);
            assert_eq!(cl::run(&p, &env), convert::run(&e, &w, &env), "{p:?}");
        }
    }
}

/// Linux's encoding: the lengths seccomp's path limit counts
#[test]
fn convert_lengths() {
    use cl::*;
    let len = |p: &[CInsn]| convert::convert(p, &convert::SECCOMP).unwrap().len();
    // Prologue 3; RET K is two instructions; RET A one
    assert_eq!(len(&[c(RET | K, 0, 0, 0)]), 5);
    assert_eq!(len(&[c(RET | A, 0, 0, 0)]), 4);
    // jf = 0: one jump; jt = 0 (JEQ): one inverted jump; else two
    let j = |jt, jf, k| {
        [
            c(JMP | JEQ | K, jt, jf, k),
            c(RET | A, 0, 0, 0),
            c(RET | A, 0, 0, 0),
        ]
    };
    assert_eq!(len(&j(1, 0, 5)), 3 + 1 + 2);
    assert_eq!(len(&j(0, 1, 5)), 3 + 1 + 2);
    assert_eq!(len(&j(0, 0, 5)), 3 + 1 + 2);
    // A constant >= 2^31 goes through a register first
    assert_eq!(len(&j(1, 0, 0xc000_003e)), 3 + 2 + 2);
    // Division by X checks for zero
    assert_eq!(
        len(&[c(ALU | DIV | X, 0, 0, 0), c(RET | A, 0, 0, 0)]),
        3 + 5 + 1
    );
}

/// Unreachable classic code is legal (Linux accepts it)
#[test]
fn convert_unreachable() {
    use cl::*;
    let p = [
        c(RET | K, 0, 0, 1),
        c(LD | IMM, 0, 0, 2),
        c(RET | A, 0, 0, 0),
    ];
    cl::check(&p).unwrap();
    let e = convert::convert(&p, &convert::SECCOMP).unwrap();
    assert_eq!(convert::run(&e, &[0; 64], &Words([0; 64])), 1);
}

/// busybox udhcpc's socket filter, converted
#[test]
fn convert_udhcpc() {
    use cl::*;
    let p = [
        c(LD | B | ABS, 0, 0, 9),
        c(JMP | JEQ | K, 0, 6, 17),
        c(LD | H | ABS, 0, 0, 6),
        c(JMP | JSET | K, 4, 0, 0x1fff),
        c(LDX | B | MSH, 0, 0, 0),
        c(LD | H | IND, 0, 0, 2),
        c(JMP | JEQ | K, 0, 1, 68),
        c(RET | K, 0, 0, 0x7fff_ffff),
        c(RET | K, 0, 0, 0),
    ];
    let e = convert::convert(&p, &convert::SOCKET).unwrap();
    let pkt = |dport: u16, frag: u16, n: usize| {
        let mut d = alloc::vec![0u8; 28];
        d[0] = 0x45;
        d[6..8].copy_from_slice(&frag.to_be_bytes());
        d[9] = 17;
        d[22..24].copy_from_slice(&dport.to_be_bytes());
        d.truncate(n);
        Pkt { data: d, salt: 0 }
    };
    assert_eq!(convert::run(&e, &[], &pkt(68, 0, 28)), 0x7fff_ffff);
    assert_eq!(convert::run(&e, &[], &pkt(67, 0, 28)), 0);
    assert_eq!(convert::run(&e, &[], &pkt(68, 1, 28)), 0);
    assert_eq!(convert::run(&e, &[], &pkt(68, 0, 21)), 0);
}
