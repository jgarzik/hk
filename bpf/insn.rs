//! eBPF instruction types and opcodes
//!
//! This module defines the eBPF instruction format and all opcodes
//! following the Linux eBPF specification.

/// eBPF instruction (8 bytes)
///
/// This is the native eBPF instruction format used internally.
/// Classic BPF (sock_filter) is converted to this format.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BpfInsn {
    /// Opcode (operation + source + class)
    pub code: u8,
    /// Destination register (low 4 bits) and source register (high 4 bits)
    pub regs: u8,
    /// Signed offset for memory/jump operations
    pub off: i16,
    /// Signed immediate constant
    pub imm: i32,
}

impl BpfInsn {
    /// Create a new eBPF instruction
    pub const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            regs: (src << 4) | (dst & 0x0f),
            off,
            imm,
        }
    }

    /// Get destination register number (0-10)
    #[inline]
    pub fn dst_reg(&self) -> u8 {
        self.regs & 0x0f
    }

    /// Get source register number (0-10)
    #[inline]
    pub fn src_reg(&self) -> u8 {
        self.regs >> 4
    }
}

// =============================================================================
// Instruction Classes (bits 0-2)
// =============================================================================

/// Load to register (LD)
pub const BPF_LD: u8 = 0x00;
/// Load to index register (LDX)
pub const BPF_LDX: u8 = 0x01;
/// Store from register (ST)
pub const BPF_ST: u8 = 0x02;
/// Store from index register (STX)
pub const BPF_STX: u8 = 0x03;
/// 32-bit ALU operations
pub const BPF_ALU: u8 = 0x04;
/// 64-bit jump operations
pub const BPF_JMP: u8 = 0x05;
/// 32-bit jump operations (eBPF extension)
pub const BPF_JMP32: u8 = 0x06;
/// 64-bit ALU operations (eBPF extension)
pub const BPF_ALU64: u8 = 0x07;

// =============================================================================
// Size Modifiers (bits 3-4, for LD/LDX/ST/STX)
// =============================================================================

/// 32-bit word
pub const BPF_W: u8 = 0x00;
/// 16-bit halfword
pub const BPF_H: u8 = 0x08;
/// 8-bit byte
pub const BPF_B: u8 = 0x10;
/// 64-bit doubleword (eBPF extension)
pub const BPF_DW: u8 = 0x18;

// =============================================================================
// Mode Modifiers (bits 5-7, for LD/LDX)
// =============================================================================

/// Immediate value
pub const BPF_IMM: u8 = 0x00;
/// Absolute offset (cBPF: offset from packet start)
pub const BPF_ABS: u8 = 0x20;
/// Indirect offset (cBPF: offset from X register)
pub const BPF_IND: u8 = 0x40;
/// Memory (register + offset)
pub const BPF_MEM: u8 = 0x60;
/// Atomic memory operations (eBPF extension)
pub const BPF_ATOMIC: u8 = 0xc0;

// =============================================================================
// ALU/JMP Operation Codes (bits 4-7)
// =============================================================================

/// Add: dst += src
pub const BPF_ADD: u8 = 0x00;
/// Subtract: dst -= src
pub const BPF_SUB: u8 = 0x10;
/// Multiply: dst *= src
pub const BPF_MUL: u8 = 0x20;
/// Divide: dst /= src
pub const BPF_DIV: u8 = 0x30;
/// Or: dst |= src
pub const BPF_OR: u8 = 0x40;
/// And: dst &= src
pub const BPF_AND: u8 = 0x50;
/// Left shift: dst <<= src
pub const BPF_LSH: u8 = 0x60;
/// Right shift (logical): dst >>= src
pub const BPF_RSH: u8 = 0x70;
/// Negate: dst = -dst
pub const BPF_NEG: u8 = 0x80;
/// Modulo: dst %= src
pub const BPF_MOD: u8 = 0x90;
/// Xor: dst ^= src
pub const BPF_XOR: u8 = 0xa0;
/// Move: dst = src (eBPF extension)
pub const BPF_MOV: u8 = 0xb0;
/// Arithmetic right shift: dst >>= src (signed, eBPF extension)
pub const BPF_ARSH: u8 = 0xc0;
/// Endianness conversion (eBPF extension)
pub const BPF_END: u8 = 0xd0;

// =============================================================================
// Jump Operation Codes (bits 4-7, for BPF_JMP/BPF_JMP32)
// =============================================================================

/// Jump always (unconditional)
pub const BPF_JA: u8 = 0x00;
/// Jump if equal: if dst == src
pub const BPF_JEQ: u8 = 0x10;
/// Jump if greater than (unsigned): if dst > src
pub const BPF_JGT: u8 = 0x20;
/// Jump if greater or equal (unsigned): if dst >= src
pub const BPF_JGE: u8 = 0x30;
/// Jump if bits set: if dst & src
pub const BPF_JSET: u8 = 0x40;
/// Jump if not equal: if dst != src (eBPF extension)
pub const BPF_JNE: u8 = 0x50;
/// Jump if signed greater than: if (s64)dst > (s64)src (eBPF extension)
pub const BPF_JSGT: u8 = 0x60;
/// Jump if signed greater or equal: if (s64)dst >= (s64)src (eBPF extension)
pub const BPF_JSGE: u8 = 0x70;
/// Call helper function (eBPF extension)
pub const BPF_CALL: u8 = 0x80;
/// Exit program, return R0 (eBPF extension)
pub const BPF_EXIT: u8 = 0x90;
/// Jump if less than (unsigned): if dst < src (eBPF extension)
pub const BPF_JLT: u8 = 0xa0;
/// Jump if less or equal (unsigned): if dst <= src (eBPF extension)
pub const BPF_JLE: u8 = 0xb0;
/// Jump if signed less than: if (s64)dst < (s64)src (eBPF extension)
pub const BPF_JSLT: u8 = 0xc0;
/// Jump if signed less or equal: if (s64)dst <= (s64)src (eBPF extension)
pub const BPF_JSLE: u8 = 0xd0;

// =============================================================================
// Source Modifiers (bit 3, for ALU/JMP)
// =============================================================================

/// Use immediate value as source
pub const BPF_K: u8 = 0x00;
/// Use source register as source
pub const BPF_X: u8 = 0x08;

// =============================================================================
// Register Numbers
// =============================================================================

/// Return value register
pub const BPF_REG_0: u8 = 0;
/// Argument 1 / context pointer
pub const BPF_REG_1: u8 = 1;
/// Argument 2
pub const BPF_REG_2: u8 = 2;
/// Argument 3
pub const BPF_REG_3: u8 = 3;
/// Argument 4
pub const BPF_REG_4: u8 = 4;
/// Argument 5
pub const BPF_REG_5: u8 = 5;
/// Callee-saved register
pub const BPF_REG_6: u8 = 6;
/// Callee-saved register (cBPF X maps here)
pub const BPF_REG_7: u8 = 7;
/// Callee-saved register
pub const BPF_REG_8: u8 = 8;
/// Callee-saved register
pub const BPF_REG_9: u8 = 9;
/// Frame pointer (read-only, points to stack)
pub const BPF_REG_10: u8 = 10;
/// Number of registers
pub const MAX_BPF_REG: usize = 11;

// =============================================================================
// Misc Constants
// =============================================================================

/// Maximum number of instructions in a BPF program
pub const BPF_MAXINSNS: usize = 4096;

/// Size of BPF stack in bytes
pub const BPF_STACK_SIZE: usize = 512;

/// Number of scratch memory words (cBPF)
pub const BPF_MEMWORDS: usize = 16;

// =============================================================================
// Helper macros for instruction construction
// =============================================================================

/// Extract instruction class (bits 0-2)
#[inline]
pub const fn bpf_class(code: u8) -> u8 {
    code & 0x07
}

/// Extract size modifier (bits 3-4)
#[inline]
pub const fn bpf_size(code: u8) -> u8 {
    code & 0x18
}

/// Extract mode modifier (bits 5-7)
#[inline]
pub const fn bpf_mode(code: u8) -> u8 {
    code & 0xe0
}

/// Extract ALU/JMP operation (bits 4-7)
#[inline]
pub const fn bpf_op(code: u8) -> u8 {
    code & 0xf0
}

/// Extract source modifier (bit 3)
#[inline]
pub const fn bpf_src(code: u8) -> u8 {
    code & 0x08
}

// =============================================================================
// Classic BPF compatibility (for cBPF-to-eBPF conversion)
// =============================================================================

/// cBPF: Return instruction class
pub const CBPF_RET: u8 = 0x06;
/// cBPF: Misc instruction class
pub const CBPF_MISC: u8 = 0x07;
/// cBPF: TAX (A -> X)
pub const CBPF_TAX: u8 = 0x00;
/// cBPF: TXA (X -> A)
pub const CBPF_TXA: u8 = 0x80;
/// cBPF: Return accumulator
pub const CBPF_RETA: u8 = 0x10;
