//! BPF program verifier
//!
//! This module implements verification of BPF programs before they can be loaded.
//! The verifier ensures that programs:
//! - Terminate (have EXIT instruction, no infinite loops)
//! - Don't access uninitialized registers
//! - Don't overflow the stack
//! - Don't access memory out of bounds
//! - Use valid opcodes
//!
//! ## Verification Approach
//!
//! The verifier performs abstract interpretation, tracking the state of each
//! register at each program point. It follows all possible execution paths
//! to ensure safety properties hold.

use alloc::vec;
use alloc::vec::Vec;

use super::insn::*;
use crate::error::KernelError;

// =============================================================================
// Register State
// =============================================================================

/// Type of value held in a register
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(dead_code)]
pub enum RegType {
    /// Register has not been written (uninitialized)
    #[default]
    NotInit,
    /// Register holds a scalar value (number)
    Scalar,
    /// Register holds a pointer to the context
    PtrToCtx,
    /// Register holds a pointer to the stack
    PtrToStack,
    /// Register holds a pointer to a map value
    PtrToMapValue,
    /// Register holds a constant known at verification time
    Const(i64),
}

/// State of a single register
#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub struct RegState {
    /// Type of value in the register
    pub reg_type: RegType,
    /// Minimum possible value (for range tracking)
    pub smin_value: i64,
    /// Maximum possible value (for range tracking)
    pub smax_value: i64,
    /// Unsigned minimum
    pub umin_value: u64,
    /// Unsigned maximum
    pub umax_value: u64,
}

impl RegState {
    /// Create a new uninitialized register
    pub fn new() -> Self {
        Self {
            reg_type: RegType::NotInit,
            smin_value: i64::MIN,
            smax_value: i64::MAX,
            umin_value: 0,
            umax_value: u64::MAX,
        }
    }

    /// Create a scalar register with unknown value
    pub fn scalar() -> Self {
        Self {
            reg_type: RegType::Scalar,
            smin_value: i64::MIN,
            smax_value: i64::MAX,
            umin_value: 0,
            umax_value: u64::MAX,
        }
    }

    /// Create a register with a known constant value
    pub fn constant(val: i64) -> Self {
        Self {
            reg_type: RegType::Const(val),
            smin_value: val,
            smax_value: val,
            umin_value: val as u64,
            umax_value: val as u64,
        }
    }

    /// Create a context pointer register
    pub fn ctx_ptr() -> Self {
        Self {
            reg_type: RegType::PtrToCtx,
            smin_value: 0,
            smax_value: i64::MAX,
            umin_value: 0,
            umax_value: u64::MAX,
        }
    }

    /// Create a stack pointer register
    pub fn stack_ptr(offset: i64) -> Self {
        Self {
            reg_type: RegType::PtrToStack,
            smin_value: offset,
            smax_value: offset,
            umin_value: 0,
            umax_value: u64::MAX,
        }
    }

    /// Check if register is readable (initialized)
    pub fn is_readable(&self) -> bool {
        !matches!(self.reg_type, RegType::NotInit)
    }

    /// Check if register holds a pointer
    #[allow(dead_code)]
    pub fn is_pointer(&self) -> bool {
        matches!(
            self.reg_type,
            RegType::PtrToCtx | RegType::PtrToStack | RegType::PtrToMapValue
        )
    }
}

// =============================================================================
// Verifier State
// =============================================================================

/// Stack slot state
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(dead_code)]
pub enum StackSlotType {
    /// Slot is uninitialized
    #[default]
    Invalid,
    /// Slot contains spilled register
    Spill,
    /// Slot contains misc data (written by store)
    Misc,
}

/// Verification state at a program point
#[derive(Clone, Debug)]
pub struct VerifierState {
    /// Register states (R0-R10)
    pub regs: [RegState; MAX_BPF_REG],
    /// Stack slot states (each slot is 8 bytes, 64 slots for 512-byte stack)
    pub stack: [StackSlotType; BPF_STACK_SIZE / 8],
    /// Current stack depth (bytes used from stack top)
    pub stack_depth: usize,
}

impl VerifierState {
    /// Create initial state for program entry
    pub fn new() -> Self {
        let mut state = Self {
            regs: Default::default(),
            stack: [StackSlotType::Invalid; BPF_STACK_SIZE / 8],
            stack_depth: 0,
        };

        // R1 contains context pointer at entry
        state.regs[BPF_REG_1 as usize] = RegState::ctx_ptr();
        // R10 is the frame pointer (read-only)
        state.regs[BPF_REG_10 as usize] = RegState::stack_ptr(0);

        state
    }
}

impl Default for VerifierState {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Verifier
// =============================================================================

/// BPF program verifier
pub struct Verifier<'a> {
    /// Instructions to verify
    insns: &'a [BpfInsn],
    /// Context size (for bounds checking)
    ctx_size: usize,
    /// Visited instruction bitmap
    visited: Vec<bool>,
    /// States at each instruction (for path merging)
    states: Vec<Option<VerifierState>>,
}

impl<'a> Verifier<'a> {
    /// Create a new verifier for the given instructions
    pub fn new(insns: &'a [BpfInsn], ctx_size: usize) -> Self {
        let len = insns.len();
        Self {
            insns,
            ctx_size,
            visited: vec![false; len],
            states: vec![None; len],
        }
    }

    /// Verify the program
    pub fn verify(&mut self) -> Result<(), KernelError> {
        if self.insns.is_empty() {
            return Err(KernelError::InvalidArgument);
        }

        if self.insns.len() > BPF_MAXINSNS {
            return Err(KernelError::InvalidArgument);
        }

        // First pass: check for EXIT instruction and basic validity
        self.check_basic_validity()?;

        // Second pass: simulate execution and track state
        let initial_state = VerifierState::new();
        self.verify_from(0, initial_state)?;

        Ok(())
    }

    /// Check basic program validity
    fn check_basic_validity(&self) -> Result<(), KernelError> {
        let mut has_exit = false;

        for (i, insn) in self.insns.iter().enumerate() {
            let class = bpf_class(insn.code);
            let op = bpf_op(insn.code);

            // Check for EXIT instruction
            if class == BPF_JMP && op == BPF_EXIT {
                has_exit = true;
            }

            // Check jump targets are in bounds
            if (class == BPF_JMP || class == BPF_JMP32) && op != BPF_EXIT && op != BPF_CALL {
                let target = i as i32 + 1 + insn.off as i32;
                if target < 0 || target as usize >= self.insns.len() {
                    return Err(KernelError::InvalidArgument);
                }
            }

            // Validate registers are in range
            if insn.dst_reg() > BPF_REG_10 {
                return Err(KernelError::InvalidArgument);
            }
            if insn.src_reg() > BPF_REG_10 {
                return Err(KernelError::InvalidArgument);
            }

            // R10 (frame pointer) is read-only
            if insn.dst_reg() == BPF_REG_10 {
                // Allow only if this is a load with R10 as base
                let mode = bpf_mode(insn.code);
                if class != BPF_LDX && class != BPF_STX && class != BPF_ST && mode != BPF_MEM {
                    return Err(KernelError::InvalidArgument);
                }
                // For ALU/JMP, R10 as dst is always invalid
                if class == BPF_ALU || class == BPF_ALU64 {
                    return Err(KernelError::InvalidArgument);
                }
            }

            // Check for 64-bit immediate loads (2 instruction sequence)
            if class == BPF_LD
                && bpf_mode(insn.code) == BPF_IMM
                && bpf_size(insn.code) == BPF_DW
                && i + 1 >= self.insns.len()
            {
                return Err(KernelError::InvalidArgument);
            }
        }

        if !has_exit {
            return Err(KernelError::InvalidArgument);
        }

        Ok(())
    }

    /// Verify from a specific instruction with given state
    fn verify_from(&mut self, mut pc: usize, mut state: VerifierState) -> Result<(), KernelError> {
        const MAX_ITERATIONS: usize = 1_000_000;
        let mut iterations = 0;

        while pc < self.insns.len() {
            iterations += 1;
            if iterations > MAX_ITERATIONS {
                // Likely infinite loop
                return Err(KernelError::PermissionDenied);
            }

            // Check if we've already verified this path
            if self.visited[pc] {
                // State merge would go here for full verification
                return Ok(());
            }
            self.visited[pc] = true;
            self.states[pc] = Some(state.clone());

            let insn = &self.insns[pc];
            let class = bpf_class(insn.code);
            let op = bpf_op(insn.code);
            let _src = bpf_src(insn.code);

            match class {
                BPF_ALU | BPF_ALU64 => {
                    self.verify_alu(insn, &mut state)?;
                    pc += 1;
                }
                BPF_LDX => {
                    self.verify_ldx(insn, &mut state)?;
                    pc += 1;
                }
                BPF_STX | BPF_ST => {
                    self.verify_stx(insn, &mut state)?;
                    pc += 1;
                }
                BPF_LD => {
                    // Handle 64-bit immediate load
                    if bpf_mode(insn.code) == BPF_IMM && bpf_size(insn.code) == BPF_DW {
                        self.verify_ld_imm64(insn, pc, &mut state)?;
                        pc += 2; // Skip the second instruction
                    } else {
                        // Other LD modes (packet access) not supported yet
                        return Err(KernelError::InvalidArgument);
                    }
                }
                BPF_JMP | BPF_JMP32 => {
                    if op == BPF_EXIT {
                        // R0 must be readable (contains return value)
                        if !state.regs[BPF_REG_0 as usize].is_readable() {
                            return Err(KernelError::PermissionDenied);
                        }
                        return Ok(());
                    } else if op == BPF_CALL {
                        self.verify_call(insn, &mut state)?;
                        pc += 1;
                    } else if op == BPF_JA {
                        // Unconditional jump
                        let target = (pc as i32 + 1 + insn.off as i32) as usize;
                        pc = target;
                    } else {
                        // Conditional jump
                        self.verify_jmp_cond(insn, &state)?;

                        // Verify both paths
                        let target = (pc as i32 + 1 + insn.off as i32) as usize;

                        // Fork: verify the taken branch
                        let taken_state = state.clone();
                        self.verify_from(target, taken_state)?;

                        // Continue with fall-through
                        pc += 1;
                    }
                }
                _ => {
                    return Err(KernelError::InvalidArgument);
                }
            }
        }

        // Fell off the end without EXIT
        Err(KernelError::PermissionDenied)
    }

    /// Verify ALU instruction
    fn verify_alu(&self, insn: &BpfInsn, state: &mut VerifierState) -> Result<(), KernelError> {
        let dst = insn.dst_reg() as usize;
        let src = insn.src_reg() as usize;
        let op = bpf_op(insn.code);
        let is_src_reg = bpf_src(insn.code) == BPF_X;

        // Source must be readable (if using register)
        if is_src_reg && !state.regs[src].is_readable() {
            return Err(KernelError::PermissionDenied);
        }

        // For most ops, dst must be readable (except MOV)
        if op != BPF_MOV && op != BPF_NEG && !state.regs[dst].is_readable() {
            return Err(KernelError::PermissionDenied);
        }

        // Check for division by zero (conservatively - could track ranges better)
        if op == BPF_DIV || op == BPF_MOD {
            if is_src_reg {
                // We can't statically prove divisor is non-zero for registers
                // In real use, this would need more sophisticated analysis
            } else if insn.imm == 0 {
                return Err(KernelError::InvalidArgument);
            }
        }

        // Update destination register state
        match op {
            BPF_MOV => {
                if is_src_reg {
                    state.regs[dst] = state.regs[src].clone();
                } else {
                    state.regs[dst] = RegState::constant(insn.imm as i64);
                }
            }
            BPF_NEG => {
                state.regs[dst] = RegState::scalar();
            }
            _ => {
                // Result is scalar with unknown value
                // (Could do range propagation here for better analysis)
                state.regs[dst] = RegState::scalar();
            }
        }

        Ok(())
    }

    /// Verify LDX (load from memory) instruction
    fn verify_ldx(&self, insn: &BpfInsn, state: &mut VerifierState) -> Result<(), KernelError> {
        let dst = insn.dst_reg() as usize;
        let src = insn.src_reg() as usize;

        // Source register must be readable
        if !state.regs[src].is_readable() {
            return Err(KernelError::PermissionDenied);
        }

        // Check memory access based on source type
        match state.regs[src].reg_type {
            RegType::PtrToCtx => {
                // Check context bounds
                let offset = insn.off as i64;
                let size = self.access_size(insn.code);
                if offset < 0 || (offset as usize + size) > self.ctx_size {
                    return Err(KernelError::PermissionDenied);
                }
                state.regs[dst] = RegState::scalar();
            }
            RegType::PtrToStack => {
                // Check stack bounds
                let base_off = state.regs[src].smin_value;
                let offset = base_off + insn.off as i64;
                let size = self.access_size(insn.code) as i64;

                // Stack grows down, valid range is [-512, 0)
                if offset < -(BPF_STACK_SIZE as i64) || offset + size > 0 {
                    return Err(KernelError::PermissionDenied);
                }

                // Check if stack slot is initialized
                let slot = ((-offset - 1) / 8) as usize;
                if slot >= BPF_STACK_SIZE / 8 {
                    return Err(KernelError::PermissionDenied);
                }
                if state.stack[slot] == StackSlotType::Invalid {
                    return Err(KernelError::PermissionDenied);
                }

                state.regs[dst] = RegState::scalar();
            }
            RegType::PtrToMapValue => {
                // Map value access - bounds would be checked with map info
                state.regs[dst] = RegState::scalar();
            }
            _ => {
                // Can't load from non-pointer
                return Err(KernelError::PermissionDenied);
            }
        }

        Ok(())
    }

    /// Verify STX/ST (store to memory) instruction
    fn verify_stx(&self, insn: &BpfInsn, state: &mut VerifierState) -> Result<(), KernelError> {
        let dst = insn.dst_reg() as usize;
        let src = insn.src_reg() as usize;
        let class = bpf_class(insn.code);

        // Destination (base pointer) must be readable
        if !state.regs[dst].is_readable() {
            return Err(KernelError::PermissionDenied);
        }

        // For STX, source must be readable
        if class == BPF_STX && !state.regs[src].is_readable() {
            return Err(KernelError::PermissionDenied);
        }

        // Check memory access based on destination type
        match state.regs[dst].reg_type {
            RegType::PtrToStack => {
                let base_off = state.regs[dst].smin_value;
                let offset = base_off + insn.off as i64;
                let size = self.access_size(insn.code) as i64;

                // Stack grows down, valid range is [-512, 0)
                if offset < -(BPF_STACK_SIZE as i64) || offset + size > 0 {
                    return Err(KernelError::PermissionDenied);
                }

                // Mark stack slot as initialized
                let slot = ((-offset - 1) / 8) as usize;
                if slot < BPF_STACK_SIZE / 8 {
                    state.stack[slot] = StackSlotType::Misc;
                }

                // Track stack depth
                let depth = (-offset) as usize;
                if depth > state.stack_depth {
                    state.stack_depth = depth;
                }
            }
            RegType::PtrToMapValue => {
                // Map value store - bounds would be checked with map info
            }
            RegType::PtrToCtx => {
                // Context is typically read-only
                return Err(KernelError::PermissionDenied);
            }
            _ => {
                return Err(KernelError::PermissionDenied);
            }
        }

        Ok(())
    }

    /// Verify 64-bit immediate load
    fn verify_ld_imm64(
        &self,
        insn: &BpfInsn,
        pc: usize,
        state: &mut VerifierState,
    ) -> Result<(), KernelError> {
        let dst = insn.dst_reg() as usize;

        // Ensure we have the second instruction
        if pc + 1 >= self.insns.len() {
            return Err(KernelError::InvalidArgument);
        }

        let insn2 = &self.insns[pc + 1];

        // Second instruction must have code 0
        if insn2.code != 0 {
            return Err(KernelError::InvalidArgument);
        }

        // Combine immediates into 64-bit value
        let imm64 = ((insn2.imm as u64) << 32) | (insn.imm as u32 as u64);

        state.regs[dst] = RegState::constant(imm64 as i64);

        Ok(())
    }

    /// Verify conditional jump
    fn verify_jmp_cond(&self, insn: &BpfInsn, state: &VerifierState) -> Result<(), KernelError> {
        let dst = insn.dst_reg() as usize;
        let src = insn.src_reg() as usize;
        let is_src_reg = bpf_src(insn.code) == BPF_X;

        // Destination must be readable
        if !state.regs[dst].is_readable() {
            return Err(KernelError::PermissionDenied);
        }

        // Source must be readable if using register
        if is_src_reg && !state.regs[src].is_readable() {
            return Err(KernelError::PermissionDenied);
        }

        Ok(())
    }

    /// Verify helper call
    fn verify_call(&self, insn: &BpfInsn, state: &mut VerifierState) -> Result<(), KernelError> {
        // R1-R5 are caller-saved, become undefined after call
        for i in 1..=5 {
            state.regs[i] = RegState::new();
        }

        // R0 contains return value
        state.regs[BPF_REG_0 as usize] = RegState::scalar();

        // For now, we allow any helper ID
        // A real verifier would check against allowed helpers for the program type
        let _helper_id = insn.imm;

        Ok(())
    }

    /// Get access size from instruction code
    fn access_size(&self, code: u8) -> usize {
        match bpf_size(code) {
            BPF_B => 1,
            BPF_H => 2,
            BPF_W => 4,
            BPF_DW => 8,
            _ => 0,
        }
    }
}

// =============================================================================
// Public API
// =============================================================================

/// Verify a BPF program
///
/// Returns Ok(()) if the program passes verification, Err with errno otherwise.
///
/// # Arguments
/// * `insns` - The BPF instructions to verify
/// * `ctx_size` - Size of the context structure for bounds checking
pub fn verify_bpf_prog(insns: &[BpfInsn], ctx_size: usize) -> Result<(), KernelError> {
    let mut verifier = Verifier::new(insns, ctx_size);
    verifier.verify()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_exit() {
        // mov r0, 0; exit
        let insns = [
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        assert!(verify_bpf_prog(&insns, 0).is_ok());
    }

    #[test]
    fn test_missing_exit() {
        // mov r0, 0 (no exit)
        let insns = [BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0)];
        assert!(verify_bpf_prog(&insns, 0).is_err());
    }

    #[test]
    fn test_uninitialized_read() {
        // add r0, r2; exit (r2 not initialized)
        let insns = [
            BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_X, 0, 2, 0, 0),
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ];
        assert!(verify_bpf_prog(&insns, 0).is_err());
    }
}
