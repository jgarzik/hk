//! BPF program container
//!
//! This module provides the `BpfProg` struct that holds a validated
//! eBPF program ready for execution.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::insn::BpfInsn;

/// A validated eBPF program ready for execution
///
/// Programs are reference-counted and can be shared between tasks
/// (e.g., for seccomp filter inheritance across fork).
#[derive(Debug)]
pub struct BpfProg {
    /// The eBPF instructions
    insns: Vec<BpfInsn>,

    /// Original program length (for stats/debugging)
    len: usize,
}

impl BpfProg {
    /// Create a new BPF program from instructions
    ///
    /// The instructions should already be validated.
    pub fn new(insns: Vec<BpfInsn>) -> Arc<Self> {
        let len = insns.len();
        Arc::new(Self { insns, len })
    }

    /// Get the program instructions
    #[inline]
    pub fn insns(&self) -> &[BpfInsn] {
        &self.insns
    }

    /// Get the number of instructions
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if the program is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}
