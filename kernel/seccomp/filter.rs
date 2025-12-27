//! Seccomp filter management
//!
//! This module handles seccomp BPF filter storage, chaining, and execution.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::bpf::{BpfInsn, BpfProg, SockFilter, bpf_run, cbpf_to_ebpf};
use crate::error::KernelError;

use super::{SECCOMP_RET_ACTION, SeccompData};

/// A seccomp filter containing an eBPF program
///
/// Filters are reference-counted and can be chained.
/// When multiple filters are attached, they are run in order
/// and the most restrictive result wins.
#[derive(Debug)]
pub struct SeccompFilter {
    /// The eBPF program to execute
    prog: Arc<BpfProg>,

    /// Previous filter in chain (parent's filter)
    /// Multiple filters stack: newer filter runs first, then prev
    prev: Option<Arc<SeccompFilter>>,

    /// Whether to log non-ALLOW actions
    log: bool,
}

impl SeccompFilter {
    /// Create a new seccomp filter from a cBPF program
    ///
    /// # Arguments
    /// * `cbpf` - Classic BPF instructions
    /// * `prev` - Previous filter to chain with
    /// * `log` - Whether to log non-ALLOW actions
    ///
    /// # Returns
    /// A new SeccompFilter wrapped in Arc, or an error
    pub fn from_cbpf(
        cbpf: &[SockFilter],
        prev: Option<Arc<SeccompFilter>>,
        log: bool,
    ) -> Result<Arc<Self>, KernelError> {
        // Convert cBPF to eBPF
        let ebpf = cbpf_to_ebpf(cbpf).map_err(|_| KernelError::InvalidArgument)?;

        let prog = BpfProg::new(ebpf);

        Ok(Arc::new(Self { prog, prev, log }))
    }

    /// Create a new seccomp filter from eBPF instructions directly
    ///
    /// This is used for testing or when eBPF programs are provided directly.
    pub fn from_ebpf(ebpf: Vec<BpfInsn>, prev: Option<Arc<SeccompFilter>>, log: bool) -> Arc<Self> {
        let prog = BpfProg::new(ebpf);
        Arc::new(Self { prog, prev, log })
    }

    /// Run this filter and all ancestors against seccomp_data
    ///
    /// Returns the most restrictive action from the filter chain.
    /// Lower action values are more restrictive.
    pub fn run(&self, data: &SeccompData) -> u32 {
        // Run this filter
        let ctx = data as *const SeccompData as *const u8;
        let ctx_len = SeccompData::SIZE;

        // SAFETY: ctx points to valid SeccompData, ctx_len is correct
        let result = unsafe { bpf_run(self.prog.insns(), ctx, ctx_len) } as u32;

        // If we have a previous filter, run it too
        if let Some(ref prev) = self.prev {
            let prev_result = prev.run(data);

            // Return the more restrictive result
            // Lower action value = more restrictive
            let result_action = result & SECCOMP_RET_ACTION;
            let prev_action = prev_result & SECCOMP_RET_ACTION;

            // Special case: KILL_PROCESS (0x80000000) is most restrictive
            // but has high bit set, so we need to handle it specially
            let result_is_kill = result >= 0x8000_0000;
            let prev_is_kill = prev_result >= 0x8000_0000;

            if result_is_kill {
                return result; // KILL is most restrictive
            }
            if prev_is_kill {
                return prev_result;
            }

            // For other actions, lower value is more restrictive
            if prev_action < result_action {
                return prev_result;
            }
        }

        result
    }

    /// Get the previous filter in the chain
    pub fn prev(&self) -> Option<&Arc<SeccompFilter>> {
        self.prev.as_ref()
    }

    /// Check if logging is enabled for this filter
    pub fn should_log(&self) -> bool {
        self.log
    }

    /// Count the number of filters in this chain
    pub fn chain_len(&self) -> usize {
        let mut count = 1;
        let mut current = self.prev.as_ref();
        while let Some(filter) = current {
            count += 1;
            current = filter.prev.as_ref();
        }
        count
    }
}

/// Copy a sock_fprog from userspace and create a filter
///
/// # Safety
/// The caller must ensure the sock_fprog pointer is valid.
pub fn create_filter_from_user<A: crate::uaccess::UaccessArch>(
    fprog_ptr: u64,
    prev: Option<Arc<SeccompFilter>>,
    log: bool,
) -> Result<Arc<SeccompFilter>, KernelError> {
    use crate::uaccess::{copy_from_user, get_user};

    // Read sock_fprog header
    if !A::access_ok(fprog_ptr, core::mem::size_of::<SockFprog>()) {
        return Err(KernelError::BadAddress);
    }

    // Read len and filter pointer
    let len: u16 = get_user::<A, u16>(fprog_ptr).map_err(|_| KernelError::BadAddress)?;
    let filter_ptr: u64 = get_user::<A, u64>(fprog_ptr + 8).map_err(|_| KernelError::BadAddress)?; // Pointer is at offset 8 (after u16 + padding)

    if len == 0 || len as usize > crate::bpf::BPF_MAXINSNS {
        return Err(KernelError::InvalidArgument);
    }

    // Allocate buffer for filter instructions
    let filter_size = len as usize * core::mem::size_of::<SockFilter>();

    if !A::access_ok(filter_ptr, filter_size) {
        return Err(KernelError::BadAddress);
    }

    // Copy filter instructions
    let mut filters = alloc::vec![SockFilter::default(); len as usize];
    // Safe: we're converting the filter array to bytes for copying
    let dest =
        unsafe { core::slice::from_raw_parts_mut(filters.as_mut_ptr() as *mut u8, filter_size) };
    copy_from_user::<A>(dest, filter_ptr, filter_size).map_err(|_| KernelError::BadAddress)?;

    // Validate the cBPF program
    crate::bpf::validate_cbpf(&filters).map_err(|_| KernelError::InvalidArgument)?;

    // Create the filter
    SeccompFilter::from_cbpf(&filters, prev, log)
}

/// sock_fprog structure for reading from userspace
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SockFprog {
    /// Number of filter blocks
    pub len: u16,
    /// Padding for alignment
    _pad: [u8; 6],
    /// Pointer to filter array
    pub filter: u64,
}
