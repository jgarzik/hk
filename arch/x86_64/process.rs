//! x86-64 thread state syscalls: arch_prctl (Linux
//! arch/x86/kernel/process_64.c), iopl and ioperm (ioport.c)

use super::percpu::{
    self, ARCH_GET_CPUID, ARCH_GET_FS, ARCH_GET_GS, ARCH_SET_CPUID, ARCH_SET_FS, ARCH_SET_GS,
    read_fs_base, write_fs_base,
};
use crate::task::percpu::{TASKLIST, current};
use crate::uaccess::UserPtr;
use crate::util::error::{KernelError, KernelResult};

/// arch_prctl(code, addr): architecture-specific thread state
///
/// Controls architecture-specific thread state. On x86_64, this is used
/// primarily for setting the FS and GS base registers for thread-local storage.
///
/// Supported operations:
/// - ARCH_SET_FS (0x1002): Set FS base address (user TLS pointer)
/// - ARCH_GET_FS (0x1003): Get FS base address
/// - ARCH_SET_GS (0x1001): Set the user GS base
/// - ARCH_GET_GS (0x1004): Get the user GS base
/// - ARCH_GET_CPUID (0x1011): Returns 1 (CPUID enabled; no faulting support)
/// - ARCH_SET_CPUID (0x1012): -ENODEV (CPUID faulting not supported)
///
/// Returns 0 on success, negative errno on error.
pub fn sys_arch_prctl(code: i32, addr: u64) -> KernelResult<i64> {
    // addr is a value for the SET codes, a u64 * for the GET ones
    let out = UserPtr::<u64>::new(addr);

    match code {
        ARCH_SET_FS => {
            // Set FS base - user TLS pointer
            if !crate::arch::user_tls_ok(addr) {
                return Err(KernelError::NotPermitted);
            }
            current()
                .tls
                .store(addr, core::sync::atomic::Ordering::Relaxed);
            write_fs_base(addr);
            Ok(0)
        }
        ARCH_GET_FS => {
            // Get FS base - return via user pointer
            // The live register (user code may have changed it)
            let tls = read_fs_base();

            out.write(&tls)?;
            Ok(0)
        }
        // CPUID faulting is not supported, so CPUID is always enabled.
        // Matches Linux on CPUs without X86_FEATURE_CPUID_FAULT
        // (arch/x86/kernel/process.c get_cpuid_mode/set_cpuid_mode).
        ARCH_GET_CPUID => Ok(1),
        ARCH_SET_CPUID => Err(KernelError::NoDevice),
        ARCH_SET_GS => {
            // The user GS base (the kernel's per-CPU base is swapped in
            // on entry): null selector, then the base, like Linux
            // do_arch_prctl_64
            if !crate::arch::user_tls_ok(addr) {
                return Err(KernelError::NotPermitted);
            }
            percpu::load_user_gs_null();
            crate::arch::write_user_gsbase(addr);
            current()
                .gsbase
                .store(addr, core::sync::atomic::Ordering::Relaxed);
            Ok(0)
        }
        ARCH_GET_GS => {
            // The live user base (`mov gs` may have changed it)
            let gs = crate::arch::read_user_gsbase();
            out.write(&gs)?;
            Ok(0)
        }
        _ => Err(KernelError::InvalidArgument),
    }
}

/// iopl(level): set the I/O privilege level
///
/// Changes the I/O privilege level of the calling thread. The IOPL determines
/// which I/O ports the thread can access.
///
/// # Arguments
/// * `level` - The new IOPL level (0-3). Level 3 grants access to all I/O ports.
///
/// # Returns
/// * 0 on success
/// * -EINVAL if level > 3
/// * -EPERM if trying to raise privilege without CAP_SYS_RAWIO
///
/// # Security
/// Lowering the privilege level is always allowed. Raising it requires
/// CAP_SYS_RAWIO capability.
///
/// # Note
/// This is an emulated IOPL - it doesn't modify the CPU's actual IOPL register.
/// The kernel stores the level per-task and uses it for permission checks.
pub fn sys_iopl(level: u32) -> KernelResult<()> {
    use crate::task::{CAP_SYS_RAWIO, capable};

    // Validate level (must be 0-3)
    if level > 3 {
        return Err(KernelError::InvalidArgument);
    }

    // Get current IOPL level
    let old = iopl_emul();

    // No change? Done.
    if level == u32::from(old) {
        return Ok(());
    }

    // Lowering privilege is always allowed
    if level < u32::from(old) {
        set_iopl_emul(level as u8);
        return Ok(());
    }

    // Raising privilege requires CAP_SYS_RAWIO
    if !capable(CAP_SYS_RAWIO) {
        return Err(KernelError::NotPermitted);
    }

    // Set new level
    set_iopl_emul(level as u8);
    Ok(())
}

/// ioperm(from, num, turn_on): port permissions (not implemented)
///
/// This syscall allows fine-grained control over individual I/O ports (0-0x3ff).
///
/// # Arguments
/// * `from` - Starting port number
/// * `num` - Number of ports
/// * `turn_on` - 1 to enable access, 0 to disable
///
/// # Returns
/// * -ENOSYS - Not implemented (requires TSS I/O bitmap infrastructure)
///
/// # Note
/// Full ioperm implementation requires per-task I/O permission bitmaps in the TSS.
/// This is not yet implemented. Use iopl(3) for full I/O port access.
pub fn sys_ioperm(_from: u64, _num: u64, _turn_on: i32) -> KernelResult<()> {
    Err(KernelError::NotImplemented)
}

/// The current task's emulated IOPL, 0-3 (3: every I/O port)
fn iopl_emul() -> u8 {
    TASKLIST.read().view(&current()).map_or(0, |t| t.iopl_emul)
}

/// Set the current task's emulated IOPL (0-3; the caller checks the
/// privilege)
fn set_iopl_emul(level: u8) {
    let me = current();
    let mut table = TASKLIST.write();
    if let Some(mut task) = table.view_mut(&me) {
        task.iopl_emul = level;
    }
}
