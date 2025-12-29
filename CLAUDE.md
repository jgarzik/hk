# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

hk is an operating system kernel written in Rust, targeting 64-bit multi-core processors (x86-64 and aarch64). It uses the Linux syscall ABI for compatibility with existing userspace programs.

## Build Commands

Run `make help` to see all targets. Key commands:

```bash
make check          # Build x86-64 + boot test (PRIMARY workflow)
make check-arm      # Build aarch64 + boot test
make clippy         # Lint x86-64
make clippy-arm     # Lint aarch64
make fmt            # Format code

make run            # Interactive QEMU x86-64
make run-arm        # Interactive QEMU aarch64
```

**Important**: Do NOT run bare `cargo clippy` - it will fail on this no_std kernel. Always use the Makefile targets which specify the correct `--target` flags.

## Project Structure

```
kernel/           # Main kernel crate (the primary codebase)
  arch/           # Architecture-specific (x86_64/, aarch64/)
  mm/             # Memory management (mmap, vma, page tables)
  task/           # Process/thread management, scheduler
  fs/             # VFS + filesystem implementations (vfat, ramfs, procfs)
  signal/         # Signal handling
  bus/            # Bus drivers (PCI)
  storage/        # Block device drivers (virtio-blk)
  usb/            # USB stack (xHCI, mass storage, serial)
  tty/            # TTY subsystem
  ns/             # Namespaces (PID, UTS, user, mount)
  net/            # Network stack (TCP/IP, sockets)
  *.rs            # Core modules (heap, frame_alloc, console, epoll, futex, etc.)

user/             # Userspace test binaries (separate from kernel workspace)
  boot_tester/    # Main test harness that runs during boot
  syscall/        # Syscall wrappers (x86_64.rs, aarch64.rs)

tools/            # Host-side tools (separate from kernel workspace)
doc/              # Documentation (SYSCALLS.md, LOCKING.md, COMPAT.md, NUMA.md)
```

**Note**: Source files are placed directly in crate roots (no `src/` directories).

## Architecture

### Kernel Design
- Multi-core SMP design (no legacy single-core support)
- Device tree based hardware description
- Per-CPU scheduler with IrqSpinlock-protected run queues
- Global task table with Mutex protection
- Reference-counted credentials (Arc<Cred>)

### Locking Model
See `doc/LOCKING.md` for comprehensive documentation. Key rules:
- **IrqSpinlock<T>**: IRQ-safe, disables interrupts - use for scheduler, signal handlers, anything accessed from interrupts
- **Mutex<T>**: NOT IRQ-safe - use for VFS, task table, allocators
- **RwLock<T>**: Multiple readers or one writer - use for VFS structures, namespaces
- **Never** acquire Mutex/RwLock from interrupt context

### Syscall Coverage
See `doc/SYSCALLS.md` for the full inventory. The kernel implements Linux-compatible syscalls for both architectures, with aarch64 using modern syscall ABI only (no legacy variants like `open`, `fork`).

## Testing

Boot tests via QEMU are the primary testing mechanism. Tests are in `user/boot_tester/tests/` and run automatically during kernel boot.

Success criteria: Serial output contains `BOOT_COMPLETE` with no FAIL messages.

```bash
# View serial log after running
cat /tmp/qemu_serial.log      # x86-64
cat /tmp/qemu_serial_arm.log  # aarch64
```

## Design Principles

1. **Cross-platform first**: Minimize arch-specific code. Prefer generic APIs with arch callbacks over `#[cfg(target_arch)]` gates.
2. **Test new syscalls**: Add tests to `user/boot_tester/` for new syscalls.
3. **Success criteria**: `make check`, `make check-arm`, `make clippy`, `make clippy-arm` must all pass.

## Known Issues

See `BUGS.md` for details. Notable: heap corruption bug affecting Arc<T> struct fields in USB mass storage driver - workaround uses global static atomics instead of struct fields.
