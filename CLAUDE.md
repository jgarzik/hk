# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

hk is an operating system kernel written in Rust, targeting x86-64 and aarch64 architectures. It aims to be Linux syscall ABI compatible.

## Build Commands

```bash
# Build and test (primary workflow)
make check          # Build x86-64 kernel + boot test in QEMU (SUCCESS criteria)
make check-arm      # Build aarch64 kernel + boot test in QEMU (SUCCESS criteria)

# Individual build targets
make build          # Build x86-64 kernel (release)
make build-arm      # Build aarch64 kernel (release)
make iso            # Build bootable ISO image (includes user binaries)

# Run in QEMU
make run            # Run x86-64 kernel
make run-arm        # Run aarch64 kernel

# Code quality (SUCCESS criteria)
make clippy         # Clippy for x86-64 (must pass with no warnings)
make clippy-arm     # Clippy for aarch64
make fmt            # Format code
```

**IMPORTANT**: Do NOT run bare `cargo clippy` or `cargo build` - they will fail on this no_std kernel.
Always use the Makefile targets which specify the correct `--target` flags.

**Success criteria for all changes**: `make check`, `make check-arm`, `make clippy` clean.

## Workspace Structure

```
hk/
├── kernel/              # Main kernel crate (no_std, no_main)
│   ├── arch/            # Architecture-specific code
│   │   ├── x86_64/      # x86-64 boot, interrupts, paging
│   │   └── aarch64/     # aarch64 boot, interrupts, paging
│   ├── bus/             # Bus drivers (PCI, etc.)
│   ├── dt/              # Device tree parsing
│   ├── fs/              # VFS + filesystem implementations
│   ├── ns/              # Namespaces
│   ├── signal/          # Signal handling
│   ├── storage/         # Block device drivers
│   ├── task/            # Process/thread management, scheduler, syscalls
│   ├── tty/             # TTY subsystem
│   ├── usb/             # USB stack (xHCI, hub, devices)
│   └── *.rs             # Core kernel modules
├── boot/                # GRUB configuration
├── user/                # Userspace test binaries (built with gcc)
└── target/              # Build output
```

**File layout**: Files are placed directly in crate roots (no `src/` directories).

## Architecture

### Design Philosophy

- **Device tree**: Central to hardware discovery on aarch64; x86-64 uses synthetic device tree
- **Linux compatible**: Uses Linux syscall ABI for each architecture
- **Monolithic kernel**: All drivers in kernel space

### Boot Memory Sequence

1. Pre-Allocator (no heap, static/stack only)
2. Early Bump Allocator (temporary, for initial allocations)
3. Frame Allocator (bitmap-based physical frame management)
4. Page Table Setup (identity map kernel)
5. Kernel Heap Allocator (enables Vec, Box, String)

### Target Architectures

- x86-64 (primary, boots via GRUB/Multiboot2)
- aarch64 (boots via device tree)

### Design Principles

1. **Cross-platform first**: Minimize arch-specific code. Build generic APIs that call back to arch-specific code, avoiding `#[cfg(target_arch)]` gates where possible.

2. **Test new syscalls**: When adding syscalls, add equivalent tests to boot_tester (unless testing is infeasible).
