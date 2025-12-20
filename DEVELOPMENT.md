# Development Guide

This guide covers building, testing, and running the hk kernel on Linux (Ubuntu).

## Prerequisites

### Required Packages

```bash
# Rust toolchain (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# QEMU for x86-64 and aarch64 emulation
sudo apt install qemu-system-x86 qemu-system-arm

# Build tools for userspace and ISO creation
sudo apt install build-essential cpio grub-pc-bin grub-common mtools xorriso

# Cross-compiler for aarch64 userspace
sudo apt install gcc-aarch64-linux-gnu
```

### Rust Components

The project uses nightly Rust. Components are specified in `rust-toolchain.toml` and should be installed automatically. If needed:

```bash
rustup target add x86_64-unknown-none
rustup target add aarch64-unknown-none
rustup target add x86_64-unknown-linux-gnu
rustup target add aarch64-unknown-linux-gnu
```

## Quick Start

```bash
# Build and test x86-64 (primary workflow)
make check          # Build + boot test in QEMU

# Build and test aarch64
make check-arm      # Build + boot test in QEMU

# Run interactively
make run            # x86-64 in QEMU
make run-arm        # aarch64 in QEMU
```

## Build Commands

### Kernel

```bash
# x86-64
make build          # Release build (optimized)
make debug          # Debug build

# aarch64
make build-arm      # Release build

# Or directly with cargo:
cargo build -p hk-kernel --target x86_64-unknown-none --release
cargo build -p hk-kernel --target aarch64-unknown-none --release
```

The kernel binary is output to:
- x86-64: `target/x86_64-unknown-none/release/kernel`
- aarch64: `target/aarch64-unknown-none/release/kernel`

### Userspace

Userspace builds automatically as part of `make check`/`make check-arm`:

```bash
cd user && make             # x86-64 userspace
cd user && make arm         # aarch64 userspace
```

The userspace build creates:
- `user/initramfs-x86_64.cpio` - x86-64 initramfs
- `user/initramfs-aarch64.cpio` - aarch64 initramfs

### Full Build + Test (Recommended)

```bash
make check          # Build x86-64 + boot test (SUCCESS criteria)
make check-arm      # Build aarch64 + boot test (SUCCESS criteria)
cargo clippy --target x86_64-unknown-none -p hk-kernel  # Linting
```

## Running in QEMU

### Basic Run

```bash
make run            # x86-64
make run-arm        # aarch64
```

### Direct QEMU Scripts

```bash
# x86-64
./run-qemu.sh           # Basic run
./run-qemu.sh -d        # Debug mode (no reboot on crash)
./run-qemu.sh -g        # Enable GDB server on port 1234

# aarch64
./run-qemu-arm.sh       # Basic run
./run-qemu-arm.sh -d    # Debug mode
```

### QEMU Configuration

The default QEMU setup:
- Memory: 512MB
- Serial output: logged to `/tmp/qemu_serial.log` (x86-64) or `/tmp/qemu_serial_arm.log` (aarch64)
- Display: `-nographic` (console mode)
- x86-64: Boots from ISO with GRUB
- aarch64: Direct kernel boot with device tree

### Boot Test

A successful boot shows `BOOT_COMPLETE` in the serial log. The `make check` and `make check-arm` targets automatically verify this.

## Testing

### Boot Tests (Primary Testing Method)

The kernel includes a comprehensive boot_tester that runs syscall and subsystem tests during boot:

```bash
make check          # Build x86-64 + run boot tests
make check-arm      # Build aarch64 + run boot tests
```

Tests are defined in `user/tests/*.rs` and cover:
- Process management (fork, exec, clone, signals)
- Memory management (mmap, mlock, munmap)
- File system operations
- Timers and scheduling
- And more...

A successful boot shows all tests passing and ends with `BOOT_COMPLETE`.

### Kernel Unit Tests

Some kernel modules have unit tests that run on the host:

```bash
cargo test -p hk-kernel --target x86_64-unknown-linux-gnu
```

Note: Most testing is done via boot tests since bare-metal kernel code requires QEMU.

## Code Quality

```bash
cargo clippy        # Run linter
cargo fmt           # Format code
cargo fmt --check   # Check formatting without modifying
```

## Project Structure

```
hk/
├── kernel/              # Main kernel crate (no_std, no_main)
│   ├── main.rs          # Entry point and kernel init
│   ├── arch/            # Architecture-specific code
│   │   ├── x86_64/      # x86-64: boot, interrupts, paging, syscalls
│   │   └── aarch64/     # aarch64: boot, exceptions, paging, syscalls
│   ├── mm/              # Memory management (mmap, vma, page tables)
│   ├── task/            # Process/thread management, scheduler
│   ├── fs/              # VFS + filesystem implementations
│   ├── signal/          # Signal handling
│   ├── bus/             # Bus drivers (PCI, etc.)
│   ├── storage/         # Block device drivers
│   ├── usb/             # USB stack (xHCI, hub, devices)
│   ├── tty/             # TTY subsystem
│   ├── ns/              # Namespaces
│   ├── dt/              # Device tree parsing
│   └── *.rs             # Core kernel modules (console, heap, frame_alloc, etc.)
├── user/                # Userspace test binaries
│   ├── boot_tester.rs   # Main test harness
│   ├── syscall/         # Syscall wrappers (x86_64.rs, aarch64.rs)
│   └── tests/           # Test modules (mmap.rs, process.rs, etc.)
├── boot/                # GRUB configuration (x86-64)
├── doc/                 # Documentation
└── target/              # Build output
```

**Note**: Source files are placed directly in crate roots (no `src/` directories).

## Debugging with GDB

1. Start QEMU with GDB server:
   ```bash
   ./run-qemu.sh -g
   ```

2. In another terminal, connect GDB:
   ```bash
   gdb target/x86_64-unknown-none/release/kernel
   (gdb) target remote :1234
   (gdb) continue
   ```

## Build Artifacts

After a full build:

```
# x86-64
target/x86_64-unknown-none/release/kernel    # Kernel binary (ELF)
target/hk-x86_64.iso                         # Bootable ISO image
user/initramfs-x86_64.cpio                   # Userspace CPIO archive

# aarch64
target/aarch64-unknown-none/release/kernel   # Kernel binary (ELF)
user/initramfs-aarch64.cpio                  # Userspace CPIO archive

# Userspace binaries
user/target/x86_64-unknown-linux-gnu/release/boot_tester
user/target/aarch64-unknown-linux-gnu/release/boot_tester
```

## Cleaning

```bash
make clean      # Clean all build artifacts
```

Or separately:

```bash
cargo clean             # Clean kernel build
cd user && make clean   # Clean userspace build
```

## Troubleshooting

### "rust-lld: not found"

Install the LLD linker:
```bash
rustup component add llvm-tools-preview
```

### QEMU permission issues

Ensure QEMU is installed:
```bash
which qemu-system-x86_64
which qemu-system-aarch64
```

### Build fails with target errors

Ensure the nightly toolchain and targets are installed:
```bash
rustup override set nightly
rustup target add x86_64-unknown-none aarch64-unknown-none
rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
```

### aarch64 cross-compilation fails

Install the cross-compiler:
```bash
sudo apt install gcc-aarch64-linux-gnu
```

### Kernel crashes immediately

Run with debug mode to see the error:
```bash
./run-qemu.sh -d        # x86-64
./run-qemu-arm.sh -d    # aarch64
```

Or enable GDB for step-by-step debugging:
```bash
./run-qemu.sh -g
```
