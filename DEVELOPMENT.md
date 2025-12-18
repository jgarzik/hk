# Development Guide

This guide covers building, testing, and running the hk kernel on Linux (Ubuntu).

## Prerequisites

### Required Packages

```bash
# Rust toolchain (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# QEMU for x86-64 emulation
sudo apt install qemu-system-x86

# Build tools for userspace and ISO creation
sudo apt install build-essential cpio grub-pc-bin grub-common mtools xorriso
```

### Rust Components

The project uses nightly Rust. Components are specified in `rust-toolchain.toml` and should be installed automatically. If needed:

```bash
rustup target add x86_64-unknown-none
```

## Quick Start

```bash
# Build everything and run in QEMU
make run

# Or step by step:
make all    # Build kernel + userspace
make run    # Run in QEMU
```

## Build Commands

### Kernel

```bash
make build      # Release build (optimized)
make debug      # Debug build (unoptimized, with debug symbols)
```

Or directly with cargo:

```bash
cargo build --target x86_64-unknown-none --release
cargo build --target x86_64-unknown-none
```

The kernel binary is output to:
- Release: `target/x86_64-unknown-none/release/kernel`
- Debug: `target/x86_64-unknown-none/debug/kernel`

### Userspace

```bash
make user       # Build boot_tester binary and create initramfs-x86_64.cpio
```

Or manually:

```bash
cd user
make all        # Builds boot_tester + creates initramfs-x86_64.cpio
```

The userspace build creates `user/initramfs-x86_64.cpio` which is embedded into the kernel at compile time.

### Full Build

```bash
make all        # Build kernel (release) + userspace
make            # Same as above (default target)
```

## Running in QEMU

### Basic Run

```bash
make run        # Builds if needed, then runs
```

### Debug Mode

```bash
make run-debug  # Runs with -no-reboot (stops on crash)
```

### Direct QEMU Script

```bash
./run-qemu.sh       # Basic run
./run-qemu.sh -d    # Debug mode (no reboot on crash)
./run-qemu.sh -g    # Enable GDB server on port 1234
```

### QEMU Configuration

The default QEMU setup:
- Memory: 512MB
- Serial output: logged to `/tmp/qemu_serial.log`
- Display: `-nographic` (console mode)

### Manual Boot Test

To manually boot test with serial output capture:

```bash
make iso
timeout 20 qemu-system-x86_64 -cdrom target/hk-x86_64.iso -nographic -m 512M -serial file:/tmp/qemu_serial.log
cat /tmp/qemu_serial.log
```

A successful boot shows `BOOT_COMPLETE` in the serial log.

## Testing

### Unit Tests

Tests run on the host (with std), not bare metal:

```bash
make test           # Run all tests
cargo test          # Same thing
cargo test -p hk-kernel     # Test specific crate
cargo test --release        # Release mode tests
```

### Boot Test

The `boot-test` target builds the kernel, boots it in QEMU, and verifies it reaches the `BOOT_COMPLETE` marker:

```bash
make boot-test              # Build and verify kernel boots successfully
cargo run -p hk-tools --bin boot-test -- --timeout 30  # With custom timeout
```

This is useful for automated testing and CI - it exits with code 0 on success, 1 on timeout, or 2 on build failure.

## Code Quality

```bash
cargo clippy        # Run linter
cargo fmt           # Format code
cargo fmt --check   # Check formatting without modifying
```

## Project Structure

```
hk/
├── kernel/         # Final kernel binary
│   ├── main.rs     # Rust entry point (_start)
│   ├── boot.S      # 32-to-64-bit boot stub (_start32)
│   ├── kernel.ld   # Linker script
│   ├── build.rs    # Build script (assembles boot.S)
│   ├── core/       # Architecture-independent kernel logic
│   ├── dt/         # Device tree parsing
│   ├── arch/       # Architecture-specific code (x86_64)
│   ├── platform/   # Platform device drivers
│   ├── fs/         # VFS + CPIO initramfs support
│   └── task/       # Task/scheduler implementation
├── boot/           # Boot configuration
│   └── grub.cfg    # GRUB menu configuration
├── tools/          # Development tools
│   └── boot_test.rs # Automated boot test harness
└── user/           # Userspace binaries
    ├── hello.rs    # Test program
    ├── user.ld     # Linker script
    └── Makefile    # Userspace build
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
target/x86_64-unknown-none/release/kernel   # Kernel binary (ELF)
target/hk-x86_64.iso                        # Bootable ISO image (x86-64)
kernel/initramfs-x86_64.cpio                # Initramfs (copied from user/)
user/initramfs-x86_64.cpio                  # Userspace CPIO archive (x86-64)
user/target/x86_64-unknown-none/release/hello  # Hello binary
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

Ensure QEMU is installed and accessible:
```bash
which qemu-system-x86_64
qemu-system-x86_64 --version
```

### Build fails with target errors

Ensure the nightly toolchain and target are installed:
```bash
rustup override set nightly
rustup target add x86_64-unknown-none
```

### Kernel crashes immediately

Run with debug mode to see the error:
```bash
make run-debug
```

Or enable GDB for step-by-step debugging:
```bash
./run-qemu.sh -g
```
