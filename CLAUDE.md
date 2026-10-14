# CLAUDE.md

hk: Rust (stable, no nightly features) no_std SMP kernel, x86-64 + aarch64, Linux syscall ABI. No `src/` dirs; sources live in crate roots.

## Mission
- Linux-compatible kernel for modern, highly multi-core 64-bit machines (x86-64, arm64). Goal is full compatibility, reached by growing a subset in chunks of work.
- Syscalls: aim for 100%. ioctls and /proc (/sys): pragmatic subset, driven by what real apps need — don't chase completeness.
- Core functionality + modern hardware first; no legacy-hardware work. Test targets: QEMU (virtio), virtio guests, a Dell OptiPlex 3020 (real HW).
- IPv6: full support is planned in a later chunk — never bake IPv4-only assumptions into shared network layers.

## Build / verify
- Use Makefile targets only; bare `cargo build/clippy` fails (no_std needs `--target`).
- Done = all pass: `make test` `make check` `make check-arm` `make check-linux` `make check-linux-arm` `make clippy` `make clippy-arm` `make fmt-check`. Clippy must be warning-free.
- `check*` boot QEMU and run `user/boot_tester`; pass = shutdown msg + no `FAIL` in `/tmp/qemu_serial.log` (arm: `/tmp/qemu_serial_arm.log`).
- `user/` and `tools/` are separate cargo workspaces (excluded from root). Setup/pkgs: `DEVELOPMENT.md`.
- `make check-linux`: same boot_tester as init on a real Linux kernel in QEMU (no root). Tests must pass on BOTH hk and Linux — expectations come from Linux, not hk. Host-only branches: `tests/helpers.rs` `host_mode()`/`skip()`.

## Rules
- Cross-platform first: generic code + arch callbacks in `kernel/arch/{x86_64,aarch64}/`, not `#[cfg(target_arch)]` sprinkled around.
- aarch64 = modern syscalls only (no `open`, `fork`, etc.); syscall numbers are per-arch.
- New syscall → add boot test in `user/boot_tester/tests/`, register in `tests/mod.rs::run_all_tests`, update `doc/SYSCALLS.md`.
- Locking correctness is top priority (many-core). Read `doc/LOCKING.md` before touching locks. IRQ-reachable state → `IrqSpinlock`; never take `Mutex`/`RwLock` in IRQ context; never sleep holding a spinlock.
- Every new/changed lock: state its IRQ class and lock-order position, and update the matching `doc/LOCKING.md` section in the SAME commit. Lock-order cycles and sleeping under a spinlock are critical bugs.
- `user/boot_tester` is no_std: provides its own `mem*`/`bcmp` symbols.

## Known issues
`BUGS.md` lists known bugs (chroot, PID/TID, wait status, …). Notably: unexplained `Arc<T>` field corruption in `kernel/usb/msc.rs`; its static-atomic workaround must not be "cleaned up" back into struct fields.
