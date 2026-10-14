# CLAUDE.md

hk: Rust (stable, no nightly features) no_std SMP kernel, x86-64 + aarch64, Linux syscall ABI. No `src/` dirs; sources live in crate roots.

## Build / verify
- Use Makefile targets only; bare `cargo build/clippy` fails (no_std needs `--target`).
- Done = all pass: `make test` `make check` `make check-arm` `make check-linux` `make clippy` `make clippy-arm` `make fmt-check`. Clippy must be warning-free.
- `check*` boot QEMU and run `user/boot_tester`; pass = shutdown msg + no `FAIL` in `/tmp/qemu_serial.log` (arm: `/tmp/qemu_serial_arm.log`).
- `user/` and `tools/` are separate cargo workspaces (excluded from root). Setup/pkgs: `DEVELOPMENT.md`.
- `make check-linux`: same boot_tester as init on a real Linux kernel in QEMU (no root). Tests must pass on BOTH hk and Linux — expectations come from Linux, not hk. Host-only branches: `tests/helpers.rs` `host_mode()`/`skip()`. Linux source: `~/tmp/repo/linux`.

## Rules
- Cross-platform first: generic code + arch callbacks in `kernel/arch/{x86_64,aarch64}/`, not `#[cfg(target_arch)]` sprinkled around.
- aarch64 = modern syscalls only (no `open`, `fork`, etc.); syscall numbers are per-arch.
- New syscall → add boot test in `user/boot_tester/tests/`, register in `tests/mod.rs::run_all_tests`, update `doc/SYSCALLS.md`.
- Locking (read `doc/LOCKING.md` before touching locks): IRQ-reachable state → `IrqSpinlock`; never take `Mutex`/`RwLock` in IRQ context.
- `user/boot_tester` is no_std: provides its own `mem*`/`bcmp` symbols.

## Known issues
`BUGS.md`: unexplained corruption of `Arc<T>` fields in `kernel/usb/msc.rs`; workaround uses static atomics — don't "clean up" back into struct fields.
