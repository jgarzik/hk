
# hk - an operating system kernel written in Rust

## Design goals

### Modern multi-processing

Multi-threaded, multi-core:  Designed for modern 64-bit multi-core processors.

Initially targeting x86-64 and aarch64.

### eBPF

The kernel supports eBPF (extended Berkeley Packet Filter) for efficient
and safe execution of user-defined programs in the kernel space. This
enables advanced networking and tracing capabilities, and is extended
beyond networking to device drivers, VFS, MM and other subsystems.

### Device tree

The kernel uses a device tree to describe the hardware components of the
system. This allows for a flexible and extensible way to manage hardware
resources.

### Hybrid Device Model

Device drivers are ELF programs that are split into two parts, a kernel
part, typically handling interrupt response, and a user part, containing
the majority of the device driver logic.  An optional third part, an
eBPF program, can also be included.

### Microkernel-ish

Push as many services as possible into eBPF program, kernel threads, and
other near-kernel userspace-like constructs.

### Linux compatible

Uses the Linux syscall ABI for each respective architecture.

