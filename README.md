
# hk - an operating system kernel written in Rust

## Design goals

### Modern multi-processing

Multi-threaded, multi-core:  Designed for modern 64-bit multi-core processors.

Initially targeting x86-64 and aarch64.

### Device tree

The kernel uses a device tree to describe the hardware components of the
system. This allows for a flexible and extensible way to manage hardware
resources.

### Linux compatible

Uses the Linux syscall ABI for each respective architecture.

### Wishlist

* hybrid kernel/user model for DMA'ing device drivers
* eBPF even more widely used
* Policy cut-off for legacy hardware:  Require >= 2021 ?  Open to debate.

### Building etc

Run `make check` or `make check-arm`.  Run `make help` for more info.

Requires qemu, dosfstools, and iso tools.

## Naming

hk stands for... happy koala, or hacker kernel, or hong kong,
