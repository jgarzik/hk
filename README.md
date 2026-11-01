
# hk - an operating system kernel written in Rust

## Mission

A Linux-compatible kernel for modern, highly multi-core 64-bit machines,
notably x86-64 and arm64. Full Linux compatibility is the goal; it is reached
incrementally by implementing an ever-growing subset of Linux in chunks of
work. System calls aim for 100% coverage; ioctls and /proc are a pragmatic,
app-driven subset. Core functionality and modern hardware come first.

## Design goals

### Modern multi-processing

Multi-threaded, multi-core:  Designed for modern 64-bit multi-core processors.

Initially targeting x86-64 and aarch64.

### Hardware discovery

arm64 discovers hardware from the device tree; x86-64 boots via multiboot2
(GRUB) and uses ACPI (MADT) for CPUs and APICs. Devices on both are found
by PCI enumeration.

### Linux compatible

Uses the Linux syscall ABI for each respective architecture.

### Wishlist

* hybrid kernel/user model for DMA'ing device drivers
* eBPF even more widely used
* Policy cut-off for legacy hardware:  Require >= 2021 ?  Open to debate.

## Status

Boots SMP on x86-64 and arm64 under QEMU. Working today: a scheduler with
per-CPU run queues and Linux's classes (stop, SCHED_FIFO/RR, EEVDF fair,
idle), with tasks placed on and balanced across every CPU and CPU
affinity; memory management with a buddy/slab allocator, TLB
shootdown, copy-on-write, shared memory, LRU reclaim and swap; a
VFS with ramfs, vfat, procfs, devtmpfs and cgroupfs; a block layer
(virtio-blk, GPT partitions); networking (virtio-net, e1000, IPv4, TCP,
UDP, ICMP, AF_UNIX, AF_PACKET, netlink); exec of dynamically linked
programs (the PT_INTERP interpreter) and #! scripts, with init started
by execve and Linux's init=/rdinit=; supplementary groups, named FIFOs,
every clock id, a ChaCha20 CRNG behind getrandom and /dev/urandom, and
/dev/kmsg over a record-based kernel log. Userland: Ubuntu's static
busybox, plus glibc's dynamic linker, bash and coreutils. The boot
tester runs the same tests on hk and on a real Linux kernel, which
defines the expected behavior.

## Building etc

Run `make check` or `make check-arm`.  Run `make help` for more info.

Requires Rust (stable), qemu, GRUB and xorriso (ISO), dosfstools, mtools
and an aarch64 cross-compiler; see DEVELOPMENT.md for the full list.

## Naming

hk stands for... happy koala, or hacker kernel, or hong kong,
