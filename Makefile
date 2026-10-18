# hk kernel Makefile

TARGET = x86_64-unknown-none
KERNEL = target/$(TARGET)/release/kernel
KERNEL_DEBUG = target/$(TARGET)/debug/kernel

# ARM64 target
TARGET_ARM = aarch64-unknown-none
KERNEL_ARM = target/$(TARGET_ARM)/release/kernel

# VFAT test image settings
VFAT_IMAGE = target/vfat.img
VFAT_SIZE_KB = 1024

# virtio-blk test disk (GPT: vfat, swap, pattern; tools/mkdisk.sh)
DISK_IMAGE = target/disk.img

# LOCKDEP=1: build with lockdep-lite (spin-lock tracking, lock order and
# sleep-in-atomic reports as LOCKDEP:FAIL) and the VMA/PTE agreement
# check (MMCHECK:FAIL), e.g. make check LOCKDEP=1
KERNEL_FEATURES = $(if $(LOCKDEP),--features lockdep)

# Machine-specific ISO configuration
# Usage: make iso MACHINE=dell
MACHINE ?=

.PHONY: all build debug user iso iso-debug run run-debug test check clean info help vfat-image disk-image
.PHONY: build-arm run-arm check-arm check-linux check-linux-arm user-arm clippy clippy-arm fmt list-machines

# Default: build everything (kernel, user binaries, ISO)
all: iso

help:
	@echo "hk kernel Makefile targets:"
	@echo ""
	@echo "  make          - Build kernel, user binaries, and ISO (default)"
	@echo "  make build    - Build kernel (release)"
	@echo "  make debug    - Build kernel (debug)"
	@echo "  make user     - Build userspace binaries and initramfs"
	@echo "  make iso      - Build bootable ISO image"
	@echo "  make iso-debug- Build bootable ISO with debug kernel"
	@echo "  make iso MACHINE=<name> - Build ISO for specific machine (e.g., MACHINE=dell)"
	@echo "  make list-machines      - List available machine configurations"
	@echo ""
	@echo "  make run      - Run kernel in QEMU"
	@echo "  make run-debug- Run debug kernel in QEMU (no reboot on crash)"
	@echo ""
	@echo "  make test     - Run cargo tests (host)"
	@echo "  make disk-image - Build the virtio-blk test disk (target/disk.img)"
	@echo "  make check    - Boot kernel in QEMU, verify tests pass"
	@echo "  make check LOCKDEP=1 - Same with lockdep-lite (LOCKDEP:FAIL reports)"
	@echo ""
	@echo "  make build-arm - Build ARM64 kernel"
	@echo "  make run-arm   - Run ARM64 kernel in QEMU"
	@echo "  make check-arm - Boot ARM64 kernel, verify tests pass"
	@echo "  make check-linux - Run boot tests on a real Linux kernel (native arch)"
	@echo "  make check-linux-arm - Same, aarch64 Linux (emulated on x86 hosts)"
	@echo ""
	@echo "  make clippy   - Run clippy linter (x86-64)"
	@echo "  make clippy-arm - Run clippy linter (aarch64)"
	@echo "  make fmt      - Format code"
	@echo ""
	@echo "  make clean    - Remove all build artifacts"
	@echo "  make info     - Show kernel binary info"

build:
	cargo build -p hk-kernel --target $(TARGET) --release $(KERNEL_FEATURES)

debug:
	cargo build -p hk-kernel --target $(TARGET) $(KERNEL_FEATURES)

user:
	$(MAKE) -C user

# Create a small FAT32 test image with test files
# Requires: dosfstools (mkfs.vfat), mtools (mcopy, mmd)
vfat-image:
	@mkdir -p target
	@dd if=/dev/zero of=$(VFAT_IMAGE) bs=1K count=$(VFAT_SIZE_KB) 2>/dev/null
	@mkfs.vfat -F 32 -n "VFAT_TEST" $(VFAT_IMAGE) >/dev/null
	@echo "Hello from FAT32!" | mcopy -i $(VFAT_IMAGE) - ::HELLO.TXT
	@mmd -i $(VFAT_IMAGE) ::TESTDIR
	@echo "Nested file content" | mcopy -i $(VFAT_IMAGE) - ::TESTDIR/NESTED.TXT
	@echo "Created $(VFAT_IMAGE) with test files"

# Rebuilt when the script changes
disk-image: $(DISK_IMAGE)

$(DISK_IMAGE): tools/mkdisk.sh
	@tools/mkdisk.sh $@

iso: build user vfat-image
	@mkdir -p target/iso/boot/grub
	@cp $(KERNEL) target/iso/boot/kernel
	@cp user/initramfs-x86_64.cpio target/iso/boot/initramfs.cpio
	@cp $(VFAT_IMAGE) target/iso/boot/vfat.img
ifdef MACHINE
	@if [ ! -f "boot/machines/$(MACHINE)/grub.cfg" ]; then \
		echo "Error: Machine '$(MACHINE)' not found (missing boot/machines/$(MACHINE)/grub.cfg)"; \
		exit 1; \
	fi
	@cp boot/machines/$(MACHINE)/grub.cfg target/iso/boot/grub/grub.cfg
	@grub-mkrescue -o target/$(MACHINE).iso target/iso 2>/dev/null
	@echo "Created target/$(MACHINE).iso"
else
	@cp boot/grub.cfg target/iso/boot/grub/grub.cfg
	@grub-mkrescue -o target/hk-x86_64.iso target/iso 2>/dev/null
endif

iso-debug: debug user vfat-image
	@mkdir -p target/iso/boot/grub
	@cp $(KERNEL_DEBUG) target/iso/boot/kernel
	@cp user/initramfs-x86_64.cpio target/iso/boot/initramfs.cpio
	@cp $(VFAT_IMAGE) target/iso/boot/vfat.img
ifdef MACHINE
	@if [ ! -f "boot/machines/$(MACHINE)/grub.cfg" ]; then \
		echo "Error: Machine '$(MACHINE)' not found (missing boot/machines/$(MACHINE)/grub.cfg)"; \
		exit 1; \
	fi
	@cp boot/machines/$(MACHINE)/grub.cfg target/iso/boot/grub/grub.cfg
	@grub-mkrescue -o target/$(MACHINE)-debug.iso target/iso 2>/dev/null
	@echo "Created target/$(MACHINE)-debug.iso"
else
	@cp boot/grub.cfg target/iso/boot/grub/grub.cfg
	@grub-mkrescue -o target/hk-x86_64.iso target/iso 2>/dev/null
endif

# List available machine configurations
list-machines:
	@echo "Available machines for ISO builds:"
	@for dir in boot/machines/*/; do \
		name=$$(basename "$$dir"); \
		if [ -f "$$dir/grub.cfg" ]; then \
			echo "  - $$name (make iso MACHINE=$$name)"; \
		fi; \
	done

run: iso disk-image
	@if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then \
		echo "QEMU not found. Install with: sudo apt install qemu-system-x86"; \
		exit 1; \
	fi
	./run-qemu.sh

run-debug: iso-debug disk-image
	@if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then \
		echo "QEMU not found. Install with: sudo apt install qemu-system-x86"; \
		exit 1; \
	fi
	./run-qemu.sh -d

test:
	cargo test -p hk-kernel

# QEMU boot test timeout in seconds (TCG on CI hosts without KVM is slow)
# Bounds hangs only; the full suite takes ~1 min locally, longer on CI
BOOT_TEST_TIMEOUT ?= 600

# QEMU -cpu override for the boot tests (see run-qemu.sh), e.g. QEMU_CPU=max
export QEMU_CPU

# hk boot test NIC (see run-qemu.sh): virtio (default) or e1000
export NIC

# NO_KVM=1: force TCG on x86 (CI's conditions)
export NO_KVM

# Serial logs, per tree (so worktrees and parallel boots don't collide)
QEMU_LOG_DIR ?= $(CURDIR)/target/qemu
export QEMU_LOG_DIR
SERIAL_LOG = $(QEMU_LOG_DIR)/serial.log
SERIAL_LOG_ARM = $(QEMU_LOG_DIR)/serial_arm.log

check: iso disk-image
	@rm -f $(SERIAL_LOG)
	@echo "Running boot test ($(BOOT_TEST_TIMEOUT) second timeout)..."
	@./run-qemu.sh -t -T $(BOOT_TEST_TIMEOUT)
	@if [ ! -f $(SERIAL_LOG) ]; then \
		echo "Boot test FAILED - QEMU did not create serial log"; \
		exit 1; \
	elif ! grep -q "Powering off" $(SERIAL_LOG); then \
		echo "Boot test FAILED - 'Powering off' not found in serial log:"; \
		cat $(SERIAL_LOG); \
		exit 1; \
	elif grep -q "FAIL" $(SERIAL_LOG); then \
		echo "Boot test FAILED - test failures detected:"; \
		grep "FAIL" $(SERIAL_LOG); \
		exit 1; \
	else \
		echo "Boot test PASSED"; \
	fi

clean:
	cargo clean
	$(MAKE) -C user clean

info: build
	@echo "Kernel: $(KERNEL)"
	@ls -la $(KERNEL)
	@file $(KERNEL)

# ============================================================================
# ARM64 (AArch64) targets
# ============================================================================

user-arm:
	$(MAKE) -C user ARCH=aarch64

build-arm: user-arm
	cargo build -p hk-kernel --target $(TARGET_ARM) --release $(KERNEL_FEATURES)

run-arm: build-arm vfat-image disk-image
	./run-qemu.sh --arch arm

check-arm: build-arm vfat-image disk-image
	@rm -f $(SERIAL_LOG_ARM)
	@echo "Running ARM boot test ($(BOOT_TEST_TIMEOUT) second timeout)..."
	@./run-qemu.sh --arch arm -t -T $(BOOT_TEST_TIMEOUT)
	@if [ ! -f $(SERIAL_LOG_ARM) ]; then \
		echo "ARM Boot test FAILED - QEMU did not create serial log"; \
		exit 1; \
	elif ! grep -qE "(Powering off|System shutdown via PSCI)" $(SERIAL_LOG_ARM); then \
		echo "ARM Boot test FAILED - shutdown message not found in serial log:"; \
		cat $(SERIAL_LOG_ARM); \
		exit 1; \
	elif grep -q "FAIL" $(SERIAL_LOG_ARM); then \
		echo "ARM Boot test FAILED - test failures detected:"; \
		grep "FAIL" $(SERIAL_LOG_ARM); \
		exit 1; \
	else \
		echo "ARM Boot test PASSED"; \
	fi

# Differential test: boot_tester as init on a real Linux kernel (native arch)
# Bounds hangs only; emulated aarch64 Linux takes ~150s, more in parallel
LINUX_TEST_TIMEOUT ?= 300
check-linux: disk-image
	./tools/linux-boot-tester.sh -T $(LINUX_TEST_TIMEOUT)

# Same, aarch64 Linux emulated on any host (for local iteration on x86)
check-linux-arm: disk-image
	./tools/linux-boot-tester.sh -a aarch64 -T $(LINUX_TEST_TIMEOUT)

info-arm: build-arm
	@echo "ARM Kernel: $(KERNEL_ARM)"
	@ls -la $(KERNEL_ARM)
	@file $(KERNEL_ARM)

# ============================================================================
# Code quality targets
# ============================================================================

# Extra clippy args, e.g. CLIPPY_FLAGS="-D warnings" (CI)
CLIPPY_FLAGS ?=

# Run clippy for x86-64 kernel (must specify target for no_std)
clippy:
	cargo clippy --target $(TARGET) -p hk-kernel -- $(CLIPPY_FLAGS)

# Run clippy for aarch64 kernel
clippy-arm: user-arm
	cargo clippy --target $(TARGET_ARM) -p hk-kernel -- $(CLIPPY_FLAGS)

# Format all code
fmt:
	cargo fmt

# Check formatting without modifying
fmt-check:
	cargo fmt --check
