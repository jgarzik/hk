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

.PHONY: all build debug user iso iso-debug run run-debug test check clean info help vfat-image
.PHONY: build-arm run-arm check-arm user-arm clippy clippy-arm fmt

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
	@echo ""
	@echo "  make run      - Run kernel in QEMU"
	@echo "  make run-debug- Run debug kernel in QEMU (no reboot on crash)"
	@echo ""
	@echo "  make test     - Run cargo tests (host)"
	@echo "  make check    - Boot kernel in QEMU, verify tests pass"
	@echo ""
	@echo "  make build-arm - Build ARM64 kernel"
	@echo "  make run-arm   - Run ARM64 kernel in QEMU"
	@echo "  make check-arm - Boot ARM64 kernel, verify tests pass"
	@echo ""
	@echo "  make clippy   - Run clippy linter (x86-64)"
	@echo "  make clippy-arm - Run clippy linter (aarch64)"
	@echo "  make fmt      - Format code"
	@echo ""
	@echo "  make clean    - Remove all build artifacts"
	@echo "  make info     - Show kernel binary info"

build:
	cargo build -p hk-kernel --target $(TARGET) --release

debug:
	cargo build -p hk-kernel --target $(TARGET)

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

iso: build user vfat-image
	@mkdir -p target/iso/boot/grub
	@cp $(KERNEL) target/iso/boot/kernel
	@cp user/initramfs-x86_64.cpio target/iso/boot/initramfs.cpio
	@cp $(VFAT_IMAGE) target/iso/boot/vfat.img
	@cp boot/grub.cfg target/iso/boot/grub/grub.cfg
	@grub-mkrescue -o target/hk-x86_64.iso target/iso 2>/dev/null

iso-debug: debug user vfat-image
	@mkdir -p target/iso/boot/grub
	@cp $(KERNEL_DEBUG) target/iso/boot/kernel
	@cp user/initramfs-x86_64.cpio target/iso/boot/initramfs.cpio
	@cp $(VFAT_IMAGE) target/iso/boot/vfat.img
	@cp boot/grub.cfg target/iso/boot/grub/grub.cfg
	@grub-mkrescue -o target/hk-x86_64.iso target/iso 2>/dev/null

run: iso
	@if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then \
		echo "QEMU not found. Install with: sudo apt install qemu-system-x86"; \
		exit 1; \
	fi
	./run-qemu.sh

run-debug: iso-debug
	@if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then \
		echo "QEMU not found. Install with: sudo apt install qemu-system-x86"; \
		exit 1; \
	fi
	./run-qemu.sh -d

test:
	cargo test --all

check: iso
	@rm -f /tmp/qemu_serial.log
	@echo "Running boot test (30 second timeout)..."
	@./run-qemu.sh -t -T 30
	@if [ ! -f /tmp/qemu_serial.log ]; then \
		echo "Boot test FAILED - QEMU did not create serial log"; \
		exit 1; \
	elif grep -q "Powering off" /tmp/qemu_serial.log; then \
		echo "Boot test PASSED"; \
	else \
		echo "Boot test FAILED - 'Powering off' not found in serial log:"; \
		cat /tmp/qemu_serial.log; \
		exit 1; \
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
	cargo build -p hk-kernel --target $(TARGET_ARM) --release

run-arm: build-arm
	./run-qemu.sh --arch arm

check-arm: build-arm
	@rm -f /tmp/qemu_serial_arm.log
	@echo "Running ARM boot test (30 second timeout)..."
	@./run-qemu.sh --arch arm -t -T 30
	@if [ ! -f /tmp/qemu_serial_arm.log ]; then \
		echo "ARM Boot test FAILED - QEMU did not create serial log"; \
		exit 1; \
	elif grep -qE "(Powering off|System shutdown via PSCI)" /tmp/qemu_serial_arm.log; then \
		echo "ARM Boot test PASSED"; \
	else \
		echo "ARM Boot test FAILED - shutdown message not found in serial log:"; \
		cat /tmp/qemu_serial_arm.log; \
		exit 1; \
	fi

info-arm: build-arm
	@echo "ARM Kernel: $(KERNEL_ARM)"
	@ls -la $(KERNEL_ARM)
	@file $(KERNEL_ARM)

# ============================================================================
# Code quality targets
# ============================================================================

# Run clippy for x86-64 kernel (must specify target for no_std)
clippy:
	cargo clippy --target $(TARGET) -p hk-kernel

# Run clippy for aarch64 kernel
clippy-arm:
	cargo clippy --target $(TARGET_ARM) -p hk-kernel

# Format all code
fmt:
	cargo fmt

# Check formatting without modifying
fmt-check:
	cargo fmt --check
