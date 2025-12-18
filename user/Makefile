# Userspace build for hk kernel
#
# Builds boot_tester and boot_tester2 (Rust no_std) and creates initramfs.cpio
#
# Usage:
#   make              - Build for x86_64 (default)
#   make ARCH=aarch64 - Build for aarch64

# Architecture selection (default: x86_64)
ARCH ?= x86_64

ifeq ($(ARCH),aarch64)
    TARGET = aarch64-unknown-linux-gnu
    INITRAMFS = initramfs-aarch64.cpio
else
    TARGET = x86_64-unknown-linux-gnu
    INITRAMFS = initramfs-x86_64.cpio
endif

CARGO = cargo

# Output files
BOOT_TESTER = target/$(TARGET)/release/boot_tester
BOOT_TESTER2 = target/$(TARGET)/release/boot_tester2
INITRD_ROOT = initrd-root

.PHONY: all clean boot_tester initramfs

all: $(INITRAMFS)

boot_tester: $(BOOT_TESTER) $(BOOT_TESTER2)

$(BOOT_TESTER): boot_tester.rs syscall/mod.rs syscall/$(ARCH).rs Cargo.toml
	$(CARGO) build --release --target $(TARGET)

$(BOOT_TESTER2): boot_tester2.rs syscall/mod.rs syscall/$(ARCH).rs Cargo.toml
	$(CARGO) build --release --target $(TARGET)

$(INITRAMFS): $(BOOT_TESTER) $(BOOT_TESTER2)
	@rm -rf $(INITRD_ROOT)
	@mkdir -p $(INITRD_ROOT)/bin
	@mkdir -p $(INITRD_ROOT)/mnt
	cp $(BOOT_TESTER) $(INITRD_ROOT)/bin/boot_tester
	cp $(BOOT_TESTER2) $(INITRD_ROOT)/bin/boot_tester2
	ln -sf boot_tester $(INITRD_ROOT)/bin/init
	echo -n "Hello from ramfs!" > $(INITRD_ROOT)/test.txt
	cd $(INITRD_ROOT) && find . | cpio -o -H newc > ../$(INITRAMFS) 2>/dev/null
	@rm -rf $(INITRD_ROOT)
	@echo "Created $(INITRAMFS)"
	@ls -la $(INITRAMFS)

clean:
	$(CARGO) clean
	rm -f initramfs-*.cpio
	rm -rf $(INITRD_ROOT)
