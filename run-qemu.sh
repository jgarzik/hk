#!/bin/bash
# Run hk kernel in QEMU (unified for x86-64 and AArch64)
#
# Usage: ./run-qemu.sh [options]
#   --arch ARCH  Select architecture: x86 (default) or arm
#   -d           Enable debug (no reboot on crash)
#   -g           Enable GDB server on port 1234
#   -t           Test mode (exit after timeout, used by make check)
#   -T N         Timeout in seconds for test mode (default: 30)
#   -u           USB serial console mode (x86 only, for make check-usb)
#
# Serial output:
#   x86: /tmp/qemu_serial.log (or /tmp/qemu_usb_serial.log with -u)
#   arm: /tmp/qemu_serial_arm.log

set -e

# Default options
ARCH="x86"
DEBUG_MODE=false
GDB_MODE=false
TEST_MODE=false
TIMEOUT=30
USB_CONSOLE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --arch)
            ARCH="$2"
            shift 2
            ;;
        -d)
            DEBUG_MODE=true
            shift
            ;;
        -g)
            GDB_MODE=true
            shift
            ;;
        -t)
            TEST_MODE=true
            shift
            ;;
        -T)
            TIMEOUT="$2"
            shift 2
            ;;
        -u)
            USB_CONSOLE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--arch x86|arm] [-d] [-g] [-t] [-T seconds] [-u]"
            echo "  --arch ARCH  Architecture: x86 (default) or arm"
            echo "  -d           Debug mode (no reboot on crash)"
            echo "  -g           Enable GDB server on port 1234"
            echo "  -t           Test mode (run with timeout, log to file)"
            echo "  -T seconds   Timeout in seconds (default: 30)"
            echo "  -u           USB serial console mode (x86 only)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate architecture
if [[ "$ARCH" != "x86" && "$ARCH" != "arm" ]]; then
    echo "Error: Invalid architecture '$ARCH'. Use 'x86' or 'arm'."
    exit 1
fi

# Architecture-specific configuration
setup_x86_config() {
    QEMU_BIN="qemu-system-x86_64"
    ISO="target/hk-x86_64.iso"
    SERIAL_LOG="/tmp/qemu_serial.log"
    USB_SERIAL_LOG="/tmp/qemu_usb_serial.log"

    # Check if ISO exists
    if [ ! -f "$ISO" ]; then
        echo "Error: ISO not found at $ISO"
        echo "Run 'make iso' first"
        exit 1
    fi

    # Base QEMU arguments
    # Use KVM if available for proper CPU feature support (invtsc)
    # Fall back to TCG (software emulation) if KVM not available
    if [ -w /dev/kvm ]; then
        QEMU_ARGS=(
            -enable-kvm
            -cpu host
            -cdrom "$ISO"
            -boot d
            -nographic
            -m 512M
            -smp 4
        )
    else
        QEMU_ARGS=(
            -cpu qemu64
            -cdrom "$ISO"
            -boot d
            -nographic
            -m 512M
            -smp 4
        )
    fi

    # Serial configuration
    if [ "$USB_CONSOLE" = true ]; then
        # USB serial console mode: USB serial is primary, standard serial disabled
        QEMU_ARGS+=(
            -serial null
            -device qemu-xhci,id=xhci
            -chardev file,id=usbserial0,path="$USB_SERIAL_LOG"
            -device usb-serial,chardev=usbserial0
        )
        SERIAL_LOG="$USB_SERIAL_LOG"
    else
        # Standard mode: regular serial console, USB devices present
        QEMU_ARGS+=(
            -serial file:"$SERIAL_LOG"
            -device qemu-xhci,id=xhci
            -chardev file,id=usbserial0,path="$USB_SERIAL_LOG"
            -device usb-serial,chardev=usbserial0
        )
    fi

    # Add USB mass storage device if vfat.img exists
    VFAT_IMG="target/vfat.img"
    if [ -f "$VFAT_IMG" ]; then
        QEMU_ARGS+=(
            -drive id=usbdisk,if=none,format=raw,file="$VFAT_IMG"
            -device usb-storage,drive=usbdisk,bus=xhci.0
        )
    fi
}

setup_arm_config() {
    QEMU_BIN="qemu-system-aarch64"
    KERNEL="target/aarch64-unknown-none/release/kernel"
    INITRAMFS="user/initramfs-aarch64.cpio"
    SERIAL_LOG="/tmp/qemu_serial_arm.log"

    # Check if kernel exists
    if [ ! -f "$KERNEL" ]; then
        echo "Error: Kernel not found at $KERNEL"
        echo "Run 'make build-arm' first"
        exit 1
    fi

    # Check if initramfs exists
    if [ ! -f "$INITRAMFS" ]; then
        echo "Error: Initramfs not found at $INITRAMFS"
        echo "Run 'cd user && make ARCH=aarch64' first"
        exit 1
    fi

    # USB console mode not supported on ARM
    if [ "$USB_CONSOLE" = true ]; then
        echo "Warning: USB console mode (-u) not supported on ARM, ignoring"
        USB_CONSOLE=false
    fi

    # Base QEMU arguments
    QEMU_ARGS=(
        -machine virt,gic-version=3
        -cpu cortex-a72
        -smp 4
        -m 512M
        -kernel "$KERNEL"
        -initrd "$INITRAMFS"
        -nographic
    )

    # Serial configuration (test vs interactive)
    if [ "$TEST_MODE" = true ]; then
        QEMU_ARGS+=(-serial file:"$SERIAL_LOG")
    else
        QEMU_ARGS+=(-serial mon:stdio)
    fi

    # Add xHCI USB controller
    QEMU_ARGS+=(-device qemu-xhci,id=xhci)

    # Add USB mass storage device if vfat.img exists
    VFAT_IMG="target/vfat.img"
    if [ -f "$VFAT_IMG" ]; then
        QEMU_ARGS+=(
            -drive id=usbdisk,if=none,format=raw,file="$VFAT_IMG"
            -device usb-storage,drive=usbdisk,bus=xhci.0
        )
    fi
}

# Check QEMU availability
check_qemu() {
    if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
        if [ "$ARCH" = "x86" ]; then
            echo "QEMU not found. Install with: sudo apt install qemu-system-x86"
        else
            echo "QEMU not found. Install with: sudo apt install qemu-system-arm"
        fi
        exit 1
    fi
}

# Setup configuration based on architecture
if [ "$ARCH" = "x86" ]; then
    setup_x86_config
else
    setup_arm_config
fi

check_qemu

# Add debug options
if [ "$DEBUG_MODE" = true ]; then
    QEMU_ARGS+=(-no-reboot -no-shutdown)
fi

# Add GDB options
if [ "$GDB_MODE" = true ]; then
    QEMU_ARGS+=(-s -S)
fi

# Run QEMU
if [ "$TEST_MODE" = true ]; then
    # Test mode: run with timeout
    # -no-reboot: exit instead of reboot on triple fault (x86)
    # </dev/null: detach stdin to avoid TTY issues when run from make
    if [ "$ARCH" = "x86" ]; then
        QEMU_ARGS+=(-no-reboot)
    fi

    rm -f "$SERIAL_LOG"
    echo "Starting QEMU ($ARCH) with ${TIMEOUT}s timeout..."
    timeout "$TIMEOUT" "$QEMU_BIN" "${QEMU_ARGS[@]}" </dev/null || true

    # Ensure file buffers are flushed
    sync
    sleep 0.5

    # Check if serial log was created
    if [ -f "$SERIAL_LOG" ]; then
        echo "Serial output saved to $SERIAL_LOG"
    else
        echo "Warning: Serial log not created at $SERIAL_LOG"
    fi
else
    # Interactive mode
    if [ "$ARCH" = "x86" ]; then
        echo "Starting QEMU (x86)..."
    else
        echo "Starting QEMU (ARM, Ctrl-A X to exit)..."
    fi
    "$QEMU_BIN" "${QEMU_ARGS[@]}"
fi
