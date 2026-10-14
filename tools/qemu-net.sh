# Shared QEMU user-mode (slirp) network options, sourced by run-qemu.sh
# (hk) and tools/linux-boot-tester.sh (Linux), so both kernels see the
# same network: guest 10.0.2.15/24 by convention, gateway 10.0.2.2, DNS
# 10.0.2.3, no IPv6 (ipv6=off). Test peers without host ports: TCP to
# 10.0.2.100:7 is an echo service (slirp guestfwd runs `cat` once per
# connection; verified on QEMU 8.2). QEMU_NET_EXTRA appends options.
#
# Usage: qemu_net_args <device-model>   (e.g. e1000, virtio-net-pci)
# Sets the QEMU_NET array.
qemu_net_args() {
    QEMU_NET=(
        -netdev "user,id=n0,ipv6=off,guestfwd=tcp:10.0.2.100:7-cmd:cat${QEMU_NET_EXTRA:+,$QEMU_NET_EXTRA}"
        -device "$1,netdev=n0"
    )
}
