# Shared QEMU user-mode (slirp) network options, sourced by run-qemu.sh
# (hk) and tools/linux-boot-tester.sh (Linux), so both kernels see the
# same network: guest 10.0.2.15/24 by convention, gateway 10.0.2.2, DNS
# 10.0.2.3, no IPv6 (ipv6=off). Test peers without host ports (slirp
# guestfwd runs a command once per connection, verified on QEMU 8.2):
#   10.0.2.100:7   TCP echo (`cat`)
#   10.0.2.100:80  HTTP/1.0 (tools/netpeer/http.py, fixed body)
# QEMU_NET_EXTRA appends options.
#
# Usage: qemu_net_args <device-model>   (e.g. e1000, virtio-net-pci)
# Sets the QEMU_NET array.
QEMU_NET_PEERS=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/netpeer

qemu_net_args() {
    local fwd="guestfwd=tcp:10.0.2.100:7-cmd:cat"
    fwd+=",guestfwd=tcp:10.0.2.100:80-cmd:python3 -I $QEMU_NET_PEERS/http.py"
    QEMU_NET=(
        -netdev "user,id=n0,ipv6=off,$fwd${QEMU_NET_EXTRA:+,$QEMU_NET_EXTRA}"
        -device "$1,netdev=n0"
    )
}
