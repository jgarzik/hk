#!/bin/sh
# busybox udhcpc event script (udhcpc -s /etc/udhcpc.sh): configures the
# lease with `ip` (netlink) and writes /etc/resolv.conf
RESOLV_CONF=/etc/resolv.conf

case "$1" in
deconfig)
	ip -4 addr flush dev "$interface"
	ip link set dev "$interface" up
	;;
bound | renew)
	ip -4 addr flush dev "$interface"
	ip addr add "$ip/${mask:-24}" ${broadcast:+broadcast "$broadcast"} dev "$interface"
	for r in $router; do
		ip route add default via "$r" dev "$interface"
		break
	done
	: >"$RESOLV_CONF"
	[ -n "$domain" ] && echo "search $domain" >>"$RESOLV_CONF"
	for d in $dns; do
		echo "nameserver $d" >>"$RESOLV_CONF"
	done
	;;
esac
exit 0
