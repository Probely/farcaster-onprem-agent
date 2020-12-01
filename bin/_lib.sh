#!/bin/sh

set -euo pipefail

HUB_IP_TTL=300

start_wireguard() {
	iface="$1"
	conf="${FARCASTER_PATH}/etc/${iface}.conf"

	test -e "${conf}" || return 1

	setup_wireguard_iface "${iface}"

	WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun \
		WG_SUDO=1 \
		WG_THREADS=2 \
		WG_LOG_LEVEL=info WG_LOG_FILE=/dev/stdout \
		WG_ERR_LOG_FILE=/dev/stderr \
		bash "${FARCASTER_PATH}/bin/wg-quick" up "${conf}"
}

get_wg_endpoint() {
	iface="$1"
	get_addr_from_conf ${iface} "^Endpoint\s*=\s*"
}

get_wg_addr() {
	iface="$1"
	get_addr_from_conf ${iface} "^Address\s*=\s*"
}

get_addr_from_conf() {
	iface="$1"
	regex="$2"
	conf="${FARCASTER_PATH}/etc/${iface}.conf"

	grep "${regex}" "${conf}" |
		sed "s/${regex}//g" |
		head -1 |
		cut -d ':' -f 1 |
		cut -d '/' -f 1
	return $?
}

wait_for_iface() {
	while ! ip link show "$1"; do
		echo "Waiting for $1 to come up..."
		sleep 1
	done
	return 0
}

get_iface_addr() {
	ip addr show "$1" | grep "\s*inet " | awk -F' ' '{print $2}'
}

resolve_host() {
	host="$1"
	echo "$(dig +short ${host} | grep '^[.0-9]*$' | sort)"
	return $?
}

HUB_IP_CHECK_TS=
HUB_IP=
is_hub_ip_fresh() {
	[ -z "${HUB_IP_CHECK_TS}" ] && return 1
	now="$(date "+%s")"
	[ $((now - HUB_IP_CHECK_TS)) -lt ${HUB_IP_TTL} ]
	return $?
}

check_hub_ip() {
	iface="$1"
	if is_hub_ip_fresh; then
		return 0
	fi
	host="$(get_wg_endpoint ${iface})"
	cur_ip="$(resolve_host ${host})"
	if [ -z "${HUB_IP}" ]; then
		HUB_IP="${cur_ip}"
	elif [ "${cur_ip}" != "$HUB_IP" ]; then
		return 1
	fi
	HUB_IP_CHECK_TS="$(date "+%s")"
	return 0
}

watch_wireguard() {
	iface="$1"
	check_hub=$2
	while true; do
		sleep 5
		if ! ip link show dev "${iface}" >/dev/null 2>&1; then
			echo "${iface} interface is down. Exiting..."
			return 1
		fi
		if [ ${check_hub} -ne 0 ] && ! check_hub_ip "${iface}"; then
			echo "Farcaster Hub address has changed. Exiting..."
			return 0
		fi
	done
}

wait_for_dev_tun() {
	while [ ! -c /dev/net/tun ]; do
		echo "Waiting for tun device to become available..."
		sleep 1
	done
}

create_dev_tun() {
	[ -c /dev/net/tun ] && return 0
	mkdir -p /dev/net
	mknod /dev/net/tun c 10 200
	return $?
}

setup_wireguard_iface() {
	iface="$1"

	# Check if the kernel has wireguard support
	ip link add "${iface}" type wireguard 2>/dev/null &&
		ip link del "${iface}" &&
		return 0

	create_dev_tun
	return $?
}
