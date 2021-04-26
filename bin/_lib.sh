#!/bin/bash

set -euo pipefail

HUB_IP_TTL=300

start_wireguard() {
	iface="$1"
	conf="${FARCASTER_PATH}/etc/${iface}.conf"

	test -e "${conf}" || { echo "Could not find config ${conf}"; return 1; }

	if ! setup_wireguard_iface "${iface}"; then
        echo "Error setting up Wireguard interface!"
        return 1
    fi

	WG_SUDO=1 \
	WG_THREADS=2 \
	WG_LOG_LEVEL=info WG_LOG_FILE=/dev/stdout \
	WG_ERR_LOG_FILE=/dev/stderr \
	wg-quick up "${conf}"
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

start_dnsmasq() {
    rundir=/run/dnsmasq
    lport=1053
    mkdir -p ${rundir}
    chmod 0711 ${rundir}
    dnsmasq -x ${rundir}/dnsmasq.pid -p "${lport}" -i "${WG_GW_IF}"
    gw_addr="$(get_wg_addr "${WG_GW_IF}")"
    for proto in tcp udp; do
        iptables -t nat -I PREROUTING -i "${WG_GW_IF}" -p ${proto} \
            --dport 53 -j DNAT --to-destination "${gw_addr}:${lport}"
        iptables -t filter -I INPUT -i "${WG_GW_IF}" -p ${proto} \
            -d "${gw_addr}" --dport "${lport}" -j ACCEPT
    done
}

get_proxy_username() {
	echo "${HTTP_PROXY:-}" |
		sed -r 's/^http(s)?\:\/\///' |
		grep '@' |
		sed 's/@[^@]*$//' |
		cut -d ':' -f 1 || echo ""
}

get_proxy_password() {
	echo "${HTTP_PROXY:-}" |
		sed -r 's/^http(s)?\:\/\///' |
		grep '@' |
		sed 's/@[^@]*$//' |
		cut -d ':' -f 2 || echo ""
}

get_proxy_address() {
	echo "${HTTP_PROXY:-}" |
		sed -r 's/^http(s)?\:\/\///' |
        sed -r 's/\/.*//' |
		sed 's/^.*@//'
}


get_proxy_host() {
	echo "$1" |
		sed -r 's/^http(s)?\:\/\///' |
        cut -d ':' -f 1
}

get_proxy_port() {
    port=$(echo "$1" | grep ':' | cut -d ':' -f 2)
    if [ "${port}" = "" ]; then
        port="8080"
    fi
    echo "${port}"
}


create_moproxy_config() {
    config_path="$1"
    user=$(get_proxy_username)
    password=$(get_proxy_password)
    address=$(get_proxy_address)
    host=$(get_proxy_host "${address}")
    ipaddr=$(dig +short "${host}" || echo "")
    ipaddr=$(test ! -z "${ipaddr}" && echo "${ipaddr}" || echo "${host}")
    port=$(get_proxy_port "${address}")
    auth=$(test ! -z "${user}" && printf "http username = ${user}\nhttp password = ${password}\n" || echo "")

    umask 033
    cat << EOF > ${config_path}
[default]
address=${ipaddr}:${port}
protocol=http
test dns=127.0.0.1:53
listen ports=1080
${auth}
EOF
}

set_proxy_redirect_rules() {
    proxy_port="$1"
    gw_addr="$(get_wg_addr "${WG_GW_IF}")"
    iptables -t nat -N PROXY-REDIRECT
    for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
        iptables -t nat -A PROXY-REDIRECT -d ${net} -j RETURN
    done
    iptables -t nat -A PROXY-REDIRECT -p tcp -j REDIRECT --to-port ${proxy_port}
    iptables -t nat -I PREROUTING -i "${WG_GW_IF}" -j PROXY-REDIRECT
    iptables -t filter -I INPUT -i "${WG_GW_IF}" -p tcp -d "${gw_addr}" --dport "${proxy_port}" -j ACCEPT
}

start_moproxy_maybe() {
    proxy_port=1080
    test -z ${HTTP_PROXY:-} && return 0
    rundir=/run/moproxy
    mkdir -p ${rundir}
    chmod 0711 ${rundir}
    config_path="${rundir}/config.ini"
    create_moproxy_config ${config_path}
    set_proxy_redirect_rules ${proxy_port}
    /bin/su -s /bin/sh -l proxy -c "exec /usr/bin/moproxy --port ${proxy_port} --list ${config_path}" &
    return 0
}

