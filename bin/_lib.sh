#!/usr/bin/env bash

set -euo pipefail

PROXY_REGEXP='^(http(s)?://)?(([0-9a-zA-Z_-]+:[0-9a-zA-Z_-]+)@)?([0-9a-zA-Z._-]+)(:([0-9]+))?$'
WORKDIR=/run/farcaster
HUB_IP_TTL=300

wg_setup_iface() {
	iface="$1"

	# Check if the kernel has wireguard support
	ip link add "${iface}" type wireguard 2>/dev/null &&
	ip link del "${iface}" &&
	return 0

	create_dev_tun
	return $?
}

wg_start() {
	iface="$1"
	conf="${FARCASTER_PATH}/etc/${iface}.conf"
	test -e "${conf}" || { echo "Could not find config ${conf}"; return 1; }

	if ! wg_setup_iface "${iface}"; then
		return 1
	fi

	WG_SUDO=1 \
	WG_THREADS=2 \
	WG_LOG_LEVEL=info WG_LOG_FILE=/dev/stdout \
	WG_ERR_LOG_FILE=/dev/stderr \
	wg-quick up "${conf}"
}

wg_stop() {
	iface="$1"
	conf="${FARCASTER_PATH}/etc/${iface}.conf"
	test -e "${conf}" || { echo "Could not find config ${conf}"; return 1; }

	wg-quick down "${conf}"
}

wg_update_endpoint() {
	iface="$1"
	endpoint="$2"
	conf="${WORKDIR}/${iface}.conf"
	test -e "${conf}" || { echo "Could not find config ${conf}"; return 1; }

	sed -i "s/^Endpoint\s*=.*$/Endpoint = ${endpoint}/g" "${conf}"
}

wg_get_latest_handshake() {
	iface="$1"
	for i in $(seq 5); do
		handshake=$(wg show ${iface} latest-handshakes | awk -F' ' '{print $2}')
		[ "${handshake}" != "0" ] && echo "${handshake}" && return
		sleep 2
	done
	echo "0"
}

wg_get_endpoint() {
	iface="$1"
	get_addr_from_conf ${iface} "^Endpoint\s*=\s*"
}

wg_get_addr() {
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
	host="$(wg_get_endpoint ${iface})"
	cur_ip="$(resolve_host ${host})"
	if [ -z "${HUB_IP}" ]; then
		HUB_IP="${cur_ip}"
	elif [ "${cur_ip}" != "$HUB_IP" ]; then
		return 1
	fi
	HUB_IP_CHECK_TS="$(date "+%s")"
	return 0
}

wg_check_iface() {
	iface="$1"
	check_hub=$2
	if ! ip link show dev "${iface}" >/dev/null 2>&1; then
		echo "${iface} interface is down. Exiting..."
		return 1
	fi
	if [ ${check_hub} -ne 0 ] && ! check_hub_ip "${iface}"; then
		echo "Farcaster Hub address has changed. Exiting..."
		return 2
	fi
}

create_dev_tun() {
	[ -c /dev/net/tun ] && return 0
	mkdir -p /dev/net
	mknod /dev/net/tun c 10 200
	return $?
}

start_dnsmasq() {
	rundir=/run/dnsmasq
	lport=1053
	mkdir -p ${rundir}
	chmod 0711 ${rundir}
	dnsmasq -x ${rundir}/dnsmasq.pid -p "${lport}" -i "${WG_GW_IF}"
	gw_addr="$(wg_get_addr "${WG_GW_IF}")"
	for proto in tcp udp; do
		iptables -t nat -I PREROUTING -i "${WG_GW_IF}" -p ${proto} \
		    --dport 53 -j DNAT --to-destination "${gw_addr}:${lport}"
		iptables -t filter -I INPUT -i "${WG_GW_IF}" -p ${proto} \
		    -d "${gw_addr}" --dport "${lport}" -j ACCEPT
	done
}

get_proxy_username() {
	echo "${HTTP_PROXY:-}" |
	sed -e 's/^"//' -e 's/"$//' |
	sed -r 's/^http(s)?\:\/\///' |
	grep '@' |
	sed 's/@[^@]*$//' |
	cut -d ':' -f 1 || echo ""
}

get_proxy_password() {
	echo "${HTTP_PROXY:-}" |
	sed -e 's/^"//' -e 's/"$//' |
	sed -r 's/^http(s)?\:\/\///' |
	grep '@' |
	sed 's/@[^@]*$//' |
	cut -d ':' -f 2 || echo ""
}

get_proxy_address() {
	echo "${HTTP_PROXY:-}" |
	sed -e 's/^"//' -e 's/"$//' |
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

start_udp_over_tcp_tunnel() {
	local_udp_port="$1"
	remote_ip="$(resolve_host $2)"
	remote_tcp_port="$3"
	setpriv --reuid=tcptun --regid=tcptun --clear-groups --no-new-privs \
		/farcaster/bin/udp2tcp --tcp-forward ${remote_ip}:${remote_tcp_port} --udp-listen 127.0.0.1:${local_udp_port} > /dev/null 2>&1 &
	pid=$!
	sleep 2
	kill -0 ${pid} 2>/dev/null && echo "${pid}" || echo "-1"
}

create_moproxy_config() {
	config_path="$1"
	listen_port="$2"
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
listen ports=${listen_port}
${auth}
EOF
}

set_proxy_redirect_rules() {
	proxy_port="$1"
	gw_addr="$(wg_get_addr "${WG_GW_IF}")"
	# Proxy redirect chain
	iptables -t nat -N PROXY-REDIRECT
	for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
		iptables -t nat -A PROXY-REDIRECT -d ${net} -j RETURN
	done
	iptables -t nat -A PROXY-REDIRECT -p tcp -j REDIRECT --to-port ${proxy_port}

	# Remote traffic arriving in the tunnel
	iptables -t nat -I PREROUTING -i "${WG_GW_IF}" -j PROXY-REDIRECT

	# Local traffic from select users go through the proxy
	iptables -t nat -I OUTPUT -m owner --uid-owner tcptun -j PROXY-REDIRECT
	iptables -t nat -I OUTPUT -m owner --gid-owner diag -j PROXY-REDIRECT

	# Make sure traffic is allowed after being redirected
	iptables -t filter -I INPUT -i "${WG_GW_IF}" -p tcp -d "${gw_addr}" --dport "${proxy_port}" -j ACCEPT
}

function set_gw_filter_and_nat_rules() {
	iptables -N FARCASTER-FILTER
	iptables -A FARCASTER-FILTER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	iptables -A FARCASTER-FILTER -p icmp --fragment -j DROP
	iptables -A FARCASTER-FILTER -p icmp --icmp-type 3/4 -m conntrack \
		--ctstate ESTABLISHED,RELATED -j ACCEPT
	iptables -A FARCASTER-FILTER -p icmp --icmp-type 4 -m conntrack \
		--ctstate ESTABLISHED,RELATED -j ACCEPT
	iptables -A FARCASTER-FILTER -p icmp --icmp-type 8 -j ACCEPT

	iptables -F INPUT
	iptables -P INPUT DROP
	iptables -A INPUT -j FARCASTER-FILTER
	iptables -A INPUT -i lo -j ACCEPT
	iptables -A INPUT -i "${WG_TUN_IF}" -p udp --dport ${WG_DEFAULT_PORT} -j ACCEPT

	iptables -F FORWARD
	iptables -P FORWARD DROP
	iptables -A FORWARD -j FARCASTER-FILTER
	iptables -A FORWARD -i "${WG_GW_IF}" -j ACCEPT

	iptables -t nat -N FARCASTER-NAT
	iptables -t nat -A FARCASTER-NAT -o "${WG_TUN_IF}" -j RETURN
	iptables -t nat -A FARCASTER-NAT -o "${WG_GW_IF}" -j RETURN
	iptables -t nat -A FARCASTER-NAT -j MASQUERADE
	iptables -t nat -F POSTROUTING
	iptables -t nat -A POSTROUTING -j FARCASTER-NAT
}

start_proxy_maybe() {
	listen_port="$1"
	test -z ${HTTP_PROXY:-} && return 0
	rundir=/run/moproxy
	mkdir -p ${rundir}
	chmod 0711 ${rundir}
	config_path="${rundir}/config.ini"
	create_moproxy_config ${config_path} ${listen_port}
	set_proxy_redirect_rules ${proxy_port}
	setpriv --reuid=proxy --regid=proxy --clear-groups --no-new-privs \
		/usr/bin/moproxy --port ${proxy_port} --list ${config_path} &
	sleep 3
	kill -0 $!
	return $?
}

function print_log() {
	echo
	echo
	echo
	cat ${1}
	echo
	echo "===================================================================="
	echo
	echo
	echo "Could not start the agent. Please contact support@probely.com and"
	echo "attach this log to your message. "
	echo
	echo
	echo "===================================================================="
	echo
	sleep 120
}

