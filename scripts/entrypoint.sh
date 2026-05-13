#!/usr/bin/env bash

set -euo pipefail

WORKDIR=/run/farcaster
WG_DEFAULT_PORT=51820
SECRETS_DIR_V2="/secrets/farcaster/data_v2"
SECRETS_DIR_V0="/secrets/farcaster/data"
MAX_WG_HANDSHAKE_TTL=190

debug_level() {
	echo "${FARCASTER_DEBUG_LEVEL:-0}"
}

log_info() {
	printf "%s\tINFO\t%s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

log_warn() {
	printf "%s\tWARN\t%s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

log_error() {
	printf "%s\tERROR\t%s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

run_cmd() {
	local msg="$1"
	shift
	local output
	if ! output=$("$@" 2>&1); then
		log_error "${msg}: ${output//$'\n'/\\n}"
		return 1
	fi
}

check_iptables() {
	if iptables-nft -t filter -L >/dev/null 2>&1; then
		command -v iptables-nft
		return 0
	elif iptables-legacy -t filter -L >/dev/null 2>&1; then
		command -v iptables-legacy
		return 0
	fi
	return 1
}

check_kernel_wireguard() {
	return $(ip link add wg-test type wireguard 2>/dev/null &&
	         ip link del wg-test > /dev/null 2>&1)
}

wg_setup_iface() {
	iface="$1"
	if ip link add "${iface}" type wireguard 2>/dev/null; then
		ip link del "${iface}" && return 0
	fi
	return 1
}

wg_start() {
	iface="$1"
	conf="${FARCASTER_PATH}/etc/${iface}.conf"
	test -e "${conf}" || { log_error "Could not find config ${conf}"; return 1; }

	if ! wg_setup_iface "${iface}"; then
		return 1
	fi

	local output
	if ! output=$(WG_SUDO=1 \
		WG_THREADS=2 \
		WG_LOG_LEVEL=info \
		WG_LOG_FILE=/dev/stdout \
		WG_ERR_LOG_FILE=/dev/stderr \
		/bin/sh -c "wg-quick down ${conf} 2>/dev/null || true; wg-quick up ${conf}" 2>&1); then
		log_error "wg-quick ${iface}: ${output//$'\n'/\\n}"
		return 1
	fi
}

wg_get_latest_handshake() {
	iface="$1"
	# Must be >= 30s (hub peer-list refresh interval)
	timeout=35
	interval=5
	attempts=$((timeout / interval))
	for attempt in $(seq 1 ${attempts}); do
		log_info "WireGuard: waiting for UDP connection (${attempt}/${attempts})"
		for _ in $(seq 1 ${interval}); do
			handshake=$(wg show "${iface}" latest-handshakes | awk -F' ' '{print $2}')
			if [ "${handshake}" != "0" ]; then
				log_info "WireGuard: UDP connection established"
				return 0
			fi
			sleep 1
		done
	done
	log_warn "UDP connection timed out"
	return 1
}

wg_get_endpoint() {
	iface="$1"
	get_addr_from_conf "${iface}" "^Endpoint[ 	]*=[ 	]*"
}

wg_get_addr() {
	iface="$1"
	get_addr_from_conf "${iface}" "^Address[ 	]*=[ 	]*"
}

get_addr_from_conf() {
	iface="$1"
	regex="$2"
	conf="${FARCASTER_PATH}/etc/${iface}.conf"

	grep "${regex}" "${conf}" | awk -v re="${regex}" '{
		sub(re, "")
		gsub(/^[ \t]+|[ \t]+$/, "")
		if (match($0, /[[a-fA-F0-9:]+].*:/)) {
			sub(/]:[0-9]+$/, "")
			sub(/:[0-9]+$/, "")
		} else {
			sub(/:[0-9]+$/, "")
		}
		sub(/\/[0-9]+$/, "")
		print $0
		exit
	}'
	return $?
}

get_system_nameservers() {
	awk '/^nameserver/ {
		addr = $2
		if (index(addr, ":") > 0) addr = "[" addr "]:53"
		else addr = addr ":53"
		print addr
	}' /etc/resolv.conf | paste -sd, -
}

start_dns_forwarder() {
	lport=1053
	gw_addr="$(wg_get_addr "${WG_GW_IF}")"
	upstreams="$(get_system_nameservers)"
	if [ -z "${upstreams}" ]; then
		upstreams="127.0.0.11:53"
	fi

	setpriv --reuid=nobody --regid=nogroup --clear-groups --no-new-privs \
		farconn dns-forward --listen "${gw_addr}:${lport}" --upstream "${upstreams}" --no-ipv6 >/dev/null 2>&1 &
	DNS_PID=$!
	sleep 1
	if ! kill -0 ${DNS_PID} 2>/dev/null; then
		return 1
	fi

	for proto in tcp udp; do
		${IPT_CMD} -t nat -I PREROUTING -i "${WG_GW_IF}" -p ${proto} \
		    --dport 53 -j DNAT --to-destination "${gw_addr}:${lport}"
		${IPT_CMD} -t filter -I INPUT -i "${WG_GW_IF}" -p ${proto} \
		    -d "${gw_addr}" --dport "${lport}" -j ACCEPT
	done
}

set_gw_filter_rules() {
	${IPT_CMD} -N FARCASTER-FILTER
	${IPT_CMD} -A FARCASTER-FILTER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	${IPT_CMD} -A FARCASTER-FILTER -p icmp --fragment -j DROP
	${IPT_CMD} -A FARCASTER-FILTER -p icmp --icmp-type 3/4 -m conntrack \
		--ctstate ESTABLISHED,RELATED -j ACCEPT
	${IPT_CMD} -A FARCASTER-FILTER -p icmp --icmp-type 4 -m conntrack \
		--ctstate ESTABLISHED,RELATED -j ACCEPT
	${IPT_CMD} -A FARCASTER-FILTER -p icmp --icmp-type 8 -j ACCEPT

	${IPT_CMD} -P INPUT DROP
	${IPT_CMD} -A INPUT -j FARCASTER-FILTER
	${IPT_CMD} -A INPUT -i lo -j ACCEPT
	${IPT_CMD} -A INPUT -i "${WG_TUN_IF}" -p udp --dport ${WG_DEFAULT_PORT} -j ACCEPT

	${IPT_CMD} -P FORWARD DROP
	${IPT_CMD} -A FORWARD -j FARCASTER-FILTER
	${IPT_CMD} -A FORWARD -i "${WG_GW_IF}" -j ACCEPT
}

set_gw_nat_rules() {
	${IPT_CMD} -t nat -N FARCASTER-NAT
	${IPT_CMD} -t nat -A FARCASTER-NAT -o "${WG_TUN_IF}" -j RETURN
	${IPT_CMD} -t nat -A FARCASTER-NAT -o "${WG_GW_IF}" -j RETURN
	${IPT_CMD} -t nat -A FARCASTER-NAT -j MASQUERADE
	${IPT_CMD} -t nat -A POSTROUTING -j FARCASTER-NAT
}

print_diagnostics() {
	echo
	echo
	echo "-----addresses-----"
	ip addr show
	echo
	echo "-----routes-----"
	ip route show
	echo
	echo "-----iptables-----"
	if [ -x "${IPT_CMD:-}" ]; then
		${IPT_CMD} -t filter -n -L -v
		${IPT_CMD} -t nat -n -L -v
	fi
	echo
}

start_userspace_agent() {
	# Handle backwards compatibility for FARCASTER_PROXY_NAMES
	if [ -z "${FARCASTER_PROXY_NAMES:-}" ] && [ -n "${FARCASTER_PROXY_USE_HOSTNAMES:-}" ]; then
		export FARCASTER_PROXY_NAMES="${FARCASTER_PROXY_USE_HOSTNAMES}"
		log_warn "Using deprecated FARCASTER_PROXY_USE_HOSTNAMES, please update to FARCASTER_PROXY_NAMES"
	fi

	log_info "Starting Farcaster agent in userspace mode"

	if [ "$(debug_level)" -gt 0 ]; then
		print_diagnostics
	fi

	extra_args=""
	if [ "$(debug_level)" -gt 1 ]; then
		extra_args="-d"
	fi
	CMD="/usr/local/bin/farcasterd ${extra_args}"
	if [ "$(id -u)" -eq 0 ]; then
		log_info "Running as root, dropping privileges"
		CMD="setpriv --reuid=farcaster --regid=farcaster --clear-groups --no-new-privs ${CMD}"
	fi
	${CMD}
}

download_and_deploy_config() {
	log_info "Fetching agent configuration"
	if ! run_cmd "config-agent" farconn config-agent "${WORK_DIR}/"; then
		return 1
	fi
	log_info "Agent configuration deployed"
}

start_kernel_mode() {
	log_info "Starting in kernel mode"

	if ! run_cmd "create work directory ${WORK_DIR}" mkdir -pm 0700 "${WORK_DIR}"; then
		return 1
	fi

	FARCASTER_FORCE_TCP=${FARCASTER_FORCE_TCP:-0}
	DISABLE_FIREWALL=$(echo "${DISABLE_FIREWALL:-}" | tr '[:upper:]' '[:lower:]')

	export IPT_CMD=$(check_iptables || echo "")
	if [ -z "${IPT_CMD}" ]; then
		log_error "Could not run iptables (missing NET_ADMIN capability?)"
		return 1
	fi

	# Download or locate configuration files
	v2_config_success="false"
	if [ "${FARCASTER_AGENT_TOKEN:-x}" != "x" ]; then
		if download_and_deploy_config; then
			v2_config_success="true"
		fi
	fi

	if [ "${v2_config_success}" != "true" ]; then
		if [ -f "${SECRETS_DIR_V0}/tunnel/wg-tunnel.conf" ] && [ -f "${SECRETS_DIR_V0}/gateway/wg-gateway.conf" ]; then
			cp "${SECRETS_DIR_V0}/tunnel/wg-tunnel.conf" "${SECRETS_DIR_V0}/gateway/wg-gateway.conf" "${WORK_DIR}/" || true
		elif [ -f "${SECRETS_DIR_V2}/wg-tunnel.conf" ] && [ -f "${SECRETS_DIR_V2}/wg-gateway.conf" ]; then
			cp "${SECRETS_DIR_V2}"/* "${WORK_DIR}/" || true
		fi
	fi

	if [ ! -f "${WORK_DIR}/wg-tunnel.conf" ] || [ ! -f "${WORK_DIR}/wg-gateway.conf" ]; then
		log_error "Could not find configuration files"
		return 1
	fi

	if ! wg_get_endpoint "${WG_TUN_IF}" >/dev/null; then
		log_error "Could not find hub host"
		return 1
	fi

	# Try UDP connection to hub
	if [ "${FARCASTER_FORCE_TCP}" = "0" ]; then
		if ! wg_start "${WG_TUN_IF}"; then
			log_warn "Could not start WireGuard tunnel, falling back to userspace mode"
			export FARCASTER_FORCE_TCP=1
			return 2
		fi
		if ! wg_get_latest_handshake "${WG_TUN_IF}"; then
			log_warn "Falling back to userspace mode"
			export FARCASTER_FORCE_TCP=1
			return 2
		fi
	else
		log_info "TCP forced, falling back to userspace mode"
		return 2
	fi

	if [ "${DISABLE_FIREWALL}" != "true" ] &&
	   [ "${DISABLE_FIREWALL}" != "yes" ] &&
	   [ "${DISABLE_FIREWALL}" != "1" ]; then
		if ! run_cmd "set gateway filter rules" set_gw_filter_rules; then
			return 1
		fi
		log_info "Gateway filter rules configured"
	else
		log_info "Gateway firewall disabled, skipping filter rules"
	fi

	if ! run_cmd "set gateway NAT rules" set_gw_nat_rules; then
		return 1
	fi
	log_info "Gateway NAT rules configured"

	if ! wg_start "${WG_GW_IF}"; then
		return 1
	fi
	log_info "WireGuard gateway started"

	if ! start_dns_forwarder; then
		log_error "Could not start DNS forwarder"
		return 1
	fi
	log_info "DNS forwarder started"

	log_info "Agent running"

	while true; do
		now=$(date +%s)
		tunnel_handshake=$(wg show "${WG_TUN_IF}" latest-handshakes | awk -F' ' '{print $2}')
		if [ $((now - tunnel_handshake)) -gt ${MAX_WG_HANDSHAKE_TTL} ]; then
			log_warn "Connection to Probely seems down, attempting to reconnect"
			break
		fi
		sleep 10
	done

	sleep 5
	return 1
}

extract_proxy_host() {
	local url="$1"
	url="${url#\"}"
	url="${url%\"}"
	url="${url#http://}"
	url="${url#https://}"
	url="${url%%/*}"
	url="${url##*@}"
	if [[ "${url}" == \[* ]]; then
		echo "${url%%\]*}]"
	else
		echo "${url%%:*}"
	fi
}

validate_proxy_not_localhost() {
	local proxy_var="$1"
	local proxy_val="${!proxy_var:-}"
	[ -z "${proxy_val}" ] && return 0

	local host
	host=$(extract_proxy_host "${proxy_val}")
	case "${host}" in
		localhost|127.0.0.1|"[::1]"|"[::ffff:127.0.0.1]")
			echo "${proxy_var} must not point to localhost (got: ${host})."
			exit 1
			;;
	esac
}

setup_proxy_environment() {
	for var in HTTP_PROXY HTTPS_PROXY NO_PROXY; do
		lower="$(echo "${var}" | tr 'A-Z' 'a-z')"
		if [ -z "${!var:-}" ] && [ -n "${!lower:-}" ]; then
			export "${var}"="${!lower}"
		elif [ -n "${!var:-}" ] && [ -z "${!lower:-}" ]; then
			export "${lower}"="${!var}"
		fi
	done

	if [ -n "${HTTP_PROXY:-}" ] && [ -z "${HTTPS_PROXY:-}" ]; then
		export HTTPS_PROXY="${HTTP_PROXY}"
		export https_proxy="${HTTP_PROXY}"
	elif [ -n "${HTTPS_PROXY:-}" ] && [ -z "${HTTP_PROXY:-}" ]; then
		export HTTP_PROXY="${HTTPS_PROXY}"
		export http_proxy="${HTTPS_PROXY}"
	fi

	validate_proxy_not_localhost HTTP_PROXY
	validate_proxy_not_localhost HTTPS_PROXY
}

init_environment() {
	log_info "Starting Farcaster agent v${FARCASTER_VERSION:-dev}"
	umask 007
	export LC_ALL=C
	export FARCASTER_PATH=/farcaster
	export PATH="${FARCASTER_PATH}/sbin:${FARCASTER_PATH}/bin:${PATH}"
	export WORK_DIR="${WORKDIR}"
	export WG_TUN_IF="wg-tunnel"
	export WG_GW_IF="wg-gateway"
	setup_proxy_environment
}

determine_run_mode() {
	export RUN_MODE="${RUN_MODE:---kernel}"

	export WIREGUARD_SUPPORT=$(check_kernel_wireguard && echo "yes" || echo "no")
	if [ "${WIREGUARD_SUPPORT}" != "yes" ]; then
		log_warn "WireGuard kernel support check failed, falling back to userspace mode"
		log_warn "Make sure you are running Linux >= 5.6 and this container has the NET_ADMIN capability"
		export RUN_MODE="--user"
	fi

	export IPT_CMD=$(check_iptables || echo "")
	export IPT_SUPPORT=$([ -x "${IPT_CMD:-}" ] && echo "yes" || echo "no")
	if [ "${IPT_SUPPORT}" != "yes" ]; then
		log_warn "iptables support check failed, falling back to userspace mode"
		log_warn "Make sure this container has the NET_ADMIN capability and iptables is installed"
		export RUN_MODE="--user"
	fi

	if [ -n "${HTTP_PROXY:-}" ]; then
		log_info "HTTP proxy detected, using userspace mode (native proxy support)"
		export RUN_MODE="--user"
	fi

	log_info "Determined run mode: $(echo "${RUN_MODE}" | sed 's/^--//')"
}

init_environment
determine_run_mode

if [ "${RUN_MODE}" == "--user" ]; then
	start_userspace_agent
else
	set +e
	start_kernel_mode
	rc=$?
	set -e
	if [ $rc -ne 0 ]; then
		log_warn "Could not start kernel agent, falling back to userspace mode"
		start_userspace_agent
	fi
fi
