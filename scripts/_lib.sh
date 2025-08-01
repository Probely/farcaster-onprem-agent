#!/usr/bin/env bash

set -euo pipefail

# Regex that handles both IPv4/hostname and IPv6 proxy formats
# Matches: [protocol://][user:pass@][host|[ipv6]][:port][/path]
PROXY_REGEXP='^(https?://)?(([^@/:]+:[^@/:]+)@)?((\[[0-9a-fA-F:]+\])|([0-9a-zA-Z._-]+))(:[0-9]+)?(/.*)?$'
WORKDIR=/run/farcaster
LOGDIR=/logs
HUB_IP_TTL=300
WG_DEFAULT_PORT=51820
INTERNAL_NETS="${INTERNAL_NETS:-10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16}"

check_iptables() {
	if iptables-nft -t filter -L >/dev/null 2>&1; then
		which iptables-nft
		return 0
	elif iptables-legacy -t filter -L >/dev/null 2>&1; then
		which iptables-legacy
		return 0
	fi
	return 1
}

wg_setup_iface() {
	iface="$1"

	# Check if the kernel has wireguard support
	ip link add "${iface}" type wireguard 2>/dev/null &&
	ip link del "${iface}" &&
	return 0

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
	WG_LOG_LEVEL=info \
	WG_LOG_FILE=/dev/stdout \
	WG_ERR_LOG_FILE=/dev/stderr \
	/bin/sh -c "wg-quick down ${conf} 2>/dev/null || true; wg-quick up ${conf}"
}

wg_stop() {
	iface="$1"
	conf="${FARCASTER_PATH}/etc/${iface}.conf"
	test -e "${conf}" || { echo "Could not find config ${conf}"; return 1; }

	wg-quick down "${conf}" || true
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
	# Try to get the handshake for 90 seconds. The hub will update
	# the known peers list every 30 seconds. Be sure to **not** make this
	# value smaller than that.
	for i in $(seq 90); do
		handshake=$(wg show "${iface}" latest-handshakes | awk -F' ' '{print $2}')
		[ "${handshake}" != "0" ] && echo "${handshake}" && return
		sleep 1
	done
	echo "0"
}

wg_get_endpoint() {
	iface="$1"
	get_addr_from_conf "${iface}" "^Endpoint\s*=\s*"
}

wg_get_addr() {
	iface="$1"
	get_addr_from_conf "${iface}" "^Address\s*=\s*"
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
	# Check if it's already an IP address using ipcalc
	if ! ipcalc -n -b "${host}" 2>&1 | grep -qi "INVALID ADDRESS"; then
		echo "${host}"
		return 0
	fi
	# Otherwise, resolve via DNS
	resolved=$(dig a +short "${host}" | head -1)
	if [ -z "${resolved}" ]; then
		# DNS resolution failed, return empty
		return 1
	fi
	echo "${resolved}"
	return 0
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
	host=$(wg_get_endpoint "${iface}")
	cur_ip=$(resolve_host "${host}")
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
	if [ "${check_hub}" -ne 0 ] && ! check_hub_ip "${iface}"; then
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
	# Suppress AAAA (IPv6) queries because some customer DNS resolvers
	# malfunction when they encounter them. The tunnel currently
	# carries only IPv4 traffic, so omitting these queries has no impact.
	filter_aaaa="--filter-AAAA"
	dnsmasq -x ${rundir}/dnsmasq.pid -p "${lport}" -i "${WG_GW_IF}" ${filter_aaaa}
	gw_addr="$(wg_get_addr "${WG_GW_IF}")"
	for proto in tcp udp; do
		${IPT_CMD} -t nat -I PREROUTING -i "${WG_GW_IF}" -p ${proto} \
		    --dport 53 -j DNAT --to-destination "${gw_addr}:${lport}"
		${IPT_CMD} -t filter -I INPUT -i "${WG_GW_IF}" -p ${proto} \
		    -d "${gw_addr}" --dport "${lport}" -j ACCEPT
	done
}

get_proxy_username() {
	local proxy="${HTTP_PROXY:-}"
	# Remove quotes
	proxy=$(echo "${proxy}" | sed -e 's/^"//' -e 's/"$//')
	# Remove protocol
	proxy=$(echo "${proxy}" | sed -r 's|^https?://||')
	# Check if has userinfo (contains @)
	if echo "${proxy}" | grep -q '@'; then
		# Extract userinfo part (everything before the last @)
		userinfo=$(echo "${proxy}" | sed 's/@[^@]*$//')
		# Extract username (everything before : in userinfo)
		echo "${userinfo}" | cut -d ':' -f 1
	fi
}

get_proxy_password() {
	local proxy="${HTTP_PROXY:-}"
	# Remove quotes
	proxy=$(echo "${proxy}" | sed -e 's/^"//' -e 's/"$//')
	# Remove protocol
	proxy=$(echo "${proxy}" | sed -r 's|^https?://||')
	# Check if has userinfo (contains @)
	if echo "${proxy}" | grep -q '@'; then
		# Extract userinfo part (everything before the last @)
		userinfo=$(echo "${proxy}" | sed 's/@[^@]*$//')
		# Check if userinfo contains a colon (has password)
		if echo "${userinfo}" | grep -q ':'; then
			# Extract password (everything after first : in userinfo)
			echo "${userinfo}" | cut -d ':' -f 2-
		fi
	fi
}

get_proxy_address() {
	local proxy="${HTTP_PROXY:-}"
	# Remove quotes
	proxy=$(echo "${proxy}" | sed -e 's/^"//' -e 's/"$//')
	# Remove protocol
	proxy=$(echo "${proxy}" | sed -r 's|^https?://||')
	# Remove path
	proxy=$(echo "${proxy}" | sed -r 's|/.*$||')
	# Remove userinfo (everything before last @)
	echo "${proxy}" | sed 's|^.*@||'
}

extract_host_from_proxy_address() {
	local address="$1"
	# Remove protocol if present
	address=$(echo "${address}" | sed -r 's|^https?://||')
	# IPv6 address
	if echo "${address}" | grep -q '^\[.*\]'; then
		echo "${address}" | sed -r 's|^(\[.*\]).*|\1|'
	else
		# IPv4 address or hostname
		echo "${address}" | cut -d ':' -f 1
	fi
}

get_proxy_port() {
	local address="$1"
	local port=""

	# IPv6 address
	if echo "${address}" | grep -q '^\[.*\]:'; then
		port=$(echo "${address}" | sed -r 's|^\[.*\]:||')
	# IPv4 address or hostname
	elif echo "${address}" | grep -q ':'; then
		port=$(echo "${address}" | sed 's|^[^:]*:||')
	fi

	# Default to 8080 if no port specified
	if [ -z "${port}" ] || [ "${port}" = "${address}" ]; then
		port="8080"
	fi
	echo "${port}"
}

start_udp_over_tcp_tunnel() {
	local_udp_port="$1"
	remote_ip=$(resolve_host "$2")
	if [ -z "${remote_ip}" ]; then
		echo "Failed to resolve host: $2" >&2
		echo "-1"
		return 1
	fi
	remote_tcp_port="$3"
	setpriv --reuid=tcptun --regid=tcptun --clear-groups --no-new-privs \
		nohup /usr/local/bin/udp2tcp --tcp-forward "${remote_ip}":"${remote_tcp_port}" --udp-listen 127.0.0.1:${local_udp_port} > /dev/null &
	pid=$!
	sleep 2
	kill -0 ${pid} 2>/dev/null && echo "${pid}" || echo "-1"
}

get_first_nameserver() {
	echo "1.1.1.1"
	return 0
    ns=$(grep -m 1 '^nameserver' /etc/resolv.conf | awk '{print $2}')
	if [ -z "${ns}" ]; then
		ns="127.0.0.1"
	fi
	echo "${ns}"
}

create_moproxy_config() {
	config_path="$1"
	listen_port="$2"
	user=$(get_proxy_username)
	password=$(get_proxy_password)
	address=$(get_proxy_address)
	host=$(extract_host_from_proxy_address "${address}")
	ipaddr=$(resolve_host "${host}" || echo "")
	ipaddr=$(test ! -z "${ipaddr}" && echo "${ipaddr}" || echo "${host}")
	port=$(get_proxy_port "${address}")
	auth=$(test ! -z "${user}" && printf "http username = %s\nhttp password = %s\n" "${user}" "${password}" || echo "")

	umask 033
	cat << EOF > "${config_path}"
[default]
address=${ipaddr}:${port}
protocol=http
test dns=$(get_first_nameserver):53
${auth}
EOF

	return $?
}

set_proxy_redirect_rules() {
	proxy_port="$1"
	# Proxy redirect chain
	# Do not redirect traffic to internal networks
	${IPT_CMD} -t nat -N PROXY-REDIRECT
	for net in ${INTERNAL_NETS}; do
		${IPT_CMD} -t nat -A PROXY-REDIRECT -d "${net}" -j RETURN
	done
	# Do not redirect traffic to the proxy itself
	proxy_addr=$(get_proxy_address)
	proxy_host=$(extract_host_from_proxy_address "${proxy_addr}")
	${IPT_CMD} -t nat -A PROXY-REDIRECT -d "${proxy_host}" -j RETURN

	${IPT_CMD} -t nat -A PROXY-REDIRECT -p tcp -j REDIRECT --to-port "${proxy_port}"

	# Remote traffic arriving in the tunnel
	${IPT_CMD} -t nat -A PREROUTING -i "${WG_GW_IF}" -j PROXY-REDIRECT

	# Traffic from the UDP to TCP tunnel. If a proxy is defined, use it
	${IPT_CMD} -t nat -A OUTPUT -p tcp -m owner --uid-owner tcptun -j PROXY-REDIRECT
	# ${IPT_CMD} -t nat -I OUTPUT -p tcp -m owner --gid-owner diag -j PROXY-REDIRECT

	# Make sure traffic is allowed after being redirected
	${IPT_CMD} -t filter -I INPUT -i "${WG_GW_IF}" -p tcp --dport "${proxy_port}" -j ACCEPT

	return $?
}

function set_gw_filter_rules() {
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

function set_gw_nat_rules() {
	${IPT_CMD} -t nat -N FARCASTER-NAT
	${IPT_CMD} -t nat -A FARCASTER-NAT -o "${WG_TUN_IF}" -j RETURN
	${IPT_CMD} -t nat -A FARCASTER-NAT -o "${WG_GW_IF}" -j RETURN
	${IPT_CMD} -t nat -A FARCASTER-NAT -j MASQUERADE
	${IPT_CMD} -t nat -A POSTROUTING -j FARCASTER-NAT
}

start_proxy_maybe() {
	listen_port="$1"
	test -z "${HTTP_PROXY:-}" && return 0
	proxy_port="${listen_port}"
	rundir=/run/moproxy
	mkdir -p ${rundir}
	chmod 0711 ${rundir}
	config_path="${rundir}/config.ini"
	if ! create_moproxy_config ${config_path} "${listen_port}"; then
		echo "Could not create the moproxy config file" >&2
		return 1
	fi
	if ! set_proxy_redirect_rules "${listen_port}"; then
		echo "Could not set the proxy redirect rules" >&2
		return 1
	fi

	log_level="info"
	log_file="/dev/null"
	if [ "$(debug_level)" -gt 0 ] && [ -d "${LOGDIR}" ]; then
		log_level="trace"
		log_file="${LOGDIR}/moproxy/moproxy.log"
	fi

	setpriv --reuid=proxy --regid=proxy --clear-groups --no-new-privs \
		nohup /usr/local/bin/moproxy --log-level "${log_level}" --host 0.0.0.0 \
		--port "${listen_port}" --list "${config_path}" --allow-direct >"${log_file}" &
	sleep 3
	kill -0 $!
	return $?
}

start_userspace_agent() {
	extra_args=""
	if [ "$(debug_level)" -gt 1 ]; then
		extra_args="-d"
	fi
	CMD="/usr/local/bin/farcasterd ${extra_args}"
	# If we're running as root, drop privileges
	if [ "$(id -u)" -eq 0 ]; then
		echo "Running as root. Dropping privileges..."
		CMD="setpriv --reuid=tcptun --regid=tcptun --clear-groups --no-new-privs ${CMD}"
	fi
	${CMD}
}

scrub_secrets() {
	local text="$1"
	shift  # Remove first argument, leaving only secrets

	local result="$text"

	# Replace each secret value with asterisks
	for secret in "$@"; do
		# Skip empty values
		[ -z "$secret" ] && continue

		# Escape special regex characters in the secret
		local escaped_secret=$(printf '%s\n' "$secret" | sed 's/[[\.*^$()+?{|]/\\&/g')

		# Replace all occurrences of the secret with asterisks
		result=$(echo "$result" | sed "s/${escaped_secret}/*******/g")
	done

	echo "$result"
}

function dump_log() {
	set +e
	echo
	echo
	echo

	log_file="${1}"
	if ! [[ "${log_file}" =~ ^/dev/|^/proc/ ]]; then
		# Clean up secrets from the log file.
		local content
		local scrubbed
		content=$(cat "${log_file}" 2>/dev/null)
		# Ensure the log file is removed.
		rm -f "${log_file}"
		scrubbed=$(scrub_secrets "${content}" \
			"${FARCASTER_AGENT_TOKEN:-}" \
			"${HTTP_PROXY:-}" \
			"${HTTPS_PROXY:-}" \
			"${SOCKS5_PROXY:-}")
		echo "${scrubbed}"
	fi

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

function print_diagnostics() {
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
	echo "-----moproxy config-----"
	cat /run/moproxy/config.ini || echo "No moproxy config found"
	echo
}

function debug_level() {
	echo "${FARCASTER_DEBUG_LEVEL:-0}"
}

is_moproxy_running() {
    pidof moproxy >/dev/null 2>&1
}

function check_kernel_wireguard() {
  return $(ip link add wg-test type wireguard 2>/dev/null &&
           ip link del wg-test > /dev/null 2>&1)
}
