#!/usr/bin/env bash

set -eu

# Store the original stderr
exec 3>&2
# Redirect stderr to the log file
if ! mkdir -pm 0700 "$(dirname "${LOG_FILE}")"; then
	echo "Could not create the log directory! Using /dev/stderr for debug output..."
	LOG_FILE="/dev/stderr"
fi
exec 2>>"${LOG_FILE}"
# Enable debug (will be printed to the log file)
set -x

if ! mkdir -pm 0700 "${WORK_DIR}"; then
	echo "Could not create the work directory ${WORK_DIR}!"
	echo "Make sure this path is writable by the container user."
	exit 1
fi


SECRETS_DIR_V2="/secrets/farcaster/data_v2"
SECRETS_DIR_V0="/secrets/farcaster/data"
UDP2TCP_PORT=8443

# The WireGuard protocol requires the client to handshake at most 180 seconds apart
MAX_WG_HANDSHAKE_TTL=190
FARCASTER_FORCE_TCP=${FARCASTER_FORCE_TCP:-0}
DISABLE_FIREWALL=$(echo "${DISABLE_FIREWALL:-}" | tr '[:upper:]' '[:lower:]')

. "${FARCASTER_PATH}"/bin/_lib.sh

# Make sure we can run iptables
export IPT_CMD=$(check_iptables)
if [ -z "${IPT_CMD}" ]; then
	echo "Could not run iptables. Make sure this container has the NET_ADMIN capability."
	exit 1
fi

function download_and_deploy_v2_config() {
	echo -ne "Downloading agent configuration\t... "
	if ! farconn config-agent "${SECRETS_DIR_V2}/"; then
		echo "failed"
		echo "Could not configure the agent"
		return 1
	fi
	echo "done"
	echo -ne "Deploying agent configuration\t... "
	if ! cp ${SECRETS_DIR_V2}/* "${WORK_DIR}"; then
		echo "failed"
		echo "Could not deploy config to ${WORK_DIR}"
		return 1
	fi
	echo "done"
	return 0
}

# If the agent token is set, download the configuration files
v2_config_success="false"
if [ "${FARCASTER_AGENT_TOKEN:-x}" != "x" ]; then
	if download_and_deploy_v2_config; then
		v2_config_success="true"
	fi
fi

# If we could not download the configuration files, try to use the legacy ones
if [ "${v2_config_success}" != "true" ]; then
	# Legacy config files
	if [ -f "${SECRETS_DIR_V0}/tunnel/wg-tunnel.conf" ] && [ -f "${SECRETS_DIR_V0}/gateway/wg-gateway.conf" ]; then
		cp "${SECRETS_DIR_V0}/tunnel/wg-tunnel.conf" "${SECRETS_DIR_V0}/gateway/wg-gateway.conf" ${WORK_DIR}/
	# New (but previously built) config files
	elif [ -f "${SECRETS_DIR_V2}/wg-tunnel.conf" ] && [ -f "${SECRETS_DIR_V2}/wg-gateway.conf" ]; then
		cp ${SECRETS_DIR_V2}/* "${WORK_DIR}/"
	else
		print_log "${LOG_FILE}"
		echo "Could not find the configuration files and the agent token is not set."
	fi
fi

if [ ! -f "${WORK_DIR}/wg-tunnel.conf" ] || [ ! -f "${WORK_DIR}/wg-gateway.conf" ]; then
	echo "Could not find the configuration files."
	print_log "${LOG_FILE}"
	exit 1
fi

if ! HUB_HOST="$(wg_get_endpoint "${WG_TUN_IF}")"; then
	echo "Could not find the hub host"
	print_log "${LOG_FILE}"
	exit 1
fi

function proxy_warning() {
	if [ "${HTTP_PROXY}" = "" ]; then
		echo -n "If an HTTP proxy is required to reach "
		echo -n "external endpoints, please set the "
		echo "HTTP_PROXY environment variable."
	else
		echo -n "Make sure the HTTP_PROXY variable is properly set."
	fi
}

# Redirect remote DNS request to a local dnsmasq and let it handle the details
echo -ne "Starting local DNS resolver\t... "
if ! start_dnsmasq; then
	echo "failed"
	echo "Could not start local DNS resolver"
	print_log "${LOG_FILE}"
	exit 1
fi
echo "done"

# If an HTTP proxy is defined, use it for all TCP connections
echo -ne "Setting HTTP proxy rules\t... "
if ! start_proxy_maybe "${TCP_PROXY_PORT}"; then
	echo "failed"
	echo
	echo -n "HTTP_PROXY defined, but could not set traffic redirection rules. "
	echo "Ensure HTTP_PROXY is correct and this container has NET_ADMIN capabilities."
	echo
	print_log "${LOG_FILE}"
	exit 1
fi
echo "done"

CONNECTED_UDP=0
echo -ne "Connecting to Probely (via UDP)\t... "
if [ "${FARCASTER_FORCE_TCP}" = "0" ]; then
	if wg_start "${WG_TUN_IF}"; then
		if [ "$(wg_get_latest_handshake "${WG_TUN_IF}")" != "0" ]; then
			CONNECTED_UDP=1
			echo "done"
		else
			echo "unsuccessful"
		fi
	fi
else
	echo "skipped"
fi

UDP2TCP_PID=0
if [ "${CONNECTED_UDP}" = "0" ]; then
	echo -ne "Configuring fallback TCP tunnel\t... "
	UDP2TCP_PID=$(start_udp_over_tcp_tunnel ${UDP2TCP_PORT} "${HUB_HOST}" 443)
	if [ "${UDP2TCP_PID}" == "-1" ]; then
		echo "failed"
		echo
		echo "Could not start fallback TCP tunnel."
		proxy_warning
		print_log "${LOG_FILE}"
		exit 1
	fi
	echo "done"

	echo -ne "Connecting to Probely (via TCP)\t... "
	wg_stop "${WG_TUN_IF}"
	wg_update_endpoint "${WG_TUN_IF}" "127.0.0.1:${UDP2TCP_PORT}"
	wg_start "${WG_TUN_IF}"
	if [ "$(wg_get_latest_handshake "${WG_TUN_IF}")" = "0" ]; then
		echo "failed"
		echo
		echo "Could not establish TCP tunnel."
		proxy_warning
		print_log "${LOG_FILE}"
		exit 1
	fi
	echo "done"
fi

echo -ne "Setting gateway filter rules\t... "
# Check if the firewall should be enabled based on the DISABLE_FIREWALL value
if [ "${DISABLE_FIREWALL}" != "true" ] &&
   [ "${DISABLE_FIREWALL}" != "yes" ] &&
   [ "${DISABLE_FIREWALL}" != "1" ] &&
   [ "${DISABLE_FIREWALL}" != "enable" ]; then
   if ! set_gw_filter_rules; then
		echo "failed"
		echo
		echo "Could not set network gateway filter rules."
		print_log "${LOG_FILE}"
		exit 1
	else
		echo "done"
	fi
else
	echo "skipped"
fi

echo -ne "Setting gateway NAT rules\t... "
if ! set_gw_nat_rules; then
	echo "failed"
	echo
	echo "Could not set network gateway NAT rules."
	print_log "${LOG_FILE}"
	exit 1
fi
echo "done"

echo -ne "Starting WireGuard gateway\t... "
if ! wg_start "${WG_GW_IF}"; then
	echo "failed"
	echo
	echo "Could not start WireGuard gateway."
	print_log "${LOG_FILE}"
	exit 1
fi
echo "done"

if [ "${CONNECTED_UDP}" = "0" ]; then
	echo
	echo "WARNING: connected to Probely in fallback mode!"
	echo -n "Performance may suffer, resulting in delays, or even "
	echo "failed scans."
	echo

	echo "Please make sure the agent can reach hub.farcaster.probely.com on UDP port 443."
	echo "For more details, check the documentation on"
	echo "https://github.com/Probely/farcaster-onprem-agent#network-requirements"
	echo
	echo
fi


echo
echo "Running..."

set +x
# Continuously monitor the agent
while true; do
	# Check if we are still connected to Probely
	now=$(date +%s)
	tunnel_handshake="$(wg_get_latest_handshake "${WG_TUN_IF}")"
	if [ $((now - tunnel_handshake)) -gt ${MAX_WG_HANDSHAKE_TTL} ]; then
		echo "Connection to Probely seems down. Attempting to reconnect..."
		break
	fi
	sleep 10
done

sleep 5
exit 1
