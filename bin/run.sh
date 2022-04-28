#!/usr/bin/env bash

set -eu

umask 007

export LC_ALL=C
export FARCASTER_PATH=/farcaster
export PATH="${FARCASTER_PATH}"/sbin:"${FARCASTER_PATH}"/bin:${PATH}

LOG_FILE="/run/log/farcaster.log"
WG_TUN_IF="wg-tunnel"
WG_GW_IF="wg-gateway"
SECRETS_DIR="/secrets/farcaster/data"
WORK_DIR="/run/farcaster"
TCP_PROXY_PORT=8080
UDP2TCP_PORT=8443
# The WireGuard protocol requires the client to handshake at most 180 seconds apart
MAX_WG_HANDSHAKE_TTL=190
HTTP_PROXY=${HTTP_PROXY:-}

. "${FARCASTER_PATH}/bin/_lib.sh"

# Enable debug
mkdir -pm 0700 $(dirname ${LOG_FILE})
exec 2>>${LOG_FILE}
set -x

if [ ! -f "${SECRETS_DIR}/tunnel/wg-tunnel.conf" ] || [ ! -f "${SECRETS_DIR}/gateway/wg-gateway.conf" ]; then
	echo "Could not find WireGuard configuration files!"
	echo "Please make sure that the agent was correctly installed"
	exit 1
fi

mkdir -p ${WORK_DIR}
chmod -R 0700 ${WORK_DIR}
cp "${SECRETS_DIR}/tunnel/wg-tunnel.conf" "${SECRETS_DIR}/gateway/wg-gateway.conf" ${WORK_DIR}/

HUB_HOST="$(wg_get_endpoint ${WG_TUN_IF})"


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
	print_log ${LOG_FILE}
	exit 1
fi
echo "done"

# If an HTTP proxy is defined, use it for all TCP connections
echo -ne "Setting HTTP proxy rules\t... "
if ! start_proxy_maybe ${TCP_PROXY_PORT}; then
	echo "failed"
	echo
	echo -n "HTTP_PROXY defined, but could not set traffic redirection rules. "
	echo "Ensure HTTP_PROXY is correct, and the container has NET_ADMIN capabilities."
	echo
	print_log ${LOG_FILE}
	exit 1
fi
echo "done"

RC=1
CONNECTED_UDP=0
echo -ne "Connecting to Probely\t\t... "
if wg_start "${WG_TUN_IF}"; then
	if [ "$(wg_get_latest_handshake ${WG_TUN_IF})" != "0" ]; then
		CONNECTED_UDP=1
		echo "done"
	else
		echo "unsuccessful"
	fi
fi

UDP2TCP_PID=0
if [ "${CONNECTED_UDP}" = "0" ]; then
	echo -ne "Trying fallback TCP tunnel\t... "
	UDP2TCP_PID=$(start_udp_over_tcp_tunnel ${UDP2TCP_PORT} ${HUB_HOST} 443)
	if [ "${UDP2TCP_PID}" == "-1" ]; then
		echo "failed"
		echo
		echo "Could not start fallback TCP tunnel."
		proxy_warning
		print_log ${LOG_FILE}
		exit 1
	fi
	echo "done"

	echo -ne "Connecting to Probely (retry)\t... "
	wg_stop "${WG_TUN_IF}"
	wg_update_endpoint "${WG_TUN_IF}" "127.0.0.1:${UDP2TCP_PORT}"
	wg_start "${WG_TUN_IF}"
	if [ "$(wg_get_latest_handshake ${WG_TUN_IF})" = "0" ]; then
		echo "failed"
		echo
		echo "Could not establish TCP tunnel."
		proxy_warning
		print_log ${LOG_FILE}
		exit 1
	fi
	echo "done"
fi

echo -ne "Setting local gateway rules\t... "
if ! set_gw_filter_and_nat_rules; then
	echo "failed"
	echo
	echo "Could not set network gateway filter and NAT rules."
	print_log ${LOG_FILE}
	exit 1
fi
echo "done"

echo -ne "Starting WireGuard gateway\t... "
if ! wg_start "${WG_GW_IF}"; then
	echo "failed"
	echo
	echo "Could not start WireGuard gateway."
	print_log ${LOG_FILE}
	exit 1
fi
echo "done"

if [ "${CONNECTED_UDP}" = "0" ]; then
	echo
	echo "WARNING: connected to Probely in fallback mode!"
	echo -n "To avoid network performance issues, please make sure the "
	echo -n "agent can reach hub.farcaster.probely.com on UDP port 443."
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
	tunnel_handshake="$(wg_get_latest_handshake ${WG_TUN_IF})"
	if [ $((now - tunnel_handshake)) -gt ${MAX_WG_HANDSHAKE_TTL} ]; then
		echo "Connection to Probely seems down. Attempting to reconnect..."
		break
	fi
	last_tunnel_handshake=${tunnel_handshake}
	sleep 120
done

sleep 5
exit 1
