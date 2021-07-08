#!/bin/bash

set -euo pipefail

export FARCASTER_PATH=/farcaster
export PATH="${FARCASTER_PATH}"/sbin:"${FARCASTER_PATH}"/bin:${PATH}

. "${FARCASTER_PATH}/bin/_lib.sh"
. "${FARCASTER_PATH}/bin/_env.sh"

LOG_FILE=/run/log/farcaster-gateway.log
mkdir -pm 0700 $(dirname ${LOG_FILE})

function setup_firewall_and_nat() {
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

# Enable debug
exec 2>>${LOG_FILE}
set -x

echo -ne "Setting up firewall and NAT rules\t... "
if ! setup_firewall_and_nat; then
    echo "error"
    echo "Could not set up firewall and NAT rules"
    print_log ${LOG_FILE}
    exit 1
fi
echo "done"

# Redirect any DNS request to a local dnsmasq and let it handle the details
echo -ne "Starting local DNS resolver\t... "
if ! start_dnsmasq; then
    echo "error"
    echo "Could not start local DNS resolver"
    print_log ${LOG_FILE}
    exit 1
fi
echo "done"

# If an HTTP proxy is defined, use it for all TCP connections
echo -ne "Checking if a proxy is required\t... "
if ! start_moproxy_maybe; then
    echo "error"
    echo -n "HTTP_PROXY variable defined, but could not redirect traffic. "
    echo "Make sure this variable is properly set."
    echo
    echo -n "If the problem persists, "
    print_log ${LOG_FILE}
    exit 1
fi
echo "done"

echo -ne "Starting WireGuard connections\t... "
if ! start_wireguard "${WG_GW_IF}"; then
    echo "error"
    echo "Could not start WireGuard service"
    print_log ${LOG_FILE}
    exit 1
fi
echo "done"

check_hub=0
echo
echo "Running..."
rc=$(watch_wireguard "${WG_GW_IF}" ${check_hub})
if [ ${rc} -ne 0 ]; then
    print_log ${LOG_FILE}
fi
exit ${rc}
