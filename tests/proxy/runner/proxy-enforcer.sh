#!/bin/bash
set -e

echo "Proxy Enforcer Script"

if [ "$ENFORCE_PROXY" = "true" ]; then
    echo "Setting up iptables rules to enforce proxy usage..."

    # Get IP addresses of proxy servers (Docker will resolve these)
    HTTP_PROXY_IP=$(getent hosts httpproxy | awk '{ print $1 }')
    SOCKS_PROXY_IP=$(getent hosts socks5proxy | awk '{ print $1 }')

    echo "HTTP Proxy IP: $HTTP_PROXY_IP"
    echo "SOCKS5 Proxy IP: $SOCKS_PROXY_IP"

    # Allow loopback
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow DNS (Docker's embedded DNS)
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

    # Allow connections to proxy servers
    iptables -A OUTPUT -d $HTTP_PROXY_IP -p tcp --dport 8080 -j ACCEPT
    iptables -A OUTPUT -d $SOCKS_PROXY_IP -p tcp --dport 1080 -j ACCEPT

    # Allow established connections (for proxy responses)
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # DROP all other outgoing connections
    # This will force all connections to go through proxies
    iptables -A OUTPUT -j DROP

    echo "iptables rules applied. Direct connections are now blocked."
    echo "Current iptables rules:"
    iptables -L OUTPUT -n -v
else
    echo "ENFORCE_PROXY not set to true, skipping iptables setup"
fi

echo ""
echo "Starting proxy tests..."
exec "$@"
