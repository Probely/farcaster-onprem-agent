#!/bin/bash
set -e

echo "Proxy Enforcer Script"

# Wait before blocking direct traffic so every test service can be reached.
for endpoint in echoserver:9000 echoserver:9001 echoserver:9443 httpproxy:8080 socks5proxy:1080; do
    # The child shell expands its own positional arguments.
    # shellcheck disable=SC2016
    if ! timeout 30 bash -c 'until (: > "/dev/tcp/$1/$2") 2>/dev/null; do sleep 0.2; done' \
        _ "${endpoint%:*}" "${endpoint##*:}"; then
        echo "Test service $endpoint did not start within 30 seconds. Check its container logs." >&2
        exit 1
    fi
done

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
    iptables -A OUTPUT -d "$HTTP_PROXY_IP" -p tcp --dport 8080 -j ACCEPT
    iptables -A OUTPUT -d "$SOCKS_PROXY_IP" -p tcp --dport 1080 -j ACCEPT

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
