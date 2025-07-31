#!/usr/bin/env bash

# Exit on error, undefined variables
set -eu

extract_proxy_host() {
    local proxy_url="$1"
    # Remove quotes
    proxy_url=$(echo "${proxy_url}" | sed -e 's/^"//' -e 's/"$//')
    # Remove protocol
    proxy_url=$(echo "${proxy_url}" | sed -r 's|^https?://||')
    # Remove path
    proxy_url=$(echo "${proxy_url}" | sed -r 's|/.*$||')
    # Remove userinfo
    proxy_url=$(echo "${proxy_url}" | sed 's|^[^@]*@||')

    # IPv6 address
    if echo "${proxy_url}" | grep -q '^\[.*\]'; then
        echo "${proxy_url}" | sed -r 's|^(\[.*\]).*|\1|'
    # IPv4 address or hostname
    else
        echo "${proxy_url}" | cut -d ':' -f 1
    fi
}

init_environment() {
    echo "Starting Farcaster agent v${FARCASTER_VERSION:-dev}..." # Set in the Dockerfile
    umask 007
    export LC_ALL=C
    export FARCASTER_PATH=/farcaster
    export PATH="${FARCASTER_PATH}/sbin:${FARCASTER_PATH}/bin:${PATH}"
    export LOG_FILE="/run/log/farcaster.log"
    export WORK_DIR="/run/farcaster"
    export WG_TUN_IF="wg-tunnel"
    export WG_GW_IF="wg-gateway"
    export TCP_PROXY_PORT=8080
    setup_proxy_environment
}

setup_proxy_environment() {
    # Sync uppercase/lowercase for each of HTTP_PROXY, HTTPS_PROXY, NO_PROXY
    for var in HTTP_PROXY HTTPS_PROXY NO_PROXY; do
        lower="$(echo "${var}" | tr 'A-Z' 'a-z')"
        if [ -z "${!var:-}" ] && [ -n "${!lower:-}" ]; then
            export "${var}"="${!lower}"
        elif [ -n "${!var:-}" ] && [ -z "${!lower:-}" ]; then
            export "${lower}"="${!var}"
        fi
    done

    # Ensure both HTTP and HTTPS are set if at least one is set
    if [ -n "${HTTP_PROXY:-}" ] && [ -z "${HTTPS_PROXY:-}" ]; then
        export HTTPS_PROXY="${HTTP_PROXY}"
        export https_proxy="${HTTP_PROXY}"
    elif [ -n "${HTTPS_PROXY:-}" ] && [ -z "${HTTP_PROXY:-}" ]; then
        export HTTP_PROXY="${HTTPS_PROXY}"
        export http_proxy="${HTTPS_PROXY}"
    fi

    # Parse the proxy values and ensure their host is not localhost and not 127.0.0.1
    for proxy in HTTP_PROXY HTTPS_PROXY; do
        if [ -n "${!proxy:-}" ]; then
            host=$(extract_proxy_host "${!proxy}")
            if [ "${host}" = "localhost" ] || [ "${host}" = "127.0.0.1" ] || [ "${host}" = "[::1]" ] || [ "${host}" = "[::ffff:127.0.0.1]" ]; then
                echo "${proxy} cannot be set to localhost."
                exit 1
            fi
        fi
    done

}

determine_run_mode() {
    # Default to kernel mode
    export RUN_MODE="${RUN_MODE:---kernel}"
    # Check for WireGuard kernel support
    export WIREGUARD_SUPPORT=$(check_kernel_wireguard && echo "yes" || echo "no")
    if [ "${WIREGUARD_SUPPORT}" != "yes" ]; then
        echo "WireGuard kernel support check failed. Falling back to userspace mode..."
        echo "Make sure you are running Linux >= 5.6 and this container has the NET_ADMIN capability."
        export RUN_MODE="--user"
    fi
    # Check for iptables support
    export IPT_CMD=$(check_iptables || echo "")
    export IPT_SUPPORT=$([ -x "${IPT_CMD:-}" ] && echo "yes" || echo "no")
    if [ "${IPT_SUPPORT}" != "yes" ]; then
        echo "iptables support check failed. Falling back to userspace mode..."
        echo "Make sure this container has the NET_ADMIN capability and iptables is installed."
        export RUN_MODE="--user"
    fi
    echo "Determined run mode: $(echo "${RUN_MODE}" | sed 's/^--//')"
}

start_user_mode() {
    echo "Starting Farcaster agent in userspace mode..."
    "${FARCASTER_PATH}/bin/run-user.sh"
}

start_kernel_mode() {
    echo "Starting Farcaster agent in kernel mode..."
    if ! "${FARCASTER_PATH}/bin/run.sh"; then
        echo "Could not start the kernel agent! Falling back to userspace mode..."
        start_user_mode
    fi
}

init_environment
. "${FARCASTER_PATH}/bin/_lib.sh"

determine_run_mode
if [ "${RUN_MODE}" == "--user" ]; then
  start_user_mode
else
  start_kernel_mode
fi
