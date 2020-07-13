#!/bin/sh

set -euo pipefail

start_wireguard() {
    iface="$1"
    conf="${FARCASTER_PATH}/etc/${iface}.conf"

    ls "${conf}" >/dev/null || return 1

    WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun \
    WG_SUDO=1 \
    WG_THREADS=2 \
    WG_LOG_LEVEL=info\
    WG_LOG_FILE=/dev/stdout \
    WG_ERR_LOG_FILE=/dev/stderr \
    bash "${FARCASTER_PATH}/bin/wg-quick" up "${conf}"
}

watch_wireguard() {
    iface="$1"
    while true; do
        sleep 2
        ip link show dev "${iface}" >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "${iface} interface is down. Exiting..."
            return 1
        fi
    done
}
