#!/bin/sh

set -euo pipefail

HUB_IP_TTL=300

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

get_hub_host() {
    iface="$1"
    conf="${FARCASTER_PATH}/etc/${iface}.conf"
    # Work-around grep's missing PCRE support
    addr_regex="^Address\s*=\s*"
    cat "${conf}" | grep "${addr_regex}" | sed "s/${addr_regex}//g"
    return $?
}

get_hub_ip() {
    host="$1"
    echo "$(dig +short ${host} | grep '^[.0-9]*$' | sort)"
    return $?
}

HUB_IP_CHECK_TS=
HUB_IP=
is_hub_ip_fresh() {
    [ -z  "${HUB_IP_CHECK_TS}" ] && return 1
    now="$(date "+%s")"
    [ $((now - HUB_IP_CHECK_TS)) -lt ${HUB_IP_TTL} ]
    return $?
}

check_hub_ip() {
    iface="$1"
    if is_hub_ip_fresh; then
        return 0
    fi
    host="$(get_hub_host ${iface})"
    cur_ip="$(get_hub_ip ${host})"
    if [ -z "${HUB_IP}" ]; then
        HUB_IP="${cur_ip}"
    elif [ "${cur_ip}" != "$HUB_IP" ]; then
        return 1
    fi
    HUB_IP_CHECK_TS="$(date "+%s")"
    return 0
}

watch_wireguard() {
    iface="$1"
    while true; do
        sleep 5
        ip link show dev "${iface}" >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "${iface} interface is down. Exiting..."
            return 1
        fi
        if ! check_hub_ip "${iface}"; then
            echo "Farcaster Hub address has changed. Exiting..."
            return 0
        fi
    done
}
