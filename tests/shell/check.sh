#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "$0")/../.."
# shellcheck source=../../scripts/_lib.sh
. scripts/_lib.sh

trap 'echo "Shell helper check failed at line $LINENO." >&2' ERR

[[ $(get_proxy_port 'proxy.example:3128') == 3128 ]]
[[ $(get_proxy_port '[::1]:8081') == 8081 ]]
[[ $(get_proxy_port 'proxy.example') == 8080 ]]
[[ $(scrub_secrets 'token=a*[b]? other=plain' 'a*[b]?') == 'token=*** other=plain' ]]
[[ $(get_first_nameserver) == 1.1.1.1 ]]

[[ $(FARCASTER_TRANSPORT='' FARCASTER_FORCE_TCP='' resolve_transport) == auto ]]
[[ $(FARCASTER_TRANSPORT=' WS ' FARCASTER_FORCE_TCP='' resolve_transport) == ws ]]
[[ $(FARCASTER_TRANSPORT='  ' FARCASTER_FORCE_TCP=true resolve_transport) == tcp ]]
[[ $(FARCASTER_TRANSPORT=udp FARCASTER_FORCE_TCP=1 resolve_transport) == udp ]]
[[ $(FARCASTER_TRANSPORT='' FARCASTER_FORCE_TCP=Yes resolve_transport) == tcp ]]
[[ $(FARCASTER_TRANSPORT='' FARCASTER_FORCE_TCP=false resolve_transport) == auto ]]
if FARCASTER_TRANSPORT=quic resolve_transport >/dev/null 2>&1; then
    echo 'resolve_transport accepted an unknown transport.' >&2
    exit 1
fi

for helper in get_proxy_username get_proxy_password get_proxy_address; do
    if HTTP_PROXY='invalid proxy' "$helper" >/dev/null 2>&1; then
        echo "$helper accepted an invalid proxy." >&2
        exit 1
    fi
done

ip() {
    case "$*" in
        'link add wg-test type wireguard') return "$add_status" ;;
        'link del wg-test') deleted=true; return "$delete_status" ;;
        *) return 1 ;;
    esac
}

add_status=0 delete_status=0 deleted=false
check_kernel_wireguard
[[ $deleted == true ]]

add_status=1 deleted=false
if check_kernel_wireguard; then
    echo 'WireGuard support check accepted a failed interface creation.' >&2
    exit 1
fi
[[ $deleted == false ]]

add_status=0 delete_status=1
if check_kernel_wireguard; then
    echo 'WireGuard support check accepted a failed interface deletion.' >&2
    exit 1
fi

echo 'Shell helper checks passed.'
