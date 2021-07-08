#!/bin/bash

set -euo pipefail

export FARCASTER_PATH=/farcaster
export PATH="${FARCASTER_PATH}"/sbin:"${FARCASTER_PATH}"/bin:${PATH}

LOG_FILE=/run/log/farcaster-tunnel.log
mkdir -pm 0700 $(dirname ${LOG_FILE})

# Enable debug
exec 2>>${LOG_FILE}
set -x

. "${FARCASTER_PATH}/bin/_lib.sh"
. "${FARCASTER_PATH}/bin/_env.sh"

rc=1
if start_wireguard "${WG_TUN_IF}"; then
    set +x
    check_hub=1
    rc=$(watch_wireguard "${WG_TUN_IF}" ${check_hub})
fi
sleep 5
exit ${rc}
