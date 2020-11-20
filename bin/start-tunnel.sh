#!/bin/sh

set -euxo pipefail

export FARCASTER_PATH=/farcaster
export LD_LIBRARY_PATH="${FARCASTER_PATH}"/lib
export XTABLES_LIBDIR="${FARCASTER_PATH}"/lib/xtables
export PATH="${FARCASTER_PATH}"/sbin:"${FARCASTER_PATH}"/bin:${PATH}

. "${FARCASTER_PATH}/bin/_lib.sh"
. "${FARCASTER_PATH}/bin/_env.sh"

rc=1
if start_wireguard "${WG_TUN_IF}"; then
    set +x
    rc=$(watch_wireguard "${WG_TUN_IF}")
fi
sleep 5
exit ${rc}
