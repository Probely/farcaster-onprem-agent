#!/usr/bin/env bash

set -eu

umask 007

export LC_ALL=C
export FARCASTER_PATH=/farcaster
export PATH="${FARCASTER_PATH}"/sbin:"${FARCASTER_PATH}"/bin:${PATH}

export LOG_FILE="/run/log/farcaster.log"
export WORK_DIR="/run/farcaster"
export WG_TUN_IF="wg-tunnel"
export WG_GW_IF="wg-gateway"

export TCP_PROXY_PORT=8080
export HTTPS_PROXY="${HTTPS_PROXY:-}"
# Use HTTPS_PROXY as a fallback for HTTP_PROXY
export HTTP_PROXY="${HTTP_PROXY:-${HTTPS_PROXY:-}}"

# Determine if this kernel has support for WireGuard
export RUN_MODE="--kernel"
if ! ip link add "${WG_TUN_IF}" type wireguard 2>/dev/null; then
  echo
  echo
  echo "This kernel does not have WireGuard support. Falling back to userspace mode..."
  echo
  echo
  export RUN_MODE="--hybrid"
fi

if [ "${RUN_MODE}" == "--hybrid" ]; then
  exec "${FARCASTER_PATH}"/bin/run-hybrid.sh
else
  exec "${FARCASTER_PATH}"/bin/run.sh
fi
