#!/usr/bin/env bash

echo "Starting Farcaster agent v${FARCASTER_VERSION}..."

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
export HTTP_PROXY="${HTTP_PROXY:-}"
export HTTPS_PROXY="${HTTPS_PROXY:-}"

if [ -n "${HTTP_PROXY}" ] && [ -z "${HTTPS_PROXY}" ]; then
  export HTTPS_PROXY="${HTTP_PROXY}"
fi

if [ -n "${HTTPS_PROXY}" ] && [ -z "${HTTP_PROXY}" ]; then
  export HTTP_PROXY="${HTTPS_PROXY}"
fi

# Determine if this kernel has support for WireGuard
export RUN_MODE="${RUN_MODE:---kernel}"
if ! { ip link add wg-test type wireguard 2>/dev/null &&
       ip link del wg-test > /dev/null 2>&1; } then
  echo
  echo
  echo "WireGuard kernel support check failed."
  echo "Make sure you are running Linux >= 5.6 and this container has the NET_ADMIN capability."
  echo
  echo "Falling back to userspace mode..."
  echo
  echo
  export RUN_MODE="--hybrid"
fi

if [ "${RUN_MODE}" == "--hybrid" ]; then
  "${FARCASTER_PATH}"/bin/run-hybrid.sh
else
  if ! "${FARCASTER_PATH}"/bin/run.sh; then
    echo "Could not start the kernel agent! Trying userspace mode..."
    "${FARCASTER_PATH}"/bin/run-hybrid.sh
  fi
fi
