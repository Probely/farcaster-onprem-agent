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

run_mode="${1:-}"
if [ "${run_mode}" == "--hybrid" ]; then
  . /farcaster/bin/run-hybrid.sh
else
  . /farcaster/bin/run.sh
fi
