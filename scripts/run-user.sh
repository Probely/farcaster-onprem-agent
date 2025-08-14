#!/usr/bin/env bash

set -eu

. "${FARCASTER_PATH}"/bin/_lib.sh

if [ "$(debug_level)" -gt 0 ]; then
	echo "Debugging enabled"
	set -x
fi

# Handle backwards compatibility for FARCASTER_PROXY_NAMES
# If FARCASTER_PROXY_NAMES is not set but the old variable is, use the old value
if [ -z "${FARCASTER_PROXY_NAMES:-}" ] && [ -n "${FARCASTER_PROXY_USE_HOSTNAMES:-}" ]; then
	export FARCASTER_PROXY_NAMES="${FARCASTER_PROXY_USE_HOSTNAMES}"
	echo "Note: Using deprecated FARCASTER_PROXY_USE_HOSTNAMES. Please update to FARCASTER_PROXY_NAMES."
fi

echo -ne "Starting Farcaster Agent\t...\n"

if [ "$(debug_level)" -gt 0 ]; then
	print_diagnostics
fi

# Finally, start the userspace agent
if ! start_userspace_agent; then
	echo "Could not start the userspace agent!"
	sleep 10
	exit $?
fi

sleep 1
