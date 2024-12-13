#!/usr/bin/env bash

set -eu

. "${FARCASTER_PATH}"/bin/_lib.sh

if [ "$(debug_level)" -gt 0 ]; then
	echo "Debugging enabled"
	set -x
fi

IPT_CMD=$(check_iptables)
export IPT_CMD

if [ -n "${HTTP_PROXY:-}" ]; then
	if [ -z "${IPT_CMD}" ]; then
		echo -n "HTTP_PROXY is defined, but could not set traffic redirection rules. "
		echo "Make sure the container has the NET_ADMIN capability."
		exit 1
	fi

	echo -ne "Setting HTTP proxy rules\t... "
	if ! start_proxy_maybe "${TCP_PROXY_PORT}"; then
		echo "failed"
		echo
		echo "HTTP_PROXY defined, but could not start the proxy daemon. "
		echo
		exit 1
	fi
fi

echo "done"

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
