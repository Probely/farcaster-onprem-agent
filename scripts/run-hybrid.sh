#!/usr/bin/env bash

set -eu

# Store the original stder
exec 3>&2
# Redirect stderr to the log file
mkdir -pm 0700 "$(dirname "${LOG_FILE}")"
exec 2>>"${LOG_FILE}"
# Enable debug (will be printed to the log file)
set -x

if ! mkdir -pm 0700 "${WORK_DIR}"; then
	echo "Could not create the work directory!"
	print_log "{$LOG_FILE}"
	sleep 60
	exit 1
fi

. "${FARCASTER_PATH}"/bin/_lib.sh

export IPT_CMD=$(check_iptables)

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
		print_log "${LOG_FILE}"
		exit 1
	fi
fi

echo "done"

echo -ne "Starting Farcaster Agent\t...\n"

set +x

# Redirect stderr back to its original file descriptor and close the backup
exec 2>&3
exec 3>&-

# Finally, start the userspace agent
start_userspace_agent "${FARCASTER_DEBUG:-0}"

if [ $? -ne 0 ]; then
	echo "Could not start the userspace agent!"
	print_log "${LOG_FILE}"
	sleep 10
	exit $?
fi

sleep 1
