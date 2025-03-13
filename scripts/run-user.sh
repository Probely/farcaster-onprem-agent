#!/usr/bin/env bash

set -eu

. "${FARCASTER_PATH}"/bin/_lib.sh

if [ "$(debug_level)" -gt 0 ]; then
	echo "Debugging enabled"
	set -x
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
