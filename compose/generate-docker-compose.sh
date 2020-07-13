#!/bin/bash

SRCDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

set -eo pipefail

SECRETS_PATH="${1%/}"
DOCKER_IMAGE="${2}"

if [ "${SECRETS_PATH}" = "" ]; then
	echo >&2 "usage: $0 SECRETS_PATH [DOCKER_IMAGE]"
	exit 1
fi

if [ "${DOCKER_IMAGE}" == "" ]; then
    DOCKER_IMAGE="probely/farcaster-onprem-agent"
fi

cat "${SRCDIR}/docker-compose.tpl.yml" |
	sed "s#{{SECRETS_PATH}}#${SECRETS_PATH}#g" | \
    sed "s#{{DOCKER_IMAGE}}#${DOCKER_IMAGE}#g"
cat << EOF

networks:
  default:
    external:
      name: farcaster
EOF
