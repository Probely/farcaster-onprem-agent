#!/bin/bash

set -eo pipefail
umask 077

if [ "$1" == "--local" ]; then
    DEPLOY_PATH="."
    INSTALL_INIT=0
else
    if [ "$(id -u)" != "0" ]; then
        echo "Sorry, but you need root privileges to run the installer."
        echo
        exit 1
    fi
    DEPLOY_PATH=/var/lib/farcaster/onprem
    INSTALL_INIT=1
fi

DOCKER_IMAGE="${DOCKER_IMAGE:-probely/farcaster-onprem-agent:latest}"
SECRETS_PATH="${DEPLOY_PATH}/secrets"

set -u

sed -i "s#{{SECRETS_PATH}}#${SECRETS_PATH}#g" ./docker-compose.yml
sed -i "s#{{DOCKER_IMAGE}}#${DOCKER_IMAGE}#g" ./docker-compose.yml

if [ "${INSTALL_INIT}" != "0" ]; then
    echo "Deploying the Agent init scripts..."
    mkdir -p "${DEPLOY_PATH}"
    mv ./secrets/ "${SECRETS_PATH}"
    chmod -R go-rwx "${SECRETS_PATH}"
    chown -R root:root "${SECRETS_PATH}"
    svcname="probely-onprem-agent"
    compose_path=/var/lib/docker-compose/${svcname}
    rm -rf ${compose_path}
    mkdir -p ${compose_path}
    mv ./docker-compose.yml ${compose_path}
    rm -f /etc/init.d/docker-compose.${svcname}
    ln -s /etc/init.d/docker-compose /etc/init.d/docker-compose.${svcname}
    rc-update add docker-compose.${svcname} default
    /etc/init.d/docker-compose.${svcname} start
else
    echo "Deploying the Agent on this path..."
fi

echo "Setup done!"
echo
