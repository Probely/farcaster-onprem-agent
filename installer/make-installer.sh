#!/usr/bin/env bash

set -eo pipefail

CONFIG_BUNDLE="$1"
if [ "${CONFIG_BUNDLE}" == "" ] || [ ! -f "${CONFIG_BUNDLE}" ]; then
    echo >&2 "usage: $0 CONFIG_BUNDLE"
    echo >&2 "CONFIG_BUNDLE is an archive containing the agent configuration"
    exit 1
fi

set -u

umask 077

RUNDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

AGENTID=$(basename ${CONFIG_BUNDLE} | sed "s/onprem-\(\w*\)\.tar\.gz$/\1/")
TMP_DIR=$(mktemp -d "/tmp/installer-XXXXXXXX")

mkdir -p "${TMP_DIR}/secrets/"
tar -xpzvf "${CONFIG_BUNDLE}" --strip 1 -C "${TMP_DIR}/secrets/"
cp ${RUNDIR}/setup.sh "${TMP_DIR}"
cp ${RUNDIR}/../compose/docker-compose.tpl.yml "${TMP_DIR}/"

cd ${RUNDIR} && mkdir -p ${RUNDIR}/target && makeself --gzip --nomd5 --nocrc \
    --sha256 --license ${RUNDIR}/../LICENSE \
    ${TMP_DIR} \
    ${RUNDIR}/target/probely-onprem-agent-${AGENTID}.run \
    "Probely On-premises Farcaster Agent" \
    ./setup.sh

rm -rf "${TMP_DIR}"
