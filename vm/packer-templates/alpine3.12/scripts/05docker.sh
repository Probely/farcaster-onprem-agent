set -ex

apk add docker
rc-update add docker default
mkdir -p /var/lib/docker-compose

cat << 'EOF' > /etc/init.d/docker-compose
#!/sbin/openrc-run

description="Runs docker-compose instances"
instance_name="${SVCNAME#*.}"
compose_config="/var/lib/docker-compose/${instance_name}/docker-compose.yml"
compose_dir="$(dirname "$(realpath "${compose_config}" 2> /dev/null)")"
docker_compose="/usr/bin/docker run \
-v /var/run/docker.sock:/var/run/docker.sock \
-v $compose_dir:$compose_dir \
-w=$compose_dir \
docker/compose:1.26.2"

depend() {
    after docker
}

checkconfig() {
    if ! [ -f "${compose_config}" ]; then
        eerror "Could not find a docker-compose.yml configuration file in "
        eerror "${compose_dir}"
        return 1
    fi
}

start() {
    checkconfig || return 1

    ebegin "Starting ${SVCNAME}"
    cd "$compose_dir" || return 1
    ${docker_compose} --project-name="${instance_name}" up -d
    eend $?
}

stop() {
    if [ "${RC_CMD}" = "restart" ]; then
        checkconfig || return 1
    fi

    ebegin "Stopping ${SVCNAME}"
    cd "$compose_dir" || return 1
    ${docker_compose} --project-name="${instance_name}" down
    eend $?
}
EOF

chmod +x /etc/init.d/docker-compose
