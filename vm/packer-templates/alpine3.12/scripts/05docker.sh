set -ex

apk add docker
rc-update add docker default

cat << 'EOF' | (cd /etc/init.d && patch -p0)
--- docker.orig
+++ docker
@@ -18,11 +18,18 @@
 
 retry="${DOCKER_RETRY:-TERM/60/KILL/10}"
 
+set_http_proxies() {
+	while read -r line; do
+		echo "${line}" | grep -q "^HTTP" && export ${line}
+	done < /etc/environment
+}
+
 depend() {
 	need sysfs cgroups
 }
 
 start_pre() {
+	set_http_proxies
 	checkpath -f -m 0644 -o root:docker "$DOCKER_ERRFILE" "$DOCKER_OUTFILE"
 }
EOF


cat << EOF >> /etc/environment
# If configured, the VM will use an HTTP(S) proxy for:
#  * Downloading Docker images
#  * System updates
#
# NOTE: even if the proxy is enabled, the VM still requires access to
# hub.farcaster.probely.com on UDP port 443 for the Wireguard tunnel
#HTTP_PROXY=http://proxy.example.com
#HTTPS_PROXY=https://proxy.example.com

EOF

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
docker/compose:1.29.1"

depend() {
    need docker
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

    ebegin "Waiting for Docker to be ready"
    is_ready=0
    for i in $(seq 20); do
        docker version >/dev/null 2>&1 && is_ready=1 && break
        sleep 1
    done
    if [ ${is_ready} -ne 1 ]; then
        return 1
    fi
    eend 0

    ebegin "Starting ${SVCNAME}"
    cd "$compose_dir" || return 1
    ${docker_compose} --project-name="${instance_name}" pull
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
