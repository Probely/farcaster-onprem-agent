#!/usr/bin/bash

set -uo pipefail

COLOR_RESET='\033[0m'
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_BLUE='\033[0;34m'

DOCKER_URLS="
    * https://auth.docker.io
    * https://registry.docker.io
    * https://registry-1.docker.io"

function print_status() {
    if [ $1 -eq 0 ]; then
        print_ok
    else
        print_error
    fi
}

function print_ok() {
    echo -e "\t\t\t${COLOR_BLUE}[${COLOR_GREEN}ok${COLOR_BLUE}]${COLOR_RESET}"
}

function print_warning() {
    echo -e "\t\t\t${COLOR_BLUE}[${COLOR_YELLOW}warn${COLOR_BLUE}]${COLOR_RESET}"
}

function print_error() {
    echo -e "\t\t\t${COLOR_BLUE}[${COLOR_RED}error${COLOR_BLUE}]${COLOR_RESET}"
}

function check_docker_client() {
    docker --version > /dev/null 2>&1
}

function check_docker_run() {
    fallback=$1
    cmd="docker run --rm probely/farcaster-onprem-agent echo 'Hello World'"
    if [ ${fallback} -eq 1 ]; then
        cmd="sudo ${cmd}"
    fi
    ${cmd} > /dev/null 2>&1
}

echo -ne "Checking if Docker is installed...\t"
check_docker_client
ret=$?
print_status ${ret}
if [ ${ret} -ne 0 ]; then
    echo "Please make sure that Docker is properly installed"
    exit 1
fi

echo -ne "Launching test container...\t\t"
if ! check_docker_run 0; then
    print_warning
    echo -ne "Launching test container (with sudo)...\t"
    check_docker_run 1
fi
ret=$?
print_status ${ret}
if [ ${ret} -ne 0 ]; then
    echo
    echo "Could not run the test Docker container!"
    echo
    echo "Please ensure that:"
    echo "  1. This user has the required permissions to run containers"
    echo 
    echo "  2. The Docker daemon can reach these URLs: ${DOCKER_URLS}"
    echo
    echo "    If an HTTP proxy is required, Docker must be configured to use it."
    echo
    echo "    If installing the Agent on the official VM:"
    echo "      * Configure the proxy in /etc/environment."
    echo "      * Restart the Docker service: /etc/init.d/docker restart"
    echo
    echo "    If installing the Agent on another system:"
    echo "      * https://docs.docker.com/network/proxy/#configure-the-docker-client"
    echo "      * https://docs.docker.com/config/daemon/systemd/#httphttps-proxy"
    echo
fi

echo
echo "Preflight checks passed. You should be able to launch the Agent containers."
echo
echo "After the containers are started, you may run additional diagnostics:"
echo
echo "* Check basic connectivity"
echo "  docker exec -ti gateway farcaster-diagnostics --check-connectivity"
echo
echo "* Check if a specific target is reachable"
echo "  docker exec -ti gateway farcaster-diagnostics --check-http <target_url>"
echo "  example: docker exec -ti gateway farcaster-diagnostics --check-http https://10.0.0.1:8080"
echo
