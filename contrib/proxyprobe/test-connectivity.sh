#!/bin/bash

set +e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test Configuration
TEST_DELAY=1  # Delay between tests in seconds

# Host Configuration
TARGET_HOST="sink0.t.probely.com"
TARGET_HOST_TCP="sink1.t.probely.com"

# Port Configuration
declare -A PORTS=(
    [http]="80"
    [https]="443"
    [tcp]="8080"
    [tcp_tls]="8443"
)

# Path Configuration
WS_PATH="/ws"

# Build Target URLs
build_targets() {
    TARGET="${TARGET_HOST}:${PORTS[http]}"
    TARGET_TLS="${TARGET_HOST}:${PORTS[https]}"
    TARGET_TCP="${TARGET_HOST_TCP}:${PORTS[tcp]}"
    TARGET_TCP_TLS="${TARGET_HOST_TCP}:${PORTS[tcp_tls]}"
    TARGET_TCP_ALT="${TARGET_HOST_TCP}:${PORTS[http]}"
    TARGET_TCP_TLS_ALT="${TARGET_HOST_TCP}:${PORTS[https]}"
    WS_URL="ws://${TARGET_HOST}${WS_PATH}"
    WSS_URL="wss://${TARGET_HOST}${WS_PATH}"
}

# Test results storage
FAILED_TESTS=()
PASSED_TESTS=()

# Proxy Configuration
setup_proxies() {
    if [ -z "$HTTP_PROXY" ] && [ -n "$HTTPS_PROXY" ]; then
        HTTP_PROXY="$HTTPS_PROXY"
    fi

    if [ -z "$SOCKS_PROXY" ] && [ -n "$SOCKS5_PROXY" ]; then
        SOCKS_PROXY="$SOCKS5_PROXY"
    fi
}

# Helper Functions
print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

run_test() {
    local description="$1"
    shift
    echo -e "\n${BLUE}Testing: ${description}${NC}"
    sleep "$TEST_DELAY"
    if "$@"; then
        echo -e "${GREEN}✓ Success${NC}"
        PASSED_TESTS+=("$description")
        return 0
    else
        echo -e "${RED}✗ Failed${NC}"
        FAILED_TESTS+=("$description")
        return 1
    fi
}

run_connection_test() {
    local desc="$1"
    local target="$2"
    local payload="$3"
    shift 3

    run_test "$desc" ./proxyprobe -target "$target" -payload-name "$payload" "$@"
}

run_ws_test() {
    local desc="$1"
    local url="$2"
    local payload="$3"
    shift 3

    run_test "$desc" ./proxyprobe -ws-url "$url" -payload-name "$payload" "$@"
}

test_direct_connections() {
    print_header "Testing Direct Connections"

    run_connection_test "Direct HTTP connection" "$TARGET" "http"
    run_connection_test "Direct HTTPS connection (secure)" "$TARGET_TLS" "http" -tls
    run_connection_test "Direct HTTPS connection (allow-intercept)" "$TARGET_TLS" "http" -tls -insecure
}

test_proxy_connections() {
    local proxy_type="$1"
    local proxy_url="$2"
    local proxy_flag="$3"

    print_header "Testing ${proxy_type} Proxy Connections via $proxy_url"

    # HTTP/HTTPS tests
    run_connection_test "HTTP via ${proxy_type} proxy" "$TARGET" "http" "$proxy_flag" "$proxy_url"
    run_connection_test "HTTPS via ${proxy_type} proxy (secure)" "$TARGET_TLS" "http" "$proxy_flag" "$proxy_url" -tls
    run_connection_test "HTTPS via ${proxy_type} proxy (allow-intercept)" "$TARGET_TLS" "http" "$proxy_flag" "$proxy_url" -tls -insecure
}

test_websocket_basic() {
    local proxy_type="$1"
    local proxy_url="$2"
    local proxy_flag="$3"
    local extra_args=()

    [[ -n "$proxy_url" ]] && extra_args=("$proxy_flag" "$proxy_url")

    local proxy_desc=""
    [[ -n "$proxy_type" ]] && proxy_desc="via ${proxy_type} proxy "

    for protocol in "text" "wireguard"; do
        local protocol_desc="${protocol^}"

        # WS/WSS tests
        run_ws_test "WS ${proxy_desc}($protocol_desc)" "$WS_URL" "$protocol" "${extra_args[@]}"
        run_ws_test "WSS ${proxy_desc}($protocol_desc secure)" "$WSS_URL" "$protocol" "${extra_args[@]}"
        run_ws_test "WSS ${proxy_desc}($protocol_desc allow-intercept)" "$WSS_URL" "$protocol" "${extra_args[@]}" -insecure
    done
}

test_protocol_connections() {
    local protocol="$1"
    local proxy_type="$2"
    local proxy_url="$3"
    local proxy_flag="$4"
    local extra_args=()

    [[ -n "$proxy_url" ]] && extra_args=("$proxy_flag" "$proxy_url")

    local proxy_desc=""
    [[ -n "$proxy_type" ]] && proxy_desc="via $proxy_type proxy "

    # Regular ports
    run_connection_test "${protocol} ${proxy_desc}(port ${PORTS[tcp]})" "$TARGET_TCP" "$protocol" "${extra_args[@]}"
    run_connection_test "${protocol} ${proxy_desc}(port ${PORTS[http]})" "$TARGET_TCP_ALT" "$protocol" "${extra_args[@]}"

    # TLS ports
    for port_target in "$TARGET_TCP_TLS" "$TARGET_TCP_TLS_ALT"; do
        local port_desc="8443"
        [[ "$port_target" == "$TARGET_TCP_TLS_ALT" ]] && port_desc="443"

        run_connection_test "${protocol}+TLS ${proxy_desc}(port $port_desc secure)" "$port_target" "$protocol" "${extra_args[@]}" -tls
        run_connection_test "${protocol}+TLS ${proxy_desc}(port $port_desc allow-intercept)" "$port_target" "$protocol" "${extra_args[@]}" -tls -insecure
    done
}

test_websocket_connections() {
    print_header "Testing WebSocket Connections"

    # Direct connections
    test_websocket_basic "" "" ""

    # Proxy connections
    [[ -n "$HTTP_PROXY" ]] && test_websocket_basic "HTTP" "$HTTP_PROXY" "-http-proxy"
    [[ -n "$SOCKS_PROXY" ]] && test_websocket_basic "SOCKS" "$SOCKS_PROXY" "-socks5-proxy"
}

test_protocol() {
    local protocol="$1"
    print_header "Testing ${protocol^} Protocol"

    # Direct connections
    test_protocol_connections "$protocol" "" "" ""

    # Proxy connections
    [[ -n "$HTTP_PROXY" ]] && test_protocol_connections "$protocol" "HTTP" "$HTTP_PROXY" "-http-proxy"
    [[ -n "$SOCKS_PROXY" ]] && test_protocol_connections "$protocol" "SOCKS" "$SOCKS_PROXY" "-socks5-proxy"
}

print_summary() {
    print_header "Test Summary"

    print_test_section() {
        local title="$1"
        local color="$2"
        local tests=("${@:3}")

        echo -e "\n${BLUE}────────────────────────────────────────────────────────────${NC}"
        echo -e "${color}${title}${NC}"
        echo -e "${BLUE}────────────────────────────────────────────────────────────${NC}"

        for test in "${tests[@]}"; do
            local symbol="✓"
            [[ "$color" == "$RED" ]] && symbol="✗"
            printf "${color}${symbol}${NC} %s\n" "$test"
        done
    }

    print_test_section "PASSED TESTS" "$GREEN" "${PASSED_TESTS[@]}"
    [[ ${#FAILED_TESTS[@]} -gt 0 ]] && print_test_section "FAILED TESTS" "$RED" "${FAILED_TESTS[@]}"

    echo -e "${BLUE}────────────────────────────────────────────────────────────${NC}"
    echo -e "SUMMARY"
    echo -e "${BLUE}────────────────────────────────────────────────────────────${NC}"
    printf "Total Tests: %s\n" "$((${#PASSED_TESTS[@]} + ${#FAILED_TESTS[@]}))"
    printf "${GREEN}Passed: %s${NC}\n" "${#PASSED_TESTS[@]}"
    printf "${RED}Failed: %s${NC}\n" "${#FAILED_TESTS[@]}"
    echo -e "${BLUE}────────────────────────────────────────────────────────────${NC}"
}

main() {
    setup_proxies
    build_targets

    print_header "Starting Connectivity Tests"
    echo "Target: $TARGET_HOST"
    [ -n "$HTTP_PROXY" ] && echo "HTTP Proxy: $HTTP_PROXY"
    [ -n "$SOCKS_PROXY" ] && echo "SOCKS Proxy: $SOCKS_PROXY"

    test_direct_connections
    [[ -n "$HTTP_PROXY" ]] && test_proxy_connections "HTTP" "$HTTP_PROXY" "-http-proxy"
    [[ -n "$SOCKS_PROXY" ]] && test_proxy_connections "SOCKS" "$SOCKS_PROXY" "-socks5-proxy"
    test_websocket_connections
    test_protocol "text"
    test_protocol "wireguard"

    print_summary

    [ ${#FAILED_TESTS[@]} -eq 0 ]
}

main "$@"