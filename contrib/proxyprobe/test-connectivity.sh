#!/bin/bash

set +e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_DELAY=1  # Delay between tests in seconds

TARGET_HOST="sink0.t.probely.com"
TARGET_HOST_TCP="sink1.t.probely.com"
TARGET_PORT="80"
TARGET_TLS_PORT="443"
TCP_PORT="8080"
TCP_TLS_PORT="8443"
WS_PATH="/ws"

TARGET="${TARGET_HOST}:${TARGET_PORT}"
TARGET_TLS="${TARGET_HOST}:${TARGET_TLS_PORT}"
TARGET_TCP="${TARGET_HOST_TCP}:${TCP_PORT}"
TARGET_TCP_TLS="${TARGET_HOST_TCP}:${TCP_TLS_PORT}"
TARGET_TCP_ALT="${TARGET_HOST_TCP}:${TARGET_PORT}"
TARGET_TCP_TLS_ALT="${TARGET_HOST_TCP}:${TARGET_TLS_PORT}"
WS_URL="ws://${TARGET_HOST}${WS_PATH}"
WSS_URL="wss://${TARGET_HOST}${WS_PATH}"

# Add at the top with other variables
FAILED_TESTS=()
PASSED_TESTS=()

# Function to print section headers
print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

# Function to run a test and check its result
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

# Test HTTP/HTTPS direct connections
test_direct_connections() {
    print_header "Testing Direct Connections"
    
    # HTTP
    run_test "Direct HTTP connection" \
        ./proxyprobe -target "$TARGET" -payload-name "http"
    
    # HTTPS secure
    run_test "Direct HTTPS connection (secure)" \
        ./proxyprobe -target "$TARGET_TLS" -tls -payload-name "http"
    
    # HTTPS insecure
    run_test "Direct HTTPS connection (insecure)" \
        ./proxyprobe -target "$TARGET_TLS" -tls -payload-name "http" -insecure
}

# Test connections through HTTP proxy
test_http_proxy_connections() {
    if [ -n "$HTTP_PROXY" ]; then
        print_header "Testing HTTP Proxy Connections via $HTTP_PROXY"
        
        # HTTP via proxy
        run_test "HTTP via proxy" \
            ./proxyprobe -target "$TARGET" -http-proxy "$HTTP_PROXY" -payload-name "http"
        
        # HTTPS via proxy secure
        run_test "HTTPS via proxy (secure)" \
            ./proxyprobe -target "$TARGET_TLS" -http-proxy "$HTTP_PROXY" -tls -payload-name "http"
        
        # HTTPS via proxy insecure
        run_test "HTTPS via proxy (insecure)" \
            ./proxyprobe -target "$TARGET_TLS" -http-proxy "$HTTP_PROXY" -tls -payload-name "http" -insecure
    fi
}

# Test connections through SOCKS proxy
test_socks_proxy_connections() {
    if [ -n "$SOCKS_PROXY" ]; then
        print_header "Testing SOCKS Proxy Connections via $SOCKS_PROXY"
        
        # HTTP via SOCKS
        run_test "HTTP via SOCKS" \
            ./proxyprobe -target "$TARGET" -socks5-proxy "$SOCKS_PROXY" -payload-name "http"
        
        # HTTPS via SOCKS secure
        run_test "HTTPS via SOCKS (secure)" \
            ./proxyprobe -target "$TARGET_TLS" -socks5-proxy "$SOCKS_PROXY" -tls -payload-name "http"
        
        # HTTPS via SOCKS insecure
        run_test "HTTPS via SOCKS (insecure)" \
            ./proxyprobe -target "$TARGET_TLS" -socks5-proxy "$SOCKS_PROXY" -tls -payload-name "http"
    fi
}

# Test WebSocket connections
test_websocket_connections() {
    print_header "Testing WebSocket Connections"
    
    # WS direct
    run_test "Direct WS connection (PING/PONG)" \
        ./proxyprobe -ws-url "$WS_URL" -payload-name "text"
    
    # WSS direct secure
    run_test "Direct WSS connection (PING/PONG) secure" \
        ./proxyprobe -ws-url "$WSS_URL" -payload-name "text"
    
    # WSS direct insecure
    run_test "Direct WSS connection (PING/PONG) insecure" \
        ./proxyprobe -ws-url "$WSS_URL" -payload-name "text" -insecure
    
    # WS/WSS with Wireguard payload
    run_test "Direct WS connection (Wireguard)" \
        ./proxyprobe -ws-url "$WS_URL" -payload-name "wireguard"
    
    # WSS with Wireguard payload secure
    run_test "Direct WSS connection (Wireguard) secure" \
        ./proxyprobe -ws-url "$WSS_URL" -payload-name "wireguard"
    
    # WSS with Wireguard payload insecure
    run_test "Direct WSS connection (Wireguard) insecure" \
        ./proxyprobe -ws-url "$WSS_URL" -payload-name "wireguard" -insecure
}

# Test TCP with custom protocol (PING/PONG)
test_tcp_protocol() {
    print_header "Testing TCP Protocol (PING/PONG)"
    
    # Direct TCP
    run_test "Direct TCP connection (port 8080)" \
        ./proxyprobe -target "$TARGET_TCP" -payload-name "text"
    
    run_test "Direct TCP connection (port 80)" \
        ./proxyprobe -target "$TARGET_TCP_ALT" -payload-name "text"

    # Direct TCP+TLS
    run_test "Direct TCP+TLS connection (port 8443)" \
        ./proxyprobe -target "$TARGET_TCP_TLS" -tls -payload-name "text"
    
    run_test "Direct TCP+TLS connection (port 443)" \
        ./proxyprobe -target "$TARGET_TCP_TLS_ALT" -tls -payload-name "text"
    
    # Via HTTP Proxy
    if [ -n "$HTTP_PROXY" ]; then
        run_test "TCP via HTTP proxy (port 8080)" \
            ./proxyprobe -target "$TARGET_TCP" -http-proxy "$HTTP_PROXY" -payload-name "text"
        
        run_test "TCP via HTTP proxy (port 80)" \
            ./proxyprobe -target "$TARGET_TCP_ALT" -http-proxy "$HTTP_PROXY" -payload-name "text"
        
        run_test "TCP+TLS via HTTP proxy (port 8443)" \
            ./proxyprobe -target "$TARGET_TCP_TLS" -http-proxy "$HTTP_PROXY" -tls -payload-name "text"
        
        run_test "TCP+TLS via HTTP proxy (port 443)" \
            ./proxyprobe -target "$TARGET_TCP_TLS_ALT" -http-proxy "$HTTP_PROXY" -tls -payload-name "text"
    fi
    
    # Via SOCKS Proxy
    if [ -n "$SOCKS_PROXY" ]; then
        run_test "TCP via SOCKS proxy (port 8080)" \
            ./proxyprobe -target "$TARGET_TCP" -socks5-proxy "$SOCKS_PROXY" -payload-name "text"
        
        run_test "TCP via SOCKS proxy (port 80)" \
            ./proxyprobe -target "$TARGET_TCP_ALT" -socks5-proxy "$SOCKS_PROXY" -payload-name "text"
        
        run_test "TCP+TLS via SOCKS proxy (port 8443)" \
            ./proxyprobe -target "$TARGET_TCP_TLS" -socks5-proxy "$SOCKS_PROXY" -tls -payload-name "text"
        
        run_test "TCP+TLS via SOCKS proxy (port 443)" \
            ./proxyprobe -target "$TARGET_TCP_TLS_ALT" -socks5-proxy "$SOCKS_PROXY" -tls -payload-name "text"
    fi
}

# Test Wireguard protocol
test_wireguard_protocol() {
    print_header "Testing Wireguard Protocol"
    
    # Direct
    run_test "Direct Wireguard connection (port 8080)" \
        ./proxyprobe -target "$TARGET_TCP" -payload-name "wireguard"
    
    run_test "Direct Wireguard connection (port 80)" \
        ./proxyprobe -target "$TARGET_TCP_ALT" -payload-name "wireguard"
    
    # Direct TLS
    run_test "Direct Wireguard+TLS connection (port 8443)" \
        ./proxyprobe -target "$TARGET_TCP_TLS" -tls -payload-name "wireguard"
    
    run_test "Direct Wireguard+TLS connection (port 443)" \
        ./proxyprobe -target "$TARGET_TCP_TLS_ALT" -tls -payload-name "wireguard"
    
    # Via HTTP Proxy
    if [ -n "$HTTP_PROXY" ]; then
        run_test "Wireguard via HTTP proxy (port 8080)" \
            ./proxyprobe -target "$TARGET_TCP" -http-proxy "$HTTP_PROXY" -payload-name "wireguard"
        
        run_test "Wireguard via HTTP proxy (port 80)" \
            ./proxyprobe -target "$TARGET_TCP_ALT" -http-proxy "$HTTP_PROXY" -payload-name "wireguard"
        
        run_test "Wireguard+TLS via HTTP proxy (port 8443)" \
            ./proxyprobe -target "$TARGET_TCP_TLS" -http-proxy "$HTTP_PROXY" -tls -payload-name "wireguard"
        
        run_test "Wireguard+TLS via HTTP proxy (port 443)" \
            ./proxyprobe -target "$TARGET_TCP_TLS_ALT" -http-proxy "$HTTP_PROXY" -tls -payload-name "wireguard"
    fi
    
    # Via SOCKS Proxy
    if [ -n "$SOCKS_PROXY" ]; then
        run_test "Wireguard via SOCKS proxy (port 8080)" \
            ./proxyprobe -target "$TARGET_TCP" -socks5-proxy "$SOCKS_PROXY" -payload-name "wireguard"
        
        run_test "Wireguard via SOCKS proxy (port 80)" \
            ./proxyprobe -target "$TARGET_TCP_ALT" -socks5-proxy "$SOCKS_PROXY" -payload-name "wireguard"
        
        run_test "Wireguard+TLS via SOCKS proxy (port 8443)" \
            ./proxyprobe -target "$TARGET_TCP_TLS" -socks5-proxy "$SOCKS_PROXY" -tls -payload-name "wireguard"
        
        run_test "Wireguard+TLS via SOCKS proxy (port 443)" \
            ./proxyprobe -target "$TARGET_TCP_TLS_ALT" -socks5-proxy "$SOCKS_PROXY" -tls -payload-name "wireguard"
    fi
}

# Add this new function before main()
print_summary() {
    print_header "Test Summary"
    
    echo -e "\n${BLUE}────────────────────────────────────────────────────────────${NC}"
    echo -e "${GREEN}PASSED TESTS${NC}"
    echo -e "${BLUE}────────────────────────────────────────────────────────────${NC}"
    for test in "${PASSED_TESTS[@]}"; do
        printf "${GREEN}✓${NC} %s\n" "$test"
    done
    
    if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
        echo -e "${BLUE}────────────────────────────────────────────────────────────${NC}"
        echo -e "${RED}FAILED TESTS${NC}"
        echo -e "${BLUE}────────────────────────────────────────────────────────────${NC}"
        for test in "${FAILED_TESTS[@]}"; do
            printf "${RED}✗${NC} %s\n" "$test"
        done
    fi
    
    echo -e "${BLUE}────────────────────────────────────────────────────────────${NC}"
    echo -e "SUMMARY"
    echo -e "${BLUE}────────────────────────────────────────────────────────────${NC}"
    printf "Total Tests: %s\n" "$((${#PASSED_TESTS[@]} + ${#FAILED_TESTS[@]}))"
    printf "${GREEN}Passed: %s${NC}\n" "${#PASSED_TESTS[@]}"
    printf "${RED}Failed: %s${NC}\n" "${#FAILED_TESTS[@]}"
    echo -e "${BLUE}────────────────────────────────────────────────────────────${NC}"
}

# Main execution
main() {
    print_header "Starting Connectivity Tests"
    echo "Target: $TARGET_HOST"
    [ -n "$HTTP_PROXY" ] && echo "HTTP Proxy: $HTTP_PROXY"
    [ -n "$SOCKS_PROXY" ] && echo "SOCKS Proxy: $SOCKS_PROXY"
    
    test_direct_connections
    test_http_proxy_connections
    test_socks_proxy_connections
    test_websocket_connections
    test_tcp_protocol
    test_wireguard_protocol
    
    print_summary
    
    # Exit with failure if any tests failed
    [ ${#FAILED_TESTS[@]} -eq 0 ]
}

main "$@" 