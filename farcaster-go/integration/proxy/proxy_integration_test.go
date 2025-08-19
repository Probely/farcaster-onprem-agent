package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	d "probely.com/farcaster/dialers"
)

func writeAndEcho(t *testing.T, conn net.Conn, line string) {
	t.Helper()
	if !strings.HasSuffix(line, "\n") {
		line += "\n"
	}
	if _, err := conn.Write([]byte(line)); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	r := bufio.NewReader(conn)
	resp, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if resp != line {
		t.Fatalf("mismatch: %q != %q", resp, line)
	}
}

func TestDirectTCP(t *testing.T) {
	target := os.Getenv("ECHO_TCP")
	if target == "" {
		t.Skip("ECHO_TCP not set")
	}
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		if os.Getenv("ENFORCE_PROXY") == "true" {
			t.Logf("expected failure with enforced proxy: %v", err)
			return
		}
		t.Fatalf("direct tcp dial: %v", err)
	}
	defer conn.Close()
	writeAndEcho(t, conn, "hello-direct")
}

func TestTCPViaEnvProxy(t *testing.T) {
	target := os.Getenv("ECHO_TCP")
	httpProxy := os.Getenv("HTTP_PROXY_URL")
	socksProxy := os.Getenv("SOCKS_PROXY_URL")
	if target == "" || httpProxy == "" || socksProxy == "" {
		t.Skip("missing envs")
	}

	cases := []struct {
		name       string
		proxy      string
		setNOProxy bool
	}{
		{"http", httpProxy, false},
		{"socks5", socksProxy, false},
		{"http_no_proxy", httpProxy, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HTTP_PROXY", tc.proxy)
			t.Setenv("HTTPS_PROXY", tc.proxy)
			if tc.setNOProxy {
				t.Setenv("NO_PROXY", "echoserver")
			} else {
				t.Setenv("NO_PROXY", "")
			}
			dialer := d.NewTCPProxyDialer(5 * time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			conn, err := dialer.DialContext(ctx, "tcp", target)
			if err != nil {
				if os.Getenv("ENFORCE_PROXY") == "true" && tc.setNOProxy {
					t.Logf("expected failure with NO_PROXY and enforced proxy: %v", err)
					return
				}
				t.Fatalf("tcp via proxy dial: %v", err)
			}
			defer conn.Close()
			writeAndEcho(t, conn, "hello-proxy")
		})
	}
}

func TestWebSocketProxyMatrix(t *testing.T) {
	echoWS := os.Getenv("ECHO_WS")
	httpProxy := os.Getenv("HTTP_PROXY_URL")
	socksProxy := os.Getenv("SOCKS_PROXY_URL")
	if echoWS == "" || httpProxy == "" || socksProxy == "" {
		t.Skip("missing envs")
	}

	clear := func() {
		for _, v := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"} {
			os.Unsetenv(v)
		}
	}

	t.Run("wss via HTTPS_PROXY", func(t *testing.T) {
		clear()
		t.Setenv("HTTPS_PROXY", httpProxy)
		// Assert CONNECT observed by proxy via env flag used by proxy image (mitmproxy logs to stdout).
		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		conn, err := d.NewWebSocketDialer(echoWS, tlsConfig, 12*time.Second).Dial()
		if err != nil {
			if os.Getenv("ENFORCE_PROXY") == "true" {
				t.Fatalf("wss via HTTPS_PROXY failed under enforcement: %v", err)
			}
			t.Fatalf("wss via HTTPS_PROXY failed: %v", err)
		}
		conn.Close()
	})

	t.Run("wss via ALL_PROXY", func(t *testing.T) {
		clear()
		t.Setenv("ALL_PROXY", httpProxy)
		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		conn, err := d.NewWebSocketDialer(echoWS, tlsConfig, 12*time.Second).Dial()
		if err != nil {
			t.Fatalf("wss via ALL_PROXY failed: %v", err)
		}
		conn.Close()
	})

	t.Run("ws via HTTP_PROXY", func(t *testing.T) {
		clear()
		wsURL := "ws://echoserver:9001/"
		t.Setenv("HTTP_PROXY", httpProxy)
		conn, err := d.NewWebSocketDialer(wsURL, nil, 12*time.Second).Dial()
		if err != nil {
			t.Fatalf("ws via HTTP_PROXY failed: %v", err)
		}
		conn.Close()
	})

	// Also test socks5 for wss via ALL_PROXY when desired environment is present
	_ = socksProxy // currently not used in these subtests
}
