package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"golang.zx2c4.com/wireguard/conn"

	d "probely.com/farcaster/dialers"
	"probely.com/farcaster/wireguard"
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
			log := zap.NewNop().Sugar()
			dialer := d.NewTCPProxyDialer(5*time.Second, log)
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

func TestWebSocketViaEnvProxy(t *testing.T) {
	echoWS := os.Getenv("ECHO_WS")
	httpProxy := os.Getenv("HTTP_PROXY_URL")
	socksProxy := os.Getenv("SOCKS_PROXY_URL")
	if echoWS == "" || httpProxy == "" || socksProxy == "" {
		t.Skip("missing envs")
	}

	cases := []struct {
		name  string
		proxy string
	}{
		{"intercepting http", httpProxy},
		{"socks5", socksProxy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, v := range []string{"HTTP_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy"} {
				t.Setenv(v, "")
			}
			t.Setenv("HTTPS_PROXY", tc.proxy)
			wsRoundTrip(t, echoWS)
		})
	}
}

// wsRoundTrip sends a datagram over a WebSocket bind to the echo server at
// wsURL and waits for its echo, resending while the bind connects.
func wsRoundTrip(t *testing.T, wsURL string) {
	t.Helper()
	u, err := wireguard.ParseWSURL(wsURL)
	if err != nil {
		t.Fatal(err)
	}
	src := netip.MustParseAddrPort("10.0.0.1:51820")
	// The echo server and mitmproxy present self-signed certificates.
	cfg := wireguard.WSConfig{URL: u, TLSConfig: &tls.Config{InsecureSkipVerify: true}}
	b, err := wireguard.NewWSBind(&src, "192.0.2.1:443", cfg, zaptest.NewLogger(t).Sugar())
	if err != nil {
		t.Fatal(err)
	}
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ep, err := b.ParseEndpoint("192.0.2.1:443")
	if err != nil {
		t.Fatal(err)
	}

	echoed := make(chan []byte, 1)
	go func() {
		bufs := [][]byte{make([]byte, 65535)}
		sizes, eps := make([]int, 1), make([]conn.Endpoint, 1)
		if n, err := fns[0](bufs, sizes, eps); err == nil && n == 1 {
			echoed <- bufs[0][:sizes[0]]
		}
	}()

	want := []byte("hello-ws")
	deadline := time.After(12 * time.Second)
	for {
		if err := b.Send([][]byte{want}, ep); err != nil {
			t.Fatalf("Send: %v", err)
		}
		select {
		case got := <-echoed:
			if !bytes.Equal(got, want) {
				t.Fatalf("echo %q, want %q", got, want)
			}
			return
		case <-time.After(200 * time.Millisecond):
		case <-deadline:
			t.Fatal("no echo within 12s")
		}
	}
}
