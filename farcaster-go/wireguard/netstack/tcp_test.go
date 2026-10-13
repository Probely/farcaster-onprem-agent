package netstack

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync"
	"testing"
	"time"

	"probely.com/farcaster/dialers"
)

const testWait = 5 * time.Second

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func serve(ln net.Listener, handle func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(c)
	}
}

// replyAfterEOFServer replies "pong:" followed by the request once the client
// half-closes, and closes without replying if that takes longer than testWait.
func replyAfterEOFServer(t *testing.T) string {
	t.Helper()
	ln := listen(t)
	go serve(ln, func(c net.Conn) {
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(testWait))
		req, err := io.ReadAll(c)
		if err != nil {
			return
		}
		_, _ = c.Write(append([]byte("pong:"), req...))
	})
	return ln.Addr().String()
}

// pipe copies in both directions until each reaches EOF, forwarding the
// half-close to the other side.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	for _, p := range [][2]net.Conn{{a, b}, {b, a}} {
		wg.Go(func() {
			_, _ = io.Copy(p[0], p[1])
			if cw, ok := p[0].(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
		})
	}
	wg.Wait()
}

// serveConnect handles an HTTP CONNECT request.
func serveConnect(w http.ResponseWriter, r *http.Request) {
	up, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer up.Close()
	c, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer c.Close()
	_, _ = brw.WriteString("HTTP/1.1 200 OK\r\n\r\n")
	_ = brw.Flush()
	pipe(c, up)
}

func httpProxy(t *testing.T) *url.URL {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(serveConnect))
	t.Cleanup(s.Close)
	return &url.URL{Scheme: "http", Host: s.Listener.Addr().String()}
}

// socks5Proxy serves SOCKS5 CONNECT to IPv4 targets without authentication.
func socks5Proxy(t *testing.T) *url.URL {
	t.Helper()
	ln := listen(t)
	go serve(ln, func(c net.Conn) {
		defer c.Close()
		// Greeting: VER NMETHODS METHODS; reply VER METHOD.
		greeting := make([]byte, 2)
		if _, err := io.ReadFull(c, greeting); err != nil {
			return
		}
		if _, err := io.ReadFull(c, make([]byte, greeting[1])); err != nil {
			return
		}
		if _, err := c.Write([]byte{5, 0}); err != nil {
			return
		}
		// Request: VER CMD RSV ATYP DST.ADDR DST.PORT, with ATYP 1 (IPv4).
		req := make([]byte, 10)
		if _, err := io.ReadFull(c, req); err != nil || req[3] != 1 {
			return
		}
		dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte(req[4:8])), binary.BigEndian.Uint16(req[8:]))
		up, err := net.Dial("tcp", dst.String())
		if err != nil {
			_, _ = c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		defer up.Close()
		if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
		pipe(c, up)
	})
	return &url.URL{Scheme: "socks5", Host: ln.Addr().String()}
}

// TestDialUpstreamThroughProxy checks that each proxy scheme yields an
// upstream connection that netstack can half-close.
func TestDialUpstreamThroughProxy(t *testing.T) {
	target := replyAfterEOFServer(t)
	tests := []struct {
		name  string
		proxy func(t *testing.T) *url.URL
	}{
		{"http", httpProxy},
		{"socks5", socks5Proxy},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// proxyFromEnvironment bypasses loopback addresses, so route through
			// proxyURL directly.
			proxyURL := tt.proxy(t)
			ns := &netstack{dialer: dialers.NewTCPProxyDialerWithProxyFunc(testWait,
				func(string) (*url.URL, error) { return proxyURL, nil }, nil)}

			up, err := ns.dialUpstream(t.Context(), target)
			if err != nil {
				t.Fatalf("dialUpstream: %v", err)
			}
			defer up.Close()

			if _, err := up.Write([]byte("ping")); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := up.CloseWrite(); err != nil {
				t.Fatalf("CloseWrite: %v", err)
			}
			got, err := io.ReadAll(up)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(got) != "pong:ping" {
				t.Fatalf("got %q, want %q", got, "pong:ping")
			}
		})
	}
}
