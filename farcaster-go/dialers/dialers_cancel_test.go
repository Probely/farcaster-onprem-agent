package dialers

import (
	"context"
	"io"
	"net"
	"net/url"
	"runtime"
	"testing"
	"time"
)

// stalledProxy accepts connections and never responds, simulating a proxy
// that hangs during its handshake.
func stalledProxy(t *testing.T) (addr string, accepted <-chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan net.Conn, 64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			ch <- c
		}
	}()
	return ln.Addr().String(), ch
}

// waitGoroutines waits up to 2s for the goroutine count to fall to limit.
func waitGoroutines(t *testing.T, limit int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > limit {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines alive, want at most %d", runtime.NumGoroutine(), limit)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestTCPProxyDialerStalledProxy verifies that dialing through a stalled proxy
// fails once the deadline expires and does not leak connections or goroutines.
func TestTCPProxyDialerStalledProxy(t *testing.T) {
	const dialTimeout = 50 * time.Millisecond
	tests := []struct {
		name    string
		scheme  string
		useCtx  bool // Call DialContext with a deadline; otherwise rely on Dial's timeout.
		timeout time.Duration
	}{
		{"https context", "https", true, time.Minute},
		{"http context", "http", true, time.Minute},
		{"socks5 context", "socks5", true, time.Minute},
		{"https timeout", "https", false, dialTimeout},
		{"socks5 timeout", "socks5", false, dialTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, accepted := stalledProxy(t)
			proxyURL := &url.URL{Scheme: tt.scheme, Host: addr}
			d := NewTCPProxyDialerWithProxyFunc(tt.timeout, func(string) (*url.URL, error) { return proxyURL, nil }, nil)

			dial := func() {
				t.Helper()
				start := time.Now()
				var c net.Conn
				var err error
				if tt.useCtx {
					ctx, cancel := context.WithTimeout(t.Context(), dialTimeout)
					defer cancel()
					c, err = d.DialContext(ctx, "tcp", "192.0.2.10:443")
				} else {
					c, err = d.Dial("tcp", "192.0.2.10:443")
				}
				if err == nil {
					c.Close()
					t.Fatal("dial through a stalled proxy succeeded")
				}
				if took := time.Since(start); took > time.Second {
					t.Fatalf("dial returned after %s, want shortly after %s", took, dialTimeout)
				}
				select {
				case pc := <-accepted:
					defer pc.Close()
					_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
					if _, err := io.Copy(io.Discard, pc); err != nil {
						t.Fatalf("proxy connection read returned %v, want EOF from the dialer closing it", err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("the dialer never connected to the proxy")
				}
			}

			// Warm up any one-time runtime goroutines before recording the baseline.
			dial()
			waitGoroutines(t, runtime.NumGoroutine())
			baseline := runtime.NumGoroutine()
			for range 5 {
				dial()
			}
			waitGoroutines(t, baseline)
		})
	}
}
