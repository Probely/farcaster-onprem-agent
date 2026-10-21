package dialers

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"probely.com/farcaster/tlsconfig"
)

// TestHTTPProxyDialerKeepsBytesAfterResponse checks that bytes arriving with
// the CONNECT response remain readable on the returned connection.
func TestHTTPProxyDialerKeepsBytesAfterResponse(t *testing.T) {
	const banner = "SSH-2.0-test\r\n"
	tests := []struct {
		name  string
		start func(*httptest.Server)
	}{
		{"http", (*httptest.Server).Start},
		{"https", (*httptest.Server).StartTLS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, _, err := http.NewResponseController(w).Hijack()
				if err != nil {
					return
				}
				defer c.Close()
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n" + banner))
			}))
			tt.start(s)
			t.Cleanup(s.Close)
			proxyURL, err := url.Parse(s.URL)
			if err != nil {
				t.Fatal(err)
			}
			if s.TLS != nil {
				ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
				t.Setenv("FARCASTER_CUSTOM_CA", base64.StdEncoding.EncodeToString(ca))
				tlsconfig.ResetCache()
				t.Cleanup(tlsconfig.ResetCache)
			}
			d := NewTCPProxyDialerWithProxyFunc(5*time.Second, func(string) (*url.URL, error) { return proxyURL, nil }, nil)

			c, err := d.DialContext(t.Context(), "tcp", "192.0.2.10:22")
			if err != nil {
				t.Fatalf("DialContext: %v", err)
			}
			defer c.Close()
			if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(c)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(got) != banner {
				t.Fatalf("read %q, want %q", got, banner)
			}
		})
	}
}

// TestHTTPProxyDialerRejectedConnect checks that a rejected CONNECT fails
// with the proxy status while the response body is still pending.
func TestHTTPProxyDialerRejectedConnect(t *testing.T) {
	release := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 65536\r\n\r\n"))
		<-release
	}))
	t.Cleanup(s.Close)
	t.Cleanup(func() { close(release) })
	proxyURL, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	d := NewTCPProxyDialerWithProxyFunc(5*time.Second, func(string) (*url.URL, error) { return proxyURL, nil }, nil)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = d.DialContext(ctx, "tcp", "192.0.2.10:22")
	if err == nil || !strings.Contains(err.Error(), "403 Forbidden") {
		t.Fatalf("DialContext error = %v, want the 403 status", err)
	}
}
