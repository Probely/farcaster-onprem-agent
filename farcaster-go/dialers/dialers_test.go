package dialers

import (
	"net"
	"net/url"
	"testing"
	"time"
)

func TestTCPProxyDialerBypassesProxyHost(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()

	// Point HTTP_PROXY at a closed port on 127.0.0.1 and use a ProxyFunc that
	// does not exempt loopback, so DialContext reaches the proxyHosts check
	// and connects directly to ln.
	proxyURL := &url.URL{Scheme: "http", Host: "127.0.0.1:1"}
	t.Setenv("HTTP_PROXY", proxyURL.String())

	d := NewTCPProxyDialerWithProxyFunc(time.Second, func(string) (*url.URL, error) {
		return proxyURL, nil
	}, nil)
	c, err := d.DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	c.Close()
}

func TestWithDefaultPort(t *testing.T) {
	tests := []struct {
		name  string
		proxy string
		want  string // Host of the returned URL.
	}{
		{"explicit port", "http://proxy.example:3128", "proxy.example:3128"},
		{"http", "http://proxy.example", "proxy.example:80"},
		{"https", "https://proxy.example", "proxy.example:443"},
		{"socks5h", "socks5h://proxy.example", "proxy.example:1080"},
		{"IPv6 literal", "http://[2001:db8::1]", "[2001:db8::1]:80"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.proxy)
			if err != nil {
				t.Fatal(err)
			}
			if got := withDefaultPort(u).Host; got != tt.want {
				t.Errorf("Host = %q, want %q", got, tt.want)
			}
		})
	}
}
