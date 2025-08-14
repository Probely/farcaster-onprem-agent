package dialers

import (
	"net/url"
	"testing"
)

func TestProxyForURLWithFallback_Table(t *testing.T) {
	tests := []struct {
		name       string
		httpProxy  string
		httpsProxy string
		targetURL  string
		wantProxy  string // empty means nil
	}{
		{"ws uses http", "http://p-http:8080", "", "ws://host/x", "http://p-http:8080"},
		{"ws falls back to https", "", "http://p-https:8080", "ws://host/x", "http://p-https:8080"},
		{"wss uses https", "", "http://p-https:8080", "wss://host/x", "http://p-https:8080"},
		{"wss falls back to http", "http://p-http:8080", "", "wss://host/x", "http://p-http:8080"},
		{"http uses http", "http://p-http:8080", "", "http://host/x", "http://p-http:8080"},
		{"http falls back to https", "", "http://p-https:8080", "http://host/x", "http://p-https:8080"},
		{"https uses https", "", "http://p-https:8080", "https://host/x", "http://p-https:8080"},
		{"https falls back to http", "http://p-http:8080", "", "https://host/x", "http://p-http:8080"},
		{"no proxies", "", "", "https://host/x", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HTTP_PROXY", tt.httpProxy)
			t.Setenv("HTTPS_PROXY", tt.httpsProxy)
			t.Setenv("NO_PROXY", "")
			u, _ := url.Parse(tt.targetURL)
			p, err := proxyForURLWithFallback(u)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantProxy == "" {
				if p != nil {
					t.Fatalf("expected nil proxy, got %v", p)
				}
				return
			}
			if p == nil || p.String() != tt.wantProxy {
				t.Fatalf("unexpected proxy. got=%v want=%s", p, tt.wantProxy)
			}
		})
	}
}
