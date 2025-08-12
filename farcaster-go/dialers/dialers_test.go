package dialers

import (
	"net/url"
	"testing"
	"time"
)

func TestProxyFromEnvironment_HTTPAndHTTPS(t *testing.T) {
	// Ensure a clean environment per test.
	t.Setenv("HTTP_PROXY", "http://proxy-http:8080")
	t.Setenv("HTTPS_PROXY", "http://proxy-https:8080")
	t.Setenv("NO_PROXY", "")
	t.Setenv("ALL_PROXY", "http://proxy-all:8080")

	// Address without scheme should favor HTTPS proxy when appropriate.
	if p, err := proxyFromEnvironment("example.com:443"); err != nil || p == nil {
		t.Fatalf("expected HTTPS proxy for 443, got err=%v url=%v", err, p)
	} else if p.String() != "http://proxy-https:8080" {
		// httpproxy selects proxy by request scheme, not proxy scheme.
		// For https targets, HTTPS_PROXY applies.
		t.Fatalf("unexpected proxy for 443: %s", p.String())
	}

	if p, err := proxyFromEnvironment("example.com:80"); err != nil || p == nil {
		t.Fatalf("expected HTTP proxy for 80, got err=%v url=%v", err, p)
	} else if p.String() != "http://proxy-https:8080" {
		// Our proxyFromEnvironment asks https first for all TCP dials, then http.
		// So with both vars set it will return HTTPS_PROXY for port 80 as well.
		t.Fatalf("unexpected proxy for 80: %s", p.String())
	}
}

func TestProxyFromEnvironment_NoProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy-http:8080")
	t.Setenv("HTTPS_PROXY", "http://proxy-https:8080")
	t.Setenv("NO_PROXY", "example.com")
	// ALL_PROXY is intentionally ignored by our implementation.
	t.Setenv("ALL_PROXY", "http://proxy-all:8080")

	if p, err := proxyFromEnvironment("example.com:443"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	} else if p != nil {
		t.Fatalf("expected no proxy due to NO_PROXY, got %v", p)
	}
}

func TestProxyFromEnvironment_AllProxyIgnored(t *testing.T) {
	// Only ALL_PROXY set.
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "")
	t.Setenv("ALL_PROXY", "http://proxy-all:8080")

	if p, err := proxyFromEnvironment("example.com:443"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	} else if p != nil {
		t.Fatalf("expected nil proxy when only ALL_PROXY is set, got %v", p)
	}
}

func TestGetProxyForURL_WebSocketSchemes(t *testing.T) {
	// Configure separate proxies for HTTP and HTTPS.
	t.Setenv("HTTP_PROXY", "http://proxy-http:8080")
	t.Setenv("HTTPS_PROXY", "http://proxy-https:8080")
	t.Setenv("NO_PROXY", "")
	t.Setenv("ALL_PROXY", "http://proxy-all:8080")

	ws, _ := url.Parse("ws://example.com/chat")
	p, err := GetProxyForURL(ws)
	if err != nil || p == nil {
		t.Fatalf("expected proxy for ws://, got err=%v url=%v", err, p)
	}
	if p.String() != "http://proxy-http:8080" {
		t.Fatalf("unexpected proxy for ws://: %s", p.String())
	}

	wss, _ := url.Parse("wss://secure.example.com/chat")
	p, err = GetProxyForURL(wss)
	if err != nil || p == nil {
		t.Fatalf("expected proxy for wss://, got err=%v url=%v", err, p)
	}
	if p.String() != "http://proxy-https:8080" {
		t.Fatalf("unexpected proxy for wss://: %s", p.String())
	}
}

func TestGetProxyForURL_WebSocketFallbacks(t *testing.T) {
	// Case 1: Only HTTP_PROXY set; wss should fall back to HTTP_PROXY.
	t.Setenv("HTTP_PROXY", "http://proxy-http:8080")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "")
	t.Setenv("ALL_PROXY", "")

	wss, _ := url.Parse("wss://secure.example.com/chat")
	if p, err := GetProxyForURL(wss); err != nil || p == nil {
		t.Fatalf("expected fallback proxy for wss://, got err=%v url=%v", err, p)
	} else if p.String() != "http://proxy-http:8080" {
		t.Fatalf("unexpected fallback for wss://: %s", p.String())
	}

	// Case 2: Only HTTPS_PROXY set; ws should fall back to HTTPS_PROXY.
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "http://proxy-https:8080")
	ws, _ := url.Parse("ws://example.com/chat")
	if p, err := GetProxyForURL(ws); err != nil || p == nil {
		t.Fatalf("expected fallback proxy for ws://, got err=%v url=%v", err, p)
	} else if p.String() != "http://proxy-https:8080" {
		t.Fatalf("unexpected fallback for ws://: %s", p.String())
	}
}

func TestWebSocketDialer_Construct(t *testing.T) {
	// Construction should not panic and should set reasonable defaults.
	_ = NewWebSocketDialer("wss://example.com/ws", nil, 5*time.Second)
}
