package dialers

import (
	"net/http"
	"net/url"

	"golang.org/x/net/http/httpproxy"
)

// proxyFromEnvironment returns the proxy URL for TCP connections based on
// environment variables. For addresses without schemes, it tries HTTPS_PROXY
// first, then HTTP_PROXY.
func proxyFromEnvironment(addr string) (*url.URL, error) {
	cfg := httpproxy.FromEnvironment()
	pf := cfg.ProxyFunc()

	if p, _ := pf(&url.URL{Scheme: "https", Host: addr}); p != nil {
		return p, nil
	}
	if p, _ := pf(&url.URL{Scheme: "http", Host: addr}); p != nil {
		return p, nil
	}
	return nil, nil
}

// GetProxyForURL returns the proxy URL for the given target URL.
func GetProxyForURL(targetURL *url.URL) (*url.URL, error) {
	if targetURL == nil {
		return nil, nil
	}
	// Use stdlib first to allow ALL_PROXY/NO_PROXY semantics when available.
	if p, err := http.ProxyFromEnvironment(&http.Request{URL: targetURL}); p != nil || err != nil {
		return p, err
	}
	return proxyForURLWithFallback(targetURL)
}

// ProxyFromEnvironmentWithFallback is similar to net/http.ProxyFromEnvironment but
// if the scheme-specific proxy env (HTTP_PROXY/HTTPS_PROXY) yields no proxy, it
// tries the opposite scheme as a fallback. NO_PROXY rules are still honored via
// httpproxy. This provides more forgiving behavior when only one proxy env is set.
func ProxyFromEnvironmentWithFallback(req *http.Request) (*url.URL, error) {
	if req == nil || req.URL == nil {
		return nil, nil
	}
	// Try stdlib first.
	if p, err := http.ProxyFromEnvironment(req); p != nil || err != nil {
		return p, err
	}
	return proxyForURLWithFallback(req.URL)
}

// proxyForURLWithFallback resolves a proxy for the given URL using environment
// variables, trying the URL's own scheme first and then the opposite one as
// fallback (http<->https). WebSocket schemes are mapped to http/https first.
func proxyForURLWithFallback(targetURL *url.URL) (*url.URL, error) {
	cfg := httpproxy.FromEnvironment()
	pf := cfg.ProxyFunc()

	resolveURL := *targetURL
	switch resolveURL.Scheme {
	case "ws":
		resolveURL.Scheme = "http"
	case "wss":
		resolveURL.Scheme = "https"
	}

	if p, _ := pf(&resolveURL); p != nil {
		return p, nil
	}

	// Try fallback to the opposite scheme.
	fallbackURL := resolveURL
	switch resolveURL.Scheme {
	case "http":
		fallbackURL.Scheme = "https"
	case "https":
		fallbackURL.Scheme = "http"
	default:
		return nil, nil
	}
	return pf(&fallbackURL)
}
