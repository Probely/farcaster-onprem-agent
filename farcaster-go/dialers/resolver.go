package dialers

import (
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
