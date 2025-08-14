// Package dialers provides network dialers with built-in proxy support.
//
// This package offers multiple dialer implementations that handle proxy
// configuration from environment variables (HTTP_PROXY, HTTPS_PROXY, NO_PROXY)
// and route connections through the appropriate proxy type (HTTP CONNECT, SOCKS5)
// or directly as needed.
//
// The main dialers provided are:
//   - TCPProxyDialer: A TCP dialer with automatic proxy detection and routing.
//   - WebSocketDialer: Specialized dialer for WebSocket connections with proxy support.
//
// All dialers implement or follow the standard net.Dialer interface,
// making them compatible with existing Go networking code.
package dialers

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

// Dialer is the interface for connection dialers, partially implementing Go's net.Dialer interface.
type Dialer interface {
	// Dial connects to the given address on the given network.
	Dial(network, addr string) (net.Conn, error)
	// DialContext connects to the address on the named network using the provided context.
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// ProxyFunc determines which proxy URL to use for a given address.
// It returns nil if no proxy should be used (direct connection).
type ProxyFunc func(addr string) (*url.URL, error)

// TCPProxyDialer handles TCP connections with automatic proxy configuration based
// on environment variables (HTTP_PROXY, HTTPS_PROXY, NO_PROXY). It routes connections
// through the appropriate proxy type (HTTP CONNECT, SOCKS5) or directly as needed.
// Non-TCP connections bypass proxy and use direct dialing.
//
// Example usage:
//
//	dialer := dialers.NewTCPProxyDialer(30 * time.Second)
//	conn, err := dialer.Dial("tcp", "example.com:443")
type TCPProxyDialer struct {
	timeout    time.Duration
	proxyFunc  ProxyFunc
	proxyHosts map[string]bool
}

// NewTCPProxyDialer creates a TCP dialer that automatically handles proxy configuration
// from environment variables.
func NewTCPProxyDialer(timeout time.Duration) *TCPProxyDialer {
	d := &TCPProxyDialer{
		timeout:    timeout,
		proxyFunc:  proxyFromEnvironment,
		proxyHosts: make(map[string]bool),
	}
	d.initProxyHosts()
	return d
}

// NewTCPProxyDialerWithProxyFunc creates a TCP dialer with custom proxy resolution logic.
func NewTCPProxyDialerWithProxyFunc(timeout time.Duration, proxyFunc ProxyFunc) *TCPProxyDialer {
	if proxyFunc == nil {
		proxyFunc = proxyFromEnvironment
	}
	d := &TCPProxyDialer{
		timeout:    timeout,
		proxyFunc:  proxyFunc,
		proxyHosts: make(map[string]bool),
	}
	d.initProxyHosts()
	return d
}

// initProxyHosts discovers all possible proxy hosts from the environment and stores them
// to prevent circular connections (connecting to the proxy through the proxy).
func (d *TCPProxyDialer) initProxyHosts() {
	// Collect proxy hosts from environment.
	for _, env := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		val := strings.TrimSpace(os.Getenv(env))
		if val == "" {
			continue
		}
		u, err := url.Parse(val)
		if err != nil || u.Host == "" {
			continue
		}
		host := u.Host
		if h, _, e := net.SplitHostPort(u.Host); e == nil {
			host = h
		}
		host = strings.ToLower(host)
		d.proxyHosts[host] = true

		// If host is an IP, record it directly.
		if ip := net.ParseIP(host); ip != nil {
			d.proxyHosts[ip.String()] = true
			continue
		}

		// Resolve hostname once with a short timeout; cache IPs.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		cancel()
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip.IP != nil {
				d.proxyHosts[ip.IP.String()] = true
			}
		}
	}
}

// Dial connects to the address on the named network.
func (d *TCPProxyDialer) Dial(network, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()
	return d.DialContext(ctx, network, addr)
}

// DialContext connects to the address on the named network using the provided context.
func (d *TCPProxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// Only handle TCP connections for proxy.
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		// For non-TCP, use direct connection.
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, network, addr)
	}

	// Determine if we should use a proxy.
	proxyURL, err := d.proxyFunc(addr)
	if err != nil {
		return nil, fmt.Errorf("proxy resolution failed: %w", err)
	}
	// If no proxy is configured, use direct connection.
	if proxyURL == nil {
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, network, addr)
	}

	targetHost := addr
	if h, _, e := net.SplitHostPort(addr); e == nil {
		targetHost = h
	}
	// If destination host matches a known proxy hostname or IP, bypass proxy.
	if d.proxyHosts[strings.ToLower(targetHost)] {
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, network, addr)
	}

	// Route through appropriate proxy type.
	switch proxyURL.Scheme {
	case "http", "https":
		pd := &httpProxyDialer{
			proxyURL: proxyURL,
			timeout:  d.timeout,
		}
		if proxyURL.User != nil {
			pd.auth = generateProxyAuth(proxyURL.User)
		}
		return pd.dialContext(ctx, network, addr)
	case "socks5":
		pd := &socks5ProxyDialer{
			proxyURL: proxyURL,
			timeout:  d.timeout,
		}
		return pd.dialContext(ctx, network, addr)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", proxyURL.Scheme)
	}
}

func generateProxyAuth(user *url.Userinfo) string {
	if user == nil {
		return ""
	}
	username := user.Username()
	password, _ := user.Password()
	auth := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}
