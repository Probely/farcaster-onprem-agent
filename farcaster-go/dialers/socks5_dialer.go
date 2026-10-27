package dialers

import (
	"context"
	"fmt"
	"net"
	"net/url"

	"golang.org/x/net/proxy"
)

// socks5ProxyDialer handles SOCKS5 proxy connections.
type socks5ProxyDialer struct {
	proxyURL *url.URL
}

func (d *socks5ProxyDialer) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// Extract auth from URL.
	var auth *proxy.Auth
	if d.proxyURL.User != nil {
		auth = &proxy.Auth{User: d.proxyURL.User.Username()}
		if pass, ok := d.proxyURL.User.Password(); ok {
			auth.Password = pass
		}
	}

	baseDialer := &net.Dialer{}
	socks5, err := proxy.SOCKS5("tcp", d.proxyURL.Host, auth, baseDialer)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	// DialWithConn runs the SOCKS5 handshake on conn in place, bounded by ctx,
	// so dialContext returns the *net.TCPConn from baseDialer.
	conn, err := baseDialer.DialContext(ctx, "tcp", d.proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 connection failed: %w", err)
	}
	handshaker := socks5.(interface {
		DialWithConn(ctx context.Context, c net.Conn, network, address string) (net.Addr, error)
	})
	if _, err := handshaker.DialWithConn(ctx, conn, network, addr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 connection failed: %w", err)
	}
	return conn, nil
}
