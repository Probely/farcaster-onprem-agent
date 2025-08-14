package dialers

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// socks5ProxyDialer handles SOCKS5 proxy connections.
type socks5ProxyDialer struct {
	proxyURL *url.URL
	timeout  time.Duration
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

	// proxy.Dialer doesn't support context, so we handle cancellation.
	type dialResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan dialResult, 1)

	go func() {
		conn, err := socks5.Dial(network, addr)
		ch <- dialResult{conn, err}
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("SOCKS5 dial cancelled: %w", ctx.Err())
	case result := <-ch:
		if result.err != nil {
			return nil, fmt.Errorf("SOCKS5 connection failed: %w", result.err)
		}
		return result.conn, nil
	}
}
