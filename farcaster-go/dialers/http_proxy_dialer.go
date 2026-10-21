package dialers

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"probely.com/farcaster/tlsconfig"
)

// httpProxyDialer handles HTTP/HTTPS proxy connections using CONNECT.
type httpProxyDialer struct {
	proxyURL *url.URL
	timeout  time.Duration
	auth     string
}

func (d *httpProxyDialer) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("HTTP proxy only supports TCP connections")
	}

	baseDialer := &net.Dialer{}

	// Connect to proxy.
	conn, err := baseDialer.DialContext(ctx, "tcp", d.proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("proxy connection failed: %w", err)
	}

	// If the proxy scheme is HTTPS, wrap the connection with TLS before sending CONNECT.
	if strings.EqualFold(d.proxyURL.Scheme, "https") {
		serverName := d.proxyURL.Host
		if h, _, splitErr := net.SplitHostPort(d.proxyURL.Host); splitErr == nil {
			serverName = h
		}

		// Get centralized TLS config.
		tlsConfig, err := tlsconfig.GetTLSConfig()
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to get TLS config: %w", err)
		}
		tlsConfig.ServerName = serverName
		tlsConn := tls.Client(conn, tlsConfig)
		if handshakeErr := tlsConn.HandshakeContext(ctx); handshakeErr != nil {
			conn.Close()
			return nil, fmt.Errorf("tls handshake with proxy failed: %w", handshakeErr)
		}
		conn = tlsConn
	}

	// Send CONNECT request.
	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if d.auth != "" {
		req.Header.Set("Proxy-Authorization", d.auth)
	}

	// Send request and read response.
	done := make(chan error, 1)
	go func() {
		if err := req.Write(conn); err != nil {
			done <- fmt.Errorf("failed to send CONNECT: %w", err)
			return
		}
		// The bytes after the response belong to the target, so read only up
		// to the end of the headers and leave the rest on conn.
		br := bufio.NewReader(oneByteReader{conn})
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			done <- fmt.Errorf("failed to read CONNECT response: %w", err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			// Report only the status; the caller closes conn.
			done <- fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
			return
		}
		done <- nil
	}()

	select {
	case <-ctx.Done():
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT cancelled: %w", ctx.Err())
	case err := <-done:
		if err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

// oneByteReader reads at most one byte per call, so a bufio.Reader over it
// reads only the bytes its caller requests.
type oneByteReader struct{ r io.Reader }

func (o oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return o.r.Read(p)
}
