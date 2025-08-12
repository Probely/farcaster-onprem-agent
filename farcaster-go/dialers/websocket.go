package dialers

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/coder/websocket"
	"probely.com/farcaster/tlsconfig"
)

// WebSocketDialer provides a way to establish WebSocket connections
// through a proxy-aware HTTP transport. It automatically handles proxy configuration
// from environment variables (HTTP_PROXY, HTTPS_PROXY, NO_PROXY) by using
// ProxyFromEnvironmentWithFallback.
//
// The dialer creates an http.Transport that respects proxy settings and uses it
// with the websocket client to establish connections through proxies when configured.
//
// Example:
//
//	ws := dialers.NewWebSocketDialer("wss://example.com/ws", nil, 30*time.Second)
//	conn, err := ws.Dial()
type WebSocketDialer struct {
	url       string
	tlsConfig *tls.Config
	timeout   time.Duration
}

// NewWebSocketDialer creates a dialer for WebSocket connections.
func NewWebSocketDialer(wsURL string, tlsConfig *tls.Config, timeout time.Duration) *WebSocketDialer {
	return &WebSocketDialer{
		url:       wsURL,
		tlsConfig: tlsConfig,
		timeout:   timeout,
	}
}

// Dial establishes a WebSocket connection using proxy settings from environment variables.
func (d *WebSocketDialer) Dial() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()
	return d.DialContext(ctx)
}

// DialContext establishes a WebSocket connection using the provided context.
func (d *WebSocketDialer) DialContext(ctx context.Context) (net.Conn, error) {
	// Parse the URL to validate it
	u, err := url.Parse(d.url)
	if err != nil {
		return nil, fmt.Errorf("invalid WebSocket URL: %w", err)
	}

	var tlsConfig *tls.Config
	if d.tlsConfig != nil {
		tlsConfig = d.tlsConfig
	} else {
		tlsConfig, err = tlsconfig.GetTLSConfig()
		if err != nil {
			tlsConfig = nil
		}
	}

	// Create transport that honors standard proxy envs and uses sane timeouts.
	transport := &http.Transport{
		TLSClientConfig:   tlsConfig,
		Proxy:             ProxyFromEnvironmentWithFallback,
		ForceAttemptHTTP2: false,
		DialContext:       (&net.Dialer{Timeout: d.timeout}).DialContext,
	}

	httpClient := &http.Client{
		Transport: transport,
	}

	opts := &websocket.DialOptions{
		HTTPClient: httpClient,
	}

	// Establish WebSocket connection
	wsConn, _, err := websocket.Dial(ctx, u.String(), opts)
	if err != nil {
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}

	// Convert to net.Conn
	return websocket.NetConn(ctx, wsConn, websocket.MessageBinary), nil
}
