package wireguard

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"bufio"

	"github.com/coder/websocket"
	"golang.org/x/net/context"
	"golang.org/x/net/proxy"
)

// Dialer is an interface for a connection dialer
type Dialer interface {
	Connect() (net.Conn, error)
	String() string
}

// DirectDialer connects directly to the target
type DirectDialer struct {
	addr    string
	timeout time.Duration
}

func NewDirectDialer(addr string, timeout time.Duration) *DirectDialer {
	return &DirectDialer{addr: addr, timeout: timeout}
}

func (d *DirectDialer) Connect() (net.Conn, error) {
	dialer := &net.Dialer{Timeout: d.timeout}
	conn, err := dialer.Dial("tcp", d.addr)
	if err != nil {
		return nil, fmt.Errorf("direct connection failed: %w", err)
	}
	return conn, nil
}

func (d *DirectDialer) String() string {
	return fmt.Sprintf("direct to %s", d.addr)
}

// HTTPProxyDialer connects via HTTP CONNECT proxy
type HTTPProxyDialer struct {
	proxyURL *url.URL
	addr     string
	timeout  time.Duration
	auth     string
}

func NewHTTPProxyDialer(proxyURL *url.URL, addr string, timeout time.Duration) *HTTPProxyDialer {
	d := &HTTPProxyDialer{
		proxyURL: proxyURL,
		addr:     addr,
		timeout:  timeout,
	}
	if proxyURL.User != nil {
		d.auth = generateProxyAuth(proxyURL.User)
	}
	return d
}

// Establish connection to the proxy and send a CONNECT request
func (d *HTTPProxyDialer) Connect() (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: d.timeout,
	}

	// Connect to proxy
	conn, err := dialer.DialContext(context.Background(), "tcp", d.proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("proxy connection failed: %w", err)
	}

	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: d.addr},
		Host:   d.addr,
		Header: make(http.Header),
	}
	if d.auth != "" {
		req.Header.Set("Proxy-Authorization", d.auth)
	}

	// Send CONNECT request and read response with timeout
	connectCtx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	done := make(chan struct{})
	var resp *http.Response
	var reqErr error

	go func() {
		defer close(done)
		reqErr = req.Write(conn)
		if reqErr != nil {
			return
		}
		br := bufio.NewReader(conn)
		resp, reqErr = http.ReadResponse(br, req)
	}()

	select {
	case <-connectCtx.Done():
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT timed out: %w", connectCtx.Err())
	case <-done:
		if reqErr != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to establish proxy connection: %w", reqErr)
		}
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s, body: %s", resp.Status, string(body))
	}

	return conn, nil
}

func (d *HTTPProxyDialer) String() string {
	return fmt.Sprintf("HTTP proxy %s to %s", d.proxyURL.Host, d.addr)
}

// SOCKS5Dialer connects via SOCKS5 proxy
type SOCKS5Dialer struct {
	proxyURL *url.URL
	addr     string
	timeout  time.Duration
}

func NewSOCKS5Dialer(proxyURL *url.URL, addr string, timeout time.Duration) *SOCKS5Dialer {
	return &SOCKS5Dialer{
		proxyURL: proxyURL,
		addr:     addr,
		timeout:  timeout,
	}
}

func (s *SOCKS5Dialer) Connect() (net.Conn, error) {
	dialer := &net.Dialer{Timeout: s.timeout}
	auth := &proxy.Auth{}
	if s.proxyURL.User != nil {
		auth.User = s.proxyURL.User.Username()
		if pass, ok := s.proxyURL.User.Password(); ok {
			auth.Password = pass
		}
	}

	socks5, err := proxy.SOCKS5("tcp", s.proxyURL.Host, auth, dialer)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	conn, err := socks5.Dial("tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 connection failed: %w", err)
	}

	return conn, nil
}

func (s *SOCKS5Dialer) String() string {
	return fmt.Sprintf("SOCKS5 proxy %s to %s", s.proxyURL.Host, s.addr)
}

// WebSocketDialer connects via WebSocket
type WebSocketDialer struct {
	url      *url.URL
	proxy    *url.URL
	insecure bool
	timeout  time.Duration
}

func NewWebSocketDialer(url *url.URL, proxy *url.URL, insecure bool, timeout time.Duration) *WebSocketDialer {
	return &WebSocketDialer{
		url:      url,
		proxy:    proxy,
		insecure: insecure,
		timeout:  timeout,
	}
}

func (s *WebSocketDialer) Connect() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: s.insecure,
		},
	}

	// Configure proxies
	if s.proxy.Scheme == "http" || s.proxy.Scheme == "https" {
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			return s.proxy, nil
		}

	} else if s.proxy.Scheme == "socks5" {
		auth := &proxy.Auth{}
		if s.proxy.User != nil {
			auth.User = s.proxy.User.Username()
			if pass, ok := s.proxy.User.Password(); ok {
				auth.Password = pass
			}
		}
		dialer, err := proxy.SOCKS5("tcp", s.proxy.Host, auth, &net.Dialer{
			Timeout: s.timeout,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
		}

		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.(proxy.ContextDialer).DialContext(ctx, network, addr)
		}

	} else {
		return nil, fmt.Errorf("unsupported proxy scheme: %s", s.proxy.Scheme)
	}

	httpClient := &http.Client{
		Transport: transport,
	}

	opts := &websocket.DialOptions{
		HTTPClient: httpClient,
	}

	wsConn, _, err := websocket.Dial(ctx, s.url.String(), opts)
	if err != nil {
		return nil, fmt.Errorf("websocket connection failed: %w", err)
	}

	return websocket.NetConn(ctx, wsConn, websocket.MessageBinary), nil
}

func (s *WebSocketDialer) String() string {
	desc := fmt.Sprintf("WebSocket to %s", s.url.String())
	if s.proxy != nil {
		desc += fmt.Sprintf(" via %s", s.proxy.String())
	}
	return desc
}

// TLSDialer connects directly using TLS
type TLSDialer struct {
	addr    string
	timeout time.Duration
}

func NewTLSDialer(addr string, timeout time.Duration) *TLSDialer {
	return &TLSDialer{addr: addr, timeout: timeout}
}

func (s *TLSDialer) Connect() (net.Conn, error) {
	dialer := &net.Dialer{Timeout: s.timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", s.addr, &tls.Config{
		InsecureSkipVerify: true, // Note: You might want to make this configurable
	})
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed: %w", err)
	}
	return conn, nil
}

func (s *TLSDialer) String() string {
	return fmt.Sprintf("TLS direct to %s", s.addr)
}

// Helper functions
func generateProxyAuth(user *url.Userinfo) string {
	if user == nil {
		return ""
	}
	username := user.Username()
	password, _ := user.Password()
	auth := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

// DialConfig is a configuration for creating dialers
type DialConfig struct {
	// Configuration options
	enableTLS  bool
	enableWS   bool
	enableWSS  bool
	httpProxy  *url.URL
	socksProxy *url.URL
}

func NewDialConfig() *DialConfig {
	return &DialConfig{
		enableTLS:  os.Getenv("ENABLE_TLS") == "true",
		enableWS:   os.Getenv("ENABLE_WS") == "true",
		enableWSS:  os.Getenv("ENABLE_WSS") == "true",
		httpProxy:  parseHTTPProxy(),
		socksProxy: parseSOCKSProxy(),
	}
}

// CreateStrategies returns a list of connection strategies for the given address
func (dc *DialConfig) Dialers(addr string, timeout time.Duration) []Dialer {
	var dialers []Dialer

	// If HTTP proxy is configured, add proxy strategies first
	if dc.httpProxy != nil {
		dialers = append(dialers,
			NewHTTPProxyDialer(dc.httpProxy, addr, timeout))

		if dc.enableTLS {
			dialers = append(dialers,
				NewHTTPProxyDialer(dc.httpProxy, addr, timeout))
		}

		if dc.enableWS {
			wsURL := &url.URL{Scheme: "ws", Host: addr, Path: "/"}
			dialers = append(dialers,
				NewWebSocketDialer(wsURL, dc.httpProxy, false, timeout))

			if dc.enableWSS {
				wssURL := &url.URL{Scheme: "wss", Host: addr, Path: "/"}
				dialers = append(dialers,
					NewWebSocketDialer(wssURL, dc.httpProxy, false, timeout))
			}
		}
	} else if dc.socksProxy != nil {
		dialers = append(dialers,
			NewSOCKS5Dialer(dc.socksProxy, addr, timeout))
	}

	// Always add direct TCP connection
	dialers = append(dialers,
		NewDirectDialer(addr, timeout))

	// Add TLS direct if enabled
	if dc.enableTLS {
		dialers = append(dialers,
			NewTLSDialer(addr, timeout))
	}

	// Add WebSocket direct if enabled
	if dc.enableWS {
		wsURL := &url.URL{Scheme: "ws", Host: addr, Path: "/"}
		dialers = append(dialers,
			NewWebSocketDialer(wsURL, nil, false, timeout))

		if dc.enableWSS {
			wssURL := &url.URL{Scheme: "wss", Host: addr, Path: "/"}
			dialers = append(dialers,
				NewWebSocketDialer(wssURL, nil, false, timeout))
		}
	}

	return dialers
}

func parseHTTPProxy() *url.URL {
	proxyURLStr := os.Getenv("HTTP_PROXY")
	if proxyURLStr == "" {
		proxyURLStr = os.Getenv("HTTPS_PROXY")
	}
	if proxyURLStr == "" {
		return nil
	}

	if !strings.HasPrefix(proxyURLStr, "http://") && !strings.HasPrefix(proxyURLStr, "https://") {
		proxyURLStr = "http://" + proxyURLStr
	}

	proxyURL, err := url.Parse(proxyURLStr)
	if err != nil {
		return nil
	}
	return proxyURL
}

func parseSOCKSProxy() *url.URL {
	proxyURLStr := os.Getenv("SOCKS5_PROXY")
	if proxyURLStr == "" {
		return nil
	}

	if !strings.HasPrefix(proxyURLStr, "socks5://") {
		proxyURLStr = "socks5://" + proxyURLStr
	}

	proxyURL, err := url.Parse(proxyURLStr)
	if err != nil {
		return nil
	}
	return proxyURL
}
