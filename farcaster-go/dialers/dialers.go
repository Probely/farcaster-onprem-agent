package dialers

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
	"golang.org/x/net/http/httpproxy"
	"golang.org/x/net/proxy"
)

type ProxyFunc func(addr string) (*url.URL, error)

// Dialer is an interface for a connection dialer
type Dialer interface {
	Connect() (net.Conn, error)
	String() string
}

// TCPProxyFromEnvironment returns the proxy URL for the given address based on
// HTTP_PROXY, HTTPS_PROXY, and NO_PROXY environment variables.
// If the address should be connected to directly, nil is returned.
func TCPProxyFromEnvironment(addr string) (*url.URL, error) {
	// Create a fake URL with the address to check proxy rules
	// We use http scheme as default for TCP connections
	u := &url.URL{
		Scheme: "http",
		Host:   addr,
	}
	return httpproxy.FromEnvironment().ProxyFunc()(u)
}

// normalizeProxyURL adds the appropriate scheme to a proxy URL if missing
func normalizeProxyURL(proxyStr string, isSocks bool) string {
	if proxyStr == "" || strings.Contains(proxyStr, "://") {
		return proxyStr
	}

	if isSocks {
		return "socks5://" + proxyStr
	}
	return "http://" + proxyStr
}

// parseProxyURL tries to parse proxy URL from environment variables
func parseProxyURL(vars []string) *url.URL {
	for _, v := range vars {
		if val := os.Getenv(v); val != "" {
			// Add default scheme if missing
			isSocks := strings.Contains(strings.ToUpper(v), "SOCKS")
			val = normalizeProxyURL(val, isSocks)

			if u, err := url.Parse(val); err == nil {
				return u
			}
		}
	}
	return nil
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
	auth := extractSOCKS5Auth(s.proxyURL)

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
	switch s.proxy.Scheme {
	case "http", "https":
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			return s.proxy, nil
		}

	case "socks5":
		auth := extractSOCKS5Auth(s.proxy)
		dialer, err := proxy.SOCKS5("tcp", s.proxy.Host, auth, &net.Dialer{
			Timeout: s.timeout,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
		}

		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.(proxy.ContextDialer).DialContext(ctx, network, addr)
		}

	default:
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

// extractSOCKS5Auth extracts authentication from URL for SOCKS5 proxy
func extractSOCKS5Auth(u *url.URL) *proxy.Auth {
	if u == nil || u.User == nil {
		return &proxy.Auth{}
	}

	auth := &proxy.Auth{
		User: u.User.Username(),
	}
	if pass, ok := u.User.Password(); ok {
		auth.Password = pass
	}
	return auth
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
		httpProxy:  ParseHTTPProxy(),
		socksProxy: ParseSOCKSProxy(),
	}
}

// WithTLS enables or disables TLS connections
func (dc *DialConfig) WithTLS(enable bool) *DialConfig {
	dc.enableTLS = enable
	return dc
}

// WithWebSocket enables or disables WebSocket connections
func (dc *DialConfig) WithWebSocket(enable bool) *DialConfig {
	dc.enableWS = enable
	return dc
}

// WithSecureWebSocket enables or disables secure WebSocket connections
func (dc *DialConfig) WithSecureWebSocket(enable bool) *DialConfig {
	dc.enableWSS = enable
	return dc
}

// WithHTTPProxy sets the HTTP proxy to use
func (dc *DialConfig) WithHTTPProxy(proxyURL *url.URL) *DialConfig {
	dc.httpProxy = proxyURL
	return dc
}

// WithSOCKSProxy sets the SOCKS proxy to use
func (dc *DialConfig) WithSOCKSProxy(proxyURL *url.URL) *DialConfig {
	dc.socksProxy = proxyURL
	return dc
}

// WithHTTPProxyString sets the HTTP proxy from a string URL
func (dc *DialConfig) WithHTTPProxyString(proxyURLStr string) *DialConfig {
	if proxyURLStr == "" {
		dc.httpProxy = nil
		return dc
	}

	proxyURLStr = normalizeProxyURL(proxyURLStr, false)
	if u, err := url.Parse(proxyURLStr); err == nil {
		dc.httpProxy = u
	}
	return dc
}

// WithSOCKSProxyString sets the SOCKS proxy from a string URL
func (dc *DialConfig) WithSOCKSProxyString(proxyURLStr string) *DialConfig {
	if proxyURLStr == "" {
		dc.socksProxy = nil
		return dc
	}

	proxyURLStr = normalizeProxyURL(proxyURLStr, true)
	if u, err := url.Parse(proxyURLStr); err == nil {
		dc.socksProxy = u
	}
	return dc
}

// CreateStrategies returns a list of connection strategies for the given address
func (dc *DialConfig) Dialers(addr string, timeout time.Duration) []Dialer {
	var dialers []Dialer

	// Helper to create WebSocket URLs
	makeWSURL := func(secure bool) *url.URL {
		scheme := "ws"
		if secure {
			scheme = "wss"
		}
		return &url.URL{Scheme: scheme, Host: addr, Path: "/"}
	}

	// If HTTP proxy is configured, add proxy strategies
	if dc.httpProxy != nil {
		dialers = append(dialers,
			NewHTTPProxyDialer(dc.httpProxy, addr, timeout))

		if dc.enableWS {
			dialers = append(dialers,
				NewWebSocketDialer(makeWSURL(false), dc.httpProxy, false, timeout))

			if dc.enableWSS {
				dialers = append(dialers,
					NewWebSocketDialer(makeWSURL(true), dc.httpProxy, false, timeout))
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
		dialers = append(dialers,
			NewWebSocketDialer(makeWSURL(false), nil, false, timeout))

		if dc.enableWSS {
			dialers = append(dialers,
				NewWebSocketDialer(makeWSURL(true), nil, false, timeout))
		}
	}

	return dialers
}

func ParseHTTPProxy() *url.URL {
	// Try each proxy variable in order
	vars := []string{"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"}
	return parseProxyURL(vars)
}

func ParseSOCKSProxy() *url.URL {
	return parseProxyURL([]string{"SOCKS5_PROXY"})
}

// TCPDialer is a smart dialer that handles proxy configuration automatically
type TCPDialer struct {
	proxyFunc ProxyFunc
	timeout   time.Duration
}

// NewTCPDialer creates a new TCP dialer with the given proxy function and timeout
func NewTCPDialer(proxyFunc ProxyFunc, timeout time.Duration) *TCPDialer {
	if proxyFunc == nil {
		// Default to environment-based proxy configuration.
		proxyFunc = TCPProxyFromEnvironment
	}
	return &TCPDialer{
		proxyFunc: proxyFunc,
		timeout:   timeout,
	}
}

// DialContext connects to the given address, using a proxy if configured
func (d *TCPDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// Determine if we should use a proxy
	proxyURL, err := d.proxyFunc(addr)
	if err != nil {
		return nil, fmt.Errorf("proxy resolution failed: %w", err)
	}

	if proxyURL != nil {
		// Use proxy connection
		switch proxyURL.Scheme {
		case "http", "https":
			proxyDialer := NewHTTPProxyDialer(proxyURL, addr, d.timeout)
			return proxyDialer.Connect()
		case "socks5":
			socksDialer := NewSOCKS5Dialer(proxyURL, addr, d.timeout)
			return socksDialer.Connect()
		default:
			return nil, fmt.Errorf("unsupported proxy scheme: %s", proxyURL.Scheme)
		}
	}

	// Direct connection
	dialer := &net.Dialer{
		Timeout: d.timeout,
	}
	return dialer.DialContext(ctx, network, addr)
}

// Dial connects to the given address (non-context version)
func (d *TCPDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}
