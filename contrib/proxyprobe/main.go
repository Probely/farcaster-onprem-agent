package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	defaultConnectTimeout = 15 * time.Second
	defaultReadTimeout    = 15 * time.Second

	// WireGuard test keys
	wireguardInitiatordPrivateKey = ""
	wireguardResponderPublicKey   = ""
)

var payloads = map[string]func(string) []byte{
	"wireguard": mockWireguardPayload,
	"http":      createHTTPPayload,
	"text":      func(_ string) []byte { return []byte("PING\r\n") },
}

type Proxy struct {
	httpProxy   url.URL
	socks5Proxy url.URL
}

func NewProxy(httpProxy, socks5Proxy url.URL) *Proxy {
	return &Proxy{
		httpProxy:   httpProxy,
		socks5Proxy: socks5Proxy,
	}
}

func (p *Proxy) connectHTTP(addr string) (*net.TCPConn, error) {
	log.Printf("Connecting to HTTP proxy %s for target %s...", p.httpProxy.Host, addr)
	dialer := &net.Dialer{
		Timeout: defaultConnectTimeout,
	}

	conn, err := dialer.DialContext(context.Background(), "tcp", p.httpProxy.Host)
	if err != nil {
		return nil, fmt.Errorf("proxy connection failed: %w", err)
	}
	log.Printf("Connected to proxy, sending CONNECT request...")

	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}

	connectCtx, cancel := context.WithTimeout(context.Background(), defaultConnectTimeout)
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

	log.Printf("Proxy CONNECT response: %s", resp.Status)

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("failed to convert proxy connection to TCP")
	}

	return tcpConn, nil
}

func (p *Proxy) connectSOCKS5(addr string) (net.Conn, error) {
	log.Printf("Connecting to SOCKS5 proxy %s for target %s...", p.socks5Proxy.Host, addr)

	// Create a custom dialer with timeout for the SOCKS5 proxy connection
	contextDialer := &net.Dialer{
		Timeout: defaultConnectTimeout,
	}

	// Create SOCKS5 dialer with our timeout-enabled contextDialer
	dialer, err := proxy.SOCKS5("tcp", p.socks5Proxy.Host, nil, contextDialer)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	// Use context with timeout for the entire SOCKS5 connection process
	ctx, cancel := context.WithTimeout(context.Background(), defaultConnectTimeout)
	defer cancel()

	// Type assert to get the ContextDialer interface
	contextDialer2, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("failed to create context dialer for SOCKS5 proxy")
	}

	// Use DialContext instead of Dial to respect timeouts
	conn, err := contextDialer2.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SOCKS5 proxy: %w", err)
	}

	log.Printf("Connected through SOCKS5 proxy")
	return conn, nil
}

func testTCPTransport(conn net.Conn, payload []byte, useTLS bool, insecure bool, connType string, host string, payloadName string) error {
	var rw io.ReadWriter = conn
	if useTLS {
		log.Printf("Starting TLS handshake (%s)...", connType)
		config := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: insecure,
		}
		tlsConn := tls.Client(conn, config)
		if err := tlsConn.SetDeadline(time.Now().Add(defaultConnectTimeout)); err != nil {
			return fmt.Errorf("failed to set TLS handshake deadline: %w", err)
		}
		if err := tlsConn.Handshake(); err != nil {
			return fmt.Errorf("TLS handshake failed: %w", err)
		}
		log.Printf("TLS handshake completed (%s)", connType)
		rw = tlsConn
		defer tlsConn.Close()
	}

	if tc, ok := rw.(interface{ SetWriteDeadline(time.Time) error }); ok {
		if err := tc.SetWriteDeadline(time.Now().Add(defaultConnectTimeout)); err != nil {
			return fmt.Errorf("failed to set write deadline: %w", err)
		}
	}

	if shouldPrintHexPayload(payloadName) {
		log.Printf("Sending payload (%s) Hex: %x", connType, payload)
	} else {
		log.Printf("Sending payload (%s): %s", connType, string(payload))
	}

	if _, err := rw.Write(payload); err != nil {
		return fmt.Errorf("failed to send payload: %w", err)
	}
	log.Printf("Payload sent, waiting for response (%s)...", connType)

	if tc, ok := rw.(interface{ SetWriteDeadline(time.Time) error }); ok {
		if err := tc.SetWriteDeadline(time.Time{}); err != nil {
			return fmt.Errorf("failed to reset write deadline: %w", err)
		}
	}

	if tc, ok := rw.(interface{ SetReadDeadline(time.Time) error }); ok {
		if err := tc.SetReadDeadline(time.Now().Add(defaultReadTimeout)); err != nil {
			return fmt.Errorf("failed to set read deadline: %w", err)
		}
	}

	response := make([]byte, 128*1024)
	n, err := rw.Read(response)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if shouldPrintHexPayload(payloadName) {
		fmt.Printf("Hex Response: %x\n", response[:n])
	} else {
		fmt.Printf("Response: %s\n", string(response[:n]))
	}
	return nil
}

func testDirectTCPTransport(target string, payload []byte, useTLS bool, insecure bool, payloadName string) error {
	log.Printf("Connecting to %s (direct)...", target)
	dialer := net.Dialer{
		Timeout: defaultConnectTimeout,
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("invalid target address: %w", err)
	}
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		return fmt.Errorf("failed to connect to target: %w", err)
	}
	log.Printf("Connected to %s (direct)", target)
	return testTCPTransport(conn.(*net.TCPConn), payload, useTLS, insecure, "direct", host, payloadName)
}

func testHTTPProxyTransport(httpProxy, target string, payload []byte, useTLS bool, insecure bool, payloadName string) error {
	httpProxyURL, err := url.Parse(httpProxy)
	if err != nil {
		return fmt.Errorf("failed to parse http proxy: %w", err)
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("invalid target address: %w", err)
	}
	proxy := NewProxy(*httpProxyURL, url.URL{})
	conn, err := proxy.connectHTTP(target)
	if err != nil {
		return fmt.Errorf("failed to connect to proxy: %w", err)
	}
	return testTCPTransport(conn, payload, useTLS, insecure, fmt.Sprintf("http proxy: %s", httpProxy), host, payloadName)
}

func testSOCKS5ProxyTransport(socks5Proxy, target string, payload []byte, useTLS bool, insecure bool, payloadName string) error {
	socks5ProxyURL, err := url.Parse(socks5Proxy)
	if err != nil {
		return fmt.Errorf("failed to parse socks5 proxy: %w", err)
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("invalid target address: %w", err)
	}
	proxy := NewProxy(url.URL{}, *socks5ProxyURL)
	conn, err := proxy.connectSOCKS5(target)
	if err != nil {
		return fmt.Errorf("failed to connect to proxy: %w", err)
	}
	defer conn.Close()
	return testTCPTransport(conn, payload, useTLS, insecure, fmt.Sprintf("socks5 proxy: %s", socks5Proxy), host, payloadName)
}

func testWebSocketTransport(wsURL *url.URL, payload []byte, insecure bool, payloadName string) error {
	proxyType := "direct"
	if os.Getenv("HTTP_PROXY") != "" {
		proxyType = fmt.Sprintf("proxy: %s", os.Getenv("HTTP_PROXY"))
	} else if os.Getenv("SOCKS5_PROXY") != "" {
		proxyType = fmt.Sprintf("proxy: %s", os.Getenv("SOCKS5_PROXY"))
	}

	log.Printf("Establishing WebSocket connection to %s (%s)...", wsURL.String(), proxyType)
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			ServerName:         wsURL.Hostname(),
			InsecureSkipVerify: insecure,
		},
		Proxy: func(req *http.Request) (*url.URL, error) {
			return http.ProxyFromEnvironment(req)
		},
		HandshakeTimeout: defaultConnectTimeout,
	}

	conn, resp, err := dialer.Dial(wsURL.String(), nil)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("websocket dial failed with status %d: %w", resp.StatusCode, err)
		}
		return fmt.Errorf("websocket dial failed: %w", err)
	}
	defer conn.Close()
	log.Printf("WebSocket connection established (%s)", proxyType)

	log.Printf("Sending WebSocket message (%s)...", proxyType)
	if err := conn.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		return fmt.Errorf("failed to write to websocket: %w", err)
	}
	log.Printf("Message sent, waiting for response (%s)...", proxyType)

	if err := conn.SetReadDeadline(time.Now().Add(defaultReadTimeout)); err != nil {
		return fmt.Errorf("failed to set read deadline: %w", err)
	}

	_, message, err := conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to read from websocket: %w", err)
	}

	if shouldPrintHexPayload(payloadName) {
		fmt.Printf("WebSocket Response: %x\n", message)
	} else {
		fmt.Printf("WebSocket Response: %s\n", string(message))
	}
	return nil
}

func shouldPrintHexPayload(payloadName string) bool {
	// Only wireguard payloads should be hex-encoded
	return payloadName == "wireguard"
}

func main() {
	var (
		target      string
		tls         bool
		hexPayload  string
		payloadName string
		wsURL       string
		httpProxy   string
		socks5Proxy string
		insecure    bool
	)

	flag.StringVar(&target, "target", "", "Target address (host:port)")
	flag.StringVar(&httpProxy, "http-proxy", "", "HTTP proxy address (host:port)")
	flag.StringVar(&socks5Proxy, "socks5-proxy", "", "SOCKS5 proxy address (host:port)")
	flag.BoolVar(&tls, "tls", false, "Use TLS")
	flag.BoolVar(&insecure, "insecure", false, "Skip TLS certificate verification")
	flag.StringVar(&hexPayload, "payload", "", "Hex-encoded payload")
	flag.StringVar(&payloadName, "payload-name", "", "Use predefined payload: [wireguard]")
	flag.StringVar(&wsURL, "ws-url", "", "WebSocket URL (only for ws/wss)")
	flag.Parse()

	if target == "" && wsURL == "" {
		log.Fatal("Either target address or WebSocket URL is required")
	}

	var payload []byte
	var err error
	if hexPayload != "" {
		payload, err = hex.DecodeString(hexPayload)
		if err != nil {
			log.Fatalf("Invalid hex payload: %v", err)
		}
	} else {
		payloadFunc, ok := payloads[payloadName]
		if !ok {
			log.Fatalf("Unknown payload name %q. Available payloads: %v", payloadName, payloads)
		}
		log.Printf("Creating %s payload. Please wait...", payloadName)
		payload = payloadFunc(target)
		log.Printf("Payload created")
		if shouldPrintHexPayload(payloadName) {
			log.Printf("Payload (hex): %x", payload)
		} else {
			log.Printf("Payload: %s", string(payload))
		}
	}

	if httpProxy != "" {
		if !strings.HasPrefix(httpProxy, "http://") && !strings.HasPrefix(httpProxy, "https://") {
			httpProxy = "http://" + httpProxy
		}
	}

	if socks5Proxy != "" {
		if !strings.HasPrefix(socks5Proxy, "socks5://") {
			socks5Proxy = "socks5://" + socks5Proxy
		}
	}

	if wsURL != "" {
		if httpProxy != "" {
			os.Setenv("HTTP_PROXY", httpProxy)
			os.Setenv("HTTPS_PROXY", httpProxy)
		}
		// Mimic the behavior of the Go's net/http package, which uses HTTP_PROXY for
		// http:// URLs and HTTPS_PROXY for https:// URLs, regardless of the actual
		// proxy URL scheme. So, settings HTTP_PROXY to a SOCKS5 proxy will make the
		// Go's net/http package use the SOCKS5 proxy for http:// URLs.
		if socks5Proxy != "" {
			os.Setenv("SOCKS5_PROXY", socks5Proxy)
			os.Setenv("HTTP_PROXY", socks5Proxy)
			os.Setenv("HTTPS_PROXY", socks5Proxy)
		}
		targetURL, err := url.Parse(wsURL)
		if err != nil {
			log.Fatalf("Failed to parse target URL: %v", err)
		}
		err = testWebSocketTransport(targetURL, payload, insecure, payloadName)
		if err != nil {
			log.Fatalf("Test failed: %v", err)
		}
		return
	}

	if httpProxy != "" {
		err = testHTTPProxyTransport(httpProxy, target, payload, tls, insecure, payloadName)
		if err != nil {
			log.Fatalf("Test failed: %v", err)
		}
		return
	}

	if socks5Proxy != "" {
		err = testSOCKS5ProxyTransport(socks5Proxy, target, payload, tls, insecure, payloadName)
		if err != nil {
			log.Fatalf("Test failed: %v", err)
		}
		return
	}

	err = testDirectTCPTransport(target, payload, tls, insecure, payloadName)
	if err != nil {
		log.Fatalf("Test failed: %v", err)
	}
}

func mockWireguardPayload(_ string) []byte {
	payload, err := hex.DecodeString("00000094010000003551e4f915a4c9ed5ae0db77a6443d7173b0a0b0702f106c1df093bbfb37e52d7f82210d1dfaeb1d1a45b41138ddf0a87991f6e100aa144215ada3f68654407ac810a88f93cfc28158cd080ac3f522a30d2323a6411ca7f8a7193cd6f4f97a671459d348fde26fe9fdc49b1f87d790f724d264e1e04eb07ba2779934917ba2d600000000000000000000000000000000")
	if err != nil {
		panic(err)
	}
	return payload
}

func createWireguardPayload(_ string) []byte {
	privKey, err := decodeKey(wireguardInitiatordPrivateKey)
	if err != nil {
		log.Fatalf("Failed to decode initiator private key: %v", err)
	}
	pubKey, err := decodeKey(wireguardResponderPublicKey)
	if err != nil {
		log.Fatalf("Failed to decode responder public key: %v", err)
	}
	tun, _, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("192.168.0.1")},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1")},
		1420)
	if err != nil {
		log.Panic(err)
	}
	bind := NewDummyBind(
		netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 51820),
		netip.AddrPortFrom(netip.MustParseAddr("1.1.1.1"), 51820),
	)
	dev := device.NewDevice(tun, bind, device.NewLogger(device.LogLevelSilent, ""))
	err = dev.IpcSet(`private_key=` + hex.EncodeToString(privKey[:]) + `
public_key=` + hex.EncodeToString(pubKey[:]) + `
allowed_ip=0.0.0.0/0
persistent_keepalive_interval=10
endpoint=127.0.0.1:58120
`)
	if err != nil {
		log.Panic(err)
	}
	err = dev.Up()
	if err != nil {
		log.Panic(err)
	}

	select {
	case payload := <-bind.OutCh:
		dev.Down()
		bind.Close()
		return framePayload(payload)
	case <-time.After(defaultConnectTimeout):
		dev.Down()
		bind.Close()
		log.Fatal("Timeout waiting for WireGuard handshake")
		return nil
	}
}

func framePayload(payload []byte) []byte {
	// Frame the payload with a 2 byte big-endian size prefix
	size := uint16(len(payload))
	framedPayload := append(make([]byte, 2), byte(size>>8), byte(size&0xff))
	framedPayload = append(framedPayload, payload...)
	return framedPayload
}

func decodeKey(b64Key string) ([32]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return [32]byte{}, err
	}
	var key [32]byte
	copy(key[:], decoded)
	return key, nil
}

func createHTTPPayload(host string) []byte {
	return []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host))
}
