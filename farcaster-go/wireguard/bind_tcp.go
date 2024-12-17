package wireguard

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"

	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/http/httpproxy"
	"golang.zx2c4.com/wireguard/conn"
)

const (
	mtu                   = 1500
	queueSize             = 1024
	headerSize            = 2
	defaultDialTimeout    = 10 * time.Second
	defaultKeepAlive      = 30 * time.Second
	defaultConnectTimeout = 30 * time.Second
)

var (
	_ conn.Endpoint = (*TCPEndpoint)(nil)
	_ conn.Bind     = (*TCPBind)(nil)
)

type RobustTCPConn struct {
	addr      string
	conn      *net.TCPConn // protected by mu for writes, can be read without lock
	mu        sync.Mutex   // guards conn modifications
	proxyURL  *url.URL     // cached proxy URL
	proxyAuth string       // cached proxy auth header
	log       *zap.SugaredLogger
}

func NewRobustTCPConn(addr string, log *zap.SugaredLogger) *RobustTCPConn {
	r := &RobustTCPConn{
		addr: addr,
		log:  log,
	}
	r.conn = nil

	proxyURL, err := r.determineProxyURL()
	if err != nil {
		r.log.Warn("Failed to determine proxy URL: ", err)
		// Continue without proxy
	} else if proxyURL != nil {
		r.log.Info("Initialized with proxy: ", proxyURL.String())
		r.proxyURL = proxyURL
		if proxyURL.User != nil {
			r.proxyAuth = r.generateProxyAuth(proxyURL.User)
		}
	}

	return r
}

func (r *RobustTCPConn) generateProxyAuth(user *url.Userinfo) string {
	if user == nil {
		return ""
	}
	username := user.Username()
	password, _ := user.Password()
	auth := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

func (r *RobustTCPConn) determineProxyURL() (*url.URL, error) {
	var proxyURL *url.URL
	schemes := []string{"https", "http"}
	for _, scheme := range schemes {
		reqURL := &url.URL{
			Scheme: scheme,
			Host:   r.addr,
		}

		// Get proxy configuration from environment
		proxyConfig := httpproxy.FromEnvironment()
		proxyURL, err := proxyConfig.ProxyFunc()(reqURL)
		if err != nil {
			return nil, fmt.Errorf("failed to determine proxy: %w", err)
		}
		if proxyURL != nil {
			r.log.Info("Using proxy from environment: ", proxyURL)
			return proxyURL, nil
		}
	}

	r.log.Debug("No proxy will be used")

	return proxyURL, nil
}

func (r *RobustTCPConn) connectDirect() (*net.TCPConn, error) {
	dialer := &net.Dialer{
		Timeout:   defaultDialTimeout,
		KeepAlive: defaultKeepAlive,
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultDialTimeout)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", r.addr)
	if err != nil {
		return nil, fmt.Errorf("direct connection failed: %w", err)
	}

	tcpConn := conn.(*net.TCPConn)
	if err := tcpConn.SetKeepAlive(true); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to set keepalive: %w", err)
	}
	if err := tcpConn.SetKeepAlivePeriod(defaultKeepAlive); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to set keepalive period: %w", err)
	}

	return tcpConn, nil
}

func (r *RobustTCPConn) connectViaProxy(proxyURL *url.URL) (*net.TCPConn, error) {
	dialer := &net.Dialer{
		Timeout:   defaultDialTimeout,
		KeepAlive: defaultKeepAlive,
	}

	conn, err := dialer.DialContext(context.Background(), "tcp", proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("proxy connection failed: %w", err)
	}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: r.addr},
		Host:   r.addr,
		Header: make(http.Header),
	}
	if r.proxyAuth != "" {
		req.Header.Set("Proxy-Authorization", r.proxyAuth)
	}

	connectCtx, cancel := context.WithTimeout(context.Background(), defaultConnectTimeout)
	defer cancel()
	done := make(chan struct{})
	var resp *http.Response

	// Write request and read response in a separate goroutine.
	go func() {
		defer close(done)
		if err = req.Write(conn); err != nil {
			// Err will be read by the select statement below.
			err = fmt.Errorf("failed to write CONNECT request: %w", err)
			return
		}
		br := bufio.NewReader(conn)
		resp, err = http.ReadResponse(br, req)
		// Note: don't close response body yet as we might need to read buffered data.
	}()

	// Wait for either completion or timeout
	select {
	case <-connectCtx.Done():
		return nil, fmt.Errorf("proxy CONNECT timed out: %w", connectCtx.Err())
	case <-done:
		if err != nil {
			return nil, err
		}
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("proxy CONNECT failed: %s, body: %s", resp.Status, string(body))
	}

	r.log.Info("Proxy CONNECT response: ", resp.Status)

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("failed to convert proxy connection to TCP")
	}

	if err := tcpConn.SetKeepAlive(true); err != nil {
		return nil, fmt.Errorf("failed to set keepalive: %w", err)
	}
	if err := tcpConn.SetKeepAlivePeriod(defaultKeepAlive); err != nil {
		return nil, fmt.Errorf("failed to set keepalive period: %w", err)
	}

	return tcpConn, nil
}

func (r *RobustTCPConn) establishConnection() (*net.TCPConn, error) {
	var newConn *net.TCPConn
	var err error

	if r.proxyURL != nil {
		r.log.Infof("Attempting connection to %s via proxy %s...", r.addr, r.proxyURL.Host)
		newConn, err = r.connectViaProxy(r.proxyURL)
		if err != nil {
			r.log.Warnf("Proxy connection to %s via %s failed: %v", r.addr, r.proxyURL.Host, err)
			return nil, fmt.Errorf("proxy connection to %s via %s failed: %w", r.addr, r.proxyURL.Host, err)
		}
		r.log.Infof("Proxy connection to %s via %s successful", r.addr, r.proxyURL.Host)
	} else {
		r.log.Infof("Attempting direct connection to %s...", r.addr)
		newConn, err = r.connectDirect()
		if err != nil {
			r.log.Warnf("Direct connection to %s failed: %v", r.addr, err)
			return nil, fmt.Errorf("direct connection failed: %w", err)
		}
		r.log.Infof("Direct connection to %s successful", r.addr)
	}

	return newConn, nil
}

func (r *RobustTCPConn) performIO(op func(*net.TCPConn) (int, error)) (n int, err error) {
	// Fast path: try without lock first
	if conn := r.conn; conn != nil {
		n, err = op(conn)
		if err == nil {
			return n, err
		}
		// Connection error occurred, fall through to reconnection logic
	}

	// Slow path: need to establish/re-establish connection
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check again with the lock. Another goroutine may have already established the connection
	// before we got the lock.
	if r.conn == nil {
		newConn, err := r.establishConnection()
		if err != nil {
			return 0, err
		}
		r.conn = newConn
	}

	n, err = op(r.conn)
	if err != nil {
		r.conn.Close()
		r.conn = nil
	}
	return n, err
}

func (r *RobustTCPConn) Read(b []byte) (n int, err error) {
	return r.performIO(func(conn *net.TCPConn) (int, error) {
		return conn.Read(b)
	})
}

func (r *RobustTCPConn) Write(b []byte) (n int, err error) {
	return r.performIO(func(conn *net.TCPConn) (int, error) {
		return conn.Write(b)
	})
}

func (r *RobustTCPConn) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.conn != nil {
		err := r.conn.Close()
		r.conn = nil
		return err
	}
	return nil
}

type TCPBind struct {
	conn *RobustTCPConn
	src  netip.AddrPort
	dst  netip.AddrPort
	log  *zap.SugaredLogger

	done chan struct{}
}

func NewTCPBind(src *netip.AddrPort, conn *RobustTCPConn, log *zap.SugaredLogger) (*TCPBind, error) {
	if src == nil {
		return nil, fmt.Errorf("src cannot be nil")
	}
	if conn == nil {
		return nil, fmt.Errorf("conn cannot be nil")
	}
	if log == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	dst, err := netip.ParseAddrPort(conn.addr)
	if err != nil {
		return nil, fmt.Errorf("invalid destination address: %w", err)
	}

	b := &TCPBind{
		src:  *src,
		dst:  dst,
		conn: conn,
		log:  log,
		done: make(chan struct{}),
	}

	return b, nil
}

func (b *TCPBind) makeReceiveIPv4() conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		if len(bufs) == 0 || len(sizes) == 0 || len(eps) == 0 {
			return 0, fmt.Errorf("invalid buffer slices")
		}

		var header [headerSize]byte
		_, err = io.ReadFull(b.conn, header[:])
		if err != nil {
			return 0, err
		}

		size := binary.BigEndian.Uint16(header[:])
		if size == 0 {
			return 0, fmt.Errorf("invalid packet size")
		}

		if size > uint16(len(bufs[0])) {
			return 0, fmt.Errorf("packet too large: %d bytes", size)
		}

		_, err = io.ReadFull(b.conn, bufs[0][:size])
		if err != nil {
			return 0, err
		}

		sizes[0] = int(size)
		eps[0] = &TCPEndpoint{src: b.src, dst: b.dst}

		return 1, nil
	}
}

func (b *TCPBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return []conn.ReceiveFunc{b.makeReceiveIPv4()}, b.src.Port(), nil
}

func (b *TCPBind) BatchSize() int {
	return 1
}

func (b *TCPBind) Close() error {
	close(b.done)
	return b.conn.Close()
}

func (b *TCPBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if len(bufs) == 0 {
		return nil
	}

	var header [headerSize]byte
	for _, data := range bufs {
		binary.BigEndian.PutUint16(header[:], uint16(len(data)))
		_, err := b.conn.Write(append(header[:], data...))
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *TCPBind) SetMark(mark uint32) error {
	return nil
}

type TCPEndpoint struct {
	dst netip.AddrPort
	src netip.AddrPort
}

func (b *TCPBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if s == "" {
		return nil, fmt.Errorf("empty endpoint string")
	}

	dst, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint address: %w", err)
	}

	if !dst.IsValid() {
		return nil, fmt.Errorf("invalid endpoint: %s", s)
	}

	return &TCPEndpoint{
		dst: dst,
	}, nil
}

func (e *TCPEndpoint) ClearSrc() {
	e.src = netip.AddrPort{}
}

func (e *TCPEndpoint) SrcToString() string {
	if !e.src.IsValid() {
		return ""
	}
	return e.src.String()
}

func (e *TCPEndpoint) DstIP() netip.Addr {
	return e.dst.Addr()
}

func (e *TCPEndpoint) DstPort() uint16 {
	return e.dst.Port()
}

func (e *TCPEndpoint) SrcIP() netip.Addr {
	return e.src.Addr()
}

func (e *TCPEndpoint) DstToBytes() []byte {
	if !e.dst.IsValid() {
		return nil
	}
	b, err := e.dst.MarshalBinary()
	if err != nil {
		return nil
	}
	return b
}
func (e *TCPEndpoint) DstToString() string {
	if !e.dst.IsValid() {
		return ""
	}
	return e.dst.String()
}
