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
	"strings"

	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/http/httpproxy"
	"golang.zx2c4.com/wireguard/conn"
)

const (
	headerSize            = 2
	defaultDialTimeout    = 10 * time.Second
	defaultKeepAlive      = 30 * time.Second
	defaultConnectTimeout = 30 * time.Second
)

var (
	_ conn.Endpoint = (*TCPEndpoint)(nil)
	_ conn.Bind     = (*TCPBind)(nil)
)

type tcpConnectionState struct {
	conn  *net.TCPConn
	epoch int64
}

type RobustTCPConn struct {
	addr      string
	conn      atomic.Value // stores *tcpConnectionState
	mu        sync.Mutex   // guards connection establishment only
	epoch     int64        // atomic, incremented for each new connection
	proxyURL  *url.URL     // cached proxy URL
	proxyAuth string       // cached proxy auth header
	log       *zap.SugaredLogger
}

func NewRobustTCPConn(addr string, log *zap.SugaredLogger) *RobustTCPConn {
	r := &RobustTCPConn{
		addr: addr,
		log:  log,
	}
	r.conn.Store((*tcpConnectionState)(nil))

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

	// Create context with timeout for the entire proxy connection process
	ctx, cancel := context.WithTimeout(context.Background(), defaultConnectTimeout)
	defer cancel()

	// Connect to the proxy server
	conn, err := dialer.DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("proxy connection failed: %w", err)
	}
	// Ensure connection is closed if any subsequent steps fail
	var success bool
	defer func() {
		if !success {
			conn.Close()
		}
	}()

	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Host: r.addr},
		Host:   r.addr,
		Header: make(http.Header),
	}

	if r.proxyAuth != "" {
		req.Header.Set("Proxy-Authorization", r.proxyAuth)
	}

	if err := conn.SetDeadline(time.Now().Add(defaultConnectTimeout)); err != nil {
		return nil, fmt.Errorf("failed to set deadline: %w", err)
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("failed to write CONNECT request: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy CONNECT failed with status: %s", resp.Status)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("failed to clear deadline: %w", err)
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("failed to convert proxy connection to TCP")
	}

	success = true
	return tcpConn, nil
}

func (r *RobustTCPConn) establishConnection() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if state := r.conn.Load().(*tcpConnectionState); state != nil {
		return nil
	}

	var newConn *net.TCPConn
	var err error

	if r.proxyURL != nil {
		r.log.Infof("Attempting connection to %s via proxy %s...", r.addr, r.proxyURL.Host)
		newConn, err = r.connectViaProxy(r.proxyURL)
		if err != nil {
			r.log.Warnf("Proxy connection to %s via %s failed: %v", r.addr, r.proxyURL.Host, err)
			return fmt.Errorf("proxy connection failed: %w", err)
		}
		r.log.Infof("Proxy connection to %s via %s successful", r.addr, r.proxyURL.Host)
	} else {
		r.log.Infof("Attempting direct connection to %s...", r.addr)
		newConn, err = r.connectDirect()
		if err != nil {
			r.log.Warnf("Direct connection to %s failed: %v", r.addr, err)
			return fmt.Errorf("direct connection failed: %w", err)
		}
		r.log.Infof("Direct connection to %s successful", r.addr)
	}

	state := &tcpConnectionState{
		conn:  newConn,
		epoch: atomic.AddInt64(&r.epoch, 1),
	}
	r.conn.Store(state)
	return nil
}

func (r *RobustTCPConn) Read(b []byte) (n int, err error) {
	for {
		state := r.conn.Load().(*tcpConnectionState)
		if state == nil {
			if err := r.establishConnection(); err != nil {
				return 0, err
			}
			continue
		}

		n, err = state.conn.Read(b)
		if err != nil && isConnectionError(err) {
			if current := r.conn.Load().(*tcpConnectionState); current != nil && current.epoch == state.epoch {
				r.conn.Store((*tcpConnectionState)(nil))
				state.conn.Close()
			}
			if err := r.establishConnection(); err != nil {
				return 0, err
			}
			continue
		}
		return n, err
	}
}

func (r *RobustTCPConn) Write(b []byte) (n int, err error) {
	for {
		state := r.conn.Load().(*tcpConnectionState)
		if state == nil {
			if err := r.establishConnection(); err != nil {
				return 0, err
			}
			continue
		}

		n, err = state.conn.Write(b)
		if err != nil && isConnectionError(err) {
			if current := r.conn.Load().(*tcpConnectionState); current != nil && current.epoch == state.epoch {
				r.conn.Store((*tcpConnectionState)(nil))
				state.conn.Close()
			}
			if err := r.establishConnection(); err != nil {
				return 0, err
			}
			continue
		}
		return n, err
	}
}

func (r *RobustTCPConn) Close() error {
	state := r.conn.Load().(*tcpConnectionState)
	if state != nil {
		r.conn.Store((*tcpConnectionState)(nil))
		return state.conn.Close()
	}
	return nil
}

func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	if err == io.ErrUnexpectedEOF {
		return true
	}
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout() || netErr.Temporary()
	}
	errStr := err.Error()
	if strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection refused") {
		return true
	}
	return false
}

type TCPBind struct {
	conn *RobustTCPConn
	src  netip.AddrPort
	dst  netip.AddrPort
	rmu  sync.Mutex
	smu  sync.Mutex
	log  *zap.SugaredLogger
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

	return &TCPBind{
		src:  *src,
		dst:  dst,
		conn: conn,
		log:  log,
	}, nil
}

func (b *TCPBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return []conn.ReceiveFunc{b.makeReceiveIPv4()}, b.src.Port(), nil
}

func (b *TCPBind) makeReceiveIPv4() conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(bufs) == 0 || len(sizes) == 0 || len(eps) == 0 {
			return 0, fmt.Errorf("invalid buffer slices")
		}

		b.rmu.Lock()
		defer b.rmu.Unlock()

		// Read the packet size header. We are framing UDP packets in TCP packets
		// using a 2 byte header.
		header := make([]byte, headerSize)
		n, err := io.ReadFull(b.conn, header)
		if err != nil {
			return 0, fmt.Errorf("failed to read header: %w", err)
		}
		if n != headerSize {
			return 0, fmt.Errorf("incomplete header read: got %d bytes", n)
		}
		pktSize := binary.BigEndian.Uint16(header)
		if pktSize == 0 {
			return 0, fmt.Errorf("invalid packet size")
		}
		if int(pktSize) > len(bufs[0]) {
			return 0, fmt.Errorf("packet too large: %d bytes", pktSize)
		}
		// Read the packet data.
		n, err = io.ReadFull(b.conn, bufs[0][:pktSize])
		if err != nil {
			return 0, fmt.Errorf("failed to read packet: %w", err)
		}
		if n != int(pktSize) {
			return 0, fmt.Errorf("incomplete packet read: got %d bytes, expected %d", n, pktSize)
		}

		eps[0] = &TCPEndpoint{src: b.src, dst: b.dst}
		sizes[0] = n

		return 1, nil
	}
}

func (b *TCPBind) BatchSize() int {
	return 1
}

func (b *TCPBind) Close() error {
	return b.conn.Close()
}

func (b *TCPBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if len(bufs) == 0 {
		return nil
	}

	b.smu.Lock()
	defer b.smu.Unlock()

	// Write the packet size header. We are framing UDP packets in TCP packets
	// using a 2 byte header.
	header := make([]byte, headerSize)
	for _, data := range bufs {
		pktSize := len(data)
		if pktSize == 0 {
			continue
		}
		if pktSize > 65535 {
			return fmt.Errorf("packet too large: %d bytes", pktSize)
		}
		binary.BigEndian.PutUint16(header, uint16(pktSize))
		_, err := b.conn.Write(header)
		if err != nil {
			return fmt.Errorf("failed to write packet header: %w", err)
		}
		// Write packet data.
		n, err := b.conn.Write(data)
		if err != nil {
			return fmt.Errorf("failed to write packet data: %w", err)
		}
		if n != pktSize {
			return fmt.Errorf("incomplete packet write: wrote %d bytes, expected %d", n, pktSize)
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
