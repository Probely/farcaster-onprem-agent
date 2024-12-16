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

	packetPool = sync.Pool{
		New: func() any {
			b := make([]byte, headerSize+mtu)
			return &b
		},
	}
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

func (r *RobustTCPConn) establishConnection() (*net.TCPConn, error) {
	var newConn *net.TCPConn
	var err error

	if r.proxyURL != nil {
		r.log.Infof("Attempting connection to %s via proxy %s...", r.addr, r.proxyURL.Host)
		newConn, err = r.connectViaProxy(r.proxyURL)
		if err != nil {
			r.log.Warnf("Proxy connection to %s via %s failed: %v", r.addr, r.proxyURL.Host, err)
			return nil, fmt.Errorf("proxy connection failed: %w", err)
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
		if err == nil || !isConnectionError(err) {
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
	if err != nil && isConnectionError(err) {
		r.conn.Close()
		r.conn = nil
		// Try to establish new connection immediately
		newConn, err := r.establishConnection()
		if err != nil {
			return 0, err
		}
		r.conn = newConn
		// Try one more time with new connection
		return op(r.conn)
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
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	errStr := err.Error()
	if strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "use of closed network connection") {
		return true
	}
	return false
}

type TCPBind struct {
	conn *RobustTCPConn
	src  netip.AddrPort
	dst  netip.AddrPort
	log  *zap.SugaredLogger

	// Channels for packet handling
	writeCh chan []byte
	readCh  chan packet
	done    chan struct{}
	wg      sync.WaitGroup
}

type packet struct {
	data []byte
	err  error
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
		src:     *src,
		dst:     dst,
		conn:    conn,
		log:     log,
		writeCh: make(chan []byte, queueSize),
		readCh:  make(chan packet, queueSize),
		done:    make(chan struct{}),
	}

	// Start reader and writer goroutines
	b.wg.Add(2)
	go b.writeLoop()
	go b.readLoop()

	return b, nil
}

func (b *TCPBind) writeLoop() {
	defer b.wg.Done()

	for {
		select {
		case <-b.done:
			return
		case data := <-b.writeCh:
			_, err := b.conn.Write(data)
			if err != nil {
				b.log.Errorf("Failed to write packet: %v", err)
			}
			packetPool.Put(data)
		}
	}
}

func (b *TCPBind) readLoop() {
	defer b.wg.Done()

	header := make([]byte, headerSize)
	for {
		select {
		case <-b.done:
			return
		default:
			_, err := io.ReadFull(b.conn, header)
			if err != nil {
				if !isConnectionError(err) {
					b.log.Errorf("Failed to read header: %v", err)
				}
				select {
				case b.readCh <- packet{err: err}:
				case <-b.done:
					return
				}
				continue
			}

			size := binary.BigEndian.Uint16(header)
			if size == 0 {
				select {
				case b.readCh <- packet{err: fmt.Errorf("invalid packet size")}:
				case <-b.done:
					return
				}
				continue
			}

			buf := packetPool.Get().([]byte)
			_, err = io.ReadFull(b.conn, buf[:size])
			if err != nil {
				packetPool.Put(buf)
				if !isConnectionError(err) {
					b.log.Errorf("Failed to read packet: %v", err)
				}
				select {
				case b.readCh <- packet{err: err}:
				case <-b.done:
					return
				}
				continue
			}

			select {
			case b.readCh <- packet{data: buf[:size]}:
			case <-b.done:
				packetPool.Put(buf)
				return
			}
		}
	}
}

func (b *TCPBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return []conn.ReceiveFunc{b.makeReceiveIPv4()}, b.src.Port(), nil
}

func (b *TCPBind) makeReceiveIPv4() conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(bufs) == 0 || len(sizes) == 0 || len(eps) == 0 {
			return 0, fmt.Errorf("invalid buffer slices")
		}

		select {
		case pkt := <-b.readCh:
			if pkt.err != nil {
				return 0, pkt.err
			}

			if len(pkt.data) > len(bufs[0]) {
				packetPool.Put(pkt.data)
				return 0, fmt.Errorf("packet too large: %d bytes", len(pkt.data))
			}

			copy(bufs[0], pkt.data)
			sizes[0] = len(pkt.data)
			eps[0] = &TCPEndpoint{src: b.src, dst: b.dst}

			packetPool.Put(pkt.data)
			return 1, nil

		case <-b.done:
			return 0, fmt.Errorf("bind is closed")
		}
	}
}

func (b *TCPBind) BatchSize() int {
	return 1
}

func (b *TCPBind) Close() error {
	close(b.done)
	b.wg.Wait()
	return b.conn.Close()
}

func (b *TCPBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if len(bufs) == 0 {
		return nil
	}

	for _, data := range bufs {
		pktSize := len(data)
		if pktSize == 0 {
			continue
		}
		if pktSize > mtu {
			return fmt.Errorf("packet too large: %d bytes", pktSize)
		}

		pkt := packetPool.Get().([]byte)
		binary.BigEndian.PutUint16(pkt, uint16(pktSize))
		copy(pkt[headerSize:], data)

		select {
		case b.writeCh <- pkt[:headerSize+pktSize]:
		case <-b.done:
			packetPool.Put(pkt)
			return fmt.Errorf("bind is closed")
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
