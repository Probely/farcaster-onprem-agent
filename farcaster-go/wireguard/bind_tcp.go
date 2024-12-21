package wireguard

import (
	"bufio"
	"bytes"
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
	headerSize            = 2
	defaultConnectTimeout = 20 * time.Second
	defaultWriteTimeout   = 20 * time.Second
	batchSize             = 1 // Note that if this is greater than 1, we need to change the way we read packets
	readBufferSize        = 1024 * 1024
)

var (
	_ conn.Endpoint = (*TCPEndpoint)(nil)
	_ conn.Bind     = (*TCPBind)(nil)
)

type RobustTCPConn struct {
	addr      string
	proxyURL  *url.URL // cached proxy URL
	proxyAuth string   // cached proxy auth header
	log       *zap.SugaredLogger

	mu        sync.Mutex // protects conn and reader
	bufreader *bufio.Reader
	conn      *net.TCPConn
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
	schemes := []string{"https", "http"}
	for _, scheme := range schemes {
		reqURL := &url.URL{
			Scheme: scheme,
			Host:   r.addr,
		}

		proxyConfig := httpproxy.FromEnvironment()
		proxyURL, err := proxyConfig.ProxyFunc()(reqURL)
		if err != nil {
			r.log.Warnf("Failed to determine proxy for scheme %s: %v", scheme, err)
			continue
		}
		if proxyURL != nil {
			r.log.Info("Using proxy from environment: ", proxyURL)
			return proxyURL, nil
		}
	}

	r.log.Debug("No proxy will be used")
	return nil, nil
}

func (r *RobustTCPConn) connectDirect() (*net.TCPConn, error) {
	dialer := &net.Dialer{
		Timeout: defaultConnectTimeout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultConnectTimeout)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", r.addr)
	if err != nil {
		return nil, fmt.Errorf("direct connection failed: %w", err)
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("failed to assert connection to *net.TCPConn")
	}

	return tcpConn, nil
}

func (r *RobustTCPConn) connectProxy(proxyURL *url.URL) (*net.TCPConn, error) {
	dialer := &net.Dialer{
		Timeout: defaultConnectTimeout,
	}

	conn, err := dialer.DialContext(context.Background(), "tcp", proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("proxy connection failed: %w", err)
	}

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

	r.log.Info("Proxy CONNECT response: ", resp.Status)

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("failed to convert proxy connection to TCP")
	}

	return tcpConn, nil
}

// connect establishes a connection to the remote address.
// It will attempt to use a proxy if one is configured.
// Caller must hold the lock.
func (r *RobustTCPConn) connect() (*net.TCPConn, error) {
	var conn *net.TCPConn
	var err error
	if r.proxyURL != nil {
		r.log.Infof("Attempting connection to %s via proxy %s...", r.addr, r.proxyURL.Host)
		conn, err = r.connectProxy(r.proxyURL)
		if err != nil {
			r.log.Warnf("Proxy connection to %s via %s failed: %v", r.addr, r.proxyURL.Host, err)
			return nil, fmt.Errorf("proxy connection to %s via %s failed: %w", r.addr, r.proxyURL.Host, err)
		}
		r.log.Infof("Proxy connection to %s via %s successful", r.addr, r.proxyURL.Host)
	} else {
		r.log.Infof("Attempting direct connection to %s...", r.addr)
		conn, err = r.connectDirect()
		if err != nil {
			r.log.Warnf("Direct connection to %s failed: %v", r.addr, err)
			return nil, fmt.Errorf("direct connection failed: %w", err)
		}
		r.log.Infof("Direct connection to %s successful", r.addr)
	}

	r.bufreader = bufio.NewReaderSize(conn, readBufferSize)
	r.log.Infof("Established connection %s", conn.LocalAddr())
	return conn, nil
}

// performIO performs the IO operation on the connection.
// Retries on connection errors.
func (r *RobustTCPConn) performIO(ioop func() (int, error)) (n int, err error) {
	conn := r.conn

	if conn != nil {
		n, err = ioop()
		if err == nil {
			return n, err
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check again with the lock. Another goroutine may have established the connection in the meantime.
	if r.conn == nil {
		newConn, err := r.connect()
		if err != nil {
			return 0, err
		}
		r.conn = newConn
	}

	n, err = ioop()
	if err != nil {
		r.conn.Close()
		r.conn = nil
		r.bufreader = nil
	}
	return n, err
}

func (r *RobustTCPConn) Read(b []byte) (n int, err error) {
	return r.performIO(func() (int, error) {
		reader := r.bufreader
		if reader == nil {
			return 0, io.ErrClosedPipe
		}
		return reader.Read(b)
	})
}

func (r *RobustTCPConn) Write(b []byte) (n int, err error) {
	return r.performIO(func() (int, error) {
		conn := r.conn
		if conn == nil {
			return 0, io.ErrClosedPipe
		}
		return conn.Write(b)
	})
}

func (r *RobustTCPConn) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn == nil {
		return nil
	}
	err := r.conn.Close()
	r.conn = nil
	r.bufreader = nil
	return err
}

type TCPBind struct {
	conn *RobustTCPConn
	src  netip.AddrPort
	dst  netip.AddrPort
	log  *zap.SugaredLogger

	open bool

	wmu      sync.Mutex
	rmu      sync.Mutex
	writebuf bytes.Buffer

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
		src:      *src,
		dst:      dst,
		conn:     conn,
		log:      log,
		done:     make(chan struct{}),
		writebuf: bytes.Buffer{},
	}

	return b, nil
}

func (b *TCPBind) makeReceiveIPv4() conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		b.rmu.Lock()
		defer b.rmu.Unlock()

		header := make([]byte, headerSize)
		_, err = io.ReadFull(b.conn, header)
		if err != nil {
			return 0, err
		}

		// Read the packet size from the header
		pktSize := int(binary.BigEndian.Uint16(header))
		if pktSize == 0 {
			return 0, fmt.Errorf("invalid packet size: 0")
		}

		if len(bufs[0]) < pktSize {
			return 0, fmt.Errorf("buffer size %d is smaller than packet size %d", len(bufs[0]), pktSize)
		}

		// Read the packet payload
		_, err = io.ReadFull(b.conn, bufs[0][:pktSize])
		if err != nil {
			b.log.Warn("Failed to read packet data: ", err)
			return 0, err
		}

		sizes[0] = pktSize
		eps[0] = &TCPEndpoint{src: b.src, dst: b.dst}
		return 1, nil
	}
}

func (b *TCPBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.wmu.Lock()
	defer b.wmu.Unlock()

	if b.open {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	b.open = true

	return []conn.ReceiveFunc{b.makeReceiveIPv4()}, b.src.Port(), nil
}

func (b *TCPBind) BatchSize() int {
	return batchSize
}

func (b *TCPBind) Close() error {
	b.wmu.Lock()
	defer b.wmu.Unlock()
	select {
	case <-b.done:
		// Already closed
		return nil
	default:
		close(b.done)
	}
	return b.conn.Close()
}

func (b *TCPBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if len(bufs) == 0 {
		return nil
	}

	b.wmu.Lock()
	defer b.wmu.Unlock()

	for _, data := range bufs {
		packetSize := len(data)
		if packetSize == 0 {
			continue
		}
		if packetSize > mtu-headerSize {
			return fmt.Errorf("packet size %d exceeds maximum allowed size", packetSize)
		}

		// Write header and packet data
		header := make([]byte, headerSize)
		binary.BigEndian.PutUint16(header, uint16(packetSize))
		_, err := b.writebuf.Write(header)
		if err != nil {
			return err
		}
		_, err = b.writebuf.Write(data)
		if err != nil {
			return err
		}
	}

	if b.writebuf.Len() > 0 {
		conn := b.conn.conn
		if conn == nil {
			return io.ErrClosedPipe
		}
		if err := b.flush(conn); err != nil {
			return err
		}
	}

	return nil
}

// flush writes the data to the connection.
// Caller must hold the lock.
func (b *TCPBind) flush(conn *net.TCPConn) error {
	data := b.writebuf.Bytes()
	total := len(data)
	written := 0

	for written < total {
		n, err := conn.Write(data[written:])
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("failed to write data to connection")
		}
		written += n
	}

	b.writebuf.Reset()
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
