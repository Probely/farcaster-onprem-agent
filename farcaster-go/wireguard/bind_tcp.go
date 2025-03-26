package wireguard

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/conn"

	"probely.com/farcaster/dialers"
)

const (
	// Protocol constants
	headerSize = 2 // Size of the uint16 big-endian length prefix
	mtu        = 1500

	// Connection parameters
	defaultDialTimeout  = 20 * time.Second
	defaultReadTimeout  = 20 * time.Second
	defaultWriteTimeout = 20 * time.Second
	keepAliveInterval   = 25 * time.Second
	maxIdleTime         = 2 * time.Minute // Time after which a connection is considered stale

	// Fixed batch size of 1 for TCP
	batchSize = 1

	// Pool buffer size - large enough for max MTU + header
	bufferSize = mtu + headerSize
)

// Add a buffer pool for reusing packet buffers
var bufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, bufferSize)
		return &buf
	},
}

// TCPEndpoint represents a Wireguard endpoint over TCP
type TCPEndpoint struct {
	dst netip.AddrPort
}

func (e *TCPEndpoint) ClearSrc()           { /* no-op for TCP */ }
func (e *TCPEndpoint) SrcToString() string { return "" }
func (e *TCPEndpoint) DstIP() netip.Addr   { return e.dst.Addr() }
func (e *TCPEndpoint) DstPort() uint16     { return e.dst.Port() }
func (e *TCPEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *TCPEndpoint) DstToBytes() []byte {
	b, _ := e.dst.MarshalBinary()
	return b
}
func (e *TCPEndpoint) DstToString() string { return e.dst.String() }

// TCPBind is a Wireguard conn.Bind implementation that works over TCP
type TCPBind struct {
	addrPort  netip.AddrPort
	endpoint  string
	localPort uint16   // Local port to use for endpoint
	conn      net.Conn // The current TCP connection

	logger *zap.SugaredLogger

	mu      sync.Mutex       // Protects conn, closed fields
	closed  bool             // Whether the bind is closed
	dialers []dialers.Dialer // Connection dialers to use
}

// NewTCPBind creates a new TCP bind for Wireguard
func NewTCPBind(src *netip.AddrPort, origEndpoint, endpoint string, logger *zap.SugaredLogger) (*TCPBind, error) {
	return NewTCPBindWithDialConfig(src, origEndpoint, endpoint, nil, logger)
}

// NewTCPBindWithDialConfig creates a new TCP bind for Wireguard with a custom dial configuration
func NewTCPBindWithDialConfig(src *netip.AddrPort, origEndpoint, endpoint string, dialConfig *dialers.DialConfig, logger *zap.SugaredLogger) (*TCPBind, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("server address cannot be empty")
	}
	if src == nil {
		return nil, fmt.Errorf("source address cannot be nil")
	}

	// Try to parse the server address
	var addrPort netip.AddrPort
	var err error
	if addrPort, err = netip.ParseAddrPort(endpoint); err != nil {
		return nil, fmt.Errorf("could not parse endpoint address: %w", err)
	}

	// Create dialers based on configuration
	dc := dialConfig
	if dc == nil {
		dc = dialers.NewDialConfig()
	}
	dialers := dc.Dialers(origEndpoint, defaultDialTimeout)

	b := &TCPBind{
		endpoint:  origEndpoint,
		addrPort:  addrPort,
		localPort: src.Port(),
		logger:    logger,
		dialers:   dialers,
	}

	return b, nil
}

// Open implements conn.Bind.Open, called by Wireguard to create the binding
func (b *TCPBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.logger.Infof("Opening TCPBind")
	b.mu.Lock()
	defer b.mu.Unlock()

	// Allow WireGuard to call Open only once
	if !b.closed {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	b.closed = false

	// Use the port provided by the caller if our localPort is 0
	if b.localPort == 0 {
		b.localPort = port
	}

	// Return the receive function - actual connection happens lazily
	return []conn.ReceiveFunc{b.receivePackets}, b.localPort, nil
}

// Close implements conn.Bind.Close, closing the TCP connection
func (b *TCPBind) Close() error {
	b.logger.Infof("Closing TCPBind")
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true

	// Close the current connection if it exists.
	if b.conn != nil {
		err := b.conn.Close()
		b.conn = nil
		return err
	}

	return nil
}

// receivePackets is the ReceiveFunc implementation for WireGuard
func (b *TCPBind) receivePackets(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	if b.isClosed() {
		return 0, net.ErrClosed
	}

	// Make sure we have a connection
	conn, err := b.ensureConnection()
	if err != nil {
		return 0, fmt.Errorf("failed to establish connection: %w", err)
	}

	// Get a buffer from the pool for this packet
	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufferPool.Put(bufPtr)

	headerBuf := buf[:headerSize]

	// Ensure we don't block indefinitely
	if err := conn.SetReadDeadline(time.Now().Add(defaultReadTimeout)); err != nil {
		b.logger.Warnf("Failed to set read deadline: %v", err)
	}

	// Read header (2-byte length prefix)
	_, err = io.ReadFull(conn, headerBuf)
	if err != nil {
		// Ignore timeout errors - these are normal when no packets are available
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return 0, nil
		}

		b.logger.Warnf("Failed to read header: %v", err)
		b.closeConnectionAsync(conn)
		return 0, err
	}

	// Decode packet size
	size := binary.BigEndian.Uint16(headerBuf)

	// Validate packet size
	if size == 0 {
		b.logger.Warn("Received zero-size packet, ignoring")
		return 0, nil
	}

	if size > mtu-headerSize {
		b.logger.Warnf("Packet too large: %d > %d", size, mtu-headerSize)
		b.closeConnectionAsync(conn)
		return 0, fmt.Errorf("packet too large: %d > %d", size, mtu-headerSize)
	}

	// Read payload into the same buffer, starting after the header
	payloadBuf := buf[headerSize : headerSize+size]

	// Set a fresh read deadline for the payload
	if err := conn.SetReadDeadline(time.Now().Add(defaultReadTimeout)); err != nil {
		b.logger.Warnf("Failed to set read deadline for payload: %v", err)
	}

	_, err = io.ReadFull(conn, payloadBuf)
	if err != nil {
		b.logger.Warnf("Failed to read payload: %v", err)
		b.closeConnectionAsync(conn)
		return 0, err
	}

	// Copy the data to WireGuard's buffer
	n := copy(bufs[0], payloadBuf)
	sizes[0] = n

	// Use server address for the endpoint
	endpoint := &TCPEndpoint{dst: b.addrPort}
	eps[0] = endpoint

	return 1, nil
}

// Parse creates an endpoint from a string address
func (b *TCPBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	dst, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint address: %w", err)
	}

	return &TCPEndpoint{dst: dst}, nil
}

// Send sends a packet via the TCP connection with a 2-byte length prefix
func (b *TCPBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if b.isClosed() {
		return net.ErrClosed
	}

	conn, err := b.ensureConnection()
	if err != nil {
		return fmt.Errorf("failed to establish connection: %w", err)
	}

	// Write each packet with a length prefix
	header := make([]byte, headerSize)
	for _, buf := range bufs {
		if len(buf) == 0 {
			continue
		}

		// Ensure packet isn't too large
		if len(buf) > mtu-headerSize {
			return fmt.Errorf("packet too large: %d > %d", len(buf), mtu-headerSize)
		}

		// Put the packet length in the header
		binary.BigEndian.PutUint16(header, uint16(len(buf)))
		// Ensure we don't block indefinitely
		if err := conn.SetWriteDeadline(time.Now().Add(defaultWriteTimeout)); err != nil {
			b.logger.Warnf("Failed to set write deadline: %v", err)
		}

		// Use net.Buffers to write both slices in a single syscall without copying
		netBuffers := net.Buffers{header, buf}
		_, err := (&netBuffers).WriteTo(conn)
		if err != nil {
			b.logger.Warnf("Failed to write packet: %v", err)
			b.closeConnectionAsync(conn)
			return fmt.Errorf("failed to write packet: %w", err)
		}
	}

	return nil
}

// BatchSize implements conn.Bind.BatchSize
func (b *TCPBind) BatchSize() int {
	return batchSize // Always 1 for TCP
}

// SetMark is a no-op for TCP
func (b *TCPBind) SetMark(mark uint32) error {
	return nil
}

// ensureConnection makes sure we have a working TCP connection.
func (b *TCPBind) ensureConnection() (net.Conn, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// If we already have a connection, reuse it
	if b.conn != nil {
		return b.conn, nil
	}

	// Check if we're closed
	if b.closed {
		return nil, net.ErrClosed
	}

	// Try each dialer
	var conn net.Conn
	var err error
	// Try each dialer while still holding the lock to prevent concurrent connection attempts
	for _, dialer := range b.dialers {
		b.logger.Infof("Trying to connect via %s...", dialer.String())
		// Attempt to connect
		conn, err = dialer.Connect()
		if err == nil {
			b.logger.Infof("Connection successful via %s", dialer.String())
			break
		}
		b.logger.Warnf("Connection attempt via %s failed: %v", dialer.String(), err)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s after %d attempts: %w",
			b.endpoint, len(b.dialers), err)
	}

	// Enable keepalives and disable Nagle's algorithm
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(keepAliveInterval)
		tcpConn.SetNoDelay(true)
	}

	// Set the new connection
	b.conn = conn

	return conn, nil
}

// isClosed checks if the bind is closed without blocking
func (b *TCPBind) isClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

// closeConnectionAsync closes a connection asynchronously
func (b *TCPBind) closeConnectionAsync(conn net.Conn) {
	if conn == nil {
		return
	}

	b.mu.Lock()
	// Only clear if it's still the current connection
	if b.conn == conn {
		b.conn = nil
	}
	b.mu.Unlock()

	// Close the connection without holding the lock
	go func() {
		if err := conn.Close(); err != nil {
			b.logger.Warnf("Error closing connection asynchronously: %v", err)
		}
	}()
}
