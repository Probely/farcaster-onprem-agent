package wireguard

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
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
		return make([]byte, bufferSize)
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

// TCPBind is a WireGuard conn.Bind implementation that works over TCP.
// It manages a single TCP connection to a remote endpoint and ensures
// that only one connection attempt is active at a time.
type TCPBind struct {
	// Configuration/Static data (usually less frequently changed)
	addrPort  netip.AddrPort // Parsed destination address
	endpoint  string         // Original endpoint string
	localPort uint16         // Local port to use for endpoint
	logger    *zap.SugaredLogger
	dialers   []dialers.Dialer // List of dialers to try when connecting

	// Synchronization and related state
	mu      sync.Mutex // Protects conn, open, dialing
	cond    *sync.Cond // Used to coordinate dial attempts
	conn    net.Conn   // Active TCP connection (nil if not connected)
	open    bool       // Indicates whether the bind has been opened
	dialing bool       // True if a dial attempt is currently in progress
}

// NewTCPBind creates a new TCP bind for Wireguard
func NewTCPBind(src *netip.AddrPort, origEndpoint, endpoint string, logger *zap.SugaredLogger) (*TCPBind, error) {
	return NewTCPBindWithDialConfig(src, origEndpoint, endpoint, nil, logger)
}

// NewTCPBindWithDialConfig creates a new TCP bind for Wireguard with a custom dial configuration.
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
	// Initialize the condition variable, associating it with the main mutex
	b.cond = sync.NewCond(&b.mu)

	return b, nil
}

// Open is called by WireGuard to initialize the bind.
// It returns a receive function and the local port to use.
// Only one call to Open is allowed per bind instance.
func (b *TCPBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.logger.Infof("Opening TCPBind")
	b.mu.Lock()
	defer b.mu.Unlock()

	// Allow WireGuard to call Open only once
	if b.open {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	b.open = true

	// Use the port provided by the caller if our localPort is 0
	if b.localPort == 0 {
		b.localPort = port
	}

	// Return the receive function - actual connection happens lazily
	return []conn.ReceiveFunc{b.receivePackets}, b.localPort, nil
}

// Close shuts down the bind and closes the active TCP connection, if any.
func (b *TCPBind) Close() error {
	b.logger.Infof("Closing TCPBind")
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.open {
		return nil
	}

	b.open = false

	// Close the current connection if it exists.
	if b.conn != nil {
		err := b.conn.Close()
		b.conn = nil
		return err
	}

	return nil
}

// receivePackets reads a single packet from the TCP connection.
// It uses a 2-byte length-prefixed framing format and returns one packet at a time.
// If the connection is broken or times out, it is closed and an error is returned.
func (b *TCPBind) receivePackets(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	if !b.open {
		return 0, net.ErrClosed
	}

	conn, err := b.ensureConnection()
	if err != nil {
		return 0, fmt.Errorf("failed to establish connection: %w", err)
	}

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	headerBuf := buf[:headerSize]

	if err := conn.SetReadDeadline(time.Now().Add(defaultReadTimeout)); err != nil {
		b.logger.Warnf("Failed to set read deadline: %v", err)
	}

	_, err = io.ReadFull(conn, headerBuf)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return 0, nil
		}

		b.logger.Warnf("Failed to read header: %v", err)
		b.closeCurrentConnectionOnError(conn)
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
		b.closeCurrentConnectionOnError(conn)
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
		b.closeCurrentConnectionOnError(conn)
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

// Send writes one or more packets to the TCP connection.
// Each packet is prefixed with a 2-byte length header.
// If the connection is broken, it is closed and an error is returned.
func (b *TCPBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if !b.open {
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
			b.closeCurrentConnectionOnError(conn)
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

// ensureConnection returns an active TCP connection, establishing one if needed.
// Only one goroutine is allowed to dial at a time; others wait for the result.
// This prevents redundant dials and ensures all goroutines share the same connection.
func (b *TCPBind) ensureConnection() (net.Conn, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for {
		// Case 1: Connection already exists and we're still open
		if b.conn != nil && b.open {
			return b.conn, nil
		}

		// Case 2: Bind has been closed — return immediately
		if !b.open {
			return nil, net.ErrClosed
		}

		// Case 3: Another goroutine is already dialing — wait for it to finish
		if b.dialing {
			b.cond.Wait()
			continue
		}

		// Case 4: No connection and no dial in progress — this goroutine will dial
		b.logger.Infof("No active connection, initiating dial sequence...")
		b.dialing = true
		break
	}

	// Dialing happens outside the lock
	b.mu.Unlock()

	var conn net.Conn
	var err error
	dialSuccess := false
	for _, dialer := range b.dialers {
		b.logger.Infof("Trying to connect via %s...", dialer.String())
		conn, err = dialer.Connect()
		if err == nil {
			b.logger.Infof("Connection successful via %s", dialer.String())
			dialSuccess = true

			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetKeepAlive(true)
				tcpConn.SetKeepAlivePeriod(keepAliveInterval)
				tcpConn.SetNoDelay(true)
			}
			break
		}
		b.logger.Warnf("Connection attempt via %s failed: %v", dialer.String(), err)
	}

	b.mu.Lock()
	b.dialing = false

	if !dialSuccess {
		finalErr := fmt.Errorf("failed to connect to %s after %d attempts: %w",
			b.endpoint, len(b.dialers), err)
		b.cond.Broadcast()
		return nil, finalErr
	}

	// Dial succeeded — check if we were closed while dialing
	if !b.open {
		b.logger.Warnf("Connection established but bind was closed concurrently.")
		go conn.Close()
		b.cond.Broadcast()
		return nil, net.ErrClosed
	}

	// Dial succeeded and we're still open — assign the connection
	b.conn = conn
	b.cond.Broadcast()

	return b.conn, nil
}

// closeCurrentConnectionOnError closes the connection if it's still the active one.
// This prevents closing a newer connection that may have been established concurrently.
func (b *TCPBind) closeCurrentConnectionOnError(conn net.Conn) {
	if conn == nil {
		return
	}

	b.mu.Lock()
	// Only close and clear if it's still the current connection.
	// This prevents closing a newer, valid connection if a stale error occurs.
	closedConn := false
	if b.conn == conn {
		b.conn = nil
		closedConn = true
	}
	b.mu.Unlock()

	// Close the connection synchronously without holding the lock
	if closedConn {
		if err := conn.Close(); err != nil {
			b.logger.Warnf("Error closing connection after error: %v", err)
		}
	}
}
