package wireguard

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"go.uber.org/zap"
	wgconn "golang.zx2c4.com/wireguard/conn"
)

const (
	mtu                   = 1500
	headerSize            = 2
	defaultConnectTimeout = 20 * time.Second
	defaultWriteTimeout   = 20 * time.Second
	batchSize             = 1               // If this is greater than 1, packet reading logic needs adjustment
	writeBufferSize       = 1024 * 1024 * 1 // 1MB write buffer
	readerBufferSize      = 1024 * 1024 * 1 // 1MB read buffer
)

var (
	_ wgconn.Endpoint = (*TCPEndpoint)(nil)
	_ wgconn.Bind     = (*TCPBind)(nil)
)

type TCPBind struct {
	conn    net.Conn
	src     netip.AddrPort
	dst     netip.AddrPort
	log     *zap.SugaredLogger
	dialers []Dialer

	open bool
	wmu  sync.Mutex
	rmu  sync.Mutex

	writebuf bytes.Buffer
	reader   *bufio.Reader
	done     chan struct{}
}

func NewTCPBind(src *netip.AddrPort, addr string, log *zap.SugaredLogger) (*TCPBind, error) {
	if src == nil {
		return nil, fmt.Errorf("src cannot be nil")
	}
	if addr == "" {
		return nil, fmt.Errorf("addr cannot be empty")
	}
	if log == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	dst, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid destination address: %w", err)
	}

	dialConfig := NewDialConfig()
	dialers := dialConfig.Dialers(addr, defaultConnectTimeout)

	b := &TCPBind{
		src:      *src,
		dst:      dst,
		log:      log,
		dialers:  dialers,
		done:     make(chan struct{}),
		writebuf: *bytes.NewBuffer(make([]byte, 0, writeBufferSize)),
	}

	return b, nil
}

// ensureConnection tries to establish a connection if not already connected.
func (b *TCPBind) ensureConnection() error {
	if b.conn != nil {
		return nil
	}

	var lastErr error
	for _, dialer := range b.dialers {
		b.log.Infof("Attempting connection using %s", dialer.String())

		conn, err := dialer.Connect()
		if err != nil {
			b.log.Warnf("Connection attempt failed: %v", err)
			lastErr = err
			continue
		}

		b.log.Infof("Successfully connected using %s", dialer.String())
		b.conn = conn
		b.reader = bufio.NewReaderSize(conn, readerBufferSize)
		return nil
	}

	return fmt.Errorf("all connection strategies failed, last error: %w", lastErr)
}

func (b *TCPBind) makeReceiveIPv4() wgconn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []wgconn.Endpoint) (n int, err error) {
		b.rmu.Lock()
		defer b.rmu.Unlock()

		// Ensure a connection is established before reading.
		if err := b.ensureConnection(); err != nil {
			return 0, err
		}

		header := make([]byte, headerSize)
		_, err = io.ReadFull(b.reader, header)
		if err != nil {
			b.conn = nil // Clear connection on failure to trigger reconnection
			b.reader = nil
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

		// Read the packet payload using the buffered reader
		_, err = io.ReadFull(b.reader, bufs[0][:pktSize])
		if err != nil {
			b.log.Warn("Failed to read packet data:", err)
			return 0, err
		}

		sizes[0] = pktSize
		eps[0] = &TCPEndpoint{src: b.src, dst: b.dst}
		return 1, nil
	}
}

func (b *TCPBind) Open(port uint16) ([]wgconn.ReceiveFunc, uint16, error) {
	b.wmu.Lock()
	defer b.wmu.Unlock()

	if b.open {
		return nil, 0, wgconn.ErrBindAlreadyOpen
	}
	b.open = true

	return []wgconn.ReceiveFunc{b.makeReceiveIPv4()}, b.src.Port(), nil
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

func (b *TCPBind) Send(bufs [][]byte, ep wgconn.Endpoint) error {
	if len(bufs) == 0 {
		return nil
	}

	b.wmu.Lock()
	defer b.wmu.Unlock()

	// Ensure a connection is established before writing.
	if err := b.ensureConnection(); err != nil {
		return err
	}

	// Write packets to buffer
	for _, data := range bufs {
		packetSize := len(data)
		if packetSize == 0 {
			continue
		}
		if packetSize > mtu-headerSize {
			return fmt.Errorf("packet size %d exceeds maximum allowed size", packetSize)
		}

		header := make([]byte, headerSize)
		binary.BigEndian.PutUint16(header, uint16(packetSize))
		if _, err := b.writebuf.Write(header); err != nil {
			return err
		}
		if _, err := b.writebuf.Write(data); err != nil {
			return err
		}
	}

	// Flush buffer to connection
	if b.writebuf.Len() > 0 {
		if err := b.flush(); err != nil {
			b.conn = nil // Clear connection on failure to trigger reconnection
			return err
		}
	}

	return nil
}

// flush writes the buffered data to the connection.
// Caller must hold the write mutex.
func (b *TCPBind) flush() error {
	data := b.writebuf.Bytes()
	total := len(data)
	written := 0

	for written < total {
		n, err := b.conn.Write(data[written:])
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

func (b *TCPBind) ParseEndpoint(s string) (wgconn.Endpoint, error) {
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
