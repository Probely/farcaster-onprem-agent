package wireguard

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"go.uber.org/zap"

	"probely.com/farcaster/dialers"
)

const (
	tcpHeaderSize   = 2 // Two-byte big-endian payload length prefix.
	tcpDialTimeout  = 20 * time.Second
	tcpWriteTimeout = 20 * time.Second
	tcpKeepAlive    = 25 * time.Second
)

var tcpFramePool = sync.Pool{
	New: func() any {
		b := make([]byte, tcpHeaderSize+maxDatagramSize)
		return &b
	},
}

// NewTCPBind returns a StreamBind that tunnels WireGuard datagrams over TCP to
// origEndpoint, using any proxy configured in the environment. Each datagram
// is framed for tcp2udp with a two-byte big-endian length prefix. WireGuard
// sees endpoint as the peer address and src's port as the local port.
func NewTCPBind(src *netip.AddrPort, origEndpoint, endpoint string, log *zap.SugaredLogger) (*StreamBind, error) {
	if src == nil {
		return nil, fmt.Errorf("source address cannot be nil")
	}
	if origEndpoint == "" {
		return nil, fmt.Errorf("server address cannot be empty")
	}
	addrPort, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("could not parse endpoint address: %w", err)
	}

	dialer := dialers.NewTCPProxyDialer(tcpDialTimeout, log)
	dial := func(ctx context.Context) (PacketConn, error) {
		c, err := dialer.DialContext(ctx, "tcp", origEndpoint)
		if err != nil {
			return nil, err
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(tcpKeepAlive)
			_ = tc.SetNoDelay(true)
		}
		return &tcpPacketConn{conn: c}, nil
	}
	opts := StreamOptions{Name: "TCP", DialTimeout: tcpDialTimeout}
	return NewStreamBind(src.Port(), addrPort, dial, opts, log), nil
}

// tcpPacketConn frames WireGuard datagrams with a two-byte length prefix over
// a stream connection. writeMu serializes writes so concurrent frames do not
// interleave on TLS proxy connections; Close bypasses the mutex to unblock a
// stalled write.
type tcpPacketConn struct {
	conn    net.Conn
	hdr     [tcpHeaderSize]byte
	writeMu sync.Mutex
}

func (c *tcpPacketConn) ReadPacket(dst []byte) (int, error) {
	if _, err := io.ReadFull(c.conn, c.hdr[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(c.hdr[:]))
	if n > maxDatagramSize || n > len(dst) {
		return 0, fmt.Errorf("frame of %d bytes exceeds %d", n, maxDatagramSize)
	}
	if n == 0 {
		return 0, nil
	}
	if _, err := io.ReadFull(c.conn, dst[:n]); err != nil {
		return 0, err
	}
	return n, nil
}

func (c *tcpPacketConn) WritePacket(p []byte) error {
	if len(p) > maxDatagramSize {
		return fmt.Errorf("packet of %d bytes exceeds %d", len(p), maxDatagramSize)
	}
	buf := tcpFramePool.Get().(*[]byte)
	defer tcpFramePool.Put(buf)
	frame := (*buf)[:tcpHeaderSize+len(p)]
	binary.BigEndian.PutUint16(frame, uint16(len(p))) //nolint:gosec // len(p) <= maxDatagramSize, checked above.
	copy(frame[tcpHeaderSize:], p)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.conn.SetWriteDeadline(time.Now().Add(tcpWriteTimeout)); err != nil {
		return err
	}
	_, err := c.conn.Write(frame)
	return err
}

func (c *tcpPacketConn) Close() error {
	return c.conn.Close()
}
