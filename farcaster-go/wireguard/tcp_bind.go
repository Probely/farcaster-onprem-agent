package wireguard

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/conn"
)

const (
	headerSize = 2
)

var (
	_ conn.Endpoint = (*TCPEndpoint)(nil)
	_ conn.Bind     = (*TCPBind)(nil)
)

type RobustTCPConn struct {
	addr string
	conn *net.TCPConn
	mu   sync.Mutex
}

func NewRobustTCPConn(addr string) *RobustTCPConn {
	return &RobustTCPConn{
		addr: addr,
	}
}

func (r *RobustTCPConn) connect() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// If the connection is already established, no need to connect again
	if r.conn != nil {
		return nil
	}

	conn, err := net.DialTimeout("tcp", r.addr, 5*time.Second)
	if err != nil {
		return err
	}

	r.conn = conn.(*net.TCPConn)
	return nil
}

func (r *RobustTCPConn) Read(b []byte) (n int, err error) {
	conn := r.conn
	if conn == nil {
		err = r.connect()
		if err != nil {
			return 0, err
		}
		conn = r.conn
	}

	n, err = conn.Read(b)
	if err != nil {
		conn = nil
		err = r.connect()
		if err != nil {
			return 0, err
		}
		conn = r.conn
		n, err = conn.Read(b)
	}
	return n, err
}

func (r *RobustTCPConn) Write(b []byte) (n int, err error) {
	conn := r.conn
	if conn == nil {
		err = r.connect()
		if err != nil {
			return 0, err
		}
		conn = r.conn
	}

	n, err = conn.Write(b)
	if err != nil {
		conn = nil
		err = r.connect()
		if err != nil {
			return 0, err
		}
		conn = r.conn
		n, err = conn.Write(b)
	}

	return n, err
}

type TCPBind struct {
	conn *RobustTCPConn
	src  netip.AddrPort
	dst  netip.AddrPort
	rmu  sync.Mutex
	smu  sync.Mutex
	log  *zap.SugaredLogger
}

func NewTCPBind(src *netip.AddrPort, conn *RobustTCPConn, log *zap.SugaredLogger) *TCPBind {

	// TODO: replace MustParseAddrPort with something saner.
	return &TCPBind{
		src:  *src,
		dst:  netip.MustParseAddrPort(conn.addr),
		conn: conn,
		log:  log,
	}
}

func (b *TCPBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return []conn.ReceiveFunc{b.makeReceiveIPv4()}, b.src.Port(), nil
}

func (b *TCPBind) makeReceiveIPv4() conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		b.rmu.Lock()
		defer b.rmu.Unlock()
		header := make([]byte, headerSize)

		// Read the packet header. It contains the size of the packet in bytes,
		// encoded as a big-endian uint16.
		n, err := b.conn.Read(header)
		if err != nil || n != headerSize {
			return 0, err
		}

		pktSize := binary.BigEndian.Uint16(header)
		bytesRead := 0
		for bytesRead < int(pktSize) {
			n, err = b.conn.Read(bufs[0][bytesRead:int(pktSize)])
			if err != nil {
				return 0, err
			}
			bytesRead += n
		}
		eps[0] = &TCPEndpoint{src: b.src, dst: b.dst}
		sizes[0] = bytesRead

		return 1, nil
	}
}

func (b *TCPBind) BatchSize() int {
	return 1
}

func (b *TCPBind) Close() error {
	return nil
}

func (b *TCPBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	header := make([]byte, headerSize)
	b.smu.Lock()
	defer b.smu.Unlock()
	for _, data := range bufs {
		pktSize := len(data)
		// Encode the packet size as a big-endian uint16.
		binary.BigEndian.PutUint16(header, uint16(pktSize))

		// Write the packet header.
		_, err := b.conn.Write(header)
		if err != nil {
			return err
		}

		// Write the packet data.
		_, err = b.conn.Write(data)
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
	dst, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &TCPEndpoint{
		dst: dst,
	}, nil
}

func (e *TCPEndpoint) ClearSrc() {
	e.src = netip.AddrPort{}
}

func (e *TCPEndpoint) SrcToString() string {
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
	b, _ := e.dst.MarshalBinary()
	return b
}

func (e *TCPEndpoint) DstToString() string {
	return e.dst.String()
}
