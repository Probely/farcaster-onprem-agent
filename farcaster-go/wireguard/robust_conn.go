package wireguard

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"sync"

	"go.uber.org/zap"
)

const readBufferSize = 1024 * 1024

// RobustTCPConn provides a thread-safe wrapper around net.Conn with buffered reading.
type RobustTCPConn struct {
	mu        sync.Mutex
	conn      net.Conn
	bufreader *bufio.Reader
	log       *zap.SugaredLogger
}

func NewRobustTCPConn(conn net.Conn, log *zap.SugaredLogger) (*RobustTCPConn, error) {
	if conn == nil || log == nil {
		return nil, fmt.Errorf("conn or log cannot be nil")
	}

	return &RobustTCPConn{
		conn:      conn,
		bufreader: bufio.NewReaderSize(conn, readBufferSize),
		log:       log,
	}, nil
}

// Read safely reads data into b using a mutex to ensure thread safety.
func (r *RobustTCPConn) Read(b []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.bufreader == nil {
		return 0, io.ErrClosedPipe
	}
	return r.bufreader.Read(b)
}

// Close safely closes the connection
func (r *RobustTCPConn) Write(b []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.conn.Write(b)
}

// Close closes the underlying connection and cleans up resources
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
