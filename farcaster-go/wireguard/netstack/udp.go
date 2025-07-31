package netstack

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"time"

	"go.uber.org/zap"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const maxUDPPacketSize = 2048

// bufferPool is a pool of byte slices used for UDP packet handling
// to reduce allocations and GC pressure during high-throughput forwarding.
// This helps avoid per-packet allocations in high-throughput scenarios.
var bufferPool = sync.Pool{
	New: func() any {
		return make([]byte, maxUDPPacketSize)
	},
}

// getBuffer gets a buffer from the pool
func getBuffer() []byte {
	return bufferPool.Get().([]byte)
}

// putBuffer returns a buffer to the pool
func putBuffer(buf []byte) {
	bufferPool.Put(buf)
}

type keepaliveTimer struct {
	// Configuration/Context related
	kaTimeout time.Duration
	ID        int64
	ctx       context.Context
	cancel    context.CancelFunc

	// Synchronization and protected state
	mu      sync.Mutex // Mutex to protect timer operations (kaTimer)
	kaTimer *time.Timer
}

func newKeepaliveTimer(kaTimeout time.Duration, logger *zap.SugaredLogger) *keepaliveTimer {
	ctx, cancel := context.WithCancel(context.Background())

	k := &keepaliveTimer{
		ctx:       ctx,
		cancel:    cancel,
		kaTimeout: kaTimeout,
		ID:        rand.Int63n(4611686018427387904),
		mu:        sync.Mutex{},
	}

	// Create the timer within a mutex lock to prevent race conditions
	k.mu.Lock()
	k.kaTimer = time.AfterFunc(kaTimeout, func() {
		logger.Debugf("UDP connection timed out: %d", k.ID)
		k.Stop() // Use Stop method to prevent deadlocks
	})
	k.mu.Unlock()

	return k
}

func (k *keepaliveTimer) Extend() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.kaTimer != nil {
		k.kaTimer.Reset(k.kaTimeout)
	}
}

func (k *keepaliveTimer) Stop() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.kaTimer != nil {
		k.kaTimer.Stop()
	}
	// Cancel the context outside the lock to avoid potential deadlocks
	// when handling context callbacks
	go k.cancel()
}

func (k *keepaliveTimer) Stopped() <-chan struct{} {
	return k.ctx.Done()
}

type netstackUDPFwd struct {
	s  *stack.Stack
	fr *udp.ForwarderRequest
	ep tcpip.Endpoint

	wq *waiter.Queue

	upstream   *net.UDPConn
	downstream *gonet.UDPConn

	keepalive *keepaliveTimer

	log *zap.SugaredLogger
}

func newNetstackUDPFwd(
	s *stack.Stack,
	fr *udp.ForwarderRequest,
	kaTimeout time.Duration,
	log *zap.SugaredLogger) (*netstackUDPFwd, error) {
	// Try to create the UDP endpoint ASAP to minimize race conditions caused
	// by the downstream sending multiple packets in quick succession.
	wq := &waiter.Queue{}
	ep, err := fr.CreateEndpoint(wq)
	if err != nil {
		return nil, fmt.Errorf("UDP create endpoint: %s", err)
	}

	f := &netstackUDPFwd{
		s:         s,
		fr:        fr,
		wq:        wq,
		ep:        ep,
		keepalive: newKeepaliveTimer(kaTimeout, log),
	}

	return f, nil
}

func (f *netstackUDPFwd) KeepAlive() *keepaliveTimer {
	return f.keepalive
}

// Close all connections and endpoints.
func (f *netstackUDPFwd) Cleanup() {
	if f.upstream != nil {
		f.upstream.Close()
	}
	if f.downstream != nil {
		f.downstream.Close()
	}
	if f.ep != nil {
		f.ep.Close()
	}

	f.keepalive.Stop()
}

// The upstream peer is the destination of the first arriving UDP packet.
func (f *netstackUDPFwd) ConnectUpstream() (*net.UDPConn, error) {
	cr := f.fr.ID()

	// Set a connection timeout
	dialer := net.Dialer{
		Timeout:   defaultConnectTimeout,
		LocalAddr: &net.UDPAddr{Port: int(cr.RemotePort)},
	}

	dstIP := parseIPv4(cr.LocalAddress)
	dstAddr := netip.AddrPortFrom(dstIP, cr.LocalPort)
	raddr := net.UDPAddrFromAddrPort(dstAddr)

	var err error
	conn, err := dialer.Dial("udp", raddr.String())
	if err != nil {
		f.log.Debugf("Error connecting to %s: %s. Retrying...", raddr, err)
		// Try with port 0 (system-assigned port)
		dialer.LocalAddr = &net.UDPAddr{Port: 0}
		conn, err = dialer.Dial("udp", raddr.String())
		if err != nil {
			f.log.Debugf("Error connecting to %s: %s. Failed.", raddr, err)
			return nil, fmt.Errorf("connect to %s: %s", raddr, err)
		}
	}

	f.upstream = conn.(*net.UDPConn)

	// Set idle timeouts
	f.upstream.SetReadDeadline(time.Now().Add(f.keepalive.kaTimeout))

	return f.upstream, nil
}

// The downstream peer is the source of the first arriving UDP packet.
func (f *netstackUDPFwd) ConnectDownstream() (*gonet.UDPConn, error) {
	f.downstream = gonet.NewUDPConn(f.wq, f.ep)

	// Set initial deadline which will be extended by the proxy
	f.downstream.SetReadDeadline(time.Now().Add(f.keepalive.kaTimeout))

	return f.downstream, nil
}

// proxyUDP forwards UDP packets between src and dst.
// It uses read/write deadlines and a keepalive timer to detect idle or dead connections.
// If either side closes or times out, the function exits and signals via the teardown channel.
func proxyUDP(src, dst net.Conn, teardown chan error, keepalive *keepaliveTimer) {
	var err error
	var n int

	buf := getBuffer()
	defer putBuffer(buf)

	for {
		select {
		case <-keepalive.Stopped():
			teardown <- nil
			return
		default:
			// Set a read deadline to avoid indefinite blocking.
			if err = src.SetReadDeadline(time.Now().Add(defaultReadTimeout)); err != nil {
				teardown <- fmt.Errorf("failed to set read deadline: %w", err)
				return
			}

			n, err = src.Read(buf)

			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout is expected; continue to check keepalive.
				continue
			}

			if err != nil {
				teardown <- err
				return
			}

			if err = dst.SetWriteDeadline(time.Now().Add(defaultReadTimeout)); err != nil {
				teardown <- fmt.Errorf("failed to set write deadline: %w", err)
				return
			}

			_, err = dst.Write(buf[:n])
			if err != nil {
				teardown <- err
				return
			}
		}

		// Reset the keepalive timer after successful activity.
		keepalive.Extend()
	}
}
