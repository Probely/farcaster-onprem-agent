package wireguard

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// maxDatagramSize is the largest datagram a connection reads or writes.
// WireGuard packets are at most the tunnel MTU plus 32 bytes.
const maxDatagramSize = 4096

// maxQueued bounds the datagrams Send keeps while disconnected.
const maxQueued = 32

const (
	defaultIdleTimeout = 240 * time.Second
	defaultDialTimeout = 20 * time.Second
	defaultBackoffMin  = time.Second
	defaultBackoffMax  = 30 * time.Second
)

var errIdle = errors.New("idle timeout exceeded")

var (
	_ conn.Endpoint = (*StreamEndpoint)(nil)
	_ conn.Bind     = (*StreamBind)(nil)
)

// PacketConn transports whole WireGuard datagrams over a byte stream. An
// implementation must support one concurrent reader and multiple concurrent
// writers, and Close must unblock both.
type PacketConn interface {
	// ReadPacket reads one datagram into dst. Returning (0, nil) indicates an
	// empty keepalive frame that the caller should ignore.
	ReadPacket(dst []byte) (int, error)
	// WritePacket writes one datagram within a bounded deadline.
	WritePacket(p []byte) error
	// Close closes the underlying connection, unblocking any in-flight
	// ReadPacket or WritePacket calls.
	Close() error
}

// DialFunc connects a new PacketConn, aborting promptly if ctx is canceled.
type DialFunc func(ctx context.Context) (PacketConn, error)

// StreamOptions configures a StreamBind. Zero values select the defaults.
type StreamOptions struct {
	// Name labels the transport in log messages (for example, "TCP").
	Name string
	// IdleTimeout is how long a connection may go without receiving before it is
	// replaced. Defaults to 240s; idle tunnels still rekey every two minutes.
	IdleTimeout time.Duration
	// DialTimeout bounds each connection attempt. Defaults to 20s.
	DialTimeout time.Duration
	// BackoffMin and BackoffMax bound the jittered retry delay between failed
	// or short-lived connections. Default to 1s and 30s.
	BackoffMin, BackoffMax time.Duration
}

// StreamEndpoint is the peer endpoint reported to WireGuard for a stream bind.
type StreamEndpoint struct {
	dst netip.AddrPort
}

func (e *StreamEndpoint) ClearSrc()           {}
func (e *StreamEndpoint) SrcToString() string { return "" }
func (e *StreamEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *StreamEndpoint) DstIP() netip.Addr   { return e.dst.Addr() }
func (e *StreamEndpoint) DstToString() string { return e.dst.String() }
func (e *StreamEndpoint) DstToBytes() []byte {
	b, _ := e.dst.MarshalBinary()
	return b
}

// StreamBind implements conn.Bind over a single reconnecting stream to a fixed
// peer endpoint.
//
// Because wireguard-go exits its receive loop on any non-temporary error,
// Receive blocks across reconnects and returns net.ErrClosed only after Close.
// While disconnected, Send queues the newest datagrams for the next
// connection. A closed bind may be reopened.
type StreamBind struct {
	endpoint  netip.AddrPort
	localPort uint16
	dial      DialFunc
	opts      StreamOptions
	log       *zap.SugaredLogger

	mu  sync.Mutex
	gen *generation // Nil while closed.
}

// NewStreamBind returns a bind that reports localPort from Open and reaches
// endpoint through dial.
func NewStreamBind(localPort uint16, endpoint netip.AddrPort, dial DialFunc, opts StreamOptions, log *zap.SugaredLogger) *StreamBind {
	if opts.IdleTimeout == 0 {
		opts.IdleTimeout = defaultIdleTimeout
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = defaultDialTimeout
	}
	if opts.BackoffMin == 0 {
		opts.BackoffMin = defaultBackoffMin
	}
	if opts.BackoffMax == 0 {
		opts.BackoffMax = defaultBackoffMax
	}
	return &StreamBind{
		endpoint:  endpoint,
		localPort: localPort,
		dial:      dial,
		opts:      opts,
		log:       log,
	}
}

// generation holds the state of a single Open-to-Close lifecycle. Each
// ReceiveFunc captures its generation, so a receiver from before Close cannot
// read from a later Open.
type generation struct {
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{} // Closed when the run goroutine exits.

	mu    sync.Mutex
	conn  *streamConn   // Nil while disconnected.
	ready chan struct{} // Closed when conn becomes non-nil.
	queue [][]byte      // Datagrams sent while disconnected, oldest first.
}

// streamConn wraps an active PacketConn with its failure and activity state.
type streamConn struct {
	PacketConn
	failed       chan struct{} // Closed by fail.
	err          error         // Cause passed to fail; read after failed is closed.
	once         sync.Once
	lastRecvNano atomic.Int64 // Unix timestamp in nanoseconds of the last read.
	received     atomic.Bool  // True once a non-empty datagram has been read.
}

// Open starts the connection manager and returns a single ReceiveFunc.
func (b *StreamBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.gen != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if b.localPort == 0 {
		b.localPort = port
	}
	ctx, cancel := context.WithCancel(context.Background()) //nolint:gosec // Close calls g.cancel.
	g := &generation{
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
		ready:  make(chan struct{}),
	}
	b.gen = g
	go b.run(g)
	return []conn.ReceiveFunc{b.receiveFunc(g)}, b.localPort, nil
}

// Close stops the connection manager, closes any active connection, and waits for
// the manager to exit.
func (b *StreamBind) Close() error {
	b.mu.Lock()
	g := b.gen
	b.gen = nil
	b.mu.Unlock()
	if g == nil {
		return nil
	}
	g.cancel()
	if c, _ := g.current(); c != nil {
		g.fail(c, net.ErrClosed)
	}
	<-g.done
	return nil
}

// Send writes each non-empty buffer in bufs to the active connection, or
// queues it while disconnected. A write error fails the connection and drops
// the remaining buffers.
func (b *StreamBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	g := b.gen
	b.mu.Unlock()
	if g == nil {
		return net.ErrClosed
	}
	for _, p := range bufs {
		if len(p) == 0 {
			continue
		}
		if len(p) > maxDatagramSize {
			b.log.Warnf("Dropping %d-byte packet larger than %d", len(p), maxDatagramSize)
			continue
		}
		c := g.connOrEnqueue(p)
		if c == nil {
			continue
		}
		if err := c.WritePacket(p); err != nil {
			g.fail(c, err)
			return nil
		}
	}
	return nil
}

// ParseEndpoint parses s as an IP:port endpoint.
func (b *StreamBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	dst, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &StreamEndpoint{dst: dst}, nil
}

// BatchSize returns 1 because a stream connection frames one datagram per read.
func (b *StreamBind) BatchSize() int { return 1 }

// SetMark is a no-op because socket marks apply only to kernel UDP sockets.
func (b *StreamBind) SetMark(uint32) error { return nil }

// receiveFunc returns the ReceiveFunc bound to g. It reads one datagram per
// call and hands read errors to the connection manager.
func (b *StreamBind) receiveFunc(g *generation) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			c, ready := g.current()
			if c == nil {
				select {
				case <-ready:
					continue
				case <-g.ctx.Done():
					return 0, net.ErrClosed
				}
			}
			n, err := c.ReadPacket(bufs[0])
			if err != nil {
				if g.ctx.Err() != nil {
					return 0, net.ErrClosed
				}
				g.fail(c, err)
				continue
			}
			c.lastRecvNano.Store(time.Now().UnixNano())
			if n == 0 {
				continue
			}
			c.received.Store(true)
			sizes[0] = n
			eps[0] = &StreamEndpoint{dst: b.endpoint}
			return 1, nil
		}
	}
}

// run maintains g's connection until g is canceled, reconnecting with jittered
// exponential backoff after dial failures or lost connections.
func (b *StreamBind) run(g *generation) {
	defer close(g.done)
	backoff := b.opts.BackoffMin
	for {
		c, err := b.connect(g.ctx)
		if err != nil {
			if g.ctx.Err() != nil {
				return
			}
			delay := jitter(backoff)
			b.log.Warnf("%s connection to %s failed: %v (retrying in %s)",
				b.opts.Name, b.endpoint, err, delay.Round(time.Millisecond))
			if !sleep(g.ctx, delay) {
				return
			}
			backoff = min(backoff*2, b.opts.BackoffMax)
			continue
		}
		if !g.publish(c) {
			c.Close()
			return
		}
		b.log.Infof("%s connection to %s established", b.opts.Name, b.endpoint)
		b.watch(g, c)
		if g.ctx.Err() != nil {
			return
		}
		// Reset backoff only after the connection delivers a datagram; a proxy or
		// load balancer may accept TCP before discovering the upstream is down.
		if c.received.Load() {
			backoff = b.opts.BackoffMin
		} else {
			backoff = min(backoff*2, b.opts.BackoffMax)
		}
		delay := jitter(backoff)
		b.log.Warnf("%s connection to %s lost: %v (reconnecting in %s)",
			b.opts.Name, b.endpoint, c.err, delay.Round(time.Millisecond))
		if !sleep(g.ctx, delay) {
			return
		}
	}
}

// connect dials a single connection within DialTimeout.
func (b *StreamBind) connect(ctx context.Context) (*streamConn, error) {
	ctx, cancel := context.WithTimeout(ctx, b.opts.DialTimeout)
	defer cancel()
	pc, err := b.dial(ctx)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		pc.Close()
		return nil, ctx.Err()
	}
	c := &streamConn{PacketConn: pc, failed: make(chan struct{})}
	c.lastRecvNano.Store(time.Now().UnixNano())
	return c, nil
}

// watch monitors c until it fails or g is canceled, failing c if no datagram
// arrives within IdleTimeout.
func (b *StreamBind) watch(g *generation, c *streamConn) {
	ticker := time.NewTicker(b.opts.IdleTimeout / 8)
	defer ticker.Stop()
	for {
		select {
		case <-c.failed:
			return
		case <-g.ctx.Done():
			return
		case <-ticker.C:
			idle := time.Since(time.Unix(0, c.lastRecvNano.Load()))
			if idle >= b.opts.IdleTimeout {
				g.fail(c, errIdle)
			}
		}
	}
}

// current returns the active connection. When disconnected, it returns nil and a
// channel that closes when the next connection is published.
func (g *generation) current() (*streamConn, <-chan struct{}) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.conn, g.ready
}

// publish installs c as the active connection, wakes waiting receivers, and
// writes the queue to c, failing c on a write error. It returns false if g has
// already been canceled.
func (g *generation) publish(c *streamConn) bool {
	g.mu.Lock()
	if g.ctx.Err() != nil {
		g.mu.Unlock()
		return false
	}
	g.conn = c
	close(g.ready)
	queue := g.queue
	g.queue = nil
	g.mu.Unlock()

	for _, p := range queue {
		if err := c.WritePacket(p); err != nil {
			g.fail(c, err)
			break
		}
	}
	return true
}

// connOrEnqueue returns the active connection, or queues p and returns nil
// while disconnected.
func (g *generation) connOrEnqueue(p []byte) *streamConn {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.conn == nil {
		g.enqueue(p)
	}
	return g.conn
}

// enqueue copies p to the queue, keeping the newest maxQueued datagrams and
// only the newest handshake initiation, since the hub rate-limits initiations.
// The caller holds g.mu.
func (g *generation) enqueue(p []byte) {
	if isInitiation(p) {
		g.queue = slices.DeleteFunc(g.queue, isInitiation)
	}
	if len(g.queue) == maxQueued {
		g.queue = slices.Delete(g.queue, 0, 1)
	}
	g.queue = append(g.queue, bytes.Clone(p))
}

// isInitiation reports whether p is a WireGuard handshake initiation.
func isInitiation(p []byte) bool {
	return len(p) == device.MessageInitiationSize &&
		binary.LittleEndian.Uint32(p) == device.MessageInitiationType
}

// fail closes c, clears it if it is still the active connection, and records err
// as the cause. Only the first call on a given connection has any effect.
func (g *generation) fail(c *streamConn, err error) {
	c.once.Do(func() {
		c.err = err
		c.Close()
		g.mu.Lock()
		if g.conn == c {
			g.conn = nil
			g.ready = make(chan struct{})
		}
		g.mu.Unlock()
		close(c.failed)
	})
}

// jitter returns a random duration chosen uniformly from [d/2, d].
func jitter(d time.Duration) time.Duration {
	half := d / 2
	return half + rand.N(half+1) //nolint:gosec // Backoff jitter needs no cryptographic randomness.
}

// sleep blocks for d and returns false if ctx is canceled first.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
