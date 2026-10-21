package wireguard

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

const testWait = 5 * time.Second

var (
	errRefused = errors.New("connection refused")

	testOpts = StreamOptions{
		Name:        "test",
		IdleTimeout: time.Second,
		DialTimeout: 200 * time.Millisecond,
		BackoffMin:  5 * time.Millisecond,
		BackoffMax:  20 * time.Millisecond,
	}
)

// waitFor polls cond until it returns true or timeout elapses.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(time.Millisecond)
	}
}

type readResult struct {
	p   []byte
	err error
}

// fakeConn is an in-memory PacketConn with scripted reads and recorded writes.
type fakeConn struct {
	reads  chan readResult
	writes chan []byte
	closed chan struct{}
	once   sync.Once

	mu       sync.Mutex
	writeErr error
}

func newFakeConn() *fakeConn {
	return &fakeConn{
		reads:  make(chan readResult, 16),
		writes: make(chan []byte, 16),
		closed: make(chan struct{}),
	}
}

func (c *fakeConn) ReadPacket(dst []byte) (int, error) {
	select {
	case r := <-c.reads:
		if r.err != nil {
			return 0, r.err
		}
		return copy(dst, r.p), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *fakeConn) WritePacket(p []byte) error {
	if c.isClosed() {
		return net.ErrClosed
	}
	c.mu.Lock()
	err := c.writeErr
	c.mu.Unlock()
	if err != nil {
		return err
	}
	select {
	case c.writes <- append([]byte(nil), p...):
		return nil
	case <-c.closed:
		return net.ErrClosed
	}
}

func (c *fakeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *fakeConn) failWrites(err error) {
	c.mu.Lock()
	c.writeErr = err
	c.mu.Unlock()
}

func (c *fakeConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// fakeDialer runs queued outcomes first, then dials fresh fakeConns.
type fakeDialer struct {
	mu       sync.Mutex
	queue    []DialFunc
	dialed   []*fakeConn
	attempts chan time.Time // Receives the time of each dial call.
	conns    chan *fakeConn
}

func newFakeDialer() *fakeDialer {
	return &fakeDialer{
		attempts: make(chan time.Time, 64),
		conns:    make(chan *fakeConn, 16),
	}
}

func (d *fakeDialer) dial(ctx context.Context) (PacketConn, error) {
	select {
	case d.attempts <- time.Now():
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	d.mu.Lock()
	var next DialFunc
	if len(d.queue) > 0 {
		next, d.queue = d.queue[0], d.queue[1:]
	}
	d.mu.Unlock()
	if next != nil {
		return next(ctx)
	}
	c := newFakeConn()
	d.mu.Lock()
	d.dialed = append(d.dialed, c)
	d.mu.Unlock()
	select {
	case d.conns <- c:
		return c, nil
	case <-ctx.Done():
		c.Close()
		return nil, ctx.Err()
	}
}

// closeAll closes every connection d has dialed.
func (d *fakeDialer) closeAll() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.dialed {
		c.Close()
	}
}

func (d *fakeDialer) queueFailure(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.queue = append(d.queue, func(context.Context) (PacketConn, error) { return nil, err })
}

// queueBlock queues a dial attempt that blocks until ctx is canceled.
func (d *fakeDialer) queueBlock() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.queue = append(d.queue, func(ctx context.Context) (PacketConn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
}

// waitAttempt returns the time of the next dial call.
func (d *fakeDialer) waitAttempt(t *testing.T) time.Time {
	t.Helper()
	select {
	case at := <-d.attempts:
		return at
	case <-time.After(testWait):
		t.Fatal("timed out waiting for a dial attempt")
		return time.Time{}
	}
}

func (d *fakeDialer) next(t *testing.T) *fakeConn {
	t.Helper()
	select {
	case c := <-d.conns:
		return c
	case <-time.After(testWait):
		t.Fatal("timed out waiting for a connection")
		return nil
	}
}

func (d *fakeDialer) expectNoDial(t *testing.T, within time.Duration) {
	t.Helper()
	select {
	case <-d.conns:
		t.Fatal("unexpected dial")
	case <-time.After(within):
	}
}

// receiver runs a ReceiveFunc in a loop until it returns an error.
type receiver struct {
	packets chan []byte
	err     chan error
}

func startReceiver(fn conn.ReceiveFunc) *receiver {
	r := &receiver{packets: make(chan []byte, 16), err: make(chan error, 1)}
	go func() {
		bufs := [][]byte{make([]byte, maxDatagramSize)}
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		for {
			n, err := fn(bufs, sizes, eps)
			if err != nil {
				r.err <- err
				return
			}
			if n == 1 {
				r.packets <- append([]byte(nil), bufs[0][:sizes[0]]...)
			}
		}
	}()
	return r
}

func (r *receiver) expectPacket(t *testing.T, want string) {
	t.Helper()
	select {
	case got := <-r.packets:
		if string(got) != want {
			t.Fatalf("received %q, want %q", got, want)
		}
	case err := <-r.err:
		t.Fatalf("receive returned error %v, want packet %q", err, want)
	case <-time.After(testWait):
		t.Fatalf("timed out waiting for packet %q", want)
	}
}

func (r *receiver) expectClosed(t *testing.T, within time.Duration) {
	t.Helper()
	select {
	case err := <-r.err:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("receive returned %v, want net.ErrClosed", err)
		}
	case p := <-r.packets:
		t.Fatalf("received unexpected packet %q", p)
	case <-time.After(within):
		t.Fatalf("receive still blocked %s after Close", within)
	}
}

func newTestBind(t *testing.T, d *fakeDialer, opts StreamOptions) *StreamBind {
	t.Helper()
	ep := netip.MustParseAddrPort("192.0.2.1:443")
	b := NewStreamBind(51820, ep, d.dial, opts, zaptest.NewLogger(t).Sugar())
	t.Cleanup(func() {
		b.Close()
		d.closeAll() // End reads that a failed test leaves blocked.
	})
	return b
}

func openBind(t *testing.T, b *StreamBind) *receiver {
	t.Helper()
	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if port != 51820 {
		t.Fatalf("Open reported port %d, want 51820", port)
	}
	return startReceiver(fns[0])
}

func waitClosed(t *testing.T, c *fakeConn) {
	t.Helper()
	waitFor(t, testWait, c.isClosed, "connection was left open")
}

func TestStreamBindReceiveSurvivesConnectionErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"eof", io.EOF},
		{"reset", &net.OpError{Op: "read", Err: syscall.ECONNRESET}},
		{"closed", &net.OpError{Op: "read", Err: net.ErrClosed}},
		{"protocol", errors.New("frame of 5000 bytes exceeds 4096")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newFakeDialer()
			b := newTestBind(t, d, testOpts)
			r := openBind(t, b)

			c1 := d.next(t)
			c1.reads <- readResult{p: []byte("one")}
			r.expectPacket(t, "one")

			c1.reads <- readResult{err: tt.err}
			waitClosed(t, c1)

			c2 := d.next(t)
			c2.reads <- readResult{p: []byte("two")}
			r.expectPacket(t, "two")
		})
	}
}

// TestStreamBindBackoff checks the delay before each redial, which jitter
// places within [backoff/2, backoff].
func TestStreamBindBackoff(t *testing.T) {
	tests := []struct {
		name        string
		failedDials int
		reads       []readResult    // Read by the connection dialed after the failed dials.
		want        []time.Duration // Backoff before each redial.
	}{
		{
			name:        "failed dials double it up to the maximum",
			failedDials: 4,
			want:        []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second},
		},
		{
			name:        "a connection lost after a keepalive doubles it",
			failedDials: 1,
			reads:       []readResult{{p: []byte{}}, {err: io.EOF}},
			want:        []time.Duration{time.Second, 4 * time.Second},
		},
		{
			name:        "a connection lost after a datagram resets it",
			failedDials: 2,
			reads:       []readResult{{p: []byte("hello")}, {err: io.EOF}},
			want:        []time.Duration{time.Second, 2 * time.Second, time.Second},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := newFakeDialer()
				for range tt.failedDials {
					d.queueFailure(errRefused)
				}
				opts := StreamOptions{BackoffMin: time.Second, BackoffMax: 4 * time.Second}
				b := newTestBind(t, d, opts)
				openBind(t, b)

				last := d.waitAttempt(t)
				for i, backoff := range tt.want {
					if i == tt.failedDials {
						c := d.next(t)
						for _, r := range tt.reads {
							c.reads <- r
						}
					}
					at := d.waitAttempt(t)
					if gap := at.Sub(last); gap < backoff/2 || gap > backoff {
						t.Fatalf("redial %d after %s, want within [%s, %s]", i+1, gap, backoff/2, backoff)
					}
					last = at
				}
			})
		})
	}
}

func TestStreamBindCloseUnblocksReceive(t *testing.T) {
	tests := []struct {
		name  string
		setup func(d *fakeDialer, opts *StreamOptions)
	}{
		{"blocked read", func(d *fakeDialer, opts *StreamOptions) {}},
		{"blocked dial", func(d *fakeDialer, opts *StreamOptions) {
			d.queueBlock()
			opts.DialTimeout = time.Minute
		}},
		{"backoff", func(d *fakeDialer, opts *StreamOptions) {
			d.queueFailure(errRefused)
			opts.BackoffMin, opts.BackoffMax = time.Minute, time.Minute
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := newFakeDialer()
				opts := testOpts
				tt.setup(d, &opts)
				b := newTestBind(t, d, opts)
				r := openBind(t, b)
				d.waitAttempt(t)
				synctest.Wait() // Let the manager and the receiver block in the named state.

				start := time.Now()
				if err := b.Close(); err != nil {
					t.Fatalf("Close: %v", err)
				}
				if took := time.Since(start); took > 100*time.Millisecond {
					t.Fatalf("Close took %s", took)
				}
				r.expectClosed(t, 100*time.Millisecond)
			})
		})
	}
}

// TestStreamBindCloseRacingDial races Close with a dial that succeeds at once.
// Close closes the connection whether or not the manager has published it.
func TestStreamBindCloseRacingDial(t *testing.T) {
	const iterations = 20000
	ep := netip.MustParseAddrPort("192.0.2.1:443")
	for range iterations {
		d := newFakeDialer()
		b := NewStreamBind(51820, ep, d.dial, testOpts, zap.NewNop().Sugar())
		if _, _, err := b.Open(0); err != nil {
			t.Fatalf("Open: %v", err)
		}
		c := d.next(t)
		if err := b.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if !c.isClosed() {
			t.Fatal("Close left a just-dialed connection open")
		}
	}
}

func TestStreamBindOpenAfterClose(t *testing.T) {
	d := newFakeDialer()
	b := newTestBind(t, d, testOpts)

	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	r1 := startReceiver(fns[0])
	c1 := d.next(t)
	c1.reads <- readResult{p: []byte("first")}
	r1.expectPacket(t, "first")

	if _, _, err := b.Open(0); !errors.Is(err, conn.ErrBindAlreadyOpen) {
		t.Fatalf("second Open returned %v, want ErrBindAlreadyOpen", err)
	}

	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	r1.expectClosed(t, 100*time.Millisecond)
	waitClosed(t, c1)

	r2 := openBind(t, b)
	c2 := d.next(t)
	c2.reads <- readResult{p: []byte("second")}
	r2.expectPacket(t, "second")

	// The first ReceiveFunc stays bound to its closed generation.
	startReceiver(fns[0]).expectClosed(t, 100*time.Millisecond)
}

func TestStreamBindSend(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := newFakeDialer()
		d.queueBlock()
		b := newTestBind(t, d, testOpts)
		openBind(t, b)
		ep := &StreamEndpoint{dst: b.endpoint}

		// While disconnected, Send queues the packet for the next connection.
		if err := b.Send([][]byte{[]byte("queued")}, ep); err != nil {
			t.Fatalf("Send while disconnected: %v", err)
		}

		c1 := d.next(t)
		synctest.Wait() // Let the manager publish c1.
		if err := b.Send([][]byte{[]byte("a"), nil, []byte("b")}, ep); err != nil {
			t.Fatalf("Send: %v", err)
		}
		for _, want := range []string{"queued", "a", "b"} {
			select {
			case got := <-c1.writes:
				if string(got) != want {
					t.Fatalf("wrote %q, want %q", got, want)
				}
			case <-time.After(testWait):
				t.Fatalf("packet %q was never written", want)
			}
		}

		// A write error fails the active connection, drops the packet, and
		// triggers a reconnect, so the next connection receives only later packets.
		c1.failWrites(&net.OpError{Op: "write", Err: syscall.EPIPE})
		if err := b.Send([][]byte{[]byte("c")}, ep); err != nil {
			t.Fatalf("Send after write error: %v", err)
		}
		waitClosed(t, c1)
		c2 := d.next(t)
		synctest.Wait() // Let the manager publish c2.
		select {
		case got := <-c2.writes:
			t.Fatalf("wrote %q again to the next connection", got)
		default:
		}

		if err := b.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := b.Send([][]byte{[]byte("d")}, ep); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Send after Close returned %v, want net.ErrClosed", err)
		}
	})
}

// TestStreamBindQueue checks which datagrams sent while disconnected reach
// the next connection.
func TestStreamBindQueue(t *testing.T) {
	initiation := func(id byte) []byte {
		p := make([]byte, device.MessageInitiationSize)
		binary.LittleEndian.PutUint32(p, device.MessageInitiationType)
		p[len(p)-1] = id
		return p
	}
	var overflow [][]byte
	for i := range maxQueued + 1 {
		overflow = append(overflow, []byte{byte(i)})
	}
	tests := []struct {
		name string
		sent [][]byte
		want [][]byte
	}{
		{
			name: "newer initiation replaces queued initiation",
			sent: [][]byte{initiation(1), []byte("data"), initiation(2)},
			want: [][]byte{[]byte("data"), initiation(2)},
		},
		{
			name: "full queue drops the oldest datagram",
			sent: overflow,
			want: overflow[1:],
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := newFakeDialer()
				d.queueBlock()
				b := newTestBind(t, d, testOpts)
				openBind(t, b)
				ep := &StreamEndpoint{dst: b.endpoint}
				for _, p := range tt.sent {
					buf := bytes.Clone(p)
					if err := b.Send([][]byte{buf}, ep); err != nil {
						t.Fatalf("Send while disconnected: %v", err)
					}
					clear(buf) // WireGuard reuses send buffers.
				}

				c := d.next(t)
				for _, want := range tt.want {
					select {
					case got := <-c.writes:
						if !bytes.Equal(got, want) {
							t.Fatalf("wrote %x, want %x", got, want)
						}
					case <-time.After(testWait):
						t.Fatalf("datagram %x was never written", want)
					}
				}
				synctest.Wait() // Let the manager finish writing the queue.
				select {
				case got := <-c.writes:
					t.Fatalf("wrote unexpected datagram %x", got)
				default:
				}
			})
		})
	}
}

func TestStreamBindIdleWatchdog(t *testing.T) {
	tests := []struct {
		name   string
		active bool // Keep delivering packets so the connection does not idle out.
	}{
		{"idle connection is replaced", false},
		{"active connection is kept", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := newFakeDialer()
				opts := testOpts
				opts.IdleTimeout = 80 * time.Millisecond
				b := newTestBind(t, d, opts)
				r := openBind(t, b)
				c1 := d.next(t)

				if !tt.active {
					waitClosed(t, c1)
					c2 := d.next(t)
					c2.reads <- readResult{p: []byte("fresh")}
					r.expectPacket(t, "fresh")
					return
				}
				for range 10 {
					c1.reads <- readResult{p: []byte("tick")}
					r.expectPacket(t, "tick")
					time.Sleep(20 * time.Millisecond)
				}
				d.expectNoDial(t, 50*time.Millisecond)
				if c1.isClosed() {
					t.Fatal("active connection was replaced")
				}
			})
		})
	}
}
