package netstack

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const maxUDPPacketSize = 2048

// bufferPool reuses per-packet buffers to avoid per-packet allocations
// during high-throughput UDP forwarding. Pointers are pooled because
// sync.Pool with non-pointer types allocates on each Put (SA6002).
var bufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, maxUDPPacketSize)
		return &b
	},
}

func getBuffer() []byte  { return *bufferPool.Get().(*[]byte) }
func putBuffer(b []byte) { bufferPool.Put(&b) }

// idleTimer signals once after timeout elapses without an Extend call,
// or when Stop is called.
type idleTimer struct {
	timeout time.Duration
	mu      sync.Mutex
	timer   *time.Timer
	done    chan struct{}
	once    sync.Once
}

func newIdleTimer(timeout time.Duration) *idleTimer {
	t := &idleTimer{
		timeout: timeout,
		done:    make(chan struct{}),
	}
	t.timer = time.AfterFunc(timeout, t.fire)
	return t
}

func (t *idleTimer) Extend() {
	t.mu.Lock()
	t.timer.Reset(t.timeout)
	t.mu.Unlock()
}

func (t *idleTimer) Stop() {
	t.mu.Lock()
	t.timer.Stop()
	t.mu.Unlock()
	t.fire()
}

func (t *idleTimer) Done() <-chan struct{} { return t.done }

func (t *idleTimer) fire() { t.once.Do(func() { close(t.done) }) }

// handleUDP dispatches an inbound UDP forwarder request. Returning false
// causes the netstack forwarder to drop the packet.
func (ns *netstack) handleUDP(r *udp.ForwarderRequest) bool {
	if ns.ctx.Err() != nil {
		return false
	}
	if r.ID().LocalPort == 53 {
		go ns.handleDNSUDP(r)
		return true
	}
	go ns.forwardUDP(r)
	return true
}

// forwardUDP proxies a single UDP "session" between a downstream netstack
// peer and an upstream server.
func (ns *netstack) forwardUDP(r *udp.ForwarderRequest) {
	downstream, err := ns.acceptUDP(r)
	if err != nil {
		ns.logConnectionError(err, "Downstream UDP accept failed")
		return
	}
	defer downstream.Close() //nolint:errcheck

	cr := r.ID()
	raddr := netip.AddrPortFrom(parseIPv4(cr.LocalAddress), cr.LocalPort)
	upstream, err := ns.dialUpstreamUDP(cr.RemotePort, raddr)
	if err != nil {
		ns.logConnectionError(err, "Upstream UDP dial failed")
		return
	}
	defer upstream.Close() //nolint:errcheck

	ns.proxyUDP(upstream, downstream)
}

// acceptUDP creates the netstack-side UDP endpoint and wraps it as a
// stdlib net.Conn.
func (ns *netstack) acceptUDP(r *udp.ForwarderRequest) (*gonet.UDPConn, error) {
	wq := &waiter.Queue{}
	ep, err := r.CreateEndpoint(wq)
	if err != nil {
		return nil, fmt.Errorf("create UDP endpoint: %v", err)
	}
	return gonet.NewUDPConn(wq, ep), nil
}

// dialUpstreamUDP dials raddr, preserving srcPort when possible
// (STUN/QUIC depend on it) and falling back to an ephemeral port if
// it is already bound.
func (ns *netstack) dialUpstreamUDP(srcPort uint16, raddr netip.AddrPort) (*net.UDPConn, error) {
	dialer := net.Dialer{
		Timeout:   defaultConnTimeout,
		LocalAddr: &net.UDPAddr{Port: int(srcPort)},
	}
	conn, err := dialer.Dial("udp", raddr.String())
	if err != nil {
		dialer.LocalAddr = &net.UDPAddr{Port: 0}
		conn, err = dialer.Dial("udp", raddr.String())
		if err != nil {
			return nil, err
		}
	}
	return conn.(*net.UDPConn), nil
}

// proxyUDP forwards packets in both directions until either side errors
// or the session is idle for keepaliveInterval.
func (ns *netstack) proxyUDP(upstream, downstream net.Conn) {
	idle := newIdleTimer(keepaliveInterval)
	done := make(chan struct{}, 2)
	go ns.copyUDP(done, idle, "downstream -> upstream", upstream, downstream)
	go ns.copyUDP(done, idle, "upstream -> downstream", downstream, upstream)

	<-idle.Done()
	_ = upstream.Close()
	_ = downstream.Close()
	<-done
	<-done
}

func (ns *netstack) copyUDP(done chan<- struct{}, idle *idleTimer, dir string, dst, src net.Conn) {
	defer func() { done <- struct{}{} }()
	defer idle.Stop()

	buf := getBuffer()
	defer putBuffer(buf)

	for {
		n, err := src.Read(buf)
		if err != nil {
			ns.logConnectionError(err, dir)
			return
		}
		if _, err := dst.Write(buf[:n]); err != nil {
			ns.logConnectionError(err, dir)
			return
		}
		idle.Extend()
	}
}

// handleDNSUDP serves DNS queries over a UDP "session" by forwarding
// them to the local resolver instead of dialing an upstream server.
func (ns *netstack) handleDNSUDP(r *udp.ForwarderRequest) {
	downstream, err := ns.acceptUDP(r)
	if err != nil {
		ns.log.Debug("Downstream DNS UDP accept failed:", err)
		return
	}
	defer downstream.Close() //nolint:errcheck

	q := getBuffer()
	defer putBuffer(q)

	for {
		if err := downstream.SetReadDeadline(time.Now().Add(dnsIdleTimeout)); err != nil {
			ns.log.Debug("Failed to set read deadline:", err)
			return
		}
		n, _, err := downstream.ReadFrom(q)
		if err != nil {
			var netErr net.Error
			if !errors.As(err, &netErr) || !netErr.Timeout() {
				ns.log.Debug("Could not read DNS query:", err)
			}
			return
		}
		reply, err := ns.resolver.Query(q[:n], "udp")
		if err != nil {
			ns.log.Debug("Could not forward DNS query:", err)
			return
		}
		if _, err := downstream.Write(reply); err != nil {
			ns.log.Debug("Could not write DNS response:", err)
			return
		}
	}
}
