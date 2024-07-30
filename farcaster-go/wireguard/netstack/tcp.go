package netstack

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Forwarder request wrapper to abstract away the details of the setting up
// a Netstack TCP connection.
type netstackTCPFwd struct {
	fr *tcp.ForwarderRequest
	ep tcpip.Endpoint

	wq *waiter.Queue
	we *waiter.Entry

	ctx    *context.Context
	cancel context.CancelFunc

	done             chan struct{}
	downstreamClosed chan struct{}

	upstream   *net.TCPConn
	downstream *gonet.TCPConn
}

func newNetstackTCPFwd(fr *tcp.ForwarderRequest) *netstackTCPFwd {
	// Context for the upstream connection.
	ctx, cancel := context.WithCancel(context.Background())

	// Get close notifications for the downstream connection.
	wq := &waiter.Queue{}
	we, downstreamClosed := waiter.NewChannelEntry(waiter.EventHUp)
	wq.EventRegister(&we)

	r := &netstackTCPFwd{
		fr:               fr,
		ctx:              &ctx,
		cancel:           cancel,
		wq:               wq,
		done:             make(chan struct{}),
		downstreamClosed: downstreamClosed,
	}

	return r
}

func (r *netstackTCPFwd) Reject() {
	r.fr.Complete(true) // Send RST.
}

func (r *netstackTCPFwd) Cleanup() {
	if r.cancel != nil {
		r.cancel()
	}
	if r.we != nil {
		r.wq.EventUnregister(r.we)
	}
	if r.done != nil {
		close(r.done)
	}
	if r.upstream != nil {
		r.upstream.Close()
	}
	if r.downstream != nil {
		r.downstream.Close()
	}
}

func (r *netstackTCPFwd) ConnectUpstream(timeout time.Duration, count int) (*net.TCPConn, error) {
	// Cleanup goroutine.
	go func() {
		select {
		case <-r.downstreamClosed:
		case <-r.done:
		}
		r.cancel()
	}()

	cr := r.fr.ID()

	// TODO: handle IPv6.
	serverIP := parseIPv4(cr.LocalAddress)
	serverAddrPort := netip.AddrPortFrom(serverIP, cr.LocalPort)

	// Connect to the server.
	var dialer net.Dialer
	server, err := dialer.DialContext(*r.ctx, "tcp", serverAddrPort.String())
	if err != nil {
		r.fr.Complete(true) // Send RST.
		return nil, fmt.Errorf("error dialing %s: %s", serverAddrPort, err)
	}

	// Set TCP keepalive options.
	setTCPConnTimeouts(server.(*net.TCPConn), keepaliveInterval, keepaliveCount)

	r.upstream = server.(*net.TCPConn)

	return r.upstream, nil
}

func (r *netstackTCPFwd) ConnectDownstream(timeout time.Duration, count int) (*gonet.TCPConn, error) {
	var err tcpip.Error

	r.ep, err = r.fr.CreateEndpoint(r.wq)
	if err != nil {
		r.fr.Complete(true) // Send RST.
		return nil, fmt.Errorf("could not create endpoint: %v", err)
	}

	if err = r.setTimeouts(timeout, count); err != nil {
		r.fr.Complete(true) // Send RST.
		return nil, fmt.Errorf("could not set timeouts: %v", err)
	}

	r.fr.Complete(false)
	r.ep.SocketOptions().SetDelayOption(true)
	r.downstream = gonet.NewTCPConn(r.wq, r.ep)

	return r.downstream, nil
}

func (r *netstackTCPFwd) setTimeouts(interval time.Duration, count int) tcpip.Error {
	// Enable keepalives.
	r.ep.SocketOptions().SetKeepAlive(true)

	// TCP_KEEPIDLE
	keepIdle := tcpip.KeepaliveIdleOption(interval)
	// TCP_KEEPINTVL
	keepIntvl := tcpip.KeepaliveIntervalOption(interval)
	// TCP_USER_TIMEOUT
	timeout := tcpUserTimeout(interval, count)
	userTimeout := tcpip.TCPUserTimeoutOption(timeout)

	// Set all the options.
	for _, opt := range []tcpip.SettableSocketOption{&keepIdle, &keepIntvl, &userTimeout} {
		if err := r.ep.SetSockOpt(opt); err != nil {
			return err
		}
	}

	// TCP_KEEPCNT
	if err := r.ep.SetSockOptInt(tcpip.KeepaliveCountOption, count); err != nil {
		return err
	}

	return nil
}

// tcpUserTimeout returns the TCP_USER_TIMEOUT value that should be
// used for a connection with the given keepalive interval and count.
// https://blog.cloudflare.com/when-tcp-sockets-refuse-to-die/
func tcpUserTimeout(interval time.Duration, count int) time.Duration {
	return interval + (interval * time.Duration(count)) - 1
}

func proxyTCP(src, dst net.Conn, teardown chan error) {
	_, err := io.Copy(dst, src)
	teardown <- err
}
