package netstack

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"go.uber.org/zap"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
	"probely.com/farcaster/dialers"
	"probely.com/farcaster/ipnamecache"
)

// Forwarder request wrapper to abstract away the details of setting up
// a Netstack TCP connection and proxying it to an upstream server.
type netstackTCPFwd struct {
	fr *tcp.ForwarderRequest
	ep tcpip.Endpoint

	wq *waiter.Queue
	we *waiter.Entry

	ctx    *context.Context
	cancel context.CancelFunc

	// Ensures Cleanup is only executed once, even if called from multiple goroutines.
	cleanupOnce sync.Once

	// Closed when Cleanup is called, used to signal shutdown to background goroutines.
	done chan struct{}

	// Triggered when the downstream (netstack) connection is closed.
	// Used to cancel the upstream connection.
	downstreamClosed chan struct{}

	upstream   *net.TCPConn   // Connection to the upstream server.
	downstream *gonet.TCPConn // Connection to the local netstack client.

	// IP->hostname cache.
	ipCache *ipnamecache.IPNameCache
	// Logger.
	log *zap.SugaredLogger
}

func newNetstackTCPFwd(fr *tcp.ForwarderRequest, ipc *ipnamecache.IPNameCache, log *zap.SugaredLogger) *netstackTCPFwd {
	// Create a cancellable context for managing upstream connection lifetime.
	ctx, cancel := context.WithCancel(context.Background())

	// Set up a waiter to detect when the downstream connection is closed (HUP).
	wq := &waiter.Queue{}
	we, downstreamClosed := waiter.NewChannelEntry(waiter.EventHUp)
	wq.EventRegister(&we)

	return &netstackTCPFwd{
		fr:               fr,
		ctx:              &ctx,
		cancel:           cancel,
		wq:               wq,
		we:               &we,
		done:             make(chan struct{}),
		downstreamClosed: downstreamClosed,
		ipCache:          ipc,
		log:              log,
	}
}

func (r *netstackTCPFwd) Reject() {
	// Reject the connection by sending a TCP RST.
	r.fr.Complete(true)
}

func (r *netstackTCPFwd) Cleanup() {
	// Ensure cleanup logic runs only once, even if called from multiple places.
	r.cleanupOnce.Do(func() {
		// Cancel the context to signal any in-flight operations to stop.
		if r.cancel != nil {
			r.cancel()
		}

		// Unregister the waiter entry to avoid leaks.
		if r.we != nil {
			r.wq.EventUnregister(r.we)
		}

		// Close the done channel to notify any goroutines waiting on shutdown.
		select {
		case <-r.done:
			// Already closed
		default:
			close(r.done)
		}

		// Close upstream and downstream connections if they exist.
		if r.upstream != nil {
			r.upstream.Close()
		}
		if r.downstream != nil {
			r.downstream.Close()
		}
	})
}

func (r *netstackTCPFwd) ConnectUpstream(dialer dialers.Dialer) (*net.TCPConn, error) {
	// Start a background goroutine that cancels the upstream connection if
	// the downstream connection closes or if Cleanup is triggered.
	go func() {
		select {
		case <-r.downstreamClosed:
		case <-r.done:
		}
		// Ensure all resources are released.
		r.Cleanup()
	}()

	cr := r.fr.ID()

	// TODO: Add IPv6 support.
	serverIP := parseIPv4(cr.LocalAddress)
	serverPort := cr.LocalPort
	serverAddrPort := netip.AddrPortFrom(serverIP, serverPort)
	serverAddr := serverAddrPort.String()

	// If enabled and cache has a hostname for this IP, switch to hostname:port
	// before proxy decision so that NO_PROXY applies to the hostname naturally.
	dialAddr := serverAddr
	if r.ipCache != nil {
		if name, ok := r.ipCache.Get(serverIP); ok && name != "" {
			dialAddr = net.JoinHostPort(name, fmt.Sprintf("%d", serverPort))
			r.log.Debugf("Using hostname for proxy connect: %s -> %s", serverAddr, dialAddr)
		}
	}

	// Proxy-aware TCP dialer.
	server, err := dialer.Dial("tcp", dialAddr)

	if err != nil {
		// Reject the connection if attempt fails.
		r.fr.Complete(true)
		return nil, err
	}

	// Set TCP keepalive options for the upstream connection.
	tcpConn := server.(*net.TCPConn)
	setTCPConnTimeouts(tcpConn, keepaliveInterval, keepaliveCount)

	r.upstream = tcpConn
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
