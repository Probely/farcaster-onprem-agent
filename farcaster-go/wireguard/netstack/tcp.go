package netstack

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// halfCloser is a connection that can shut down its read and write streams
// independently. Both *net.TCPConn and *gonet.TCPConn satisfy it.
type halfCloser interface {
	io.ReadWriteCloser
	CloseWrite() error
	CloseRead() error
}

// handleTCP dispatches an inbound TCP request. It runs on a netstack
// worker goroutine and must not block.
func (ns *netstack) handleTCP(r *tcp.ForwarderRequest) {
	if ns.ctx.Err() != nil {
		r.Complete(true)
		return
	}
	if r.ID().LocalPort == 53 {
		go ns.handleDNSTCP(r)
		return
	}
	go ns.forwardTCP(r)
}

// forwardTCP proxies one TCP connection. The upstream is dialed before
// the netstack endpoint is created so a failed dial sends a RST instead
// of accepting the SYN and tearing the connection down immediately.
func (ns *netstack) forwardTCP(r *tcp.ForwarderRequest) {
	// Complete must be called or the in-flight slot leaks.
	completed := false
	defer func() {
		if !completed {
			r.Complete(true)
		}
	}()

	cr := r.ID()
	addr := ns.dialAddr(parseIPv4(cr.LocalAddress), cr.LocalPort)

	upstream, err := ns.dialUpstream(ns.ctx, addr)
	if err != nil {
		ns.logConnectionError(err, "Upstream dial failed")
		return
	}
	defer upstream.Close() //nolint:errcheck

	downstream, err := ns.acceptDownstream(r)
	if err != nil {
		ns.logConnectionError(err, "Downstream accept failed")
		return
	}
	completed = true
	defer downstream.Close() //nolint:errcheck

	ns.proxyTCP(upstream, downstream)
}

// dialUpstream dials the real server with the proxy-aware dialer and
// applies TCP keepalives.
func (ns *netstack) dialUpstream(ctx context.Context, addr string) (*net.TCPConn, error) {
	conn, err := ns.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tc := conn.(*net.TCPConn)
	if err := setTCPConnTimeouts(tc, keepaliveInterval, keepaliveCount); err != nil {
		_ = tc.Close()
		return nil, fmt.Errorf("set upstream keepalives: %w", err)
	}
	return tc, nil
}

// acceptDownstream completes the SYN handshake and returns the netstack-side
// connection. On error, the caller must Complete(true) to send a RST.
func (ns *netstack) acceptDownstream(r *tcp.ForwarderRequest) (*gonet.TCPConn, error) {
	wq := &waiter.Queue{}
	ep, tcpErr := r.CreateEndpoint(wq)
	if tcpErr != nil {
		return nil, fmt.Errorf("create endpoint: %v", tcpErr)
	}
	if err := setEndpointKeepalives(ep, keepaliveInterval, keepaliveCount); err != nil {
		ep.Close()
		return nil, err
	}
	r.Complete(false)
	ep.SocketOptions().SetDelayOption(true)
	return gonet.NewTCPConn(wq, ep), nil
}

// dialAddr returns the address to dial for a destination, swapping the IP
// for a cached hostname when one is known. Hostnames let NO_PROXY rules
// match by name and keep CONNECT proxies that reject literal IPs working.
func (ns *netstack) dialAddr(ip netip.Addr, port uint16) string {
	if ns.ipCache != nil {
		if name, ok := ns.ipCache.Get(ip); ok && name != "" {
			addr := net.JoinHostPort(name, strconv.Itoa(int(port)))
			ns.log.Debugf("Using hostname for proxy connect: %s -> %s", netip.AddrPortFrom(ip, port), addr)
			return addr
		}
	}
	return netip.AddrPortFrom(ip, port).String()
}

// proxyTCP copies bytes in both directions, half-closing each side as
// its source returns EOF.
func (ns *netstack) proxyTCP(upstream, downstream halfCloser) {
	done := make(chan error, 2)
	go ns.halfCopy(done, "downstream -> upstream", upstream, downstream)
	go ns.halfCopy(done, "upstream -> downstream", downstream, upstream)

	for i := range 2 {
		select {
		case err := <-done:
			if err != nil {
				ns.logConnectionError(err, "TCP proxy connection closed")
			}
		case <-ns.ctx.Done():
			_ = upstream.Close()
			_ = downstream.Close()
			for range 2 - i {
				<-done
			}
			return
		}
	}
}

func (ns *netstack) halfCopy(done chan<- error, dir string, dst, src halfCloser) {
	_, err := io.Copy(dst, src)
	_ = dst.CloseWrite()
	_ = src.CloseRead()
	if err != nil {
		err = fmt.Errorf("%s: %w", dir, err)
	}
	done <- err
}

// setEndpointKeepalives enables TCP keepalives on a netstack endpoint.
func setEndpointKeepalives(ep tcpip.Endpoint, interval time.Duration, count int) error {
	ep.SocketOptions().SetKeepAlive(true)
	keepIdle := tcpip.KeepaliveIdleOption(interval)
	keepIntvl := tcpip.KeepaliveIntervalOption(interval)
	userTimeout := tcpip.TCPUserTimeoutOption(tcpUserTimeout(interval, count))
	for _, opt := range []tcpip.SettableSocketOption{&keepIdle, &keepIntvl, &userTimeout} {
		if err := ep.SetSockOpt(opt); err != nil {
			return fmt.Errorf("set keepalive option: %v", err)
		}
	}
	if err := ep.SetSockOptInt(tcpip.KeepaliveCountOption, count); err != nil {
		return fmt.Errorf("set keepalive count: %v", err)
	}
	return nil
}

// tcpUserTimeout returns the TCP_USER_TIMEOUT for a connection with the given
// keepalive interval and probe count.
//
// See https://blog.cloudflare.com/when-tcp-sockets-refuse-to-die/.
func tcpUserTimeout(interval time.Duration, count int) time.Duration {
	return interval + (interval * time.Duration(count)) - 1
}

// handleDNSTCP serves DNS queries over a TCP connection by forwarding them to
// the local resolver instead of dialing an upstream server.
func (ns *netstack) handleDNSTCP(r *tcp.ForwarderRequest) {
	completed := false
	defer func() {
		if !completed {
			r.Complete(true)
		}
	}()

	downstream, err := ns.acceptDownstream(r)
	if err != nil {
		ns.log.Debug("Downstream DNS TCP connection failed:", err)
		return
	}
	completed = true
	defer downstream.Close() //nolint:errcheck

	const (
		writeTimeout = 5 * time.Second
		maxMessage   = 65535
	)
	q := make([]byte, maxMessage)

	for {
		// RFC 7766 §4: one deadline covers length and body to mitigate
		// slow-read attacks.
		if err := downstream.SetReadDeadline(time.Now().Add(dnsIdleTimeout)); err != nil {
			ns.log.Debug("Failed to set read deadline:", err)
			return
		}

		var length uint16
		if err := binary.Read(downstream, binary.BigEndian, &length); err != nil {
			var netErr net.Error
			if !errors.As(err, &netErr) || !netErr.Timeout() {
				ns.log.Debug("Could not read DNS query length:", err)
			}
			return
		}
		if length == 0 || int(length) > maxMessage {
			ns.log.Debug("Invalid DNS query length:", length)
			return
		}
		if _, err := io.ReadFull(downstream, q[:length]); err != nil {
			ns.log.Debug("Could not read DNS query:", err)
			return
		}

		reply, err := ns.resolver.Query(q[:length], "tcp")
		if err != nil {
			ns.log.Debug("Could not forward DNS query:", err)
			return
		}

		if err := downstream.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
			ns.log.Debug("Failed to set write deadline:", err)
			return
		}
		if len(reply) > maxMessage {
			ns.log.Debug("DNS response exceeds max message size:", len(reply))
			return
		}
		//nolint:gosec // length is bounded above by maxMessage (uint16 max).
		if err := binary.Write(downstream, binary.BigEndian, uint16(len(reply))); err != nil {
			ns.log.Debug("Failed writing DNS response length:", err)
			return
		}
		if _, err := downstream.Write(reply); err != nil {
			ns.log.Debug("Failed writing DNS response:", err)
			return
		}
	}
}
