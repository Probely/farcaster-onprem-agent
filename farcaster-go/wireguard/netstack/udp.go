package netstack

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"time"

	"go.uber.org/zap"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const maxUDPPacketSize = 2048

type keepaliveTimer struct {
	kaTimer   *time.Timer
	kaTimeout time.Duration
	ctx       *context.Context
	cancel    context.CancelFunc
	ID        int64
}

func newKeepaliveTimer(kaTimeout time.Duration, logger *zap.SugaredLogger) *keepaliveTimer {
	ctx, cancel := context.WithCancel(context.Background())

	k := &keepaliveTimer{
		ctx:       &ctx,
		cancel:    cancel,
		kaTimeout: kaTimeout,
		ID:        rand.Int63n(4611686018427387904),
	}

	k.kaTimer = time.AfterFunc(kaTimeout, func() {
		logger.Debugf("UDP connection timed out: %d", k.ID)
		k.cancel()
	})

	return k
}

func (k *keepaliveTimer) Extend() {
	k.kaTimer.Reset(k.kaTimeout)
}

func (k *keepaliveTimer) Stop() {
	k.kaTimer.Stop()
	k.cancel()
}

func (k *keepaliveTimer) Stopped() <-chan struct{} {
	return (*k.ctx).Done()
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

	laddr := &net.UDPAddr{Port: int(cr.RemotePort)}

	dstIP := parseIPv4(cr.LocalAddress)
	dstAddr := netip.AddrPortFrom(dstIP, cr.LocalPort)
	raddr := net.UDPAddrFromAddrPort(dstAddr)

	var err error
	f.upstream, err = net.DialUDP("udp", laddr, raddr)
	if err != nil {
		f.log.Debugf("Error connecting to %s: %s. Retrying...", raddr, err)
		laddr.Port = 0
		f.upstream, err = net.DialUDP("udp", laddr, raddr)
		if err != nil {
			f.log.Debugf("Error connecting to %s: %s. Retrying...", raddr, err)
			return nil, fmt.Errorf("connect to %s: %s", raddr, err)
		}
	}

	return f.upstream, nil
}

// The downstream peer is the source of the first arriving UDP packet.
func (f *netstackUDPFwd) ConnectDownstream() (*gonet.UDPConn, error) {
	f.downstream = gonet.NewUDPConn(f.wq, f.ep)
	return f.downstream, nil
}

func proxyUDP(src, dst net.Conn, teardown chan error, keepalive *keepaliveTimer) {
	var err error
	var n int

	// TODO: use a buffer pool?
	buf := make([]byte, maxUDPPacketSize)
	for {
		select {
		case <-keepalive.Stopped():
			goto done
		default:
			// Read from src.
			n, err = src.Read(buf)
			if err != nil {
				goto error
			}
			// Write to dst.
			_, err = dst.Write(buf[:n])
			if err != nil {
				goto error
			}
		}
		keepalive.Extend()
	}

error:
	keepalive.Stop()
done:
	teardown <- err
}
