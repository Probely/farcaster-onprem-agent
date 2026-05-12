package netstack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"probely.com/farcaster/dialers"
	"probely.com/farcaster/ipnamecache"
)

const (
	linkChanBufSize = 512
	nicID           = 1

	keepaliveInterval = 120 * time.Second
	keepaliveCount    = 4

	defaultConnTimeout = 10 * time.Second

	// dnsIdleTimeout bounds idle time on forwarded DNS connections.
	// 30s matches Unbound and BIND defaults (RFC 7766 §4).
	dnsIdleTimeout = 30 * time.Second

	maxInFlightTCP = 1024
)

type netstack struct {
	// Netstack stack.
	stack *stack.Stack
	// Netstack link-layer endpoint.
	ep *channel.Endpoint
	// Inbound packets from the NIC.
	inbound chan *buffer.View

	// DNS resolver.
	resolver *resolver

	// Context.
	ctx    context.Context
	cancel context.CancelFunc

	once sync.Once

	log *zap.SugaredLogger

	// IPv6 DNS resolution.
	useIPv6 bool

	// IP -> hostname cache built from DNS resolutions.
	ipCache *ipnamecache.IPNameCache

	// Use hostnames for proxy CONNECT/SOCKS5 when available.
	proxyUseNames bool

	// Dialer.
	dialer dialers.Dialer
}

func newNetstack(ip netip.Addr, mtu int, logger *zap.SugaredLogger, useIPv6 bool, proxyUseNames bool) (*netstack, error) {
	if logger == nil {
		return nil, errors.New("nil logger")
	}

	// Create the stack with IPv4 support.
	sopts := stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
		},
		HandleLocal: false,
	}
	s := stack.New(sopts)

	// Enable SACK.
	sackon := tcpip.TCPSACKEnabled(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackon); err != nil {
		return nil, fmt.Errorf("failed to enable SACK: %s", err)
	}

	// Enable receive buffer auto-tuning.
	tune := tcpip.TCPModerateReceiveBufferOption(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &tune); err != nil {
		return nil, fmt.Errorf("failed to enable receive buffer auto-tuning: %s", err)
	}

	// Channel-based link-layer endpoint.
	ep := channel.New(linkChanBufSize, uint32(mtu), "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("failed to create NIC: %s", err)
	}

	// NIC IPv4 address.
	pa := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
	}
	if err := s.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("failed to add protocol address: %s", err)
	}

	// Default route (0.0.0.0/0)
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         nicID,
	}})

	// Packets from the NIC.
	inbound := make(chan *buffer.View, linkChanBufSize)

	// IP name cache.
	var ipc *ipnamecache.IPNameCache
	if proxyUseNames {
		normalizer := func(hostname string) string {
			hostname = strings.ToLower(hostname)
			hostname = strings.TrimSuffix(hostname, ".")
			return hostname
		}
		ipc, _ = ipnamecache.New(ipnamecache.WithNormalizer(normalizer))
	}

	// DNS resolver.
	resolver, err := newResolver(logger, useIPv6, ipc)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS resolver: %s", err)
	}

	// Context.
	ctx, cancel := context.WithCancel(context.Background())

	ns := &netstack{
		stack:         s,
		ep:            ep,
		inbound:       inbound,
		resolver:      resolver,
		ctx:           ctx,
		cancel:        cancel,
		once:          sync.Once{},
		dialer:        dialers.NewTCPProxyDialer(defaultConnTimeout, logger),
		log:           logger,
		useIPv6:       useIPv6,
		ipCache:       ipc,
		proxyUseNames: proxyUseNames,
	}

	// Forwarding.
	s.SetNICForwarding(nicID, ipv4.ProtocolNumber, true)
	// Enable promiscuous mode so that we can accept packets destined to other hosts.
	s.SetPromiscuousMode(nicID, true)
	// Enable spoofing so that we can send packets with a source IP that is not ours.
	s.SetSpoofing(nicID, true)
	// TCP forwarding.
	defaultRcvWnd := 0 // Use the default receive window size.
	tcpFwd := tcp.NewForwarder(s, defaultRcvWnd, maxInFlightTCP, ns.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	// UDP forwarding.
	udpFwd := udp.NewForwarder(s, ns.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	go ns.ReadPackets()

	return ns, nil
}

func (ns *netstack) Close() {
	ns.once.Do(func() {
		ns.cancel()
		ns.stack.Close()
		ns.stack.Wait()

		// Drain remaining packets from the inbound channel.
		for {
			select {
			case pkt := <-ns.inbound:
				pkt.Release()
			default:
				return
			}
		}
	})
}

func (ns *netstack) ReadPackets() {
	for {
		select {
		case <-ns.ctx.Done():
			return
		default:
			pkt := ns.ep.ReadContext(ns.ctx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			pkt.DecRef()
			select {
			case ns.inbound <- view:
			case <-ns.ctx.Done():
				view.Release()
				return
			}
		}
	}
}

func (ns *netstack) ReadPacket() (*buffer.View, bool) {
	select {
	case <-ns.ctx.Done():
		return nil, false
	case pkt, ok := <-ns.inbound:
		return pkt, ok
	}
}

func (ns *netstack) WritePacket(buf *[]byte) {
	// TODO: can we reduce allocations here?
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(*buf)})
	ns.ep.InjectInbound(ipv4.ProtocolNumber, pkb)
	pkb.DecRef()
}

// Parse a netstack IPv4 address and return a netip.Addr.
func parseIPv4(addr tcpip.Address) netip.Addr {
	return netip.AddrFrom4(addr.As4())
}

func isCommonNetworkError(err error) bool {
	var netErr net.Error
	if err == nil {
		return true
	}
	return errors.Is(err, io.EOF) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, net.ErrClosed) ||
		(errors.As(err, &netErr) && netErr.Timeout()) ||
		strings.Contains(err.Error(), "connection reset by peer")
}

func (ns *netstack) logConnectionError(err error, msg string) {
	if ns.ctx.Err() != nil {
		ns.log.Debugf("%s: %v", msg, err)
		return
	}
	if isCommonNetworkError(err) {
		ns.log.Debugf("%s: %v", msg, err)
		return
	}
	ns.log.Warnf("%s: %v", msg, err)
}
