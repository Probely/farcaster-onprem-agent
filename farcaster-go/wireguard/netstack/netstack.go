package netstack

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
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
)

const (
	linkChanBufSize = 512
	nicID           = 1

	keepaliveInterval = 120 * time.Second
	keepaliveCount    = 4

	maxInFlightTCP = 1024
)

type netstack struct {
	// Netstack stack.
	stack *stack.Stack
	// Netstack link-layer endpoint.
	ep *channel.Endpoint
	// Inbound packets channel.
	inbound chan *buffer.View

	// DNS resolver.
	resolver *resolver

	// Context.
	ctx    context.Context
	cancel context.CancelFunc

	once sync.Once

	log *zap.SugaredLogger
}

func newNetstack(ip netip.Addr, mtu int, logger *zap.SugaredLogger) (*netstack, error) {
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
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackon)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackon); err != nil {
		return nil, fmt.Errorf("failed to enable SACK: %s", err)
	}

	// Enable receive buffer auto-tuning.
	tune := tcpip.TCPModerateReceiveBufferOption(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &tune); err != nil {
		return nil, fmt.Errorf("failed to enable receive buffer auto-tuning: %s", err)
	}

	// Create a channel-based link-layer endpoint.
	ep := channel.New(linkChanBufSize, uint32(mtu), "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("failed to create NIC: %s", err)
	}

	// Add an IPv4 address to the NIC.
	pa := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
	}
	if err := s.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("failed to add protocol address: %s", err)
	}

	// Add default route (0.0.0.0/0)
	s.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         nicID,
	}})

	// Channel to receive packets from the NIC.
	inbound := make(chan *buffer.View, linkChanBufSize)

	// DNS resolver.
	resolver, err := newResolver(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS resolver: %s", err)
	}

	// Context.
	ctx, cancel := context.WithCancel(context.Background())

	ns := &netstack{
		stack:    s,
		ep:       ep,
		inbound:  inbound,
		resolver: resolver,
		ctx:      ctx,
		cancel:   cancel,
		once:     sync.Once{},
		log:      logger,
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
	// Receive notifications when netstack has packets ready to be read.
	// ep.AddNotify(ns)
	go ns.ReadPackets()

	return ns, nil
}

func (ns *netstack) Close() {
	ns.once.Do(func() {
		ns.cancel()
		ns.stack.RemoveNIC(nicID)
		ns.ep.Close()
	})
}

// WriteNotify is called by netstack when a packet is received from a WireGuard peer.
func (ns *netstack) WriteNotify() {
	select {
	case <-ns.ctx.Done():
		return
	default:
		pkt := ns.ep.Read()
		if pkt.IsNil() {
			return
		}
		view := pkt.ToView()
		pkt.DecRef()
		ns.inbound <- view
	}
}

func (ns *netstack) ReadPackets() {
	for {
		select {
		case <-ns.ctx.Done():
			return
		default:
			pkt := ns.ep.ReadContext(ns.ctx)
			if pkt.IsNil() {
				return
			}
			view := pkt.ToView()
			pkt.DecRef()
			ns.inbound <- view
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

func (ns *netstack) handleTCP(r *tcp.ForwarderRequest) {
	fwd := newNetstackTCPFwd(r)

	// Get the connection request.
	cr := r.ID()

	// Handle DNS requests.
	if cr.LocalPort == 53 {
		go ns.handleDNSTCP(fwd)
		return
	}

	// Forward the connection.
	go ns.forwardTCP(fwd)
}

func (ns *netstack) forwardTCP(fwd *netstackTCPFwd) {
	// Cleanup will close the connections.
	defer fwd.Cleanup()

	// Try to connect to the server (upstream) first.
	upstream, err := fwd.ConnectUpstream(keepaliveInterval, keepaliveCount)
	if err != nil {
		ns.log.Warnf("Upstream connection failed: %s", err)
		return
	}
	downstream, err := fwd.ConnectDownstream(keepaliveInterval, keepaliveCount)
	if err != nil {
		ns.log.Warnf("Downstream connection failed: %s", err)
		return
	}

	// Forward packets.
	teardown := make(chan error, 2)
	go proxyTCP(downstream, upstream, teardown)
	go proxyTCP(upstream, downstream, teardown)

	// Wait for the connections to close.
	err = <-teardown
	if err != nil {
		ns.log.Warnf("Stopped TCP proxy for connection: %v", err)
	}
}

func (ns *netstack) handleUDP(r *udp.ForwarderRequest) {
	// Create a new UDP forwarder ASAP. Do not run any other code before this.
	fwd, err := newNetstackUDPFwd(ns.stack, r, keepaliveInterval, ns.log)
	if err != nil {
		ns.log.Debug("Failed creating UDP forwarder:", err)
		return
	}
	// Get the connection request.
	cr := r.ID()

	if cr.LocalPort == 53 {
		go ns.handleDNSUDP(fwd)
		return
	}

	// Forward the connection.
	go ns.forwardUDP(fwd)
}

func (ns *netstack) forwardUDP(fwd *netstackUDPFwd) {
	// Cleanup will close the connections.
	defer fwd.Cleanup()

	upstream, err := fwd.ConnectUpstream()
	if err != nil {
		ns.log.Warnf("Upstream connection failed: %s", err)
		return
	}
	downstream, err := fwd.ConnectDownstream()
	if err != nil {
		ns.log.Warnf("Downstream connection failed: %s", err)
		return
	}

	// Forward packets.
	teardown := make(chan error, 2)
	go proxyUDP(downstream, upstream, teardown, fwd.KeepAlive())
	go proxyUDP(upstream, downstream, teardown, fwd.KeepAlive())

	// Wait for the connections to close.
	err = <-teardown
	if err != nil {
		ns.log.Warnf("Stopped UDP proxy for connection: %s", err)
	}
}

func (ns *netstack) handleDNSUDP(fwd *netstackUDPFwd) {
	defer fwd.Cleanup()

	// Note that, unlike forwarded UDP connections, we don't connect to the
	// upstream server. Instead, we forward the DNS request to the system DNS
	// resolvers. This allows the remote peer to resolve hostnames belonging to
	// the local network.

	downstream, err := fwd.ConnectDownstream()
	if err != nil {
		ns.log.Debug("Downstream connection failed:", err)
		return
	}

	// Read multiple DNS requests from the same UDP connection.
	minTimeout := 30 * time.Second
	readTimeout := max(minTimeout, keepaliveInterval-minTimeout)
	q := make([]byte, maxUDPPacketSize)
	for {
		downstream.SetReadDeadline(time.Now().Add(readTimeout))
		n, _, err := downstream.ReadFrom(q)
		if err != nil {
			// Ignore timeout errors.
			if err, ok := err.(net.Error); ok && !err.Timeout() {
				ns.log.Debug("Could not read DNS query:", err)
			}
			return
		}
		r, err := ns.resolver.Query(q[:n], "udp")
		if err != nil {
			ns.log.Debug("Could not forward DNS query:", err)
			return
		}
		_, err = downstream.Write(r)
		if err != nil {
			ns.log.Debug("Could not write DNS response:", err)
			return
		}
	}
}

func (ns *netstack) handleDNSTCP(fwd *netstackTCPFwd) {
	defer fwd.Cleanup()

	// Note that, unlike forwarded TCP connections, we don't connect to the
	// upstream server. Instead, we forward the DNS request to the system DNS
	// resolvers. This allows the remote peer to resolve hostnames belonging to
	// the local network.

	downstream, err := fwd.ConnectDownstream(keepaliveInterval, keepaliveCount)
	if err != nil {
		ns.log.Debug("Downstream DNS TCP connection failed:", err)
		return
	}

	// Read multiple DNS requests from the same TCP connection.
	readTimeout := 1000 * time.Millisecond

	// XXX: determine the correct value. It should be 64 KB, even though it can
	// be implementation-specific.
	maxTCPDNSReplySize := 4096
	q := make([]byte, maxTCPDNSReplySize)
	for {
		downstream.SetReadDeadline(time.Now().Add(readTimeout))
		// Read the length of the DNS request.
		var length uint16
		err := binary.Read(downstream, binary.BigEndian, &length)
		if err != nil {
			// Ignore timeout errors.
			if err, ok := err.(net.Error); ok && !err.Timeout() {
				ns.log.Debug("Could not read DNS query length:", err)
			}
			return
		}
		// Read the DNS request.
		_, err = io.ReadFull(downstream, q[:length])
		if err != nil {
			ns.log.Debug("Could not read DNS query:", err)
			return
		}
		// Do the DNS query.
		r, err := ns.resolver.Query(q[:length], "tcp")
		if err != nil {
			ns.log.Debug("Could not forward DNS query:", err)
			return
		}
		// Write the length of the DNS response.
		err = binary.Write(downstream, binary.BigEndian, uint16(len(r)))
		if err != nil {
			ns.log.Debug("Failed writing DNS response length:", err)
			return
		}
		// Write the DNS response.
		_, err = downstream.Write(r)
		if err != nil {
			ns.log.Debug("Failed writing DNS response:", err)
			return
		}
	}
}

// Parse a netstack IPv4 address and return a netip.Addr.
func parseIPv4(addr tcpip.Address) netip.Addr {
	return netip.AddrFrom4(addr.As4())
}
