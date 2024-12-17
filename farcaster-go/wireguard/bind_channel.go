package wireguard

import (
	"errors"
	"net"
	"net/netip"

	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/conn"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"probely.com/farcaster/netutils"
)

// Linux's default TTL.
const defaultTTL = 64

var (
	errPacketTooSmall  = errors.New("packet too small")
	errInvalidProtocol = errors.New("protocol not UDP")
	errInvalidPort     = errors.New("invalid port")
)

var (
	_ conn.Endpoint = (*ChannelEndpoint)(nil)
	_ conn.Bind     = (*ChannelBind)(nil)
)

type ChannelEndpoint struct {
	dst netip.AddrPort
	src netip.AddrPort
}

type ChannelBind struct {
	tun    *ChannelTUN
	listen netip.AddrPort
	log    *zap.SugaredLogger
}

func (b *ChannelBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	dst, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &ChannelEndpoint{
		dst: dst,
		src: b.listen,
	}, nil
}

func (e *ChannelEndpoint) ClearSrc() {
	e.src = netip.AddrPort{}
}

func (e *ChannelEndpoint) SrcToString() string {
	return e.src.String()
}

func (e *ChannelEndpoint) DstIP() netip.Addr {
	return e.dst.Addr()
}

func (e *ChannelEndpoint) DstPort() uint16 {
	return e.dst.Port()
}

func (e *ChannelEndpoint) SrcIP() netip.Addr {
	return e.src.Addr()
}

func (e *ChannelEndpoint) DstToBytes() []byte {
	b, _ := e.dst.MarshalBinary()
	return b
}

func (e *ChannelEndpoint) DstToString() string {
	return e.dst.String()
}

func NewChannelBind(addr *netip.AddrPort, tun *ChannelTUN, log *zap.SugaredLogger) *ChannelBind {
	return &ChannelBind{
		tun:    tun,
		listen: *addr,
		log:    log,
	}
}

func (b *ChannelBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.log.Infof("Opened channel bind")
	return []conn.ReceiveFunc{b.makeReceiveIPv4()}, b.listen.Port(), nil
}

// Returns the endpoint and a byte slice to the UDP payload.
func (b *ChannelBind) processInboundPacket(pkt *[]byte) (conn.Endpoint, []byte, error) {
	// Make sure the packet is large enough to contain an IPv4 header.
	if len(*pkt) < header.IPv4MinimumSize {
		return nil, nil, errPacketTooSmall
	}
	ipHeader := header.IPv4(*pkt)

	// Check that it is a UDP packet.
	if ipHeader.TransportProtocol() != header.UDPProtocolNumber {
		return nil, nil, errInvalidProtocol
	}

	// Ensure that the IPv4 header lenght is valid.
	ipHdrLen := ipHeader.HeaderLength()
	if ipHdrLen < header.IPv4MinimumSize {
		return nil, nil, errPacketTooSmall
	}

	// Check that the packet is large enough to contain a UDP header.
	if len(*pkt) < int(ipHdrLen+header.UDPMinimumSize) {
		return nil, nil, errPacketTooSmall
	}

	// We only care about packets sent to the port we're listening on.
	udpHeader := header.UDP((*pkt)[ipHdrLen:])
	if udpHeader.DestinationPort() != b.listen.Port() {
		b.log.Debugf("Received packet on port %d (local_port=%d), ignoring",
			udpHeader.DestinationPort(), b.listen.Port())
		return nil, nil, errInvalidPort
	}

	// Extract the endpoint address and port from the IP header.
	addr := netip.AddrFrom4(ipHeader.SourceAddress().As4())

	return &ChannelEndpoint{
			dst: netip.AddrPortFrom(addr, udpHeader.SourcePort()),
			src: b.listen,
		},
		udpHeader.Payload(),
		nil
}

// Create an outbound UDP packet. The data is written to the provided packet.
func (b *ChannelBind) makeOutboundPacket(pkt *[]byte, data []byte, ep *ChannelEndpoint) error {
	ipHdrLen := header.IPv4MinimumSize
	udpHdrLen := header.UDPMinimumSize
	pktLen := ipHdrLen + udpHdrLen + len(data)

	*pkt = (*pkt)[:pktLen]

	// Initialize the IPv4 header.
	// WireGuard sets the TOS field on control packets to 0x88. we don't because
	// our traffic is already tunneled inside another WireGuard tunnel.
	ipHeader := header.IPv4(*pkt)
	ipHeader.Encode(&header.IPv4Fields{
		TotalLength: uint16(pktLen),
		TTL:         defaultTTL,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFromSlice(b.listen.Addr().AsSlice()),
		DstAddr:     tcpip.AddrFromSlice(ep.dst.Addr().AsSlice()),
		TOS:         0x00,
	})
	ipHeader.SetHeaderLength(uint8(ipHdrLen))
	ipHeader.SetChecksum(^ipHeader.CalculateChecksum())

	// Initialize the UDP header.
	udpHeader := header.UDP((*pkt)[ipHdrLen:])
	udpHeader.Encode(&header.UDPFields{
		SrcPort: b.listen.Port(),
		DstPort: ep.DstPort(),
		Length:  uint16(pktLen - ipHdrLen),
	})

	// Copy the payload.
	copy((*pkt)[ipHdrLen+udpHdrLen:], data)

	// We leave the UDP checksum as zero (this is valid for IPv4).

	return nil
}

func (b *ChannelBind) makeReceiveIPv4() conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		for {
			select {
			case <-b.tun.Closed:
				return 0, net.ErrClosed
			case pkt := <-b.tun.Inbound:
				ep, data, err := b.processInboundPacket(pkt)
				// Drop invalid packets.
				if err != nil {
					dump, _ := netutils.DumpPacket(*pkt, false)
					b.log.Debugf("Dropping invalid packet: %s", dump)
					b.tun.PutPacket(pkt)
					continue
				}

				eps[0] = ep
				copy(bufs[0], data)
				sizes[0] = len(data)

				// TODO: dump packet only in debug mode.
				//dump, _ := netutils.DumpPacket(*pkt, true)
				//b.log.Debugf("Received WG packet: %s", dump)

				b.tun.PutPacket(pkt)
				return 1, nil
			}
		}
	}
}

func (b *ChannelBind) BatchSize() int {
	return 1
}

func (b *ChannelBind) Close() error {
	b.log.Infof("Closed channel bind")
	return nil
}

func (b *ChannelBind) Send(buf [][]byte, ep conn.Endpoint) error {
	var err error
	for _, data := range buf {
		pkt := b.tun.GetPacket()
		err = b.makeOutboundPacket(pkt, data, ep.(*ChannelEndpoint))
		if err != nil {
			b.tun.PutPacket(pkt)
			return err
		}
		//if b.log.Level() == zap.DebugLevel {
		//	dump, _ := netutils.DumpPacket(*pkt, true)
		//	b.log.Debugf("Sending WG packet: %s", dump)
		//}
		b.tun.Outbound <- pkt
	}
	return nil
}

func (b *ChannelBind) SetMark(mark uint32) error {
	return nil
}
