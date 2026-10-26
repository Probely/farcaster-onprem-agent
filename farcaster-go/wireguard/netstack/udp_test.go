package netstack

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func TestDNSUDPBackToBackQueries(t *testing.T) {
	tunDevice, err := NewTUN(netip.MustParseAddr("100.64.0.1"), "test", 1420, zap.NewNop().Sugar(), false, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tunDevice.Close() })
	ns := tunDevice.ns

	src := netip.MustParseAddrPort("100.64.0.2:45678")
	dst := netip.MustParseAddrPort("192.0.2.1:53")
	packets := make([][]byte, 2)
	// AAAA queries are answered locally, independently of the host's DNS servers.
	for i := range packets {
		query := new(dns.Msg)
		query.SetQuestion("example.test.", dns.TypeAAAA)
		query.Id = uint16(i + 1)
		payload, err := query.Pack()
		if err != nil {
			t.Fatal(err)
		}
		packets[i] = udpTestPacket(src, dst, payload)
	}
	if n, err := tunDevice.Write(packets, 0); err != nil || n != len(packets) {
		t.Fatalf("Write = %d, %v; want %d, nil", n, err, len(packets))
	}

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	seen := make(map[uint16]bool)
	for range packets {
		var packet []byte
		select {
		case view := <-ns.inbound:
			packet = bytes.Clone(view.AsSlice())
			view.Release()
		case <-ctx.Done():
			t.Fatalf("received %d of %d datagrams: %v", len(seen), len(packets), ctx.Err())
		}
		ip := header.IPv4(packet)
		if ip.Protocol() != uint8(udp.ProtocolNumber) {
			t.Fatalf("response protocol = %d, want UDP", ip.Protocol())
		}
		payload := header.UDP(ip.Payload()).Payload()
		var reply dns.Msg
		if err := reply.Unpack(payload); err != nil {
			t.Fatal(err)
		}
		if !reply.Response {
			t.Fatalf("unexpected DNS response: %v", &reply)
		}
		seen[reply.Id] = true
	}
	if len(seen) != 2 || !seen[1] || !seen[2] {
		t.Fatalf("response IDs = %v, want 1 and 2", seen)
	}
}

func udpTestPacket(src, dst netip.AddrPort, payload []byte) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	ip := header.IPv4(packet)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(udp.ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src.Addr().As4()),
		DstAddr:     tcpip.AddrFrom4(dst.Addr().As4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	datagram := header.UDP(ip.Payload())
	datagram.Encode(&header.UDPFields{
		SrcPort: src.Port(),
		DstPort: dst.Port(),
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	copy(datagram.Payload(), payload)
	return packet
}
