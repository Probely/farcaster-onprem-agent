package netstack

import (
	"bytes"
	"context"
	"net"
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
		if i == 1 {
			query.SetEdns0(4096, false)
			query.IsEdns0().Option = append(query.IsEdns0().Option, &dns.EDNS0_PADDING{Padding: make([]byte, 3000)})
		}
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

func TestUDPForwardPreservesDatagramAtBufferLimit(t *testing.T) {
	input, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Close() })
	sender, err := net.DialUDP("udp4", nil, input.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	output, reader := net.Pipe()
	defer reader.Close()

	ns := &netstack{ctx: t.Context(), log: zap.NewNop().Sugar()}
	done := make(chan struct{}, 1)
	idle := newIdleTimer(time.Second)
	go ns.copyUDP(done, idle, "test", output, input)
	t.Cleanup(func() {
		_ = input.Close()
		_ = output.Close()
		<-done
	})

	want := bytes.Repeat([]byte{0x42}, 2048)
	if _, err := sender.Write(want); err != nil {
		t.Fatal(err)
	}
	if err := reader.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want)+1)
	n, err := reader.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], want) {
		t.Fatalf("forwarded %d bytes, want %d unchanged bytes", n, len(want))
	}
}

func TestUDPFlowLimit(t *testing.T) {
	for _, tt := range []struct {
		name         string
		flows        int64
		wantProtocol uint8
	}{
		{name: "last_slot", flows: maxUDPFlows - 1, wantProtocol: uint8(udp.ProtocolNumber)},
		{name: "at_limit", flows: maxUDPFlows, wantProtocol: uint8(header.ICMPv4ProtocolNumber)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tunDevice, err := NewTUN(netip.MustParseAddr("100.64.0.1"), "test", 1420, zap.NewNop().Sugar(), false, false)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = tunDevice.Close() })
			ns := tunDevice.ns
			// Model occupied slots without opening thousands of sockets.
			ns.udpFlows.Store(tt.flows)
			query := new(dns.Msg)
			query.SetQuestion("example.test.", dns.TypeAAAA)
			payload, err := query.Pack()
			if err != nil {
				t.Fatal(err)
			}
			packet := udpTestPacket(netip.MustParseAddrPort("100.64.0.2:45678"),
				netip.MustParseAddrPort("192.0.2.1:53"), payload)
			if n, err := tunDevice.Write([][]byte{packet}, 0); err != nil || n != 1 {
				t.Fatalf("Write = %d, %v; want 1, nil", n, err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			var response []byte
			select {
			case view := <-ns.inbound:
				response = bytes.Clone(view.AsSlice())
				view.Release()
			case <-ctx.Done():
				t.Fatalf("no response: %v", ctx.Err())
			}
			ip := header.IPv4(response)
			if got := ip.Protocol(); got != tt.wantProtocol {
				t.Fatalf("response protocol = %d, want %d", got, tt.wantProtocol)
			}
			if tt.wantProtocol == uint8(header.ICMPv4ProtocolNumber) {
				icmp := header.ICMPv4(ip.Payload())
				if icmp.Type() != header.ICMPv4DstUnreachable || icmp.Code() != header.ICMPv4PortUnreachable {
					t.Fatalf("ICMP type/code = %d/%d, want port unreachable", icmp.Type(), icmp.Code())
				}
			}
			if got := ns.udpFlows.Load(); got != maxUDPFlows {
				t.Fatalf("flow count = %d, want %d", got, maxUDPFlows)
			}
			if err := tunDevice.Close(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			for ns.udpFlows.Load() != tt.flows && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if got := ns.udpFlows.Load(); got != tt.flows {
				t.Fatalf("flow count after close = %d, want %d", got, tt.flows)
			}
		})
	}
}
