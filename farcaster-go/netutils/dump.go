package netutils

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func DumpPacket(packet []byte, printPayload bool) (string, error) {
	var ipv4 layers.IPv4
	var tcp layers.TCP
	var udp layers.UDP
	var icmpv4 layers.ICMPv4

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ipv4, &tcp, &udp, &icmpv4)
	parser.IgnoreUnsupported = true

	decoded := make([]gopacket.LayerType, 0, 1)
	err := parser.DecodeLayers(packet, &decoded)
	if err != nil {
		return "", err
	}

	sb := strings.Builder{}
	timestamp := time.Now()
	sb.WriteString(fmt.Sprintf("%s IP %s", timestamp.Format("15:04:05.000000"), ipv4.SrcIP))

	if ipv4.Protocol == layers.IPProtocolTCP {
		flags := ""
		if tcp.SYN {
			flags += "S"
		}
		if tcp.ACK {
			flags += "."
		}
		if tcp.FIN {
			flags += "F"
		}
		if tcp.RST {
			flags += "R"
		}
		if tcp.PSH {
			flags += "P"
		}

		sb.WriteString(fmt.Sprintf(".%d > %s.%d: Flags [%s], seq %d:%d, ack %d, win %d, options %v",
			tcp.SrcPort, ipv4.DstIP, tcp.DstPort, flags, tcp.Seq, tcp.Seq+uint32(len(tcp.Payload)), tcp.Ack, tcp.Window, tcp.Options))
	} else if ipv4.Protocol == layers.IPProtocolUDP {
		sb.WriteString(fmt.Sprintf(".%d > %s.%d: UDP, length %d", udp.SrcPort, ipv4.DstIP, udp.DstPort, udp.Length))
		if printPayload {
			sb.WriteString(fmt.Sprintf("\npayload %d bytes:\n%s", len(udp.Payload), hex.Dump(udp.Payload)))
		}
	} else if ipv4.Protocol == layers.IPProtocolICMPv4 {
		sb.WriteString(fmt.Sprintf(" > %s: ICMP %s, id %d, seq %d, length %d",
			ipv4.DstIP, icmpv4.TypeCode, icmpv4.Id, icmpv4.Seq, len(icmpv4.Payload)))
	} else {
		sb.WriteString(fmt.Sprintf(" > %s: Unknown protocol %d", ipv4.DstIP, ipv4.Protocol))
	}

	return sb.String(), nil
}
