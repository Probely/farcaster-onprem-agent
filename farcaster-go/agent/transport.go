package agent

import (
	"fmt"
	"os"
	"strings"
)

// Transport selects how the agent reaches the hub: over UDP, TCP, or
// WebSocket, or each in order with TransportAuto. The zero value behaves as
// TransportAuto.
type Transport string

const (
	TransportAuto Transport = "auto" // UDP, then TCP, then WebSocket.
	TransportUDP  Transport = "udp"
	TransportTCP  Transport = "tcp"
	TransportWS   Transport = "ws"
)

// ResolveTransport returns the transport named by flag, else by
// FARCASTER_TRANSPORT, else TransportTCP if FARCASTER_FORCE_TCP is true, else
// TransportAuto. Blank values count as unset.
func ResolveTransport(flag string) (Transport, error) {
	v := strings.TrimSpace(flag)
	if v == "" {
		v = strings.TrimSpace(os.Getenv("FARCASTER_TRANSPORT"))
	}
	if v == "" {
		if isTrue(os.Getenv("FARCASTER_FORCE_TCP")) {
			return TransportTCP, nil
		}
		return TransportAuto, nil
	}
	switch t := Transport(strings.ToLower(v)); t {
	case TransportAuto, TransportUDP, TransportTCP, TransportWS:
		return t, nil
	}
	return "", fmt.Errorf("unknown transport %q: use auto, udp, tcp or ws", v)
}

// isTrue reports whether s is 1, t, true, y, yes or on, in any case. The
// kernel-mode scripts accept the same values.
func isTrue(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "t", "true", "y", "yes", "on":
		return true
	}
	return false
}

// steps returns the transports to try, in order.
func (t Transport) steps() []Transport {
	if t == "" || t == TransportAuto {
		return []Transport{TransportUDP, TransportTCP, TransportWS}
	}
	return []Transport{t}
}

// label names the transport in log messages.
func (t Transport) label() string {
	switch t {
	case TransportUDP:
		return "UDP"
	case TransportTCP:
		return "TCP"
	case TransportWS:
		return "WebSocket"
	}
	return string(t)
}
