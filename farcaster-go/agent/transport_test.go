package agent

import "testing"

func TestResolveTransport(t *testing.T) {
	tests := []struct {
		name      string
		flag      string
		transport string // FARCASTER_TRANSPORT.
		forceTCP  string // FARCASTER_FORCE_TCP.
		want      Transport
		wantErr   bool
	}{
		{"default", "", "", "", TransportAuto, false},
		{"flag over env", "ws", "udp", "", TransportWS, false},
		{"env ignores case and spaces", "", " TCP ", "", TransportTCP, false},
		{"whitespace env falls back to force tcp", " ", "  ", "true", TransportTCP, false},
		{"env over force tcp", "", "ws", "true", TransportWS, false},
		{"force tcp", "", "", "Yes", TransportTCP, false},
		{"force tcp false", "", "", "false", TransportAuto, false},
		{"unknown transport", "", "websocket", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("FARCASTER_TRANSPORT", tt.transport)
			t.Setenv("FARCASTER_FORCE_TCP", tt.forceTCP)
			got, err := ResolveTransport(tt.flag)
			if got != tt.want || (err != nil) != tt.wantErr {
				t.Fatalf("ResolveTransport(%q) = %q, %v; want %q, error %v", tt.flag, got, err, tt.want, tt.wantErr)
			}
		})
	}
}
