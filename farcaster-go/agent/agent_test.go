package agent

import (
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
)

var token = os.Getenv("FARCASTER_AGENT_TOKEN")

func TestAgentLifecycle(t *testing.T) {
	if token == "" {
		t.Skip("Skipping TestAgentLifecycle: FARCASTER_AGENT_TOKEN not set")
	}
	logger := zap.NewNop().Sugar()
	useIPv6 := false
	proxyUseNames := false
	a := New(token, nil, logger, useIPv6, proxyUseNames, ConnOptions{})
	if a.CheckToken() != nil {
		t.Error("Valid token considered invalid")
	}

	err := a.ConnectWait()
	if err != nil {
		t.Errorf("Failed to connect to agent hub: %v", err)
	}

	t.Logf("Agent a status: %v", a.State.Status())

	t.Logf("Disconnecting agent a...")
	err = a.Down()
	if err != nil {
		t.Errorf("Failed to disconnect agent a: %v", err)
	}

	t.Logf("Closing agent a...")
	a.Close()

	b := New(token, nil, logger, useIPv6, proxyUseNames, ConnOptions{})
	if b.CheckToken() != nil {
		t.Error("Valid token considered invalid")
	}

	err = b.ConnectWait()
	if err != nil {
		t.Errorf("Failed to connect to agent hub: %v", err)
	}

	err = b.Down()
	if err != nil {
		t.Errorf("Failed to disconnect agent: %v", err)
	}

	b.Close()
}

func TestHandshakeFresh(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tests := []struct {
		name string
		last int64
		want bool
	}{
		{"no handshake", 0, false},
		{"just under max age", now.Add(-maxHandshakeAge + time.Second).Unix(), true},
		{"at max age", now.Add(-maxHandshakeAge).Unix(), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := handshakeFresh(tt.last, now); got != tt.want {
				t.Fatalf("handshakeFresh(%d) = %v, want %v", tt.last, got, tt.want)
			}
		})
	}
}
