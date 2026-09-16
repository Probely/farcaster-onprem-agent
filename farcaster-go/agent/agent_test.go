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
	a := New(token, nil, logger, useIPv6, proxyUseNames)
	if a.CheckToken() != nil {
		t.Error("Valid token considered invalid")
	}

	err := a.Up()
	if err != nil {
		t.Errorf("Failed to start agent: %v", err)
	}

	err = a.ConnectWait(5)
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

	b := New(token, nil, logger, useIPv6, proxyUseNames)
	if b.CheckToken() != nil {
		t.Error("Valid token considered invalid")
	}

	err = b.Up()
	if err != nil {
		t.Errorf("Failed to start agent: %v", err)
	}

	err = b.ConnectWait(5)
	if err != nil {
		t.Errorf("Failed to connect to agent hub: %v", err)
	}

	err = b.Down()
	if err != nil {
		t.Errorf("Failed to disconnect agent: %v", err)
	}

	b.Close()
}

func TestIsHandshakeFresh(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name          string
		lastHandshake int64
		want          bool
	}{
		{"never handshaked", 0, false},
		{"negative timestamp", -1, false},
		{"just handshaked", now.Unix(), true},
		{"one keepalive ago", now.Add(-25 * time.Second).Unix(), true},
		// Regression: a Unix timestamp was once compared directly against 300,
		// which is always false, so the agent reported "connecting" forever.
		{"two minutes ago, one missed re-handshake", now.Add(-129 * time.Second).Unix(), true},
		{"just inside the window", now.Add(-(maxHandshakeAge - time.Second)).Unix(), true},
		{"exactly at the window", now.Add(-maxHandshakeAge).Unix(), false},
		{"well past the window", now.Add(-10 * time.Minute).Unix(), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isHandshakeFresh(tt.lastHandshake, now); got != tt.want {
				t.Errorf("isHandshakeFresh(%d) = %v, want %v", tt.lastHandshake, got, tt.want)
			}
		})
	}
}
