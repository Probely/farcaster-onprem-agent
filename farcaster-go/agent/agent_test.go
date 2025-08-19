package agent

import (
	"os"
	"testing"

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
