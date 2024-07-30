package agent

import (
	"os"
	"testing"
)

var token = os.Getenv("FARCASTER_API_TOKEN")

//func TestInvalidToken(t *testing.T) {
//	a := New("invalid-token", false, nil)
//	err := a.CheckToken()
//	if err == nil {
//		t.Error("Invalid token considered valid")
//	}
//
//}

func TestAgentLifecycle(t *testing.T) {
	a := New(token, nil)
	if a.CheckToken() != nil {
		t.Error("Valid token considered invalid")
	}

	err := a.Up()
	if err != nil {
		t.Errorf("Failed to start agent: %v", err)
	}

	err = a.WaitForConnection(5)
	if err != nil {
		t.Errorf("Failed to connect to agent hub: %v", err)
	}

	t.Logf("Agent a status: %v", a.State.Status)

	t.Logf("Disconnecting agent a...")
	err = a.Down()
	if err != nil {
		t.Errorf("Failed to disconnect agent a: %v", err)
	}

	t.Logf("Closing agent a...")
	a.Close()

	b := New(token, nil)
	if b.CheckToken() != nil {
		t.Error("Valid token considered invalid")
	}

	err = b.Up()
	if err != nil {
		t.Errorf("Failed to start agent: %v", err)
	}

	err = b.WaitForConnection(5)
	if err != nil {
		t.Errorf("Failed to connect to agent hub: %v", err)
	}

	err = b.Down()
	if err != nil {
		t.Errorf("Failed to disconnect agent: %v", err)
	}

	b.Close()
}
