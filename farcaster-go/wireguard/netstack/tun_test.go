package netstack

import (
	"net/netip"
	"testing"

	"go.uber.org/zap"
)

func TestCloseEndsEvents(t *testing.T) {
	tunDevice, err := NewTUN(netip.MustParseAddr("100.64.0.1"), "test", 1420, zap.NewNop().Sugar(), false, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tunDevice.Close() })
	<-tunDevice.Events() // Initial EventUp.
	for range 2 {
		if err := tunDevice.Close(); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case _, ok := <-tunDevice.Events():
		if ok {
			t.Fatal("Events is still open after Close")
		}
	default:
		t.Fatal("Events is still open after Close")
	}
}
