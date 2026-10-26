package wireguard

import "testing"

func TestChannelTUNCloseEndsEvents(t *testing.T) {
	tunDevice := NewChannelTUN("test", 1420)
	t.Cleanup(func() { _ = tunDevice.Close() })
	<-tunDevice.Events()
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
