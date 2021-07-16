package check

import (
	"errors"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
)

const (
	handshakeTTL = time.Second * 600
)

func WireguardTunnel(name string) error {
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wg.Close()

	dev, err := wg.Device(name)
	if err != nil {
		return err
	}

	if len(dev.Peers) == 0 {
		return errors.New("WireGuard tunnel has no peers")
	}

	handshakeExpiryTime := dev.Peers[0].LastHandshakeTime.Add(handshakeTTL)
	if time.Now().After(handshakeExpiryTime) {
		return errors.New("WireGuard handshake is expired")
	}

	return nil
}
