package services

import (
	"errors"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
)

const (
	handshakeTTL = time.Second * 180
)

func CheckWireguardTunnel(name string) error {
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
		return errors.New("device has no peers")
	}

	handshakeExpiryTime := dev.Peers[0].LastHandshakeTime.Add(handshakeTTL)
	if time.Now().After(handshakeExpiryTime) {
		return errors.New("connection handshake not yet established or expired")
	}

	return nil
}
