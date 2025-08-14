// Netstack-based tunnel that allows remote peers to access local services, and
// the local peer to connect to remote services.
//
// Our goal is to forward packets received on the tunnel to any service we can reach.
// This implementation terminates connections from remote peers, as we are unable to
// inject packets into the kernel's network stack, which would need a TUN/TAP device.
//
// This approach is inspired by libslirp.

package netstack

import (
	"net/netip"
	"os"
	"sync"

	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/tun"
)

// TUN implements the tun.Device interface using Netstack.
type TUN struct {
	ns     *netstack
	events chan tun.Event
	name   string
	mtu    int
	log    *zap.SugaredLogger
	closed bool
	mu     sync.Mutex
}

// NewTUN creates a new TUN device using Netstack.
func NewTUN(addr netip.Addr, name string, mtu int, logger *zap.SugaredLogger, ipv6 bool, proxyUseNames bool) (*TUN, error) {
	ns, err := newNetstack(addr, mtu, logger, ipv6, proxyUseNames)
	if err != nil {
		return nil, err
	}
	t := &TUN{
		ns:     ns,
		events: make(chan tun.Event, 10),
		name:   name,
		mtu:    mtu,
		log:    logger,
		closed: false,
	}

	logger.Info("Created TUN device: ", t.name)

	t.events <- tun.EventUp
	return t, nil
}

// File returns the file descriptor of the TUN device.
func (t *TUN) File() *os.File { return nil }

// Read is called by the WireGuard device to read packets from Netstack.
func (t *TUN) Read(packets [][]byte, sizes []int, offset int) (int, error) {
	pkt, ok := t.ns.ReadPacket()
	if !ok {
		return 0, os.ErrClosed
	}
	n, err := pkt.Read(packets[0][offset:])
	if err != nil {
		return 0, err
	}

	//data, _ := netutils.DumpPacket(packets[0][offset:offset+n], true)
	//t.log.Debugf("Read packet from Netstack: %s\n", data)

	sizes[0] = n
	return 1, nil
}

// Write is called by the WireGuard device to deliver packets to Netstack.
func (t *TUN) Write(packets [][]byte, offset int) (int, error) {
	for _, pkt := range packets {
		p := pkt[offset:]
		if len(p) == 0 {
			continue
		}
		//data, _ := netutils.DumpPacket(p, true)
		//t.log.Debugf("Writing packet to Netstack: %s\n", data)
		t.ns.WritePacket(&p)
	}
	return len(packets), nil
}

// BatchSize returns the number of packets to read/write at once.
func (t *TUN) BatchSize() int {
	return 1
}

// MTU returns the MTU of the TUN device.
func (t *TUN) MTU() (int, error) { return t.mtu, nil }

// Name returns the name of the TUN device.
func (t *TUN) Name() (string, error) { return t.name, nil }

// Events returns the events channel for the TUN device.
func (t *TUN) Events() <-chan tun.Event { return t.events }

// Close closes the TUN device.
func (t *TUN) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}

	t.closed = true
	t.mu.Unlock()

	// Tear down the network stack.
	t.ns.Close()
	t.log.Info("Closed TUN device: ", t.name)
	return nil
}
