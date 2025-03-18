// Inspired by WireGuard's channel_tun.go with some modifications:
//  * Packet pool to reduce memory allocations.
//  * Adapted to work with our ChannelBind implementation.

package wireguard

import (
	"io"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	chanBufSize   = 256
	maxPacketSize = 2048
)

// ChannelTUN is a TUN device that uses channels to send and receive packets.
type ChannelTUN struct {
	Inbound  chan *[]byte // Incoming packets.
	Outbound chan *[]byte // Outbound packets.
	Closed   chan struct{}
	once     sync.Once

	// Packet pool to reduce memory allocations.
	pktPool *sync.Pool

	events chan tun.Event
	name   string
	mtu    int
}

// NewChannelTUN creates a new ChannelTUN device.
func NewChannelTUN(name string, mtu int) *ChannelTUN {
	c := &ChannelTUN{
		Inbound:  make(chan *[]byte, chanBufSize),
		Outbound: make(chan *[]byte, chanBufSize),
		Closed:   make(chan struct{}),
		pktPool: &sync.Pool{
			New: func() any {
				b := make([]byte, 0, maxPacketSize)
				return &b
			},
		},
		events: make(chan tun.Event, 1),
		name:   name,
	}
	c.mtu = mtu
	c.events <- tun.EventUp
	return c
}

func (c *ChannelTUN) GetPacket() *[]byte {
	return c.pktPool.Get().(*[]byte)
}

func (c *ChannelTUN) PutPacket(pkt *[]byte) {
	p := (*pkt)[:0]
	*pkt = p
	c.pktPool.Put(pkt)
}

func (c *ChannelTUN) File() *os.File { return nil }

// Read is called by the WireGuard device to read packets from the TUN.
func (c *ChannelTUN) Read(packets [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-c.Closed:
		return 0, os.ErrClosed
	case pkt := <-c.Outbound:
		defer c.PutPacket(pkt)
		n := copy(packets[0][offset:], *pkt)
		sizes[0] = n
		return 1, nil
	}
}

// Write is called by the WireGuard device to deliver a packet for routing.
func (c *ChannelTUN) Write(packets [][]byte, offset int) (int, error) {
	if offset == -1 {
		c.once.Do(func() {
			close(c.Closed)
		})
		return 0, io.EOF
	}

	// Read packets from WireGuard and deliver them to the TUN.
	for i, data := range packets {
		if len(data[offset:]) > maxPacketSize {
			return i, os.ErrInvalid
		}
		pkt := c.GetPacket()
		n := copy((*pkt)[:cap(*pkt)], data[offset:])

		*pkt = (*pkt)[:n]
		select {
		case <-c.Closed:
			c.PutPacket(pkt)
			return i, os.ErrClosed
		case c.Inbound <- pkt:
		}
	}
	return len(packets), nil
}

func (c *ChannelTUN) BatchSize() int {
	return 1
}

func (c *ChannelTUN) MTU() (int, error)        { return c.mtu, nil }
func (c *ChannelTUN) Name() (string, error)    { return c.name, nil }
func (c *ChannelTUN) Events() <-chan tun.Event { return c.events }
func (c *ChannelTUN) Close() error {
	_, _ = c.Write(nil, -1)
	return nil
}
