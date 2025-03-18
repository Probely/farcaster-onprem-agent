package main

import (
	"fmt"
	"io"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

var (
	_ conn.Endpoint = (*DummyEndpoint)(nil)
	_ conn.Bind     = (*DummyBind)(nil)
)

type DummyBind struct {
	InCh  chan []byte
	OutCh chan []byte
	done  chan struct{}
	src   netip.AddrPort
	dst   netip.AddrPort
	mu    sync.Mutex
	open  bool
}

func NewDummyBind(src, dst netip.AddrPort) *DummyBind {
	return &DummyBind{
		InCh:  make(chan []byte, 1024),
		OutCh: make(chan []byte, 1024),
		done:  make(chan struct{}),
		src:   src,
		dst:   dst,
	}
}

func (b *DummyBind) makeReceiveIPv4() conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		select {
		case data := <-b.InCh:
			bufs[0] = data
			sizes[0] = len(data)
			eps[0] = &DummyEndpoint{src: b.src, dst: b.dst}
			return 1, nil
		case <-b.done:
			return 0, io.ErrClosedPipe
		}
	}
}

func (b *DummyBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.open {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	b.open = true

	return []conn.ReceiveFunc{b.makeReceiveIPv4()}, 51820, nil
}

func (b *DummyBind) BatchSize() int {
	return 1
}

func (b *DummyBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open {
		return nil
	}
	close(b.done)
	b.open = false
	return nil
}

func (b *DummyBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if len(bufs) == 0 {
		return nil
	}

	for _, buf := range bufs {
		if len(buf) == 0 {
			continue
		}
		b.OutCh <- buf
	}

	return nil
}

func (b *DummyBind) SetMark(mark uint32) error {
	return nil
}

type DummyEndpoint struct {
	dst netip.AddrPort
	src netip.AddrPort
}

func (b *DummyBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if s == "" {
		return nil, fmt.Errorf("empty endpoint string")
	}

	dst, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint address: %w", err)
	}

	if !dst.IsValid() {
		return nil, fmt.Errorf("invalid endpoint: %s", s)
	}

	return &DummyEndpoint{
		dst: dst,
	}, nil
}

func (e *DummyEndpoint) ClearSrc() {
	e.src = netip.AddrPort{}
}

func (e *DummyEndpoint) SrcToString() string {
	if !e.src.IsValid() {
		return ""
	}
	return e.src.String()
}

func (e *DummyEndpoint) DstIP() netip.Addr {
	return e.dst.Addr()
}

func (e *DummyEndpoint) DstPort() uint16 {
	return e.dst.Port()
}

func (e *DummyEndpoint) SrcIP() netip.Addr {
	return e.src.Addr()
}

func (e *DummyEndpoint) DstToBytes() []byte {
	if !e.dst.IsValid() {
		return nil
	}
	b, err := e.dst.MarshalBinary()
	if err != nil {
		return nil
	}
	return b
}

func (e *DummyEndpoint) DstToString() string {
	if !e.dst.IsValid() {
		return ""
	}
	return e.dst.String()
}
