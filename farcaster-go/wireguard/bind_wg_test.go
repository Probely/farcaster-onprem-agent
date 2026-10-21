package wireguard

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"go.uber.org/zap/zaptest"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

var (
	agentIP = netip.MustParseAddr("10.0.0.1")
	hubIP   = netip.MustParseAddr("10.0.0.2")
)

// streamBridge relays stream connections to the hub's UDP socket.
type streamBridge interface {
	// reset aborts every open connection with RST, simulating a
	// bridge restart or a hub replacement.
	reset()
	setHub(netip.AddrPort)
}

// tcpUDPBridge emulates tcp2udp, relaying length-prefixed TCP frames to the
// hub over a per-connection UDP socket.
type tcpUDPBridge struct {
	ln net.Listener

	mu    sync.Mutex
	hub   *net.UDPAddr
	conns []*net.TCPConn
}

func startTCPBridge(t *testing.T, hub netip.AddrPort) *tcpUDPBridge {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &tcpUDPBridge{ln: ln, hub: net.UDPAddrFromAddrPort(hub)}
	t.Cleanup(b.close)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tc := c.(*net.TCPConn)
			b.mu.Lock()
			b.conns = append(b.conns, tc)
			hub := b.hub
			b.mu.Unlock()
			go serveBridge(tc, hub)
		}
	}()
	return b
}

func serveBridge(c *net.TCPConn, hub *net.UDPAddr) {
	defer c.Close()
	udp, err := net.DialUDP("udp", nil, hub)
	if err != nil {
		return
	}
	pc := &tcpPacketConn{conn: c}
	go func() {
		defer udp.Close()
		buf := make([]byte, maxDatagramSize)
		for {
			n, err := pc.ReadPacket(buf)
			if err != nil {
				return
			}
			if _, err := udp.Write(buf[:n]); n > 0 && err != nil {
				return
			}
		}
	}()
	buf := make([]byte, maxDatagramSize)
	for {
		n, err := udp.Read(buf)
		if err != nil {
			return
		}
		if err := pc.WritePacket(buf[:n]); err != nil {
			return
		}
	}
}

func (b *tcpUDPBridge) addr() string { return b.ln.Addr().String() }

func (b *tcpUDPBridge) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.conns {
		_ = c.SetLinger(0)
		c.Close()
	}
	b.conns = nil
}

func (b *tcpUDPBridge) setHub(hub netip.AddrPort) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.hub = net.UDPAddrFromAddrPort(hub)
}

func (b *tcpUDPBridge) close() {
	b.ln.Close()
	b.reset()
}

// wsUDPBridge emulates the hub's WebSocket bridge, relaying binary messages
// to the hub over a per-connection UDP socket.
type wsUDPBridge struct {
	srv *httptest.Server

	mu    sync.Mutex
	hub   *net.UDPAddr
	conns []net.Conn // Hijacked TLS connections.
}

func startWSBridge(t *testing.T, hub netip.AddrPort) *wsUDPBridge {
	t.Helper()
	b := &wsUDPBridge{hub: net.UDPAddrFromAddrPort(hub)}
	b.srv = httptest.NewUnstartedServer(http.HandlerFunc(b.serve))
	b.srv.Config.ConnState = func(c net.Conn, s http.ConnState) {
		if s == http.StateHijacked {
			b.mu.Lock()
			b.conns = append(b.conns, c)
			b.mu.Unlock()
		}
	}
	b.srv.StartTLS()
	t.Cleanup(func() {
		b.reset()
		b.srv.Close()
	})
	return b
}

func (b *wsUDPBridge) serve(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer func() { _ = ws.CloseNow() }()
	b.mu.Lock()
	hub := b.hub
	b.mu.Unlock()
	udp, err := net.DialUDP("udp", nil, hub)
	if err != nil {
		return
	}
	defer udp.Close()
	go func() {
		defer udp.Close()
		for {
			_, p, err := ws.Read(context.Background())
			if err != nil {
				return
			}
			if _, err := udp.Write(p); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, maxDatagramSize)
	for {
		n, err := udp.Read(buf)
		if err != nil {
			return
		}
		if err := ws.Write(context.Background(), websocket.MessageBinary, buf[:n]); err != nil {
			return
		}
	}
}

func (b *wsUDPBridge) url() *url.URL {
	return &url.URL{Scheme: "wss", Host: b.srv.Listener.Addr().String(), Path: wsPath}
}

func (b *wsUDPBridge) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.conns {
		_ = c.(*tls.Conn).NetConn().(*net.TCPConn).SetLinger(0)
		c.Close()
	}
	b.conns = nil
}

func (b *wsUDPBridge) setHub(hub netip.AddrPort) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.hub = net.UDPAddrFromAddrPort(hub)
}

func newKey(t *testing.T) (priv, pub []byte) {
	t.Helper()
	priv = make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func startDevice(t *testing.T, name string, tun *ChannelTUN, bind conn.Bind, cfg string) *device.Device {
	t.Helper()
	dev := device.NewDevice(tun, bind, device.NewLogger(device.LogLevelError, name+": "))
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatalf("%s IpcSet: %v", name, err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("%s Up: %v", name, err)
	}
	t.Cleanup(dev.Close)
	return dev
}

// hubDevice starts a hub WireGuard device on a random loopback UDP port.
func hubDevice(t *testing.T, priv, agentPub []byte) (*device.Device, *ChannelTUN, netip.AddrPort) {
	t.Helper()
	tun := NewChannelTUN("hub", 1420)
	cfg := fmt.Sprintf("private_key=%x\npublic_key=%x\nallowed_ip=%s/32\n", priv, agentPub, agentIP)
	dev := startDevice(t, "hub", tun, conn.NewStdNetBind(), cfg)
	state, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(state, "\n") {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			port, err := strconv.ParseUint(v, 10, 16)
			if err != nil {
				t.Fatal(err)
			}
			return dev, tun, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
		}
	}
	t.Fatal("listen_port missing from hub device state")
	return nil, nil, netip.AddrPort{}
}

// ipv4Packet builds a minimal IPv4/UDP packet.
func ipv4Packet(src, dst netip.Addr, payload string) []byte {
	const ipLen, udpLen = 20, 8
	pkt := make([]byte, ipLen+udpLen+len(payload))
	pkt[0] = 0x45 // IPv4, 20-byte header.
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	pkt[8] = defaultTTL
	pkt[9] = 17 // UDP.
	copy(pkt[12:], src.AsSlice())
	copy(pkt[16:], dst.AsSlice())
	binary.BigEndian.PutUint16(pkt[ipLen:], 40000)
	binary.BigEndian.PutUint16(pkt[ipLen+2:], 40000)
	binary.BigEndian.PutUint16(pkt[ipLen+4:], uint16(udpLen+len(payload)))
	copy(pkt[ipLen+udpLen:], payload)
	return pkt
}

// expectDelivery repeatedly sends a packet from one TUN until the peer
// receives it. The 30s deadline accommodates wireguard-go's re-handshake
// timer, which fires after 15s of unanswered traffic.
func expectDelivery(t *testing.T, from, to *ChannelTUN, src, dst netip.Addr, payload string) {
	t.Helper()
	want := ipv4Packet(src, dst, payload)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		pkt := from.GetPacket()
		*pkt = append(*pkt, want...)
		from.Outbound <- pkt
		timeout := time.After(500 * time.Millisecond)
	read:
		for {
			select {
			case got := <-to.Inbound:
				delivered := bytes.Equal(*got, want)
				to.PutPacket(got)
				if delivered {
					return
				}
			case <-timeout:
				break read
			}
		}
	}
	t.Fatalf("packet %q was never delivered", payload)
}

// TestStreamBindRecoversFromConnectionReset verifies that a WireGuard tunnel over
// each stream transport restores bidirectional traffic after a bridge restart,
// where the hub keeps its session. The TCP case also replaces the hub, which
// requires a new handshake; that recovery runs in the transport-independent
// StreamBind core.
func TestStreamBindRecoversFromConnectionReset(t *testing.T) {
	tests := []struct {
		name       string
		start      func(t *testing.T, hub, src netip.AddrPort) (streamBridge, conn.Bind, string)
		replaceHub bool
	}{
		{"tcp", func(t *testing.T, hub, src netip.AddrPort) (streamBridge, conn.Bind, string) {
			b := startTCPBridge(t, hub)
			bind, err := NewTCPBind(&src, b.addr(), b.addr(), zaptest.NewLogger(t).Sugar())
			if err != nil {
				t.Fatal(err)
			}
			return b, bind, b.addr()
		}, true},
		{"ws", func(t *testing.T, hub, src netip.AddrPort) (streamBridge, conn.Bind, string) {
			b := startWSBridge(t, hub)
			cfg := WSConfig{URL: b.url(), Dialer: &net.Dialer{}, TLSConfig: trusting(b.srv.Certificate())}
			bind, err := NewWSBind(&src, b.url().Host, cfg, zaptest.NewLogger(t).Sugar())
			if err != nil {
				t.Fatal(err)
			}
			return b, bind, b.url().Host
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agentPriv, agentPub := newKey(t)
			hubPriv, hubPub := newKey(t)
			hubDev, hubTun, hubAddr := hubDevice(t, hubPriv, agentPub)
			bridge, bind, endpoint := tt.start(t, hubAddr, netip.AddrPortFrom(agentIP, 51820))

			agentTun := NewChannelTUN("agent", 1420)
			agentCfg := fmt.Sprintf("private_key=%x\npublic_key=%x\nendpoint=%s\nallowed_ip=%s/32\npersistent_keepalive_interval=1\n",
				agentPriv, hubPub, endpoint, hubIP)
			startDevice(t, "agent", agentTun, bind, agentCfg)

			roundTrip := func(step string) {
				t.Helper()
				expectDelivery(t, agentTun, hubTun, agentIP, hubIP, "agent to hub, "+step)
				expectDelivery(t, hubTun, agentTun, hubIP, agentIP, "hub to agent, "+step)
			}
			roundTrip("initial")

			bridge.reset()
			roundTrip("after bridge restart")

			if !tt.replaceHub {
				return
			}
			if testing.Short() {
				t.Skip("skipping the hub replacement, which waits for a WireGuard re-handshake")
			}
			hubDev.Close()
			_, hubTun, hubAddr = hubDevice(t, hubPriv, agentPub)
			bridge.setHub(hubAddr)
			bridge.reset()
			roundTrip("after hub replacement")
		})
	}
}
