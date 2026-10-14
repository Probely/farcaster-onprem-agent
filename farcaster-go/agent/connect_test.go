package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/mr-tron/base58"
	"go.uber.org/zap/zaptest"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"

	"probely.com/farcaster/tlsconfig"
	"probely.com/farcaster/wireguard"
)

// TestConnectWaitFallsBackToWebSocket verifies that the auto transport tries
// UDP, then TCP, then WebSocket, and connects over the first transport that
// reaches the hub.
func TestConnectWaitFallsBackToWebSocket(t *testing.T) {
	// Longer than wireguard-go's 5s handshake retry: a stream transport drops
	// the first initiation, which WireGuard sends before the connection is
	// established.
	defer func(d time.Duration) { handshakeTimeout = d }(handshakeTimeout)
	handshakeTimeout = 7 * time.Second

	agentPriv, agentPub := newKey(t)
	hubPriv, hubPub := newKey(t)
	bridge := startWSBridge(t, startHub(t, hubPriv, agentPub))

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: bridge.Certificate().Raw})
	t.Setenv("FARCASTER_CUSTOM_CA", base64.StdEncoding.EncodeToString(certPEM))
	t.Setenv("FARCASTER_SKIP_CERT_VERIFY", "")
	for _, v := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		t.Setenv(v, "")
	}
	tlsconfig.ResetCache()
	t.Cleanup(tlsconfig.ResetCache)

	// The configured endpoint has no hub behind it on UDP or TCP.
	token, apiURL := configAPI(t, agentPriv, hubPub, unusedAddr(t))
	wsURL := "wss://" + bridge.Listener.Addr().String() + "/v1/wg"
	a := New(token, []string{apiURL}, zaptest.NewLogger(t).Sugar(), false, false, ConnOptions{WSURL: wsURL})
	t.Cleanup(a.Close)

	if err := a.ConnectWait(); err != nil {
		t.Fatalf("ConnectWait: %v", err)
	}
	if got := a.State.Status(); got != StatusConnected {
		t.Fatalf("status = %s, want %s", got, StatusConnected)
	}
	if got := a.State.ConnectionType; got != ConnectionWS {
		t.Fatalf("connection type = %d, want ConnectionWS", got)
	}
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

// unusedAddr returns a loopback address with no TCP or UDP listener.
func unusedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// startHub starts a hub WireGuard device that accepts the agent's key and
// returns its UDP address.
func startHub(t *testing.T, priv, agentPub []byte) netip.AddrPort {
	t.Helper()
	dev := device.NewDevice(wireguard.NewChannelTUN("hub", 1420), conn.NewStdNetBind(), device.NewLogger(device.LogLevelError, "hub: "))
	t.Cleanup(dev.Close)
	if err := dev.IpcSet(fmt.Sprintf("private_key=%x\npublic_key=%x\nallowed_ip=10.0.0.1/32\n", priv, agentPub)); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
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
			return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
		}
	}
	t.Fatal("listen_port missing from hub device state")
	return netip.AddrPort{}
}

// startWSBridge starts a TLS server that relays each WebSocket's binary
// messages to hub over UDP, as the hub's WebSocket bridge does.
func startWSBridge(t *testing.T, hub netip.AddrPort) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.CloseNow() }()
		udp, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(hub))
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
		buf := make([]byte, 65535)
		for {
			n, err := udp.Read(buf)
			if err != nil {
				return
			}
			if err := ws.Write(context.Background(), websocket.MessageBinary, buf[:n]); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// configAPI serves an agent configuration in the API's format, a gzipped
// tarball of WireGuard files whose private keys are sealed with the token,
// and returns the token and the API URL.
func configAPI(t *testing.T, tunnelPriv, hubPub []byte, endpoint string) (token, apiURL string) {
	t.Helper()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	seal := func(priv []byte) string {
		var nonce [24]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			t.Fatal(err)
		}
		plain := []byte(base64.StdEncoding.EncodeToString(priv))
		return base58.Encode(secretbox.Seal(nonce[:], plain, &nonce, &key))
	}
	gatewayPriv, _ := newKey(t)
	_, peerPub := newKey(t)
	files := map[string]string{
		"wg-tunnel.conf": fmt.Sprintf("[Interface]\nAddress = 10.0.0.1\nPrivateKey = {{private_key}}\n"+
			"[Peer]\nPublicKey = %s\nAllowedIPs = 10.0.0.2/32\nEndpoint = %s\nPersistentKeepalive = 25\n",
			base64.StdEncoding.EncodeToString(hubPub), endpoint),
		"wg-gateway.conf": fmt.Sprintf("[Interface]\nAddress = 10.1.0.1/32\nPrivateKey = {{private_key}}\n"+
			"[Peer]\nPublicKey = %s\nAllowedIPs = 10.1.0.2/32\n",
			base64.StdEncoding.EncodeToString(peerPub)),
		"tunnel.key":  "PrivateKey = " + seal(tunnelPriv),
		"gateway.key": "PrivateKey = " + seal(gatewayPriv),
	}

	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(key[:])
	path := "/scanning-agents/" + base58.Encode(sum[:]) + "/config-files/"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(archive.Bytes())
	}))
	t.Cleanup(srv.Close)
	return base58.Encode(key[:]), srv.URL
}
