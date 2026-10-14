package wireguard

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"go.uber.org/zap"

	"probely.com/farcaster/dialers"
	"probely.com/farcaster/tlsconfig"
)

const (
	wsDialTimeout  = 20 * time.Second
	wsWriteTimeout = 20 * time.Second
	wsPath         = "/v1/wg" // The hub's WebSocket endpoint.
)

var (
	errTextMessage   = errors.New("received a text message")
	errFrameTooLarge = fmt.Errorf("message exceeds %d bytes", maxDatagramSize)
)

// WSConfig configures a WebSocket bind.
type WSConfig struct {
	// URL is the hub's WebSocket URL, usually from WSURL.
	URL *url.URL
	// Dialer opens the TCP connection, through a proxy if needed. Defaults to
	// a dialers.TCPProxyDialer configured from the environment.
	Dialer dialers.Dialer
	// TLSConfig verifies the hub's certificate. Defaults to
	// tlsconfig.GetTLSConfig.
	TLSConfig *tls.Config
}

// WSURL returns the hub WebSocket URL for origEndpoint. It parses override when
// non-empty, and otherwise builds wss://<host>/v1/wg on TCP 443 from
// origEndpoint's host.
func WSURL(origEndpoint, override string) (*url.URL, error) {
	if override != "" {
		return ParseWSURL(override)
	}
	host, _, err := net.SplitHostPort(origEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid hub endpoint %q: %w", origEndpoint, err)
	}
	if host == "" {
		return nil, fmt.Errorf("hub endpoint %q has no host", origEndpoint)
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return &url.URL{Scheme: "wss", Host: host, Path: wsPath}, nil
}

// ParseWSURL parses s as a wss:// URL with a host.
func ParseWSURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("invalid WebSocket URL: %w", err)
	}
	if u.Scheme != "wss" || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid WebSocket URL %q: want wss://host[:port]/path", s)
	}
	return u, nil
}

// NewWSBind returns a StreamBind that tunnels WireGuard datagrams to cfg.URL,
// one datagram per binary WebSocket message. WireGuard sees endpoint as the
// peer address and src's port as the local port.
func NewWSBind(src *netip.AddrPort, endpoint string, cfg WSConfig, log *zap.SugaredLogger) (*StreamBind, error) {
	if src == nil {
		return nil, fmt.Errorf("source address cannot be nil")
	}
	addrPort, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("could not parse endpoint address: %w", err)
	}
	d, err := newWSDialer(cfg, log)
	if err != nil {
		return nil, err
	}
	opts := StreamOptions{Name: "WebSocket", DialTimeout: wsDialTimeout}
	return NewStreamBind(src.Port(), addrPort, d.dial, opts, log), nil
}

// wsDialer opens WebSocket connections to a fixed URL.
type wsDialer struct {
	url    *url.URL
	addr   string // Host and port of url.
	dialer dialers.Dialer
	tls    *tls.Config
}

func newWSDialer(cfg WSConfig, log *zap.SugaredLogger) (*wsDialer, error) {
	if cfg.URL == nil {
		return nil, fmt.Errorf("WebSocket URL cannot be nil")
	}
	tlsCfg := cfg.TLSConfig.Clone()
	if tlsCfg == nil {
		var err error
		if tlsCfg, err = tlsconfig.GetTLSConfig(); err != nil {
			return nil, err
		}
	}
	tlsCfg.ServerName = cfg.URL.Hostname()
	tlsCfg.MinVersion = max(tlsCfg.MinVersion, tls.VersionTLS12)
	d := cfg.Dialer
	if d == nil {
		d = dialers.NewTCPProxyDialer(wsDialTimeout, log)
	}
	port := cfg.URL.Port()
	if port == "" {
		port = "443"
	}
	return &wsDialer{
		url:    cfg.URL,
		addr:   net.JoinHostPort(cfg.URL.Hostname(), port),
		dialer: d,
		tls:    tlsCfg,
	}, nil
}

// dial opens a WebSocket connection. ctx bounds the TCP or proxy connection,
// the TLS handshake and the HTTP upgrade.
func (d *wsDialer) dial(ctx context.Context) (PacketConn, error) {
	conn, err := d.dialer.DialContext(ctx, "tcp", d.addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(conn, d.tls)
	if err := tc.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tls handshake with %s: %w", d.addr, err)
	}
	// Hand tc to the HTTP client once so the upgrade runs on the pre-dialed
	// connection.
	var pending atomic.Pointer[tls.Conn]
	pending.Store(tc)
	client := &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
				if c := pending.Swap(nil); c != nil {
					return c, nil
				}
				return nil, errors.New("connection already used")
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ws, _, err := websocket.Dial(ctx, d.url.String(), &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		tc.Close()
		return nil, fmt.Errorf("websocket upgrade: %w", err)
	}
	ws.SetReadLimit(maxDatagramSize)
	return &wsPacketConn{conn: ws}, nil
}

// wsPacketConn sends and receives one datagram per binary WebSocket message.
type wsPacketConn struct {
	conn *websocket.Conn
}

func (c *wsPacketConn) ReadPacket(dst []byte) (int, error) {
	// StreamBind's idle watchdog bounds read inactivity and replaces stalled
	// connections.
	typ, r, err := c.conn.Reader(context.Background())
	if err != nil {
		return 0, err
	}
	if typ != websocket.MessageBinary {
		return 0, errTextMessage
	}
	n, err := io.ReadFull(r, dst[:min(len(dst), maxDatagramSize)])
	if err == nil {
		// dst is full, so the message is complete only if nothing follows.
		var probe [1]byte
		if _, err = io.ReadFull(r, probe[:]); err == nil {
			return 0, errFrameTooLarge
		}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return n, nil
	}
	return 0, err
}

func (c *wsPacketConn) WritePacket(p []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), wsWriteTimeout)
	defer cancel()
	return c.conn.Write(ctx, websocket.MessageBinary, p)
}

func (c *wsPacketConn) Close() error {
	return c.conn.CloseNow()
}
