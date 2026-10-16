package wireguard

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"go.uber.org/zap/zaptest"

	"probely.com/farcaster/dialers"
	"probely.com/farcaster/tlsconfig"
)

// wsServer starts a TLS server that runs serve on each WebSocket opened at
// wsPath. It returns the WebSocket URL and the server's self-signed
// certificate.
func wsServer(t *testing.T, serve func(*websocket.Conn)) (*url.URL, *x509.Certificate) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(wsPath, func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.CloseNow() }()
		serve(c)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return &url.URL{Scheme: "wss", Host: srv.Listener.Addr().String(), Path: wsPath}, srv.Certificate()
}

// trusting returns a TLS configuration whose only root is cert.
func trusting(cert *x509.Certificate) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{RootCAs: pool}
}

// echo returns each message to the client until the connection closes.
func echo(c *websocket.Conn) {
	for {
		typ, p, err := c.Read(context.Background())
		if err != nil {
			return
		}
		if err := c.Write(context.Background(), typ, p); err != nil {
			return
		}
	}
}

// dialWS opens a connection with cfg. The dial context ends when dialWS
// returns, so a connection that works afterwards outlives its dial context.
func dialWS(t *testing.T, cfg WSConfig) (PacketConn, error) {
	t.Helper()
	d, err := newWSDialer(cfg, zaptest.NewLogger(t).Sugar())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), testWait)
	defer cancel()
	pc, err := d.dial(ctx)
	if err == nil {
		t.Cleanup(func() { pc.Close() })
	}
	return pc, err
}

// expectEcho writes datagrams to an echoing peer and reads them back in order.
func expectEcho(t *testing.T, pc PacketConn) {
	t.Helper()
	want := [][]byte{[]byte("first"), bytes.Repeat([]byte{0xa5}, maxDatagramSize)}
	for _, p := range want {
		if err := pc.WritePacket(p); err != nil {
			t.Fatalf("WritePacket: %v", err)
		}
	}
	dst := make([]byte, 65535)
	for _, p := range want {
		n, err := pc.ReadPacket(dst)
		if err != nil {
			t.Fatalf("ReadPacket: %v", err)
		}
		if !bytes.Equal(dst[:n], p) {
			t.Fatalf("read %d bytes, want the %d-byte datagram", n, len(p))
		}
	}
}

func TestWSPacketConnRead(t *testing.T) {
	binary := func(p []byte) func(context.Context, *websocket.Conn) error {
		return func(ctx context.Context, c *websocket.Conn) error {
			return c.Write(ctx, websocket.MessageBinary, p)
		}
	}
	maxSize := bytes.Repeat([]byte{0xa5}, maxDatagramSize)
	tests := []struct {
		name    string
		send    func(context.Context, *websocket.Conn) error
		want    []byte
		wantErr error
	}{
		{"empty keepalive", binary(nil), nil, nil},
		{"max size", binary(maxSize), maxSize, nil},
		{"oversize", binary(append(maxSize, 0)), nil, errFrameTooLarge},
		{"fragmented", func(ctx context.Context, c *websocket.Conn) error {
			w, err := c.Writer(ctx, websocket.MessageBinary)
			if err != nil {
				return err
			}
			for _, part := range []string{"frag", "mented"} {
				if _, err := io.WriteString(w, part); err != nil {
					return err
				}
			}
			return w.Close()
		}, []byte("fragmented"), nil},
		{"text", func(ctx context.Context, c *websocket.Conn) error {
			return c.Write(ctx, websocket.MessageText, []byte("text"))
		}, nil, errTextMessage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, cert := wsServer(t, func(c *websocket.Conn) {
				if err := tt.send(context.Background(), c); err != nil {
					return
				}
				_, _, _ = c.Read(context.Background()) // Hold the connection open.
			})
			pc, err := dialWS(t, WSConfig{URL: u, Dialer: &net.Dialer{}, TLSConfig: trusting(cert)})
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			dst := make([]byte, 65535)
			n, err := pc.ReadPacket(dst)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ReadPacket error = %v, want %v", err, tt.wantErr)
			}
			if !bytes.Equal(dst[:n], tt.want) {
				t.Fatalf("ReadPacket returned %d bytes, want %d", n, len(tt.want))
			}
		})
	}
}

func TestWSDialVerifiesCertificate(t *testing.T) {
	u, cert := wsServer(t, echo)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	tests := []struct {
		name     string
		customCA string
		trusted  bool
	}{
		{"untrusted", "", false},
		{"FARCASTER_CUSTOM_CA", base64.StdEncoding.EncodeToString(certPEM), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("FARCASTER_SKIP_CERT_VERIFY", "")
			t.Setenv("FARCASTER_CUSTOM_CA", tt.customCA)
			tlsconfig.ResetCache()
			t.Cleanup(tlsconfig.ResetCache)

			pc, err := dialWS(t, WSConfig{URL: u, Dialer: &net.Dialer{}})
			if !tt.trusted {
				if _, ok := errors.AsType[x509.UnknownAuthorityError](err); !ok {
					t.Fatalf("dial error = %v, want x509.UnknownAuthorityError", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			expectEcho(t, pc)
		})
	}
}

func TestWSDialRefusesRedirect(t *testing.T) {
	var followed atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc(wsPath, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})
	mux.HandleFunc("/elsewhere", func(w http.ResponseWriter, r *http.Request) {
		followed.Store(true)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	u := &url.URL{Scheme: "wss", Host: srv.Listener.Addr().String(), Path: wsPath}

	if _, err := dialWS(t, WSConfig{URL: u, Dialer: &net.Dialer{}, TLSConfig: trusting(srv.Certificate())}); err == nil {
		t.Fatal("dial succeeded against a redirect")
	}
	if followed.Load() {
		t.Fatal("dial followed the redirect")
	}
}

// TestWSDialHonorsContext verifies that the dial context bounds the TLS
// handshake and the HTTP upgrade.
func TestWSDialHonorsContext(t *testing.T) {
	tests := []struct {
		name  string
		start func(t *testing.T) (u *url.URL, tlsCfg *tls.Config)
	}{
		{"stalled TLS handshake", func(t *testing.T) (*url.URL, *tls.Config) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ln.Close() })
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				<-t.Context().Done()
				c.Close()
			}()
			return &url.URL{Scheme: "wss", Host: ln.Addr().String(), Path: wsPath}, &tls.Config{}
		}},
		{"stalled upgrade", func(t *testing.T) (*url.URL, *tls.Config) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				<-r.Context().Done()
			}))
			t.Cleanup(srv.Close)
			return &url.URL{Scheme: "wss", Host: srv.Listener.Addr().String(), Path: wsPath}, trusting(srv.Certificate())
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, tlsCfg := tt.start(t)
			d, err := newWSDialer(WSConfig{URL: u, Dialer: &net.Dialer{}, TLSConfig: tlsCfg}, zaptest.NewLogger(t).Sugar())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()
			start := time.Now()
			if pc, err := d.dial(ctx); err == nil {
				pc.Close()
				t.Fatal("dial against a stalled server succeeded")
			}
			if took := time.Since(start); took > time.Second {
				t.Fatalf("dial returned after %s, want shortly after the 50ms deadline", took)
			}
		})
	}
}

func TestWSDialThroughConnectProxy(t *testing.T) {
	u, cert := wsServer(t, echo)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	targets := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil || req.Method != http.MethodConnect {
			return
		}
		targets <- req.Host
		up, err := net.Dial("tcp", req.Host)
		if err != nil {
			return
		}
		defer up.Close()
		if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			return
		}
		go func() { _, _ = io.Copy(up, br) }()
		_, _ = io.Copy(c, up)
	}()

	proxyURL := &url.URL{Scheme: "http", Host: ln.Addr().String()}
	dialer := dialers.NewTCPProxyDialerWithProxyFunc(testWait, func(string) (*url.URL, error) { return proxyURL, nil }, nil)
	pc, err := dialWS(t, WSConfig{URL: u, Dialer: dialer, TLSConfig: trusting(cert)})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	select {
	case got := <-targets:
		if got != u.Host {
			t.Fatalf("proxy received CONNECT %s, want %s", got, u.Host)
		}
	default:
		t.Fatal("dial bypassed the proxy")
	}
	expectEcho(t, pc)
}

func TestWSURL(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		override string
		want     string
		wantErr  bool
	}{
		{"hostname on UDP 53", "hub.example.com:53", "", "wss://hub.example.com/v1/wg", false},
		{"IPv6 literal", "[2001:db8::1]:443", "", "wss://[2001:db8::1]/v1/wg", false},
		{"override", "hub.example.com:53", "wss://proxy.example.com:8443/hub", "wss://proxy.example.com:8443/hub", false},
		{"override without TLS", "hub.example.com:53", "ws://hub.example.com/v1/wg", "", true},
		{"endpoint without port", "hub.example.com", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := WSURL(tt.endpoint, tt.override)
			if (err != nil) != tt.wantErr {
				t.Fatalf("WSURL(%q, %q) error = %v, wantErr %v", tt.endpoint, tt.override, err, tt.wantErr)
			}
			if err == nil && u.String() != tt.want {
				t.Fatalf("WSURL(%q, %q) = %s, want %s", tt.endpoint, tt.override, u, tt.want)
			}
		})
	}
}
