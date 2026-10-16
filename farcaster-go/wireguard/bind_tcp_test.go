package wireguard

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// TestTCPPacketConnFraming verifies that ReadPacket and WritePacket match
// tcp2udp's two-byte length-prefixed framing.
func TestTCPPacketConnFraming(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{"empty", 0, false},
		{"one byte", 1, false},
		{"wireguard mtu", 1452, false},
		{"max", maxDatagramSize, false},
		{"oversize", maxDatagramSize + 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xa5}, tt.size)
			frame := binary.BigEndian.AppendUint16(nil, uint16(tt.size))
			frame = append(frame, payload...)

			t.Run("write", func(t *testing.T) {
				a, b := net.Pipe()
				defer b.Close()
				go func() {
					defer a.Close()
					_ = (&tcpPacketConn{conn: a}).WritePacket(payload)
				}()
				got, err := io.ReadAll(b)
				if err != nil {
					t.Fatal(err)
				}
				if tt.wantErr {
					if len(got) != 0 {
						t.Fatalf("WritePacket wrote %d bytes for an oversize datagram", len(got))
					}
					return
				}
				if !bytes.Equal(got, frame) {
					t.Fatalf("WritePacket wrote %d bytes, want the %d-byte frame", len(got), len(frame))
				}
			})

			t.Run("read", func(t *testing.T) {
				a, b := net.Pipe()
				defer b.Close()
				go func() {
					defer a.Close()
					_, _ = a.Write(frame)
				}()
				dst := make([]byte, maxDatagramSize)
				n, err := (&tcpPacketConn{conn: b}).ReadPacket(dst)
				if tt.wantErr {
					if err == nil {
						t.Fatalf("ReadPacket accepted a %d-byte frame", tt.size)
					}
					return
				}
				if err != nil {
					t.Fatalf("ReadPacket: %v", err)
				}
				if !bytes.Equal(dst[:n], payload) {
					t.Fatalf("ReadPacket returned %d bytes, want %d", n, tt.size)
				}
			})
		})
	}
}

// TestTCPPacketConnConcurrentWrites verifies that concurrent writes arrive as
// intact frames over both plain TCP and TLS (as used with an HTTPS proxy).
func TestTCPPacketConnConcurrentWrites(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		name := "tcp"
		if useTLS {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) {
			client, server := connPair(t, useTLS)
			const writers, perWriter = 8, 200
			writer := &tcpPacketConn{conn: client}
			var wg sync.WaitGroup
			errs := make(chan error, writers)
			for id := range writers {
				wg.Go(func() {
					for seq := range perWriter {
						size := 1 + (id*perWriter+seq)%1400
						if err := writer.WritePacket(bytes.Repeat([]byte{byte(id + 1)}, size)); err != nil {
							errs <- err
							return
						}
					}
				})
			}

			reader := &tcpPacketConn{conn: server}
			dst := make([]byte, maxDatagramSize)
			_ = server.SetReadDeadline(time.Now().Add(testWait))
			for i := range writers * perWriter {
				n, err := reader.ReadPacket(dst)
				if err != nil {
					t.Fatalf("frame %d: %v", i, err)
				}
				if n == 0 || bytes.Count(dst[:n], dst[:1]) != n {
					t.Fatalf("frame %d of %d bytes mixes writers: %x", i, n, dst[:min(n, 16)])
				}
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Fatalf("WritePacket: %v", err)
			}
		})
	}
}

// connPair returns a connected loopback client and server pair, optionally
// wrapped in TLS.
func connPair(t *testing.T, useTLS bool) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	if !useTLS {
		return client, server
	}

	cert, pool := selfSignedCert(t)
	tlsServer := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	tlsClient := tls.Client(client, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
	handshake := make(chan error, 1)
	go func() { handshake <- tlsServer.Handshake() }()
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-handshake; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	return tlsClient, tlsServer
}

func selfSignedCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func TestNewTCPBindValidation(t *testing.T) {
	src := netip.MustParseAddrPort("10.0.0.1:51820")
	tests := []struct {
		name     string
		src      *netip.AddrPort
		orig     string
		endpoint string
		wantErr  bool
	}{
		{"valid", &src, "hub:443", "192.0.2.1:443", false},
		{"nil source", nil, "hub:443", "192.0.2.1:443", true},
		{"empty server", &src, "", "192.0.2.1:443", true},
		{"unresolved endpoint", &src, "hub:443", "hub:443", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewTCPBind(tt.src, tt.orig, tt.endpoint, zaptest.NewLogger(t).Sugar())
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewTCPBind error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
