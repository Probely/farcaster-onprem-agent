package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

func serveTCPEcho(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("tcp listen: %v", err)
	}
	log.Printf("TCP echo listening on %s", addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("tcp accept: %v", err)
			continue
		}
		go func(conn net.Conn) {
			defer conn.Close()
			r := bufio.NewReader(conn)
			for {
				b, err := r.ReadBytes('\n')
				if err != nil {
					return
				}
				if _, err := conn.Write(b); err != nil {
					return
				}
			}
		}(c)
	}
}

func serveWSEcho(addr string) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			log.Printf("ws accept: %v", err)
			return
		}
		defer c.Close(websocket.StatusNormalClosure, "bye")
		for {
			t, data, err := c.Read(r.Context())
			if err != nil {
				return
			}
			if err := c.Write(r.Context(), t, data); err != nil {
				return
			}
		}
	})
	log.Printf("WS echo listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func serveWSEchoTLS(addr string) {
	// Generate a self-signed certificate at runtime
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("rsa key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "echoserver.local"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("x509 keypair: %v", err)
	}

	srv := &http.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("https listen: %v", err)
	}
	log.Printf("WSS echo listening on %s", addr)
	log.Fatal(srv.Serve(tls.NewListener(ln, srv.TLSConfig)))
}

func main() {
	go serveTCPEcho(":9000")
	go serveWSEcho(":9001")
	serveWSEchoTLS(":9443")
}
