package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/acme/autocert"
)

var (
	// Known responses for specific messages
	responses = map[string]string{
		// Text-based
		hex.EncodeToString([]byte("PING\r\n")): hex.EncodeToString([]byte("PONG\r\n")),
		// WireGuard
		"00000094010000003551e4f915a4c9ed5ae0db77a6443d7173b0a0b0702f106c1df093bbfb37e52d7f82210d1dfaeb1d1a45b41138ddf0a87991f6e100aa144215ada3f68654407ac810a88f93cfc28158cd080ac3f522a30d2323a6411ca7f8a7193cd6f4f97a671459d348fde26fe9fdc49b1f87d790f724d264e1e04eb07ba2779934917ba2d600000000000000000000000000000000": "005c02000000efae78a63551e4f99fefc045fdadfebeeb0e0be61cea839cacfad56f7a68ca348626b650c498467954f5745488d6619fb9420854c2ce314f735e631bdc0f2a23b3a856fcdce6007800000000000000000000000000000000",
	}

	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins for testing
		},
	}

	debugMode bool
)

// debugLog prints debug messages when debug mode is enabled
func debugLog(format string, v ...interface{}) {
	if debugMode {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func getCertManager(hostnames string) *autocert.Manager {
	// Create cache directory if it doesn't exist
	cacheDir := os.Getenv("ACME_CACHE_DIR")
	if cacheDir == "" {
		cacheDir = "certs"
	}
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		os.MkdirAll(cacheDir, 0755)
	}

	// Split hostnames by comma and trim spaces
	hosts := strings.Split(hostnames, ",")
	for i, host := range hosts {
		hosts[i] = strings.TrimSpace(host)
	}

	return &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(hosts...),
		Cache:      autocert.DirCache(cacheDir),
	}
}

// Helper function to safely lookup binary data in the responses map
func lookupResponse(data []byte) ([]byte, bool) {
	hexKey := hex.EncodeToString(data)
	hexResponse, exists := responses[hexKey]
	if !exists {
		return data, false
	}
	response, err := hex.DecodeString(hexResponse)
	if err != nil {
		return data, false
	}
	return response, true
}

func main() {
	var (
		httpAddr   string
		httpsAddr  string
		tcpAddr    string
		tcpTLSAddr string
		hostnames  string
	)

	flag.StringVar(&httpAddr, "http", ":8080", "HTTP address")
	flag.StringVar(&httpsAddr, "https", ":8443", "HTTPS address")
	flag.StringVar(&tcpAddr, "tcp", ":8081", "TCP address")
	flag.StringVar(&tcpTLSAddr, "tcp-tls", ":8444", "TCP TLS address")
	flag.StringVar(&hostnames, "hostnames", "", "Comma-separated list of TLS hostnames (required)")
	flag.BoolVar(&debugMode, "debug", false, "Enable debug logging")
	flag.Parse()

	// Validate required hostname
	if hostnames == "" {
		log.Fatal("TLS hostnames are required. Please provide using -hostnames flag")
	}

	// Initialize autocert manager
	certManager := getCertManager(hostnames)

	// Get the first hostname to use as default
	defaultHost := strings.Split(hostnames, ",")[0]
	defaultHost = strings.TrimSpace(defaultHost)

	// Create TLS config using autocert
	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			debugLog("TLS handshake requested for ServerName: %s", hello.ServerName)
			if hello.ServerName == "" {
				debugLog("Empty ServerName, using default: %s", defaultHost)
				hello.ServerName = defaultHost
			}
			cert, err := certManager.GetCertificate(hello)
			if err != nil {
				log.Printf("[ERROR] Failed to get certificate: %v", err)
				return nil, err
			}
			debugLog("Certificate obtained successfully for %s", hello.ServerName)
			return cert, nil
		},
		NextProtos: []string{
			"h2", "http/1.1",
			"acme-tls/1",
		},
		MinVersion: tls.VersionTLS12,
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start HTTP/HTTPS servers
	wg.Add(1)
	go func() {
		defer wg.Done()
		mux := http.NewServeMux()
		mux.HandleFunc("/", handleHTTP)
		mux.HandleFunc("/ws", handleWebSocket)

		// Create a handler that checks for ACME challenges first, then falls back to our mux
		combinedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if this is an ACME challenge
			if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
				certManager.HTTPHandler(nil).ServeHTTP(w, r)
				return
			}
			// Otherwise, use our regular handler
			mux.ServeHTTP(w, r)
		})

		httpServer := &http.Server{
			Addr:    httpAddr,
			Handler: combinedHandler,
		}

		httpsServer := &http.Server{
			Addr: httpsAddr,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				debugLog("New HTTPS connection from %s for %s %s",
					r.RemoteAddr, r.Method, r.URL.Path)
				mux.ServeHTTP(w, r)
			}),
			TLSConfig:      tlsConfig,
			ReadTimeout:    30 * time.Second,
			WriteTimeout:   30 * time.Second,
			IdleTimeout:    120 * time.Second,
			MaxHeaderBytes: 1 << 20, // 1MB
			ConnState: func(conn net.Conn, state http.ConnState) {
				debugLog("Connection %s state changed to %s",
					conn.RemoteAddr(), state)
			},
		}

		// Start both servers
		errChan := make(chan error, 2)

		// Start HTTPS server
		go func() {
			debugLog("Starting HTTPS server on %s", httpsAddr)
			if err := httpsServer.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
				errChan <- fmt.Errorf("HTTPS server error on %s: %v", httpsAddr, err)
			}
		}()

		// Start HTTP server
		go func() {
			debugLog("Starting HTTP server on %s", httpAddr)
			if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
				errChan <- fmt.Errorf("HTTP server error on %s: %v", httpAddr, err)
			}
		}()

		// Handle server errors
		select {
		case err := <-errChan:
			log.Fatal(err)
		case <-ctx.Done():
			// Normal shutdown, continue
		}

		// Graceful shutdown for both servers
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()

		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
		}
		if err := httpsServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTPS server shutdown error: %v", err)
		}
	}()

	// Start TCP/TLS server
	wg.Add(1)
	go func() {
		defer wg.Done()
		var listeners []net.Listener

		// Start plain TCP server
		tcpListener, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			log.Fatalf("Failed to start TCP server on %s: %v", tcpAddr, err)
			return
		}
		listeners = append(listeners, tcpListener)
		debugLog("Starting TCP server on %s", tcpAddr)
		go handleTCPServer(tcpListener)

		// Start TLS server if TLS is configured
		if tlsConfig != nil {
			tlsListener, err := net.Listen("tcp", tcpTLSAddr)
			if err != nil {
				log.Fatalf("Failed to start TLS server on %s: %v", tcpTLSAddr, err)
				return
			}
			tlsListener = tls.NewListener(tlsListener, tlsConfig)
			listeners = append(listeners, tlsListener)
			debugLog("Starting TLS server on %s", tcpTLSAddr)
			go handleTCPServer(tlsListener)
		}

		// Wait for context cancellation and close all listeners
		<-ctx.Done()
		for _, l := range listeners {
			l.Close()
		}
	}()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for interrupt signal
	<-sigChan
	log.Println("Shutting down servers...")
	cancel() // Cancel context to trigger graceful shutdown

	wg.Wait()
	log.Println("Servers stopped")
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	debugLog("Handling %s request from %s to %s", r.Proto, r.RemoteAddr, r.URL.Path)
	defer debugLog("Completed request from %s to %s", r.RemoteAddr, r.URL.Path)

	// Handle root path with HTML message
	if r.URL.Path == "/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!DOCTYPE html>
<html>
<body>
    <h1>You made it. Welcome.</h1>
</body>
</html>`))
		return
	}

	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		log.Printf("[ERROR] Failed to read request body from %s: %v", r.RemoteAddr, err)
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	debugLog("Received body from %s: %x", r.RemoteAddr, body)

	response, exists := lookupResponse(body)
	if !exists {
		response = body // Echo back if no known response
		debugLog("No matching response found, echoing back")
	} else {
		debugLog("Found matching response")
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(response)
	if err != nil {
		log.Printf("[ERROR] Failed to write response to %s: %v", r.RemoteAddr, err)
		return
	}
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("WebSocket connection established with %s", conn.RemoteAddr())

	messageType, message, err := conn.ReadMessage()
	if err != nil {
		log.Printf("WebSocket read error: %v", err)
		return
	}

	log.Printf("Received WebSocket message from %s: %x", conn.RemoteAddr(), message)

	response, exists := lookupResponse(message)
	if !exists {
		response = message // Echo back if no known response
	}

	if err := conn.WriteMessage(messageType, response); err != nil {
		log.Printf("WebSocket write error: %v", err)
		return
	}
}

func handleTCPServer(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if !isClosedError(err) {
				log.Printf("Accept error: %v", err)
			}
			return
		}
		go handleTCPConnection(conn)
	}
}

func handleTCPConnection(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 64*1024)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		log.Printf("TCP read error: %v", err)
		return
	}

	message := buf[:n]
	log.Printf("Received message from %s: %x", conn.RemoteAddr(), message)

	response, exists := lookupResponse(message)
	if !exists {
		response = message // Echo back if no known response
	}

	if _, err := conn.Write(response); err != nil {
		log.Printf("TCP write error: %v", err)
		return
	}
}

func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	return err == net.ErrClosed || err.Error() == "use of closed network connection"
}
