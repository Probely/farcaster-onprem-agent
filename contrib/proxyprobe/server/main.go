package main

import (
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
	"sync"
	"syscall"

	"github.com/gorilla/websocket"
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
)

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
		httpAddr string
		tcpAddr  string
		certFile string
		keyFile  string
	)

	flag.StringVar(&httpAddr, "http", ":8080", "HTTP/HTTPS address")
	flag.StringVar(&tcpAddr, "tcp", ":8081", "TCP/TLS address")
	flag.StringVar(&certFile, "cert", "", "TLS certificate file")
	flag.StringVar(&keyFile, "key", "", "TLS key file")
	flag.Parse()

	// Create TLS config if cert and key files are provided
	var tlsConfig *tls.Config
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatalf("Failed to load TLS certificate: %v", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}

	var wg sync.WaitGroup

	// Start HTTP/HTTPS server
	wg.Add(1)
	go func() {
		defer wg.Done()
		mux := http.NewServeMux()
		mux.HandleFunc("/", handleHTTP)
		mux.HandleFunc("/ws", handleWebSocket)

		server := &http.Server{
			Addr:      httpAddr,
			Handler:   mux,
			TLSConfig: tlsConfig,
		}

		// Start plain HTTP server
		go func() {
			log.Printf("Starting HTTP server on %s", httpAddr)
			if err := server.ListenAndServe(); err != http.ErrServerClosed {
				log.Printf("HTTP server error: %v", err)
			}
		}()

		// Start HTTPS server if TLS is configured
		if tlsConfig != nil {
			httpsAddr := fmt.Sprintf(":%d", getPort(httpAddr)+1)
			tlsServer := &http.Server{
				Addr:      httpsAddr,
				Handler:   mux,
				TLSConfig: tlsConfig,
			}
			log.Printf("Starting HTTPS server on %s", httpsAddr)
			if err := tlsServer.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
				log.Printf("HTTPS server error: %v", err)
			}
		}
	}()

	// Start TCP/TLS server
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Start plain TCP server
		tcpListener, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			log.Printf("Failed to start TCP server: %v", err)
			return
		}
		log.Printf("Starting TCP server on %s", tcpAddr)
		go handleTCPServer(tcpListener)

		// Start TLS server if TLS is configured
		if tlsConfig != nil {
			tlsAddr := fmt.Sprintf(":%d", getPort(tcpAddr)+1)
			tlsListener, err := net.Listen("tcp", tlsAddr)
			if err != nil {
				log.Printf("Failed to start TLS server: %v", err)
				return
			}
			tlsListener = tls.NewListener(tlsListener, tlsConfig)
			log.Printf("Starting TLS server on %s", tlsAddr)
			go handleTCPServer(tlsListener)
		}
	}()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for interrupt signal
	<-sigChan
	log.Println("Shutting down servers...")

	// Here you could add graceful shutdown code if needed

	wg.Wait()
	log.Println("Servers stopped")
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received HTTP request from %s", r.RemoteAddr)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	response, exists := lookupResponse(body)
	if !exists {
		response = body // Echo back if no known response
	}

	w.Write(response)
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

func getPort(addr string) int {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return 8080
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	return err == net.ErrClosed || err.Error() == "use of closed network connection"
}
