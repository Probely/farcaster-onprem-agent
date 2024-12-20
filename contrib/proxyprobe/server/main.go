package main

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for testing
	},
}

func main() {
	var (
		addr     string
		certFile string
		keyFile  string
	)

	flag.StringVar(&addr, "addr", ":8080", "Address to listen on")
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
	wg.Add(4) // HTTP, WebSocket, TCP Text, TCP Binary

	// Start HTTP/WebSocket server
	go func() {
		defer wg.Done()
		mux := http.NewServeMux()
		mux.HandleFunc("/", handleHTTP)
		mux.HandleFunc("/ws", handleWebSocket)

		server := &http.Server{
			Addr:      addr,
			Handler:   mux,
			TLSConfig: tlsConfig,
		}

		log.Printf("Starting HTTP/WebSocket server on %s", addr)
		var err error
		if tlsConfig != nil {
			err = server.ListenAndServeTLS("", "")
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Start TCP Text server
	tcpAddr := fmt.Sprintf(":%d", getPort(addr)+1)
	go func() {
		defer wg.Done()
		listener, err := createListener(tcpAddr, tlsConfig)
		if err != nil {
			log.Printf("Failed to start TCP text server: %v", err)
			return
		}
		log.Printf("Starting TCP text server on %s", listener.Addr())
		handleTCPServer(listener, handleTextConnection)
	}()

	// Start TCP Binary server
	binaryAddr := fmt.Sprintf(":%d", getPort(addr)+2)
	go func() {
		defer wg.Done()
		listener, err := createListener(binaryAddr, tlsConfig)
		if err != nil {
			log.Printf("Failed to start TCP binary server: %v", err)
			return
		}
		log.Printf("Starting TCP binary server on %s", listener.Addr())
		handleTCPServer(listener, handleBinaryConnection)
	}()

	// Start WireGuard server
	wgAddr := fmt.Sprintf(":%d", getPort(addr)+3)
	go func() {
		defer wg.Done()
		listener, err := createListener(wgAddr, tlsConfig)
		if err != nil {
			log.Printf("Failed to start WireGuard server: %v", err)
			return
		}
		log.Printf("Starting WireGuard server on %s", listener.Addr())
		handleTCPServer(listener, handleWireGuardConnection)
	}()

	wg.Wait()
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received HTTP request from %s", r.RemoteAddr)
	w.Write([]byte("HTTP OK\n"))
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

	// Echo the message back
	if err := conn.WriteMessage(messageType, message); err != nil {
		log.Printf("WebSocket write error: %v", err)
		return
	}
}

func handleTextConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	message, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		log.Printf("Text connection read error: %v", err)
		return
	}

	log.Printf("Received text message from %s: %q", conn.RemoteAddr(), message)
	conn.Write([]byte(fmt.Sprintf("Text OK: %s", message)))
}

func handleBinaryConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		log.Printf("Binary connection read error: %v", err)
		return
	}

	log.Printf("Received binary message from %s: %x", conn.RemoteAddr(), buf[:n])
	conn.Write(buf[:n]) // Echo the binary data back
}

func handleWireGuardConnection(conn net.Conn) {
	defer conn.Close()

	// Read the 2-byte size prefix
	sizeBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, sizeBuf); err != nil {
		log.Printf("Failed to read size prefix: %v", err)
		return
	}

	size := (int(sizeBuf[0]) << 8) | int(sizeBuf[1])
	payload := make([]byte, size)

	if _, err := io.ReadFull(conn, payload); err != nil {
		log.Printf("Failed to read payload: %v", err)
		return
	}

	log.Printf("Received WireGuard handshake from %s: %s", conn.RemoteAddr(), hex.EncodeToString(payload))

	// Echo the framed payload back
	response := append(sizeBuf, payload...)
	if _, err := conn.Write(response); err != nil {
		log.Printf("Failed to write response: %v", err)
		return
	}
}

func createListener(addr string, tlsConfig *tls.Config) (net.Listener, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	if tlsConfig != nil {
		return tls.NewListener(listener, tlsConfig), nil
	}
	return listener, nil
}

func handleTCPServer(listener net.Listener, handler func(net.Conn)) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if !isClosedError(err) {
				log.Printf("Accept error: %v", err)
			}
			return
		}
		go handler(conn)
	}
}

func getPort(addr string) int {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return 8080 // Default fallback
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
