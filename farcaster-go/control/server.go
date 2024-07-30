package control

import (
	"bufio"
	"fmt"
	"net"
	"strings"

	"go.uber.org/zap"
	"probely.com/farcaster/agent"
)

// handler is a function that handles a control API request.
type handler func([]string) (string, error)

// maxMsgSize is the maximum size of a control API message.
const maxMsgSize = 2048

// Server is the server for the control API.
type Server struct {
	agent    *agent.Agent
	listener net.Listener
	handlers map[string]handler

	log *zap.SugaredLogger
}

// NewServer creates a new control API server.
// Changes made to this API must be reflected in any client code that uses it.
// Client code can be found in:
// - github.com/Probely/farcaster-windows/farcasterd/farcasterd.go
func NewServer(addr, group string, log *zap.SugaredLogger) (*Server, error) {
	listener, err := newListener(addr, group)
	if err != nil {
		return nil, err
	}
	s := &Server{
		listener: listener,
		log:      log,
	}

	// Request handlers.
	var handlers = map[string]handler{
		"status": s.handleStatus,
	}
	s.handlers = handlers

	return s, nil
}

// Run starts the control API server.
func (s *Server) Run() error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.log.Warnf("API accept call failed: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

// Close closes the control API server.
func (s *Server) Close() {
	s.listener.Close()
}

// handleConn handles a control API connection.
func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	// Send greeting.
	fmt.Fprintf(conn, "+OK control server ready\r\n")

	// Read commands.
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, maxMsgSize), maxMsgSize)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		parts := strings.Split(line, " ")
		handler, exists := s.handlers[strings.ToLower(parts[0])]
		if !exists {
			s.log.Warnf("Invalid API command: %s", parts[0])
			fmt.Fprintf(conn, "-ERR invalid command: %s\r\n", parts[0])
			continue
		}
		resp, err := handler(parts[1:])
		if err != nil {
			s.log.Warnf("API handler failed: %v", err)
			fmt.Fprintf(conn, "-ERR %s\r\n", err)
			continue
		}
		fmt.Fprintf(conn, "+OK %s\r\n", resp)
	}

	if err := scanner.Err(); err != nil {
		s.log.Warnf("API command parser failed: %v", err)
	}
}

func (s *Server) handleStatus(args []string) (string, error) {
	if s.agent == nil {
		return fmt.Sprintf("status=%s", agent.StatusDisconnected), nil
	}

	resp := fmt.Sprintf("status=%s", s.agent.State.Status)
	return resp, nil
}
