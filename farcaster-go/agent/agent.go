package agent

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"probely.com/farcaster/config"
	"probely.com/farcaster/wireguard"
	"probely.com/farcaster/wireguard/netstack"
)

// status represents the application status.
type status int

const (
	StatusDisconnected status = iota
	StatusConnecting
	StatusConnected
	StatusError
)

const (
	ConnectionTCP = iota
	ConnectionUDP
)

const defaultListenPort = 51820

func (s status) String() string {
	switch s {
	case StatusDisconnected:
		return "disconnected"
	case StatusConnecting:
		return "connecting"
	case StatusConnected:
		return "connected"
	case StatusError:
		return "error"
	default:
		return "unknown"
	}
}

// state represents the agent state.
type state struct {
	ConnectionType int
	Uptime         uint32
	TxBytes        uint64
	RxBytes        uint64

	status atomic.Uint32
}

// NewState creates a new application state.
func newState() *state {
	s := &state{}
	s.SetStatus(StatusDisconnected)
	return s
}

func (s *state) SetStatus(st status) {
	s.status.Store(uint32(st))
}

func (s *state) Status() status {
	return status(s.status.Load())
}

// Agent represents the Farcaster agent. It is responsible for managing the
// tunnel and the gateway connections. It's not thread-safe.
type Agent struct {
	// Agent state.
	State *state
	// API token.
	token string
	// API URLs.
	apiURLs []string
	// Configuration.
	cfg *config.FarcasterConfig
	// Tunnel.
	tun    tun.Device
	tunDev *device.Device
	// Gateway.
	gw    tun.Device
	gwDev *device.Device
	// Connection count (including previous connections).
	conns  atomic.Uint32
	cancel chan struct{}
	log    *zap.SugaredLogger
}

// New creates a new agent.
func New(token string, apiURLs []string, logger *zap.SugaredLogger) *Agent {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	return &Agent{
		State:   newState(),
		token:   token,
		apiURLs: apiURLs,
		cancel:  make(chan struct{}),
		log:     logger,
	}
}

func (a *Agent) loadConfig() (*config.FarcasterConfig, error) {
	// Try to read the token from a file. This can be useful to avoid showing
	// the token in the process list. If the token is not a file, it is used
	// as-is.
	t, err := os.ReadFile(a.token)
	if err == nil {
		a.log.Infof("Using token from file: %s", a.token)
	} else {
		t = []byte(a.token)
	}

	// Fetch the encrypted agent configuration using Probely's API.
	cfg := config.NewFarcasterConfig(string(t), a.apiURLs, a.log)
	if err := cfg.Load(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (a *Agent) CheckToken() error {
	// Load the configuration.
	_, err := a.loadConfig()
	return err
}

func (a *Agent) UpTCP() error {
	cfg := a.cfg.Files["wg-tunnel.conf"]
	addr := strings.Split(cfg.Address, "/")[0]
	port := cfg.ListenPort

	srcAddr, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", addr, port))
	if err != nil {
		return fmt.Errorf("invalid tunnel address: %w", err)
	}

	host, _, err := net.SplitHostPort(cfg.Peers[0].Endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint: %w", err)
	}
	bind, err := wireguard.NewTCPBind(&srcAddr, net.JoinHostPort(host, "443"), a.log)
	if err != nil {
		return fmt.Errorf("failed to create TCP bind: %w", err)
	}

	return a.up(bind)
}

func (a *Agent) Up() error {
	return a.up(conn.NewStdNetBind())
}

func (a *Agent) up(bind conn.Bind) error {
	// If the agent was already configured, just bring the tunnel up.
	if a.tunDev != nil {
		return a.tunDev.Up()
	}

	var err error
	// Load the configuration.
	a.cfg, err = a.loadConfig()
	if err != nil {
		return err
	}

	wgl := device.LogLevelError
	if a.log.Level() == zap.DebugLevel {
		wgl = device.LogLevelVerbose
	}

	// The agent creates two WireGuard tunnels:
	//
	// 1. "wg-tunnel" connects to the agent hub using an outbound connection
	// which helps to avoid issues with NAT gateways and firewalls.
	// It periodically sends keep-alive messages to the agent hub to make sure that
	// connection tracking entries are kept.
	//
	// 2. "wg-gateway" is used by cloud agents (e.g., scanners) to reach us via
	// the agent hub.

	// Configure the "tunnel" device.
	tunCfg := a.cfg.Files["wg-tunnel.conf"]
	tunCfg.MTU = 1420
	a.tun = wireguard.NewChannelTUN("tunnel", tunCfg.MTU)
	a.tunDev = device.NewDevice(a.tun, bind, device.NewLogger(wgl, "tunnel: "))

	err = a.tunDev.IpcSet(tunCfg.UAPIConfig())
	if err != nil {
		return fmt.Errorf("tunnel not configured: %w", err)
	}

	a.log.Info("Starting Farcaster tunnel...")
	err = a.tunDev.Up()
	if err != nil {
		return fmt.Errorf("tunnel failed to start: %w", err)
	}

	// Configure the "gateway" device.
	gwCfg := a.cfg.Files["wg-gateway.conf"]
	// Remove the netmask from the address.
	gwIP := strings.Split(gwCfg.Address, "/")[0]
	addr, err := netip.ParseAddr(gwIP)
	if err != nil {
		return fmt.Errorf("invalid gateway address: %w", err)
	}

	// Create a netstack-based TUN device. We use its userspace TCP/IP stack to
	// route traffic from remote peers to the local network without requiring
	// special privileges or devices (e.g. /dev/net/tun).
	mtu := gwCfg.MTU
	// Clamp MTU to 1340 to avoid issues with broken path MTU discovery.
	if mtu > 1340 {
		mtu = 1340
	}
	a.gw, err = netstack.NewTUN(addr, "gateway", mtu, a.log)
	if err != nil {
		return fmt.Errorf("failed to create gateway: %w", err)
	}

	if tunCfg.ListenPort == 0 {
		a.log.Debugf("Using default listen port for tunnel: %d", defaultListenPort)
		tunCfg.ListenPort = defaultListenPort
	}
	tunAddr, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", tunCfg.Address, tunCfg.ListenPort))
	if err != nil {
		return fmt.Errorf("invalid tunnel address: %w", err)
	}

	gwBind := wireguard.NewChannelBind(&tunAddr, a.tun.(*wireguard.ChannelTUN), a.log)
	a.gwDev = device.NewDevice(a.gw, gwBind, device.NewLogger(wgl, "gateway: "))

	// Configure the gateway device.
	gwCfg.ListenPort = 0 // Workaround for a race condition in WireGuard initialization.
	err = a.gwDev.IpcSet(gwCfg.UAPIConfig())
	if err != nil {
		return fmt.Errorf("gateway not configured: %w", err)
	}

	a.log.Info("Starting Farcaster gateway...")
	err = a.gwDev.Up()
	if err != nil {
		return fmt.Errorf("gateway failed to start: %w", err)
	}

	// Increment the connection count.
	a.conns.Add(1)

	go a.updateState(a.conns.Load())

	return nil
}

func (a *Agent) Down() error {
	dev := a.tunDev
	if dev == nil {
		return nil
	}
	return dev.Down()
}

func (a *Agent) Close() {
	// Stop any goroutine that is running for this connection.
	a.cancel <- struct{}{}

	if a.tun != nil {
		err := a.tun.Close()
		if err != nil {
			a.log.Errorf("Failed to close tunnel: %v", err)
		}
		a.tun = nil
	}

	if a.tunDev != nil {
		a.tunDev.Close()
		a.tunDev = nil
	}

	if a.gw != nil {
		err := a.gw.Close()
		if err != nil {
			a.log.Errorf("Failed to close gateway: %v", err)
		}
		a.gw = nil
	}

	// Close the tunnel and the gateway.
	if a.gwDev != nil {
		a.gwDev.Close()
		a.gwDev = nil
	}
}

func (a *Agent) ConnectWait(maxTries int) error {
	if err := a.Up(); err != nil {
		return fmt.Errorf("failed to start agent: %w", err)
	}

	if a.tunDev == nil {
		return fmt.Errorf("tunnel not configured")
	}

	tunCfg := a.cfg.Files["wg-tunnel.conf"]
	hub := tunCfg.Peers[0]

	// Try UDP 443 first
	if err := a.checkConnection("UDP", hub.Endpoint); err == nil {
		return nil
	}

	// Try TCP as fallback.
	a.log.Warnf("Failed to connect using UDP, trying TCP...")
	a.Close()
	if err := a.UpTCP(); err != nil {
		return fmt.Errorf("failed to start agent: %w", err)
	}

	if err := a.checkConnection("TCP", hub.Endpoint); err == nil {
		return nil
	}

	return fmt.Errorf("failed to connect to the agent hub")
}

func (a *Agent) checkConnection(protocol, endpoint string) error {
	a.log.Infof("Connecting to %s %s (will wait up to 30 seconds)...", endpoint, protocol)

	startTime := time.Now()
	checkTicker := time.NewTicker(500 * time.Millisecond)
	logTicker := time.NewTicker(5 * time.Second)
	defer checkTicker.Stop()
	defer logTicker.Stop()

	for time.Since(startTime) < 30*time.Second {
		select {
		case <-checkTicker.C:
			wgStats, err := wireguard.DeviceStats(a.tunDev)
			if err != nil {
				return fmt.Errorf("failed getting tunnel stats: %w", err)
			}

			if wgStats.LastHandshakeTimeSec > 0 {
				a.State.SetStatus(StatusConnected)
				if protocol == "TCP" {
					a.State.ConnectionType = ConnectionTCP
				} else {
					a.State.ConnectionType = ConnectionUDP
				}
				return nil
			}

		case <-logTicker.C:
			elapsed := int(time.Since(startTime).Seconds())
			a.log.Infof("Waiting for connection... %d/30 seconds", elapsed)
		}
	}

	return fmt.Errorf("connection timed out")
}

// UpdateState periodically updates the agent state.
func (a *Agent) updateState(conn uint32) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.cancel:
			a.log.Infof("Stopping agent state updater for connection %d", conn)
			return
		case <-ticker.C:
			dev := a.tunDev
			if dev == nil {
				a.log.Errorf("Could not get tunnel device")
				return
			}
			stats, err := wireguard.DeviceStats(dev)
			if err != nil {
				a.log.Errorf("Could not get tunnel stats: %v", err)
				return
			}
			if stats.LastHandshakeTimeSec > 0 && stats.LastHandshakeTimeSec < 300 {
				a.State.SetStatus(StatusConnected)
				//a.State.ConnectionType = ConnectionUDP
			} else {
				a.State.SetStatus(StatusConnecting)
				//a.State.ConnectionType = ConnectionUDP
			}
		}
	}
}
