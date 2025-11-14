package agent

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
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
	// WaitGroup to track background goroutines.
	wg sync.WaitGroup
	// Flag to track if Close has already been called.
	closing atomic.Bool
	// Enable IPv6 DNS resolution.
	useIPv6 bool
	// Use hostnames in proxy requests when available.
	proxyUseNames bool
}

// New creates a new agent.
func New(token string, apiURLs []string, logger *zap.SugaredLogger, useIPv6 bool, proxyUseNames bool) *Agent {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	return &Agent{
		State:         newState(),
		token:         token,
		apiURLs:       apiURLs,
		cancel:        make(chan struct{}, 1), // Use buffered channel to ensure signal is not lost
		log:           logger,
		useIPv6:       useIPv6,
		proxyUseNames: proxyUseNames,
	}
}

func (a *Agent) loadConfig(mustResolve bool) error {
	if a.cfg != nil {
		return nil
	}
	t, err := os.ReadFile(a.token)
	if err == nil {
		a.log.Infof("Using token from file: %s", a.token)
	} else {
		t = []byte(a.token)
	}

	// Fetch the encrypted agent configuration using Probely's API.
	a.cfg = config.NewFarcasterConfig(string(t), a.apiURLs, a.log)
	if err := a.cfg.Load(mustResolve); err != nil {
		return err
	}
	return nil
}

func (a *Agent) CheckToken() error {
	// We do not need DNS to check for token validity.
	return a.loadConfig(false)
}

func (a *Agent) UpTCP() error {
	if err := a.loadConfig(false); err != nil {
		return err
	}

	tunCfg := a.cfg.Files["wg-tunnel.conf"]
	if tunCfg == nil {
		return fmt.Errorf("tunnel configuration not found")
	}
	tunAddr := strings.Split(tunCfg.Address, "/")[0]
	tunPort := tunCfg.ListenPort

	srcAddr, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", tunAddr, tunPort))
	if err != nil {
		return fmt.Errorf("invalid tunnel address: %w", err)
	}

	if len(tunCfg.Peers) == 0 {
		return fmt.Errorf("no peers found in tunnel configuration")
	}

	peer := tunCfg.Peers[0]

	bind, err := wireguard.NewTCPBind(&srcAddr, peer.OrigEndpoint, peer.Endpoint, a.log)
	if err != nil {
		return fmt.Errorf("failed to create TCP bind: %w", err)
	}

	return a.up(bind)
}

func (a *Agent) Up() error {
	return a.up(conn.NewStdNetBind())
}

func (a *Agent) up(bind conn.Bind) error {
	// Ensure that tunnels are not yet configured.
	if a.tunDev != nil || a.gwDev != nil {
		return fmt.Errorf("tunnels already configured: %v, %v", a.tunDev, a.gwDev)
	}

	if err := a.loadConfig(true); err != nil {
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

	err := a.tunDev.IpcSet(tunCfg.UAPIConfig())
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
	mtu := min(gwCfg.MTU, 1340)
	a.gw, err = netstack.NewTUN(addr, "gateway", mtu, a.log, a.useIPv6, a.proxyUseNames)
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
	connID := a.conns.Load()

	go a.updateState(connID)

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
	// Check if Close has already been called to avoid deadlocks
	if a.closing.Swap(true) {
		a.log.Debug("Close already in progress, skipping")
		return
	}

	a.log.Debug("Close() started")

	close(a.cancel)
	a.log.Debug("Signaled all background goroutines to exit")

	a.log.Debug("Waiting for background goroutines...")
	waitDone := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		a.log.Debug("All background goroutines exited successfully")
	case <-time.After(5 * time.Second):
		a.log.Warn("Timed out waiting for background goroutines to exit - proceeding with cleanup anyway")
	}

	if a.gw != nil {
		a.log.Debug("Closing gateway TUN device")
		err := a.gw.Close()
		if err != nil {
			a.log.Warnf("Failed to close gateway: %v", err)
		}
		a.gw = nil
		a.log.Debug("Gateway TUN device closed")
	}

	if a.tun != nil {
		a.log.Debug("Closing tunnel TUN device")
		err := a.tun.Close()
		if err != nil {
			a.log.Warnf("Failed to close tunnel: %v", err)
		}
		a.tun = nil
		a.log.Debug("Tunnel TUN device closed")
	}

	if a.gwDev != nil {
		a.log.Debug("Bringing down gateway WireGuard device")
		a.gwDev.Down()
		a.log.Debug("Waiting before closing gateway WireGuard device")
		time.Sleep(250 * time.Millisecond)
		a.log.Debug("Closing gateway WireGuard device")
		a.gwDev.Close()
		a.gwDev = nil
		a.log.Debug("Gateway WireGuard device closed")
	}

	if a.tunDev != nil {
		a.log.Debug("Bringing down tunnel WireGuard device")
		a.tunDev.Down()
		a.log.Debug("Waiting before closing tunnel WireGuard device")
		time.Sleep(250 * time.Millisecond)
		a.log.Debug("Closing tunnel WireGuard device")
		a.tunDev.Close()
		a.tunDev = nil
		a.log.Debug("Tunnel WireGuard device closed")
	}

	a.cfg = nil
	a.log.Debug("Close() completed successfully")
}

func (a *Agent) ConnectWait(maxTries int) error {
	connect := func(upFunc func() error, protocol string) error {
		if err := upFunc(); err != nil {
			return fmt.Errorf("failed to start agent: %w", err)
		}
		if a.tunDev == nil {
			return fmt.Errorf("tunnel not configured")
		}
		hub := a.cfg.Files["wg-tunnel.conf"].Peers[0]
		return a.checkConnection(protocol, hub.OrigEndpoint)
	}

	// Helper function to clean up resources if the connection fails
	cleanupFailedConnection := func() {
		// Clean up any partial resources but don't fully close the agent
		// This ensures we can reuse the agent for the next connection attempt
		if a.tunDev != nil {
			a.log.Debug("Bringing down tunnel WireGuard device")
			a.tunDev.Down()
			a.log.Debug("Waiting before closing tunnel WireGuard device")
			time.Sleep(250 * time.Millisecond)
			a.log.Debug("Closing tunnel WireGuard device")
			a.tunDev.Close()
			a.tunDev = nil
			a.log.Debug("Tunnel WireGuard device closed")
		}

		if a.gwDev != nil {
			a.log.Debug("Bringing down gateway WireGuard device")
			a.gwDev.Down()
			a.log.Debug("Waiting before closing gateway WireGuard device")
			time.Sleep(250 * time.Millisecond)
			a.log.Debug("Closing gateway WireGuard device")
			a.gwDev.Close()
			a.gwDev = nil
			a.log.Debug("Gateway WireGuard device closed")
		}

		a.cfg = nil
	}

	forceTCP, _ := strconv.ParseBool(os.Getenv("FARCASTER_FORCE_TCP"))
	if forceTCP {
		a.log.Info("TCP connection forced. Connecting...")
		err := connect(a.UpTCP, "TCP")
		if err != nil {
			a.log.Infof("TCP connection failed: %v", err)
			a.Close() // Fully close the agent only if TCP fails
			return err
		}
		return nil
	}

	a.log.Info("Connecting via UDP...")
	var err error
	if err = connect(a.Up, "UDP"); err == nil {
		return nil
	}
	a.log.Warnf("UDP connection failed: %v", err)

	// Don't fully close the agent here, just clean up resources
	cleanupFailedConnection()

	a.log.Info("Trying TCP...")
	err = connect(a.UpTCP, "TCP")
	if err != nil {
		a.log.Warnf("TCP connection failed: %v", err)
		a.Close() // Fully close the agent since both attempts failed
		return err
	}
	return nil
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
				a.log.Warnf("Failed getting tunnel stats: %v", err)
				continue // Don't fail immediately on stats error
			}

			if wgStats.LastHandshakeTimeSec > 0 {
				a.log.Infof("WireGuard handshake successful over %s", protocol)
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
			a.log.Infof("Waiting for WireGuard handshake... %d/30 seconds", elapsed)
		}
	}

	return fmt.Errorf("connection timed out waiting for WireGuard handshake")
}

// UpdateState periodically updates the agent state.
func (a *Agent) updateState(conn uint32) {
	a.wg.Add(1)
	defer a.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	a.log.Debugf("Started state updater for connection %d", conn)

	for {
		select {
		case <-a.cancel:
			a.log.Infof("Stopped state updater for connection %d", conn)
			return
		case <-ticker.C:
			dev := a.tunDev
			if dev == nil {
				a.log.Errorf("Could not get tunnel device")
				return
			}

			// Add timeout for DeviceStats to prevent blocking forever
			statsChan := make(chan struct {
				stats *wireguard.WireguardStats
				err   error
			})

			go func() {
				stats, err := wireguard.DeviceStats(dev)
				statsChan <- struct {
					stats *wireguard.WireguardStats
					err   error
				}{stats, err}
			}()

			select {
			case result := <-statsChan:
				if result.err != nil {
					a.log.Errorf("Could not get tunnel stats: %v", result.err)
					continue
				}

				if result.stats.LastHandshakeTimeSec > 0 && result.stats.LastHandshakeTimeSec < 300 {
					a.State.SetStatus(StatusConnected)
				} else {
					a.State.SetStatus(StatusConnecting)
				}

			case <-time.After(5 * time.Second):
				a.log.Errorf("Timed out waiting for device stats")
				continue

			case <-a.cancel:
				a.log.Infof("Canceled while waiting for device stats (connection %d)", conn)
				return
			}
		}
	}
}
