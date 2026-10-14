package agent

import (
	"context"
	"errors"
	"fmt"
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
	ConnectionWS
)

const defaultListenPort = 51820

// maxHandshakeAge is how long the agent reports itself connected after a
// handshake: WireGuard rejects a session 180s after its handshake.
const maxHandshakeAge = 180 * time.Second

// udpHandshakeTimeout allows three WireGuard handshake attempts, ~5s apart.
// streamHandshakeTimeout matches the TCP and WebSocket dial timeout.
var (
	udpHandshakeTimeout    = 15 * time.Second
	streamHandshakeTimeout = 20 * time.Second
)

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
	conns atomic.Uint32
	// stopState stops the state updater of the current connection and waits
	// for it to exit. Nil while disconnected.
	stopState func()
	log       *zap.SugaredLogger
	// Flag to track if Close has already been called.
	closing atomic.Bool
	// Enable IPv6 DNS resolution.
	useIPv6 bool
	// Use hostnames in proxy requests when available.
	proxyUseNames bool
	conn          ConnOptions
}

// ConnOptions selects how the agent reaches the hub.
type ConnOptions struct {
	Transport Transport
	// WSURL overrides the WebSocket URL derived from the hub endpoint.
	WSURL string
}

// New creates a new agent.
func New(token string, apiURLs []string, logger *zap.SugaredLogger, useIPv6 bool, proxyUseNames bool, conn ConnOptions) *Agent {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	return &Agent{
		State:         newState(),
		token:         token,
		apiURLs:       apiURLs,
		log:           logger,
		useIPv6:       useIPv6,
		proxyUseNames: proxyUseNames,
		conn:          conn,
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

// hubPeer loads the configuration, resolving the hub endpoint if possible, and
// returns the tunnel's source address and the hub peer.
func (a *Agent) hubPeer() (netip.AddrPort, *config.Peer, error) {
	if err := a.loadConfig(false); err != nil {
		return netip.AddrPort{}, nil, err
	}

	tunCfg := a.cfg.Files["wg-tunnel.conf"]
	if tunCfg == nil {
		return netip.AddrPort{}, nil, fmt.Errorf("tunnel configuration not found")
	}
	tunAddr := strings.Split(tunCfg.Address, "/")[0]
	tunPort := tunCfg.ListenPort

	srcAddr, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", tunAddr, tunPort))
	if err != nil {
		return netip.AddrPort{}, nil, fmt.Errorf("invalid tunnel address: %w", err)
	}

	if len(tunCfg.Peers) == 0 {
		return netip.AddrPort{}, nil, fmt.Errorf("no peers found in tunnel configuration")
	}
	return srcAddr, tunCfg.Peers[0], nil
}

// newBind returns the WireGuard bind for transport t.
func (a *Agent) newBind(t Transport) (conn.Bind, error) {
	switch t {
	case TransportUDP:
		return conn.NewStdNetBind(), nil
	case TransportTCP:
		srcAddr, peer, err := a.hubPeer()
		if err != nil {
			return nil, err
		}
		bind, err := wireguard.NewTCPBind(&srcAddr, peer.OrigEndpoint, peer.Endpoint, a.log)
		if err != nil {
			return nil, fmt.Errorf("failed to create TCP bind: %w", err)
		}
		return bind, nil
	case TransportWS:
		srcAddr, peer, err := a.hubPeer()
		if err != nil {
			return nil, err
		}
		u, err := wireguard.WSURL(peer.OrigEndpoint, a.conn.WSURL)
		if err != nil {
			return nil, err
		}
		bind, err := wireguard.NewWSBind(&srcAddr, peer.Endpoint, wireguard.WSConfig{URL: u}, a.log)
		if err != nil {
			return nil, fmt.Errorf("failed to create WebSocket bind: %w", err)
		}
		return bind, nil
	default:
		return nil, fmt.Errorf("unknown transport %q", t)
	}
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
	connID := a.conns.Add(1)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.updateState(ctx, a.tunDev, connID)
	}()
	a.stopState = func() {
		cancel()
		<-done
	}

	return nil
}

func (a *Agent) Down() error {
	dev := a.tunDev
	if dev == nil {
		return nil
	}
	return dev.Down()
}

// Close stops the state updater and tears down the gateway and tunnel devices.
func (a *Agent) Close() {
	// Check if Close has already been called to avoid deadlocks
	if a.closing.Swap(true) {
		a.log.Debug("Close already in progress, skipping")
		return
	}

	a.log.Debug("Close() started")
	a.disconnect()
	a.log.Debug("Close() completed successfully")
}

// ConnectWait tries each transport in the configured order and
// returns once WireGuard completes a handshake over one of them. If every
// transport fails, it closes the agent.
func (a *Agent) ConnectWait() error {
	var errs []error
	for _, t := range a.conn.Transport.steps() {
		a.log.Infof("Connecting over %s...", t.label())
		err := a.connect(t)
		if err == nil {
			return nil
		}
		a.log.Warnf("%s connection failed: %v", t.label(), err)
		errs = append(errs, fmt.Errorf("%s: %w", t.label(), err))
		a.disconnect()
	}
	a.Close()
	return errors.Join(errs...)
}

// connect starts the tunnel over transport t and waits for the first handshake.
func (a *Agent) connect(t Transport) error {
	bind, err := a.newBind(t)
	if err != nil {
		return fmt.Errorf("failed to start agent: %w", err)
	}
	if err := a.up(bind); err != nil {
		return fmt.Errorf("failed to start agent: %w", err)
	}
	hub := a.cfg.Files["wg-tunnel.conf"].Peers[0]
	return a.checkConnection(t, hub.OrigEndpoint)
}

// disconnect stops the state updater and closes the gateway and tunnel devices
// so the next transport attempt starts from a fresh configuration.
func (a *Agent) disconnect() {
	if a.stopState != nil {
		a.stopState()
		a.stopState = nil
	}

	if a.gw != nil {
		a.log.Debug("Closing gateway TUN device")
		if err := a.gw.Close(); err != nil {
			a.log.Warnf("Failed to close gateway: %v", err)
		}
		a.gw = nil
		a.log.Debug("Gateway TUN device closed")
	}

	if a.tun != nil {
		a.log.Debug("Closing tunnel TUN device")
		if err := a.tun.Close(); err != nil {
			a.log.Warnf("Failed to close tunnel: %v", err)
		}
		a.tun = nil
		a.log.Debug("Tunnel TUN device closed")
	}

	if a.gwDev != nil {
		a.log.Debug("Bringing down gateway WireGuard device")
		_ = a.gwDev.Down()
		a.log.Debug("Waiting before closing gateway WireGuard device")
		time.Sleep(250 * time.Millisecond)
		a.log.Debug("Closing gateway WireGuard device")
		a.gwDev.Close()
		a.gwDev = nil
		a.log.Debug("Gateway WireGuard device closed")
	}

	if a.tunDev != nil {
		a.log.Debug("Bringing down tunnel WireGuard device")
		_ = a.tunDev.Down()
		a.log.Debug("Waiting before closing tunnel WireGuard device")
		time.Sleep(250 * time.Millisecond)
		a.log.Debug("Closing tunnel WireGuard device")
		a.tunDev.Close()
		a.tunDev = nil
		a.log.Debug("Tunnel WireGuard device closed")
	}

	a.cfg = nil
}

func (a *Agent) checkConnection(t Transport, endpoint string) error {
	timeout := streamHandshakeTimeout
	if t == TransportUDP {
		timeout = udpHandshakeTimeout
	}
	a.log.Infof("Connecting to %s %s (will wait up to %s)...", endpoint, t.label(), timeout)

	startTime := time.Now()
	checkTicker := time.NewTicker(500 * time.Millisecond)
	logTicker := time.NewTicker(5 * time.Second)
	defer checkTicker.Stop()
	defer logTicker.Stop()

	for time.Since(startTime) < timeout {
		select {
		case <-checkTicker.C:
			wgStats, err := wireguard.DeviceStats(a.tunDev)
			if err != nil {
				a.log.Warnf("Failed getting tunnel stats: %v", err)
				continue // Don't fail immediately on stats error
			}

			if wgStats.LastHandshakeTimeSec > 0 {
				a.log.Infof("WireGuard handshake successful over %s", t.label())
				a.State.SetStatus(StatusConnected)
				switch t {
				case TransportTCP:
					a.State.ConnectionType = ConnectionTCP
				case TransportWS:
					a.State.ConnectionType = ConnectionWS
				default:
					a.State.ConnectionType = ConnectionUDP
				}
				return nil
			}

		case <-logTicker.C:
			elapsed := time.Since(startTime).Round(time.Second)
			a.log.Infof("Waiting for WireGuard handshake... %s/%s", elapsed, timeout)
		}
	}

	return fmt.Errorf("connection timed out waiting for WireGuard handshake")
}

// updateState refreshes the agent status from dev every 30 seconds until ctx
// is canceled.
func (a *Agent) updateState(ctx context.Context, dev *device.Device, conn uint32) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	a.log.Debugf("Started state updater for connection %d", conn)

	for {
		select {
		case <-ctx.Done():
			a.log.Infof("Stopped state updater for connection %d", conn)
			return
		case <-ticker.C:
			// Buffer capacity 1 lets the goroutine send and exit after a
			// timeout or cancellation.
			statsChan := make(chan struct {
				stats *wireguard.WireguardStats
				err   error
			}, 1)

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

				if handshakeFresh(result.stats.LastHandshakeTimeSec, time.Now()) {
					a.State.SetStatus(StatusConnected)
				} else {
					a.State.SetStatus(StatusConnecting)
				}

			case <-time.After(5 * time.Second):
				a.log.Errorf("Timed out waiting for device stats")
				continue

			case <-ctx.Done():
				a.log.Infof("Canceled while waiting for device stats (connection %d)", conn)
				return
			}
		}
	}
}

// handshakeFresh reports whether a handshake at Unix time last, in seconds, is
// younger than maxHandshakeAge at now. Zero means no handshake yet.
func handshakeFresh(last int64, now time.Time) bool {
	return last > 0 && now.Sub(time.Unix(last, 0)) < maxHandshakeAge
}
