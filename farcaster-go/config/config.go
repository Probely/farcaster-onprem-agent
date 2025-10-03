package config

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/nacl/secretbox"
	"probely.com/farcaster/netutils"
	"probely.com/farcaster/settings"
	"probely.com/farcaster/tlsconfig"

	"github.com/mr-tron/base58"
)

const (
	defaultMTU     = 1420
	defaultPort    = 0
	defaultTimeout = time.Second * 30
)

// WireGuardConfig represents a WireGuard configuration. Not all fields are
// supported.
type WireGuardConfig struct {
	Address    string
	PrivateKey []byte
	ListenPort int
	MTU        int
	Peers      []*Peer

	Raw string
}

// UAPIConfig returns the configuration in the format expected by the
// WireGuard userspace implementations. This is not the same as the configuration
// file format. See https://www.wireguard.com/xplatform/ for details.
func (wc *WireGuardConfig) UAPIConfig() string {
	var cfg bytes.Buffer

	// Interface.
	cfg.WriteString(fmt.Sprintf("private_key=%s\n", hex.EncodeToString(wc.PrivateKey)))
	if wc.ListenPort != 0 {
		cfg.WriteString(fmt.Sprintf("listen_port=%d\n", wc.ListenPort))
	}

	// Peers.
	for _, peer := range wc.Peers {
		cfg.WriteString(fmt.Sprintf("public_key=%s\n", hex.EncodeToString(peer.PublicKey)))
		cfg.WriteString(fmt.Sprintf("allowed_ip=%s\n", peer.AllowedIPs))

		if peer.Endpoint != "" {
			cfg.WriteString(fmt.Sprintf("endpoint=%s\n", peer.Endpoint))
		}
		if peer.PersistentKeepalive != 0 {
			cfg.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.PersistentKeepalive))
		}
	}

	return cfg.String()
}

// Peer represents a WireGuard peer.
type Peer struct {
	PublicKey           []byte
	Endpoint            string
	OrigEndpoint        string
	AllowedIPs          string
	PersistentKeepalive int
}

// FarcasterConfig represents a Farcaster agent configuration.
type FarcasterConfig struct {
	Files map[string]*WireGuardConfig

	token   string
	apiURLs []string
	log     *zap.SugaredLogger
}

// NewFarcasterConfig returns a new Farcaster agent configuration.
func NewFarcasterConfig(token string, apiURLs []string, logger *zap.SugaredLogger) *FarcasterConfig {
	return &FarcasterConfig{
		Files:   make(map[string]*WireGuardConfig),
		token:   strings.TrimSpace(token),
		apiURLs: apiURLs,
		log:     logger,
	}
}

// Load fetches and parses the agent configuration from Probely's API.
func (c *FarcasterConfig) Load(mustResolve bool) error {
	type fetchResult struct {
		url     string
		data    []byte
		headers http.Header
		err     error
	}

	// Try each API URL, collecting diagnostics to report if all attempts fail.
	var results []fetchResult
	for _, url := range c.apiURLs {
		data, headers, err := c.fetch(url)
		if err != nil {
			results = append(results, fetchResult{
				url:     url,
				data:    data,
				headers: headers,
				err:     err,
			})
			continue
		}

		c.log.Infof("Fetched configuration from %s", url)
		if err = c.build(data); err != nil {
			return fmt.Errorf("could not build configuration: %w", err)
		}
		if err = c.parse(mustResolve); err != nil {
			return fmt.Errorf("could not parse configuration: %w", err)
		}
		return nil
	}

	// All attempts failed. Log diagnostics for each failure.
	for _, result := range results {
		c.log.Errorf("Failed to fetch configuration from %s: %v", result.url, result.err)
		for k, v := range result.headers {
			c.log.Debugf("  %s: %s", k, strings.Join(v, ", "))
		}
		c.log.Debugf("Response body from %s: %s", result.url, result.data)
	}

	return fmt.Errorf("could not fetch configuration from any of %d URL(s)", len(c.apiURLs))
}

func (c *FarcasterConfig) parse(mustResolve bool) error {
	if c == nil || c.Files == nil {
		return fmt.Errorf("invalid configuration structure")
	}

	for _, file := range c.Files {
		file.Peers = make([]*Peer, 0)

		var peer *Peer
		var parseErr error

		for lineNum, line := range strings.Split(file.Raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue // Skip empty lines and comments
			}

			if strings.HasPrefix(line, "[Peer]") {
				if peer != nil {
					file.Peers = append(file.Peers, peer)
				}
				peer = &Peer{}
				continue
			}
			// Ignore the [Interface] line
			if strings.HasPrefix(line, "[Interface]") {
				continue
			}

			// Handle settings that require parsing key=value
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				return fmt.Errorf("malformed configuration line %d: %s", lineNum+1, line)
			}

			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			if value == "" {
				return fmt.Errorf("empty value for key %s on line %d", key, lineNum+1)
			}

			parseErr = nil // Reset parse error for this line

			switch key {
			case "Address":
				file.Address = value
			case "MTU":
				file.MTU, parseErr = strconv.Atoi(value)
				// Validate reasonable MTU range
				if parseErr == nil && (file.MTU < 576 || file.MTU > 65535) {
					parseErr = fmt.Errorf("MTU value %d is out of reasonable range (576-65535)", file.MTU)
				}
			case "PrivateKey":
				file.PrivateKey, parseErr = base64.StdEncoding.DecodeString(value)
				if parseErr == nil && len(file.PrivateKey) != 32 {
					parseErr = fmt.Errorf("private key has invalid length: %d, expected 32", len(file.PrivateKey))
				}
			case "ListenPort":
				file.ListenPort, parseErr = strconv.Atoi(value)
				if parseErr == nil && (file.ListenPort < 0 || file.ListenPort > 65535) {
					parseErr = fmt.Errorf("port value %d is out of range (0-65535)", file.ListenPort)
				}
			case "PublicKey":
				if peer == nil {
					return fmt.Errorf("found PublicKey without preceding [Peer] section on line %d", lineNum+1)
				}
				peer.PublicKey, parseErr = base64.StdEncoding.DecodeString(value)
				if parseErr == nil && len(peer.PublicKey) != 32 {
					parseErr = fmt.Errorf("public key has invalid length: %d, expected 32", len(peer.PublicKey))
				}
			case "AllowedIPs":
				if peer == nil {
					return fmt.Errorf("found AllowedIPs without preceding [Peer] section on line %d", lineNum+1)
				}
				peer.AllowedIPs = value
			case "Endpoint":
				if peer == nil {
					return fmt.Errorf("found Endpoint without preceding [Peer] section on line %d", lineNum+1)
				}
				peer.Endpoint = value
				peer.OrigEndpoint = value
				parseErr = c.resolveEndpoint(peer)
				if parseErr != nil && !mustResolve {
					peer.Endpoint = "0.0.0.0:443"
					parseErr = nil
				}
			case "PersistentKeepalive":
				if peer == nil {
					return fmt.Errorf("found PersistentKeepalive without preceding [Peer] section on line %d", lineNum+1)
				}
				peer.PersistentKeepalive, parseErr = strconv.Atoi(value)
				if parseErr == nil && peer.PersistentKeepalive < 0 {
					parseErr = fmt.Errorf("persistent keepalive must be non-negative, got %d", peer.PersistentKeepalive)
				}
			default:
			}

			if parseErr != nil {
				return fmt.Errorf("error parsing line %d (%s): %v", lineNum+1, line, parseErr)
			}
		}

		// Don't forget to add the last peer
		if peer != nil {
			file.Peers = append(file.Peers, peer)
		}
	}

	return nil
}

// resolveEndpoint handles DNS resolution for endpoint hostnames
func (c *FarcasterConfig) resolveEndpoint(peer *Peer) error {
	host, port, err := net.SplitHostPort(peer.Endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint format %s: %v", peer.Endpoint, err)
	}

	// Try to validate port
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 0 || portNum > 65535 {
		return fmt.Errorf("invalid port in endpoint %s: %v", peer.Endpoint, err)
	}

	// Skip resolution if host is already an IP address
	if net.ParseIP(host) != nil {
		return nil // Already an IP, no resolution needed
	}

	// Attempt to resolve host to IP address
	// First try with the default resolver
	resolverCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use LookupNetIP with explicit ip4 family
	var netipAddrs []netip.Addr
	netipAddrs, err = net.DefaultResolver.LookupNetIP(resolverCtx, "ip4", host)

	// Successfully resolved with default resolver
	if err == nil && len(netipAddrs) > 0 {
		peer.Endpoint = net.JoinHostPort(netipAddrs[0].String(), port)
		return nil
	}

	// Try to resolve using DoH as fallback
	dohCtx, dohCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dohCancel()

	netipAddrs, err = netutils.LookupNetIPDoH(dohCtx, "ip4", host)

	// Successfully resolved with DoH
	if err == nil && len(netipAddrs) > 0 {
		peer.Endpoint = net.JoinHostPort(netipAddrs[0].String(), port)
		c.log.Warnf("Default DNS resolvers failed. Resolved %s using DoH", host)
		return nil
	}

	// Log DoH failure
	if err != nil {
		c.log.Warnf("Could not resolve host %s: %v. All resolution attempts failed", host, err)
	}

	return fmt.Errorf("could not resolve host %s. All resolution attempts failed", host)
}

func (c *FarcasterConfig) getHTTPClient(timeout time.Duration) *http.Client {
	tlsConfig, err := tlsconfig.GetTLSConfig()
	if err != nil {
		c.log.Warnf("Error getting TLS config: %v", err)
		tlsConfig = &tls.Config{}
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
		},
	}
}

// fetch returns the agent configuration along with response headers.
// Headers are returned even on error to aid in troubleshooting network issues.
func (c *FarcasterConfig) fetch(url string) (data []byte, headers http.Header, err error) {
	var tokenData []byte

	// Create a public token. A public token is an identifier that allows us
	// to fetch the configuration for this agent.
	if tokenData, err = base58.Decode(c.token); err != nil {
		return nil, nil, err
	}
	cksum := sha256.Sum256(tokenData)
	pubToken := base58.Encode(cksum[:])

	u := fmt.Sprintf("%s/scanning-agents/%s/config-files/", url, pubToken)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	userAgent := fmt.Sprintf("%s/%s (%s %s)", settings.Name, settings.Version, runtime.GOOS, runtime.GOARCH)
	req.Header.Set("User-Agent", userAgent)

	client := c.getHTTPClient(defaultTimeout)
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	headers = resp.Header.Clone()

	// Read response body before checking status to capture error pages.
	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return data, headers, fmt.Errorf("could not read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		if resp.StatusCode == 404 {
			return data, headers, fmt.Errorf("agent token not found (HTTP %d)", resp.StatusCode)
		}
		return data, headers, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return data, headers, nil
}

// Decrypt configuration secrets, such as private keys.
// secret must be base58-encoded.
func (c *FarcasterConfig) decrypt(secret string) ([]byte, error) {
	var data []byte
	var err error

	// Decode the base58-encoded secret
	if data, err = base58.Decode(secret); err != nil {
		return nil, err
	}
	// The encrypted secret should be at least 24 bytes, as that is the IV
	// size used by nacl SecretBox
	if len(data) < 24 {
		return nil, fmt.Errorf("encrypted secret should be at least 24 bytes long")
	}

	// Decode the token to use as the secret decryption key
	var dt []byte
	if dt, err = base58.Decode(c.token); err != nil {
		return nil, err
	}
	var key [32]byte
	copy(key[:], dt)

	// Extract the nonce from encrypted data
	var nonce [24]byte
	copy(nonce[:], data[:24])

	// Decrypt data
	var ok bool
	if data, ok = secretbox.Open(nil, data[24:], &nonce, &key); !ok {
		return nil, fmt.Errorf("could not decrypt configuration secret")
	}

	return data, nil
}

// From an agent configuration archive (tar.gz), decrypt keys and build
// the configuration files.
func (c *FarcasterConfig) build(data []byte) error {

	// Extract configuration files and keys.
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("invalid config data: %s", err)
	}
	defer gz.Close()

	// Files to extract from the archive.
	c.Files["wg-gateway.conf"] = &WireGuardConfig{}
	c.Files["wg-tunnel.conf"] = &WireGuardConfig{}

	// Extract files from the archive.
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		var wc *WireGuardConfig
		var ok bool
		if strings.HasSuffix(hdr.Name, ".conf") { // Config files.
			cname := path.Base(hdr.Name)
			if wc, ok = c.Files[cname]; !ok {
				c.log.Warnf("Unknown config file: %s", cname)
				continue
			}
			wc.MTU = defaultMTU
			wc.ListenPort = defaultPort
			data, _ := io.ReadAll(tr)
			wc.Raw = string(data)

		} else if strings.HasSuffix(hdr.Name, ".key") { // Encrypted keys.
			kname := path.Base(hdr.Name)
			cname := fmt.Sprintf("wg-%s.conf", strings.TrimSuffix(kname, ".key"))
			if wc, ok = c.Files[cname]; !ok {
				c.log.Warnf("Unknown key file: %s", kname)
				continue
			}
			// Read encrypted key.
			data, err := io.ReadAll(tr)
			if err != nil {
				return err
			}
			parts := strings.Split(string(data), " = ")
			if len(parts) != 2 {
				return fmt.Errorf("found invalid key: %s", kname)
			}
			// Decrypt the key.
			if wc.PrivateKey, err = c.decrypt(parts[1]); err != nil {
				return err
			}
		}
	}

	// Replace keys in the raw configuration files.
	for _, file := range c.Files {
		file.Raw = strings.ReplaceAll(file.Raw, "{{private_key}}", string(file.PrivateKey))
	}

	return nil
}

// Write the configuration as WireGuard config files to dest.
func (c *FarcasterConfig) Write(dest string) error {
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}
	for name, file := range c.Files {
		fpath := path.Join(dest, name)
		if err := os.WriteFile(fpath, []byte(file.Raw), 0o600); err != nil {
			return err
		}
	}
	return nil
}
