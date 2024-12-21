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
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/nacl/secretbox"
	"probely.com/farcaster/settings"

	"github.com/mr-tron/base58"
)

const (
	defaultMTU  = 1420
	defaultPort = 0
	timeout     = time.Second * 30
)

var (
	configClient = createHTTPClient()

	defaultAPIURLs = []string{
		"https://api.eu.probely.com",
		"https://api.us.probely.com",
	}
)

// createHTTPClient creates an HTTP client with the appropriate TLS configuration
func createHTTPClient() *http.Client {
	// Check if certificate verification should be skipped
	skipVerify := false
	if val := os.Getenv("FARCASTER_SKIP_CERT_VERIFY"); val != "" {
		switch strings.ToLower(val) {
		case "1", "ok", "true", "yes", "enable", "enabled":
			skipVerify = true
		}
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipVerify,
		},
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

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
	AllowedIPs          string
	PersistentKeepalive int
}

// FarcasterConfig represents a Farcaster agent configuration.
type FarcasterConfig struct {
	Files map[string]*WireGuardConfig

	token string
	log   *zap.SugaredLogger
}

// NewFarcasterConfig returns a new Farcaster agent configuration.
func NewFarcasterConfig(token string, logger *zap.SugaredLogger) *FarcasterConfig {
	return &FarcasterConfig{
		Files: make(map[string]*WireGuardConfig),

		token: strings.TrimSpace(token),
		log:   logger,
	}
}

// Returns the Probely API URLs
func (c *FarcasterConfig) apiURLs() []string {
	url := os.Getenv("FARCASTER_API_URL")
	if url != "" {
		// Remove any beginning or trailing quotes and spaces.
		url = strings.Trim(url, "\"' ")
		return []string{url}
	}
	return defaultAPIURLs
}

// Load fetches and parses the agent configuration from Probely's API.
func (c *FarcasterConfig) Load() error {
	var err error

	// Fetch the config using the API.
	var data []byte
	for _, url := range c.apiURLs() {
		c.log.Infof("Trying to fetch agent configuration from %s...", url)
		if data, err = c.fetch(url); err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("could not fetch config. is the token correct? %s", err)
	}

	// Decrypt the keys and build the raw configuration files.
	if err = c.build(data); err != nil {
		return fmt.Errorf("could not build config. is the token correct? %s", err)
	}

	// Parse the configuration files.
	if err = c.parse(); err != nil {
		return fmt.Errorf("could not parse config. is the token correct? %s", err)
	}

	return nil
}

func (c *FarcasterConfig) parse() error {
	var err error

	for _, file := range c.Files {
		var peer *Peer

		for _, line := range strings.Split(file.Raw, "\n") {
			if strings.HasPrefix(line, "Address") {
				parts := strings.SplitN(line, "=", 2)
				file.Address = strings.TrimSpace(parts[1])
			} else if strings.HasPrefix(line, "MTU") {
				parts := strings.SplitN(line, "=", 2)
				file.MTU, err = strconv.Atoi(strings.TrimSpace(parts[1]))
				if err != nil {
					return err
				}
			} else if strings.HasPrefix(line, "PrivateKey") {
				parts := strings.SplitN(line, "=", 2)
				keyStr := strings.TrimSpace(parts[1])
				file.PrivateKey, err = base64.StdEncoding.DecodeString(keyStr)
				if err != nil {
					return err
				}
			} else if strings.HasPrefix(line, "ListenPort") {
				parts := strings.SplitN(line, "=", 2)
				file.ListenPort, err = strconv.Atoi(strings.TrimSpace(parts[1]))
				if err != nil {
					return err
				}
			} else if strings.HasPrefix(line, "[Peer]") {
				if peer != nil {
					file.Peers = append(file.Peers, peer)
				}
				peer = &Peer{}
			} else if strings.HasPrefix(line, "PublicKey") {
				parts := strings.SplitN(line, "=", 2)
				peer.PublicKey, err = base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
				if err != nil {
					return err
				}
			} else if strings.HasPrefix(line, "AllowedIPs") {
				parts := strings.SplitN(line, "=", 2)
				peer.AllowedIPs = strings.TrimSpace(parts[1])
			} else if strings.HasPrefix(line, "Endpoint") {
				parts := strings.SplitN(line, "=", 2)
				peer.Endpoint = strings.TrimSpace(parts[1])
				host, port, err := net.SplitHostPort(peer.Endpoint)
				if err != nil {
					return err
				}
				// Make sure that host is an IP address.
				ip, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip4", host)
				if err != nil {
					return err
				}
				if len(ip) == 0 {
					return fmt.Errorf("could not resolve host %s", host)
				}
				peer.Endpoint = net.JoinHostPort(ip[0].String(), port)
			} else if strings.HasPrefix(line, "PersistentKeepalive") {
				parts := strings.SplitN(line, "=", 2)
				peer.PersistentKeepalive, err = strconv.Atoi(strings.TrimSpace(parts[1]))
				if err != nil {
					return err
				}
			}
		}

		if peer != nil {
			file.Peers = append(file.Peers, peer)
		}
	}

	return nil
}

// Fetch the configuration from the API.
func (c *FarcasterConfig) fetch(url string) ([]byte, error) {
	var data []byte
	var err error

	// Create a public token. A public token is an identifier that allows us
	// to fetch the configuration for this agent.
	if data, err = base58.Decode(c.token); err != nil {
		return nil, err
	}
	cksum := sha256.Sum256(data)
	pubToken := base58.Encode(cksum[:])

	// Prepare the request.
	u := fmt.Sprintf("%s/scanning-agents/%s/config-files/", url, pubToken)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}

	// Set the user agent.
	userAgent := fmt.Sprintf("%s/%s (%s %s)", settings.Name, settings.Version, runtime.GOOS, runtime.GOARCH)
	req.Header.Set("User-Agent", userAgent)
	if _, err = http.NewRequest("GET", u, nil); err != nil {
		return nil, err
	}

	// Send the request.
	resp, err := configClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check the response.
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, fmt.Errorf("server response code: %d", resp.StatusCode)
	}

	// Read the response body.
	if data, err = io.ReadAll(resp.Body); err != nil {
		return nil, fmt.Errorf("could not download config: %s", err)
	}

	return data, nil
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
