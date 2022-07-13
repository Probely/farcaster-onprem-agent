package actions

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/secretbox"

	"github.com/mr-tron/base58"
)

const apiURL = "https://api.stg.probely.com"

type configFile struct {
	Data   string
	Secret string
}

var configClient = &http.Client{
	Timeout: time.Second * 20,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// Fetch the encrypted configuration for the agent
func FetchConfig(token string) ([]byte, error) {
	var data []byte
	var err error

	// Create a public token. A public token is an identifier that allows us
	// to fetch the encrypted configuration for this agent
	if data, err = base58.Decode(token); err != nil {
		return nil, err
	}
	cksum := sha256.Sum256(data)
	pubToken := base58.Encode(cksum[:])

	// Fetch the configuration
	url := fmt.Sprintf("%s/scanning-agents/%s/config-files/", apiURL, pubToken)
	if _, err = http.NewRequest("GET", url, nil); err != nil {
		return nil, err
	}

	var resp *http.Response
	if resp, err = configClient.Get(url); err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check for errors
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, fmt.Errorf("invalid server response: %d", resp.StatusCode)
	}

	if data, err = ioutil.ReadAll(resp.Body); err != nil {
		return nil, fmt.Errorf("could not download config: %s", err)
	}

	return data, nil
}

// Decrypt agent configuration encrypted secret, such as private keys
// Encrypted secret and token are base58-encoded
func decryptSecret(secret string, token string) (string, error) {
	var data []byte
	var err error

	// Decode the base58-encoded encrypted data
	if data, err = base58.Decode(secret); err != nil {
		return "", err
	}

	// The encrypted data should be at least 24 bytes, as that is the IV
	// size used by nacl SecretBox
	if len(data) < 24 {
		return "", fmt.Errorf("encrypted secret should be at least 24 bytes long")
	}

	// Decode token to be used as decryption key
	var tokenb []byte
	if tokenb, err = base58.Decode(token); err != nil {
		return "", err
	}
	var key [32]byte
	copy(key[:], tokenb)

	// Extract nonce from encrypted data
	var nonce [24]byte
	copy(nonce[:], data[:24])

	// Decrypt data
	var ok bool
	if data, ok = secretbox.Open(nil, data[24:], &nonce, &key); !ok {
		return "", fmt.Errorf("could not decrypt configuration secret")
	}

	return string(data), nil
}

// From an agent configuratoin archive (tar.gz), decrypt secret keys and build
// final configuration files. Returns a map with path, content pairs
func CreateConfig(data []byte, token string) (map[string][]byte, error) {
	var err error

	// Extract configuration files and keys
	var gz *gzip.Reader
	if gz, err = gzip.NewReader(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("could not decompress configuration: %s", err)
	}
	defer gz.Close()

	files := map[string]configFile{
		"wg-gateway.conf": {},
		"wg-tunnel.conf":  {},
	}
	tr := tar.NewReader(gz)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		var f configFile
		var ok bool
		if strings.HasSuffix(hdr.Name, ".conf") { // Config files
			cfg := path.Base(hdr.Name)
			if f, ok = files[cfg]; !ok {
				fmt.Fprintf(os.Stderr, "Unknown config file: %s\n", cfg)
				continue
			}
			data, _ := io.ReadAll(tr)
			f.Data = string(data)

		} else if strings.HasSuffix(hdr.Name, ".key") { // Secrets
			name := path.Base(hdr.Name)
			cfg := fmt.Sprintf("wg-%s.conf", strings.TrimSuffix(name, ".key"))
			if f, ok = files[cfg]; !ok {
				fmt.Fprintf(os.Stderr, "Unknown config file: %s\n", cfg)
				continue
			}
			// Read secret contents
			secret, _ := io.ReadAll(tr)
			f.Secret = string(secret)
			// Expected secret format: name = secret
			parts := strings.Split(f.Secret, " = ")[1]
			if len(parts) != 2 {
				return nil, fmt.Errorf("found invalid secret: %s", name)
			}
			// Decrypt the secret
			if f.Secret, err = decryptSecret(f.Secret, token); err != nil {
				return nil, err
			}
			fmt.Println("Decrypted secret:", f.Secret)
		}
	}
	// Build configuration files

	return nil, nil
}
