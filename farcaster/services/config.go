package services

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

type ConfigFile struct {
	Data   string
	Secret string
}

var configClient = &http.Client{
	Timeout: time.Second * 10,
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

// Decrypt configuration secrets, such as private keys
// Both secret and token must be base58-encoded
func decryptSecret(secret string, token string) (string, error) {
	var data []byte
	var err error

	// Decode the base58-encoded secret
	if data, err = base58.Decode(secret); err != nil {
		return "", err
	}
	// The encrypted secret should be at least 24 bytes, as that is the IV
	// size used by nacl SecretBox
	if len(data) < 24 {
		return "", fmt.Errorf("encrypted secret should be at least 24 bytes long")
	}

	// Decode the token to use as the secret decryption key
	var dt []byte
	if dt, err = base58.Decode(token); err != nil {
		return "", err
	}
	var key [32]byte
	copy(key[:], dt)

	// Extract the nonce from encrypted data
	var nonce [24]byte
	copy(nonce[:], data[:24])

	// Decrypt data
	var ok bool
	if data, ok = secretbox.Open(nil, data[24:], &nonce, &key); !ok {
		return "", fmt.Errorf("could not decrypt configuration secret")
	}

	return string(data), nil
}

// Takes a map of path: ConfigFile and replaces secret placeholders by actual
// decrypted secrets
func fillSecrets(files map[string]*ConfigFile) {
	for _, file := range files {
		file.Data = strings.ReplaceAll(file.Data, "{{private_key}}", file.Secret)
	}
}

// From an agent configuration archive (tar.gz), decrypt secrets and build
// the configuration files
func BuildConfig(data []byte, token string) (map[string]*ConfigFile, error) {
	var err error

	// Extract configuration files and keys
	var gz *gzip.Reader
	if gz, err = gzip.NewReader(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("could not decompress configuration: %s", err)
	}
	defer gz.Close()

	files := map[string]*ConfigFile{
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
		var c *ConfigFile
		var ok bool
		if strings.HasSuffix(hdr.Name, ".conf") { // Config files
			cname := path.Base(hdr.Name)
			if c, ok = files[cname]; !ok {
				fmt.Fprintf(os.Stderr, "Unknown config file: %s\n", cname)
				continue
			}
			data, _ := io.ReadAll(tr)
			c.Data = string(data)

		} else if strings.HasSuffix(hdr.Name, ".key") { // Secrets
			sname := path.Base(hdr.Name)
			cname := fmt.Sprintf("wg-%s.conf", strings.TrimSuffix(sname, ".key"))
			if c, ok = files[cname]; !ok {
				fmt.Fprintf(os.Stderr, "Unknown config file: %s\n", cname)
				continue
			}
			// Read secret contents
			secret, _ := io.ReadAll(tr)
			c.Secret = string(secret)
			// Expected secret format: name = secret
			parts := strings.Split(c.Secret, " = ")
			if len(parts) != 2 {
				return nil, fmt.Errorf("found invalid secret: %s", sname)
			}
			c.Secret = parts[1]
			// Decrypt the secret
			if c.Secret, err = decryptSecret(c.Secret, token); err != nil {
				return nil, err
			}
		}
	}

	fillSecrets(files)

	return files, nil
}

// Writes configuration files to dest
func WriteConfig(files map[string]*ConfigFile, dest string) error {
	if err := os.MkdirAll(dest, 0700); err != nil {
		return err
	}
	for name, file := range files {
		fpath := path.Join(dest, name)
		if err := os.WriteFile(fpath, []byte(file.Data), 0600); err != nil {
			return err
		}
	}
	return nil
}
