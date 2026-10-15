package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"sync"
)

var (
	// Cached TLS configuration.
	cachedConfig    *tls.Config
	cachedConfigErr error
	configOnce      sync.Once
)

// GetTLSConfig returns a TLS configuration based on the following environment variables:
//   - FARCASTER_SKIP_CERT_VERIFY: Skip certificate verification (insecure).
//   - FARCASTER_CUSTOM_CA: CA certificate(s) to trust, as the path to a PEM
//     file or as base64-encoded PEM.
func GetTLSConfig() (*tls.Config, error) {
	configOnce.Do(func() {
		cachedConfig, cachedConfigErr = buildTLSConfig()
	})

	if cachedConfigErr != nil {
		return nil, cachedConfigErr
	}

	// Always return a clone to prevent mutations affecting other users.
	return cachedConfig.Clone(), nil
}

// buildTLSConfig performs the actual TLS configuration building.
// This is only called once by GetTLSConfig via sync.Once.
func buildTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{}

	// Check for skip verify first (takes precedence for backward compatibility).
	if val := os.Getenv("FARCASTER_SKIP_CERT_VERIFY"); val != "" {
		switch strings.ToLower(val) {
		case "1", "ok", "true", "yes", "enable", "enabled":
			tlsConfig.InsecureSkipVerify = true
			return tlsConfig, nil
		}
	}

	// Check for custom CA.
	customCA := os.Getenv("FARCASTER_CUSTOM_CA")
	if customCA == "" {
		return tlsConfig, nil
	}

	caData, err := readCustomCA(customCA)
	if err != nil {
		return nil, err
	}

	// Create certificate pool with system CAs.
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		rootCAs = x509.NewCertPool()
	}

	// Parse and add custom CA(s).
	if !addCertsFromPEM(rootCAs, caData) {
		return nil, fmt.Errorf("failed to parse any certificates from FARCASTER_CUSTOM_CA")
	}

	tlsConfig.RootCAs = rootCAs

	return tlsConfig, nil
}

// readCustomCA reads PEM data from the regular file at value, or decodes value
// as base64.
func readCustomCA(value string) ([]byte, error) {
	if fi, err := os.Stat(value); err == nil && fi.Mode().IsRegular() { //nolint:gosec // The operator chooses the path.
		data, err := os.ReadFile(value) //nolint:gosec // The operator chooses the path.
		if err != nil {
			return nil, fmt.Errorf("failed to read FARCASTER_CUSTOM_CA: %w", err)
		}
		return data, nil
	}
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("FARCASTER_CUSTOM_CA is neither a file nor base64-encoded PEM: %w", err)
	}
	return data, nil
}

// addCertsFromPEM adds certificates from PEM data to the pool.
// Returns true if at least one certificate was added.
func addCertsFromPEM(pool *x509.CertPool, pemData []byte) bool {
	added := false
	for len(pemData) > 0 {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				pool.AddCert(cert)
				added = true
			}
		}
		pemData = rest
	}
	return added
}

// ResetCache clears the cached configurations. This is mainly useful for testing
// or if environment variables change and you need to reload the configuration.
func ResetCache() {
	configOnce = sync.Once{}
	cachedConfig = nil
	cachedConfigErr = nil
}
