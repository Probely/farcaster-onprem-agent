package tlsconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGetTLSConfig(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		t.Setenv("FARCASTER_SKIP_CERT_VERIFY", "")
		t.Setenv("FARCASTER_CUSTOM_CA", "")
		ResetCache()
		t.Cleanup(ResetCache)

		config, err := GetTLSConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if config.InsecureSkipVerify {
			t.Error("expected InsecureSkipVerify to be false")
		}
		if config.RootCAs != nil {
			t.Error("expected RootCAs to be nil for default config")
		}
	})

	t.Run("skip verify values", func(t *testing.T) {
		tests := []struct {
			val  string
			want bool
		}{
			{"true", true},
			{"Yes", true},
			{"false", false},
		}
		for _, tt := range tests {
			t.Run(tt.val, func(t *testing.T) {
				t.Setenv("FARCASTER_SKIP_CERT_VERIFY", tt.val)
				t.Setenv("FARCASTER_CUSTOM_CA", "")
				ResetCache()
				t.Cleanup(ResetCache)

				config, err := GetTLSConfig()
				if err != nil {
					t.Fatalf("GetTLSConfig() error: %v", err)
				}
				if config.InsecureSkipVerify != tt.want {
					t.Errorf("InsecureSkipVerify = %v, want %v", config.InsecureSkipVerify, tt.want)
				}
			})
		}
	})

	t.Run("invalid base64 custom CA", func(t *testing.T) {
		t.Setenv("FARCASTER_SKIP_CERT_VERIFY", "")
		t.Setenv("FARCASTER_CUSTOM_CA", "not-valid-base64!")
		ResetCache()
		t.Cleanup(ResetCache)

		if _, err := GetTLSConfig(); err == nil {
			t.Error("expected error for invalid base64")
		}
	})

	t.Run("valid base64 but invalid certificate", func(t *testing.T) {
		t.Setenv("FARCASTER_SKIP_CERT_VERIFY", "")
		t.Setenv("FARCASTER_CUSTOM_CA", base64.StdEncoding.EncodeToString([]byte("not a certificate")))
		ResetCache()
		t.Cleanup(ResetCache)

		if _, err := GetTLSConfig(); err == nil {
			t.Error("expected error for invalid certificate")
		}
	})

	t.Run("config is cloned", func(t *testing.T) {
		t.Setenv("FARCASTER_SKIP_CERT_VERIFY", "true")
		t.Setenv("FARCASTER_CUSTOM_CA", "")
		ResetCache()
		t.Cleanup(ResetCache)

		config1, err := GetTLSConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		config2, err := GetTLSConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if config1 == config2 {
			t.Error("expected different config instances (should be cloned)")
		}

		config1.ServerName = "test.example.com"
		if config2.ServerName == "test.example.com" {
			t.Error("modifying cloned config affected other instance")
		}

		config3, err := GetTLSConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if config3.ServerName == "test.example.com" {
			t.Error("modifying cloned config affected cached config")
		}
	})
}

func TestCustomCASources(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		value string
	}{
		{"base64 PEM", base64.StdEncoding.EncodeToString(caPEM)},
		{"PEM file", caFile},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("FARCASTER_SKIP_CERT_VERIFY", "")
			t.Setenv("FARCASTER_CUSTOM_CA", tt.value)
			ResetCache()
			t.Cleanup(ResetCache)

			config, err := GetTLSConfig()
			if err != nil {
				t.Fatalf("GetTLSConfig: %v", err)
			}
			if _, err := ca.Verify(x509.VerifyOptions{Roots: config.RootCAs}); err != nil {
				t.Fatalf("custom CA is not trusted: %v", err)
			}
		})
	}
}
