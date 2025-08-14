package tlsconfig

import (
	"encoding/base64"
	"os"
	"testing"
)

func TestGetTLSConfig(t *testing.T) {
	// Save original env vars
	origSkipVerify := os.Getenv("FARCASTER_SKIP_CERT_VERIFY")
	origCustomCA := os.Getenv("FARCASTER_CUSTOM_CA")
	defer func() {
		os.Setenv("FARCASTER_SKIP_CERT_VERIFY", origSkipVerify)
		os.Setenv("FARCASTER_CUSTOM_CA", origCustomCA)
		ResetCache()
	}()

	t.Run("default config", func(t *testing.T) {
		os.Unsetenv("FARCASTER_SKIP_CERT_VERIFY")
		os.Unsetenv("FARCASTER_CUSTOM_CA")
		ResetCache()

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

	t.Run("skip verify enabled", func(t *testing.T) {
		os.Setenv("FARCASTER_SKIP_CERT_VERIFY", "true")
		os.Unsetenv("FARCASTER_CUSTOM_CA")
		ResetCache()

		config, err := GetTLSConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !config.InsecureSkipVerify {
			t.Error("expected InsecureSkipVerify to be true")
		}
	})

	t.Run("skip verify with various true values", func(t *testing.T) {
		trueValues := []string{"1", "ok", "true", "yes", "enable", "enabled", "TRUE", "Yes"}
		os.Unsetenv("FARCASTER_CUSTOM_CA")

		for _, val := range trueValues {
			os.Setenv("FARCASTER_SKIP_CERT_VERIFY", val)
			ResetCache()

			config, err := GetTLSConfig()
			if err != nil {
				t.Fatalf("unexpected error for value %q: %v", val, err)
			}
			if !config.InsecureSkipVerify {
				t.Errorf("expected InsecureSkipVerify to be true for value %q", val)
			}
		}
	})

	t.Run("skip verify with false values", func(t *testing.T) {
		falseValues := []string{"0", "false", "no", "disabled", "anything-else"}
		os.Unsetenv("FARCASTER_CUSTOM_CA")

		for _, val := range falseValues {
			os.Setenv("FARCASTER_SKIP_CERT_VERIFY", val)
			ResetCache()

			config, err := GetTLSConfig()
			if err != nil {
				t.Fatalf("unexpected error for value %q: %v", val, err)
			}
			if config.InsecureSkipVerify {
				t.Errorf("expected InsecureSkipVerify to be false for value %q", val)
			}
		}
	})

	t.Run("invalid base64 custom CA", func(t *testing.T) {
		os.Unsetenv("FARCASTER_SKIP_CERT_VERIFY")
		os.Setenv("FARCASTER_CUSTOM_CA", "not-valid-base64!")
		ResetCache()

		_, err := GetTLSConfig()
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})

	t.Run("valid base64 but invalid certificate", func(t *testing.T) {
		os.Unsetenv("FARCASTER_SKIP_CERT_VERIFY")
		os.Setenv("FARCASTER_CUSTOM_CA", base64.StdEncoding.EncodeToString([]byte("not a certificate")))
		ResetCache()

		_, err := GetTLSConfig()
		if err == nil {
			t.Error("expected error for invalid certificate")
		}
	})

	// Note: Testing with a real certificate would require generating a test CA
	// which is beyond the scope of this unit test

	t.Run("config is cloned", func(t *testing.T) {
		os.Setenv("FARCASTER_SKIP_CERT_VERIFY", "true")
		os.Unsetenv("FARCASTER_CUSTOM_CA")
		ResetCache()

		config1, err := GetTLSConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		config2, err := GetTLSConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Configs should be different instances
		if config1 == config2 {
			t.Error("expected different config instances (should be cloned)")
		}

		// Modifying one should not affect the other
		config1.ServerName = "test.example.com"
		if config2.ServerName == "test.example.com" {
			t.Error("modifying cloned config affected other instance")
		}

		// Getting a third config should also be unaffected
		config3, err := GetTLSConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if config3.ServerName == "test.example.com" {
			t.Error("modifying cloned config affected cached config")
		}
	})
}

func TestResetCache(t *testing.T) {
	// Save original env vars
	origSkipVerify := os.Getenv("FARCASTER_SKIP_CERT_VERIFY")
	defer func() {
		os.Setenv("FARCASTER_SKIP_CERT_VERIFY", origSkipVerify)
		ResetCache()
	}()

	os.Setenv("FARCASTER_SKIP_CERT_VERIFY", "true")
	ResetCache()

	config1, _ := GetTLSConfig()

	ResetCache()

	config2, _ := GetTLSConfig()

	if config1 == config2 {
		t.Error("expected new config instance after reset")
	}
}
