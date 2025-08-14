package tlsconfig_test

import (
	"encoding/base64"
	"fmt"
	"os"
)

// Note: GetTLSConfig() returns a cloned configuration each time it's called,
// so it's safe to modify the returned config without affecting other callers.

// Example_customCA demonstrates how to use the FARCASTER_CUSTOM_CA environment variable
// to add custom Certificate Authorities to the trust store.
func Example_customCA() {
	// Example: Setting a custom CA certificate (base64 encoded PEM)
	// In practice, you would have your actual CA certificate here
	customCAPEM := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHIgKwERfuMA0GCSqGSIb3DQEBCwUAMBkxFzAVBgNVBAMMDkZh
cmNhc3RlciBUZXN0MB4XDTI0MDEwMTAwMDAwMFoXDTM0MDEwMTAwMDAwMFowGTEX
MBUGA1UEAwwORmFyY2FzdGVyIFRlc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ
AoGBAK... (truncated for example)
-----END CERTIFICATE-----`

	// Encode the PEM certificate to base64
	encodedCA := base64.StdEncoding.EncodeToString([]byte(customCAPEM))

	// Set the environment variable
	os.Setenv("FARCASTER_CUSTOM_CA", encodedCA)

	// Now all TLS connections in farcaster will trust this CA
	// in addition to the system's default CAs

	fmt.Println("Custom CA configured")
}

// Example_skipCertVerify demonstrates the insecure option to skip certificate verification.
// WARNING: This should only be used in development/testing environments!
func Example_skipCertVerify() {
	// Enable skipping certificate verification
	os.Setenv("FARCASTER_SKIP_CERT_VERIFY", "true")

	// Now all TLS connections will skip certificate verification
	// This is INSECURE and should not be used in production!

	fmt.Println("Certificate verification disabled (INSECURE)")
}

// Example_multipleCAs demonstrates how to add multiple CA certificates.
func Example_multipleCAs() {
	// You can include multiple certificates in a single PEM block
	multipleCAPEM := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHIgKwERfuMA0GCSqGSIb3DQEBCwUAMBkxFzAVBgNVBAMMDkZh
... (first CA certificate)
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHIgKwERfvMA0GCSqGSIb3DQEBCwUAMBkxFzAVBgNVBAMMDkZh
... (second CA certificate)
-----END CERTIFICATE-----`

	// Encode all certificates together
	encodedCAs := base64.StdEncoding.EncodeToString([]byte(multipleCAPEM))

	// Set the environment variable
	os.Setenv("FARCASTER_CUSTOM_CA", encodedCAs)

	fmt.Println("Multiple custom CAs configured")
}
