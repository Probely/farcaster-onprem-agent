package netutils

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"probely.com/farcaster/tlsconfig"
)

const cloudflareDoHEndpoint = "https://1.1.1.1/dns-query"

// LookupNetIPDoH performs a DNS over HTTPS query using Cloudflare's DoH service.
// It accepts a context, network type ("ip", "ip4", "ip6"), and hostname to resolve.
func LookupNetIPDoH(ctx context.Context, network, host string) ([]netip.Addr, error) {
	var recordType string
	switch network {
	case "ip4":
		recordType = "A"
	case "ip6":
		recordType = "AAAA"
	case "ip":
		recordType = "ANY"
	default:
		return nil, fmt.Errorf("invalid network type: %s", network)
	}

	baseURL, err := url.Parse(cloudflareDoHEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Cloudflare DoH endpoint: %w", err)
	}

	params := url.Values{}
	params.Set("name", host)
	params.Set("type", recordType)
	baseURL.RawQuery = params.Encode()

	// Use centralized TLS config for DoH queries
	tlsConfig, err := tlsconfig.GetTLSConfig()
	if err != nil {
		tlsConfig = &tls.Config{}
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-OK HTTP status: %s", resp.Status)
	}

	var dnsResp struct {
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %w", err)
	}

	var addrs []netip.Addr
	for _, ans := range dnsResp.Answer {
		addr, err := netip.ParseAddr(ans.Data)
		if err != nil {
			return nil, fmt.Errorf("invalid IP address in DNS response: %w", err)
		}
		addrs = append(addrs, addr)
	}

	return addrs, nil
}
