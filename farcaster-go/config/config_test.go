package config

import (
	"net"
	"testing"

	"go.uber.org/zap"
)

// TestResolveEndpointFromHostsFile resolves localhost from /etc/hosts with
// Go's resolver, which agent containers use.
func TestResolveEndpointFromHostsFile(t *testing.T) {
	resolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true}
	t.Cleanup(func() { net.DefaultResolver = resolver })

	c := NewFarcasterConfig("", nil, zap.NewNop().Sugar())
	peer := &Peer{Endpoint: "localhost:51820"}
	if err := c.resolveEndpoint(peer); err != nil {
		t.Fatal(err)
	}
	if want := "127.0.0.1:51820"; peer.Endpoint != want {
		t.Errorf("Endpoint = %q, want %q", peer.Endpoint, want)
	}
}
