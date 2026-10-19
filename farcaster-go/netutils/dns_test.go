package netutils

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestDecodeAddrsSkipsCNAME(t *testing.T) {
	const body = `{"Status":0,"Answer":[
		{"name":"hub.example.com","type":5,"TTL":300,"data":"edge.example.net."},
		{"name":"edge.example.net","type":1,"TTL":300,"data":"192.0.2.10"}]}`
	got, err := decodeAddrs(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if want := []netip.Addr{netip.MustParseAddr("192.0.2.10")}; !slices.Equal(got, want) {
		t.Errorf("decodeAddrs() = %v, want %v", got, want)
	}
}
