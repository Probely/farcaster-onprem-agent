//go:build !windows

package netstack

import "github.com/miekg/dns"

func getSystemResolvers() ([]string, error) {
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	return config.Servers, nil
}
