package netstack

import (
	"net"
	"os/exec"
	"strings"
	"syscall"
)

const ipconfigSeparator = ". : "

func getSystemResolvers() ([]string, error) {
	var resolvers []string

	cmd := exec.Command("ipconfig", "/all")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	inDNSSection := false
	for _, line := range lines {
		// Skip lines until we get to the DNS section.
		if !inDNSSection {
			if !strings.Contains(line, "DNS Servers") {
				continue
			}

			inDNSSection = true
			split := strings.Split(line, ipconfigSeparator)
			if len(split) != 2 {
				continue
			}
			resolver := strings.TrimSpace(split[1])
			if net.ParseIP(resolver) != nil {
				resolvers = append(resolvers, resolver)
			}
			continue
		}

		// Read the resolver, if it's valid.
		resolver := strings.TrimSpace(line)
		if net.ParseIP(resolver) != nil {
			resolvers = append(resolvers, resolver)
		}

		// New section.
		if strings.Contains(line, ipconfigSeparator) {
			inDNSSection = false
		}
	}

	return resolvers, nil
}
