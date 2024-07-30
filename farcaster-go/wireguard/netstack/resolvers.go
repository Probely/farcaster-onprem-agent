//go:build !windows

package netstack

import (
	"bufio"
	"os"
	"strings"
)

func getSystemResolvers() ([]string, error) {
	var resolvers []string

	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "nameserver") {
			resolver := strings.TrimSpace(strings.Split(line, " ")[1])
			resolvers = append(resolvers, resolver)
		}
	}

	if scanner.Err() != nil {
		return nil, scanner.Err()
	}

	return resolvers, nil
}
