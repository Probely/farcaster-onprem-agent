//go:build !linux

package netstack

import (
	"net"
	"time"
)

func setTCPConnTimeouts(c *net.TCPConn, interval time.Duration, count int) error {
	err := c.SetKeepAlive(true)
	if err != nil {
		return err
	}

	// TCP_KEEPIDLE and TCP_KEEPINTVL
	err = c.SetKeepAlivePeriod(interval)
	return err
}
