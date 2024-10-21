package netstack

import (
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func setTCPConnTimeouts(c *net.TCPConn, interval time.Duration, count int) error {
	err := c.SetKeepAlive(true)
	if err != nil {
		return err
	}

	// TCP_KEEPIDLE and TCP_KEEPINTVL
	err = c.SetKeepAlivePeriod(interval)
	if err != nil {
		return err
	}

	sc, err := c.SyscallConn()
	if err != nil {
		return err
	}

	// TCP_KEEPCNT
	err = sc.Control(func(fd uintptr) {
		syscall.SetsockoptInt(int(fd), syscall.SOL_TCP, syscall.TCP_KEEPCNT, count)
	})
	if err != nil {
		return err
	}

	timeout := tcpUserTimeout(interval, count)
	err = sc.Control(func(fd uintptr) {
		timeoutMs := int(timeout / time.Millisecond)
		syscall.SetsockoptInt(int(fd), syscall.SOL_TCP, unix.TCP_USER_TIMEOUT, timeoutMs)
	})
	return err
}
