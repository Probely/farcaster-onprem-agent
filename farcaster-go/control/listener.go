//go:build !windows
// +build !windows

package control

import (
	"net"
	"os"
	"syscall"
)

// newListener creates a new Unix socket listener for the control API.
func newListener(path, extraGroup string) (net.Listener, error) {
	_ = os.Remove(path)
	umask := syscall.Umask(0077)
	l, err := net.Listen("unix", path)
	syscall.Umask(umask)
	return l, err
}
