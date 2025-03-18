//go:build !windows
// +build !windows

package farcasterd

import "go.uber.org/zap"

func isWindowsService() bool {
	return false
}

func runWindowsService(_ string, _ func() error, _ *zap.SugaredLogger) error {
	// Never called on non-windows platforms
	return nil
}
