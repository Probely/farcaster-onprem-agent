//go:build !windows
// +build !windows

package farcasterd

func isWindowsService() bool {
	return false
}
