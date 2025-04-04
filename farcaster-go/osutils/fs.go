//go:build !windows
// +build !windows

package osutils

// LockDownPermissions is a no-op on non-Windows platforms
func LockDownPermissions(_ string) error {
	return nil
}
