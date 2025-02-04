//go:build !windows
// +build !windows

package farcasterd

// lockDownPermissions is a no-op on non-Windows platforms
func lockDownPermissions(_ string) error {
	return nil
}
