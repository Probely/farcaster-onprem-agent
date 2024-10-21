package control

import (
	"fmt"
	"net"
	"os/user"
	"syscall"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func userSID() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}

	// Convert the username to a pointer that the windows API can use.
	account, err := syscall.UTF16PtrFromString(u.Username)
	if err != nil {
		return "", fmt.Errorf("failed to convert user to pointer: %v", err)
	}

	var sid *windows.SID
	var sidSize uint32
	var domainSize uint32
	var use uint32

	// Call LookupAccountName first to get the sizes needed.
	err = windows.LookupAccountName(nil, account, sid, &sidSize, nil, &domainSize, &use)

	if err == windows.ERROR_INSUFFICIENT_BUFFER {
		// Allocate the buffers of the correct sizes.
		sid = (*windows.SID)(unsafe.Pointer(&make([]byte, sidSize)[0]))
		domain := make([]uint16, domainSize)

		// Call LookupAccountName again to get the actual SID.
		err = windows.LookupAccountName(nil, account, sid, &sidSize, &domain[0], &domainSize, &use)
	}

	if err != nil {
		return "", fmt.Errorf("failed to lookup account name: %v", err)
	}

	return sid.String(), nil
}

// newListener creates a new Windows named pipe listener for the control API.
func newListener(addr string, extraSID string) (net.Listener, error) {
	// Allow Administrators and SYSTEM access.
	sddl := "D:P(A;;GA;;;BA)(A;;GA;;;SY)"

	// Allow access the current user.
	sid, _ := userSID()
	if sid != "" {
		sddl += "(A;;GA;;;" + sid + ")"
	}

	// Allow any extra SIDs access.
	if extraSID != "" {
		sddl += "(A;;GA;;;" + extraSID + ")"
	}

	pc := &winio.PipeConfig{
		SecurityDescriptor: sddl,
	}

	return winio.ListenPipe(addr, pc)
}
